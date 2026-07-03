//! Handshake: 2048-byte gepadde berichten met één gedeeld KEM-slot,
//! fragmentatie voor MTU-veilig transport, en de state machine met
//! transcript-ondertekening (Ed25519 via de Authenticator-trait).

use crate::aead::AeadAlgo;
use crate::crypto::{derive_shared, mac_key_from, role_bound_hash, Authenticator, Transcript};
use crate::error::{ChameleonError, Result};
use crate::session::Session;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use rand::RngCore;
use ring::hmac;
use std::collections::HashMap;
use x25519_dalek::{EphemeralSecret, PublicKey as XPub};

// Vaste berichtgrootte, ruim genoeg voor de HYBRIDE handtekening
// (Ed25519 64 B + ML-DSA-65 3309 B = 3373 B) bovenop de Kyber-pubkey/ct in het
// KEM-slot. Init/Response/Confirm zijn allemaal even groot en met ruis gepad,
// zodat de berichtgrootte niets over het type of het gekozen auth-schema
// verraadt. Post-quantum sleutels zijn nu eenmaal groot; een handshake is een
// eenmalige gebeurtenis, dus de extra fragmenten kosten niets wezenlijks.
pub const HANDSHAKE_MSG_LEN: usize = 8192;
// v3: naast het geobfusceerde datapad (v2, obf.rs) is nu ook de HANDSHAKE-
// envelope geobfusceerd (hsobf.rs, statische-sleutel wrap-then-fragment).
// v4: de twee transcript-handtekeningen zijn ROL-gebonden (SIG_LABEL_*), zodat
// responder en initiator niet langer over identieke bytes tekenen (L-5). Dat
// verandert de handshake-auth; de versie-bump laat een peer met een oudere
// handshake meteen schoon falen i.p.v. met een verwarrende MAC-fout.
pub const PROTO_VERSION: u8 = 4;

/// Rol-labels voor de domeinscheiding van de transcript-handtekeningen (L-5):
/// de responder tekent de Response, de initiator de Confirm — nooit over
/// dezelfde bytes. Ze worden vóór de transcript-hash gehasht (`role_bound_hash`).
const SIG_LABEL_RESPONDER: &[u8] = b"Chameleon-PQ-v1 responder proof";
const SIG_LABEL_INITIATOR: &[u8] = b"Chameleon-PQ-v1 initiator proof";

/// Bovengrens op het aantal gelijktijdig onvoltooide berichten in één
/// Reassembler. Sinds Fase 2 wordt (bij handshake-obfuscatie) elk niet-data-
/// datagram een kandidaat-fragment, dus een msg_id-flood zou anders geheugen
/// kunnen opblazen. Nieuwe msg_id's boven de cap worden genegeerd; samen met
/// `prune_old` blijft het geheugen begrensd.
const MAX_PENDING_MSGS: usize = 64;

const X25519_PUB_LEN: usize = 32;
const KYBER_PK_LEN: usize = 1184;
const KYBER_CT_LEN: usize = 1088;
const KEM_SLOT_LEN: usize = KYBER_PK_LEN; // grootste van pub/ct
const MAC_LEN: usize = 32;

const FRAG_PAYLOAD: usize = 1024;
const FRAG_HEADER_LEN: usize = 8;

// ── Fragmentatie (alleen handshake) ──────────────────────────────────────────

pub fn fragment(msg_id: u32, full: &[u8]) -> Vec<Bytes> {
    let chunks: Vec<&[u8]> = full.chunks(FRAG_PAYLOAD).collect();
    let total = chunks.len() as u16;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let mut b = BytesMut::with_capacity(FRAG_HEADER_LEN + chunk.len());
            b.put_u32_le(msg_id);
            b.put_u16_le(i as u16);
            b.put_u16_le(total);
            b.put_slice(chunk);
            b.freeze()
        })
        .collect()
}

#[derive(Default)]
pub struct Reassembler {
    partials: HashMap<u32, PartialMsg>,
}

struct PartialMsg {
    total: u16,
    chunks: HashMap<u16, Bytes>,
    /// Tijdstip waarop het EERSTE fragment binnenkwam. Bewust niet
    /// ververst bij latere fragmenten: anders kan een aanvaller een
    /// incomplete entry eindeloos levend houden door af en toe één
    /// fragment te sturen (precies de DoS die we willen voorkomen).
    first_seen: std::time::Instant,
}

impl Reassembler {
    /// Cleartext-pad: parse de 8-byte fragment-header en push de delen.
    /// Gebruikt door de niet-geobfusceerde (fallback) handshake-weg.
    pub fn push(&mut self, raw: &[u8]) -> Result<Option<Bytes>> {
        if raw.len() < FRAG_HEADER_LEN {
            return Err(ChameleonError::PacketTooShort {
                got: raw.len(),
                need: FRAG_HEADER_LEN,
            });
        }
        let mut hdr = &raw[..FRAG_HEADER_LEN];
        let msg_id = hdr.get_u32_le();
        let index = hdr.get_u16_le();
        let total = hdr.get_u16_le();
        let payload = Bytes::copy_from_slice(&raw[FRAG_HEADER_LEN..]);
        self.push_parts(msg_id, index, total, payload)
    }

    /// Push reeds-geparseerde fragment-delen. Gebruikt door de geobfusceerde
    /// handshake-weg (hsobf.rs ontmaskert de header vóór deze aanroep). Zelfde
    /// partial/complete-logica als `push`, met een cap tegen msg_id-floods.
    pub fn push_parts(
        &mut self,
        msg_id: u32,
        index: u16,
        total: u16,
        payload: Bytes,
    ) -> Result<Option<Bytes>> {
        if total == 0 || index >= total {
            return Err(ChameleonError::Handshake {
                state: "reassemble".into(),
                msg: "invalid fragment index/total".into(),
            });
        }
        // DoS-cap: een NIEUW msg_id boven de grens wordt genegeerd, zodat een
        // stroom willekeurige datagrammen het geheugen niet kan opblazen.
        if !self.partials.contains_key(&msg_id) && self.partials.len() >= MAX_PENDING_MSGS {
            return Ok(None);
        }
        let entry = self.partials.entry(msg_id).or_insert_with(|| PartialMsg {
            total,
            chunks: HashMap::new(),
            first_seen: std::time::Instant::now(),
        });
        if entry.total != total {
            return Err(ChameleonError::Handshake {
                state: "reassemble".into(),
                msg: "inconsistent fragment count".into(),
            });
        }
        entry.chunks.insert(index, payload);
        if entry.chunks.len() as u16 == entry.total {
            let mut out = BytesMut::new();
            for i in 0..entry.total {
                let part = entry
                    .chunks
                    .get(&i)
                    .ok_or_else(|| ChameleonError::Handshake {
                        state: "reassemble".into(),
                        msg: "missing fragment".into(),
                    })?;
                out.put_slice(part);
            }
            self.partials.remove(&msg_id);
            return Ok(Some(out.freeze()));
        }
        Ok(None)
    }

    /// Verwijder entries die te lang incompleet bleven. Roep dit periodiek
    /// aan (bv. via een tokio interval) zodat half-afgemaakte berichten geen
    /// geheugen blijven vasthouden — de State-Bloat-DoS-fix.
    pub fn prune_old(&mut self, max_age: std::time::Duration) {
        let now = std::time::Instant::now();
        self.partials
            .retain(|_id, msg| now.duration_since(msg.first_seen) < max_age);
    }

    /// Aantal incomplete berichten dat nu in de buffer staat (voor metrics/tests).
    pub fn pending_count(&self) -> usize {
        self.partials.len()
    }
}

// ── HandshakeMessage ─────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    Init = 0x01,
    Response = 0x02,
    /// Derde bericht: initiator bevestigt zijn identiteit aan de responder.
    /// Draagt de handtekening van de initiator over het volledige transcript.
    /// Maakt de handshake wederzijds geauthenticeerd.
    Confirm = 0x03,
}

impl HandshakeType {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Init),
            0x02 => Ok(Self::Response),
            0x03 => Ok(Self::Confirm),
            _ => Err(ChameleonError::Handshake {
                state: "decode".into(),
                msg: format!("unknown type {v}"),
            }),
        }
    }
}

#[derive(Clone)]
pub struct HandshakeMessage {
    pub version: u8,
    pub msg_type: HandshakeType,
    /// Voorgestelde/onderhandelde AEAD-cipher (AeadAlgo wire-id). In Init de
    /// voorkeur van de initiator; in Response de definitieve onderhandelde keuze.
    /// Zit in het transcript -> downgrade-bestendig.
    pub aead_algo: u8,
    pub x25519_pub: [u8; X25519_PUB_LEN],
    pub kem: [u8; KEM_SLOT_LEN],
    pub sig: Vec<u8>,
    pub mac: [u8; MAC_LEN],
}

impl HandshakeMessage {
    fn fill_noise(buf: &mut [u8]) {
        rand::rngs::OsRng.fill_bytes(buf);
    }

    pub fn new_init(
        x25519_pub: [u8; X25519_PUB_LEN],
        kyber_pub: &[u8],
        sig_len: usize,
        aead_algo: u8,
    ) -> Result<Self> {
        if kyber_pub.len() != KYBER_PK_LEN {
            return Err(ChameleonError::Handshake {
                state: "encode".into(),
                msg: "bad kyber pub len".into(),
            });
        }
        let mut kem = [0u8; KEM_SLOT_LEN];
        kem.copy_from_slice(kyber_pub);
        let mut sig = vec![0u8; sig_len];
        Self::fill_noise(&mut sig);
        let mut mac = [0u8; MAC_LEN];
        Self::fill_noise(&mut mac);
        Ok(Self {
            version: PROTO_VERSION,
            msg_type: HandshakeType::Init,
            aead_algo,
            x25519_pub,
            kem,
            sig,
            mac,
        })
    }

    pub fn new_response(
        x25519_pub: [u8; X25519_PUB_LEN],
        kyber_ct: &[u8],
        sig_len: usize,
        aead_algo: u8,
    ) -> Result<Self> {
        if kyber_ct.len() != KYBER_CT_LEN {
            return Err(ChameleonError::Handshake {
                state: "encode".into(),
                msg: "bad kyber ct len".into(),
            });
        }
        let mut kem = [0u8; KEM_SLOT_LEN];
        kem[..KYBER_CT_LEN].copy_from_slice(kyber_ct);
        Self::fill_noise(&mut kem[KYBER_CT_LEN..]);
        Ok(Self {
            version: PROTO_VERSION,
            msg_type: HandshakeType::Response,
            aead_algo,
            x25519_pub,
            kem,
            sig: vec![0u8; sig_len],
            mac: [0u8; MAC_LEN],
        })
    }

    pub fn kyber_pub(&self) -> &[u8] {
        &self.kem[..KYBER_PK_LEN]
    }
    pub fn kyber_ct(&self) -> &[u8] {
        &self.kem[..KYBER_CT_LEN]
    }

    /// Confirm-bericht: draagt alleen de initiator-handtekening (+ MAC).
    /// x25519_pub en kem zijn noise — ze dragen geen betekenis in deze fase
    /// en vallen buiten de transcript-binding. De sig wordt door de caller
    /// gezet ná het berekenen van het transcript.
    pub fn new_confirm(sig_len: usize) -> Result<Self> {
        let mut x25519_pub = [0u8; X25519_PUB_LEN];
        Self::fill_noise(&mut x25519_pub);
        let mut kem = [0u8; KEM_SLOT_LEN];
        Self::fill_noise(&mut kem);
        Ok(Self {
            version: PROTO_VERSION,
            msg_type: HandshakeType::Confirm,
            aead_algo: 0, // niet van toepassing op Confirm
            x25519_pub,
            kem,
            sig: vec![0u8; sig_len],
            mac: [0u8; MAC_LEN],
        })
    }

    pub fn encode(&self) -> Result<Bytes> {
        let mut buf = BytesMut::with_capacity(HANDSHAKE_MSG_LEN);
        buf.put_u8(self.version);
        buf.put_u8(self.msg_type as u8);
        buf.put_u8(self.aead_algo);
        buf.put_slice(&self.x25519_pub);
        buf.put_slice(&self.kem);
        buf.put_u16_le(self.sig.len() as u16);
        buf.put_slice(&self.sig);
        buf.put_slice(&self.mac);
        let used = buf.len();
        if used > HANDSHAKE_MSG_LEN {
            return Err(ChameleonError::Handshake {
                state: "encode".into(),
                msg: format!("message {used} > {HANDSHAKE_MSG_LEN}"),
            });
        }
        let mut pad = vec![0u8; HANDSHAKE_MSG_LEN - used];
        Self::fill_noise(&mut pad);
        buf.put_slice(&pad);
        Ok(buf.freeze())
    }

    pub fn decode(mut raw: Bytes) -> Result<Self> {
        if raw.len() != HANDSHAKE_MSG_LEN {
            return Err(ChameleonError::Handshake {
                state: "decode".into(),
                msg: format!("expected {HANDSHAKE_MSG_LEN}, got {}", raw.len()),
            });
        }
        let version = raw.get_u8();
        if version != PROTO_VERSION {
            return Err(ChameleonError::Handshake {
                state: "decode".into(),
                msg: format!("bad version {version}"),
            });
        }
        let msg_type = HandshakeType::from_u8(raw.get_u8())?;
        let aead_algo = raw.get_u8();
        let mut x25519_pub = [0u8; X25519_PUB_LEN];
        raw.copy_to_slice(&mut x25519_pub);
        let mut kem = [0u8; KEM_SLOT_LEN];
        raw.copy_to_slice(&mut kem);
        let sig_len = raw.get_u16_le() as usize;
        if raw.remaining() < sig_len + MAC_LEN {
            return Err(ChameleonError::Handshake {
                state: "decode".into(),
                msg: "truncated sig/mac".into(),
            });
        }
        let mut sig = vec![0u8; sig_len];
        raw.copy_to_slice(&mut sig);
        let mut mac = [0u8; MAC_LEN];
        raw.copy_to_slice(&mut mac);
        Ok(Self {
            version,
            msg_type,
            aead_algo,
            x25519_pub,
            kem,
            sig,
            mac,
        })
    }

    pub fn transcript_bytes(&self) -> Bytes {
        let mut b = BytesMut::new();
        b.put_u8(self.version);
        b.put_u8(self.msg_type as u8);
        b.put_slice(&self.x25519_pub);
        match self.msg_type {
            HandshakeType::Init => {
                b.put_u8(self.aead_algo); // bind voorgestelde cipher
                b.put_slice(self.kyber_pub());
            }
            HandshakeType::Response => {
                b.put_u8(self.aead_algo); // bind onderhandelde cipher
                b.put_slice(self.kyber_ct());
            }
            // Confirm voegt geen sleutelmateriaal toe: het transcript is na
            // de Response bevroren, en Confirm ondertekent juist dat transcript.
            // Deze functie hoort niet op een Confirm te worden aangeroepen,
            // maar we houden de match compleet en veilig.
            HandshakeType::Confirm => {}
        }
        b.freeze()
    }
}

// ── State machine ────────────────────────────────────────────────────────────
//
// Wederzijds geauthenticeerde 3-berichten-handshake:
//
//   1. Init     (initiator -> responder)  : ephemeral sleutels
//   2. Response (responder -> initiator)  : ephemeral sleutels + responder-sig
//   3. Confirm  (initiator -> responder)  : initiator-sig over het transcript
//
// De responder gaat na Response naar SentResponse en VERTROUWT de sessie
// pas zodra de Confirm-handtekening klopt. Zo authenticeren beide kanten
// elkaar, niet alleen de responder.

pub enum Handshake {
    Idle,
    /// Initiator: init verstuurd, wacht op response.
    SentInit {
        eph_x: EphemeralSecret,
        // Geboxed: de Kyber-secret-key is ~2.4 KB; los gehouden zou hij elke
        // Handshake-variant (en dus elke move) onnodig groot maken.
        eph_kyber_sk: Box<kyber768::SecretKey>,
        transcript: Transcript,
    },
    /// Responder: response verstuurd, wacht op confirm. Houdt de (nog niet
    /// vertrouwde) sessie en de transcript-hash vast tot de confirm klopt.
    SentResponse {
        session: Session,
        transcript_hash: [u8; 32],
    },
    /// Volledig wederzijds geauthenticeerd.
    Established {
        session: Session,
    },
    Failed,
}

impl Handshake {
    pub fn start(auth: &dyn Authenticator) -> Result<(Self, Bytes)> {
        let eph_x = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let x_pub = XPub::from(&eph_x);
        let (eph_kyber_pk, eph_kyber_sk) = kyber768::keypair();

        let msg = HandshakeMessage::new_init(
            x_pub.to_bytes(),
            eph_kyber_pk.as_bytes(),
            auth.signature_len(),
            AeadAlgo::preferred().as_u8(),
        )?;
        let mut transcript = Transcript::new();
        transcript.absorb(&msg.transcript_bytes());
        let wire = msg.encode()?;
        Ok((
            Handshake::SentInit {
                eph_x,
                eph_kyber_sk: Box::new(eph_kyber_sk),
                transcript,
            },
            wire,
        ))
    }

    /// RESPONDER stap 1: verwerk Init, bouw Response. Gaat naar SentResponse
    /// (nog NIET Established — de initiator moet zich eerst bewijzen).
    pub fn respond(raw: Bytes, session_id: u32, auth: &dyn Authenticator) -> Result<(Self, Bytes)> {
        let init = HandshakeMessage::decode(raw)?;
        if init.msg_type != HandshakeType::Init {
            return Err(ChameleonError::Handshake {
                state: "respond".into(),
                msg: "expected Init".into(),
            });
        }
        let peer_kyber_pk = kyber768::PublicKey::from_bytes(init.kyber_pub()).map_err(|_| {
            ChameleonError::Handshake {
                state: "respond".into(),
                msg: "kem slot is not a valid Kyber public key".into(),
            }
        })?;

        let mut transcript = Transcript::new();
        transcript.absorb(&init.transcript_bytes());

        // Onderhandel de cipher: initiator-voorstel vs. onze eigen voorkeur.
        // AEGIS alleen als beide kanten het kunnen, anders ChaCha20.
        let peer_pref = AeadAlgo::from_u8(init.aead_algo).unwrap_or(AeadAlgo::ChaCha20Poly1305);
        let chosen = AeadAlgo::negotiate(AeadAlgo::preferred(), peer_pref);

        let (kyber_ss, kyber_ct) = kyber768::encapsulate(&peer_kyber_pk);
        let eph_x = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let x_pub = XPub::from(&eph_x);
        let peer_x = XPub::from(init.x25519_pub);
        let x_ss = eph_x.diffie_hellman(&peer_x);
        let shared = derive_shared(x_ss.as_bytes(), kyber_ss.as_bytes());

        let mut resp = HandshakeMessage::new_response(
            x_pub.to_bytes(),
            kyber_ct.as_bytes(),
            auth.signature_len(),
            chosen.as_u8(),
        )?;
        transcript.absorb(&resp.transcript_bytes());

        let th = transcript.hash();
        // Rol-gebonden handtekening (L-5): responder tekent SIG_LABEL_RESPONDER‖th.
        resp.sig = auth.sign(&role_bound_hash(SIG_LABEL_RESPONDER, &th))?;
        let mac_key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key_from(&shared));
        let tag = hmac::sign(&mac_key, &th);
        resp.mac.copy_from_slice(tag.as_ref());

        let wire = resp.encode()?;
        let session = Session::from_handshake_with_algo(session_id, shared, false, chosen)?;
        // Bewaar de transcript-hash zodat we straks de Confirm kunnen verifiëren.
        Ok((
            Handshake::SentResponse {
                session,
                transcript_hash: th,
            },
            wire,
        ))
    }

    /// INITIATOR stap 2: verwerk Response, verifieer responder, bouw Confirm.
    /// De initiator wordt Established (heeft de responder geauthenticeerd) EN
    /// produceert het Confirm-bericht dat hij terugstuurt zodat de responder
    /// óók de initiator kan authenticeren.
    pub fn finalize(
        self,
        raw: Bytes,
        session_id: u32,
        auth: &dyn Authenticator,
    ) -> Result<(Self, Bytes)> {
        let (eph_x, eph_kyber_sk, mut transcript) = match self {
            Handshake::SentInit {
                eph_x,
                eph_kyber_sk,
                transcript,
            } => (eph_x, eph_kyber_sk, transcript),
            _ => {
                return Err(ChameleonError::Handshake {
                    state: "finalize".into(),
                    msg: "not in SentInit state".into(),
                })
            }
        };
        let resp = HandshakeMessage::decode(raw)?;
        if resp.msg_type != HandshakeType::Response {
            return Err(ChameleonError::Handshake {
                state: "finalize".into(),
                msg: "expected Response".into(),
            });
        }
        let ct = kyber768::Ciphertext::from_bytes(resp.kyber_ct()).map_err(|_| {
            ChameleonError::Handshake {
                state: "finalize".into(),
                msg: "kem slot is not a valid Kyber ciphertext".into(),
            }
        })?;
        let kyber_ss = kyber768::decapsulate(&ct, &eph_kyber_sk);
        let peer_x = XPub::from(resp.x25519_pub);
        let x_ss = eph_x.diffie_hellman(&peer_x);
        let shared = derive_shared(x_ss.as_bytes(), kyber_ss.as_bytes());

        transcript.absorb(&resp.transcript_bytes());
        let th = transcript.hash();

        // Authenticeer de RESPONDER via zijn rol-gebonden handtekening (L-5).
        auth.verify(&role_bound_hash(SIG_LABEL_RESPONDER, &th), &resp.sig)?;
        let mac_key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key_from(&shared));
        hmac::verify(&mac_key, &th, &resp.mac).map_err(|_| ChameleonError::Handshake {
            state: "finalize".into(),
            msg: "MAC verification failed".into(),
        })?;

        // Bouw het Confirm-bericht: onze handtekening over hetzelfde transcript.
        // Hiermee bewijst de initiator zijn identiteit aan de responder.
        let mut confirm = HandshakeMessage::new_confirm(auth.signature_len())?;
        // Rol-gebonden handtekening (L-5): initiator tekent SIG_LABEL_INITIATOR‖th.
        confirm.sig = auth.sign(&role_bound_hash(SIG_LABEL_INITIATOR, &th))?;
        let tag = hmac::sign(&mac_key, &th);
        confirm.mac.copy_from_slice(tag.as_ref());
        let wire = confirm.encode()?;

        // De responder heeft de definitieve cipher gekozen; lees 'm uit de
        // Response. Die keuze zit in het transcript, dus als een aanvaller 'm
        // had veranderd faalt de MAC-verificatie hierboven al.
        let chosen = AeadAlgo::from_u8(resp.aead_algo)?;
        let session = Session::from_handshake_with_algo(session_id, shared, true, chosen)?;
        Ok((Handshake::Established { session }, wire))
    }

    /// RESPONDER stap 2: verwerk Confirm, authenticeer de INITIATOR.
    /// Pas hierna is de sessie wederzijds geauthenticeerd en vertrouwd.
    pub fn confirm(self, raw: Bytes, auth: &dyn Authenticator) -> Result<Self> {
        let (session, transcript_hash) = match self {
            Handshake::SentResponse {
                session,
                transcript_hash,
            } => (session, transcript_hash),
            _ => {
                return Err(ChameleonError::Handshake {
                    state: "confirm".into(),
                    msg: "not in SentResponse state".into(),
                })
            }
        };
        let conf = HandshakeMessage::decode(raw)?;
        if conf.msg_type != HandshakeType::Confirm {
            return Err(ChameleonError::Handshake {
                state: "confirm".into(),
                msg: "expected Confirm".into(),
            });
        }

        // Authenticeer de INITIATOR via zijn rol-gebonden handtekening (L-5) over
        // het transcript. Dit is wat de handshake wederzijds maakt: zonder geldige
        // initiator-handtekening wordt de sessie NOOIT vertrouwd. De rol-binding
        // zorgt dat de responder-handtekening (over SIG_LABEL_RESPONDER‖th) hier
        // niet als initiator-bewijs kan worden gereflecteerd.
        auth.verify(
            &role_bound_hash(SIG_LABEL_INITIATOR, &transcript_hash),
            &conf.sig,
        )
        .map_err(|_| ChameleonError::Handshake {
            state: "confirm".into(),
            msg: "initiator signature verification failed (not the expected peer)".into(),
        })?;

        Ok(Handshake::Established { session })
    }
}
