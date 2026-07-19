//! Handshake: 2048-byte padded messages with one shared KEM slot,
//! fragmentation for MTU-safe transport, and the state machine with
//! transcript signing (Ed25519 via the Authenticator trait).

use crate::aead::AeadAlgo;
use crate::crypto::{
    derive_session_id, derive_shared, mac_key_from, role_bound_hash, Authenticator, Transcript,
};
use crate::error::{ChameleonError, Result};
use crate::session::Session;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use rand::RngCore;
use ring::hmac;
use std::collections::HashMap;
use x25519_dalek::{EphemeralSecret, PublicKey as XPub};

// Fixed message size, ample for the HYBRID signature
// (Ed25519 64 B + ML-DSA-65 3309 B = 3373 B) on top of the ML-KEM pubkey/ct in
// the KEM slot. Init/Response/Confirm are all the same size and noise-padded, so
// the message size reveals nothing about the type or the chosen auth scheme.
// Post-quantum keys are simply large; a handshake is a one-time event, so the
// extra fragments cost nothing meaningful.
pub const HANDSHAKE_MSG_LEN: usize = 8192;
// v3: besides the obfuscated data path (v2, obf.rs), the HANDSHAKE envelope is
// now obfuscated too (hsobf.rs, static-key wrap-then-fragment).
// v4: the two transcript signatures are ROLE-bound (SIG_LABEL_*), so responder
// and initiator no longer sign over identical bytes (L-5).
// v5: the transcript now also absorbs the IDENTITIES of both parties
// (auth.identity_binding(), L-6), so the signatures bind who is signing
// (unknown-key-share defense).
// v6: the KEM is now FIPS 203 ML-KEM-768 (pqcrypto-mlkem) instead of pre-standard
// Kyber768 (I-11). Same key/ct sizes (1184/1088) but a different algorithm.
// v7: the handshake now carries a return-routability cookie (L-4) and a
// CookieChallenge message type; the responder does expensive crypto only after
// a valid cookie. Every version bump changes the handshake, so an older peer
// fails immediately and cleanly instead of with a confusing MAC error.
pub const PROTO_VERSION: u8 = 7;

/// Role labels for the domain separation of the transcript signatures (L-5):
/// the responder signs the Response, the initiator the Confirm — never over
/// the same bytes. They are hashed before the transcript hash (`role_bound_hash`).
const SIG_LABEL_RESPONDER: &[u8] = b"Chameleon-PQ-v1 responder proof";
const SIG_LABEL_INITIATOR: &[u8] = b"Chameleon-PQ-v1 initiator proof";

/// Upper bound on the number of simultaneously incomplete messages in one
/// Reassembler. Since Phase 2, every non-data datagram becomes a candidate
/// fragment (with handshake obfuscation), so a msg_id flood could otherwise
/// blow up memory. New msg_ids above the cap are ignored; together with
/// `prune_old` the memory stays bounded.
const MAX_PENDING_MSGS: usize = 64;

/// Upper bound on the number of fragments a single message may claim, and on
/// the size of any one fragment's payload. Every real handshake message is a
/// fixed HANDSHAKE_MSG_LEN (8192 B), split into FRAG_PAYLOAD-sized (1024 B)
/// chunks — never more than 8 fragments in practice. Without this bound, a
/// single attacker-controlled datagram could claim `total` up to 65535 with a
/// payload up to the UDP_BUF (64 KB) each, letting one never-completed message
/// grow to several GB before `MAX_PENDING_MSGS` even applies (a State-Bloat-DoS
/// pre-authentication, since reassembly runs before the L-4 cookie check).
/// This mirrors `hsobf::MAX_FRAGMENTS`, which already enforces the same bound
/// on the obfuscated path — this closes the gap on the cleartext path.
const MAX_FRAGMENTS: u16 = 64;

const X25519_PUB_LEN: usize = 32;
const MLKEM_PK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;
const KEM_SLOT_LEN: usize = MLKEM_PK_LEN; // largest of pub/ct
const MAC_LEN: usize = 32;
/// Length of the return-routability cookie (L-4). HMAC-SHA256 over the source
/// address, truncated to 16 bytes — enough against forging, not in the transcript.
const COOKIE_LEN: usize = 16;

const FRAG_PAYLOAD: usize = 1024;
const FRAG_HEADER_LEN: usize = 8;

// ── Fragmentation (handshake only) ───────────────────────────────────────────

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
    /// Timestamp when the FIRST fragment arrived. Deliberately not
    /// refreshed on later fragments: otherwise an attacker could keep an
    /// incomplete entry alive forever by sending one fragment now and
    /// then (exactly the DoS we want to prevent).
    first_seen: std::time::Instant,
}

impl Reassembler {
    /// Cleartext path: parse the 8-byte fragment header and push the parts.
    /// Used by the non-obfuscated (fallback) handshake path.
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

    /// Push already-parsed fragment parts. Used by the obfuscated handshake
    /// path (hsobf.rs unmasks the header before this call). Same
    /// partial/complete logic as `push`, with a cap against msg_id floods.
    pub fn push_parts(
        &mut self,
        msg_id: u32,
        index: u16,
        total: u16,
        payload: Bytes,
    ) -> Result<Option<Bytes>> {
        if total == 0 || total > MAX_FRAGMENTS || index >= total {
            return Err(ChameleonError::Handshake {
                state: "reassemble".into(),
                msg: "invalid fragment index/total".into(),
            });
        }
        if payload.len() > FRAG_PAYLOAD {
            return Err(ChameleonError::Handshake {
                state: "reassemble".into(),
                msg: "fragment payload larger than any real handshake chunk".into(),
            });
        }
        // DoS cap: a NEW msg_id above the limit is ignored, so a stream of
        // random datagrams cannot blow up memory.
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

    /// Remove entries that stayed incomplete too long. Call this periodically
    /// (e.g. via a tokio interval) so half-finished messages don't keep
    /// holding memory — the State-Bloat-DoS fix.
    pub fn prune_old(&mut self, max_age: std::time::Duration) {
        let now = std::time::Instant::now();
        self.partials
            .retain(|_id, msg| now.duration_since(msg.first_seen) < max_age);
    }

    /// Number of incomplete messages currently in the buffer (for metrics/tests).
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
    /// Third message: the initiator proves its identity to the responder.
    /// Carries the initiator's signature over the full transcript.
    /// Makes the handshake mutually authenticated.
    Confirm = 0x03,
    /// Return-routability challenge (L-4): the responder sends this instead of a
    /// Response when the Init carries no valid cookie. Costs no handshake
    /// crypto; carries only the cookie (in the `cookie` field), the rest is noise.
    CookieChallenge = 0x04,
}

impl HandshakeType {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Init),
            0x02 => Ok(Self::Response),
            0x03 => Ok(Self::Confirm),
            0x04 => Ok(Self::CookieChallenge),
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
    /// Proposed/negotiated AEAD cipher (AeadAlgo wire-id). In Init the
    /// initiator's preference; in Response the final negotiated choice.
    /// Included in the transcript -> downgrade-resistant.
    pub aead_algo: u8,
    pub x25519_pub: [u8; X25519_PUB_LEN],
    pub kem: [u8; KEM_SLOT_LEN],
    pub sig: Vec<u8>,
    pub mac: [u8; MAC_LEN],
    /// Return-routability cookie (L-4). Zero in the first Init; filled by the
    /// initiator with the cookie issued by the responder on the retry. Not in the
    /// transcript — purely an anti-DoS token.
    pub cookie: [u8; COOKIE_LEN],
}

impl HandshakeMessage {
    fn fill_noise(buf: &mut [u8]) {
        rand::rngs::OsRng.fill_bytes(buf);
    }

    pub fn new_init(
        x25519_pub: [u8; X25519_PUB_LEN],
        mlkem_pub: &[u8],
        sig_len: usize,
        aead_algo: u8,
    ) -> Result<Self> {
        if mlkem_pub.len() != MLKEM_PK_LEN {
            return Err(ChameleonError::Handshake {
                state: "encode".into(),
                msg: "bad ML-KEM pub len".into(),
            });
        }
        let mut kem = [0u8; KEM_SLOT_LEN];
        kem.copy_from_slice(mlkem_pub);
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
            cookie: [0u8; COOKIE_LEN],
        })
    }

    pub fn new_response(
        x25519_pub: [u8; X25519_PUB_LEN],
        mlkem_ct: &[u8],
        sig_len: usize,
        aead_algo: u8,
    ) -> Result<Self> {
        if mlkem_ct.len() != MLKEM_CT_LEN {
            return Err(ChameleonError::Handshake {
                state: "encode".into(),
                msg: "bad ML-KEM ct len".into(),
            });
        }
        let mut kem = [0u8; KEM_SLOT_LEN];
        kem[..MLKEM_CT_LEN].copy_from_slice(mlkem_ct);
        Self::fill_noise(&mut kem[MLKEM_CT_LEN..]);
        Ok(Self {
            version: PROTO_VERSION,
            msg_type: HandshakeType::Response,
            aead_algo,
            x25519_pub,
            kem,
            sig: vec![0u8; sig_len],
            mac: [0u8; MAC_LEN],
            cookie: [0u8; COOKIE_LEN],
        })
    }

    pub fn mlkem_pub(&self) -> &[u8] {
        &self.kem[..MLKEM_PK_LEN]
    }
    pub fn mlkem_ct(&self) -> &[u8] {
        &self.kem[..MLKEM_CT_LEN]
    }

    /// Confirm message: carries only the initiator signature (+ MAC).
    /// x25519_pub and kem are noise — they carry no meaning in this phase
    /// and fall outside the transcript binding. The sig is set by the caller
    /// after computing the transcript.
    pub fn new_confirm(sig_len: usize) -> Result<Self> {
        let mut x25519_pub = [0u8; X25519_PUB_LEN];
        Self::fill_noise(&mut x25519_pub);
        let mut kem = [0u8; KEM_SLOT_LEN];
        Self::fill_noise(&mut kem);
        Ok(Self {
            version: PROTO_VERSION,
            msg_type: HandshakeType::Confirm,
            aead_algo: 0, // not applicable to Confirm
            x25519_pub,
            kem,
            sig: vec![0u8; sig_len],
            mac: [0u8; MAC_LEN],
            cookie: [0u8; COOKIE_LEN],
        })
    }

    /// Build a CookieChallenge (L-4): the responder sends this instead of a
    /// Response if the Init carries no valid cookie. Costs no handshake crypto —
    /// it carries only the issued `cookie`; x25519_pub/kem/mac are noise and the
    /// sig is empty, so on the wire (same 8192-byte size, obfuscated) it is
    /// indistinguishable from a real handshake.
    pub fn new_cookie_challenge(cookie: [u8; COOKIE_LEN]) -> Result<Self> {
        let mut x25519_pub = [0u8; X25519_PUB_LEN];
        Self::fill_noise(&mut x25519_pub);
        let mut kem = [0u8; KEM_SLOT_LEN];
        Self::fill_noise(&mut kem);
        let mut mac = [0u8; MAC_LEN];
        Self::fill_noise(&mut mac);
        Ok(Self {
            version: PROTO_VERSION,
            msg_type: HandshakeType::CookieChallenge,
            aead_algo: 0,
            x25519_pub,
            kem,
            sig: Vec::new(),
            mac,
            cookie,
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
        buf.put_slice(&self.cookie);
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
        if raw.remaining() < sig_len + MAC_LEN + COOKIE_LEN {
            return Err(ChameleonError::Handshake {
                state: "decode".into(),
                msg: "truncated sig/mac/cookie".into(),
            });
        }
        let mut sig = vec![0u8; sig_len];
        raw.copy_to_slice(&mut sig);
        let mut mac = [0u8; MAC_LEN];
        raw.copy_to_slice(&mut mac);
        let mut cookie = [0u8; COOKIE_LEN];
        raw.copy_to_slice(&mut cookie);
        Ok(Self {
            version,
            msg_type,
            aead_algo,
            x25519_pub,
            kem,
            sig,
            mac,
            cookie,
        })
    }

    pub fn transcript_bytes(&self) -> Bytes {
        let mut b = BytesMut::new();
        b.put_u8(self.version);
        b.put_u8(self.msg_type as u8);
        b.put_slice(&self.x25519_pub);
        match self.msg_type {
            HandshakeType::Init => {
                b.put_u8(self.aead_algo); // bind proposed cipher
                b.put_slice(self.mlkem_pub());
            }
            HandshakeType::Response => {
                b.put_u8(self.aead_algo); // bind negotiated cipher
                b.put_slice(self.mlkem_ct());
            }
            // Confirm adds no key material: the transcript is frozen after
            // the Response, and Confirm signs exactly that transcript.
            // This function should not be called on a Confirm/CookieChallenge,
            // but we keep the match complete and safe.
            HandshakeType::Confirm | HandshakeType::CookieChallenge => {}
        }
        b.freeze()
    }
}

// ── State machine ────────────────────────────────────────────────────────────
//
// Mutually authenticated 3-message handshake:
//
//   1. Init     (initiator -> responder)  : ephemeral keys
//   2. Response (responder -> initiator)  : ephemeral keys + responder sig
//   3. Confirm  (initiator -> responder)  : initiator sig over the transcript
//
// After Response the responder moves to SentResponse and does NOT TRUST the
// session until the Confirm signature checks out. This way both sides
// authenticate each other, not just the responder.

pub enum Handshake {
    Idle,
    /// Initiator: init sent, waiting for response.
    SentInit {
        eph_x: EphemeralSecret,
        // Boxed: the ML-KEM secret key is ~2.4 KB; kept inline it would make
        // every Handshake variant (and thus every move) needlessly large.
        eph_mlkem_sk: Box<mlkem768::SecretKey>,
        transcript: Transcript,
    },
    /// Responder: response sent, waiting for confirm. Holds the (not yet
    /// trusted) session and the transcript hash until the confirm checks out.
    SentResponse {
        session: Session,
        transcript_hash: [u8; 32],
    },
    /// Fully mutually authenticated.
    Established {
        session: Session,
    },
    Failed,
}

impl Handshake {
    pub fn start(auth: &dyn Authenticator) -> Result<(Self, Bytes)> {
        let eph_x = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let x_pub = XPub::from(&eph_x);
        let (eph_mlkem_pk, eph_mlkem_sk) = mlkem768::keypair();

        let msg = HandshakeMessage::new_init(
            x_pub.to_bytes(),
            eph_mlkem_pk.as_bytes(),
            auth.signature_len(),
            AeadAlgo::preferred().as_u8(),
        )?;
        let mut transcript = Transcript::new();
        // L-6: bind the identities (own + peer, symmetric) before the rest.
        transcript.absorb(&auth.identity_binding());
        transcript.absorb(&msg.transcript_bytes());
        let wire = msg.encode()?;
        Ok((
            Handshake::SentInit {
                eph_x,
                eph_mlkem_sk: Box::new(eph_mlkem_sk),
                transcript,
            },
            wire,
        ))
    }

    /// RESPONDER step 1: process Init, build Response. Moves to SentResponse
    /// (not yet Established — the initiator must prove itself first).
    pub fn respond(raw: Bytes, auth: &dyn Authenticator) -> Result<(Self, Bytes)> {
        let init = HandshakeMessage::decode(raw)?;
        if init.msg_type != HandshakeType::Init {
            return Err(ChameleonError::Handshake {
                state: "respond".into(),
                msg: "expected Init".into(),
            });
        }
        let peer_mlkem_pk = mlkem768::PublicKey::from_bytes(init.mlkem_pub()).map_err(|_| {
            ChameleonError::Handshake {
                state: "respond".into(),
                msg: "kem slot is not a valid ML-KEM public key".into(),
            }
        })?;

        let mut transcript = Transcript::new();
        // L-6: bind the identities (own + peer, symmetric) before the rest.
        transcript.absorb(&auth.identity_binding());
        transcript.absorb(&init.transcript_bytes());

        // Negotiate the cipher: initiator proposal vs. our own preference.
        // AEGIS only if both sides can do it, otherwise ChaCha20.
        let peer_pref = AeadAlgo::from_u8(init.aead_algo).unwrap_or(AeadAlgo::ChaCha20Poly1305);
        let chosen = AeadAlgo::negotiate(AeadAlgo::preferred(), peer_pref);

        let (mlkem_ss, mlkem_ct) = mlkem768::encapsulate(&peer_mlkem_pk);
        let eph_x = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let x_pub = XPub::from(&eph_x);
        let peer_x = XPub::from(init.x25519_pub);
        let x_ss = eph_x.diffie_hellman(&peer_x);
        // L-9: reject an all-zero (low-order/non-contributory) X25519 result.
        // Mitigated by the hybrid ML-KEM leg, but we fail explicitly here.
        if x_ss.as_bytes().iter().all(|&b| b == 0) {
            return Err(ChameleonError::Handshake {
                state: "respond".into(),
                msg: "X25519 shared secret is all-zero (low-order/non-contributory point)".into(),
            });
        }
        let shared = derive_shared(x_ss.as_bytes(), mlkem_ss.as_bytes());

        let mut resp = HandshakeMessage::new_response(
            x_pub.to_bytes(),
            mlkem_ct.as_bytes(),
            auth.signature_len(),
            chosen.as_u8(),
        )?;
        transcript.absorb(&resp.transcript_bytes());

        let th = transcript.hash();
        // Role-bound signature (L-5): responder signs SIG_LABEL_RESPONDER‖th.
        resp.sig = auth.sign(&role_bound_hash(SIG_LABEL_RESPONDER, &th))?;
        let mac_key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key_from(&shared));
        let tag = hmac::sign(&mac_key, &th);
        resp.mac.copy_from_slice(tag.as_ref());

        let wire = resp.encode()?;
        // I-13: the session_id comes from the shared secret; both sides derive
        // the same, so no process-global counter that can desync.
        let session_id = derive_session_id(&shared);
        let session = Session::from_handshake_with_algo(session_id, shared, false, chosen)?;
        // Store the transcript hash so we can verify the Confirm later.
        Ok((
            Handshake::SentResponse {
                session,
                transcript_hash: th,
            },
            wire,
        ))
    }

    /// INITIATOR step 2: process Response, verify responder, build Confirm.
    /// The initiator becomes Established (has authenticated the responder) AND
    /// produces the Confirm message it sends back so the responder can
    /// authenticate the initiator too.
    pub fn finalize(self, raw: Bytes, auth: &dyn Authenticator) -> Result<(Self, Bytes)> {
        let (eph_x, eph_mlkem_sk, mut transcript) = match self {
            Handshake::SentInit {
                eph_x,
                eph_mlkem_sk,
                transcript,
            } => (eph_x, eph_mlkem_sk, transcript),
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
        let ct = mlkem768::Ciphertext::from_bytes(resp.mlkem_ct()).map_err(|_| {
            ChameleonError::Handshake {
                state: "finalize".into(),
                msg: "kem slot is not a valid ML-KEM ciphertext".into(),
            }
        })?;
        let mlkem_ss = mlkem768::decapsulate(&ct, &eph_mlkem_sk);
        let peer_x = XPub::from(resp.x25519_pub);
        let x_ss = eph_x.diffie_hellman(&peer_x);
        // L-9: reject an all-zero (low-order/non-contributory) X25519 result.
        if x_ss.as_bytes().iter().all(|&b| b == 0) {
            return Err(ChameleonError::Handshake {
                state: "finalize".into(),
                msg: "X25519 shared secret is all-zero (low-order/non-contributory point)".into(),
            });
        }
        let shared = derive_shared(x_ss.as_bytes(), mlkem_ss.as_bytes());

        transcript.absorb(&resp.transcript_bytes());
        let th = transcript.hash();

        // Authenticate the RESPONDER via its role-bound signature (L-5).
        auth.verify(&role_bound_hash(SIG_LABEL_RESPONDER, &th), &resp.sig)?;
        let mac_key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key_from(&shared));
        hmac::verify(&mac_key, &th, &resp.mac).map_err(|_| ChameleonError::Handshake {
            state: "finalize".into(),
            msg: "MAC verification failed".into(),
        })?;

        // Build the Confirm message: our signature over the same transcript.
        // This is how the initiator proves its identity to the responder.
        let mut confirm = HandshakeMessage::new_confirm(auth.signature_len())?;
        // Role-bound signature (L-5): initiator signs SIG_LABEL_INITIATOR‖th.
        confirm.sig = auth.sign(&role_bound_hash(SIG_LABEL_INITIATOR, &th))?;
        let tag = hmac::sign(&mac_key, &th);
        confirm.mac.copy_from_slice(tag.as_ref());
        let wire = confirm.encode()?;

        // The responder chose the final cipher; read it from the
        // Response. That choice is in the transcript, so if an attacker had
        // changed it the MAC verification above would already fail.
        let chosen = AeadAlgo::from_u8(resp.aead_algo)?;
        // I-13: the same derived session_id as the responder (from `shared`).
        let session_id = derive_session_id(&shared);
        let session = Session::from_handshake_with_algo(session_id, shared, true, chosen)?;
        Ok((Handshake::Established { session }, wire))
    }

    /// RESPONDER step 2: process Confirm, authenticate the INITIATOR.
    /// Only after this is the session mutually authenticated and trusted.
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

        // Authenticate the INITIATOR via its role-bound signature (L-5) over
        // the transcript. This is what makes the handshake mutual: without a
        // valid initiator signature the session is NEVER trusted. The role
        // binding ensures the responder signature (over SIG_LABEL_RESPONDER‖th)
        // cannot be reflected here as initiator proof.
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
