//! Statische-sleutel obfuscatie voor de HANDSHAKE-envelope (Fase 2).
//!
//! ACHTERGROND: obf.rs verbergt het DATApad met een per-sessie sleutel. De
//! handshake heeft dat probleem niet opgelost: er is nog géén sessiesleutel
//! terwijl de handshake loopt. Toch lekte de handshake op de wire nog een
//! constant type-byte (0x02), genulde velden, een cleartext fragment-header
//! (msg_id/index/total) en een herkenbare burst van 8 vaste ~1032-byte
//! fragmenten. Deze laag maakt elk handshake-datagram tot een uniform-ogende
//! willekeurige bytereeks.
//!
//! SLEUTEL: afgeleid uit VOORAF GEDEELD materiaal (obfs4-stijl), want er is nog
//! geen sessiegeheim. Standaard uit de al voorgedeelde Ed25519-pubkeys; met een
//! optionele `[obfuscation].psk_hex` als sterker geheim. Beide kanten leiden
//! dezelfde sleutel af (de pubkeys worden byte-lexicografisch gesorteerd, dus
//! symmetrisch).
//!
//! CONSTRUCTIE (wrap-then-fragment): verzegel het volledige 8192-byte
//! HandshakeMessage-blob met ChaCha20-Poly1305 onder de statische sleutel
//! (random 12-byte nonce), fragmenteer DAARNA in wisselend-grote stukken, en
//! maskeer de fragment-header. De ontvanger herassembleert blind op de
//! (cleartext, willekeurige) msg_id, opent met de statische sleutel, en draait
//! dan de gewone HandshakeMessage::decode.
//!
//! EERLIJKE GRENS: dit is OBFUSCATIE, geen extra beveiliging. De statische
//! sleutel geeft géén forward secrecy en géén echte authenticatie — de échte
//! handshake-crypto (Kyber+X25519 ephemeral, transcript-ondertekening in
//! tunnel.rs) blijft ongewijzigd en levert alle daadwerkelijke veiligheid. Een
//! tegenstander die beide pubkeys al heeft kan de-obfusceren (gebruik dan
//! psk_hex). De ~8 KB totale omvang en de 2-RTT burst-timing blijven zichtbaar;
//! cover traffic / pacing is geen onderdeel van deze fase.

use crate::error::{ChameleonError, Result};
use bytes::{Bytes, BytesMut};
use rand::{rngs::OsRng, Rng, RngCore};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::hmac;
use zeroize::Zeroizing;

/// ChaCha20-Poly1305 nonce- en taglengtes (via `ring`, net als aead.rs).
pub const HS_NONCE_LEN: usize = 12;
pub const HS_TAG_LEN: usize = 16;
/// Fragment-header: msg_id(4) ‖ gemaskeerd(index(2) ‖ total(2)).
pub const HS_FRAG_HEADER_LEN: usize = 8;

/// Grenzen voor de wisselend-grote fragmentatie. Alles ruim onder de 1280-MTU
/// (wire = HS_FRAG_HEADER_LEN + chunk), zodat padding/fragmentatie de
/// datagrammen nooit over de MTU duwt.
const MIN_CHUNK: usize = 512;
const MAX_CHUNK: usize = 1024;

/// Bovengrens op het aantal fragmenten per bericht — een goedkope ruis-poort in
/// `unmask_fragment` tegen een vervalste `total` die de reassembler zou laten
/// wachten op absurd veel stukken. Ruim boven wat een 8 KB-handshake nodig heeft
/// (≈9–16 fragmenten van MIN_CHUNK..MAX_CHUNK).
pub const MAX_FRAGMENTS: u16 = 64;

/// Leid de statische handshake-obfuscatiesleutel af. Symmetrisch: beide kanten
/// komen op dezelfde 32 bytes uit. Met `psk` gezet is dat het IKM; anders de
/// byte-lexicografisch gesorteerde Ed25519-pubkeys.
pub fn derive_hs_obf_key(
    own_ed_pub: &[u8; 32],
    peer_ed_pub: &[u8; 32],
    psk: Option<&[u8]>,
) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let ikm: Zeroizing<Vec<u8>> = match psk {
        Some(p) => Zeroizing::new(p.to_vec()),
        None => {
            // Sorteer zodat initiator en responder dezelfde volgorde gebruiken.
            let (lo, hi) = if own_ed_pub <= peer_ed_pub {
                (own_ed_pub, peer_ed_pub)
            } else {
                (peer_ed_pub, own_ed_pub)
            };
            let mut v = Vec::with_capacity(64);
            v.extend_from_slice(lo);
            v.extend_from_slice(hi);
            Zeroizing::new(v)
        }
    };

    let hk = Hkdf::<Sha256>::new(Some(b"Chameleon-PQ-v1-hs-obf"), &ikm);
    let mut key = [0u8; 32];
    hk.expand(b"handshake obfuscation key", &mut key)
        .expect("32 is a valid HKDF output length");
    key
}

/// Het 4-byte header-masker voor een bericht, gekeyed op de sleutel + msg_id.
/// Alle fragmenten van hetzelfde bericht delen dit masker (msg_id is constant
/// binnen een bericht); de ontvanger kan het herberekenen omdat msg_id cleartext
/// is. Reikt niet aan de AEAD-authenticatie — dat is de tag in `open`.
fn frag_mask(key: &[u8; 32], msg_id: u32) -> [u8; 4] {
    let mac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&mac_key, &msg_id.to_le_bytes());
    let mut m = [0u8; 4];
    m.copy_from_slice(&tag.as_ref()[..4]);
    m
}

/// Bouw de LessSafeKey voor de statische obfuscatie-cipher (ChaCha20-Poly1305).
fn cipher(key: &[u8; 32]) -> Result<LessSafeKey> {
    let ubk = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|_| ChameleonError::Kdf("hs-obf key".into()))?;
    Ok(LessSafeKey::new(ubk))
}

/// UITGAAND: verzegel het volledige HandshakeMessage-blob en splits het in
/// wisselend-grote, gemaskeerde fragmenten die wire-klaar zijn.
pub fn seal_and_fragment(hs_obf_key: &[u8; 32], msg: &[u8]) -> Result<Vec<Bytes>> {
    // 1. Verzegel: blob = nonce(12) ‖ ciphertext+tag.
    let mut nonce_bytes = [0u8; HS_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let lk = cipher(hs_obf_key)?;
    let mut sealed = msg.to_vec();
    lk.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::empty(),
        &mut sealed,
    )
    .map_err(|_| ChameleonError::DecryptionFailed)?;
    let mut blob = Vec::with_capacity(HS_NONCE_LEN + sealed.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&sealed);

    // 2. Wisselend-grote fragmentatie (varieert aantal én maten per handshake).
    let msg_id: u32 = OsRng.next_u32();
    let mask = frag_mask(hs_obf_key, msg_id);
    let chunks = variable_chunks(&blob);
    let total = chunks.len() as u16;
    debug_assert!(total <= MAX_FRAGMENTS, "fragmentatie binnen de cap");

    let mut out = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.iter().enumerate() {
        let index = i as u16;
        let mut hdr = [0u8; HS_FRAG_HEADER_LEN];
        hdr[0..4].copy_from_slice(&msg_id.to_le_bytes());
        // gemaskeerd: index(2 LE) ‖ total(2 LE) XOR mask
        let it = [
            index as u8,
            (index >> 8) as u8,
            total as u8,
            (total >> 8) as u8,
        ];
        for k in 0..4 {
            hdr[4 + k] = it[k] ^ mask[k];
        }
        let mut buf = BytesMut::with_capacity(HS_FRAG_HEADER_LEN + chunk.len());
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(chunk);
        out.push(buf.freeze());
    }
    Ok(out)
}

/// Splits `blob` in stukken van wisselende grootte in [MIN_CHUNK, MAX_CHUNK].
/// Het laatste stuk is de rest (≤ MAX_CHUNK), zelf variabel omdat de eerdere
/// maten willekeurig zijn — dus geen vaste "klein laatste fragment"-signatuur.
fn variable_chunks(blob: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while blob.len() - off > MAX_CHUNK {
        let take = OsRng.gen_range(MIN_CHUNK..=MAX_CHUNK);
        out.push(&blob[off..off + take]);
        off += take;
    }
    out.push(&blob[off..]);
    out
}

/// INKOMEND: win uit één datagram de fragment-header terug (msg_id cleartext,
/// index/total ontmaskerd). `None` bij een te kort datagram of een onmogelijke
/// index/total — een goedkope, panic-vrije ruis-poort. Doet GEEN AEAD-open.
pub fn unmask_fragment(hs_obf_key: &[u8; 32], raw: &[u8]) -> Option<(u32, u16, u16, Bytes)> {
    if raw.len() < HS_FRAG_HEADER_LEN {
        return None;
    }
    let msg_id = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let mask = frag_mask(hs_obf_key, msg_id);
    let index = u16::from_le_bytes([raw[4] ^ mask[0], raw[5] ^ mask[1]]);
    let total = u16::from_le_bytes([raw[6] ^ mask[2], raw[7] ^ mask[3]]);
    if total == 0 || total > MAX_FRAGMENTS || index >= total {
        return None;
    }
    Some((
        msg_id,
        index,
        total,
        Bytes::copy_from_slice(&raw[HS_FRAG_HEADER_LEN..]),
    ))
}

/// Open een volledig herassembleerd blob terug naar het originele bericht.
/// `Err` bij een tag-mismatch — d.w.z. niet voor ons / ruis / verkeerde sleutel.
pub fn open(hs_obf_key: &[u8; 32], reassembled: &[u8]) -> Result<Bytes> {
    if reassembled.len() < HS_NONCE_LEN + HS_TAG_LEN {
        return Err(ChameleonError::DecryptionFailed);
    }
    let (nonce_bytes, ct) = reassembled.split_at(HS_NONCE_LEN);
    let lk = cipher(hs_obf_key)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| ChameleonError::DecryptionFailed)?;
    let mut buf = ct.to_vec();
    let plain = lk
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| ChameleonError::DecryptionFailed)?;
    Ok(Bytes::copy_from_slice(plain))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reassemble(frags: &[(u32, u16, u16, Bytes)]) -> Bytes {
        // Sorteer op index en concateneer (zoals de Reassembler blind doet).
        let total = frags[0].2 as usize;
        let mut parts: Vec<Option<&Bytes>> = vec![None; total];
        for (_id, idx, _tot, chunk) in frags {
            parts[*idx as usize] = Some(chunk);
        }
        let mut out = BytesMut::new();
        for p in parts {
            out.extend_from_slice(p.expect("compleet"));
        }
        out.freeze()
    }

    #[test]
    fn derive_is_symmetric_pubkeys() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        // Beide kanten (own/peer omgewisseld) leiden dezelfde sleutel af.
        assert_eq!(
            derive_hs_obf_key(&a, &b, None),
            derive_hs_obf_key(&b, &a, None)
        );
    }

    #[test]
    fn derive_psk_overrides_and_symmetric() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let psk = [0x99u8; 32];
        let k1 = derive_hs_obf_key(&a, &b, Some(&psk));
        let k2 = derive_hs_obf_key(&b, &a, Some(&psk));
        assert_eq!(k1, k2);
        // PSK-sleutel verschilt van de pubkey-afgeleide.
        assert_ne!(k1, derive_hs_obf_key(&a, &b, None));
    }

    #[test]
    fn seal_fragment_reassemble_open_roundtrip() {
        let key = [0x33u8; 32];
        let msg = vec![0xABu8; 8192]; // volle handshake-grootte
        let frags = seal_and_fragment(&key, &msg).unwrap();
        assert!(frags.len() >= 2, "8 KB fragmenteert");

        let recovered: Vec<_> = frags
            .iter()
            .map(|f| unmask_fragment(&key, f).expect("geldig fragment"))
            .collect();
        // Alle fragmenten delen dezelfde msg_id en total.
        let total = recovered[0].2;
        assert!(recovered.iter().all(|r| r.2 == total));
        assert_eq!(total as usize, frags.len());

        let blob = reassemble(&recovered);
        let opened = open(&key, &blob).unwrap();
        assert_eq!(&opened[..], &msg[..]);
    }

    #[test]
    fn fragment_count_and_sizes_vary() {
        let key = [0x44u8; 32];
        let msg = vec![0u8; 8192];
        // Over meerdere runs varieert het aantal fragmenten (jitter).
        let mut counts = std::collections::HashSet::new();
        for _ in 0..12 {
            counts.insert(seal_and_fragment(&key, &msg).unwrap().len());
        }
        assert!(counts.len() > 1, "aantal fragmenten varieert per handshake");
    }

    #[test]
    fn wrong_key_open_fails() {
        let key = [0x55u8; 32];
        let msg = vec![0x5Au8; 4096];
        let frags = seal_and_fragment(&key, &msg).unwrap();
        let recovered: Vec<_> = frags
            .iter()
            .map(|f| unmask_fragment(&key, f).unwrap())
            .collect();
        let blob = reassemble(&recovered);
        // Verkeerde sleutel -> tag-mismatch.
        assert!(open(&[0x56u8; 32], &blob).is_err());
    }

    #[test]
    fn unmask_rejects_short_and_bad() {
        let key = [0x66u8; 32];
        assert!(unmask_fragment(&key, &[0u8; HS_FRAG_HEADER_LEN - 1]).is_none());
        // Een geldig fragment ontmaskert wél.
        let frags = seal_and_fragment(&key, &vec![1u8; 2048]).unwrap();
        assert!(unmask_fragment(&key, &frags[0]).is_some());
    }
}
