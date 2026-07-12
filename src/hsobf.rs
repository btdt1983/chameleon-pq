//! Static-key obfuscation for the HANDSHAKE envelope (Phase 2).
//!
//! BACKGROUND: obf.rs hides the DATA path with a per-session key. The handshake
//! did not solve that problem: there is no session key yet while the handshake
//! is running. Still, the handshake leaked on the wire a constant type-byte
//! (0x02), zeroed fields, a cleartext fragment-header (msg_id/index/total) and
//! a recognizable burst of 8 fixed ~1032-byte fragments. This layer turns every
//! handshake-datagram into a uniform-looking random byte sequence.
//!
//! KEY: derived from PRE-SHARED material (obfs4-style), because there is no
//! session secret yet. By default from the already pre-shared Ed25519-pubkeys;
//! with an optional `[obfuscation].psk_hex` as a stronger secret. Both sides
//! derive the same key (the pubkeys are sorted byte-lexicographically, so it is
//! symmetric).
//!
//! CONSTRUCTION (wrap-then-fragment): seal the full 8192-byte HandshakeMessage
//! blob with ChaCha20-Poly1305 under the static key (random 12-byte nonce),
//! THEN fragment into variable-sized chunks, and mask the fragment-header. The
//! receiver reassembles blindly on the (cleartext, random) msg_id, opens with
//! the static key, and then runs the ordinary HandshakeMessage::decode.
//!
//! HONEST LIMIT: this is OBFUSCATION, not extra security. The static key gives
//! no forward secrecy and no real authentication — the real handshake-crypto
//! (ML-KEM+X25519 ephemeral, transcript-signing in tunnel.rs) stays unchanged
//! and provides all the actual security. An adversary who already has both
//! pubkeys can de-obfuscate (use psk_hex then). The ~8 KB total size and the
//! 2-RTT burst-timing stay visible; cover traffic / pacing is not part of this
//! phase.

use crate::error::{ChameleonError, Result};
use bytes::{Bytes, BytesMut};
use rand::{rngs::OsRng, Rng, RngCore};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::hmac;
use zeroize::Zeroizing;

/// ChaCha20-Poly1305 nonce- and tag-lengths (via `ring`, like aead.rs).
pub const HS_NONCE_LEN: usize = 12;
pub const HS_TAG_LEN: usize = 16;
/// Fragment-header: msg_id(4) ‖ masked(index(2) ‖ total(2)).
pub const HS_FRAG_HEADER_LEN: usize = 8;

/// Bounds for the variable-sized fragmentation. Everything well below the
/// 1280-MTU (wire = HS_FRAG_HEADER_LEN + chunk), so padding/fragmentation never
/// pushes the datagrams over the MTU.
const MIN_CHUNK: usize = 512;
const MAX_CHUNK: usize = 1024;

/// Upper bound on the number of fragments per message — a cheap noise-gate in
/// `unmask_fragment` against a forged `total` that would make the reassembler
/// wait for absurdly many chunks. Well above what an 8 KB-handshake needs
/// (≈9–16 fragments of MIN_CHUNK..MAX_CHUNK).
pub const MAX_FRAGMENTS: u16 = 64;

/// Derive the static handshake-obfuscation key. Symmetric: both sides arrive at
/// the same 32 bytes. With `psk` set that is the IKM; otherwise the
/// byte-lexicographically sorted Ed25519-pubkeys.
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
            // Sort so initiator and responder use the same order.
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

/// The 4-byte header-mask for a message, keyed on the key + msg_id. All
/// fragments of the same message share this mask (msg_id is constant within a
/// message); the receiver can recompute it because msg_id is cleartext. Does
/// not reach the AEAD-authentication — that is the tag in `open`.
fn frag_mask(key: &[u8; 32], msg_id: u32) -> [u8; 4] {
    let mac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&mac_key, &msg_id.to_le_bytes());
    let mut m = [0u8; 4];
    m.copy_from_slice(&tag.as_ref()[..4]);
    m
}

/// Build the LessSafeKey for the static obfuscation-cipher (ChaCha20-Poly1305).
fn cipher(key: &[u8; 32]) -> Result<LessSafeKey> {
    let ubk = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|_| ChameleonError::Kdf("hs-obf key".into()))?;
    Ok(LessSafeKey::new(ubk))
}

/// OUTGOING: seal the full HandshakeMessage-blob and split it into
/// variable-sized, masked fragments that are wire-ready.
pub fn seal_and_fragment(hs_obf_key: &[u8; 32], msg: &[u8]) -> Result<Vec<Bytes>> {
    // 1. Seal: blob = nonce(12) ‖ ciphertext+tag.
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

    // 2. Variable-sized fragmentation (varies count and sizes per handshake).
    let msg_id: u32 = OsRng.next_u32();
    let mask = frag_mask(hs_obf_key, msg_id);
    let chunks = variable_chunks(&blob);
    let total = chunks.len() as u16;
    debug_assert!(total <= MAX_FRAGMENTS, "fragmentation within the cap");

    let mut out = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.iter().enumerate() {
        let index = i as u16;
        let mut hdr = [0u8; HS_FRAG_HEADER_LEN];
        hdr[0..4].copy_from_slice(&msg_id.to_le_bytes());
        // masked: index(2 LE) ‖ total(2 LE) XOR mask
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

/// Split `blob` into chunks of varying size in [MIN_CHUNK, MAX_CHUNK]. The last
/// chunk is the remainder (≤ MAX_CHUNK), itself variable because the earlier
/// sizes are random — so no fixed "small last fragment" signature.
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

/// INCOMING: recover the fragment-header from a single datagram (msg_id
/// cleartext, index/total unmasked). `None` for a too-short datagram or an
/// impossible index/total — a cheap, panic-free noise-gate. Does NO AEAD-open.
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

/// Open a fully reassembled blob back into the original message. `Err` on a
/// tag-mismatch — i.e. not for us / noise / wrong key.
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
        // Sort by index and concatenate (as the Reassembler does blindly).
        let total = frags[0].2 as usize;
        let mut parts: Vec<Option<&Bytes>> = vec![None; total];
        for (_id, idx, _tot, chunk) in frags {
            parts[*idx as usize] = Some(chunk);
        }
        let mut out = BytesMut::new();
        for p in parts {
            out.extend_from_slice(p.expect("complete"));
        }
        out.freeze()
    }

    #[test]
    fn derive_is_symmetric_pubkeys() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        // Both sides (own/peer swapped) derive the same key.
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
        // PSK-key differs from the pubkey-derived one.
        assert_ne!(k1, derive_hs_obf_key(&a, &b, None));
    }

    #[test]
    fn seal_fragment_reassemble_open_roundtrip() {
        let key = [0x33u8; 32];
        let msg = vec![0xABu8; 8192]; // full handshake size
        let frags = seal_and_fragment(&key, &msg).unwrap();
        assert!(frags.len() >= 2, "8 KB fragments");

        let recovered: Vec<_> = frags
            .iter()
            .map(|f| unmask_fragment(&key, f).expect("valid fragment"))
            .collect();
        // All fragments share the same msg_id and total.
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
        // Across multiple runs the fragment count varies (jitter).
        let mut counts = std::collections::HashSet::new();
        for _ in 0..12 {
            counts.insert(seal_and_fragment(&key, &msg).unwrap().len());
        }
        assert!(counts.len() > 1, "fragment count varies per handshake");
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
        // Wrong key -> tag-mismatch.
        assert!(open(&[0x56u8; 32], &blob).is_err());
    }

    #[test]
    fn unmask_rejects_short_and_bad() {
        let key = [0x66u8; 32];
        assert!(unmask_fragment(&key, &[0u8; HS_FRAG_HEADER_LEN - 1]).is_none());
        // A valid fragment does unmask.
        let frags = seal_and_fragment(&key, &vec![1u8; 2048]).unwrap();
        assert!(unmask_fragment(&key, &frags[0]).is_some());
    }
}
