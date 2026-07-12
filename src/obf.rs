//! Obfuscation layer for the DATA path: QUIC-style header-protection + padding.
//!
//! BACKGROUND: the old data-path frame (frame.rs) still showed on the wire a
//! constant type-byte (0x01), a constant session_id for the whole session and
//! a monotonically increasing counter. That is — even without a static magic —
//! a trivially matchable stream fingerprint, and the packet length leaked the
//! plaintext length exactly. This layer turns every data-path datagram on the
//! wire into a uniform-looking random byte sequence: no fixed byte, no visible
//! session_id, no visible counter, no visible frame-type, and (via padding) no
//! exact length.
//!
//! HOW (following RFC 9001 §5.4, QUIC header-protection):
//!   1. The inner AEAD/nonce/replay core in session.rs stays UNCHANGED. We
//!      encrypt the plaintext exactly as before (aad = the logical header
//!      H = [0x01, session_id, counter]).
//!   2. From the resulting ciphertext+tag we take a `sample` (the last 16
//!      bytes, always within the AEAD-tag) and derive a 13-byte mask from it:
//!      mask = HMAC-SHA256(obf_key, sample)[..13].
//!   3. The visible header becomes masked_H = H XOR mask. Wire = masked_H ‖ ct.
//!
//! The header integrity comes NOT from the (malleable) XOR mask but from the
//! fact that the receiver passes the recovered H as AEAD-aad: tampering with
//! masked_H or with ct yields a wrong counter/session or a broken tag — in both
//! cases the AEAD verification fails. Exactly like QUIC: the mask is pure
//! confidentiality, the tag is the authentication.
//!
//! The real frame-type (Data/KeepAlive/Close) sits in the INNER framing
//! (pack_inner), encrypted within the AEAD-plaintext, so that on the wire every
//! datagram is structurally identical and the type never leaks.

use crate::error::{ChameleonError, Result};
use crate::frame::HEADER_LEN;
use bytes::Bytes;
use rand::RngCore;
use ring::hmac;

/// Number of bytes we sample from the ciphertext tail for the mask. 16 always
/// fits within the AEAD-tag (ChaCha20 tag = 16, AEGIS = 32), even with empty
/// plaintext (keepalive), so it is uniform across both ciphers.
pub const SAMPLE_LEN: usize = 16;

/// Length of the masked header on the wire — equal to the old cleartext
/// frame-header (type ‖ session_id ‖ counter), so the wire-overhead is +0.
pub const HP_HEADER_LEN: usize = HEADER_LEN; // 13

/// MTU-safe wire-size for the data path (frame::MAX_PAYLOAD + HEADER_LEN).
pub const MTU_WIRE: usize = 1280;

/// On the wire every obfuscated datagram ALWAYS carries the Data domain (0x01).
/// The real type is encrypted in the inner framing. This is also the aad-type-
/// byte that session.rs::data_aad hardcodes, so the masked header masks exactly
/// the bytes that are authenticated as aad.
const WIRE_TYPE_DATA: u8 = 0x01;

/// Minimum size of the inner framing: inner_type(1) + real_len(2).
const INNER_HEADER_LEN: usize = 3;

/// Padding policy for the data path. Configurable via config; hides the packet
/// size (which otherwise leaks the plaintext length exactly) at the cost of
/// bandwidth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PadPolicy {
    /// No padding — lowest overhead, but the size reveals the length.
    Off,
    /// Pad to size classes (see `BUCKETS`): hides the exact length, moderate
    /// overhead. The default.
    Bucketed,
    /// Pad every packet to the maximum MTU-safe size: best size-obfuscation,
    /// highest bandwidth cost.
    Full,
}

impl From<crate::config::PaddingPolicy> for PadPolicy {
    fn from(p: crate::config::PaddingPolicy) -> Self {
        match p {
            crate::config::PaddingPolicy::Off => PadPolicy::Off,
            crate::config::PaddingPolicy::Bucketed => PadPolicy::Bucketed,
            crate::config::PaddingPolicy::Full => PadPolicy::Full,
        }
    }
}

/// Size classes (on the INNER framed-length) for Bucketed padding. Deliberately
/// kept small: all well below the MTU-safe limit, so padding never pushes the
/// datagrams over the MTU (extra IP-fragmentation is itself a fingerprint).
/// Packets larger than the top class are not padded.
const BUCKETS: [usize; 5] = [64, 128, 256, 512, 1024];

/// Maximum inner framed-length that still fits in an MTU-safe wire-datagram,
/// given the tag-length of the chosen cipher.
pub fn max_framed(tag_len: usize) -> usize {
    MTU_WIRE
        .saturating_sub(HP_HEADER_LEN)
        .saturating_sub(tag_len)
}

/// What the receiver recovers from the masked header. Contains NO plaintext:
/// the AEAD-open (in session.rs) happens afterwards with the recovered counter.
pub struct Recovered {
    /// Wire-type domain (should be 0x01 = Data). Purely for a sanity-check;
    /// the real authentication is the AEAD-tag.
    pub wire_type: u8,
    pub session_id: u32,
    pub counter: u64,
}

/// Derive the 13-byte header-mask from the ciphertext-sample.
fn header_mask(obf_key: &[u8; 32], sample: &[u8]) -> [u8; HP_HEADER_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, obf_key);
    let tag = hmac::sign(&key, sample);
    let mut mask = [0u8; HP_HEADER_LEN];
    mask.copy_from_slice(&tag.as_ref()[..HP_HEADER_LEN]);
    mask
}

/// The ciphertext tail that serves as the sample. Assumption: `ct.len() >=
/// SAMPLE_LEN` (always true — the AEAD-tag alone is ≥16 bytes).
fn sample_of(ct: &[u8]) -> &[u8] {
    &ct[ct.len() - SAMPLE_LEN..]
}

/// OUTGOING: given the already-sealed ciphertext+tag, build the wire-datagram
/// `masked_H ‖ ct`. `counter`/`session_id` belong to the nonce/aad with which
/// `ct` was sealed.
pub fn seal_wire(obf_key: &[u8; 32], session_id: u32, counter: u64, ct: &[u8]) -> Bytes {
    debug_assert!(ct.len() >= SAMPLE_LEN, "ct at least one AEAD tag long");
    let mut h = [0u8; HP_HEADER_LEN];
    h[0] = WIRE_TYPE_DATA;
    h[1..5].copy_from_slice(&session_id.to_le_bytes());
    h[5..13].copy_from_slice(&counter.to_le_bytes());

    let mask = header_mask(obf_key, sample_of(ct));
    for i in 0..HP_HEADER_LEN {
        h[i] ^= mask[i];
    }

    let mut out = Vec::with_capacity(HP_HEADER_LEN + ct.len());
    out.extend_from_slice(&h);
    out.extend_from_slice(ct);
    Bytes::from(out)
}

/// INCOMING: recover the header from a single candidate-obf_key. Does NO
/// AEAD-open (session.rs does that with the recovered counter). Returns `None`
/// for a too-short datagram — a cheap, panic-free gate against noise/short
/// packets.
pub fn unmask(obf_key: &[u8; 32], datagram: &[u8]) -> Option<Recovered> {
    if datagram.len() < HP_HEADER_LEN + SAMPLE_LEN {
        return None;
    }
    let mask = header_mask(obf_key, sample_of(datagram));
    let mut h = [0u8; HP_HEADER_LEN];
    for i in 0..HP_HEADER_LEN {
        h[i] = datagram[i] ^ mask[i];
    }
    Some(Recovered {
        wire_type: h[0],
        session_id: u32::from_le_bytes(h[1..5].try_into().unwrap()),
        counter: u64::from_le_bytes(h[5..13].try_into().unwrap()),
    })
}

/// The ciphertext (after the 13-byte header) of an incoming datagram.
/// The caller must already have gated the minimum length via `unmask`.
pub fn ct_slice(datagram: &[u8]) -> &[u8] {
    &datagram[HP_HEADER_LEN..]
}

/// Pack the plaintext into the inner framing (which is sealed afterwards):
/// `inner_type(1) ‖ real_len(2 LE) ‖ plaintext ‖ random_pad`. The real type is
/// baked in here, so it does not leak on the wire. `max_framed` bounds the
/// padding so the wire-datagram stays MTU-safe.
pub fn pack_inner(
    inner_type: u8,
    plaintext: &[u8],
    policy: PadPolicy,
    max_framed: usize,
) -> Vec<u8> {
    // Data-path payloads are MTU-bounded; real_len fits easily in a u16.
    debug_assert!(plaintext.len() <= u16::MAX as usize);
    let real_len = plaintext.len();
    let base = INNER_HEADER_LEN + real_len;
    let target = pad_target(base, policy, max_framed);

    let mut buf = Vec::with_capacity(target);
    buf.push(inner_type);
    buf.extend_from_slice(&(real_len as u16).to_le_bytes());
    buf.extend_from_slice(plaintext);
    if target > base {
        let mut pad = vec![0u8; target - base];
        rand::rngs::OsRng.fill_bytes(&mut pad);
        buf.extend_from_slice(&pad);
    }
    buf
}

/// Choose the target length for the inner framing according to the padding
/// policy.
fn pad_target(base: usize, policy: PadPolicy, max_framed: usize) -> usize {
    match policy {
        PadPolicy::Off => base,
        PadPolicy::Full => {
            if base <= max_framed {
                max_framed
            } else {
                base // already larger than MTU-safe: don't inflate further
            }
        }
        PadPolicy::Bucketed => {
            for &b in BUCKETS.iter() {
                if b >= base && b <= max_framed {
                    return b;
                }
            }
            base // larger than the top class (or than MTU): don't pad
        }
    }
}

/// Unpack the inner framing again after a successful AEAD-open: return
/// (inner_type, plaintext), with the padding stripped.
pub fn unpack_inner(framed: &[u8]) -> Result<(u8, Bytes)> {
    if framed.len() < INNER_HEADER_LEN {
        return Err(ChameleonError::PacketTooShort {
            got: framed.len(),
            need: INNER_HEADER_LEN,
        });
    }
    let inner_type = framed[0];
    let real_len = u16::from_le_bytes([framed[1], framed[2]]) as usize;
    let end = INNER_HEADER_LEN + real_len;
    if end > framed.len() {
        // real_len points beyond the buffer — corrupt/malicious.
        return Err(ChameleonError::DecryptionFailed);
    }
    Ok((
        inner_type,
        Bytes::copy_from_slice(&framed[INNER_HEADER_LEN..end]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fake ciphertext of >= SAMPLE_LEN bytes for the masking tests
    // (the masking layer is independent of the AEAD; the end-to-end AEAD-tests
    // live in tests/integration.rs).
    fn fake_ct(len: usize, fill: u8) -> Vec<u8> {
        vec![fill; len]
    }

    #[test]
    fn seal_unmask_roundtrip() {
        let key = [0x11u8; 32];
        let ct = fake_ct(40, 0xAB);
        let wire = seal_wire(&key, 0xDEADBEEF, 0x0102030405060708, &ct);
        // Header is 13 bytes; rest == ct.
        assert_eq!(wire.len(), HP_HEADER_LEN + ct.len());
        assert_eq!(ct_slice(&wire), &ct[..]);

        let rec = unmask(&key, &wire).expect("long enough");
        assert_eq!(rec.wire_type, WIRE_TYPE_DATA);
        assert_eq!(rec.session_id, 0xDEADBEEF);
        assert_eq!(rec.counter, 0x0102030405060708);
    }

    #[test]
    fn wire_header_is_not_plaintext_0x01() {
        // The first byte on the wire must NOT be the constant 0x01: it is
        // masked. (The chance it is coincidentally 0x01 is ~1/256 — we pick a
        // ct where that is not the case and mainly check it differs from H[0].)
        let key = [0x22u8; 32];
        let ct = fake_ct(32, 0x5C);
        let wire = seal_wire(&key, 7, 1, &ct);
        let mask = header_mask(&key, sample_of(&ct));
        assert_eq!(wire[0], WIRE_TYPE_DATA ^ mask[0]);
    }

    #[test]
    fn tamper_masked_header_changes_recovery() {
        let key = [0x33u8; 32];
        let ct = fake_ct(48, 0x77);
        let mut wire = seal_wire(&key, 100, 200, &ct).to_vec();
        // Tamper with the session_id field in the masked header.
        wire[2] ^= 0xFF;
        let rec = unmask(&key, &wire).unwrap();
        // The recovered session differs -> in practice it falls outside the
        // candidate and/or the AEAD-open fails. Here: recovery != original.
        assert_ne!(rec.session_id, 100);
    }

    #[test]
    fn min_length_gate_returns_none() {
        let key = [0x44u8; 32];
        assert!(unmask(&key, &[0u8; HP_HEADER_LEN]).is_none());
        assert!(unmask(&key, &[0u8; HP_HEADER_LEN + SAMPLE_LEN - 1]).is_none());
        assert!(unmask(&key, &[0u8; HP_HEADER_LEN + SAMPLE_LEN]).is_some());
    }

    #[test]
    fn pack_unpack_roundtrip_no_pad() {
        let framed = pack_inner(0x03, b"", PadPolicy::Off, max_framed(16));
        // Off: only inner header (3) + 0 plaintext.
        assert_eq!(framed.len(), INNER_HEADER_LEN);
        let (t, pt) = unpack_inner(&framed).unwrap();
        assert_eq!(t, 0x03);
        assert!(pt.is_empty());

        let framed = pack_inner(0x01, b"hello", PadPolicy::Off, max_framed(16));
        let (t, pt) = unpack_inner(&framed).unwrap();
        assert_eq!(t, 0x01);
        assert_eq!(&pt[..], b"hello");
    }

    #[test]
    fn bucketed_padding_rounds_up_and_strips() {
        let mf = max_framed(16);
        let framed = pack_inner(0x01, b"short", PadPolicy::Bucketed, mf);
        // base = 3 + 5 = 8 -> first bucket 64.
        assert_eq!(framed.len(), 64);
        let (t, pt) = unpack_inner(&framed).unwrap();
        assert_eq!(t, 0x01);
        assert_eq!(&pt[..], b"short");
    }

    #[test]
    fn full_padding_hides_length() {
        let mf = max_framed(16);
        let a = pack_inner(0x01, b"x", PadPolicy::Full, mf);
        let b = pack_inner(0x01, &vec![0u8; 500], PadPolicy::Full, mf);
        // Both padded to the same max_framed -> equal length (size hidden).
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), mf);
        // And the payloads come back exactly.
        assert_eq!(&unpack_inner(&a).unwrap().1[..], b"x");
        assert_eq!(unpack_inner(&b).unwrap().1.len(), 500);
    }

    #[test]
    fn unpack_rejects_bad_length() {
        // real_len points beyond the buffer.
        let mut framed = vec![0x01u8, 0xFF, 0xFF]; // len=65535 but buffer is 3
        framed.extend_from_slice(b"tiny");
        assert!(unpack_inner(&framed).is_err());
        // Too short for even the inner header.
        assert!(unpack_inner(&[0x01u8, 0x00]).is_err());
    }
}
