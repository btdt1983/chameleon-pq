//! Pluggable AEAD layer for the data path.
//!
//! The data path uses one AEAD cipher per session. Two options sit behind the
//! `Aead` trait:
//!
//!   • ChaCha20-Poly1305 (via `ring`) — constant-time on ALL hardware, the
//!     safe universal standard and fallback.
//!   • AEGIS-256X2 — faster and a stronger AEAD than AES-GCM on CPUs WITH
//!     AES hardware instructions; CAESAR winner, open, IETF draft for TLS 1.3.
//!     Without AES hardware AEGIS falls back to software AES (slower and
//!     timing-sensitive), so we pick it ONLY if the CPU supports it.
//!
//! The choice is made at session setup via `AeadAlgo::preferred()`, which
//! queries the CPU. The chosen algorithm id is bound into the handshake
//! transcript (see tunnel.rs), so an attacker cannot downgrade the choice to
//! the weaker option without breaking the MAC.

use crate::error::{ChameleonError, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use zeroize::Zeroizing;

/// Which AEAD a session uses. The wire id (u8) is bound into the transcript,
/// so the numbers are stable and must not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AeadAlgo {
    ChaCha20Poly1305 = 0x01,
    Aegis256X2 = 0x02,
}

impl AeadAlgo {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::ChaCha20Poly1305),
            0x02 => Ok(Self::Aegis256X2),
            _ => Err(ChameleonError::Handshake {
                state: "aead".into(),
                msg: format!("unknown AEAD id {v}"),
            }),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Nonce length in bytes for this algorithm.
    pub fn nonce_len(self) -> usize {
        match self {
            AeadAlgo::ChaCha20Poly1305 => 12, // 96-bit
            AeadAlgo::Aegis256X2 => 32,       // 256-bit
        }
    }

    /// AEAD tag length in bytes. The obfuscation layer (obf.rs) uses this to
    /// compute the MTU-safe padding limit; the tag is also the source of the
    /// header-protection sample (always >= SAMPLE_LEN = 16).
    pub fn tag_len(self) -> usize {
        match self {
            AeadAlgo::ChaCha20Poly1305 => 16, // Poly1305 tag
            AeadAlgo::Aegis256X2 => 32,       // 256-bit tag (see AEGIS_TAG_LEN)
        }
    }

    /// The preferred choice for THIS machine, determined ONCE and cached.
    ///
    /// "Has AES-NI" turned out too coarse a measure: on older AES-NI CPUs
    /// without wide SIMD (e.g. Westmere) the `aegis` crate falls back to slow
    /// software AES and AEGIS is in fact 30× SLOWER than ChaCha (which has its
    /// own assembly via `ring`). So we don't pick blindly on a feature flag but
    /// measure at startup which cipher is really faster here. On modern
    /// hardware AEGIS-256X2 wins comfortably (AES-NI stays the de facto default
    /// there); on this machine ChaCha wins — automatically, without config.
    ///
    /// Important: this is a local preference. Both peers must run the same
    /// algorithm (see `negotiate`), because the session keys and nonce lengths
    /// differ per cipher.
    pub fn preferred() -> Self {
        use std::sync::OnceLock;
        static PREFERRED: OnceLock<AeadAlgo> = OnceLock::new();
        *PREFERRED.get_or_init(pick_preferred)
    }

    /// Negotiate the algorithm to use between our own preference and the
    /// peer's. Rule: use AEGIS only if BOTH sides can; otherwise fall back to
    /// ChaCha20. This way a strong server works with a weak client without
    /// anyone running an unsafe software AES.
    pub fn negotiate(local: Self, peer: Self) -> Self {
        if local == AeadAlgo::Aegis256X2 && peer == AeadAlgo::Aegis256X2 {
            AeadAlgo::Aegis256X2
        } else {
            AeadAlgo::ChaCha20Poly1305
        }
    }
}

/// Can this CPU actually run AEGIS-256X2 (the 2-lane "X2" variant)?
/// x86/x86_64: AES-NI AND AVX2. AES-NI alone is NOT enough — the X2 variant
/// processes two lanes in 256-bit (AVX2) registers, so on a CPU WITH AES-NI
/// but WITHOUT AVX2 (e.g. Xeon X5660 / Westmere, or Sandy/Ivy Bridge) the
/// `aegis` crate executes an AVX2 instruction the CPU does not know → a native
/// STATUS_ILLEGAL_INSTRUCTION (0xC000001D): a hard crash that no panic hook
/// catches, and that even the startup benchmark trips (it must, after all, run
/// AEGIS to measure it). So we gate here, before AEGIS is called even once.
/// aarch64: the AES crypto extension (NEON; no AVX2 needed).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpu_can_aegis() -> bool {
    std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("avx2")
}

#[cfg(target_arch = "aarch64")]
fn cpu_can_aegis() -> bool {
    std::arch::is_aarch64_feature_detected!("aes")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
fn cpu_can_aegis() -> bool {
    false // unknown architecture: pick the safe, universal cipher (ChaCha20)
}

/// Determine (once) the fastest safe cipher for this machine.
fn pick_preferred() -> AeadAlgo {
    // If this CPU cannot run AEGIS safely (no AES-NI+AVX2), then AEGIS is not
    // an option — and we may not even BENCHMARK it, because that runs AEGIS
    // and already crashes (illegal instruction). ChaCha20 (via ring) is
    // constant-time and fast everywhere.
    if !cpu_can_aegis() {
        return AeadAlgo::ChaCha20Poly1305;
    }
    // With AES-NI: measure which is really faster (lower = faster).
    let chacha = bench_seal(AeadAlgo::ChaCha20Poly1305);
    let aegis = bench_seal(AeadAlgo::Aegis256X2);
    let choice = if aegis <= chacha {
        AeadAlgo::Aegis256X2
    } else {
        AeadAlgo::ChaCha20Poly1305
    };
    tracing::info!(
        "AEAD auto-select: {:?} (startup-bench 512×1200B — ChaCha {:.1} ms, AEGIS {:.1} ms)",
        choice,
        chacha.as_secs_f64() * 1e3,
        aegis.as_secs_f64() * 1e3
    );
    choice
}

/// Micro-benchmark: time to seal a batch of MTU packets with this algorithm.
/// Kept small so the startup cost is negligible (< ~5 ms on modern hardware;
/// tens of ms on a slow AES-NI CPU).
fn bench_seal(algo: AeadAlgo) -> std::time::Duration {
    use std::time::Instant;
    let key = Zeroizing::new([0u8; 32]);
    let dir = match make_directional(algo, &key) {
        Ok(d) => d,
        Err(_) => return std::time::Duration::MAX, // unusable → never chosen
    };
    let nonce = vec![0u8; algo.nonce_len()];
    let pt = [0u8; 1200];
    // Warmup (caches / turbo-ramp).
    for _ in 0..128 {
        let _ = dir.seal(&nonce, b"", &pt);
    }
    let t = Instant::now();
    for _ in 0..512 {
        let _ = dir.seal(&nonce, b"", &pt);
    }
    t.elapsed()
}

// ── The Aead trait ───────────────────────────────────────────────────────────

/// One direction (tx or rx) of a session cipher. Encrypts/decrypts in an
/// in-place-like manner with a per-packet nonce derived from (salt, counter).
/// `aad` (associated data) is authenticated but not encrypted; the data path
/// binds the frame header in here (type/session_id/counter), so tampering with
/// the visible header makes tag verification fail.
pub trait DirectionalAead: Send + Sync {
    /// Encrypt `plaintext`, return ciphertext+tag.
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    /// Decrypt `ciphertext` (incl. tag), return plaintext.
    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

// ── ChaCha20-Poly1305 via ring ───────────────────────────────────────────────

pub struct ChaChaDir {
    key: LessSafeKey,
}

impl ChaChaDir {
    pub fn new(key_bytes: &Zeroizing<[u8; 32]>) -> Result<Self> {
        let key = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &**key_bytes)
                .map_err(|_| ChameleonError::Kdf("chacha key".into()))?,
        );
        Ok(Self { key })
    }
}

impl DirectionalAead for ChaChaDir {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| ChameleonError::DecryptionFailed)?;
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| ChameleonError::DecryptionFailed)?;
        Ok(buf)
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| ChameleonError::DecryptionFailed)?;
        let mut buf = ciphertext.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| ChameleonError::DecryptionFailed)?;
        Ok(plain.to_vec())
    }
}

// ── AEGIS-256X2 ──────────────────────────────────────────────────────────────

use aegis::aegis256x2::Aegis256X2;

const AEGIS_TAG_LEN: usize = 32; // we use the 256-bit tag

pub struct AegisDir {
    key: [u8; 32],
}

impl AegisDir {
    pub fn new(key_bytes: &Zeroizing<[u8; 32]>) -> Result<Self> {
        Ok(Self { key: **key_bytes })
    }
}

impl DirectionalAead for AegisDir {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 32 {
            return Err(ChameleonError::DecryptionFailed);
        }
        let mut n = [0u8; 32];
        n.copy_from_slice(nonce);
        let cipher = Aegis256X2::<AEGIS_TAG_LEN>::new(&self.key, &n);
        let (mut ct, tag) = cipher.encrypt(plaintext, aad);
        // Wire format: ciphertext || tag (same style as ring's append-tag).
        ct.extend_from_slice(&tag);
        Ok(ct)
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 32 || ciphertext.len() < AEGIS_TAG_LEN {
            return Err(ChameleonError::DecryptionFailed);
        }
        let mut n = [0u8; 32];
        n.copy_from_slice(nonce);
        let split = ciphertext.len() - AEGIS_TAG_LEN;
        let (ct, tag_bytes) = ciphertext.split_at(split);
        let mut tag = [0u8; AEGIS_TAG_LEN];
        tag.copy_from_slice(tag_bytes);
        let cipher = Aegis256X2::<AEGIS_TAG_LEN>::new(&self.key, &n);
        cipher
            .decrypt(ct, &tag, aad)
            .map_err(|_| ChameleonError::DecryptionFailed)
    }
}

// The AEGIS key lives as plain [u8;32] in the process (the `aegis` crate takes
// no Zeroizing key). Wipe it explicitly on drop so it does not linger in a core
// dump/swap. ChaCha via `ring` already wipes its own key on drop.
impl Drop for AegisDir {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

// ── Constructor: build the right direction cipher for an algorithm ───────────

pub fn make_directional(
    algo: AeadAlgo,
    key_bytes: &Zeroizing<[u8; 32]>,
) -> Result<Box<dyn DirectionalAead>> {
    match algo {
        AeadAlgo::ChaCha20Poly1305 => Ok(Box::new(ChaChaDir::new(key_bytes)?)),
        AeadAlgo::Aegis256X2 => Ok(Box::new(AegisDir::new(key_bytes)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha_roundtrip() {
        let key = Zeroizing::new([0x11u8; 32]);
        let dir = ChaChaDir::new(&key).unwrap();
        let nonce = [0x22u8; 12];
        let ct = dir.seal(&nonce, b"hdr", b"secret message").unwrap();
        let pt = dir.open(&nonce, b"hdr", &ct).unwrap();
        assert_eq!(&pt[..], b"secret message");
    }

    #[test]
    fn aegis_roundtrip() {
        let key = Zeroizing::new([0x33u8; 32]);
        let dir = AegisDir::new(&key).unwrap();
        let nonce = [0x44u8; 32];
        let ct = dir.seal(&nonce, b"hdr", b"secret message").unwrap();
        let pt = dir.open(&nonce, b"hdr", &ct).unwrap();
        assert_eq!(&pt[..], b"secret message");
    }

    #[test]
    fn aegis_rejects_tampered() {
        let key = Zeroizing::new([0x55u8; 32]);
        let dir = AegisDir::new(&key).unwrap();
        let nonce = [0x66u8; 32];
        let mut ct = dir.seal(&nonce, b"hdr", b"abc").unwrap();
        ct[0] ^= 0xFF; // tamper with the ciphertext
        assert!(dir.open(&nonce, b"hdr", &ct).is_err());
    }

    #[test]
    fn aad_mismatch_is_rejected() {
        // Authenticated header: changing the AAD (e.g. a forged session_id/type
        // in the frame header) must make verification fail.
        // ChaCha20: 12-byte nonce.
        let c = ChaChaDir::new(&Zeroizing::new([0x77u8; 32])).unwrap();
        let ct = c.seal(&[0x01u8; 12], b"header-A", b"payload").unwrap();
        assert!(
            c.open(&[0x01u8; 12], b"header-B", &ct).is_err(),
            "ChaCha: different AAD must fail"
        );
        assert_eq!(
            &c.open(&[0x01u8; 12], b"header-A", &ct).unwrap()[..],
            b"payload"
        );

        // AEGIS: 32-byte nonce.
        let a = AegisDir::new(&Zeroizing::new([0x88u8; 32])).unwrap();
        let ct = a.seal(&[0x02u8; 32], b"header-A", b"payload").unwrap();
        assert!(
            a.open(&[0x02u8; 32], b"header-B", &ct).is_err(),
            "AEGIS: different AAD must fail"
        );
        assert_eq!(
            &a.open(&[0x02u8; 32], b"header-A", &ct).unwrap()[..],
            b"payload"
        );
    }

    #[test]
    fn negotiate_requires_both_for_aegis() {
        use AeadAlgo::*;
        assert_eq!(AeadAlgo::negotiate(Aegis256X2, Aegis256X2), Aegis256X2);
        assert_eq!(
            AeadAlgo::negotiate(Aegis256X2, ChaCha20Poly1305),
            ChaCha20Poly1305
        );
        assert_eq!(
            AeadAlgo::negotiate(ChaCha20Poly1305, Aegis256X2),
            ChaCha20Poly1305
        );
        assert_eq!(
            AeadAlgo::negotiate(ChaCha20Poly1305, ChaCha20Poly1305),
            ChaCha20Poly1305
        );
    }
}
