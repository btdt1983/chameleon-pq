//! Active session: per-direction keys, nonce management, AEAD via ring,
//! sliding-window replay protection, and a SessionManager for rekey.

use crate::aead::{make_directional, AeadAlgo, DirectionalAead};
use crate::error::{ChameleonError, Result};
use crate::frame::FrameType;
use crate::obf::{self, PadPolicy};
use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use zeroize::Zeroizing;

// ── Sliding-window replay protection ─────────────────────────────────────────
//
// Window of 2048 packets (WireGuard-scale), stored as a bitset of 32 u64
// words. Ample for paths with heavy reordering. The logic is identical to
// the old 64-bit version; only the bit indexing now runs over
// (word, bit-in-word) instead of a single u64.

const WINDOW_BITS: u64 = 2048;
const WINDOW_WORDS: usize = (WINDOW_BITS / 64) as usize; // 32

struct ReplayWindow {
    highest: u64,
    /// bit i (measured as distance below `highest`) set = counter seen.
    bitmap: [u64; WINDOW_WORDS],
    seeded: bool,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0u64; WINDOW_WORDS],
            seeded: false,
        }
    }

    /// Test whether the bit `delta` positions below `highest` is set.
    fn bit_is_set(&self, delta: u64) -> bool {
        let word = (delta / 64) as usize;
        let bit = delta % 64;
        (self.bitmap[word] >> bit) & 1 == 1
    }

    /// Set the bit `delta` positions below `highest`.
    fn set_bit(&mut self, delta: u64) {
        let word = (delta / 64) as usize;
        let bit = delta % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    /// Shift the whole window `shift` positions up (toward newer counters).
    /// Bits that fall outside the window are lost; new positions are 0.
    fn shift_window(&mut self, shift: u64) {
        if shift >= WINDOW_BITS {
            // Window fully passed: clear everything.
            self.bitmap = [0u64; WINDOW_WORDS];
            return;
        }
        let word_shift = (shift / 64) as usize;
        let bit_shift = shift % 64;

        if bit_shift == 0 {
            // Whole-word shift, no bit-carry needed.
            for i in (0..WINDOW_WORDS).rev() {
                self.bitmap[i] = if i >= word_shift {
                    self.bitmap[i - word_shift]
                } else {
                    0
                };
            }
        } else {
            for i in (0..WINDOW_WORDS).rev() {
                let mut v = 0u64;
                if i >= word_shift {
                    v = self.bitmap[i - word_shift] << bit_shift;
                    if i > word_shift {
                        v |= self.bitmap[i - word_shift - 1] >> (64 - bit_shift);
                    }
                }
                self.bitmap[i] = v;
            }
        }
    }

    /// Cheap pre-check. Mutates nothing; commit runs separately after decrypt.
    fn check(&self, counter: u64) -> Result<()> {
        if !self.seeded {
            return Ok(());
        }
        if counter > self.highest {
            return Ok(());
        }
        let delta = self.highest - counter;
        if delta >= WINDOW_BITS {
            return Err(ChameleonError::DecryptionFailed);
        }
        if self.bit_is_set(delta) {
            return Err(ChameleonError::DecryptionFailed);
        }
        Ok(())
    }

    /// Commit after successful decryption.
    fn commit(&mut self, counter: u64) {
        if !self.seeded {
            self.seeded = true;
            self.highest = counter;
            self.bitmap = [0u64; WINDOW_WORDS];
            self.set_bit(0); // current position
            return;
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            self.shift_window(shift);
            self.highest = counter;
            self.set_bit(0); // new highest = delta 0
        } else {
            let delta = self.highest - counter;
            if delta < WINDOW_BITS {
                self.set_bit(delta);
            }
        }
    }
}

// ── Session ──────────────────────────────────────────────────────────────────

pub struct Session {
    pub session_id: u32,
    algo: AeadAlgo,
    tx_aead: Box<dyn DirectionalAead>,
    rx_aead: Box<dyn DirectionalAead>,
    tx_counter: AtomicU64,
    tx_salt: [u8; 4],
    rx_salt: [u8; 4],
    rekey_at: u64,
    replay: Mutex<ReplayWindow>,
    /// Per-direction header-protection keys for the obfuscation layer (obf.rs).
    /// Separate from the AEAD keys, derived from the same shared secret with
    /// their own HKDF labels. Stored as plain [u8;32] (they go to the obf layer
    /// as &[u8;32]) but are explicitly wiped on drop — see `impl Drop`.
    tx_obf_key: [u8; 32],
    rx_obf_key: [u8; 32],
}

impl Session {
    /// Build a session with the default negotiated cipher (ChaCha20 unless
    /// chosen otherwise elsewhere). Kept for existing call-sites/tests.
    pub fn from_handshake(
        session_id: u32,
        shared: Zeroizing<[u8; 32]>,
        is_initiator: bool,
    ) -> Result<Self> {
        // Default: ChaCha20-Poly1305 (safe on all hardware). The handshake
        // picks explicitly via `from_handshake_with_algo` once AEGIS applies.
        Self::from_handshake_with_algo(session_id, shared, is_initiator, AeadAlgo::ChaCha20Poly1305)
    }

    /// Build a session with an EXPLICITLY negotiated AEAD algorithm.
    pub fn from_handshake_with_algo(
        session_id: u32,
        shared: Zeroizing<[u8; 32]>,
        is_initiator: bool,
        algo: AeadAlgo,
    ) -> Result<Self> {
        let (tx_bytes, rx_bytes) = derive_directional_keys(&shared, is_initiator)?;

        let tx_aead = make_directional(algo, &tx_bytes)?;
        let rx_aead = make_directional(algo, &rx_bytes)?;

        let (tx_obf_key, rx_obf_key) = derive_obf_keys(&shared, is_initiator)?;

        let (tx_salt, rx_salt) = if is_initiator {
            ([0x01, 0, 0, 0], [0x02, 0, 0, 0])
        } else {
            ([0x02, 0, 0, 0], [0x01, 0, 0, 0])
        };

        Ok(Self {
            session_id,
            algo,
            tx_aead,
            rx_aead,
            tx_counter: AtomicU64::new(0),
            tx_salt,
            rx_salt,
            rekey_at: 1 << 48,
            replay: Mutex::new(ReplayWindow::new()),
            tx_obf_key,
            rx_obf_key,
        })
    }

    pub fn algo(&self) -> AeadAlgo {
        self.algo
    }

    pub fn tx_counter_value(&self) -> u64 {
        self.tx_counter.load(Ordering::Relaxed)
    }

    pub fn rekey_at(&self) -> u64 {
        self.rekey_at
    }

    /// Reserve `n` contiguous tx counters and return the first. Decoupled
    /// from sealing on purpose: the nonce/AAD only depend on the counter
    /// value, not on when the seal actually runs, so a caller can fix the
    /// ORDER of a batch of packets right here (one atomic op) and then seal
    /// them later — sequentially, in parallel, out of completion order,
    /// whatever — without ever risking two packets sharing a counter.
    /// Every caller MUST seal every reserved counter exactly once: a
    /// reserved-but-never-sealed counter just burns a nonce value, which is
    /// harmless (nonces don't need to be contiguous), but a counter sealed
    /// TWICE is a catastrophic AEAD nonce reuse.
    pub fn reserve_counters(&self, n: u64) -> Result<u64> {
        let first = self.tx_counter.fetch_add(n, Ordering::Relaxed);
        // Check the LAST counter in the range, not just the first: a whole
        // reserved batch must fit under rekey_at, or a later seal in the
        // batch would silently run past the point rekeying was supposed to
        // have happened.
        if first.saturating_add(n.saturating_sub(1)) >= self.rekey_at {
            return Err(ChameleonError::RekeyRequired);
        }
        Ok(first)
    }

    /// Core AEAD seal against an counter reserved earlier via
    /// `reserve_counters` — no counter allocation here. `pub(crate)` because
    /// callers outside this crate have no business minting raw AEAD
    /// ciphertext without the obfuscation wrapper; `seal_obf_with_counter`
    /// is the public equivalent for the data path this project actually uses.
    pub(crate) fn seal_with_counter(&self, counter: u64, plaintext: &[u8]) -> Result<Bytes> {
        let nonce = self.make_nonce(self.tx_salt, counter);
        let aad = self.data_aad(counter);
        let ct = self.tx_aead.seal(&nonce, &aad, plaintext)?;
        Ok(Bytes::from(ct))
    }

    /// Encrypt an outbound packet. Returns (counter, ciphertext+tag).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(u64, Bytes)> {
        let counter = self.reserve_counters(1)?;
        Ok((counter, self.seal_with_counter(counter, plaintext)?))
    }

    /// Decrypt an inbound packet. Order: check → decrypt → commit.
    pub fn decrypt(&self, counter: u64, ciphertext: &[u8]) -> Result<Bytes> {
        {
            let win = self.replay.lock();
            win.check(counter)?;
        }
        let nonce = self.make_nonce(self.rx_salt, counter);
        let aad = self.data_aad(counter);
        let plain = self.rx_aead.open(&nonce, &aad, ciphertext)?;
        let plain = Bytes::from(plain);
        {
            let mut win = self.replay.lock();
            win.check(counter)?; // re-check under lock = race-safe
            win.commit(counter);
        }
        Ok(plain)
    }

    /// Build the nonce at the correct width for the chosen algorithm:
    /// salt (4 bytes) followed by the little-endian counter, right-padded with
    /// zeros to the algorithm's nonce length (12 or 32 bytes).
    fn make_nonce(&self, salt: [u8; 4], counter: u64) -> Vec<u8> {
        let len = self.algo.nonce_len();
        let mut n = vec![0u8; len];
        n[..4].copy_from_slice(&salt);
        n[4..12].copy_from_slice(&counter.to_le_bytes());
        n
    }

    /// Associated data for a Data frame: the visible frame header
    /// (type domain separation ‖ session_id ‖ counter). Authenticating this as
    /// AAD makes any change to the cleartext header break the AEAD tag, so an
    /// active attacker cannot alter the header unnoticed.
    fn data_aad(&self, counter: u64) -> [u8; 13] {
        let mut aad = [0u8; 13];
        aad[0] = 0x01; // FrameType::Data — domain separation vs type confusion
        aad[1..5].copy_from_slice(&self.session_id.to_le_bytes());
        aad[5..13].copy_from_slice(&counter.to_le_bytes());
        aad
    }

    // ── Obfuscated data path (obf.rs layer on top of the AEAD core) ──────────

    /// Seal an outbound data-path datagram with obfuscation: pack the real
    /// `inner_type` + the plaintext into the inner framing (with padding),
    /// encrypt that via the UNCHANGED AEAD core, and mask the header. Returns
    /// the wire-ready datagram (masked_header ‖ ct).
    pub fn seal_obf(&self, inner_type: u8, plaintext: &[u8], policy: PadPolicy) -> Result<Bytes> {
        let counter = self.reserve_counters(1)?;
        self.seal_obf_core(counter, inner_type, plaintext, policy)
    }

    /// Shared implementation for `seal_obf`/`seal_obf_with_counter`: pack the
    /// inner framing, seal it, mask the header. `counter` is assumed already
    /// reserved (via `reserve_counters` — directly or through `seal_obf`).
    fn seal_obf_core(
        &self,
        counter: u64,
        inner_type: u8,
        plaintext: &[u8],
        policy: PadPolicy,
    ) -> Result<Bytes> {
        let max_framed = obf::max_framed(self.algo.tag_len());
        let framed = obf::pack_inner(inner_type, plaintext, policy, max_framed);
        let ct = self.seal_with_counter(counter, &framed)?;
        Ok(obf::seal_wire(
            &self.tx_obf_key,
            self.session_id,
            counter,
            &ct,
        ))
    }

    /// Seal against a counter reserved EARLIER via `reserve_counters` — the
    /// data-path (obfuscated) equivalent of `seal_with_counter`. Used by the
    /// tunnel's outbound pipeline: a batch's counters are reserved up front
    /// (fixing on-wire order), then sealed here, possibly in parallel and
    /// out of completion order — see `engine::CryptoEngine::seal_batch_with_counters`.
    pub fn seal_obf_with_counter(
        &self,
        counter: u64,
        inner_type: u8,
        plaintext: &[u8],
        policy: PadPolicy,
    ) -> Result<Bytes> {
        self.seal_obf_core(counter, inner_type, plaintext, policy)
    }

    /// Try to open an inbound datagram as an obfuscated data-path packet for
    /// THIS session. Returns:
    ///   • Ok(Some((type, plaintext))) — opened and authenticated for us;
    ///   • Ok(None)                    — not for this session (too short, other
    ///                                    session_id, or AEAD open fails) → the
    ///                                    caller tries another candidate;
    ///   • Err(..)                     — authenticated but the inner framing is
    ///                                    corrupt/unknown (protocol error).
    fn try_open_obf(&self, datagram: &[u8]) -> Result<Option<(FrameType, Bytes)>> {
        let rec = match obf::unmask(&self.rx_obf_key, datagram) {
            Some(r) => r,
            None => return Ok(None), // too short / noise
        };
        // Cheap pre-filter: the session_id must match. This is a
        // performance gate, not the security boundary — that is the AEAD tag.
        if rec.session_id != self.session_id {
            return Ok(None);
        }
        match self.decrypt(rec.counter, obf::ct_slice(datagram)) {
            Ok(framed) => {
                let (inner_type, pt) = obf::unpack_inner(&framed)?;
                Ok(Some((FrameType::from_u8(inner_type)?, pt)))
            }
            // Tag mismatch/replay: not (any longer) for us — let the caller try
            // the next candidate; otherwise it eventually gets dropped.
            Err(_) => Ok(None),
        }
    }
}

// Wipe the obfuscation header keys on drop. The AEAD keys themselves live in
// the Box<dyn DirectionalAead> and are wiped there (ring / AegisDir::drop); the
// derived directional key bytes are Zeroizing. This way no session key remains
// in memory after drop.
impl Drop for Session {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.tx_obf_key.zeroize();
        self.rx_obf_key.zeroize();
    }
}

/// Per-direction key pair (tx, rx), both zeroized on drop.
type DirectionalKeys = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

fn derive_directional_keys(shared: &[u8; 32], is_initiator: bool) -> Result<DirectionalKeys> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"Chameleon-PQ-v1-directional"), shared);
    let mut a = Zeroizing::new([0u8; 32]);
    let mut b = Zeroizing::new([0u8; 32]);
    hk.expand(b"key-A->B", a.as_mut())
        .map_err(|_| ChameleonError::Kdf("A".into()))?;
    hk.expand(b"key-B->A", b.as_mut())
        .map_err(|_| ChameleonError::Kdf("B".into()))?;
    // Initiator sends on A->B and receives on B->A; responder the reverse.
    if is_initiator {
        Ok((a, b))
    } else {
        Ok((b, a))
    }
}

/// Per-direction header-protection keys for the obfuscation layer. From the
/// same shared secret and the same HKDF context as the AEAD keys, but with
/// their OWN info labels — HKDF-Expand with different `info` yields
/// independent keys, so clean domain separation from `key-A->B`/`B->A`.
fn derive_obf_keys(shared: &[u8; 32], is_initiator: bool) -> Result<([u8; 32], [u8; 32])> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"Chameleon-PQ-v1-directional"), shared);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    hk.expand(b"obf-A->B", &mut a)
        .map_err(|_| ChameleonError::Kdf("obf-A".into()))?;
    hk.expand(b"obf-B->A", &mut b)
        .map_err(|_| ChameleonError::Kdf("obf-B".into()))?;
    // Same direction swap as the AEAD keys: (tx_obf, rx_obf).
    if is_initiator {
        Ok((a, b))
    } else {
        Ok((b, a))
    }
}

// ── SessionManager: active + previous session during rekey ───────────────────

const REKEY_AFTER_FRACTION_NUM: u64 = 3;
const REKEY_AFTER_FRACTION_DEN: u64 = 4;

pub struct SessionManager {
    current: RwLock<Arc<Session>>,
    previous: RwLock<Option<Arc<Session>>>,
    rekey_threshold: u64,
    rekey_in_progress: AtomicU64,
    /// Timestamp of the last rekey attempt. Prevents a rekey storm:
    /// after a failed or just-completed rekey, a new one may not start
    /// immediately. Stored as Mutex<Instant> because Instant is not
    /// atomic.
    last_rekey_attempt: Mutex<std::time::Instant>,
}

/// Minimum interval between two rekey attempts. A failed rekey
/// therefore cannot re-fire in a tight loop.
const MIN_REKEY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

impl SessionManager {
    pub fn new(initial: Session) -> Self {
        let rekey_at = initial.rekey_at();
        Self {
            current: RwLock::new(Arc::new(initial)),
            previous: RwLock::new(None),
            rekey_threshold: rekey_at / REKEY_AFTER_FRACTION_DEN * REKEY_AFTER_FRACTION_NUM,
            rekey_in_progress: AtomicU64::new(0),
            // Start far in the past so the first rekey is not blocked.
            last_rekey_attempt: Mutex::new(std::time::Instant::now() - MIN_REKEY_INTERVAL * 2),
        }
    }

    pub fn current_session_id(&self) -> u32 {
        self.current.read().session_id
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(u32, u64, Bytes)> {
        let sess = self.current.read().clone();
        let (counter, ct) = sess.encrypt(plaintext)?;
        Ok((sess.session_id, counter, ct))
    }

    /// Pin the active session and reserve `n` counters against it, in one
    /// step. The pinning is load-bearing, not defensive: if a rekey lands
    /// between this call and the eventual seal, the caller MUST seal
    /// against the SAME `Arc<Session>` returned here — never re-read
    /// `current` later — or a counter reserved on the old session's tx
    /// sequence would get sealed under the new session's keys.
    pub fn reserve(&self, n: u64) -> Result<(Arc<Session>, u64)> {
        let sess = self.current.read().clone();
        let first = sess.reserve_counters(n)?;
        Ok((sess, first))
    }

    pub fn decrypt(&self, session_id: u32, counter: u64, ct: &[u8]) -> Result<Bytes> {
        {
            let cur = self.current.read();
            if cur.session_id == session_id {
                return cur.decrypt(counter, ct);
            }
        }
        let prev = self.previous.read();
        if let Some(p) = prev.as_ref() {
            if p.session_id == session_id {
                return p.decrypt(counter, ct);
            }
        }
        Err(ChameleonError::DecryptionFailed)
    }

    // ── Obfuscated data path ─────────────────────────────────────────────────

    /// Seal an outbound data-path datagram with obfuscation on the CURRENT
    /// session. `inner_type` is the real frame type (Data/KeepAlive/Close).
    pub fn seal_obf(&self, inner_type: u8, plaintext: &[u8], policy: PadPolicy) -> Result<Bytes> {
        let sess = self.current.read().clone();
        sess.seal_obf(inner_type, plaintext, policy)
    }

    /// Seal a cover/dummy datagram (Phase 3): an obfuscated data-path packet
    /// with inner type Padding and empty payload. The receiver silently
    /// discards it (does count as a sign of life). Fills empty slots in the
    /// constant-rate pacer, so burst/idle patterns disappear.
    pub fn seal_cover(&self, policy: PadPolicy) -> Result<Bytes> {
        let sess = self.current.read().clone();
        sess.seal_obf(FrameType::Padding as u8, b"", policy)
    }

    /// Open an inbound obfuscated datagram via trial decryption over the
    /// active sessions (current first, then previous during a rekey overlap).
    /// The trial set is ≤2; a packet that opens under neither is dropped
    /// (looks like noise). Returns (real frame type, plaintext).
    pub fn decrypt_obf(&self, datagram: &[u8]) -> Result<(FrameType, Bytes)> {
        let current = self.current.read().clone();
        if let Some(res) = current.try_open_obf(datagram)? {
            return Ok(res);
        }
        let previous = self.previous.read().clone();
        if let Some(p) = previous {
            if let Some(res) = p.try_open_obf(datagram)? {
                return Ok(res);
            }
        }
        Err(ChameleonError::DecryptionFailed)
    }

    /// True (once) as soon as the tx counter passes the threshold AND enough
    /// time has elapsed since the previous attempt (anti-storm). On failure the
    /// caller MUST call `abort_rekey()` to release the claim, or
    /// `install_new_session()` on success.
    pub fn needs_rekey(&self) -> bool {
        if self.current.read().tx_counter_value() < self.rekey_threshold {
            return false;
        }
        // Anti-storm: respect the minimum interval since the previous attempt.
        {
            let last = self.last_rekey_attempt.lock();
            if last.elapsed() < MIN_REKEY_INTERVAL {
                return false;
            }
        }
        // Claim the rekey slot atomically; only the first caller wins.
        let won = self
            .rekey_in_progress
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if won {
            *self.last_rekey_attempt.lock() = std::time::Instant::now();
        }
        won
    }

    /// Release the rekey claim after a FAILED attempt, so a later attempt
    /// (after the interval) can start again. The timestamp stays in place,
    /// so the storm protection still applies.
    pub fn abort_rekey(&self) {
        self.rekey_in_progress.store(0, Ordering::Release);
    }

    pub fn install_new_session(&self, new_session: Session) {
        let new_arc = Arc::new(new_session);
        let old = {
            let mut cur = self.current.write();
            let old = cur.clone();
            *cur = new_arc;
            old
        };
        *self.previous.write() = Some(old);
        self.rekey_in_progress.store(0, Ordering::Release);
    }

    pub fn retire_previous(&self) {
        *self.previous.write() = None;
    }
}
