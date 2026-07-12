//! The crypto engine: the ONE point where outbound traffic is encrypted.
//!
//! The data path runs entirely on the CPU (ring / AEGIS), which is constant-
//! time and low-latency per packet. There is DELIBERATELY no GPU branch:
//! per-packet GPU encryption loses to the CPU because the upload/dispatch/
//! read-back latency far exceeds the few hundred nanoseconds of AEAD work, and
//! the heavy once-per-connection math (ML-KEM, signatures) has no volume to
//! parallelise over. See DESIGN.md §11–§12.
//!
//! The engine yields WIRE-READY datagrams. With obfuscation on (the default)
//! that is the obfuscated data-path frame (obf.rs: QUIC-style header-protection
//! + padding); with obfuscation off the classic Frame::new_data frame.

use crate::error::Result;
use crate::frame::{Frame, FrameType};
use crate::obf::PadPolicy;
use crate::session::SessionManager;
use bytes::Bytes;
use rayon::prelude::*;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct OutboundPacket {
    pub plaintext: Bytes,
}

/// Result of one incoming datagram decrypted in parallel: (source address, raw
/// datagram bytes, and the open result — `Ok((type, plaintext))` for the data
/// path, `Err` for a handshake fragment or noise).
pub type DecryptResult = (SocketAddr, Bytes, Result<(FrameType, Bytes)>);

pub struct CryptoEngine {
    sessions: Arc<SessionManager>,
    /// Whether the data path is obfuscated (config `[obfuscation].enabled`).
    obf_enabled: bool,
    /// Padding policy for the obfuscation layer.
    pad_policy: PadPolicy,
}

impl CryptoEngine {
    pub fn new(sessions: Arc<SessionManager>, obf_enabled: bool, pad_policy: PadPolicy) -> Self {
        Self {
            sessions,
            obf_enabled,
            pad_policy,
        }
    }

    pub fn sessions(&self) -> &Arc<SessionManager> {
        &self.sessions
    }

    /// Build a wire-ready COVER/dummy datagram (constant size via `Full`),
    /// for the constant-rate pacer (Phase 3).
    pub fn cover_datagram(&self) -> Result<Bytes> {
        self.sessions.seal_cover(PadPolicy::Full)
    }

    /// Seal one REAL data-path packet at constant size (`Full`), for the paced
    /// path — there real and cover must share the same fixed size, otherwise the
    /// size histogram leaks exactly what the constant rate is meant to hide.
    pub fn seal_data_full(&self, plaintext: &[u8]) -> Result<Bytes> {
        self.sessions
            .seal_obf(FrameType::Data as u8, plaintext, PadPolicy::Full)
    }

    /// Seal one outbound packet into a wire-ready datagram. The obf seal
    /// happens in `SessionManager::seal_obf`; the counter is atomic, so this is
    /// safe from multiple threads at once (see `encrypt_batch_par`).
    fn seal_one(&self, plaintext: &[u8]) -> Result<Bytes> {
        if self.obf_enabled {
            self.sessions
                .seal_obf(FrameType::Data as u8, plaintext, self.pad_policy)
        } else {
            let (sid, counter, ct) = self.sessions.encrypt(plaintext)?;
            Frame::new_data(sid, counter, ct).encode()
        }
    }

    /// Encrypt a batch of outbound packets into WIRE-READY datagrams
    /// (sequential — for small batches).
    pub fn encrypt_batch(&self, batch: Vec<OutboundPacket>) -> Result<Vec<Bytes>> {
        batch
            .iter()
            .map(|pkt| self.seal_one(&pkt.plaintext))
            .collect()
    }

    /// Like `encrypt_batch`, but seals the batch in PARALLEL across all
    /// CPU cores (Phase C). Order-preserving; `collect` short-circuits on the
    /// first error (e.g. RekeyRequired) just like the sequential variant. Call
    /// this inside a `spawn_blocking` (rayon blocks).
    pub fn encrypt_batch_par(&self, batch: Vec<OutboundPacket>) -> Result<Vec<Bytes>> {
        batch
            .par_iter()
            .map(|pkt| self.seal_one(&pkt.plaintext))
            .collect()
    }

    /// Decrypt a batch of incoming datagrams in PARALLEL across all CPU cores.
    /// Returns per datagram (src, raw bytes, result) in INPUT order, so the
    /// caller can partition: `Ok` = data/keepalive/close/padding (data path),
    /// `Err` = handshake fragment or noise (back to the serial coordinator).
    /// The AEAD open is lock-free, so this scales across cores.
    pub fn decrypt_batch_par(&self, datagrams: &[(SocketAddr, Bytes)]) -> Vec<DecryptResult> {
        datagrams
            .par_iter()
            .map(|(src, dg)| (*src, dg.clone(), self.sessions.decrypt_obf(dg)))
            .collect()
    }
}
