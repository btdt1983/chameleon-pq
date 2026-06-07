//! De crypto-engine: het ENE punt waar uitgaand verkeer wordt versleuteld.
//!
//! Het datapad draait volledig op de CPU (ring / AEGIS), die per pakket
//! constant-time en low-latency is. Er is BEWUST geen GPU-tak: per-pakket
//! GPU-encryptie verliest het van de CPU omdat de upload/dispatch/read-back-
//! latency de paar honderd nanoseconden AEAD-werk ruim overstijgt, en de
//! zware once-per-connection wiskunde (Kyber, handtekeningen) heeft geen
//! volume om over te parallelliseren. Zie DESIGN.md §11–§12.

use crate::error::Result;
use crate::session::SessionManager;
use bytes::Bytes;
use std::sync::Arc;

pub struct OutboundPacket {
    pub plaintext: Bytes,
}

pub struct EncryptedPacket {
    pub session_id: u32,
    pub counter: u64,
    pub ciphertext: Bytes,
}

pub struct CryptoEngine {
    sessions: Arc<SessionManager>,
}

impl CryptoEngine {
    pub fn new(sessions: Arc<SessionManager>) -> Self {
        Self { sessions }
    }

    pub fn sessions(&self) -> &Arc<SessionManager> {
        &self.sessions
    }

    /// Versleutel een batch uitgaande pakketten op de CPU.
    pub fn encrypt_batch(&self, batch: Vec<OutboundPacket>) -> Result<Vec<EncryptedPacket>> {
        let mut out = Vec::with_capacity(batch.len());
        for pkt in batch {
            let (session_id, counter, ct) = self.sessions.encrypt(&pkt.plaintext)?;
            out.push(EncryptedPacket {
                session_id,
                counter,
                ciphertext: ct,
            });
        }
        Ok(out)
    }
}
