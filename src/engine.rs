//! De crypto-engine: het ENE punt waar uitgaand verkeer wordt versleuteld.
//!
//! Het datapad draait volledig op de CPU (ring / AEGIS), die per pakket
//! constant-time en low-latency is. Er is BEWUST geen GPU-tak: per-pakket
//! GPU-encryptie verliest het van de CPU omdat de upload/dispatch/read-back-
//! latency de paar honderd nanoseconden AEAD-werk ruim overstijgt, en de
//! zware once-per-connection wiskunde (Kyber, handtekeningen) heeft geen
//! volume om over te parallelliseren. Zie DESIGN.md §11–§12.
//!
//! De engine levert WIRE-KLARE datagrammen. Met obfuscatie aan (standaard) is
//! dat het geobfusceerde datapad-frame (obf.rs: QUIC-stijl header-protection +
//! padding); met obfuscatie uit het klassieke Frame::new_data-frame.

use crate::error::Result;
use crate::frame::{Frame, FrameType};
use crate::obf::PadPolicy;
use crate::session::SessionManager;
use bytes::Bytes;
use std::sync::Arc;

pub struct OutboundPacket {
    pub plaintext: Bytes,
}

pub struct CryptoEngine {
    sessions: Arc<SessionManager>,
    /// Of het datapad geobfusceerd wordt (config `[obfuscation].enabled`).
    obf_enabled: bool,
    /// Padding-beleid voor de obfuscatie-laag.
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

    /// Versleutel een batch uitgaande pakketten tot WIRE-KLARE datagrammen.
    /// De obf-seal gebeurt in `SessionManager::seal_obf` onder één sessie-lock,
    /// zodat de counter en de header-protection-sleutel altijd bij elkaar horen
    /// (geen race met een gelijktijdige rekey).
    pub fn encrypt_batch(&self, batch: Vec<OutboundPacket>) -> Result<Vec<Bytes>> {
        let mut out = Vec::with_capacity(batch.len());
        for pkt in batch {
            let wire = if self.obf_enabled {
                self.sessions
                    .seal_obf(FrameType::Data as u8, &pkt.plaintext, self.pad_policy)?
            } else {
                let (sid, counter, ct) = self.sessions.encrypt(&pkt.plaintext)?;
                Frame::new_data(sid, counter, ct).encode()?
            };
            out.push(wire);
        }
        Ok(out)
    }
}
