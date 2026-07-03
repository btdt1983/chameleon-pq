//! De crypto-engine: het ENE punt waar uitgaand verkeer wordt versleuteld.
//!
//! Het datapad draait volledig op de CPU (ring / AEGIS), die per pakket
//! constant-time en low-latency is. Er is BEWUST geen GPU-tak: per-pakket
//! GPU-encryptie verliest het van de CPU omdat de upload/dispatch/read-back-
//! latency de paar honderd nanoseconden AEAD-werk ruim overstijgt, en de
//! zware once-per-connection wiskunde (ML-KEM, handtekeningen) heeft geen
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
use rayon::prelude::*;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct OutboundPacket {
    pub plaintext: Bytes,
}

/// Resultaat van één parallel-ontsleuteld inkomend datagram: (bron-adres, ruwe
/// datagram-bytes, en het open-resultaat — `Ok((type, plaintext))` voor het
/// datapad, `Err` voor een handshake-fragment of ruis).
pub type DecryptResult = (SocketAddr, Bytes, Result<(FrameType, Bytes)>);

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

    /// Bouw een wire-klaar COVER/dummy-datagram (constante grootte via `Full`),
    /// voor de constant-rate pacer (Fase 3).
    pub fn cover_datagram(&self) -> Result<Bytes> {
        self.sessions.seal_cover(PadPolicy::Full)
    }

    /// Verzegel één ECHT datapad-pakket met constante grootte (`Full`), voor het
    /// gepacede pad — daar moeten echt én cover dezelfde vaste grootte hebben,
    /// anders lekt de grootte-histogram wat de constante rate juist verbergt.
    pub fn seal_data_full(&self, plaintext: &[u8]) -> Result<Bytes> {
        self.sessions
            .seal_obf(FrameType::Data as u8, plaintext, PadPolicy::Full)
    }

    /// Verzegel één uitgaand pakket tot een wire-klaar datagram. De obf-seal
    /// gebeurt in `SessionManager::seal_obf`; de counter is atomisch, dus dit is
    /// veilig vanuit meerdere threads tegelijk (zie `encrypt_batch_par`).
    fn seal_one(&self, plaintext: &[u8]) -> Result<Bytes> {
        if self.obf_enabled {
            self.sessions
                .seal_obf(FrameType::Data as u8, plaintext, self.pad_policy)
        } else {
            let (sid, counter, ct) = self.sessions.encrypt(plaintext)?;
            Frame::new_data(sid, counter, ct).encode()
        }
    }

    /// Versleutel een batch uitgaande pakketten tot WIRE-KLARE datagrammen
    /// (sequentieel — voor kleine batches).
    pub fn encrypt_batch(&self, batch: Vec<OutboundPacket>) -> Result<Vec<Bytes>> {
        batch
            .iter()
            .map(|pkt| self.seal_one(&pkt.plaintext))
            .collect()
    }

    /// Zoals `encrypt_batch`, maar verzegelt de batch PARALLEL over alle
    /// CPU-cores (Fase C). Order-behoudend; `collect` short-circuit op de eerste
    /// fout (bv. RekeyRequired) net als de sequentiële variant. Roep dit aan
    /// binnen een `spawn_blocking` (rayon blokkeert).
    pub fn encrypt_batch_par(&self, batch: Vec<OutboundPacket>) -> Result<Vec<Bytes>> {
        batch
            .par_iter()
            .map(|pkt| self.seal_one(&pkt.plaintext))
            .collect()
    }

    /// Ontsleutel een batch inkomende datagrammen PARALLEL over alle CPU-cores.
    /// Geeft per datagram (src, ruwe bytes, resultaat) terug in INVOER-volgorde,
    /// zodat de aanroeper kan partitioneren: `Ok` = data/keepalive/close/padding
    /// (datapad), `Err` = handshake-fragment of ruis (terug naar de seriële
    /// coördinator). De AEAD-open is lock-vrij, dus dit schaalt over cores.
    pub fn decrypt_batch_par(&self, datagrams: &[(SocketAddr, Bytes)]) -> Vec<DecryptResult> {
        datagrams
            .par_iter()
            .map(|(src, dg)| (*src, dg.clone(), self.sessions.decrypt_obf(dg)))
            .collect()
    }
}
