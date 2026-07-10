//! TUN-interface laag: cross-platform, asynchroon.
//!
//! Exposeer twee mpsc-kanalen zodat de rest van de applicatie
//! platform-agnostisch blijft:
//!
//!   plaintext_from_tun: Receiver<Bytes>  — IP-pakketten die van de
//!                                          kernel/TUN binnenkomen en
//!                                          versleuteld naar de peer moeten.
//!   plaintext_to_tun:   Sender<Bytes>    — Ontsleutelde IP-pakketten
//!                                          die naar de kernel/TUN moeten.
//!
//! PLATFORM-VEREISTEN
//!   Linux:   CAP_NET_ADMIN (of sudo) om de TUN-interface aan te maken.
//!   Windows: wintun.dll naast de binary (https://www.wintun.net).
//!
//! We drijven de I/O via `tun` 0.8's `AsyncDevice` (`recv`/`send`). Op Windows
//! draait dat op `wintun-bindings`: een `try_receive`-ringfast-path die tijdens
//! verkeer nooit blokkeert, en bij idle één pool-thread op het OS-read-event
//! parkeert — GEEN thread-per-pakket zoals `tun` 0.6, wat de per-pakket-muur en
//! de burst-instabiliteit veroorzaakte.
//!
//! In tests (zonder CAP_NET_ADMIN) kun je `TunPair::new_mock()` gebruiken;
//! dat geeft twee in-memory kanalen die dezelfde API bieden.

use crate::config::TunConfig;
use crate::error::{ChameleonError, Result};
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

const TUN_READ_BUF: usize = 65_536;
const CHANNEL_DEPTH: usize = 512;

/// Het publieke API-oppervlak van de TUN-laag.
pub struct TunPair {
    /// Lees hieruit: plaintext IP-pakketten richting encrypt → UDP.
    pub from_tun: mpsc::Receiver<Bytes>,
    /// Schrijf hierheen: decrypted IP-pakketten richting kernel.
    pub to_tun: mpsc::Sender<Bytes>,
    /// Handles to the TUN read/write tasks (None for the mock). The caller
    /// aborts + awaits these on teardown so the device is fully released before
    /// it is re-created — the read task parks on `recv()` and would otherwise
    /// keep the interface open indefinitely when idle.
    pub read_task: Option<tokio::task::JoinHandle<()>>,
    pub write_task: Option<tokio::task::JoinHandle<()>>,
}

impl TunPair {
    /// Maak een echte TUN-interface aan en start de I/O-taken.
    /// Faalt als de rechten ontbreken of het platform niet ondersteund wordt.
    pub fn create(cfg: &TunConfig) -> Result<Self> {
        let device = build_async_device(cfg)?;
        Ok(Self::spawn_io(device))
    }

    /// In-memory mock (geen kernel-interface nodig). Bedoeld voor tests en voor
    /// clients die de tunnel-loops willen aandrijven zonder een echte TUN. Van
    /// buiten stuur je bytes in via `inject_tx`; lees uitvoer via `drain_rx`.
    pub fn new_mock() -> (Self, MockHandles) {
        let (inject_tx, inject_rx) = mpsc::channel::<Bytes>(CHANNEL_DEPTH);
        let (drain_tx, drain_rx) = mpsc::channel::<Bytes>(CHANNEL_DEPTH);
        let pair = TunPair {
            from_tun: inject_rx,
            to_tun: drain_tx,
            read_task: None,
            write_task: None,
        };
        (
            pair,
            MockHandles {
                inject_tx,
                drain_rx,
            },
        )
    }

    fn spawn_io(device: tun::AsyncDevice) -> Self {
        let (from_tun_tx, from_tun_rx) = mpsc::channel::<Bytes>(CHANNEL_DEPTH);
        let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Bytes>(CHANNEL_DEPTH);

        // Share the device between the read and write tasks: `recv`/`send` both
        // take `&self` (concurrent recv+send on one wintun session is fine), and
        // the device is dropped — releasing the interface — only once BOTH tasks
        // end, which is exactly what the teardown wants.
        let device = Arc::new(device);
        let dev_read = device.clone();

        // Lees-taak: TUN → engine (encrypt-kant). `recv` gebruikt de ring-fast-
        // path tijdens verkeer en parkeert alleen bij idle op het OS-read-event.
        let read_task = tokio::spawn(async move {
            let mut buf = vec![0u8; TUN_READ_BUF];
            loop {
                match dev_read.recv(&mut buf).await {
                    Ok(0) => {
                        error!("TUN read: EOF");
                        break;
                    }
                    Ok(n) => {
                        debug!("TUN read {} bytes", n);
                        let pkt = Bytes::copy_from_slice(&buf[..n]);
                        if from_tun_tx.send(pkt).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("TUN read error: {e}");
                        break;
                    }
                }
            }
        });

        // Schrijf-taak: engine (decrypt-kant) → TUN.
        let write_task = tokio::spawn(async move {
            while let Some(pkt) = to_tun_rx.recv().await {
                debug!("TUN write {} bytes", pkt.len());
                if let Err(e) = device.send(&pkt).await {
                    error!("TUN write error: {e}");
                    break;
                }
            }
        });

        TunPair {
            from_tun: from_tun_rx,
            to_tun: to_tun_tx,
            read_task: Some(read_task),
            write_task: Some(write_task),
        }
    }
}

/// Uiteinden van een mock-TUN: `inject_tx` speelt "kernel → TUN", `drain_rx`
/// leest "TUN → kernel".
pub struct MockHandles {
    /// Stuur bytes in alsof ze van de TUN komen.
    pub inject_tx: mpsc::Sender<Bytes>,
    /// Lees bytes die naar de TUN gestuurd zouden worden.
    pub drain_rx: mpsc::Receiver<Bytes>,
}

// ── TUN-aanmaak (cross-platform via tun 0.8 `create_as_async`) ───────────────

/// Maak een asynchrone TUN-interface aan. tun 0.8 levert op elk platform dezelfde
/// `AsyncDevice` met `recv`/`send`; op Windows draait dat op `wintun-bindings`
/// (ring fast-path + OS-event, geen thread-per-pakket).
fn build_async_device(cfg: &TunConfig) -> Result<tun::AsyncDevice> {
    let addr: Ipv4Addr = cfg.address.parse().map_err(|e| ChameleonError::Handshake {
        state: "tun".into(),
        msg: format!("invalid tun address '{}': {e}", cfg.address),
    })?;
    let mask: Ipv4Addr = cfg.netmask.parse().map_err(|e| ChameleonError::Handshake {
        state: "tun".into(),
        msg: format!("invalid netmask '{}': {e}", cfg.netmask),
    })?;

    let mut tun_cfg = tun::Configuration::default();
    tun_cfg
        .tun_name(cfg.name.as_str())
        .address(addr)
        .netmask(mask)
        .mtu(cfg.mtu)
        .up();

    let device = tun::create_as_async(&tun_cfg).map_err(|e| ChameleonError::Handshake {
        state: "tun".into(),
        msg: format!(
            "failed to create TUN '{}': {e} \
             (Linux/macOS need CAP_NET_ADMIN or sudo; \
              Windows needs wintun.dll next to the binary — https://www.wintun.net)",
            cfg.name
        ),
    })?;

    info!(
        "TUN interface '{}' up — address {} mask {}",
        cfg.name, addr, mask
    );
    Ok(device)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifieer dat de mock-variant werkt zonder kernel-rechten.
    #[tokio::test]
    async fn mock_roundtrip() {
        let (pair, handles) = TunPair::new_mock();
        let TunPair {
            mut from_tun,
            to_tun,
            ..
        } = pair;
        let MockHandles {
            inject_tx,
            mut drain_rx,
        } = handles;

        // Simuleer: kernel stuurt pakket naar TUN.
        inject_tx
            .send(Bytes::from_static(b"fake IP packet"))
            .await
            .unwrap();
        let received = from_tun.recv().await.unwrap();
        assert_eq!(&received[..], b"fake IP packet");

        // Simuleer: engine schrijft terug naar TUN.
        to_tun
            .send(Bytes::from_static(b"decrypted IP"))
            .await
            .unwrap();
        let written = drain_rx.recv().await.unwrap();
        assert_eq!(&written[..], b"decrypted IP");
    }
}
