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
//! In tests (zonder CAP_NET_ADMIN) kun je `TunPair::new_mock()` gebruiken;
//! dat geeft twee in-memory kanalen die dezelfde API bieden.

use crate::config::TunConfig;
use crate::error::{ChameleonError, Result};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
}

impl TunPair {
    /// Maak een echte TUN-interface aan en start de I/O-taken.
    /// Faalt als de rechten ontbreken of het platform niet ondersteund wordt.
    pub fn create(cfg: &TunConfig) -> Result<Self> {
        let iface = build_tun(cfg)?;
        Ok(Self::spawn_io(iface))
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
        };
        (
            pair,
            MockHandles {
                inject_tx,
                drain_rx,
            },
        )
    }

    fn spawn_io<T>(iface: T) -> Self
    where
        T: AsyncReadExt + AsyncWriteExt + Send + Unpin + 'static,
    {
        let (from_tun_tx, from_tun_rx) = mpsc::channel::<Bytes>(CHANNEL_DEPTH);
        let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Bytes>(CHANNEL_DEPTH);

        // Split the device into independent read/write halves so we can
        // move each into its own task without a borrow conflict.
        let (mut reader, mut writer) = tokio::io::split(iface);

        // Lees-taak: TUN → engine (encrypt-kant)
        tokio::spawn(async move {
            let mut buf = vec![0u8; TUN_READ_BUF];
            loop {
                match reader.read(&mut buf).await {
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

        // Schrijf-taak: engine (decrypt-kant) → TUN
        tokio::spawn(async move {
            while let Some(pkt) = to_tun_rx.recv().await {
                debug!("TUN write {} bytes", pkt.len());
                if let Err(e) = writer.write_all(&pkt).await {
                    error!("TUN write error: {e}");
                    break;
                }
            }
        });

        TunPair {
            from_tun: from_tun_rx,
            to_tun: to_tun_tx,
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

// ── Platform-specifieke TUN-aanmaak ─────────────────────────────────────────

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn build_tun(
    cfg: &TunConfig,
) -> Result<impl AsyncReadExt + AsyncWriteExt + Send + Unpin + 'static> {
    use std::net::Ipv4Addr;

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
        .name(&cfg.name)
        .address(addr)
        .netmask(mask)
        .mtu(cfg.mtu as i32)
        .up();

    // tun::create_as_async geeft een AsyncDevice die AsyncRead + AsyncWrite implementeert.
    let device = tun::create_as_async(&tun_cfg).map_err(|e| ChameleonError::Handshake {
        state: "tun".into(),
        msg: format!(
            "failed to create TUN '{}': {e} (do you have CAP_NET_ADMIN?)",
            cfg.name
        ),
    })?;

    info!(
        "TUN interface '{}' up — address {} mask {}",
        cfg.name, addr, mask
    );
    Ok(device)
}

#[cfg(target_os = "windows")]
fn build_tun(
    cfg: &TunConfig,
) -> Result<impl AsyncReadExt + AsyncWriteExt + Send + Unpin + 'static> {
    use std::net::Ipv4Addr;

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
        .name(&cfg.name)
        .address(addr)
        .netmask(mask)
        .mtu(cfg.mtu as i32)
        .up();

    let device = tun::create_as_async(&tun_cfg).map_err(|e| ChameleonError::Handshake {
        state: "tun".into(),
        msg: format!(
            "failed to create TUN '{}': {e} \
             (Windows requires wintun.dll in the same directory as the binary — \
              download from https://www.wintun.net)",
            cfg.name
        ),
    })?;

    info!("TUN interface '{}' up (Windows/Wintun)", cfg.name);
    Ok(device)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn build_tun(
    _cfg: &TunConfig,
) -> Result<impl AsyncReadExt + AsyncWriteExt + Send + Unpin + 'static> {
    Err(ChameleonError::Handshake {
        state: "tun".into(),
        msg: format!("TUN not supported on platform '{}'", std::env::consts::OS),
    })
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
