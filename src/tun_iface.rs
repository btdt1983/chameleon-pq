//! TUN-interface layer: cross-platform, asynchronous.
//!
//! Exposes two mpsc channels so the rest of the application stays
//! platform-agnostic:
//!
//!   plaintext_from_tun: Receiver<Bytes>  — IP packets coming in from the
//!                                          kernel/TUN that must be encrypted
//!                                          and sent to the peer.
//!   plaintext_to_tun:   Sender<Bytes>    — Decrypted IP packets that must
//!                                          go to the kernel/TUN.
//!
//! PLATFORM REQUIREMENTS
//!   Linux:   CAP_NET_ADMIN (or sudo) to create the TUN interface.
//!   Windows: wintun.dll next to the binary (https://www.wintun.net).
//!
//! We drive the I/O via `tun` 0.8's `AsyncDevice` (`recv`/`send`). On Windows
//! that runs on `wintun-bindings`: a `try_receive` ring fast-path that never
//! blocks during traffic, and parks one pool thread on the OS read-event when
//! idle — NOT thread-per-packet like `tun` 0.6, which caused the per-packet
//! wall and the burst instability.
//!
//! In tests (without CAP_NET_ADMIN) you can use `TunPair::new_mock()`;
//! that gives two in-memory channels offering the same API.

use crate::config::TunConfig;
use crate::error::{ChameleonError, Result};
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

const TUN_READ_BUF: usize = 65_536;
const CHANNEL_DEPTH: usize = 512;

/// The public API surface of the TUN layer.
pub struct TunPair {
    /// Read from here: plaintext IP packets heading for encrypt → UDP.
    pub from_tun: mpsc::Receiver<Bytes>,
    /// Write here: decrypted IP packets heading for the kernel.
    pub to_tun: mpsc::Sender<Bytes>,
    /// Handles to the TUN read/write tasks (None for the mock). The caller
    /// aborts + awaits these on teardown so the device is fully released before
    /// it is re-created — the read task parks on `recv()` and would otherwise
    /// keep the interface open indefinitely when idle.
    pub read_task: Option<tokio::task::JoinHandle<()>>,
    pub write_task: Option<tokio::task::JoinHandle<()>>,
}

impl TunPair {
    /// Create a real TUN interface and start the I/O tasks.
    /// Fails if the permissions are missing or the platform is unsupported.
    pub fn create(cfg: &TunConfig) -> Result<Self> {
        let device = build_async_device(cfg)?;
        Ok(Self::spawn_io(device))
    }

    /// In-memory mock (no kernel interface needed). Meant for tests and for
    /// clients that want to drive the tunnel loops without a real TUN. From
    /// outside you push bytes in via `inject_tx`; read output via `drain_rx`.
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

        // Read task: TUN → engine (encrypt side). `recv` uses the ring fast-
        // path during traffic and parks only when idle on the OS read-event.
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

        // Write task: engine (decrypt side) → TUN.
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

/// Ends of a mock TUN: `inject_tx` plays "kernel → TUN", `drain_rx`
/// reads "TUN → kernel".
pub struct MockHandles {
    /// Push bytes in as if they came from the TUN.
    pub inject_tx: mpsc::Sender<Bytes>,
    /// Read bytes that would be sent to the TUN.
    pub drain_rx: mpsc::Receiver<Bytes>,
}

// ── TUN creation (cross-platform via tun 0.8 `create_as_async`) ──────────────

/// Create an asynchronous TUN interface. tun 0.8 yields the same `AsyncDevice`
/// with `recv`/`send` on every platform; on Windows that runs on
/// `wintun-bindings` (ring fast-path + OS-event, no thread-per-packet).
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
        .up();

    // MTU: set it on Linux/macOS, but NOT on Windows. wintun keeps its own
    // default (1500) and tun 0.6 — the last version that worked on our Windows
    // client — never pushed the MTU onto the interface either. The 0.8 WinAPI
    // MTU path is an extra failure surface for no gain (the tunnel already ran
    // fine with the wintun default), so we leave it alone there.
    #[cfg(not(windows))]
    tun_cfg.mtu(cfg.mtu);

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

    /// Verify that the mock variant works without kernel permissions.
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

        // Simulate: kernel sends packet to TUN.
        inject_tx
            .send(Bytes::from_static(b"fake IP packet"))
            .await
            .unwrap();
        let received = from_tun.recv().await.unwrap();
        assert_eq!(&received[..], b"fake IP packet");

        // Simulate: engine writes back to TUN.
        to_tun
            .send(Bytes::from_static(b"decrypted IP"))
            .await
            .unwrap();
        let written = drain_rx.recv().await.unwrap();
        assert_eq!(&written[..], b"decrypted IP");
    }
}
