//! Client-core: verbind als initiator en draai de tunnel op de achtergrond, met
//! live status voor een frontend (UI). Dit is de motor die elke client — CLI,
//! GUI, service — hergebruikt. Er zit GEEN eigen crypto in: alle beveiliging komt
//! uit de handshake (`net::run_handshake_initiator`) en de tunnel-loops
//! (`tunnel_loops::run_tunnel_loops`). Een client kan zo niets verzwakken; het
//! enige wat het beveiligingsniveau bepaalt is de CONFIG (zie `security_warnings`).

use crate::config::{AppConfig, EffectiveTraffic};
use crate::crypto::{Authenticator, Ed25519Auth, HybridAuth, MlDsaAuth};
use crate::engine::CryptoEngine;
use crate::error::Result;
use crate::frame::FrameType;
use crate::net::run_handshake_initiator;
use crate::obf::PadPolicy;
use crate::session::SessionManager;
use crate::tun_iface::TunPair;
use crate::tunnel_loops::{run_tunnel_loops, TunnelParams, TunnelStats};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::watch;

/// Bouw de peer-authenticator uit de config: Ed25519, of hybride Ed25519 + ML-DSA
/// (post-quantum) als beide ML-DSA-velden gezet zijn.
pub fn build_auth(cfg: &AppConfig) -> Result<Arc<dyn Authenticator>> {
    let seed = cfg.identity.seed_bytes()?;
    let peer_pub = cfg.identity.peer_pub_bytes()?;
    let ed = Ed25519Auth::new(&seed[..], peer_pub)?;
    match (
        cfg.identity.mldsa_secret_bytes()?,
        cfg.identity.peer_mldsa_pub_bytes()?,
    ) {
        (Some(sk), Some(pk)) => {
            let mldsa = MlDsaAuth::from_keys(&sk[..], &pk)?;
            Ok(Arc::new(HybridAuth::new(vec![
                Box::new(ed),
                Box::new(mldsa),
            ])))
        }
        _ => Ok(Arc::new(ed)),
    }
}

/// Leid de statische handshake-obfuscatiesleutel af, of `None` als handshake-
/// obfuscatie uit staat. Zelfde afleiding als de server, zodat ze matchen.
pub fn hs_obf_key(cfg: &AppConfig) -> Result<Option<[u8; 32]>> {
    if !cfg.obfuscation.handshake {
        return Ok(None);
    }
    let own_pub = Ed25519Auth::derive_public(&cfg.identity.seed_bytes()?[..]);
    let peer_pub = cfg.identity.peer_pub_bytes()?;
    let psk = cfg.obfuscation.psk_bytes()?;
    Ok(Some(crate::hsobf::derive_hs_obf_key(
        &own_pub,
        &peer_pub,
        psk.as_deref(),
    )))
}

/// Luide waarschuwingen bij een config die NIET op vol beveiligingsniveau draait
/// (secure-by-default + loud warning). Een lege lijst = alle beveiliging aan.
/// Een frontend hoort deze prominent te tonen.
pub fn security_warnings(cfg: &AppConfig) -> Vec<String> {
    let mut w = Vec::new();
    if !cfg.identity.has_mldsa() {
        w.push(
            "Geen ML-DSA-sleutels: peer-auth is Ed25519-only (KLASSIEK, niet \
             post-quantum). Zet mldsa_* aan BEIDE kanten voor hybride PQ-auth."
                .into(),
        );
    }
    if !cfg.obfuscation.enabled {
        w.push(
            "obfuscation.enabled = false: het datapad is ONGEOBFUSCEERD en \
             control-frames zijn ongeauthenticeerd — alleen voor debug op een \
             vertrouwd netwerk."
                .into(),
        );
    } else if !cfg.obfuscation.handshake {
        w.push(
            "obfuscation.handshake = false: de handshake-envelope is niet verhuld \
             (een DPI-tegenstander kan 'm herkennen)."
                .into(),
        );
    } else if cfg.obfuscation.psk_hex.is_none() {
        w.push(
            "obfuscation.psk_hex niet gezet: de handshake-obf-sleutel is \
             pubkey-afgeleid (zwakker; geen DoS-gating tegen wie de pubkeys kent). \
             Zet psk_hex aan BEIDE kanten."
                .into(),
        );
    }
    // Check the EFFECTIVE traffic (after profile resolution): profile="off" (or a
    // custom profile with enabled=false) means no pacing. A stale raw `enabled`
    // field must not trigger this when a paced profile is selected.
    if !cfg.traffic.effective().enabled {
        w.push(
            "traffic-profiel \"off\": geen timing-/cover-verkeer, dus burst- en \
             idle-patronen blijven zichtbaar (bewuste snelheid-vs-verhulling-keuze)."
                .into(),
        );
    }
    w
}

/// Momentopname van de tunnel-status voor een UI.
#[derive(Debug, Clone)]
pub struct Status {
    pub connected: bool,
    pub peer: SocketAddr,
    pub session_id: u32,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// Epoch-seconden van het laatst ontvangen pakket (0 = nog niets).
    pub last_recv_epoch: u64,
    pub uptime_secs: u64,
}

/// Een verbonden client: de tunnel-loops draaien op de achtergrond; deze handle
/// geeft status en kan de tunnel sluiten.
pub struct Client {
    stats: Arc<TunnelStats>,
    task: tokio::task::JoinHandle<()>,
    peer: SocketAddr,
    session_id: u32,
    started_epoch: u64,
    /// Live control of the traffic pacer: send a new `EffectiveTraffic` to
    /// re-profile the running tunnel (e.g. GUI profile switch) without reconnect.
    traffic_tx: watch::Sender<EffectiveTraffic>,
    // Kept so `disconnect` can send an authenticated Close (fast server-side
    // teardown → fast reconnect). The SessionManager is shared with the tunnel,
    // so it tracks rekeys and the Close uses the current keys.
    sessions: Arc<SessionManager>,
    socket: Arc<UdpSocket>,
    pad: PadPolicy,
    obf: bool,
}

// Manual Debug: CryptoEngine/SessionManager aren't Debug, but a frontend's
// Message enum derives Debug over `Arc<Client>`, so Client must be Debug.
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("peer", &self.peer)
            .field("session_id", &self.session_id)
            .field("started_epoch", &self.started_epoch)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Verbind als initiator naar `server`: doe de handshake en start de
    /// tunnel-loops op de achtergrond (deze functie keert terug zodra de tunnel
    /// staat). `tun` levert de frontend: `TunPair::create` voor een echte TUN, of
    /// `TunPair::new_mock` voor tests. De handshake regelt de L-4-cookie,
    /// M-2-retries en obfuscatie zelf — de client krijgt alle beveiliging vanzelf.
    pub async fn connect(
        cfg: &AppConfig,
        server: SocketAddr,
        auth: Arc<dyn Authenticator>,
        tun: TunPair,
    ) -> Result<Self> {
        let socket = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
        let hs_obf = hs_obf_key(cfg)?;
        let session =
            run_handshake_initiator(&socket, server, auth.as_ref(), hs_obf.as_ref()).await?;
        let session_id = session.session_id;

        let pad: PadPolicy = cfg.obfuscation.padding.into();
        let engine = Arc::new(CryptoEngine::new(
            Arc::new(SessionManager::new(session)),
            cfg.obfuscation.enabled,
            pad,
        ));

        let stats = Arc::new(TunnelStats::default());
        // Meteen op verbonden zetten: de handshake IS gelukt. (run_tunnel_loops
        // zet 'm ook, maar die taak start async — anders is er een korte race
        // waarin status() nog "niet verbonden" zou melden.)
        stats.connected.store(true, Ordering::Relaxed);
        // Live pacer control: seeded with the connect-time profile; `set_traffic`
        // pushes updates that the outbound loop applies without a reconnect.
        let (traffic_tx, traffic_rx) = watch::channel(cfg.traffic.effective());
        // Clone the shared handles `disconnect` needs to send a graceful Close,
        // before `engine`/`socket` are moved into the tunnel task.
        let sessions = engine.sessions().clone();
        let socket_close = socket.clone();
        let obf = cfg.obfuscation.enabled;
        let task = tokio::spawn(run_tunnel_loops(
            socket,
            engine,
            tun,
            server,
            TunnelParams::from_config(cfg),
            auth,
            hs_obf,
            stats.clone(),
            traffic_rx,
        ));

        Ok(Self {
            stats,
            task,
            peer: server,
            session_id,
            started_epoch: now_secs(),
            traffic_tx,
            sessions,
            socket: socket_close,
            pad,
            obf,
        })
    }

    /// Live status voor een UI.
    pub fn status(&self) -> Status {
        Status {
            connected: self.stats.connected.load(Ordering::Relaxed) && !self.task.is_finished(),
            peer: self.peer,
            session_id: self.session_id,
            tx_bytes: self.stats.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.stats.rx_bytes.load(Ordering::Relaxed),
            last_recv_epoch: self.stats.last_recv_epoch.load(Ordering::Relaxed),
            uptime_secs: now_secs().saturating_sub(self.started_epoch),
        }
    }

    /// Re-profile the running tunnel's traffic pacer live, without a reconnect.
    /// Pass the resolved `EffectiveTraffic` for the desired profile; the outbound
    /// loop applies it on its next tick. No-op once the tunnel has stopped.
    pub fn set_traffic(&self, traffic: EffectiveTraffic) {
        // Err only if the tunnel task (the sole receiver) is gone — safe to ignore.
        let _ = self.traffic_tx.send(traffic);
    }

    /// Close the tunnel: stop the background task. Takes `&self` (JoinHandle::abort
    /// is `&self`) so a frontend can keep the client behind an `Arc`.
    pub fn disconnect(&self) {
        // Best-effort authenticated Close so the server tears the session down
        // immediately (instead of waiting out its dead-peer timeout) → fast
        // reconnect. Only meaningful with obfuscation on; a cleartext Close is
        // ignored by the peer (unauthenticated). Fire-and-forget: we abort next.
        if self.obf {
            if let Ok(wire) = self
                .sessions
                .seal_obf(FrameType::Close as u8, b"", self.pad)
            {
                let socket = self.socket.clone();
                let peer = self.peer;
                tokio::spawn(async move {
                    let _ = socket.send_to(&wire, peer).await;
                });
            }
        }
        self.task.abort();
        self.stats.connected.store(false, Ordering::Relaxed);
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
