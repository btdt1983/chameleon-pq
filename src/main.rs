//! Chameleon-PQ — main entry point.
//!
//! ARCHITECTUUR VAN DE MAIN LOOPS (kristalhelder):
//!
//!  ┌─────────┐   plaintext    ┌──────────────┐  encrypted frame  ┌──────────┐
//!  │   TUN   │ ─────────────► │ CryptoEngine │ ─────────────────► │   UDP    │
//!  │ (kernel)│                │    (CPU)     │                    │  socket  │
//!  │         │ ◄───────────── │              │ ◄───────────────── │          │
//!  └─────────┘   plaintext    └──────────────┘  encrypted frame   └──────────┘
//!
//!  TUN ─► engine.encrypt_batch() ─► (obf wire) ─► socket.send_to()
//!  socket.recv_from() ─► sessions.decrypt_obf()  ─► TUN
//!                         └─(bij mislukking)─► frame.decode() ─► handshake/rekey
//!
//! Het datapad is standaard geobfusceerd (obf.rs, QUIC-stijl header-protection):
//! de inbound-loop probeert eerst decrypt_obf() en valt alleen terug op het
//! cleartext-frame voor de (nog cleartext) handshake/rekey-berichten.

use bytes::Bytes;
use chameleon::config::{AppConfig, Cli, Command};
use chameleon::crypto::{Authenticator, Ed25519Auth, HybridAuth, MlDsaAuth};
use chameleon::engine::{CryptoEngine, OutboundPacket};
use chameleon::frame::{Frame, FrameType};
use chameleon::hsobf;
use chameleon::net::{run_handshake_initiator, run_handshake_responder};
use chameleon::obf::PadPolicy;
use chameleon::session::SessionManager;
use chameleon::tun_iface::TunPair;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

const UDP_BUF: usize = 65_536;
const MAX_BATCH: usize = 256;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    match &cli.command {
        Command::Keygen => {
            run_keygen();
            return Ok(());
        }
        Command::Check => {
            let cfg = AppConfig::load(&cli.config)?;
            println!(
                "Config OK — bind={} tun={}",
                cfg.network.bind_addr, cfg.tun.name
            );
            return Ok(());
        }
        _ => {}
    }

    let cfg = AppConfig::load(&cli.config)?;
    let auth = build_auth(&cfg)?;

    match &cli.command {
        Command::Server { bind } => {
            let addr = bind.unwrap_or(cfg.network.bind_addr);
            run_server(cfg, addr, auth).await?;
        }
        Command::Client { server } => {
            let addr = server.or(cfg.network.server_addr).ok_or_else(|| {
                anyhow::anyhow!(
                    "server address required (--server or network.server_addr in config)"
                )
            })?;
            run_client(cfg, addr, auth).await?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

// ── Server ───────────────────────────────────────────────────────────────────

async fn run_server(
    cfg: AppConfig,
    bind: SocketAddr,
    auth: Arc<dyn Authenticator>,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    info!("server listening on {bind}");

    let hs_obf = hs_obf_key_from_cfg(&cfg)?;
    let (session, peer) = run_handshake_responder(&socket, auth.as_ref(), hs_obf.as_ref()).await?;
    info!("session {} established with {peer}", session.session_id);

    let tun = TunPair::create(&cfg.tun)?;
    let engine = build_engine(session, &cfg);
    run_tunnel_loops(socket, engine, tun, peer, &cfg, auth.clone(), hs_obf).await;
    Ok(())
}

// ── Client ───────────────────────────────────────────────────────────────────

async fn run_client(
    cfg: AppConfig,
    server: SocketAddr,
    auth: Arc<dyn Authenticator>,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    info!("connecting to {server}");

    let hs_obf = hs_obf_key_from_cfg(&cfg)?;
    let session = run_handshake_initiator(&socket, server, auth.as_ref(), hs_obf.as_ref()).await?;
    info!("session {} established with {server}", session.session_id);

    let tun = TunPair::create(&cfg.tun)?;
    let engine = build_engine(session, &cfg);
    run_tunnel_loops(socket, engine, tun, server, &cfg, auth.clone(), hs_obf).await;
    Ok(())
}

// ── Gedeelde tunnel-loops ────────────────────────────────────────────────────

fn build_engine(session: chameleon::session::Session, cfg: &AppConfig) -> Arc<CryptoEngine> {
    let mgr = Arc::new(SessionManager::new(session));
    let pad_policy: PadPolicy = cfg.obfuscation.padding.into();
    Arc::new(CryptoEngine::new(mgr, cfg.obfuscation.enabled, pad_policy))
}

/// Leid de statische handshake-obfuscatiesleutel af uit de config (Fase 2).
/// `None` als handshake-obfuscatie uit staat; dan valt de handshake terug op het
/// klassieke cleartext-frame. De sleutel komt uit de voorgedeelde Ed25519-pubkeys
/// (eigen afgeleid uit de seed, peer uit config) of, indien gezet, uit psk_hex.
fn hs_obf_key_from_cfg(cfg: &AppConfig) -> anyhow::Result<Option<[u8; 32]>> {
    if !cfg.obfuscation.handshake {
        return Ok(None);
    }
    let own_pub = Ed25519Auth::derive_public(&cfg.identity.seed_bytes()?);
    let peer_pub = cfg.identity.peer_pub_bytes()?;
    let psk = cfg.obfuscation.psk_bytes()?;
    Ok(Some(chameleon::hsobf::derive_hs_obf_key(
        &own_pub,
        &peer_pub,
        psk.as_deref(),
    )))
}

/// Bouw de peer-authenticator uit de config. Met ML-DSA-sleutels wordt het
/// een HYBRIDE schema (Ed25519 + ML-DSA): de handshake-handtekening geldt pas
/// als beide legs valideren, zodat de authenticatie kwantum-bestendig wordt
/// zonder de klassieke garantie op te geven. Zonder ML-DSA-sleutels valt het
/// terug op Ed25519-only (klassiek).
fn build_auth(cfg: &AppConfig) -> anyhow::Result<Arc<dyn Authenticator>> {
    let seed = cfg.identity.seed_bytes()?;
    let peer_pub = cfg.identity.peer_pub_bytes()?;
    let ed = Ed25519Auth::new(&seed, peer_pub)?;

    match (
        cfg.identity.mldsa_secret_bytes()?,
        cfg.identity.peer_mldsa_pub_bytes()?,
    ) {
        (Some(sk), Some(pk)) => {
            let mldsa = MlDsaAuth::from_keys(&sk, &pk)?;
            info!("peer-auth: hybrid Ed25519 + ML-DSA-65 (post-quantum signatures)");
            Ok(Arc::new(HybridAuth::new(vec![
                Box::new(ed),
                Box::new(mldsa),
            ])))
        }
        _ => {
            warn!(
                "peer-auth: Ed25519 only — no ML-DSA keys configured (classical, \
                   not post-quantum). Run `keygen` and set the mldsa_* fields for hybrid auth."
            );
            Ok(Arc::new(ed))
        }
    }
}

async fn run_tunnel_loops(
    socket: Arc<UdpSocket>,
    engine: Arc<CryptoEngine>,
    tun: TunPair,
    peer: SocketAddr,
    cfg: &AppConfig,
    auth: Arc<dyn Authenticator>,
    hs_obf: Option<[u8; 32]>,
) {
    use chameleon::rekey::{
        handshake_channel, rekey_as_initiator, rekey_as_responder, rekey_responder_confirm,
        schedule_retire,
    };
    use chameleon::tunnel::Reassembler;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    let TunPair { from_tun, to_tun } = tun;
    let linger = Duration::from_micros(cfg.engine.batch_linger_us);

    // Kanaal waarmee de inbound-loop handshake-frames doorgeeft aan een
    // lopende rekey-driver. ZO is de inbound-loop de enige socket-lezer.
    let (hs_tx, mut hs_rx) = handshake_channel();
    // Markeert of er nu een rekey loopt (voorkomt dubbele initiatie).
    let rekeying = Arc::new(AtomicBool::new(false));

    // Keepalive / dode-peer-detectie: epoch-seconden van het laatst ontvangen
    // pakket. Een aparte taak stuurt KeepAlive bij stilte en sluit de tunnel
    // als er te lang niets binnenkomt.
    let last_recv = Arc::new(AtomicU64::new(now_secs()));
    const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
    const PEER_DEAD_AFTER: u64 = 45; // seconden zonder enig pakket = dood

    // ── Outbound: TUN → engine → UDP ─────────────────────────────
    let engine_out = engine.clone();
    let socket_out = socket.clone();
    let auth_out = auth.clone();
    let peer_out = peer;
    let rekeying_out = rekeying.clone();
    let outbound = tokio::spawn(async move {
        let mut pending: Vec<OutboundPacket> = Vec::with_capacity(MAX_BATCH);
        let mut tick = interval(linger);
        let mut from_tun = from_tun;

        loop {
            tokio::select! {
                maybe = from_tun.recv() => {
                    match maybe {
                        Some(pkt) => {
                            pending.push(OutboundPacket { plaintext: pkt });
                            if pending.len() >= MAX_BATCH {
                                flush_outbound(&engine_out, &socket_out, &mut pending, peer_out).await;
                            }
                        }
                        None => break,
                    }
                }
                _ = tick.tick() => {
                    if !pending.is_empty() {
                        flush_outbound(&engine_out, &socket_out, &mut pending, peer_out).await;
                    }
                    // Rekey-trigger: alleen als de drempel is bereikt EN er niet
                    // al een rekey loopt. We initiëren hier als INITIATOR.
                    if engine_out.sessions().needs_rekey()
                        && !rekeying_out.swap(true, Ordering::AcqRel)
                    {
                        let new_id = chameleon::net::alloc_session_id();
                        info!("rekey threshold reached — starting rekey on session {new_id}");
                        // De rekey-driver leest GEEN socket; response komt via hs_rx.
                        let r = rekey_as_initiator(
                            &socket_out, peer_out, auth_out.as_ref(),
                            engine_out.sessions(), new_id, &mut hs_rx, hs_obf.as_ref(),
                        ).await;
                        match r {
                            Ok(()) => schedule_retire(engine_out.sessions().clone()),
                            Err(e) => {
                                warn!("rekey failed: {e}");
                                // Geef de claim in de SessionManager vrij zodat een
                                // latere poging (na het anti-storm-interval) kan starten.
                                engine_out.sessions().abort_rekey();
                            }
                        }
                        rekeying_out.store(false, Ordering::Release);
                    }
                }
            }
        }
    });

    // ── Inbound: UDP → engine → TUN (+ handshake demux + prune) ───
    let engine_in = engine.clone();
    let socket_in = socket.clone();
    let auth_in = auth.clone();
    let last_recv_in = last_recv.clone();
    let inbound = tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUF];
        // Reassembler voor mid-sessie rekey-init frames (responder-kant).
        let mut rekey_reasm = Reassembler::default();
        // Pending rekey-responder state: na de init bewaren we de (nog niet
        // vertrouwde) handshake tot de Confirm binnenkomt (wederzijdse auth).
        let mut pending_rekey: Option<(chameleon::tunnel::Handshake, u32)> = None;
        let mut rekey_confirm_reasm = Reassembler::default();
        let mut prune_tick = interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                _ = prune_tick.tick() => {
                    // State-Bloat-DoS-fix: ruim half-afgemaakte fragmenten op.
                    rekey_reasm.prune_old(Duration::from_secs(10));
                    rekey_confirm_reasm.prune_old(Duration::from_secs(10));
                }
                recv = socket_in.recv_from(&mut buf) => {
                    let (n, src) = match recv {
                        Ok(v)  => v,
                        Err(e) => { error!("UDP recv: {e}"); continue; }
                    };
                    // 1) Geobfusceerd datapad EERST (data/keepalive/close). Slaagt
                    //    dit, dan is het pakket vóór ons en geauthenticeerd; het
                    //    echte type komt uit de inner framing.
                    if let Ok((ft, plain)) = engine_in.sessions().decrypt_obf(&buf[..n]) {
                        last_recv_in.store(now_secs(), Ordering::Relaxed);
                        match ft {
                            FrameType::Data => {
                                debug!("inbound {} bytes -> TUN", plain.len());
                                if to_tun.send(plain).await.is_err() { break; }
                            }
                            FrameType::KeepAlive => debug!("keepalive (obf) received"),
                            FrameType::Close => { info!("peer closed session"); break; }
                            FrameType::Handshake => {} // niet verwacht via het obf-pad
                        }
                        continue;
                    }

                    // 2) Handshake-obfuscatie AAN: alles wat geen data is, is een
                    //    (rekey-)handshake-of-ruis. We vallen hier NOOIT terug op
                    //    cleartext — een gemaskeerd byte mag niet per ongeluk als
                    //    Close/KeepAlive worden gelezen (clean break).
                    if let Some(k) = hs_obf {
                        if let Some((mid, idx, tot, chunk)) = hsobf::unmask_fragment(&k, &buf[..n]) {
                            last_recv_in.store(now_secs(), Ordering::Relaxed);
                            if rekeying.load(Ordering::Acquire) {
                                // Wij zijn rekey-initiator: geef de rauwe datagram door.
                                let _ = hs_tx.send(Bytes::copy_from_slice(&buf[..n])).await;
                            } else if pending_rekey.is_none() {
                                // Peer initieert rekey, fase 1 (init).
                                if let Ok(Some(blob)) = rekey_reasm.push_parts(mid, idx, tot, chunk) {
                                    if let Ok(init_wire) = hsobf::open(&k, &blob) {
                                        let new_id = chameleon::net::alloc_session_id();
                                        match rekey_as_responder(
                                            &socket_in, src, auth_in.as_ref(),
                                            new_id, init_wire, Some(&k),
                                        ).await {
                                            Ok(hs) => { pending_rekey = Some((hs, new_id)); }
                                            Err(e) => warn!("responder rekey (init) failed: {e}"),
                                        }
                                    }
                                }
                            } else if let Ok(Some(blob)) = rekey_confirm_reasm.push_parts(mid, idx, tot, chunk) {
                                // Fase 2 (confirm).
                                if let Ok(confirm_wire) = hsobf::open(&k, &blob) {
                                    let (hs, new_id) = pending_rekey.take().unwrap();
                                    if let Err(e) = rekey_responder_confirm(
                                        hs, auth_in.as_ref(),
                                        engine_in.sessions(), new_id, confirm_wire,
                                    ) {
                                        warn!("responder rekey (confirm) failed: {e}");
                                    } else {
                                        schedule_retire(engine_in.sessions().clone());
                                    }
                                }
                            }
                        }
                        continue;
                    }

                    // 3) Handshake-obfuscatie UIT: klassiek cleartext frame —
                    //    handshake/rekey of het niet-geobfusceerde datapad.
                    let frame = match Frame::decode(Bytes::copy_from_slice(&buf[..n])) {
                        Ok(f)  => f,
                        Err(e) => { warn!("bad frame: {e}"); continue; }
                    };
                    // Elk geldig pakket = teken van leven van de peer.
                    last_recv_in.store(now_secs(), Ordering::Relaxed);
                    match frame.frame_type {
                        FrameType::Data => {
                            match engine_in.sessions().decrypt(
                                frame.session_id, frame.sequence, &frame.payload)
                            {
                                Ok(plain) => {
                                    debug!("inbound {} bytes -> TUN", plain.len());
                                    if to_tun.send(plain).await.is_err() { break; }
                                }
                                Err(e) => debug!("decrypt drop: {e}"),
                            }
                        }
                        FrameType::Handshake => {
                            // Demux: lopende rekey die WIJ initieerden (-> hs_tx,
                            // als rauwe datagram) of een NIEUWE rekey van de peer?
                            if rekeying.load(Ordering::Acquire) {
                                let _ = hs_tx.send(Bytes::copy_from_slice(&buf[..n])).await;
                            } else if pending_rekey.is_none() {
                                if let Ok(Some(init_wire)) = rekey_reasm.push(&frame.payload) {
                                    let new_id = chameleon::net::alloc_session_id();
                                    match rekey_as_responder(
                                        &socket_in, src, auth_in.as_ref(),
                                        new_id, init_wire, None,
                                    ).await {
                                        Ok(hs) => { pending_rekey = Some((hs, new_id)); }
                                        Err(e) => warn!("responder rekey (init) failed: {e}"),
                                    }
                                }
                            } else if let Ok(Some(confirm_wire)) = rekey_confirm_reasm.push(&frame.payload) {
                                let (hs, new_id) = pending_rekey.take().unwrap();
                                if let Err(e) = rekey_responder_confirm(
                                    hs, auth_in.as_ref(),
                                    engine_in.sessions(), new_id, confirm_wire,
                                ) {
                                    warn!("responder rekey (confirm) failed: {e}");
                                } else {
                                    schedule_retire(engine_in.sessions().clone());
                                }
                            }
                        }
                        FrameType::KeepAlive => debug!("keepalive received"),
                        FrameType::Close     => { info!("peer closed session"); break; }
                    }
                }
            }
        }
    });

    // ── Keepalive + dode-peer-detectie ───────────────────────────
    // Stuurt periodiek een KeepAlive-frame en sluit de tunnel als er te
    // lang niets binnenkwam. Draait als derde taak naast in/outbound.
    let socket_ka = socket.clone();
    let last_recv_ka = last_recv.clone();
    let peer_ka = peer;
    let engine_ka = engine.clone();
    let obf_enabled_ka = cfg.obfuscation.enabled;
    let pad_policy_ka: PadPolicy = cfg.obfuscation.padding.into();
    let keepalive = tokio::spawn(async move {
        let mut ka_tick = interval(KEEPALIVE_INTERVAL);
        loop {
            ka_tick.tick().await;
            let idle = now_secs().saturating_sub(last_recv_ka.load(Ordering::Relaxed));
            if idle >= PEER_DEAD_AFTER {
                warn!("peer silent for {idle}s — declaring dead, closing tunnel");
                break;
            }
            // Stuur een keepalive zodat de andere kant óók weet dat wij leven.
            // Geobfusceerd (zodat de keepalive niet als klein vast pakket
            // opvalt) tenzij obfuscatie uit staat; dan het klassieke frame.
            let wire = if obf_enabled_ka {
                engine_ka
                    .sessions()
                    .seal_obf(FrameType::KeepAlive as u8, b"", pad_policy_ka)
                    .ok()
            } else {
                Frame {
                    frame_type: FrameType::KeepAlive,
                    session_id: 0,
                    sequence: 0,
                    payload: Bytes::new(),
                }
                .encode()
                .ok()
            };
            if let Some(wire) = wire {
                let _ = socket_ka.send_to(&wire, peer_ka).await;
            }
        }
    });

    tokio::select! {
        r = outbound  => { if let Err(e) = r { error!("outbound task: {e}"); } }
        r = inbound   => { if let Err(e) = r { error!("inbound task: {e}"); } }
        r = keepalive => { if let Err(e) = r { error!("keepalive task: {e}"); } }
    }
    info!("tunnel closed");
}

async fn flush_outbound(
    engine: &CryptoEngine,
    socket: &UdpSocket,
    pending: &mut Vec<OutboundPacket>,
    peer: SocketAddr,
) {
    let batch = std::mem::take(pending);
    let count = batch.len();
    match engine.encrypt_batch(batch) {
        Ok(wires) => {
            for wire in wires {
                if let Err(e) = socket.send_to(&wire, peer).await {
                    error!("UDP send: {e}");
                }
            }
            debug!("flushed {} pkts", count);
        }
        Err(e) => error!("encrypt_batch: {e}"),
    }
}

// ── Keygen ───────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run_keygen() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };

    // Ed25519 (klassieke leg): seed via OsRng, daaruit de publieke sleutel.
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let ed_pub_hex = hex(kp.public_key().as_ref());
    let ed_seed_hex = hex(&seed);

    // ML-DSA-65 (post-quantum leg): vol keypair (geen seed-afleiding).
    let (mldsa_pub, mldsa_sk) = MlDsaAuth::generate();
    let mldsa_pub_hex = hex(&mldsa_pub);
    let mldsa_sk_hex = hex(&mldsa_sk);

    println!("# ── Voeg toe aan config.toml van DEZE node (GEHEIM houden) ──");
    println!("[identity]");
    println!("ed25519_seed_hex   = \"{ed_seed_hex}\"");
    println!("mldsa_secret_hex   = \"{mldsa_sk_hex}\"");
    println!();
    println!("# ── Geef deze twee publieke sleutels aan de PEER (out-of-band) ──");
    println!("# (in de config van de peer onder [identity]:)");
    println!("peer_ed25519_pub_hex = \"{ed_pub_hex}\"");
    println!("peer_mldsa_pub_hex   = \"{mldsa_pub_hex}\"");
    println!();
    println!("# Laat de mldsa_*-velden weg aan BEIDE kanten voor klassieke (Ed25519-only) auth.");
}

// ── Logging init ─────────────────────────────────────────────────────────────

fn init_logging(verbosity: u8) {
    use tracing_subscriber::{fmt, EnvFilter};
    let level = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let _ = fmt()
        .with_env_filter(EnvFilter::new(level))
        .with_target(true)
        .with_thread_ids(false)
        .try_init();
}
