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
use chameleon::config::{AppConfig, Cli, Command, TrafficMode};
use chameleon::crypto::{Authenticator, Ed25519Auth, HybridAuth, MlDsaAuth};
use chameleon::engine::{CryptoEngine, OutboundPacket};
use chameleon::frame::{Frame, FrameType};
use chameleon::hsobf;
use chameleon::net::{run_handshake_initiator, run_handshake_responder};
use chameleon::obf::PadPolicy;
use chameleon::pacer::{Emit, Pacer, ShapeMode};
use chameleon::session::SessionManager;
use chameleon::tun_iface::TunPair;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

const MAX_BATCH: usize = 256;
/// Bovengrens op de outbound-wachtrij onder pacing. Bij overvol wordt het
/// nieuwste TUN-pakket getaild-dropt (TCP herstelt); ongebonden bufferen zou de
/// constante rate breken en latency opstapelen.
const MAX_QUEUE: usize = 1024;
/// Batch-drempel voor het parallelle crypto-pad (Fase C): onder deze grootte
/// verzegelen/ontsleutelen we sequentieel om de spawn_blocking+rayon-overhead
/// bij licht verkeer te vermijden.
const PAR_THRESHOLD: usize = 16;

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
    init_rayon_pool(&cfg);

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

/// Initialiseer de globale rayon-thread-pool voor parallelle crypto (Fase C).
/// `workers = 0` => automatisch alle logische cores. Eenmalig per proces; een
/// tweede aanroep (bv. rayon al lazily geïnitialiseerd) faalt stil.
fn init_rayon_pool(cfg: &AppConfig) {
    let workers = if cfg.engine.workers > 0 {
        cfg.engine.workers
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    };
    match rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build_global()
    {
        Ok(()) => info!("crypto worker pool: {workers} thread(s)"),
        Err(e) => warn!("rayon pool already initialised ({e}); using existing"),
    }
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

    // Timing-/cover-traffic pacing (Fase 3). `paced` alleen als óók het datapad
    // geobfusceerd is (cover-pakketten rijden erop; config valideert dit).
    let paced = cfg.traffic.enabled && cfg.obfuscation.enabled;
    let pace_mode = match cfg.traffic.mode {
        TrafficMode::Cbr => ShapeMode::Cbr,
        TrafficMode::Adaptive => ShapeMode::Adaptive,
    };
    let pace_slot = Duration::from_micros(1_000_000u64 / cfg.traffic.rate_pps.max(1) as u64);
    let pace_burst = cfg.traffic.burst.max(1) as usize;
    let pace_cooldown = Duration::from_millis(cfg.traffic.cooldown_ms);

    // Gedeelde GSO/GRO-state voor gebatchte UDP-I/O (quinn-udp). Faalt zelden;
    // op een kernel zonder GSO/GRO valt quinn-udp vanzelf per-pakket terug.
    let sock_state = match chameleon::udp::socket_state(&socket) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("UDP I/O state init failed: {e}");
            return;
        }
    };

    // ── Outbound: TUN → engine → UDP ─────────────────────────────
    let engine_out = engine.clone();
    let socket_out = socket.clone();
    let auth_out = auth.clone();
    let peer_out = peer;
    let rekeying_out = rekeying.clone();
    let state_out = sock_state.clone();
    let outbound = tokio::spawn(async move {
        let mut pending: Vec<OutboundPacket> = Vec::with_capacity(MAX_BATCH);
        let mut from_tun = from_tun;
        // Ticker: het vaste slot-tempo bij pacing, anders de batch-linger.
        let mut tick = interval(if paced { pace_slot } else { linger });
        let mut pacer = Pacer::new(pace_mode, pace_cooldown);

        loop {
            tokio::select! {
                maybe = from_tun.recv() => {
                    match maybe {
                        Some(pkt) => {
                            if paced {
                                // Bounded queue met tail-drop (zie MAX_QUEUE).
                                if pending.len() >= MAX_QUEUE {
                                    debug!("outbound queue full — tail-drop");
                                } else {
                                    pending.push(OutboundPacket { plaintext: pkt });
                                }
                            } else {
                                pending.push(OutboundPacket { plaintext: pkt });
                                if pending.len() >= MAX_BATCH {
                                    flush_outbound(&engine_out, &socket_out, &state_out, &mut pending, peer_out).await;
                                }
                            }
                        }
                        None => break,
                    }
                }
                _ = tick.tick() => {
                    if paced {
                        // Emit `burst` datagrammen per slot en verstuur ze in ÉÉN
                        // GSO-syscall: echte pakketten uit de wachtrij, lege slots
                        // gevuld met cover — alle op constante grootte (Full), zodat
                        // rate én grootte constant blijven en de slot-burst (die de
                        // pacer sowieso al produceert) in één syscall past.
                        let mut slot: Vec<Bytes> = Vec::with_capacity(pace_burst);
                        for _ in 0..pace_burst {
                            match pacer.next_emit(!pending.is_empty(), Instant::now()) {
                                Emit::Real => {
                                    let pkt = pending.remove(0);
                                    match engine_out.seal_data_full(&pkt.plaintext) {
                                        Ok(wire) => slot.push(wire),
                                        Err(e) => error!("seal data: {e}"),
                                    }
                                }
                                Emit::Cover => match engine_out.cover_datagram() {
                                    Ok(wire) => slot.push(wire),
                                    Err(e) => error!("cover datagram: {e}"),
                                },
                                // Adaptive-idle: niets meer te sturen dit slot.
                                Emit::Idle => break,
                            }
                        }
                        for (run, seg) in chameleon::udp::group_equal_sized(&slot) {
                            if let Err(e) =
                                chameleon::udp::batch_send(&socket_out, &state_out, peer_out, run, seg).await
                            {
                                error!("UDP batch send (paced): {e}");
                            }
                        }
                    } else if !pending.is_empty() {
                        flush_outbound(&engine_out, &socket_out, &state_out, &mut pending, peer_out).await;
                    }

                    // Rekey-trigger (gedeeld): drempel bereikt EN geen lopende rekey.
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
    let state_in = sock_state.clone();
    let inbound = tokio::spawn(async move {
        // Gebatchte ontvangst-buffers (GRO): één syscall levert meerdere
        // datagrammen, die we hieronder één voor één door de bestaande demux halen.
        let (mut recv_storage, mut recv_metas) = chameleon::udp::recv_buffers();
        // Reassembler voor mid-sessie rekey-init frames (responder-kant).
        let mut rekey_reasm = Reassembler::default();
        // Pending rekey-responder state: na de init bewaren we de (nog niet
        // vertrouwde) handshake tot de Confirm binnenkomt (wederzijdse auth).
        let mut pending_rekey: Option<(chameleon::tunnel::Handshake, u32)> = None;
        let mut rekey_confirm_reasm = Reassembler::default();
        let mut prune_tick = interval(Duration::from_secs(10));

        'inbound: loop {
            tokio::select! {
                _ = prune_tick.tick() => {
                    // State-Bloat-DoS-fix: ruim half-afgemaakte fragmenten op.
                    rekey_reasm.prune_old(Duration::from_secs(10));
                    rekey_confirm_reasm.prune_old(Duration::from_secs(10));
                }
                recv = chameleon::udp::batch_recv(&socket_in, &state_in, &mut recv_storage, &mut recv_metas) => {
                    let count = match recv {
                        Ok(c)  => c,
                        Err(e) => { error!("UDP recv: {e}"); continue; }
                    };
                    // Collect de (GRO-gesplitste) datagrammen owned, zodat de
                    // storage-borrow vrijkomt vóór de per-datagram-verwerking met
                    // awaits. De kopie is verwaarloosbaar t.o.v. de syscall-winst.
                    let datagrams: Vec<(std::net::SocketAddr, Bytes)> =
                        chameleon::udp::iter_datagrams(&recv_storage, &recv_metas, count)
                            .map(|(a, d)| (a, Bytes::copy_from_slice(d)))
                            .collect();

                    // Ontsleutel de batch PARALLEL over alle cores bij voldoende
                    // volume; bij een kleine batch sequentieel (vermijd overhead).
                    // Alleen de datapad-decrypt is parallel; de (zeldzame)
                    // handshake/rekey-demux blijft serieel op deze coördinator.
                    let results: Vec<chameleon::engine::DecryptResult> = if datagrams.len()
                        >= PAR_THRESHOLD
                    {
                        let engine = engine_in.clone();
                        match tokio::task::spawn_blocking(move || engine.decrypt_batch_par(&datagrams))
                            .await
                        {
                            Ok(r) => r,
                            Err(e) => {
                                error!("decrypt task join error: {e}");
                                continue;
                            }
                        }
                    } else {
                        datagrams
                            .into_iter()
                            .map(|(src, dg)| {
                                let r = engine_in.sessions().decrypt_obf(&dg);
                                (src, dg, r)
                            })
                            .collect()
                    };

                    for (src, datagram, result) in results {
                        // 1) Datapad (parallel ontsleuteld): direct afhandelen.
                        if let Ok((ft, plain)) = result {
                            last_recv_in.store(now_secs(), Ordering::Relaxed);
                            match ft {
                                FrameType::Data => {
                                    debug!("inbound {} bytes -> TUN", plain.len());
                                    if to_tun.send(plain).await.is_err() { break 'inbound; }
                                }
                                FrameType::KeepAlive => debug!("keepalive (obf) received"),
                                FrameType::Close => { info!("peer closed session"); break 'inbound; }
                                FrameType::Handshake => {} // niet verwacht via het obf-pad
                                FrameType::Padding => debug!("cover packet discarded"),
                            }
                            continue;
                        }

                        // Geen datapad → handshake-fragment of ruis: SERIEEL op de
                        // coördinator (rekey-state blijft op één thread).
                        // 2) Handshake-obfuscatie AAN.
                        if let Some(k) = hs_obf {
                            if let Some((mid, idx, tot, chunk)) = hsobf::unmask_fragment(&k, &datagram) {
                                last_recv_in.store(now_secs(), Ordering::Relaxed);
                                if rekeying.load(Ordering::Acquire) {
                                    let _ = hs_tx.send(datagram.clone()).await;
                                } else if pending_rekey.is_none() {
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

                        // 3) Handshake-obfuscatie UIT: klassiek cleartext frame.
                        let frame = match Frame::decode(datagram.clone()) {
                            Ok(f)  => f,
                            Err(e) => { warn!("bad frame: {e}"); continue; }
                        };
                        last_recv_in.store(now_secs(), Ordering::Relaxed);
                        match frame.frame_type {
                            FrameType::Data => {
                                match engine_in.sessions().decrypt(
                                    frame.session_id, frame.sequence, &frame.payload)
                                {
                                    Ok(plain) => {
                                        debug!("inbound {} bytes -> TUN", plain.len());
                                        if to_tun.send(plain).await.is_err() { break 'inbound; }
                                    }
                                    Err(e) => debug!("decrypt drop: {e}"),
                                }
                            }
                            FrameType::Handshake => {
                                if rekeying.load(Ordering::Acquire) {
                                    let _ = hs_tx.send(datagram.clone()).await;
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
                            FrameType::Close     => { info!("peer closed session"); break 'inbound; }
                            FrameType::Padding => {}
                        }
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
    // Onder CBR-pacing stroomt er sowieso constant (cover-)verkeer, dus de
    // periodieke keepalive-send is overbodig — we slaan 'm dan over en houden
    // alleen de dode-peer-detectie. (Adaptive kan idle-stil vallen, dus daar
    // blijft de keepalive-send nodig.)
    let ka_skip_send = paced && matches!(cfg.traffic.mode, TrafficMode::Cbr);
    let keepalive = tokio::spawn(async move {
        let mut ka_tick = interval(KEEPALIVE_INTERVAL);
        loop {
            ka_tick.tick().await;
            let idle = now_secs().saturating_sub(last_recv_ka.load(Ordering::Relaxed));
            if idle >= PEER_DEAD_AFTER {
                warn!("peer silent for {idle}s — declaring dead, closing tunnel");
                break;
            }
            if ka_skip_send {
                continue; // CBR-cover levert het leven-signaal al
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
    engine: &Arc<CryptoEngine>,
    socket: &UdpSocket,
    state: &quinn_udp::UdpSocketState,
    pending: &mut Vec<OutboundPacket>,
    peer: SocketAddr,
) {
    let batch = std::mem::take(pending);
    let count = batch.len();
    // Kleine batch: sequentieel (vermijd de spawn_blocking+rayon-overhead).
    // Grote batch: verzegel PARALLEL over alle cores via één spawn_blocking-hop.
    let sealed = if count < PAR_THRESHOLD {
        engine.encrypt_batch(batch)
    } else {
        let engine = engine.clone();
        match tokio::task::spawn_blocking(move || engine.encrypt_batch_par(batch)).await {
            Ok(r) => r,
            Err(e) => {
                error!("seal task join error: {e}");
                return;
            }
        }
    };
    match sealed {
        Ok(wires) => {
            // Verstuur gelijk-grote runs in zo min mogelijk syscalls (GSO waar
            // mogelijk). Onder Full is de hele batch één run → één GSO-call.
            for (run, seg) in chameleon::udp::group_equal_sized(&wires) {
                if let Err(e) = chameleon::udp::batch_send(socket, state, peer, run, seg).await {
                    error!("UDP batch send: {e}");
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
