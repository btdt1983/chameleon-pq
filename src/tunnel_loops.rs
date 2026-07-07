//! De live tunnel-loops: outbound (TUN → engine → UDP), inbound (UDP → engine →
//! TUN, met handshake-/rekey-demux) en keepalive/dode-peer-detectie. Uit main.rs
//! gehaald zodat de orchestratie zowel testbaar (zie tests/e2e_tunnel.rs) als
//! herbruikbaar is voor andere clients dan de meegeleverde binary.
//!
//! De inbound-loop is de ENIGE socket-lezer (sole-reader-invariant); mid-sessie
//! handshake-frames gaan via een kanaal naar de rekey-driver (zie rekey.rs).

use crate::config::{AppConfig, EffectiveTraffic, TrafficMode};
use crate::crypto::Authenticator;
use crate::engine::{CryptoEngine, DecryptResult, OutboundPacket};
use crate::frame::{Frame, FrameType};
use crate::hsobf;
use crate::obf::PadPolicy;
use crate::pacer::{Emit, Pacer, ShapeMode};
use crate::rekey::{
    handshake_channel, rekey_as_initiator, rekey_as_responder, rekey_responder_confirm,
    schedule_retire,
};
use crate::tun_iface::TunPair;
use crate::tunnel::{Handshake, Reassembler};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::watch;
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

/// De configuratie-waarden die `run_tunnel_loops` nodig heeft, OWNED (geen
/// `&AppConfig`-borrow) zodat de loop als taak gespawned kan worden — precies wat
/// een client-UI wil (connect → tunnel draait op de achtergrond, UI blijft leven).
#[derive(Debug, Clone)]
pub struct TunnelParams {
    pub batch_linger_us: u64,
    pub obf_enabled: bool,
    pub padding: PadPolicy,
    pub traffic_enabled: bool,
    pub traffic_mode: TrafficMode,
    pub rate_pps: u32,
    pub burst: u16,
    pub cooldown_ms: u64,
}

impl TunnelParams {
    pub fn from_config(cfg: &AppConfig) -> Self {
        let t = cfg.traffic.effective();
        if t.enabled {
            // ~1232 B wire per packet (MTU-safe datagram); ceiling = rate×burst×size.
            let pps = t.rate_pps as u64 * t.burst as u64;
            let ceiling_mbit = pps * 1232 * 8 / 1_000_000;
            info!(
                "traffic profile: {:?} — {:?}, {}×{} = {} pps ≈ {} Mbit/s ceiling",
                cfg.traffic.profile, t.mode, t.rate_pps, t.burst, pps, ceiling_mbit
            );
        } else {
            info!(
                "traffic profile: {:?} — pacer OFF (no timing shaping, WireGuard-comparable)",
                cfg.traffic.profile
            );
        }
        Self {
            batch_linger_us: cfg.engine.batch_linger_us,
            obf_enabled: cfg.obfuscation.enabled,
            padding: cfg.obfuscation.padding.into(),
            traffic_enabled: t.enabled,
            traffic_mode: t.mode,
            rate_pps: t.rate_pps,
            burst: t.burst,
            cooldown_ms: t.cooldown_ms,
        }
    }
}

/// Live tellers voor een lopende tunnel, zodat een frontend (client-UI) status
/// kan tonen. Lock-vrij; `run_tunnel_loops` werkt ze bij. Bytes tellen de
/// PLAINTEXT (wat door de TUN gaat), niet de wire-grootte.
#[derive(Default, Debug)]
pub struct TunnelStats {
    /// True zolang de tunnel-loops draaien.
    pub connected: AtomicBool,
    /// Plaintext-bytes vanaf de TUN richting peer (uitgaand).
    pub tx_bytes: AtomicU64,
    /// Plaintext-bytes vanaf de peer richting TUN (inkomend).
    pub rx_bytes: AtomicU64,
    /// Epoch-seconden van het laatst ONTVANGEN pakket (0 = nog niets).
    pub last_recv_epoch: AtomicU64,
}

/// Draai de drie tunnel-taken (outbound, inbound, keepalive) tot een van hen
/// eindigt (peer-close, dode peer, of een gesloten TUN-kanaal). Voer eerst de
/// handshake uit (`net::run_handshake_*`) om `engine`/`peer`/`hs_obf` te krijgen.
// Veel argumenten, maar het is één centrale orchestratie-functie; ze bundelen in
// een struct zou de call-sites alleen maar omslachtiger maken.
#[allow(clippy::too_many_arguments)]
pub async fn run_tunnel_loops(
    socket: Arc<UdpSocket>,
    engine: Arc<CryptoEngine>,
    tun: TunPair,
    peer: SocketAddr,
    params: TunnelParams,
    auth: Arc<dyn Authenticator>,
    hs_obf: Option<[u8; 32]>,
    stats: Arc<TunnelStats>,
    // Live-updatable traffic params: the outbound loop reconfigures its pacer when
    // this changes (e.g. GUI profile switch) without tearing down the tunnel.
    traffic_rx: watch::Receiver<EffectiveTraffic>,
) {
    let TunPair { from_tun, to_tun } = tun;
    let linger = Duration::from_micros(params.batch_linger_us);
    stats.connected.store(true, Ordering::Relaxed);

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

    // Timing-/cover-traffic pacing (phase 3). `paced` only when the data path is
    // also obfuscated (cover packets ride on it; the config validates this).
    // Cover traffic requires obfuscation, so a live profile switch can only turn
    // pacing on when obfuscation is enabled; capture it for the outbound loop.
    let obf_on = params.obf_enabled;
    let paced = params.traffic_enabled && obf_on;
    let pace_mode = match params.traffic_mode {
        TrafficMode::Cbr => ShapeMode::Cbr,
        TrafficMode::Adaptive => ShapeMode::Adaptive,
    };
    let pace_slot = Duration::from_micros(1_000_000u64 / params.rate_pps.max(1) as u64);
    let pace_burst = params.burst.max(1) as usize;
    let pace_cooldown = Duration::from_millis(params.cooldown_ms);

    // Gedeelde GSO/GRO-state voor gebatchte UDP-I/O (quinn-udp). Faalt zelden;
    // op een kernel zonder GSO/GRO valt quinn-udp vanzelf per-pakket terug.
    let sock_state = match crate::udp::socket_state(&socket) {
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
    let stats_out = stats.clone();
    let outbound = tokio::spawn(async move {
        let mut pending: Vec<OutboundPacket> = Vec::with_capacity(MAX_BATCH);
        let mut from_tun = from_tun;
        // Ticker: fixed slot rate when pacing, otherwise the batch-linger.
        let mut tick = interval(if paced { pace_slot } else { linger });
        let mut pacer = Pacer::new(pace_mode, pace_cooldown);
        // Live-reconfigurable pacing state: a `traffic_rx` change (e.g. a GUI
        // profile switch) recomputes these without tearing down the tunnel.
        let mut paced = paced;
        let mut pace_burst = pace_burst;
        let mut traffic_rx = traffic_rx;
        let mut traffic_live = true;

        loop {
            tokio::select! {
                maybe = from_tun.recv() => {
                    match maybe {
                        Some(pkt) => {
                            stats_out.tx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
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
                        for (run, seg) in crate::udp::group_equal_sized(&slot) {
                            if let Err(e) =
                                crate::udp::batch_send(&socket_out, &state_out, peer_out, run, seg).await
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
                        let new_id = crate::net::alloc_session_id();
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
                // Live traffic-profile switch: recompute pacing on the fly, with
                // no reconnect. `if traffic_live` disables this arm once every
                // sender is gone (CLI paths keep one alive for the session).
                res = traffic_rx.changed(), if traffic_live => {
                    if res.is_err() {
                        traffic_live = false; // all senders dropped
                    } else {
                        let eff = *traffic_rx.borrow_and_update();
                        paced = eff.enabled && obf_on;
                        let new_mode = match eff.mode {
                            TrafficMode::Cbr => ShapeMode::Cbr,
                            TrafficMode::Adaptive => ShapeMode::Adaptive,
                        };
                        let new_slot =
                            Duration::from_micros(1_000_000u64 / eff.rate_pps.max(1) as u64);
                        pace_burst = eff.burst.max(1) as usize;
                        tick = interval(if paced { new_slot } else { linger });
                        pacer = Pacer::new(new_mode, Duration::from_millis(eff.cooldown_ms));
                        info!(
                            "live traffic switch: {} ({} pps)",
                            if paced { "paced" } else { "off" },
                            eff.rate_pps as u64 * eff.burst as u64
                        );
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
    let peer_in = peer;
    let stats_in = stats.clone();
    let inbound = tokio::spawn(async move {
        // Gebatchte ontvangst-buffers (GRO): één syscall levert meerdere
        // datagrammen, die we hieronder één voor één door de bestaande demux halen.
        let (mut recv_storage, mut recv_metas) = crate::udp::recv_buffers();
        // Reassembler voor mid-sessie rekey-init frames (responder-kant).
        let mut rekey_reasm = Reassembler::default();
        // Pending rekey-responder state: na de init bewaren we de (nog niet
        // vertrouwde) handshake tot de Confirm binnenkomt (wederzijdse auth).
        let mut pending_rekey: Option<(Handshake, u32)> = None;
        let mut rekey_confirm_reasm = Reassembler::default();
        let mut prune_tick = interval(Duration::from_secs(10));

        'inbound: loop {
            tokio::select! {
                _ = prune_tick.tick() => {
                    // State-Bloat-DoS-fix: ruim half-afgemaakte fragmenten op.
                    rekey_reasm.prune_old(Duration::from_secs(10));
                    rekey_confirm_reasm.prune_old(Duration::from_secs(10));
                }
                recv = crate::udp::batch_recv(&socket_in, &state_in, &mut recv_storage, &mut recv_metas) => {
                    let count = match recv {
                        Ok(c)  => c,
                        Err(e) => { error!("UDP recv: {e}"); continue; }
                    };
                    // Collect de (GRO-gesplitste) datagrammen owned, zodat de
                    // storage-borrow vrijkomt vóór de per-datagram-verwerking met
                    // awaits. De kopie is verwaarloosbaar t.o.v. de syscall-winst.
                    let datagrams: Vec<(std::net::SocketAddr, Bytes)> =
                        crate::udp::iter_datagrams(&recv_storage, &recv_metas, count)
                            .map(|(a, d)| (a, Bytes::copy_from_slice(d)))
                            .collect();

                    // Ontsleutel de batch PARALLEL over alle cores bij voldoende
                    // volume; bij een kleine batch sequentieel (vermijd overhead).
                    // Alleen de datapad-decrypt is parallel; de (zeldzame)
                    // handshake/rekey-demux blijft serieel op deze coördinator.
                    let results: Vec<DecryptResult> = if datagrams.len()
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
                            let now = now_secs();
                            last_recv_in.store(now, Ordering::Relaxed);
                            stats_in.last_recv_epoch.store(now, Ordering::Relaxed);
                            match ft {
                                FrameType::Data => {
                                    debug!("inbound {} bytes -> TUN", plain.len());
                                    stats_in.rx_bytes.fetch_add(plain.len() as u64, Ordering::Relaxed);
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
                        //
                        // M-1: accepteer control-/handshake-verkeer ALLEEN van de
                        // gevestigde peer. De rekey-demux hieronder stuurt een
                        // ~8 KB response en doet dure crypto (ML-KEM+DH+ML-DSA);
                        // met een ongepind bron-adres zou een gespooft `src`
                        // reflectie/amplificatie naar een slachtoffer toelaten én
                        // rekey-crypto op ruis verspillen. Het datapad hierboven is
                        // al door de AEAD-tag beschermd en hoeft niet gepind.
                        if src != peer_in {
                            continue;
                        }

                        // 2) Handshake-obfuscatie AAN.
                        if let Some(k) = hs_obf {
                            if let Some((mid, idx, tot, chunk)) = hsobf::unmask_fragment(&k, &datagram) {
                                last_recv_in.store(now_secs(), Ordering::Relaxed);
                                if rekeying.load(Ordering::Acquire) {
                                    let _ = hs_tx.send(datagram.clone()).await;
                                } else if pending_rekey.is_none() {
                                    if let Ok(Some(blob)) = rekey_reasm.push_parts(mid, idx, tot, chunk) {
                                        if let Ok(init_wire) = hsobf::open(&k, &blob) {
                                            let new_id = crate::net::alloc_session_id();
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
                        let now = now_secs();
                        last_recv_in.store(now, Ordering::Relaxed);
                        stats_in.last_recv_epoch.store(now, Ordering::Relaxed);
                        match frame.frame_type {
                            FrameType::Data => {
                                match engine_in.sessions().decrypt(
                                    frame.session_id, frame.sequence, &frame.payload)
                                {
                                    Ok(plain) => {
                                        debug!("inbound {} bytes -> TUN", plain.len());
                                        stats_in.rx_bytes.fetch_add(plain.len() as u64, Ordering::Relaxed);
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
                                        let new_id = crate::net::alloc_session_id();
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
                            // L-7: een cleartext Close (obf uit) is ONGEAUTHENTICEERD;
                            // niet afbreken op injectie. Een echte peer-exit wordt door
                            // de dode-peer-detectie opgevangen. (De geobfusceerde,
                            // geauthenticeerde Close hierboven breekt wél af.)
                            FrameType::Close => warn!(
                                "cleartext Close genegeerd (obf uit = ongeauthenticeerd); \
                                 tunnel blijft staan"
                            ),
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
    let obf_enabled_ka = params.obf_enabled;
    let pad_policy_ka: PadPolicy = params.padding;
    // Onder CBR-pacing stroomt er sowieso constant (cover-)verkeer, dus de
    // periodieke keepalive-send is overbodig — we slaan 'm dan over en houden
    // alleen de dode-peer-detectie. (Adaptive kan idle-stil vallen, dus daar
    // blijft de keepalive-send nodig.)
    let ka_skip_send = paced && matches!(params.traffic_mode, TrafficMode::Cbr);
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
    stats.connected.store(false, Ordering::Relaxed);
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
            for (run, seg) in crate::udp::group_equal_sized(&wires) {
                if let Err(e) = crate::udp::batch_send(socket, state, peer, run, seg).await {
                    error!("UDP batch send: {e}");
                }
            }
            debug!("flushed {} pkts", count);
        }
        Err(e) => error!("encrypt_batch: {e}"),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
