//! The live tunnel loops: outbound (TUN → engine → UDP), inbound (UDP → engine →
//! TUN, with handshake/rekey demux) and keepalive/dead-peer detection. Pulled out
//! of main.rs so the orchestration is both testable (see tests/e2e_tunnel.rs) and
//! reusable for clients other than the bundled binary.
//!
//! The inbound loop is the ONLY socket reader (sole-reader invariant); mid-session
//! handshake frames go via a channel to the rekey driver (see rekey.rs).

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
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, error, info, trace, warn};

const MAX_BATCH: usize = 256;
/// Upper bound on the outbound queue under pacing. When full, the newest TUN
/// packet is tail-dropped; unbounded buffering would break the constant rate
/// and pile up latency. But "TCP recovers" undersells the cost of dropping
/// too early: TCP reads a tail-drop as congestion and halves its window, so a
/// queue too shallow for the configured pace rate causes exactly the
/// collapse-and-slowly-recover cycle it's meant to avoid — observed in
/// practice on the Throughput profile (6000x8 ≈ 473 Mbit ceiling), where a
/// single TCP burst overflowed the old 1024-packet cap in under a
/// millisecond and tanked a whole test to ~5 Mbit. Sized to comfortably hold
/// roughly one RTT (~40ms against a WAN peer) of Throughput's peak rate
/// (473 Mbit/s / 8 * 0.04s / ~1232B/packet ≈ 1920 packets) with headroom.
const MAX_QUEUE: usize = 4096;
/// Fix #2: depth of the sealed-batch hand-off channel between the outbound drain
/// loop and the single UDP sender task (used by the PACED path's residue
/// flush only now — see the tick arm). Also reused as the depth of the
/// reserve-order channel between the outbound reader and
/// `run_sequential_sender` (same "how many in-flight batches" shape, no
/// reason for a second constant). Bounded so a slow consumer back-pressures
/// the loop (→ from_tun → wintun → TCP) instead of buffering unboundedly.
const SEND_PIPELINE_BATCHES: usize = 16;

/// The configuration values that `run_tunnel_loops` needs, OWNED (no
/// `&AppConfig` borrow) so the loop can be spawned as a task — exactly what a
/// client UI wants (connect → tunnel runs in the background, UI stays alive).
#[derive(Debug, Clone)]
pub struct TunnelParams {
    pub batch_linger_us: u64,
    pub gso: bool,
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
            gso: cfg.engine.gso,
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

// ── Crypto dispatch: reserve counters, seal/decrypt on rayon's warm pool ───
//
// Modeled on wireguard-go's own device pipeline (RoutineEncryption/
// RoutineDecryption worker pools + RoutineSequentialSender), not on a
// per-batch "big enough to bother going parallel" size threshold — four
// rounds of tuning that threshold (spawn_blocking-gated, then a dedicated
// worker-thread-gated) each under-performed or, worse, introduced a real
// ordering bug (see `dispatch_seal`'s doc). wireguard-go's actual shape:
// fix each element's position in the stream FIRST (cheap), THEN hand the
// (possibly slow, possibly parallel) work to a warm pool, and only enforce
// ORDER on the way back out — never on the way in. That is what
// `dispatch_seal` / `run_sequential_sender` (outbound) and the inbound
// dispatch in `run_tunnel_loops` below implement; there is no size
// threshold anywhere in this module anymore.
//
// rayon's global pool (already used and proven elsewhere in this crate —
// `encrypt_batch_par`/`decrypt_batch_par`) is the "warm pool": `rayon::spawn`
// injects a job into an ALREADY-RUNNING work-stealing pool (no OS thread to
// wake, no thread-pool hand-off), unlike the two things tried before it
// (`tokio::task::spawn_blocking`, and a hand-rolled dedicated `std::thread`
// parked in a channel `recv()`) which both showed measurable, live-tested
// dispatch overhead.

/// Every `rayon::spawn` crypto job in this module MUST go through this.
/// `rayon::spawn`'s job type has NO `catch_unwind` of its own (checked
/// against the vendored rayon-core source): an escaping panic calls
/// `std::process::abort()`, which kills the WHOLE SERVER PROCESS — every
/// session, not just this connection — unlike a panic in a tokio task
/// (contained, surfaces as `JoinError::is_panic()`) or the old dedicated
/// `std::thread` design (contained to that thread). The realistic panic
/// surface here is thin (the parsers this touches are Result/Option-
/// returning, not `.unwrap()`-on-attacker-data), but the blast radius is
/// severe enough to close unconditionally rather than rely on that staying
/// true forever.
fn rayon_spawn_guarded<F, T>(f: F, tx: tokio::sync::oneshot::Sender<crate::error::Result<T>>)
where
    F: FnOnce() -> crate::error::Result<T> + Send + 'static,
    T: Send + 'static,
{
    rayon::spawn(move || {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| {
            Err(crate::error::ChameleonError::Internal(
                "crypto worker panicked".into(),
            ))
        });
        let _ = tx.send(r); // Err = receiver dropped (teardown) — harmless
    });
}

/// Reserve counters for the WHOLE batch right here (one atomic op — see
/// `CryptoEngine::reserve`), fixing its position in the outbound counter
/// sequence BEFORE any parallel work starts, then dispatch the actual seal
/// to rayon. This ordering is the fix for a real bug hit during development:
/// an earlier version fired batches at a worker WITHOUT reserving counters
/// first, so a batch that started sealing later but finished sooner could
/// grab LOWER counters than one still in flight — sending packets out of
/// counter order, which the peer's replay window doesn't tolerate
/// unboundedly and started rejecting as replays. Reserving up front makes
/// that impossible: the counter range is fixed before dispatch, so whichever
/// order the seals actually complete in, the SEQUENCE they belong to never
/// changes — only `run_sequential_sender`'s draining has to respect it.
///
/// Never blocks on sealing itself — only on the (typically instant) call to
/// `CryptoEngine::reserve`, which is a single atomic fetch_add.
fn dispatch_seal(
    engine: &Arc<CryptoEngine>,
    batch: Vec<OutboundPacket>,
) -> crate::error::Result<tokio::sync::oneshot::Receiver<crate::error::Result<Vec<Bytes>>>> {
    let (sess, base_counter) = engine.reserve(batch.len() as u64)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let engine = engine.clone();
    rayon_spawn_guarded(
        move || engine.seal_batch_with_counters(&sess, base_counter, &batch),
        tx,
    );
    Ok(rx)
}

/// Drains `order_rx` strictly FIFO — the order `dispatch_seal` calls
/// happened in, i.e. `from_tun` drain order — awaiting each batch's seal
/// result before considering the next, so on-wire order always matches
/// reservation order even though sealing itself may finish in a different
/// order across batches (see `dispatch_seal`'s doc for why this matters).
/// Once a result is in hand, opportunistically drains any OTHER
/// already-completed results (non-blocking) before flushing to the socket,
/// so a burst of quickly-finished small batches still goes out in as few
/// GSO syscalls as possible — the moment a next one isn't ready yet, drainage
/// stops and that receiver is remembered (never skipped) for the following
/// iteration, which awaits it properly. This is the only place order is
/// enforced; `dispatch_seal`'s callers never wait for it.
async fn run_sequential_sender(
    mut order_rx: tokio::sync::mpsc::Receiver<
        tokio::sync::oneshot::Receiver<crate::error::Result<Vec<Bytes>>>,
    >,
    socket: Arc<UdpSocket>,
    state: Arc<quinn_udp::UdpSocketState>,
    peer: SocketAddr,
    gso: bool,
) {
    use tokio::sync::oneshot::error::TryRecvError;

    let mut pending = None;
    loop {
        let next = match pending.take() {
            Some(rx) => rx,
            None => match order_rx.recv().await {
                Some(rx) => rx,
                None => break, // reader gone -> teardown
            },
        };
        let mut wires: Vec<Bytes> = Vec::new();
        match next.await {
            Ok(Ok(w)) => wires.extend(w),
            Ok(Err(e)) => error!("seal: {e}"),
            Err(_) => {} // sealer dropped without replying — shouldn't happen
        }
        // Opportunistic batching: only ever consume a LATER item while the
        // one we just popped is confirmed already-ready — the instant one
        // isn't, stash it as `pending` (never drop it) and stop draining for
        // this flush; the next loop iteration awaits it for real, preserving
        // order exactly.
        loop {
            let Ok(mut next_rx) = order_rx.try_recv() else {
                break;
            };
            match next_rx.try_recv() {
                Ok(Ok(w)) => wires.extend(w),
                Ok(Err(e)) => error!("seal: {e}"),
                Err(TryRecvError::Closed) => {} // sealer dropped — skip, keep draining
                Err(TryRecvError::Empty) => {
                    pending = Some(next_rx);
                    break;
                }
            }
        }
        if wires.is_empty() {
            continue;
        }
        for (run, seg) in crate::udp::group_equal_sized(&wires) {
            if let Err(e) = crate::udp::batch_send(&socket, &state, peer, run, seg, gso).await {
                error!("UDP batch send (sequential): {e}");
            }
        }
    }
}

/// Live counters for a running tunnel, so a frontend (client UI) can show
/// status. Lock-free; `run_tunnel_loops` updates them. Bytes count the
/// PLAINTEXT (what goes through the TUN), not the wire size.
#[derive(Default, Debug)]
pub struct TunnelStats {
    /// True while the tunnel loops are running.
    pub connected: AtomicBool,
    /// Plaintext bytes from the TUN toward the peer (outbound).
    pub tx_bytes: AtomicU64,
    /// Plaintext bytes from the peer toward the TUN (inbound).
    pub rx_bytes: AtomicU64,
    /// Epoch seconds of the last RECEIVED packet (0 = nothing yet).
    pub last_recv_epoch: AtomicU64,
}

/// Run the three tunnel tasks (outbound, inbound, keepalive) until one of them
/// ends (peer close, dead peer, or a closed TUN channel). First run the
/// handshake (`net::run_handshake_*`) to obtain `engine`/`peer`/`hs_obf`.
// Many arguments, but it is one central orchestration function; bundling them in
// a struct would only make the call sites more cumbersome.
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
    let TunPair {
        from_tun,
        to_tun,
        read_task,
        write_task,
    } = tun;
    // Abort-on-drop guard: if this future is cancelled (Client::disconnect aborts
    // the task), stop the TUN read/write tasks too — the read task blocks on
    // read() and would otherwise keep the interface open, breaking the next
    // connect. On a normal return we also abort+await them explicitly below.
    struct TunGuard(Vec<tokio::task::AbortHandle>);
    impl Drop for TunGuard {
        fn drop(&mut self) {
            for h in &self.0 {
                h.abort();
            }
        }
    }
    let _tun_guard = TunGuard(
        [read_task.as_ref(), write_task.as_ref()]
            .into_iter()
            .flatten()
            .map(|h| h.abort_handle())
            .collect(),
    );
    let linger = Duration::from_micros(params.batch_linger_us);
    stats.connected.store(true, Ordering::Relaxed);

    // Channel the inbound loop uses to pass handshake frames to a running
    // rekey driver. THIS keeps the inbound loop the only socket reader.
    let (hs_tx, mut hs_rx) = handshake_channel();
    // Marks whether a rekey is running now (prevents double initiation).
    let rekeying = Arc::new(AtomicBool::new(false));

    // Keepalive / dead-peer detection: epoch seconds of the last received
    // packet. A separate task sends KeepAlive on silence and closes the tunnel
    // if nothing arrives for too long.
    let last_recv = Arc::new(AtomicU64::new(now_secs()));
    const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
    const PEER_DEAD_AFTER: u64 = 45; // seconds without any packet = dead

    // Timing-/cover-traffic pacing (phase 3). `paced` only when the data path is
    // also obfuscated (cover packets ride on it; the config validates this).
    // Cover traffic requires obfuscation, so a live profile switch can only turn
    // pacing on when obfuscation is enabled; capture it for the outbound loop.
    let obf_on = params.obf_enabled;
    let gso = params.gso;
    let paced = params.traffic_enabled && obf_on;
    let pace_mode = match params.traffic_mode {
        TrafficMode::Cbr => ShapeMode::Cbr,
        TrafficMode::Adaptive => ShapeMode::Adaptive,
    };
    let pace_slot = Duration::from_micros(1_000_000u64 / params.rate_pps.max(1) as u64);
    let pace_burst = params.burst.max(1) as usize;
    let pace_cooldown = Duration::from_millis(params.cooldown_ms);

    // Shared GSO/GRO state for batched UDP I/O (quinn-udp). Rarely fails;
    // on a kernel without GSO/GRO quinn-udp falls back to per-packet on its own.
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
    // Run the three loops in a JoinSet so all of them are aborted when this
    // function returns OR is cancelled (Client::disconnect aborts this task). A
    // plain select! on JoinHandles detaches the losers, leaking a tunnel that
    // keeps sending — which broke disconnect and the server's session loop.
    let mut tasks = tokio::task::JoinSet::new();
    // Fix #2: single UDP sender task. The outbound loop SEALS (assigns AEAD
    // counters in from_tun drain order) then ships wires here; this ONE task pops
    // FIFO and awaits the sends, so on-wire order == counter order. Spawned INTO
    // `tasks` so tasks.shutdown()/drop aborts it — a detached tokio::spawn would
    // leak a live sender.
    let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<Vec<Bytes>>(SEND_PIPELINE_BATCHES);
    {
        let socket_snd = socket.clone();
        let state_snd = sock_state.clone();
        let peer_snd = peer;
        let gso_snd = gso;
        tasks.spawn(async move {
            while let Some(wires) = send_rx.recv().await {
                for (run, seg) in crate::udp::group_equal_sized(&wires) {
                    if let Err(e) =
                        crate::udp::batch_send(&socket_snd, &state_snd, peer_snd, run, seg, gso_snd)
                            .await
                    {
                        error!("UDP batch send (pipeline): {e}");
                    }
                }
            }
        });
    }
    // Reserve-order channel + sequential sender (see the module-level doc
    // above `dispatch_seal`/`run_sequential_sender`): the outbound drain loop
    // below reserves AEAD counters for a batch, fires the actual seal at
    // rayon, and pushes the receiver here WITHOUT waiting — full pipelining
    // across batches. `run_sequential_sender` is what enforces on-wire order,
    // by draining this channel strictly FIFO.
    let (order_tx, order_rx) = tokio::sync::mpsc::channel(SEND_PIPELINE_BATCHES);
    tasks.spawn(run_sequential_sender(
        order_rx,
        socket.clone(),
        sock_state.clone(),
        peer,
        gso,
    ));
    tasks.spawn(async move {
        // VecDeque, not Vec: the paced tick arm pops from the front every slot
        // (Vec::remove(0) would shift every remaining element — O(n) per pop,
        // O(n^2) to drain a burst).
        // Pre-sized to MAX_QUEUE, not MAX_BATCH: this is the buffer meant to
        // absorb a burst up to that cap, so it shouldn't need to reallocate
        // while doing exactly that.
        let mut pending: VecDeque<OutboundPacket> = VecDeque::with_capacity(MAX_QUEUE);
        let mut drained: Vec<Bytes> = Vec::with_capacity(MAX_BATCH);
        let mut from_tun = from_tun;
        // Ticker: fixed slot rate when pacing, otherwise the batch-linger.
        // MissedTickBehavior::Skip (not the tokio default Burst): if a paced
        // slot's synchronous seal_data_full() calls ever take longer than
        // pace_slot (e.g. burst=8 in a 166us slot at Throughput leaves only
        // ~21us/packet — tight without AES-NI/AVX2), Burst would fire every
        // missed tick back-to-back to catch up, which both starves other
        // tasks (the TUN-read producer feeding `pending`) AND defeats the
        // whole point of a CONSTANT-rate pacer (bursty catch-up is exactly
        // the timing signal this module exists to hide). Skip just drops the
        // ticks it couldn't make and stays on the original schedule instead.
        let mut tick = interval(if paced { pace_slot } else { linger });
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut pacer = Pacer::new(pace_mode, pace_cooldown);
        // Live-reconfigurable pacing state: a `traffic_rx` change (e.g. a GUI
        // profile switch) recomputes these without tearing down the tunnel.
        let mut paced = paced;
        let mut pace_burst = pace_burst;
        let mut traffic_rx = traffic_rx;
        let mut traffic_live = true;

        loop {
            tokio::select! {
                n = from_tun.recv_many(&mut drained, MAX_BATCH) => {
                    if n == 0 {
                        break; // channel closed → teardown
                    }
                    for pkt in &drained {
                        stats_out.tx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    }
                    if paced {
                        // PACED: stage into `pending` (bounded, tail-drop); the tick
                        // arm emits at the constant slot rate.
                        for pkt in drained.drain(..) {
                            if pending.len() >= MAX_QUEUE {
                                debug!("outbound queue full — tail-drop");
                            } else {
                                pending.push_back(OutboundPacket { plaintext: pkt });
                            }
                        }
                    } else {
                        // NON-PACED throughput path: reserve this batch's
                        // counters right here (fixes on-wire order), dispatch
                        // the seal to rayon, and hand the receiver to
                        // run_sequential_sender — no waiting, no size
                        // threshold, full pipelining across batches. See the
                        // module-level doc above `dispatch_seal`.
                        let batch: Vec<OutboundPacket> = drained
                            .drain(..)
                            .map(|plaintext| OutboundPacket { plaintext })
                            .collect();
                        match dispatch_seal(&engine_out, batch) {
                            Ok(rx) => {
                                if order_tx.send(rx).await.is_err() {
                                    break; // sequential sender gone
                                }
                            }
                            Err(e) => error!("reserve: {e}"),
                        }
                    }
                }
                _ = tick.tick() => {
                    if paced {
                        // Emit `burst` datagrams per slot and send them in ONE
                        // GSO syscall: real packets from the queue, empty slots
                        // filled with cover — all at constant size (Full), so
                        // rate and size stay constant and the slot burst (which
                        // the pacer already produces anyway) fits in one syscall.
                        let mut slot: Vec<Bytes> = Vec::with_capacity(pace_burst);
                        for _ in 0..pace_burst {
                            match pacer.next_emit(!pending.is_empty(), Instant::now()) {
                                Emit::Real => {
                                    let pkt = pending
                                        .pop_front()
                                        .expect("Emit::Real implies pending is non-empty");
                                    match engine_out.seal_data_full(&pkt.plaintext) {
                                        Ok(wire) => slot.push(wire),
                                        Err(e) => error!("seal data: {e}"),
                                    }
                                }
                                Emit::Cover => match engine_out.cover_datagram() {
                                    Ok(wire) => slot.push(wire),
                                    Err(e) => error!("cover datagram: {e}"),
                                },
                                // Adaptive-idle: nothing left to send this slot.
                                Emit::Idle => break,
                            }
                        }
                        for (run, seg) in crate::udp::group_equal_sized(&slot) {
                            if let Err(e) =
                                crate::udp::batch_send(&socket_out, &state_out, peer_out, run, seg, gso).await
                            {
                                error!("UDP batch send (paced): {e}");
                            }
                        }
                    } else if !pending.is_empty() {
                        // Residue staged while paced, then live-switched to off: seal
                        // & ship once so nothing is stranded. Steady non-paced traffic
                        // never uses `pending` (recv_many ships directly).
                        let batch = Vec::from(std::mem::take(&mut pending));
                        match engine_out.encrypt_batch(batch) {
                            Ok(wires) if !wires.is_empty() => {
                                if send_tx.send(wires).await.is_err() {
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => error!("encrypt_batch: {e}"),
                        }
                    }

                    // Rekey trigger (shared): threshold reached AND no rekey running.
                    if engine_out.sessions().needs_rekey()
                        && !rekeying_out.swap(true, Ordering::AcqRel)
                    {
                        let new_id = crate::net::alloc_session_id();
                        info!("rekey threshold reached — starting rekey on session {new_id}");
                        // The rekey driver reads NO socket; response comes via hs_rx.
                        let r = rekey_as_initiator(
                            &socket_out, peer_out, auth_out.as_ref(),
                            engine_out.sessions(), new_id, &mut hs_rx, hs_obf.as_ref(),
                        ).await;
                        match r {
                            Ok(()) => schedule_retire(engine_out.sessions().clone()),
                            Err(e) => {
                                warn!("rekey failed: {e}");
                                // Release the claim in the SessionManager so a
                                // later attempt (after the anti-storm interval) can start.
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
                        let new_paced = eff.enabled && obf_on;
                        // Fix #2 correctness: the decoupled sender is a 2nd socket
                        // writer. Across a live off→paced switch it must not race the
                        // paced arm's direct sends, or already-queued low counters
                        // could arrive after fresh high-counter paced packets and fall
                        // outside the peer's 2048 replay window. Drain the sender queue
                        // before enabling paced (leaves ≤1 in-flight batch, in window).
                        if !paced && new_paced {
                            while send_tx.capacity() < send_tx.max_capacity() {
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                        }
                        // On paced→off, seal & ship any `pending` residue NOW (in
                        // order) so the steady recv_many path can't seal newer packets
                        // ahead of it.
                        if paced && !new_paced && !pending.is_empty() {
                            let batch = Vec::from(std::mem::take(&mut pending));
                            if let Ok(wires) = engine_out.encrypt_batch(batch) {
                                if !wires.is_empty() && send_tx.send(wires).await.is_err() {
                                    break;
                                }
                            }
                        }
                        paced = new_paced;
                        let new_mode = match eff.mode {
                            TrafficMode::Cbr => ShapeMode::Cbr,
                            TrafficMode::Adaptive => ShapeMode::Adaptive,
                        };
                        let new_slot =
                            Duration::from_micros(1_000_000u64 / eff.rate_pps.max(1) as u64);
                        pace_burst = eff.burst.max(1) as usize;
                        tick = interval(if paced { new_slot } else { linger });
                        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
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
    tasks.spawn(async move {
        // Batched receive buffers (GRO): one syscall yields multiple
        // datagrams, which we run one by one through the existing demux below.
        let (mut recv_storage, mut recv_metas) = crate::udp::recv_buffers();
        // Reassembler for mid-session rekey-init frames (responder side).
        let mut rekey_reasm = Reassembler::default();
        // Pending rekey-responder state: after the init we keep the (not yet
        // trusted) handshake until the Confirm arrives (mutual auth).
        let mut pending_rekey: Option<(Handshake, u32)> = None;
        let mut rekey_confirm_reasm = Reassembler::default();
        let mut prune_tick = interval(Duration::from_secs(10));
        // Warm-pool dispatch for decrypt (see the module-level doc above
        // `dispatch_seal`/`rayon_spawn_guarded`). No ordering step needed
        // here, unlike outbound: the replay window tolerates reordering and
        // TUN write order need not match receive order (the OS already
        // handles out-of-order network delivery), so results are just
        // processed as they land, via a JoinSet — the same idiom this
        // function already uses for its top-level tasks. `rayon::spawn`
        // removes the old dedicated-thread design's implicit concurrency=1
        // bound, so a semaphore (sized to rayon's actual pool) caps
        // in-flight decrypt jobs instead of growing unboundedly if decrypt
        // ever falls behind recv.
        let decrypt_sem = Arc::new(tokio::sync::Semaphore::new(rayon::current_num_threads()));
        let mut decrypt_jobs: tokio::task::JoinSet<Vec<DecryptResult>> =
            tokio::task::JoinSet::new();

        'inbound: loop {
            tokio::select! {
                _ = prune_tick.tick() => {
                    // State-Bloat-DoS fix: clean up half-finished fragments.
                    rekey_reasm.prune_old(Duration::from_secs(10));
                    rekey_confirm_reasm.prune_old(Duration::from_secs(10));
                }
                recv = crate::udp::batch_recv(&socket_in, &state_in, &mut recv_storage, &mut recv_metas) => {
                    let count = match recv {
                        Ok(c)  => c,
                        Err(e) => { error!("UDP recv: {e}"); continue; }
                    };
                    // Collect the (GRO-split) datagrams owned, so the storage
                    // borrow is released before the per-datagram processing with
                    // awaits. The copy is negligible vs. the syscall gain.
                    let datagrams: Vec<(std::net::SocketAddr, Bytes)> =
                        crate::udp::iter_datagrams(&recv_storage, &recv_metas, count)
                            .map(|(a, d)| (a, Bytes::copy_from_slice(d)))
                            .collect();

                    let permit = match decrypt_sem.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => break 'inbound, // semaphore closed — shouldn't happen
                    };
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let eng = engine_in.clone();
                    rayon_spawn_guarded(move || Ok(eng.decrypt_batch_par(&datagrams)), tx);
                    decrypt_jobs.spawn(async move {
                        let _permit = permit; // held until this job's results are consumed
                        match rx.await {
                            Ok(Ok(results)) => results,
                            Ok(Err(e)) => { error!("decrypt: {e}"); Vec::new() }
                            Err(_) => Vec::new(), // rayon job dropped without replying — shouldn't happen
                        }
                    });
                }
                Some(join_res) = decrypt_jobs.join_next(), if !decrypt_jobs.is_empty() => {
                    let results = match join_res {
                        Ok(r) => r,
                        Err(e) => {
                            if !e.is_cancelled() { error!("decrypt job: {e}"); }
                            continue;
                        }
                    };

                    for (src, datagram, result) in results {
                        // 1) Data path (decrypted in parallel): handle directly.
                        if let Ok((ft, plain)) = result {
                            let now = now_secs();
                            last_recv_in.store(now, Ordering::Relaxed);
                            stats_in.last_recv_epoch.store(now, Ordering::Relaxed);
                            match ft {
                                FrameType::Data => {
                                    trace!("inbound {} bytes -> TUN", plain.len());
                                    stats_in.rx_bytes.fetch_add(plain.len() as u64, Ordering::Relaxed);
                                    if to_tun.send(plain).await.is_err() { break 'inbound; }
                                }
                                FrameType::KeepAlive => debug!("keepalive (obf) received"),
                                FrameType::Close => { info!("peer closed session"); break 'inbound; }
                                FrameType::Handshake => {} // not expected via the obf path
                                FrameType::Padding => trace!("cover packet discarded"),
                            }
                            continue;
                        }

                        // No data path → handshake fragment or noise: SERIAL on
                        // the coordinator (rekey state stays on one thread).
                        //
                        // M-1: accept control/handshake traffic ONLY from the
                        // established peer. The rekey demux below sends a
                        // ~8 KB response and does expensive crypto (ML-KEM+DH+ML-DSA);
                        // with an unpinned source address a spoofed `src` would
                        // allow reflection/amplification toward a victim and
                        // waste rekey crypto on noise. The data path above is
                        // already protected by the AEAD tag and need not be pinned.
                        if src != peer_in {
                            continue;
                        }

                        // 2) Handshake obfuscation ON.
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

                        // 3) Handshake obfuscation OFF: classic cleartext frame.
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
                                        trace!("inbound {} bytes -> TUN", plain.len());
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
                            // L-7: a cleartext Close (obf off) is UNAUTHENTICATED;
                            // don't tear down on injection. A real peer exit is caught
                            // by the dead-peer detection. (The obfuscated,
                            // authenticated Close above does tear down.)
                            FrameType::Close => warn!(
                                "cleartext Close ignored (obf off = unauthenticated); \
                                 tunnel stays up"
                            ),
                            FrameType::Padding => {}
                        }
                    }
                }
            }
        }
    });

    // ── Keepalive + dead-peer detection ──────────────────────────
    // Sends a KeepAlive frame periodically and closes the tunnel if nothing
    // arrived for too long. Runs as the third task alongside in/outbound.
    let socket_ka = socket.clone();
    let last_recv_ka = last_recv.clone();
    let peer_ka = peer;
    let engine_ka = engine.clone();
    let obf_enabled_ka = params.obf_enabled;
    let pad_policy_ka: PadPolicy = params.padding;
    // Under CBR pacing there is constant (cover) traffic anyway, so the
    // periodic keepalive send is redundant — we skip it then and keep
    // only the dead-peer detection. (Adaptive can fall idle-silent, so there
    // the keepalive send stays necessary.)
    let ka_skip_send = paced && matches!(params.traffic_mode, TrafficMode::Cbr);
    tasks.spawn(async move {
        let mut ka_tick = interval(KEEPALIVE_INTERVAL);
        loop {
            ka_tick.tick().await;
            let idle = now_secs().saturating_sub(last_recv_ka.load(Ordering::Relaxed));
            if idle >= PEER_DEAD_AFTER {
                warn!("peer silent for {idle}s — declaring dead, closing tunnel");
                break;
            }
            if ka_skip_send {
                continue; // CBR cover already provides the liveness signal
            }
            // Send a keepalive so the other side knows we are alive too.
            // Obfuscated (so the keepalive doesn't stand out as a small fixed
            // packet) unless obfuscation is off; then the classic frame.
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

    // Wait for the first loop to finish (peer close, dead peer, or TUN/socket
    // error). Returning here drops `tasks`, which aborts the other two loops;
    // being cancelled (Client::disconnect aborts this task) drops `tasks` too,
    // so a disconnect actually stops the tunnel instead of leaking a sender.
    if let Some(Err(e)) = tasks.join_next().await {
        if !e.is_cancelled() {
            error!("tunnel task join error: {e}");
        }
    }
    // Abort AND await the remaining loops so the socket has no second reader when
    // the caller (server session loop) re-listens on it — a lingering reader
    // would swallow the next handshake and time out its confirm.
    tasks.shutdown().await;
    // Fully release the TUN device (abort + await) before returning, so the
    // server loop can re-create `chameleon0` without a name clash.
    if let Some(h) = read_task {
        h.abort();
        let _ = h.await;
    }
    if let Some(h) = write_task {
        h.abort();
        let _ = h.await;
    }
    stats.connected.store(false, Ordering::Relaxed);
    info!("tunnel closed");
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// A panic escaping the closure must surface as `Err(..)` on the oneshot,
    /// not `std::process::abort()` the test process — the exact failure mode
    /// `rayon_spawn_guarded` exists to prevent (see its doc comment).
    #[tokio::test]
    async fn rayon_spawn_guarded_catches_panics() {
        let (tx, rx) = tokio::sync::oneshot::channel::<crate::error::Result<i32>>();
        rayon_spawn_guarded(
            || -> crate::error::Result<i32> { panic!("deliberate test panic") },
            tx,
        );
        let result = rx.await.expect("guard always replies, even after a panic");
        assert!(
            result.is_err(),
            "a panicking job must surface as Err, never abort the process"
        );
    }

    /// Regression test for the real ordering bug this design fixes: submit
    /// several synthetic "batches" through the exact same order_tx ->
    /// run_sequential_sender path the outbound pipeline uses, completing them
    /// in a DELIBERATELY SCRAMBLED order (the first-submitted batch resolves
    /// slowest, the last-submitted resolves fastest — the inverse of FIFO).
    /// Assert the bytes that actually hit the wire come out in SUBMISSION
    /// order, not completion order.
    #[tokio::test(flavor = "multi_thread")]
    async fn sequential_sender_preserves_submission_order_under_scrambled_completion() {
        let send_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let recv_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer = recv_sock.local_addr().unwrap();
        let state = Arc::new(crate::udp::socket_state(&send_sock).unwrap());

        let (order_tx, order_rx) = tokio::sync::mpsc::channel(16);
        let sender_task = tokio::spawn(run_sequential_sender(
            order_rx,
            Arc::new(send_sock),
            state,
            peer,
            false, // gso off: one send per element, simplest to reason about
        ));

        const N: u64 = 20;
        for i in 0..N {
            let (tx, rx) = tokio::sync::oneshot::channel::<crate::error::Result<Vec<Bytes>>>();
            // Invert latency vs. submission order: batch 0 (submitted FIRST)
            // resolves SLOWEST; batch N-1 (submitted LAST) resolves FASTEST.
            // If the sender enforced order by racing receivers instead of
            // draining strictly FIFO (the bug this guards against), batch
            // N-1's marker would hit the wire before batch 0's.
            let delay_ms = (N - i) * 2;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let marker = Bytes::from(i.to_le_bytes().to_vec());
                let _ = tx.send(Ok(vec![marker]));
            });
            order_tx.send(rx).await.unwrap();
        }
        drop(order_tx); // let run_sequential_sender exit once drained

        let mut received = Vec::new();
        let mut buf = [0u8; 64];
        for _ in 0..N {
            let (len, _addr) =
                tokio::time::timeout(Duration::from_secs(5), recv_sock.recv_from(&mut buf))
                    .await
                    .expect("datagram arrives within 5s")
                    .unwrap();
            let bytes: [u8; 8] = buf[..len].try_into().expect("marker is 8 bytes");
            received.push(u64::from_le_bytes(bytes));
        }

        sender_task.abort();

        assert_eq!(
            received,
            (0..N).collect::<Vec<_>>(),
            "wire order must match submission order, not completion order"
        );
    }
}
