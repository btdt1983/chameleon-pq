//! The actor that owns the [`Supervisor`] and answers protocol requests.
//!
//! One task owns all mutable state; everything else talks to it through a
//! [`ControllerHandle`] (an mpsc queue with a oneshot reply per request) and
//! watches state through a `watch` channel. Nothing is locked across an await:
//! `Connect` is spawned as its own task and its outcome is fed back into the
//! actor's own queue.
//!
//! The connect function is injected ([`ConnectFn`]) so tests never touch a TUN
//! adapter or the firewall.

use super::policy::Policy;
use super::protocol::{
    ErrorCode, KillSwitchState, LogLine, Phase, PolicySummary, ReconnectInfo, Request, Response,
    StateSnapshot, TrafficProfile, TunnelInfo,
};
use super::reconnect::{self, FailClass};
use super::supervisor::{self, ConnectOutcome, Supervisor};
use crate::client::security_warnings;
use crate::config::AppConfig;
use std::collections::VecDeque;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Log lines kept for `GetLog`.
const LOG_CAP: usize = 200;

pub type ConnectFuture = Pin<Box<dyn Future<Output = ConnectOutcome> + Send>>;
/// `(effective config, server, want_kill_switch)` to a connect future.
pub type ConnectFn = Arc<dyn Fn(AppConfig, SocketAddr, bool) -> ConnectFuture + Send + Sync>;

/// The real connect: [`supervisor::connect`].
pub fn real_connect() -> ConnectFn {
    Arc::new(|cfg, server, ks| Box::pin(supervisor::connect(cfg, server, ks)))
}

enum Cmd {
    Request(Request, oneshot::Sender<Response>),
    /// `keep_kill_switch`: leave it engaged (system shutdown).
    Shutdown {
        keep_kill_switch: bool,
        done: oneshot::Sender<()>,
    },
}

/// Cheap, cloneable front door to the controller task.
#[derive(Clone)]
pub struct ControllerHandle {
    tx: mpsc::Sender<Cmd>,
    state: watch::Receiver<StateSnapshot>,
}

impl ControllerHandle {
    /// Send a request and wait for its answer.
    pub async fn request(&self, req: Request) -> Response {
        let (done_tx, done_rx) = oneshot::channel();
        if self.tx.send(Cmd::Request(req, done_tx)).await.is_err() {
            return stopped();
        }
        done_rx.await.unwrap_or_else(|_| stopped())
    }

    /// Latest state plus change notifications (one value per change).
    pub fn subscribe(&self) -> watch::Receiver<StateSnapshot> {
        self.state.clone()
    }

    /// Orderly teardown (an administrator stop); returns once routes, DNS and
    /// the kill switch are restored.
    pub async fn shutdown(&self) {
        self.shutdown_with(false).await;
    }

    /// Like [`Self::shutdown`] but the kill switch stays engaged: for a system
    /// shutdown, where fail-closed is preferred.
    pub async fn shutdown_keeping_kill_switch(&self) {
        self.shutdown_with(true).await;
    }

    async fn shutdown_with(&self, keep_kill_switch: bool) {
        let (done, done_rx) = oneshot::channel();
        let cmd = Cmd::Shutdown {
            keep_kill_switch,
            done,
        };
        if self.tx.send(cmd).await.is_ok() {
            let _ = done_rx.await;
        }
    }
}

/// Under `enforced`, a tunnel without its kill switch is not acceptable: if the
/// switch could not be engaged, close the tunnel and report why. (A failed
/// attempt leaves any switch that did engage in place, as for a failed connect.)
fn require_kill_switch(outcome: ConnectOutcome) -> ConnectOutcome {
    match outcome {
        (Ok(client), Some(Ok(ks))) => (Ok(client), Some(Ok(ks))),
        (Ok(client), other) => {
            client.disconnect();
            let why = match &other {
                Some(Err(e)) => e.clone(),
                _ => "not requested".to_string(),
            };
            (
                Err(format!(
                    "the kill switch is enforced by your administrator but could not be \
                     engaged ({why}); the connection was closed"
                )),
                other,
            )
        }
        failed => failed,
    }
}

fn stopped() -> Response {
    Response::Error {
        code: ErrorCode::Internal,
        message: "service is shutting down".into(),
    }
}

fn error(code: ErrorCode, message: impl Into<String>) -> Response {
    Response::Error {
        code,
        message: message.into(),
    }
}

/// Start the controller task with the default (permissive, today's) policy.
pub fn spawn(
    cfg: AppConfig,
    supervisor: Supervisor,
    connect_fn: ConnectFn,
) -> (ControllerHandle, JoinHandle<()>) {
    spawn_with_policy(cfg, Policy::default(), supervisor, connect_fn)
}

/// Start the controller task. `cfg` is the administrator's config and `policy`
/// what the users of the service may do; the caller has validated the pair
/// ([`Policy::validate`]).
pub fn spawn_with_policy(
    cfg: AppConfig,
    policy: Policy,
    mut supervisor: Supervisor,
    connect_fn: ConnectFn,
) -> (ControllerHandle, JoinHandle<()>) {
    supervisor.set_log_hint("the service log");
    let startup_notes = supervisor.take_notes();
    let (tx, rx) = mpsc::channel(32);
    let (outcome_tx, outcome_rx) = mpsc::channel(1);
    let profile = cfg.traffic.profile;
    let (state_tx, state_rx) = watch::channel(snapshot(
        &supervisor,
        profile,
        &cfg,
        &policy,
        &Reconnect::default(),
    ));
    let actor = Actor {
        cfg,
        policy,
        sup: supervisor,
        profile,
        rc: Reconnect::default(),
        log: VecDeque::new(),
        next_seq: 1,
        state_tx,
        connect_fn,
        outcome_tx,
    };
    let mut actor = actor;
    actor.push_log(startup_notes);
    let join = tokio::spawn(actor.run(rx, outcome_rx));
    (
        ControllerHandle {
            tx,
            state: state_rx,
        },
        join,
    )
}

/// What the actor remembers about its automatic reconnect.
#[derive(Debug, Default)]
struct Reconnect {
    /// The user (or, later, `auto_connect`) wants a tunnel. Cleared by an
    /// allowed Disconnect and by a permanent failure.
    want_connected: bool,
    /// Failed attempts since the last good connection (0 = none pending).
    attempt: u32,
    /// When the next attempt starts; `None` while idle, connecting or connected.
    next_at: Option<Instant>,
    last_error: Option<String>,
    /// When the current connection came up.
    connected_since: Option<Instant>,
}

fn snapshot(
    sup: &Supervisor,
    profile: TrafficProfile,
    cfg: &AppConfig,
    policy: &Policy,
    rc: &Reconnect,
) -> StateSnapshot {
    let waiting = rc.want_connected && rc.next_at.is_some() && !sup.is_connecting();
    let phase = if sup.is_connecting() {
        Phase::Connecting
    } else if sup.is_connected() {
        Phase::Connected
    } else if waiting {
        Phase::Reconnecting
    } else {
        Phase::Disconnected
    };
    let reconnect =
        (rc.want_connected && rc.attempt > 0 && !sup.is_connected()).then(|| ReconnectInfo {
            attempt: rc.attempt,
            next_in_secs: rc.next_at.filter(|_| !sup.is_connecting()).map(|t| {
                t.saturating_duration_since(Instant::now())
                    .as_secs_f64()
                    .ceil() as u64
            }),
            last_error: rc.last_error.clone(),
        });
    let kill_switch = if sup.kill_switch_engaged() {
        KillSwitchState::Engaged
    } else if sup.kill_switch_orphan() {
        KillSwitchState::Orphaned
    } else {
        KillSwitchState::Off
    };
    let tunnel = sup.status().filter(|s| s.connected).map(|s| TunnelInfo {
        peer: s.peer.to_string(),
        session_id: s.session_id,
        tx_bytes: s.tx_bytes,
        rx_bytes: s.rx_bytes,
        last_recv_epoch: s.last_recv_epoch,
        uptime_secs: s.uptime_secs,
    });
    StateSnapshot {
        phase,
        tunnel,
        kill_switch,
        profile,
        warnings: security_warnings(cfg),
        policy: PolicySummary::from(policy),
        reconnect,
    }
}

struct Actor {
    cfg: AppConfig,
    policy: Policy,
    sup: Supervisor,
    profile: TrafficProfile,
    rc: Reconnect,
    log: VecDeque<LogLine>,
    next_seq: u64,
    state_tx: watch::Sender<StateSnapshot>,
    connect_fn: ConnectFn,
    outcome_tx: mpsc::Sender<ConnectOutcome>,
}

impl Actor {
    async fn run(
        mut self,
        mut rx: mpsc::Receiver<Cmd>,
        mut outcome_rx: mpsc::Receiver<ConnectOutcome>,
    ) {
        // Always-on: the first attempt starts at once, not after the first tick.
        if self.policy.auto_connect {
            if let Some(server) = self.cfg.network.server_addr {
                self.rc.want_connected = true;
                self.start_attempt(server);
                self.publish();
            }
        }
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    Some(Cmd::Request(req, reply)) => {
                        let resp = self.handle(req);
                        let _ = reply.send(resp);
                    }
                    Some(Cmd::Shutdown { keep_kill_switch, done }) => {
                        self.shutdown(&mut outcome_rx, keep_kill_switch).await;
                        let _ = done.send(());
                        return;
                    }
                    // Every handle dropped: nobody can talk to us any more.
                    None => {
                        self.shutdown(&mut outcome_rx, false).await;
                        return;
                    }
                },
                Some(outcome) = outcome_rx.recv() => {
                    self.on_outcome(outcome);
                }
                _ = tick.tick() => {
                    let was_connected = self.sup.is_connected();
                    let lines = self.sup.poll();
                    self.push_log(lines);
                    self.on_tick(was_connected);
                }
            }
            self.publish();
        }
    }

    fn handle(&mut self, req: Request) -> Response {
        match req {
            Request::GetState {} => Response::State(self.snapshot()),
            Request::GetLog { since } => Response::Log {
                lines: self.log.iter().filter(|l| l.seq > since).cloned().collect(),
            },
            Request::Connect { profile } => self.connect(profile),
            Request::Disconnect {} => {
                if !self.policy.disconnect_allowed() {
                    return error(
                        ErrorCode::Denied,
                        "your administrator does not allow disconnecting",
                    );
                }
                if self.sup.is_connecting() {
                    return error(ErrorCode::Busy, "a connection attempt is in progress");
                }
                // The user no longer wants a tunnel: stop any pending retry.
                self.rc = Reconnect::default();
                let lines = self
                    .sup
                    .disconnect(self.policy.disconnect_keeps_kill_switch());
                self.push_log(lines);
                Response::Ok {}
            }
            Request::SetProfile { profile } => {
                if !self.policy.profile_allowed(profile) {
                    return error(
                        ErrorCode::Denied,
                        format!("the profile '{profile}' is not allowed by your administrator"),
                    );
                }
                self.profile = profile;
                self.cfg.traffic.profile = profile;
                let line = if self.sup.apply_traffic(&self.cfg.traffic) {
                    format!("Profile changed live → {profile}")
                } else {
                    format!("Profile: {profile}")
                };
                self.push_log(vec![line]);
                Response::Ok {}
            }
            // No policy and no caller identity yet; admins use the elevated
            // `chameleon-pq killswitch off`.
            Request::ClearKillSwitch {} => error(
                ErrorCode::Denied,
                "clearing the kill switch is not allowed from this client",
            ),
        }
    }

    fn connect(&mut self, profile: Option<TrafficProfile>) -> Response {
        if self.sup.is_connecting() || self.sup.is_connected() {
            return error(ErrorCode::Busy, "already connecting or connected");
        }
        let Some(server) = self.cfg.network.server_addr else {
            return error(ErrorCode::Internal, "the service config has no server_addr");
        };
        if let Some(p) = profile {
            if !self.policy.profile_allowed(p) {
                return error(
                    ErrorCode::Denied,
                    format!("the profile '{p}' is not allowed by your administrator"),
                );
            }
            self.profile = p;
            self.cfg.traffic.profile = p;
        }
        // An explicit Connect starts a fresh series: no waiting, counter reset.
        self.rc = Reconnect {
            want_connected: true,
            ..Reconnect::default()
        };
        self.start_attempt(server);
        Response::Ok {}
    }

    /// Start one connect attempt (user request or scheduled retry).
    fn start_attempt(&mut self, server: SocketAddr) {
        self.rc.next_at = None;
        let cfg = self.cfg.clone();
        let want_kill_switch = self.policy.kill_switch_wanted(cfg.tun.kill_switch);
        let enforced = self.policy.kill_switch == super::policy::KillSwitchPolicy::Enforced;
        self.sup.begin_connect();
        let what = if self.rc.attempt > 0 {
            format!("Reconnecting to {server} (attempt {}) …", self.rc.attempt)
        } else {
            format!("Connecting to {server} …")
        };
        self.push_log(vec![what]);
        let fut = (self.connect_fn)(cfg, server, want_kill_switch);
        let tx = self.outcome_tx.clone();
        tokio::spawn(async move {
            let outcome = fut.await;
            let outcome = if enforced {
                require_kill_switch(outcome)
            } else {
                outcome
            };
            let _ = tx.send(outcome).await;
        });
    }

    /// Apply a finished attempt, then decide whether to retry.
    fn on_outcome(&mut self, outcome: ConnectOutcome) {
        let error = outcome.0.as_ref().err().cloned();
        let lines = self.sup.on_connected(outcome);
        self.push_log(lines);
        match error {
            None => {
                self.rc.connected_since = Some(Instant::now());
                self.rc.next_at = None;
                self.rc.last_error = None;
                // `attempt` is reset once the connection proved stable.
            }
            Some(e) if self.rc.want_connected => self.schedule_retry(&e),
            Some(_) => {}
        }
    }

    /// Plan the next attempt after a failure, or give up on a permanent one.
    fn schedule_retry(&mut self, error: &str) {
        let class = reconnect::classify(error);
        self.rc.last_error = Some(error.to_string());
        if class == FailClass::Permanent {
            self.rc = Reconnect::default();
            self.push_log(vec![format!(
                "Not retrying: {error}. Fix the service config and connect again."
            )]);
            return;
        }
        self.rc.attempt = self.rc.attempt.saturating_add(1);
        let wait = reconnect::delay(class, self.rc.attempt, rand::random::<f64>());
        self.rc.next_at = Some(Instant::now() + wait);
        let note = if class == FailClass::Rejected {
            " (the server's identity check failed: check the pinned keys)"
        } else {
            ""
        };
        self.push_log(vec![format!(
            "Next attempt in {} s{note}.",
            wait.as_secs_f64().round() as u64
        )]);
    }

    /// Once a second: notice a drop, mark a stable connection, start due retries.
    fn on_tick(&mut self, was_connected: bool) {
        if !self.rc.want_connected {
            return;
        }
        if self.sup.is_connected() {
            if self
                .rc
                .connected_since
                .is_some_and(|t| t.elapsed() >= reconnect::STABLE_AFTER)
            {
                self.rc.attempt = 0;
            }
            return;
        }
        if was_connected {
            // The tunnel just died. It was good for a while or not: that decides
            // whether we start from the shortest delay again.
            self.rc.connected_since = None;
            self.schedule_retry("the tunnel dropped");
            return;
        }
        let due = self.rc.next_at.is_some_and(|t| Instant::now() >= t);
        if due && !self.sup.is_connecting() {
            if let Some(server) = self.cfg.network.server_addr {
                self.start_attempt(server);
            }
        }
    }

    /// Finish an in-flight connect first (it may have created the adapter and
    /// engaged the kill switch), then tear everything down in order.
    async fn shutdown(
        &mut self,
        outcome_rx: &mut mpsc::Receiver<ConnectOutcome>,
        keep_kill_switch: bool,
    ) {
        if self.sup.is_connecting() {
            if let Some(outcome) = outcome_rx.recv().await {
                let lines = self.sup.on_connected(outcome);
                self.push_log(lines);
            }
        }
        self.rc = Reconnect::default();
        let lines = self.sup.shutdown(keep_kill_switch).await;
        self.push_log(lines);
        self.publish();
    }

    fn snapshot(&self) -> StateSnapshot {
        snapshot(&self.sup, self.profile, &self.cfg, &self.policy, &self.rc)
    }

    fn push_log(&mut self, lines: Vec<String>) {
        for text in lines {
            tracing::info!("{text}");
            self.log.push_back(LogLine {
                seq: self.next_seq,
                text,
            });
            self.next_seq += 1;
            if self.log.len() > LOG_CAP {
                self.log.pop_front();
            }
        }
    }

    /// Publish the snapshot if it changed.
    fn publish(&self) {
        let snap = self.snapshot();
        self.state_tx.send_if_modified(|cur| {
            if *cur == snap {
                false
            } else {
                *cur = snap;
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Notify;

    fn test_cfg() -> AppConfig {
        AppConfig::load(std::path::Path::new("config.example.toml")).expect("example config loads")
    }

    /// A connect fn that waits for `gate` and then fails with `err`.
    fn gated_failure(gate: Arc<Notify>, err: &'static str) -> ConnectFn {
        Arc::new(move |_cfg, _server, _ks| {
            let gate = gate.clone();
            Box::pin(async move {
                gate.notified().await;
                (Err(err.to_string()), None)
            })
        })
    }

    fn start(connect_fn: ConnectFn) -> (ControllerHandle, JoinHandle<()>) {
        spawn(test_cfg(), Supervisor::with_orphan(false), connect_fn)
    }

    async fn state(h: &ControllerHandle) -> StateSnapshot {
        match h.request(Request::GetState {}).await {
            Response::State(s) => s,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn starts_disconnected_and_reports_the_config_profile() {
        let (h, _j) = start(gated_failure(Arc::new(Notify::new()), "x"));
        let s = state(&h).await;
        assert_eq!(s.phase, Phase::Disconnected);
        assert_eq!(s.kill_switch, KillSwitchState::Off);
        assert!(s.tunnel.is_none());
        assert_eq!(s.profile, test_cfg().traffic.profile);
    }

    #[tokio::test]
    async fn connect_is_busy_while_in_flight_and_failure_returns_to_idle() {
        let gate = Arc::new(Notify::new());
        let (h, _j) = start(gated_failure(gate.clone(), "boom"));
        let mut watch = h.subscribe();

        assert_eq!(
            h.request(Request::Connect { profile: None }).await,
            Response::Ok {}
        );
        assert_eq!(state(&h).await.phase, Phase::Connecting);

        // A second connect and a disconnect are refused while connecting.
        for req in [Request::Connect { profile: None }, Request::Disconnect {}] {
            match h.request(req).await {
                Response::Error { code, .. } => assert_eq!(code, ErrorCode::Busy),
                other => panic!("expected Busy, got {other:?}"),
            }
        }

        gate.notify_one();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if watch.borrow().phase == Phase::Reconnecting {
                    break;
                }
                watch.changed().await.unwrap();
            }
        })
        .await
        .expect("waits to retry after the failed connect");

        let lines = match h.request(Request::GetLog { since: 0 }).await {
            Response::Log { lines } => lines,
            other => panic!("{other:?}"),
        };
        let texts: Vec<_> = lines.iter().map(|l| l.text.as_str()).collect();
        assert!(texts.iter().any(|t| t.starts_with("Connecting to ")));
        assert!(texts.contains(&"Connection failed: boom"));
        // Sequence numbers are strictly increasing and `since` filters.
        assert!(lines.windows(2).all(|w| w[0].seq < w[1].seq));
        let last = lines.last().unwrap().seq;
        match h.request(Request::GetLog { since: last }).await {
            Response::Log { lines } => assert!(lines.is_empty()),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn disconnect_while_idle_is_ok() {
        let (h, _j) = start(gated_failure(Arc::new(Notify::new()), "x"));
        assert_eq!(h.request(Request::Disconnect {}).await, Response::Ok {});
    }

    #[tokio::test]
    async fn set_profile_is_reflected_in_the_snapshot() {
        let (h, _j) = start(gated_failure(Arc::new(Notify::new()), "x"));
        assert_eq!(
            h.request(Request::SetProfile {
                profile: TrafficProfile::Stealth
            })
            .await,
            Response::Ok {}
        );
        assert_eq!(state(&h).await.profile, TrafficProfile::Stealth);
    }

    #[tokio::test]
    async fn connect_profile_override_sticks() {
        let gate = Arc::new(Notify::new());
        let (h, _j) = start(gated_failure(gate.clone(), "x"));
        h.request(Request::Connect {
            profile: Some(TrafficProfile::Throughput),
        })
        .await;
        assert_eq!(state(&h).await.profile, TrafficProfile::Throughput);
        gate.notify_one();
    }

    #[tokio::test]
    async fn clear_kill_switch_is_denied() {
        let (h, _j) = start(gated_failure(Arc::new(Notify::new()), "x"));
        match h.request(Request::ClearKillSwitch {}).await {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::Denied),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn shutdown_waits_for_an_in_flight_connect() {
        let gate = Arc::new(Notify::new());
        let (h, j) = start(gated_failure(gate.clone(), "x"));
        h.request(Request::Connect { profile: None }).await;

        let h2 = h.clone();
        let stopping = tokio::spawn(async move { h2.shutdown().await });
        // The connect has not finished, so shutdown must still be pending.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!stopping.is_finished());

        gate.notify_one();
        tokio::time::timeout(Duration::from_secs(5), stopping)
            .await
            .expect("shutdown completes once the connect resolves")
            .unwrap();
        j.await.unwrap();

        // The actor is gone: requests now get a clean error, not a hang.
        match h.request(Request::GetState {}).await {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::Internal),
            other => panic!("{other:?}"),
        }
    }

    fn start_with(
        cfg: AppConfig,
        policy: Policy,
        connect_fn: ConnectFn,
    ) -> (ControllerHandle, JoinHandle<()>) {
        spawn_with_policy(cfg, policy, Supervisor::with_orphan(false), connect_fn)
    }

    fn denied(resp: Response) -> bool {
        matches!(
            resp,
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        )
    }

    /// A connect fn that records the kill-switch flag it was asked for.
    fn recording(flag: Arc<std::sync::atomic::AtomicI8>) -> ConnectFn {
        Arc::new(move |_c, _s, ks| {
            flag.store(ks as i8, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { (Err("x".to_string()), None) })
        })
    }

    #[tokio::test]
    async fn policy_can_forbid_disconnect() {
        let policy = Policy::parse("allow_user_disconnect = false", "t").unwrap();
        let (h, _j) = start_with(
            test_cfg(),
            policy,
            gated_failure(Arc::new(Notify::new()), "x"),
        );
        assert!(denied(h.request(Request::Disconnect {}).await));
        // The summary tells the GUI, so it can hide the button.
        assert!(!state(&h).await.policy.allow_user_disconnect);
    }

    #[tokio::test]
    async fn policy_limits_the_profiles_for_set_profile_and_connect() {
        let cfg = test_cfg();
        let own = format!("{:?}", cfg.traffic.profile).to_lowercase();
        // Allow only the config's own profile.
        let policy = Policy::parse(&format!("allowed_profiles = [\"{own}\"]"), "t").unwrap();
        let other = [
            TrafficProfile::Stealth,
            TrafficProfile::Balanced,
            TrafficProfile::Throughput,
            TrafficProfile::Off,
        ]
        .into_iter()
        .find(|p| *p != cfg.traffic.profile)
        .unwrap();
        let (h, _j) = start_with(
            cfg.clone(),
            policy,
            gated_failure(Arc::new(Notify::new()), "x"),
        );

        assert!(denied(
            h.request(Request::SetProfile { profile: other }).await
        ));
        assert!(denied(
            h.request(Request::Connect {
                profile: Some(other)
            })
            .await
        ));
        // Neither the refused SetProfile nor the refused Connect changed anything.
        let s = state(&h).await;
        assert_eq!(s.profile, cfg.traffic.profile);
        assert_eq!(s.phase, Phase::Disconnected);
        // The allowed profile still works.
        assert_eq!(
            h.request(Request::SetProfile {
                profile: cfg.traffic.profile
            })
            .await,
            Response::Ok {}
        );
    }

    #[tokio::test]
    async fn kill_switch_policy_decides_what_connect_asks_for() {
        use std::sync::atomic::{AtomicI8, Ordering};
        for (policy, cfg_value, expected) in [
            ("kill_switch = \"user_choice\"", true, 1),
            ("kill_switch = \"user_choice\"", false, 0),
            ("kill_switch = \"enforced\"", false, 1),
            ("kill_switch = \"enforced\"", true, 1),
            ("kill_switch = \"off\"", true, 0),
            ("kill_switch = \"off\"", false, 0),
        ] {
            let mut cfg = test_cfg();
            cfg.tun.kill_switch = cfg_value;
            cfg.tun.route_all = true;
            let flag = Arc::new(AtomicI8::new(-1));
            let (h, _j) = start_with(
                cfg,
                Policy::parse(policy, "t").unwrap(),
                recording(flag.clone()),
            );
            assert_eq!(
                h.request(Request::Connect { profile: None }).await,
                Response::Ok {}
            );
            tokio::time::timeout(Duration::from_secs(5), async {
                while flag.load(Ordering::SeqCst) == -1 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("connect fn called");
            assert_eq!(
                flag.load(Ordering::SeqCst),
                expected,
                "policy [{policy}] with config kill_switch={cfg_value}"
            );
        }
    }

    #[tokio::test]
    async fn a_failed_attempt_under_enforced_passes_through_untouched() {
        // Failures (no tunnel was built) need no extra handling.
        let failed: ConnectOutcome = (Err("boom".into()), Some(Err("ks".into())));
        let out = require_kill_switch(failed);
        assert_eq!(out.0.err().as_deref(), Some("boom"));
        assert_eq!(out.1.unwrap().err().as_deref(), Some("ks"));
    }

    // ---- automatic reconnect (paused clock: no real waiting) ----

    /// A connect fn that always fails with `err` and counts its calls.
    fn counting_failure(
        calls: Arc<std::sync::atomic::AtomicUsize>,
        err: &'static str,
    ) -> ConnectFn {
        Arc::new(move |_cfg, _server, _ks| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { (Err(err.to_string()), None) })
        })
    }

    fn calls_of(c: &Arc<std::sync::atomic::AtomicUsize>) -> usize {
        c.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Advance the paused clock one second at a time, letting the actor run.
    async fn run_for(secs: u64) {
        for _ in 0..secs {
            tokio::time::advance(Duration::from_secs(1)).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_connect_is_retried_with_growing_waits() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (h, _j) = start(counting_failure(
            calls.clone(),
            "UDP / IO error: unreachable",
        ));
        h.request(Request::Connect { profile: None }).await;
        // No clock advance yet: the first attempt has failed, the retry waits.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(calls_of(&calls), 1);
        let s = state(&h).await;
        assert_eq!(s.phase, Phase::Reconnecting);
        let info = s.reconnect.expect("reconnect info while waiting");
        assert_eq!(info.attempt, 1);
        assert!(info.next_in_secs.is_some());
        assert!(info.last_error.unwrap().contains("unreachable"));

        // Waits are about 1, 2, 4, 8 s (+-20%, rounded up by the 1 s tick):
        // after 40 s there must have been several, but nowhere near one per second.
        run_for(40).await;
        let n = calls_of(&calls);
        assert!((4..=9).contains(&n), "unexpected number of attempts: {n}");
        assert!(state(&h).await.reconnect.unwrap().attempt as usize >= n - 1);
    }

    #[tokio::test(start_paused = true)]
    async fn disconnect_cancels_the_retry_loop() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (h, _j) = start(counting_failure(calls.clone(), "unreachable"));
        h.request(Request::Connect { profile: None }).await;
        run_for(3).await;
        assert_eq!(state(&h).await.phase, Phase::Reconnecting);

        assert_eq!(h.request(Request::Disconnect {}).await, Response::Ok {});
        let s = state(&h).await;
        assert_eq!(s.phase, Phase::Disconnected);
        assert!(s.reconnect.is_none());
        let before = calls_of(&calls);
        run_for(120).await;
        assert_eq!(calls_of(&calls), before, "no attempts after Disconnect");
    }

    #[tokio::test(start_paused = true)]
    async fn a_permanent_error_is_not_retried() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (h, _j) = start(counting_failure(
            calls.clone(),
            "configuration error: Key derivation failed: invalid Ed25519 seed",
        ));
        h.request(Request::Connect { profile: None }).await;
        run_for(120).await;
        assert_eq!(calls_of(&calls), 1);
        let s = state(&h).await;
        assert_eq!(s.phase, Phase::Disconnected);
        assert!(s.reconnect.is_none());
        let lines = match h.request(Request::GetLog { since: 0 }).await {
            Response::Log { lines } => lines,
            other => panic!("{other:?}"),
        };
        assert!(lines.iter().any(|l| l.text.starts_with("Not retrying:")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_identity_check_waits_much_longer() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (h, _j) = start(counting_failure(
            calls.clone(),
            "Handshake error in state 'Ed25519': Ed25519 verification failed (MITM or wrong peer)",
        ));
        h.request(Request::Connect { profile: None }).await;
        run_for(1).await;
        let info = state(&h).await.reconnect.unwrap();
        assert!(info.next_in_secs.unwrap() >= 12, "{info:?}");
        run_for(10).await;
        assert_eq!(calls_of(&calls), 1, "still waiting after 10 s");
    }

    #[tokio::test(start_paused = true)]
    async fn an_explicit_connect_skips_the_wait_and_restarts_the_series() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (h, _j) = start(counting_failure(
            calls.clone(),
            "Handshake error in state 'Ed25519': Ed25519 verification failed",
        ));
        h.request(Request::Connect { profile: None }).await;
        run_for(1).await;
        assert_eq!(calls_of(&calls), 1);
        // Mid-wait (the next automatic attempt is 12 s or more away).
        h.request(Request::Connect { profile: None }).await;
        run_for(1).await;
        assert_eq!(calls_of(&calls), 2);
        assert_eq!(
            state(&h).await.reconnect.unwrap().attempt,
            1,
            "series restarted"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn forbidden_disconnect_does_not_stop_the_retries() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let policy = Policy {
            allow_user_disconnect: false,
            ..Policy::default()
        };
        let (h, _j) = start_with(
            test_cfg(),
            policy,
            counting_failure(calls.clone(), "unreachable"),
        );
        h.request(Request::Connect { profile: None }).await;
        run_for(3).await;
        assert!(denied(h.request(Request::Disconnect {}).await));
        let before = calls_of(&calls);
        run_for(60).await;
        assert!(calls_of(&calls) > before, "retries continue");
        assert_ne!(state(&h).await.phase, Phase::Disconnected);
    }

    // ---- auto_connect ----

    #[tokio::test(start_paused = true)]
    async fn auto_connect_connects_at_start_retries_and_cannot_be_disconnected() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let policy = Policy::parse("auto_connect = true", "t").unwrap();
        let (h, _j) = start_with(
            test_cfg(),
            policy,
            counting_failure(calls.clone(), "unreachable"),
        );
        // No request was sent, yet the service is already trying.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(calls_of(&calls), 1, "first attempt at once");
        let s = state(&h).await;
        assert_eq!(s.phase, Phase::Reconnecting);
        assert!(s.policy.auto_connect);
        assert!(
            !s.policy.allow_user_disconnect,
            "the summary shows the effective rule"
        );

        // Users cannot stop it, and it keeps going.
        assert!(denied(h.request(Request::Disconnect {}).await));
        run_for(40).await;
        assert!(calls_of(&calls) >= 4);
        assert_ne!(state(&h).await.phase, Phase::Disconnected);
    }

    #[tokio::test(start_paused = true)]
    async fn without_auto_connect_nothing_happens_until_asked() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (h, _j) = start(counting_failure(calls.clone(), "unreachable"));
        run_for(30).await;
        assert_eq!(calls_of(&calls), 0);
        assert_eq!(state(&h).await.phase, Phase::Disconnected);
        assert!(!state(&h).await.policy.auto_connect);
    }

    #[tokio::test(start_paused = true)]
    async fn a_start_kill_switch_failure_is_logged_for_the_user() {
        let mut sup = Supervisor::with_orphan(false);
        sup.adopt_start_kill_switch(Err("no firewall".into()));
        let (h, _j) = spawn(
            test_cfg(),
            sup,
            counting_failure(Arc::new(std::sync::atomic::AtomicUsize::new(0)), "x"),
        );
        let lines = match h.request(Request::GetLog { since: 0 }).await {
            Response::Log { lines } => lines,
            other => panic!("{other:?}"),
        };
        assert!(lines
            .iter()
            .any(|l| l.text.contains("could not be engaged at service start")));
    }

    #[tokio::test]
    async fn dropping_every_handle_stops_the_actor() {
        let (h, j) = start(gated_failure(Arc::new(Notify::new()), "x"));
        drop(h);
        tokio::time::timeout(Duration::from_secs(5), j)
            .await
            .expect("actor exits when no handle is left")
            .unwrap();
    }
}
