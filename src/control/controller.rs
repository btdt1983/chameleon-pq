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

use super::protocol::{
    ErrorCode, KillSwitchState, LogLine, Phase, Request, Response, StateSnapshot, TrafficProfile,
    TunnelInfo,
};
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
    Shutdown(oneshot::Sender<()>),
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

    /// Orderly teardown; returns once routes/DNS/kill switch are restored.
    pub async fn shutdown(&self) {
        let (done_tx, done_rx) = oneshot::channel();
        if self.tx.send(Cmd::Shutdown(done_tx)).await.is_ok() {
            let _ = done_rx.await;
        }
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

/// Start the controller task. `cfg` is the administrator's config.
pub fn spawn(
    cfg: AppConfig,
    mut supervisor: Supervisor,
    connect_fn: ConnectFn,
) -> (ControllerHandle, JoinHandle<()>) {
    supervisor.set_log_hint("the service log");
    let (tx, rx) = mpsc::channel(32);
    let (outcome_tx, outcome_rx) = mpsc::channel(1);
    let profile = cfg.traffic.profile;
    let (state_tx, state_rx) = watch::channel(snapshot(&supervisor, profile, &cfg));
    let actor = Actor {
        cfg,
        sup: supervisor,
        profile,
        log: VecDeque::new(),
        next_seq: 1,
        state_tx,
        connect_fn,
        outcome_tx,
    };
    let join = tokio::spawn(actor.run(rx, outcome_rx));
    (
        ControllerHandle {
            tx,
            state: state_rx,
        },
        join,
    )
}

fn snapshot(sup: &Supervisor, profile: TrafficProfile, cfg: &AppConfig) -> StateSnapshot {
    let phase = if sup.is_connecting() {
        Phase::Connecting
    } else if sup.is_connected() {
        Phase::Connected
    } else {
        Phase::Disconnected
    };
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
    }
}

struct Actor {
    cfg: AppConfig,
    sup: Supervisor,
    profile: TrafficProfile,
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
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    Some(Cmd::Request(req, reply)) => {
                        let resp = self.handle(req);
                        let _ = reply.send(resp);
                    }
                    Some(Cmd::Shutdown(done)) => {
                        self.shutdown(&mut outcome_rx).await;
                        let _ = done.send(());
                        return;
                    }
                    // Every handle dropped: nobody can talk to us any more.
                    None => {
                        self.shutdown(&mut outcome_rx).await;
                        return;
                    }
                },
                Some(outcome) = outcome_rx.recv() => {
                    let lines = self.sup.on_connected(outcome);
                    self.push_log(lines);
                }
                _ = tick.tick() => {
                    let lines = self.sup.poll();
                    self.push_log(lines);
                }
            }
            self.publish();
        }
    }

    fn handle(&mut self, req: Request) -> Response {
        match req {
            Request::GetState {} => Response::State(snapshot(&self.sup, self.profile, &self.cfg)),
            Request::GetLog { since } => Response::Log {
                lines: self.log.iter().filter(|l| l.seq > since).cloned().collect(),
            },
            Request::Connect { profile } => self.connect(profile),
            Request::Disconnect {} => {
                if self.sup.is_connecting() {
                    return error(ErrorCode::Busy, "a connection attempt is in progress");
                }
                let lines = self.sup.disconnect();
                self.push_log(lines);
                Response::Ok {}
            }
            Request::SetProfile { profile } => {
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
            self.profile = p;
            self.cfg.traffic.profile = p;
        }
        let cfg = self.cfg.clone();
        let want_kill_switch = cfg.tun.kill_switch;
        self.sup.begin_connect();
        self.push_log(vec![format!("Connecting to {server} …")]);
        let fut = (self.connect_fn)(cfg, server, want_kill_switch);
        let tx = self.outcome_tx.clone();
        tokio::spawn(async move {
            let outcome = fut.await;
            let _ = tx.send(outcome).await;
        });
        Response::Ok {}
    }

    /// Finish an in-flight connect first (it may have created the adapter and
    /// engaged the kill switch), then tear everything down in order.
    async fn shutdown(&mut self, outcome_rx: &mut mpsc::Receiver<ConnectOutcome>) {
        if self.sup.is_connecting() {
            if let Some(outcome) = outcome_rx.recv().await {
                let lines = self.sup.on_connected(outcome);
                self.push_log(lines);
            }
        }
        let lines = self.sup.shutdown().await;
        self.push_log(lines);
        self.publish();
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
        let snap = snapshot(&self.sup, self.profile, &self.cfg);
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
                if watch.borrow().phase == Phase::Disconnected {
                    break;
                }
                watch.changed().await.unwrap();
            }
        })
        .await
        .expect("returns to Disconnected after the failed connect");

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
