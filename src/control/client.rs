//! Frontend side of the control protocol, over any `AsyncRead + AsyncWrite`.
//!
//! [`ServiceClient::connect_stream`] performs the Hello exchange and starts a
//! task that owns the stream. Requests are answered in order (the server handles
//! one request at a time per connection and writes replies in that order), so
//! pending replies are a FIFO. `State` events update a `watch` value; callers
//! read it with [`ServiceClient::state`] and never poll for it.
//!
//! Reads run in their own task: `read_exact` is not cancel-safe and must not sit
//! inside a `select!`.

use super::protocol::{
    decode, read_frame, write_message, ClientMessage, CodecError, Event, Hello, Request, Response,
    ServerMessage, StateSnapshot, PROTOCOL_VERSION,
};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{split, AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, watch};

/// How long to wait for the server's Hello and first state.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a single request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error, Clone)]
pub enum ClientError {
    #[error("connection to the service is closed")]
    Closed,
    #[error("the service did not answer in time")]
    Timeout,
    #[error("protocol error: {0}")]
    Protocol(String),
}

type Pending = (Request, oneshot::Sender<Response>);

/// Cloneable handle to a live connection.
#[derive(Clone, Debug)]
pub struct ServiceClient {
    tx: mpsc::Sender<Pending>,
    state: watch::Receiver<StateSnapshot>,
    /// Dropped when the connection task ends, so `is_closed` is accurate even
    /// if nobody has sent a request since.
    alive: Arc<watch::Receiver<()>>,
}

impl ServiceClient {
    /// Hello exchange plus the initial state. Fails on a version mismatch.
    pub async fn connect_stream<S>(stream: S) -> Result<Self, ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, mut writer) = split(stream);
        let handshake = async {
            write_message(&mut writer, &ClientMessage::Hello(Hello::current()))
                .await
                .map_err(proto)?;
            match next_message(&mut reader).await? {
                ServerMessage::Hello(h) if h.protocol_version == PROTOCOL_VERSION => {}
                ServerMessage::Hello(h) => {
                    return Err(ClientError::Protocol(format!(
                        "service speaks protocol {}, this client speaks {PROTOCOL_VERSION}",
                        h.protocol_version
                    )))
                }
                ServerMessage::Response(Response::Error { message, .. }) => {
                    return Err(ClientError::Protocol(message))
                }
                other => return Err(ClientError::Protocol(format!("unexpected {other:?}"))),
            }
            match next_message(&mut reader).await? {
                ServerMessage::Event(Event::State(s)) => Ok(s),
                other => Err(ClientError::Protocol(format!(
                    "expected initial state, got {other:?}"
                ))),
            }
        };
        let initial = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
            .await
            .map_err(|_| ClientError::Timeout)??;

        let (state_tx, state_rx) = watch::channel(initial);
        let (req_tx, mut req_rx) = mpsc::channel::<Pending>(8);
        let (alive_tx, alive_rx) = watch::channel(());
        let (frame_tx, mut frame_rx) = mpsc::channel::<Result<Vec<u8>, CodecError>>(8);

        tokio::spawn(async move {
            loop {
                let frame = read_frame(&mut reader).await;
                let stop = frame.is_err();
                if frame_tx.send(frame).await.is_err() || stop {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            // Keep the sender alive for the life of the task; dropping it is the
            // "closed" signal.
            let _alive = alive_tx;
            let mut pending: VecDeque<oneshot::Sender<Response>> = VecDeque::new();
            loop {
                tokio::select! {
                    req = req_rx.recv() => {
                        let Some((req, reply)) = req else { break };
                        // Queue the reply in the same step that writes the
                        // request, so ordering can never drift.
                        pending.push_back(reply);
                        if write_message(&mut writer, &ClientMessage::Request(req)).await.is_err() {
                            break;
                        }
                    }
                    frame = frame_rx.recv() => {
                        let Some(Ok(body)) = frame else { break };
                        match decode::<ServerMessage>(&body) {
                            Ok(ServerMessage::Response(r)) => {
                                // A caller that timed out dropped its receiver;
                                // the entry stays in the queue so later replies
                                // still line up.
                                if let Some(reply) = pending.pop_front() {
                                    let _ = reply.send(r);
                                }
                            }
                            Ok(ServerMessage::Event(Event::State(s))) => {
                                let _ = state_tx.send(s);
                            }
                            Ok(ServerMessage::Hello(_)) | Err(_) => break,
                        }
                    }
                }
            }
            // Task ends: pending reply senders drop, waking callers with Closed.
        });

        Ok(Self {
            tx: req_tx,
            state: state_rx,
            alive: Arc::new(alive_rx),
        })
    }

    /// Latest state pushed by the service.
    pub fn state(&self) -> StateSnapshot {
        self.state.borrow().clone()
    }

    /// Whether the connection has ended (service stopped, pipe broken, protocol
    /// error). A closed client never recovers; connect a new one.
    pub fn is_closed(&self) -> bool {
        self.alive.has_changed().is_err()
    }

    /// Send a request and wait for its reply.
    pub async fn request(&self, req: Request) -> Result<Response, ClientError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send((req, reply_tx))
            .await
            .map_err(|_| ClientError::Closed)?;
        match tokio::time::timeout(REQUEST_TIMEOUT, reply_rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err(ClientError::Closed),
            Err(_) => Err(ClientError::Timeout),
        }
    }
}

fn proto(e: CodecError) -> ClientError {
    ClientError::Protocol(e.to_string())
}

async fn next_message<R: AsyncRead + Unpin>(r: &mut R) -> Result<ServerMessage, ClientError> {
    let body = read_frame(r).await.map_err(proto)?;
    decode::<ServerMessage>(&body).map_err(proto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::control::controller::{self, ConnectFn};
    use crate::control::protocol::{ErrorCode, Phase, TrafficProfile};
    use crate::control::server::serve_connection;
    use crate::control::supervisor::Supervisor;
    use tokio::sync::Notify;

    fn controller_with(connect: ConnectFn) -> controller::ControllerHandle {
        let cfg = AppConfig::load(std::path::Path::new("config.example.toml")).unwrap();
        controller::spawn(cfg, Supervisor::with_orphan(false), connect).0
    }

    fn failing(gate: Arc<Notify>) -> ConnectFn {
        Arc::new(move |_c, _s, _k| {
            let gate = gate.clone();
            Box::pin(async move {
                gate.notified().await;
                (Err("nope".to_string()), None)
            })
        })
    }

    async fn client_to(handle: controller::ControllerHandle) -> ServiceClient {
        let (c, s) = tokio::io::duplex(64 * 1024);
        tokio::spawn(serve_connection(s, handle));
        ServiceClient::connect_stream(c).await.expect("connects")
    }

    #[tokio::test]
    async fn connects_and_reads_the_initial_state() {
        let c = client_to(controller_with(failing(Arc::new(Notify::new())))).await;
        assert_eq!(c.state().phase, Phase::Disconnected);
        assert!(!c.is_closed());
    }

    #[tokio::test]
    async fn request_reply_and_pushed_state_through_the_real_server() {
        let gate = Arc::new(Notify::new());
        let c = client_to(controller_with(failing(gate.clone()))).await;

        assert_eq!(
            c.request(Request::SetProfile {
                profile: TrafficProfile::Stealth
            })
            .await
            .unwrap(),
            Response::Ok {}
        );
        // The matching Event arrives interleaved with the Response and updates
        // the watched state without any polling request.
        tokio::time::timeout(Duration::from_secs(5), async {
            while c.state().profile != TrafficProfile::Stealth {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("state event applied");

        // A refused request still returns a reply, in order.
        match c.request(Request::ClearKillSwitch {}).await.unwrap() {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::Denied),
            other => panic!("{other:?}"),
        }
        c.request(Request::Connect { profile: None }).await.unwrap();
        gate.notify_one();
    }

    #[tokio::test]
    async fn replies_stay_in_order_for_concurrent_requests() {
        let c = client_to(controller_with(failing(Arc::new(Notify::new())))).await;
        let a = c.request(Request::GetState {});
        let b = c.request(Request::ClearKillSwitch {});
        let d = c.request(Request::GetLog { since: 0 });
        let (a, b, d) = tokio::join!(a, b, d);
        assert!(matches!(a.unwrap(), Response::State(_)));
        assert!(matches!(b.unwrap(), Response::Error { .. }));
        assert!(matches!(d.unwrap(), Response::Log { .. }));
    }

    #[tokio::test]
    async fn server_closing_marks_the_client_closed() {
        let handle = controller_with(failing(Arc::new(Notify::new())));
        let (c, s) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_connection(s, handle));
        let client = ServiceClient::connect_stream(c).await.unwrap();
        server.abort();
        let _ = server.await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !client.is_closed() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("closed is noticed");
        assert!(matches!(
            client.request(Request::GetState {}).await,
            Err(ClientError::Closed)
        ));
    }

    #[tokio::test]
    async fn version_mismatch_is_reported() {
        // A fake server that answers Hello with a different version.
        let (c, mut s) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let _ = read_frame(&mut s).await;
            let _ = write_message(
                &mut s,
                &ServerMessage::Hello(Hello {
                    protocol_version: PROTOCOL_VERSION + 1,
                }),
            )
            .await;
        });
        match ServiceClient::connect_stream(c).await {
            Err(ClientError::Protocol(m)) => assert!(m.contains("protocol")),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn silent_server_times_out_the_handshake() {
        let (c, _s) = tokio::io::duplex(1024); // server end kept open, says nothing
        assert!(matches!(
            ServiceClient::connect_stream(c).await,
            Err(ClientError::Timeout)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_out_request_does_not_shift_later_replies() {
        // Server: Hello + state, then answers both requests at t=12s.
        let (c, mut s) = tokio::io::duplex(64 * 1024);
        let snap = StateSnapshot {
            phase: Phase::Disconnected,
            tunnel: None,
            kill_switch: crate::control::protocol::KillSwitchState::Off,
            profile: TrafficProfile::default(),
            warnings: vec![],
        };
        tokio::spawn(async move {
            let _ = read_frame(&mut s).await; // client Hello
            write_message(&mut s, &ServerMessage::Hello(Hello::current()))
                .await
                .unwrap();
            write_message(&mut s, &ServerMessage::Event(Event::State(snap)))
                .await
                .unwrap();
            let _ = read_frame(&mut s).await; // request 1
            let _ = read_frame(&mut s).await; // request 2
            tokio::time::sleep(Duration::from_secs(7)).await; // t=12s: after request 1's 10s timeout, before request 2's 15s one
            write_message(&mut s, &ServerMessage::Response(Response::Ok {}))
                .await
                .unwrap(); // reply to request 1 (abandoned)
            write_message(
                &mut s,
                &ServerMessage::Response(Response::Log { lines: vec![] }),
            )
            .await
            .unwrap(); // reply to request 2
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        let client = ServiceClient::connect_stream(c).await.unwrap();
        let c1 = client.clone();
        let first = tokio::spawn(async move { c1.request(Request::Disconnect {}).await });
        tokio::time::sleep(Duration::from_secs(5)).await;
        let c2 = client.clone();
        let second = tokio::spawn(async move { c2.request(Request::GetLog { since: 0 }).await });

        assert!(matches!(first.await.unwrap(), Err(ClientError::Timeout)));
        // The second request, issued while the first was outstanding, still gets
        // ITS reply (the Log), not the abandoned Ok.
        match second.await.unwrap() {
            Ok(Response::Log { .. }) => {}
            other => panic!("replies shifted: {other:?}"),
        }
    }
}
