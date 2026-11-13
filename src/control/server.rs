//! Per-connection protocol handling, independent of the transport.
//!
//! [`serve_connection`] speaks the protocol over any `AsyncRead + AsyncWrite`
//! stream, so the same code serves a Windows named pipe in production and an
//! in-memory duplex in tests. The transport (pipe creation, ACLs) lives in the
//! Windows-only module.
//!
//! Conversation: the client sends `Hello`; the server checks the version, answers
//! with its own `Hello` and an initial `State` event, then handles `Request`s
//! and pushes a `State` event whenever the controller's state changes.
//!
//! Reads happen in a separate task and are handed over through a channel:
//! `read_exact` is not cancel-safe, so it must never sit inside a `select!`.

use super::controller::ControllerHandle;
use super::protocol::{
    decode, read_frame, write_message, ClientMessage, CodecError, ErrorCode, Event, Hello,
    Response, ServerMessage, PROTOCOL_VERSION,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{split, AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Semaphore};

/// How long a new connection may take to send its `Hello`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Concurrent connections served at once (design doc, section 5).
pub const MAX_CONNECTIONS: usize = 8;

/// Admission control: at most `MAX_CONNECTIONS` served at once; extra
/// connections are closed immediately instead of queueing.
#[derive(Clone)]
pub struct Server {
    handle: ControllerHandle,
    permits: Arc<Semaphore>,
}

impl Server {
    pub fn new(handle: ControllerHandle) -> Self {
        Self::with_limit(handle, MAX_CONNECTIONS)
    }

    pub fn with_limit(handle: ControllerHandle, limit: usize) -> Self {
        Self {
            handle,
            permits: Arc::new(Semaphore::new(limit)),
        }
    }

    pub fn handle(&self) -> &ControllerHandle {
        &self.handle
    }

    /// Serve `stream` on its own task, or drop it when at capacity.
    /// Returns whether the connection was admitted.
    pub fn admit<S>(&self, stream: S) -> bool
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            tracing::warn!("control connection refused: at capacity");
            return false;
        };
        let handle = self.handle.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = serve_connection(stream, handle).await {
                tracing::debug!("control connection ended: {e}");
            }
        });
        true
    }
}

/// Drive one client connection to completion.
pub async fn serve_connection<S>(stream: S, handle: ControllerHandle) -> Result<(), CodecError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = split(stream);

    // 1. Hello, with a deadline: a connection that says nothing is dropped.
    let first = tokio::time::timeout(HELLO_TIMEOUT, read_frame(&mut reader))
        .await
        .map_err(|_| {
            CodecError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no Hello in time",
            ))
        })??;
    match decode::<ClientMessage>(&first) {
        Ok(ClientMessage::Hello(h)) if h.protocol_version == PROTOCOL_VERSION => {}
        Ok(ClientMessage::Hello(h)) => {
            let msg = format!(
                "protocol version {} not supported (server speaks {PROTOCOL_VERSION})",
                h.protocol_version
            );
            send_error(&mut writer, ErrorCode::Protocol, msg.clone()).await;
            return Err(CodecError::Malformed(msg));
        }
        Ok(_) => {
            send_error(
                &mut writer,
                ErrorCode::Protocol,
                "expected Hello first".into(),
            )
            .await;
            return Err(CodecError::Malformed("Hello expected first".into()));
        }
        Err(e) => {
            send_error(&mut writer, ErrorCode::Protocol, "malformed Hello".into()).await;
            return Err(e);
        }
    }
    write_message(&mut writer, &ServerMessage::Hello(Hello::current())).await?;

    let mut state = handle.subscribe();
    let initial = state.borrow_and_update().clone();
    write_message(&mut writer, &ServerMessage::Event(Event::State(initial))).await?;

    // 2. Reader task feeds decoded frames in; this loop never reads directly.
    let (frame_tx, mut frame_rx) = mpsc::channel::<Result<Vec<u8>, CodecError>>(4);
    let reader_task = tokio::spawn(async move {
        loop {
            let frame = read_frame(&mut reader).await;
            let stop = frame.is_err();
            if frame_tx.send(frame).await.is_err() || stop {
                break;
            }
        }
    });

    let result = async {
        loop {
            tokio::select! {
                frame = frame_rx.recv() => {
                    let Some(frame) = frame else { return Ok(()) };
                    let body = match frame {
                        Ok(b) => b,
                        // Clean close by the client.
                        Err(CodecError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            return Ok(());
                        }
                        Err(e) => return Err(e),
                    };
                    match decode::<ClientMessage>(&body) {
                        Ok(ClientMessage::Request(req)) => {
                            let resp = handle.request(req).await;
                            write_message(&mut writer, &ServerMessage::Response(resp)).await?;
                        }
                        Ok(ClientMessage::Hello(_)) => {
                            send_error(&mut writer, ErrorCode::Protocol, "unexpected Hello".into()).await;
                            return Err(CodecError::Malformed("second Hello".into()));
                        }
                        Err(e) => {
                            send_error(&mut writer, ErrorCode::Protocol, "malformed message".into()).await;
                            return Err(e);
                        }
                    }
                }
                changed = state.changed() => {
                    if changed.is_err() {
                        return Ok(()); // controller gone
                    }
                    let snap = state.borrow_and_update().clone();
                    write_message(&mut writer, &ServerMessage::Event(Event::State(snap))).await?;
                }
            }
        }
    }
    .await;

    reader_task.abort();
    result
}

async fn send_error<W: AsyncWrite + Unpin>(w: &mut W, code: ErrorCode, message: String) {
    let _ = write_message(
        w,
        &ServerMessage::Response(Response::Error { code, message }),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::control::controller::{self, ConnectFn};
    use crate::control::protocol::{encode, Phase, Request, TrafficProfile};
    use crate::control::supervisor::Supervisor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn controller() -> ControllerHandle {
        let cfg = AppConfig::load(std::path::Path::new("config.example.toml")).unwrap();
        let connect: ConnectFn =
            Arc::new(|_c, _s, _k| Box::pin(async { (Err("test".to_string()), None) }));
        controller::spawn(cfg, Supervisor::with_orphan(false), connect).0
    }

    /// Returns the client end; the server end is served on a task.
    fn connect(
        handle: ControllerHandle,
    ) -> (
        DuplexStream,
        tokio::task::JoinHandle<Result<(), CodecError>>,
    ) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(serve_connection(server, handle));
        (client, task)
    }

    async fn send(c: &mut DuplexStream, m: &ClientMessage) {
        c.write_all(&encode(m).unwrap()).await.unwrap();
    }

    async fn recv(c: &mut DuplexStream) -> ServerMessage {
        let body = read_frame(c).await.expect("a frame");
        decode(&body).expect("valid server message")
    }

    async fn handshake(c: &mut DuplexStream) {
        send(c, &ClientMessage::Hello(Hello::current())).await;
        assert_eq!(recv(c).await, ServerMessage::Hello(Hello::current()));
        match recv(c).await {
            ServerMessage::Event(Event::State(s)) => assert_eq!(s.phase, Phase::Disconnected),
            other => panic!("expected initial state, got {other:?}"),
        }
    }

    async fn expect_eof(c: &mut DuplexStream) {
        let mut buf = [0u8; 1];
        assert_eq!(
            c.read(&mut buf).await.unwrap(),
            0,
            "connection should be closed"
        );
    }

    #[tokio::test]
    async fn hello_then_get_state() {
        let (mut c, _t) = connect(controller());
        handshake(&mut c).await;
        send(&mut c, &ClientMessage::Request(Request::GetState {})).await;
        match recv(&mut c).await {
            ServerMessage::Response(Response::State(s)) => assert_eq!(s.phase, Phase::Disconnected),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn request_before_hello_is_refused_and_closed() {
        let (mut c, t) = connect(controller());
        send(&mut c, &ClientMessage::Request(Request::GetState {})).await;
        match recv(&mut c).await {
            ServerMessage::Response(Response::Error { code, .. }) => {
                assert_eq!(code, ErrorCode::Protocol)
            }
            other => panic!("{other:?}"),
        }
        expect_eof(&mut c).await;
        assert!(t.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn version_mismatch_is_refused() {
        let (mut c, _t) = connect(controller());
        send(
            &mut c,
            &ClientMessage::Hello(Hello {
                protocol_version: PROTOCOL_VERSION + 1,
            }),
        )
        .await;
        match recv(&mut c).await {
            ServerMessage::Response(Response::Error { code, message }) => {
                assert_eq!(code, ErrorCode::Protocol);
                assert!(message.contains("not supported"));
            }
            other => panic!("{other:?}"),
        }
        expect_eof(&mut c).await;
    }

    #[tokio::test]
    async fn oversized_header_closes_without_a_response() {
        let (mut c, t) = connect(controller());
        c.write_all(&0xFFFF_FFFFu32.to_be_bytes()).await.unwrap();
        expect_eof(&mut c).await;
        assert!(matches!(t.await.unwrap(), Err(CodecError::TooLarge(_))));
    }

    #[tokio::test]
    async fn oversized_header_after_hello_closes() {
        let (mut c, t) = connect(controller());
        handshake(&mut c).await;
        c.write_all(&0xFFFF_FFFFu32.to_be_bytes()).await.unwrap();
        expect_eof(&mut c).await;
        assert!(matches!(t.await.unwrap(), Err(CodecError::TooLarge(_))));
    }

    #[tokio::test]
    async fn truncated_frame_closes() {
        let (mut c, t) = connect(controller());
        handshake(&mut c).await;
        let frame = encode(&ClientMessage::Request(Request::GetState {})).unwrap();
        c.write_all(&frame[..frame.len() - 2]).await.unwrap();
        drop(c); // EOF mid-frame
        assert!(
            t.await.unwrap().is_ok(),
            "an EOF is treated as the client going away"
        );
    }

    #[tokio::test]
    async fn malformed_json_after_hello_gets_an_error_then_close() {
        let (mut c, t) = connect(controller());
        handshake(&mut c).await;
        let junk = b"{\"kind\":\"Request\",\"type\":\"Nope\"}";
        c.write_all(&(junk.len() as u32).to_be_bytes())
            .await
            .unwrap();
        c.write_all(junk).await.unwrap();
        match recv(&mut c).await {
            ServerMessage::Response(Response::Error { code, .. }) => {
                assert_eq!(code, ErrorCode::Protocol)
            }
            other => panic!("{other:?}"),
        }
        expect_eof(&mut c).await;
        assert!(t.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn second_hello_is_a_protocol_error() {
        let (mut c, _t) = connect(controller());
        handshake(&mut c).await;
        send(&mut c, &ClientMessage::Hello(Hello::current())).await;
        match recv(&mut c).await {
            ServerMessage::Response(Response::Error { code, .. }) => {
                assert_eq!(code, ErrorCode::Protocol)
            }
            other => panic!("{other:?}"),
        }
        expect_eof(&mut c).await;
    }

    #[tokio::test(start_paused = true)]
    async fn silent_connection_times_out() {
        let (mut c, t) = connect(controller());
        // Never send Hello; virtual time jumps past the deadline.
        expect_eof(&mut c).await;
        match t.await.unwrap() {
            Err(CodecError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::TimedOut),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn state_changes_are_pushed_as_events() {
        let (mut c, _t) = connect(controller());
        handshake(&mut c).await;
        send(
            &mut c,
            &ClientMessage::Request(Request::SetProfile {
                profile: TrafficProfile::Stealth,
            }),
        )
        .await;
        // The response and the pushed event may arrive in either order.
        let mut got_ok = false;
        let mut got_event = false;
        for _ in 0..2 {
            match recv(&mut c).await {
                ServerMessage::Response(Response::Ok {}) => got_ok = true,
                ServerMessage::Event(Event::State(s)) => {
                    assert_eq!(s.profile, TrafficProfile::Stealth);
                    got_event = true;
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(got_ok && got_event);
    }

    #[tokio::test]
    async fn connection_cap_refuses_the_extra_client() {
        let server = Server::with_limit(controller(), 1);
        let (mut a, a_server) = tokio::io::duplex(1024);
        assert!(server.admit(a_server));
        // `a` holds the only permit while it stays open.
        send(&mut a, &ClientMessage::Hello(Hello::current())).await;
        let _ = recv(&mut a).await;

        let (mut b, b_server) = tokio::io::duplex(1024);
        assert!(!server.admit(b_server));
        expect_eof(&mut b).await;

        // Closing `a` frees the slot.
        drop(a);
        for _ in 0..50 {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
            let (_c, s) = tokio::io::duplex(1024);
            if server.admit(s) {
                return;
            }
        }
        panic!("slot was never released");
    }
}
