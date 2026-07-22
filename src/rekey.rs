//! Rekey driver that solves the shared-socket problem.
//!
//! THE PROBLEM
//!   run_handshake_initiator reads from the socket itself (recv_from). During a
//!   live tunnel the inbound loop reads from that same socket too. Two readers
//!   on one socket = race: the rekey response is swallowed by the data loop and
//!   dropped as a data frame. The rekey then hangs forever.
//!
//! THE SOLUTION
//!   The inbound loop stays the ONLY reader. When it sees a Handshake frame
//!   mid-session, it forwards it via a channel to this driver. The driver sends
//!   itself (send_to is allowed from multiple tasks) but RECEIVES exclusively
//!   via the channel. This way there is exactly one socket reader.

use crate::crypto::Authenticator;
use crate::error::Result;
use crate::net::{build_handshake_datagrams, push_handshake, send_handshake, HandshakeSink};
use crate::session::SessionManager;
use crate::tunnel::{Handshake, Reassembler};
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, info};

/// An incoming handshake fragment, forwarded by the inbound loop.
pub type HandshakeFrameRx = mpsc::Receiver<Bytes>;
pub type HandshakeFrameTx = mpsc::Sender<Bytes>;

/// Per-attempt wait for the response; on loss we resend the init.
/// Total time = MAX_REKEY_RETRIES * PER_ATTEMPT_TIMEOUT.
const PER_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(800);
const MAX_REKEY_RETRIES: usize = 4;

/// As INITIATOR, run a rekey without reading the socket itself.
/// Response fragments arrive via `hs_rx` (fed by the inbound loop).
/// On loss of the init or response packet the init is resent (bounded
/// retry). The ephemeral keys stay constant across retries — only the
/// transmission is repeated. `sink` decides how datagrams leave: straight to
/// the socket, or handed to the outbound pacer (see `HandshakeSink`) — the
/// caller picks based on whether a traffic profile is currently shaping timing.
pub(crate) async fn rekey_as_initiator(
    sink: &HandshakeSink<'_>,
    auth: &dyn Authenticator,
    sessions: &SessionManager,
    new_session_id: u32,
    hs_rx: &mut HandshakeFrameRx,
    hs_obf: Option<&[u8; 32]>,
) -> Result<()> {
    let (hs, init_wire) = Handshake::start(auth)?;
    // Build the init datagrams once (obf or cleartext) and resend the same
    // bytes per retry, so that a lost fragment can still be completed by a
    // later attempt.
    let init_datagrams = build_handshake_datagrams(new_session_id, &init_wire, hs_obf)?;

    // Retry loop: send init, wait for response; on timeout send again.
    // The Reassembler is set up fresh per attempt so that a half-received old
    // response does not pollute a later attempt.
    let mut last_err = crate::error::ChameleonError::Handshake {
        state: "rekey".into(),
        msg: "no attempts made".into(),
    };

    for attempt in 1..=MAX_REKEY_RETRIES {
        // (Re)send the init message.
        for datagram in &init_datagrams {
            sink.send(datagram).await?;
        }

        let mut reasm = Reassembler::default();
        let attempt_result = timeout(PER_ATTEMPT_TIMEOUT, async {
            while let Some(raw) = hs_rx.recv().await {
                // A malformed/spoofed datagram here is noise, not a reason to
                // give up the whole retry loop — mirrors how
                // run_handshake_responder treats reassembly errors (net.rs).
                // Only a genuinely closed channel (recv() returning None,
                // below) should stop retrying.
                match push_handshake(&mut reasm, &raw, hs_obf) {
                    Ok(Some(resp_wire)) => return Ok(Some(resp_wire)),
                    Ok(None) => {}
                    Err(e) => debug!("rekey reassembly drop: {e}"),
                }
            }
            Err::<Option<Bytes>, _>(crate::error::ChameleonError::ChannelClosed)
        })
        .await;

        match attempt_result {
            Ok(Ok(Some(resp_wire))) => {
                // finalize verifies the responder and returns the Confirm message.
                return match hs.finalize(resp_wire, auth)? {
                    (Handshake::Established { session }, confirm_wire) => {
                        // Send Confirm so the responder authenticates us.
                        send_handshake(sink, new_session_id, &confirm_wire, hs_obf).await?;
                        let sid = session.session_id; // derived session_id (I-13)
                        sessions.install_new_session(session);
                        info!(
                            "rekey complete after {attempt} attempt(s), mutual — \
                               now on session {sid}"
                        );
                        Ok(())
                    }
                    _ => Err(crate::error::ChameleonError::Handshake {
                        state: "rekey".into(),
                        msg: "rekey handshake failed (auth/MAC)".into(),
                    }),
                };
            }
            Ok(Ok(None)) => unreachable!("timeout closure returns Some or Err"),
            Ok(Err(e)) => {
                last_err = e;
                break;
            } // channel closed: stop
            Err(_) => {
                // Timeout on this attempt: log and retry.
                debug!("rekey attempt {attempt} timed out, retrying");
                last_err = crate::error::ChameleonError::Handshake {
                    state: "rekey".into(),
                    msg: format!("timed out after {attempt} attempts"),
                };
            }
        }
    }

    Err(last_err)
}

/// Schedule cleanup of the previous session after a grace period.
/// Called from the tunnel loop that holds an Arc<SessionManager>.
pub fn schedule_retire(sessions: Arc<SessionManager>) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        sessions.retire_previous();
        info!("previous session retired (grace period elapsed)");
    });
}

/// RESPONDER side of a mid-session rekey, phase 1: process the incoming init
/// and send the response back. Does NOT install the session yet — it is only
/// trusted after a valid Confirm (phase 2). Returns the pending handshake so
/// the inbound loop holds onto it until the Confirm arrives.
///
/// This two-stage model fits the fact that the inbound loop is the only reader
/// of the socket: it first feeds the init here, and later the Confirm to
/// `rekey_responder_confirm`. `sink` — see `rekey_as_initiator`'s doc.
pub(crate) async fn rekey_as_responder(
    sink: &HandshakeSink<'_>,
    auth: &dyn Authenticator,
    new_session_id: u32,
    init_wire: Bytes,
    hs_obf: Option<&[u8; 32]>,
) -> Result<Handshake> {
    match Handshake::respond(init_wire, auth)? {
        (hs @ Handshake::SentResponse { .. }, resp_wire) => {
            send_handshake(sink, new_session_id, &resp_wire, hs_obf).await?;
            info!(
                "rekey (responder) response sent — awaiting confirm for session {new_session_id}"
            );
            Ok(hs)
        }
        _ => Err(crate::error::ChameleonError::Handshake {
            state: "rekey-responder".into(),
            msg: "respond did not yield SentResponse".into(),
        }),
    }
}

/// RESPONDER side of a mid-session rekey, phase 2: process the Confirm,
/// authenticate the initiator, and only then install the new session.
/// Without a valid Confirm the rekey session is never trusted.
pub fn rekey_responder_confirm(
    hs: Handshake,
    auth: &dyn Authenticator,
    sessions: &SessionManager,
    new_session_id: u32,
    confirm_wire: Bytes,
) -> Result<()> {
    match hs.confirm(confirm_wire, auth)? {
        Handshake::Established { session } => {
            let sid = session.session_id; // derived session_id (I-13)
            sessions.install_new_session(session);
            info!(
                "rekey (responder) complete, mutual — now on session {sid} (req {new_session_id})"
            );
            Ok(())
        }
        _ => Err(crate::error::ChameleonError::Handshake {
            state: "rekey-responder".into(),
            msg: "confirm did not establish session".into(),
        }),
    }
}

/// Helper: create the channel over which the inbound loop forwards handshake
/// frames to a running rekey driver.
pub fn handshake_channel() -> (HandshakeFrameTx, HandshakeFrameRx) {
    mpsc::channel(16)
}
