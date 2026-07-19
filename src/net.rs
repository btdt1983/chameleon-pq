//! Network glue: the UDP wiring of the INITIAL handshake (initiator +
//! responder, with fragmentation/obfuscation) plus small helpers. The live in/
//! outbound datapath loops run in `main.rs::run_tunnel_loops`; that is the sole
//! socket reader (sole-reader invariant, see rekey.rs).

use crate::crypto::Authenticator;
use crate::error::{ChameleonError, Result};
use crate::frame::{Frame, FrameType};
use crate::hsobf;
use crate::tunnel::{
    fragment, Handshake, HandshakeMessage, HandshakeType, Reassembler, HANDSHAKE_MSG_LEN,
};
use bytes::Bytes;
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

const UDP_BUF: usize = 65_536;

/// Timeouts for the INITIAL handshake (M-2). The initiator resends its init
/// when no response arrives (bounded retry, ephemeral keys stay the same).
/// The responder waits bounded for the Confirm and then returns to listening,
/// so a bogus/incomplete init cannot lock it up permanently.
const HS_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(800);
const HS_MAX_ATTEMPTS: usize = 8;
const HS_CONFIRM_TIMEOUT: Duration = Duration::from_secs(2);

/// Validity window of a return-routability cookie (L-4). A handshake completes
/// within seconds, so 120s is ample; we accept the current + previous window.
const COOKIE_WINDOW_SECS: u64 = 120;

/// Stateless cookie issuance for the responder (L-4). One per-process secret; the
/// cookie itself = HMAC(secret, src ‖ time window), so there is NO per-initiator
/// state before the cookie validates — exactly what the anti-DoS property gives.
struct CookieState {
    secret: [u8; 32],
}

impl CookieState {
    fn new() -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Self { secret }
    }

    fn bucket() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / COOKIE_WINDOW_SECS)
            .unwrap_or(0)
    }

    fn issue(&self, src: &SocketAddr) -> [u8; 16] {
        crate::crypto::compute_cookie(&self.secret, src, Self::bucket())
    }

    /// Valid if the cookie matches the current or previous time window (so a
    /// cookie around a window boundary does not instantly become invalid).
    /// Constant-time comparison — it's a MAC comparison, so a timing leak would
    /// allow byte-by-byte forging.
    fn valid(&self, src: &SocketAddr, cookie: &[u8; 16]) -> bool {
        let b = Self::bucket();
        let ct_eq = |bucket: u64| {
            let expected = crate::crypto::compute_cookie(&self.secret, src, bucket);
            let mut diff = 0u8;
            for i in 0..16 {
                diff |= cookie[i] ^ expected[i];
            }
            diff == 0
        };
        ct_eq(b) || ct_eq(b.wrapping_sub(1))
    }
}

/// Generates increasing session ids for new sessions (rekey).
static SESSION_COUNTER: AtomicU32 = AtomicU32::new(1);
pub fn alloc_session_id() -> u32 {
    next_session_id()
}
fn next_session_id() -> u32 {
    SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ── Handshake wiring over UDP (with fragmentation) ───────────────────────────

/// Build the wire-ready datagrams for a handshake message: obfuscated via
/// hsobf (static key, wrap-then-fragment) if `hs_obf` is set, otherwise the
/// classic cleartext `Frame::new_handshake` path. Separate from sending, so
/// that a rekey retry can resend the same datagrams.
pub(crate) fn build_handshake_datagrams(
    session_id: u32,
    wire: &[u8],
    hs_obf: Option<&[u8; 32]>,
) -> Result<Vec<Bytes>> {
    match hs_obf {
        Some(k) => hsobf::seal_and_fragment(k, wire),
        None => fragment(session_id, wire)
            .into_iter()
            .map(|frag| Frame::new_handshake(frag).encode())
            .collect(),
    }
}

/// Send a handshake message over the wire (obf or cleartext, see
/// `build_handshake_datagrams`).
pub(crate) async fn send_handshake(
    socket: &UdpSocket,
    peer: SocketAddr,
    session_id: u32,
    wire: &[u8],
    hs_obf: Option<&[u8; 32]>,
) -> Result<()> {
    for datagram in build_handshake_datagrams(session_id, wire, hs_obf)? {
        socket.send_to(&datagram, peer).await?;
    }
    Ok(())
}

/// Push one incoming datagram into the handshake reassembler; return the full
/// message once complete. On the obf path this is NOISE-TOLERANT: short or
/// unknown datagrams (and even a complete-but-not-opening blob) yield
/// `Ok(None)`, so stray noise never breaks off the handshake.
pub(crate) fn push_handshake(
    reasm: &mut Reassembler,
    raw: &[u8],
    hs_obf: Option<&[u8; 32]>,
) -> Result<Option<Bytes>> {
    match hs_obf {
        Some(k) => {
            let (mid, idx, tot, chunk) = match hsobf::unmask_fragment(k, raw) {
                Some(v) => v,
                None => return Ok(None),
            };
            match reasm.push_parts(mid, idx, tot, chunk) {
                Ok(Some(blob)) => Ok(hsobf::open(k, &blob).ok()),
                _ => Ok(None),
            }
        }
        None => {
            let frame = Frame::decode(Bytes::copy_from_slice(raw))?;
            if frame.frame_type != FrameType::Handshake {
                return Ok(None);
            }
            reasm.push(&frame.payload)
        }
    }
}

/// CLIENT/INITIATOR: run the handshake and return the Established session.
/// M-2: bounded retry — when no response arrives the same init is resent;
/// after `HS_MAX_ATTEMPTS` the handshake fails cleanly instead of hanging.
/// The response is only accepted from the `peer`.
pub async fn run_handshake_initiator(
    socket: &UdpSocket,
    peer: SocketAddr,
    auth: &dyn Authenticator,
    hs_obf: Option<&[u8; 32]>,
) -> Result<crate::session::Session> {
    let session_id = next_session_id();
    let (hs, init_wire) = Handshake::start(auth)?;
    // Build the init datagrams once and resend the same bytes per attempt
    // (ephemeral keys stay constant, as in the rekey driver). On a
    // CookieChallenge (L-4) they are rebuilt with the cookie inside.
    let mut init_datagrams = build_handshake_datagrams(session_id, &init_wire, hs_obf)?;

    let mut buf = vec![0u8; UDP_BUF];
    let mut resp_wire = None;
    for attempt in 1..=HS_MAX_ATTEMPTS {
        for datagram in &init_datagrams {
            socket.send_to(datagram, peer).await?;
        }
        let mut reasm = Reassembler::default();
        let got = timeout(HS_ATTEMPT_TIMEOUT, async {
            loop {
                let (n, src) = socket.recv_from(&mut buf).await?;
                if src != peer {
                    continue; // accept the response only from the peer
                }
                if let Some(w) = push_handshake(&mut reasm, &buf[..n], hs_obf)? {
                    return Ok::<Option<Bytes>, ChameleonError>(Some(w));
                }
            }
        })
        .await;
        match got {
            Ok(Ok(Some(w))) => {
                // L-4: a CookieChallenge instead of a Response — echo the cookie
                // in the Init and resend (next loop iteration). This proves
                // return-routability before the responder does expensive crypto.
                if w.len() == HANDSHAKE_MSG_LEN && w[1] == HandshakeType::CookieChallenge as u8 {
                    if let Ok(ch) = HandshakeMessage::decode(w) {
                        let mut m = HandshakeMessage::decode(init_wire.clone())?;
                        m.cookie = ch.cookie;
                        init_datagrams =
                            build_handshake_datagrams(session_id, &m.encode()?, hs_obf)?;
                        debug!("handshake: got cookie challenge, resending init with cookie");
                    }
                } else {
                    resp_wire = Some(w);
                    break;
                }
            }
            Ok(Ok(None)) => unreachable!("closure yields Some or an error"),
            Ok(Err(e)) => return Err(e), // socket error
            Err(_) => debug!("handshake init attempt {attempt} timed out, retrying"),
        }
    }
    let resp_wire = resp_wire.ok_or(ChameleonError::Handshake {
        state: "initiator".into(),
        msg: "no handshake response after retries (peer unreachable?)".into(),
    })?;

    // finalize verifies the responder AND returns the Confirm message.
    match hs.finalize(resp_wire, auth)? {
        (Handshake::Established { session }, confirm_wire) => {
            // Send the Confirm message so the responder can authenticate US
            // (mutual auth).
            send_handshake(socket, peer, session_id, &confirm_wire, hs_obf).await?;
            info!(
                "handshake complete (initiator, mutual), session {}",
                session.session_id
            );
            Ok(session)
        }
        _ => Err(ChameleonError::Handshake {
            state: "initiator".into(),
            msg: "handshake failed (auth/MAC)".into(),
        }),
    }
}

/// SERVER/RESPONDER: wait for init, send response, wait for confirm,
/// authenticate the initiator, only then return the trusted session.
///
/// M-2: robust against a bogus/incomplete init. Phase 1 waits (unbounded — a
/// server simply listens on its peer) for an init that opens AND passes through
/// `respond`; an init that does not is skipped instead of letting the server
/// crash. Phase 2 waits BOUNDED (`HS_CONFIRM_TIMEOUT`) for the Confirm from
/// that one address; on timeout or an invalid Confirm the half-open handshake
/// lapses and we listen again — so an attacker cannot lock us up permanently.
pub async fn run_handshake_responder(
    socket: &UdpSocket,
    auth: &dyn Authenticator,
    hs_obf: Option<&[u8; 32]>,
) -> Result<(crate::session::Session, SocketAddr)> {
    let session_id = next_session_id();
    let mut buf = vec![0u8; UDP_BUF];
    // L-4: per-process cookie secret. The responder only does expensive crypto
    // after a valid return-routability cookie (see CookieState).
    let cookies = CookieState::new();

    'listen: loop {
        // Phase 1: wait for a complete, processable Init.
        let mut reasm = Reassembler::default();
        // Phase 1 waits UNBOUNDED for a complete Init (see the doc above), so a
        // slow-trickle attacker sending fragments across many msg_ids (each
        // left incomplete) could otherwise hold stale entries for as long as
        // this loop runs. Prune periodically — same State-Bloat-DoS fix
        // `tunnel_loops.rs` already applies to the rekey reassemblers.
        let mut prune_tick = tokio::time::interval(Duration::from_secs(10));
        let (hs, peer_addr) = loop {
            let (n, src) = tokio::select! {
                r = socket.recv_from(&mut buf) => r?,
                _ = prune_tick.tick() => {
                    reasm.prune_old(Duration::from_secs(10));
                    continue;
                }
            };
            match push_handshake(&mut reasm, &buf[..n], hs_obf) {
                Ok(Some(init_wire)) => {
                    // Decode cheaply to read the type + cookie BEFORE we do
                    // expensive ML-KEM/DH/ML-DSA crypto (L-4).
                    let init_msg = match HandshakeMessage::decode(init_wire.clone()) {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("ignoring bad handshake init from {src}: {e}");
                            reasm = Reassembler::default();
                            continue;
                        }
                    };
                    if init_msg.msg_type != HandshakeType::Init {
                        reasm = Reassembler::default();
                        continue;
                    }
                    // No valid cookie -> send a cheap CookieChallenge and wait
                    // for a resent Init. This way a spoofed source NEVER lures
                    // us into the expensive crypto/large Response.
                    if !cookies.valid(&src, &init_msg.cookie) {
                        match HandshakeMessage::new_cookie_challenge(cookies.issue(&src)) {
                            Ok(ch) => match ch.encode() {
                                Ok(wire) => {
                                    let _ = send_handshake(socket, src, session_id, &wire, hs_obf)
                                        .await;
                                }
                                Err(e) => warn!("cookie challenge encode: {e}"),
                            },
                            Err(e) => warn!("cookie challenge build: {e}"),
                        }
                        reasm = Reassembler::default();
                        continue;
                    }
                    // Valid cookie -> return-routable -> do the expensive handshake.
                    match Handshake::respond(init_wire, auth) {
                        Ok((hs, resp_wire)) => {
                            send_handshake(socket, src, session_id, &resp_wire, hs_obf).await?;
                            break (hs, src);
                        }
                        // Invalid init (e.g. broken ML-KEM key): skip.
                        Err(e) => {
                            warn!("ignoring bad handshake init from {src}: {e}");
                            reasm = Reassembler::default();
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => debug!("handshake reassembly drop: {e}"),
            }
        };

        // Phase 2: wait bounded for the Confirm from peer_addr.
        let mut confirm_reasm = Reassembler::default();
        let confirmed = timeout(HS_CONFIRM_TIMEOUT, async {
            loop {
                let (n, src) = socket.recv_from(&mut buf).await?;
                if src != peer_addr {
                    continue; // ignore other sources during the confirm phase
                }
                if let Some(w) = push_handshake(&mut confirm_reasm, &buf[..n], hs_obf)? {
                    return Ok::<Bytes, ChameleonError>(w);
                }
            }
        })
        .await;

        match confirmed {
            Ok(Ok(confirm_wire)) => match hs.confirm(confirm_wire, auth) {
                Ok(Handshake::Established { session }) => {
                    info!(
                        "handshake complete (responder, mutual), session {}",
                        session.session_id
                    );
                    return Ok((session, peer_addr));
                }
                Ok(_) => {
                    warn!("responder: confirm did not establish — re-listening");
                    continue 'listen;
                }
                Err(e) => {
                    warn!("responder: confirm from {peer_addr} rejected ({e}) — re-listening");
                    continue 'listen;
                }
            },
            Ok(Err(e)) => return Err(e), // socket error
            Err(_) => {
                warn!("responder: timed out awaiting confirm from {peer_addr} — re-listening");
                continue 'listen;
            }
        }
    }
}
