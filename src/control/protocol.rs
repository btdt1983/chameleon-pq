//! Wire-level vocabulary between a frontend and the privileged side, plus the
//! framing codec.
//!
//! Deliberately small and data-only. **Nothing here carries a file path, a
//! server address, raw config or a free-form command**: every field is an enum
//! or a bounded value, so an unprivileged caller can never make a privileged
//! process read a file or contact a host of the caller's choosing (design doc,
//! sections 5 and 7).
//!
//! Framing: a 4-byte big-endian length followed by that many bytes of UTF-8
//! JSON. The length is validated against [`MAX_FRAME`] **before** any buffer is
//! allocated. Every struct rejects unknown fields. Decoding is the pure
//! function [`decode`] so it can be fuzzed directly.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bumped on an incompatible change. Exchanged in [`Hello`].
/// v2: `StateSnapshot` carries the administrator policy summary.
/// v3: `Phase::Reconnecting` and `StateSnapshot::reconnect` (automatic reconnect).
pub const PROTOCOL_VERSION: u32 = 3;

/// Largest accepted frame body, in bytes.
pub const MAX_FRAME: usize = 64 * 1024;

pub use crate::config::TrafficProfile;
pub use crate::control::policy::KillSwitchPolicy;

/// Lifecycle phase of the tunnel as seen by a frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Disconnected,
    Connecting,
    Connected,
    /// The service wants to be connected, the last attempt failed or the tunnel
    /// dropped, and it is waiting for the next attempt (see `reconnect`).
    Reconnecting,
}

/// Machine-readable error class (the human text travels separately and is
/// never parsed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// A request the current state does not allow (e.g. connect while connected).
    Busy,
    /// Not allowed (policy / not implemented for unprivileged callers).
    Denied,
    /// Malformed or unexpected message.
    Protocol,
    /// Anything else on the privileged side.
    Internal,
}

/// Kill-switch state as a frontend needs to show it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KillSwitchState {
    Off,
    /// Engaged by this supervisor.
    Engaged,
    /// Found at startup, left over from an earlier run.
    Orphaned,
}

/// Live tunnel numbers (only while connected).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelInfo {
    /// Peer endpoint, display only.
    pub peer: String,
    pub session_id: u32,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// Epoch seconds of the last received packet (0 = nothing yet).
    pub last_recv_epoch: u64,
    pub uptime_secs: u64,
}

/// The part of the administrator policy a frontend needs to shape its UI. The
/// service enforces the policy regardless; this only avoids offering buttons
/// that would be refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySummary {
    pub allow_user_disconnect: bool,
    /// `None` = every profile.
    pub allowed_profiles: Option<Vec<TrafficProfile>>,
    pub kill_switch: KillSwitchPolicy,
    pub allow_update_check: bool,
}

impl PolicySummary {
    pub fn profile_allowed(&self, p: TrafficProfile) -> bool {
        self.allowed_profiles
            .as_ref()
            .map_or(true, |list| list.contains(&p))
    }
}

impl From<&crate::control::policy::Policy> for PolicySummary {
    fn from(p: &crate::control::policy::Policy) -> Self {
        Self {
            allow_user_disconnect: p.allow_user_disconnect,
            allowed_profiles: p.allowed_profiles.clone(),
            kill_switch: p.kill_switch,
            allow_update_check: p.allow_update_check,
        }
    }
}

/// Everything a frontend needs to draw its state. Owned by the protocol, not
/// derived from internal types, so internals can change without a wire change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateSnapshot {
    pub phase: Phase,
    pub tunnel: Option<TunnelInfo>,
    pub kill_switch: KillSwitchState,
    /// Profile in effect (or that the next connect will use).
    pub profile: TrafficProfile,
    /// Secure-by-default warnings for the active config.
    pub warnings: Vec<String>,
    pub policy: PolicySummary,
    /// Present while the service is retrying on its own.
    pub reconnect: Option<ReconnectInfo>,
}

/// Progress of the automatic reconnect, for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconnectInfo {
    /// 1 for the first retry.
    pub attempt: u32,
    /// Seconds until the next attempt; `None` while an attempt is running.
    pub next_in_secs: Option<u64>,
    /// Why the previous attempt (or the tunnel) failed.
    pub last_error: Option<String>,
}

/// First message in each direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub protocol_version: u32,
}

impl Hello {
    pub fn current() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
        }
    }
}

/// What a frontend may ask. No paths, no addresses, no config.
///
/// Variants without data are written `Name {}` rather than as unit variants:
/// serde does not enforce `deny_unknown_fields` for unit variants of internally
/// tagged enums, so `{"type":"GetState","x":1}` would be accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Request {
    GetState {},
    /// Connect with the administrator's config. `profile` optionally overrides
    /// the traffic profile for this connection.
    Connect {
        profile: Option<TrafficProfile>,
    },
    Disconnect {},
    /// Re-profile the running tunnel (or the next connect) without reconnecting.
    SetProfile {
        profile: TrafficProfile,
    },
    /// Escape hatch; policy-gated (always [`ErrorCode::Denied`] for now).
    ClearKillSwitch {},
    /// Service log lines with sequence number greater than `since`.
    GetLog {
        since: u64,
    },
}

/// Answer to exactly one [`Request`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Response {
    Ok {},
    State(StateSnapshot),
    Log { lines: Vec<LogLine> },
    Error { code: ErrorCode, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogLine {
    pub seq: u64,
    pub text: String,
}

/// Pushed by the service without a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Event {
    State(StateSnapshot),
}

/// Frontend to service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ClientMessage {
    Hello(Hello),
    Request(Request),
}

/// Service to frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ServerMessage {
    Hello(Hello),
    Response(Response),
    Event(Event),
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge(usize),
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// Validate a frame header and return the body length. No allocation happens
/// before this succeeds.
pub fn parse_len(header: [u8; 4]) -> Result<usize, CodecError> {
    let n = u32::from_be_bytes(header) as usize;
    if n > MAX_FRAME {
        return Err(CodecError::TooLarge(n));
    }
    Ok(n)
}

/// Serialise `msg` into a complete frame (header + body).
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, CodecError> {
    let body = serde_json::to_vec(msg).map_err(|e| CodecError::Malformed(e.to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(CodecError::TooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse a frame body. Pure: the fuzz entry point.
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, CodecError> {
    if body.len() > MAX_FRAME {
        return Err(CodecError::TooLarge(body.len()));
    }
    serde_json::from_slice(body).map_err(|e| CodecError::Malformed(e.to_string()))
}

/// Read one frame body. An `UnexpectedEof` before the header or inside the body
/// is returned as an I/O error.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, CodecError> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).await?;
    let n = parse_len(header)?;
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// Write one message as a frame and flush.
pub async fn write_message<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> Result<(), CodecError> {
    let frame = encode(msg)?;
    w.write_all(&frame).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> StateSnapshot {
        StateSnapshot {
            phase: Phase::Connected,
            tunnel: Some(TunnelInfo {
                peer: "203.0.113.5:51820".into(),
                session_id: 7,
                tx_bytes: 1,
                rx_bytes: 2,
                last_recv_epoch: 3,
                uptime_secs: 4,
            }),
            kill_switch: KillSwitchState::Engaged,
            profile: TrafficProfile::Balanced,
            warnings: vec!["w".into()],
            reconnect: None,
            policy: PolicySummary::from(&crate::control::policy::Policy::default()),
        }
    }

    #[test]
    fn every_message_roundtrips() {
        let reqs = vec![
            Request::GetState {},
            Request::Connect { profile: None },
            Request::Connect {
                profile: Some(TrafficProfile::Stealth),
            },
            Request::Disconnect {},
            Request::SetProfile {
                profile: TrafficProfile::Throughput,
            },
            Request::ClearKillSwitch {},
            Request::GetLog { since: 9 },
        ];
        for r in reqs {
            let m = ClientMessage::Request(r);
            let f = encode(&m).unwrap();
            let n = parse_len(f[..4].try_into().unwrap()).unwrap();
            assert_eq!(n, f.len() - 4);
            assert_eq!(decode::<ClientMessage>(&f[4..]).unwrap(), m);
        }
        let srv = vec![
            ServerMessage::Hello(Hello::current()),
            ServerMessage::Response(Response::Ok {}),
            ServerMessage::Response(Response::State(snap())),
            ServerMessage::Response(Response::Log {
                lines: vec![LogLine {
                    seq: 1,
                    text: "x".into(),
                }],
            }),
            ServerMessage::Response(Response::Error {
                code: ErrorCode::Busy,
                message: "m".into(),
            }),
            ServerMessage::Event(Event::State(snap())),
        ];
        for m in srv {
            let f = encode(&m).unwrap();
            assert_eq!(decode::<ServerMessage>(&f[4..]).unwrap(), m);
        }
    }

    #[test]
    fn oversized_header_is_rejected_before_allocating() {
        assert!(matches!(
            parse_len(0xFFFF_FFFFu32.to_be_bytes()),
            Err(CodecError::TooLarge(_))
        ));
        assert!(parse_len((MAX_FRAME as u32).to_be_bytes()).is_ok());
        assert!(parse_len((MAX_FRAME as u32 + 1).to_be_bytes()).is_err());
    }

    #[test]
    fn unknown_fields_and_variants_are_rejected() {
        assert!(decode::<ClientMessage>(br#"{"kind":"Request","type":"GetState","x":1}"#).is_err());
        assert!(decode::<ClientMessage>(br#"{"kind":"Request","type":"Nope"}"#).is_err());
        assert!(
            decode::<ClientMessage>(br#"{"kind":"Hello","protocol_version":1,"x":1}"#).is_err()
        );
        // A path smuggled into Connect must not parse.
        assert!(decode::<ClientMessage>(
            br#"{"kind":"Request","type":"Connect","profile":null,"config_path":"C:\\x"}"#
        )
        .is_err());
    }

    #[test]
    fn garbage_never_panics() {
        for body in [&b""[..], b"\xff\xfe", b"{", b"null", b"[1,2]", b"\"\""] {
            assert!(decode::<ClientMessage>(body).is_err());
        }
    }

    #[tokio::test]
    async fn read_frame_handles_truncation() {
        let f = encode(&ClientMessage::Hello(Hello::current())).unwrap();
        let mut short = &f[..f.len() - 1];
        assert!(matches!(
            read_frame(&mut short).await,
            Err(CodecError::Io(_))
        ));
        let mut hdr = &f[..2];
        assert!(matches!(read_frame(&mut hdr).await, Err(CodecError::Io(_))));
        let mut full = &f[..];
        let body = read_frame(&mut full).await.unwrap();
        assert!(decode::<ClientMessage>(&body).is_ok());
    }
}
