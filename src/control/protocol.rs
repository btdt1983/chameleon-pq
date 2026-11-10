//! Wire-level vocabulary between a frontend and the privileged side.
//!
//! Deliberately small and data-only. **Nothing here carries a file path, a
//! server address, raw config or a free-form command**: every field is an enum
//! or a bounded value, so an unprivileged caller can never make a privileged
//! process read a file or contact a host of the caller's choosing (design doc,
//! sections 5 and 7). The in-process API in [`super::supervisor`] still takes
//! an `AppConfig` and `SocketAddr` directly; that is a local call, not wire
//! data, and goes away when the service owns the config.
//!
//! There is no codec yet: framing and `serde_json` arrive with the pipe
//! transport.

use serde::{Deserialize, Serialize};

/// Bumped on an incompatible change. Exchanged in `Hello` once the pipe exists.
pub const PROTOCOL_VERSION: u32 = 1;

/// Lifecycle phase of the tunnel as seen by a frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Disconnected,
    Connecting,
    Connected,
}

/// Machine-readable error class (the human text travels separately and is
/// never parsed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    Config,
    Tun,
    KillSwitch,
    Handshake,
    Denied,
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
