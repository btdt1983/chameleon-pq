//! Control plane: what a frontend (GUI/CLI) can ask of the tunnel, and the
//! [`supervisor`] that owns the connect/disconnect/kill-switch lifecycle.
//!
//! See `docs/DESIGN-windows-service.md`. In this first step the supervisor is
//! driven **in-process** by the GUI (no behaviour change); later the same
//! supervisor runs inside a Windows service and the GUI talks to it over a
//! named pipe using the types in [`protocol`].

pub mod controller;
pub mod protocol;
pub mod server;

#[cfg(windows)]
pub mod pipe_windows;
#[cfg(windows)]
pub mod service_windows;
pub mod supervisor;
