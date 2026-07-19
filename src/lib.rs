pub mod aead;
pub mod client;
pub mod config;
pub mod crypto;
pub mod dns;
pub mod engine;
pub mod error;
pub mod frame;
pub mod hsobf;
pub mod killswitch;
pub mod net;
pub mod obf;
pub mod pacer;
pub mod rekey;
pub mod route;
pub mod session;
pub mod setup;
pub mod tun_iface;
pub mod tunnel;
pub mod tunnel_loops;
pub mod udp;

pub use error::{ChameleonError, Result};

/// The product version — single source of truth for the CLI, server, and GUI.
/// Sourced from this crate's own `Cargo.toml` at compile time, so the normal
/// release step (bump `version` here, `chore(release): X.Y.Z`) is the ONLY
/// thing that needs updating: `gui/main.rs` displays this same constant via
/// its `chameleon-pq` path dependency, so a new GUI build always shows the
/// matching version without a second, easy-to-forget manual bump.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
