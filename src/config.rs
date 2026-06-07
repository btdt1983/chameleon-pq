//! TOML-configuratie en CLI voor Chameleon-PQ.
//!
//! Voorbeeld config.toml:
//!
//!   [identity]
//!   ed25519_seed_hex   = "0101...01"   # 32 bytes hex = eigen private seed
//!   peer_ed25519_pub_hex = "0909...09" # 32 bytes hex = peer's publieke sleutel
//!
//!   [network]
//!   bind_addr   = "0.0.0.0:51820"
//!   server_addr = "1.2.3.4:51820"   # alleen nodig in client-modus
//!
//!   [tun]
//!   name    = "chameleon0"
//!   address = "10.99.0.1"
//!   netmask = "255.255.255.0"
//!   mtu     = 1400
//!
//!   [engine]
//!   batch_linger_us           = 200

use crate::error::{ChameleonError, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name    = "chameleon-pq",
    version = env!("CARGO_PKG_VERSION"),
    about   = "Hybrid post-quantum VPN (Kyber768 + X25519 + Ed25519)",
)]
pub struct Cli {
    /// Pad naar config.toml
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,

    /// Verhoog verbositeit (-v = debug, -vv = trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start als server (wacht op inkomende verbindingen)
    Server {
        #[arg(long)]
        bind: Option<SocketAddr>,
    },
    /// Start als client (verbindt naar server)
    Client {
        #[arg(long)]
        server: Option<SocketAddr>,
    },
    /// Genereer een nieuw Ed25519 keypair (print naar stdout)
    Keygen,
    /// Valideer het configuratiebestand
    Check,
}

// ── Config-structs ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub identity: IdentityConfig,
    pub network: NetworkConfig,
    pub tun: TunConfig,
    #[serde(default)]
    pub engine: EngineConfig,
}

#[derive(Debug, Deserialize)]
pub struct IdentityConfig {
    /// Eigen Ed25519 seed: 32 bytes als lowercase hex-string.
    pub ed25519_seed_hex: String,
    /// Voorgedeelde publieke sleutel van de peer: 32 bytes hex.
    pub peer_ed25519_pub_hex: String,
    /// Eigen ML-DSA-65 secret key (hex). Optioneel: aanwezig => hybride
    /// (Ed25519 + ML-DSA) peer-authenticatie; afwezig => alleen Ed25519.
    /// Moet samen met `peer_mldsa_pub_hex` worden gezet.
    #[serde(default)]
    pub mldsa_secret_hex: Option<String>,
    /// Voorgedeelde ML-DSA-65 publieke sleutel van de peer (hex).
    #[serde(default)]
    pub peer_mldsa_pub_hex: Option<String>,
}

impl IdentityConfig {
    pub fn seed_bytes(&self) -> Result<[u8; 32]> {
        hex_to_32(&self.ed25519_seed_hex, "identity.ed25519_seed_hex")
    }
    pub fn peer_pub_bytes(&self) -> Result<[u8; 32]> {
        hex_to_32(&self.peer_ed25519_pub_hex, "identity.peer_ed25519_pub_hex")
    }

    /// Eigen ML-DSA secret key als bytes, indien geconfigureerd.
    pub fn mldsa_secret_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.mldsa_secret_hex
            .as_deref()
            .map(|s| hex_to_vec(s, "identity.mldsa_secret_hex"))
            .transpose()
    }

    /// Voorgedeelde ML-DSA publieke sleutel van de peer als bytes, indien geconfigureerd.
    pub fn peer_mldsa_pub_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.peer_mldsa_pub_hex
            .as_deref()
            .map(|s| hex_to_vec(s, "identity.peer_mldsa_pub_hex"))
            .transpose()
    }

    /// True als beide ML-DSA-velden zijn gezet (hybride auth gevraagd).
    pub fn has_mldsa(&self) -> bool {
        self.mldsa_secret_hex.is_some() && self.peer_mldsa_pub_hex.is_some()
    }
}

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_bind")]
    pub bind_addr: SocketAddr,
    pub server_addr: Option<SocketAddr>,
}

#[derive(Debug, Deserialize)]
pub struct TunConfig {
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_tun_addr")]
    pub address: String,
    #[serde(default = "default_netmask")]
    pub netmask: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

#[derive(Debug, Deserialize, Default)]
pub struct EngineConfig {
    #[serde(default = "default_linger")]
    pub batch_linger_us: u64,
}

// ── defaults ─────────────────────────────────────────────────────────────────

fn default_bind() -> SocketAddr {
    "0.0.0.0:51820".parse().unwrap()
}
fn default_tun_name() -> String {
    "chameleon0".into()
}
fn default_tun_addr() -> String {
    "10.99.0.1".into()
}
fn default_netmask() -> String {
    "255.255.255.0".into()
}
fn default_mtu() -> u16 {
    1400
}
fn default_linger() -> u64 {
    200
}

// ── Loader ───────────────────────────────────────────────────────────────────

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| ChameleonError::Handshake {
            state: "config".into(),
            msg: format!("cannot read {:?}: {e}", path),
        })?;
        let cfg: AppConfig = toml::from_str(&raw).map_err(|e| ChameleonError::Handshake {
            state: "config".into(),
            msg: format!("TOML parse error: {e}"),
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        self.identity.seed_bytes()?;
        self.identity.peer_pub_bytes()?;
        // ML-DSA is optioneel, maar de twee velden horen bij elkaar: een halve
        // configuratie (alleen secret óf alleen peer-pub) is bijna zeker een
        // vergissing en zou stilletjes naar Ed25519-only terugvallen.
        match (
            &self.identity.mldsa_secret_hex,
            &self.identity.peer_mldsa_pub_hex,
        ) {
            (Some(_), Some(_)) | (None, None) => {
                // Valideer dat de sleutels parsen als ze er zijn.
                self.identity.mldsa_secret_bytes()?;
                self.identity.peer_mldsa_pub_bytes()?;
            }
            _ => {
                return Err(ChameleonError::Handshake {
                    state: "config".into(),
                    msg: "identity: set BOTH mldsa_secret_hex and peer_mldsa_pub_hex, \
                          or neither (hybrid ML-DSA auth is all-or-nothing)"
                        .into(),
                });
            }
        }
        if self.tun.mtu < 576 {
            return Err(ChameleonError::Handshake {
                state: "config".into(),
                msg: format!("tun.mtu {} is below minimum 576", self.tun.mtu),
            });
        }
        Ok(())
    }
}

// ── Hex helper ───────────────────────────────────────────────────────────────

fn hex_to_32(s: &str, field: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(ChameleonError::Handshake {
            state: "config".into(),
            msg: format!("{field}: expected 64 hex chars, got {}", s.len()),
        });
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0], field)?;
        let lo = hex_nibble(chunk[1], field)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Decodeer een hex-string van willekeurige (even) lengte naar bytes.
/// Gebruikt voor ML-DSA-sleutels, die veel groter zijn dan 32 bytes.
fn hex_to_vec(s: &str, field: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(ChameleonError::Handshake {
            state: "config".into(),
            msg: format!("{field}: hex length {} is not even", s.len()),
        });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = hex_nibble(chunk[0], field)?;
        let lo = hex_nibble(chunk[1], field)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8, field: &str) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ChameleonError::Handshake {
            state: "config".into(),
            msg: format!("{field}: invalid hex character '{}'", b as char),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let seed = [0xABu8; 32];
        let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        let back = hex_to_32(&hex, "test").unwrap();
        assert_eq!(back, seed);
    }

    #[test]
    fn hex_rejects_bad_input() {
        assert!(hex_to_32("zz", "test").is_err());
        assert!(hex_to_32("ab", "test").is_err()); // too short
    }
}
