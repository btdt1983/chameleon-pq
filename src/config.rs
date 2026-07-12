//! TOML configuration and CLI for Chameleon-PQ.
//!
//! Example config.toml:
//!
//!   [identity]
//!   ed25519_seed_hex   = "0101...01"   # 32 bytes hex = own private seed
//!   peer_ed25519_pub_hex = "0909...09" # 32 bytes hex = peer's public key
//!
//!   [network]
//!   bind_addr   = "0.0.0.0:51820"
//!   server_addr = "1.2.3.4:51820"   # only needed in client mode
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
use zeroize::Zeroizing;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name    = "chameleon-pq",
    version = env!("CARGO_PKG_VERSION"),
    about   = "Hybrid post-quantum VPN (ML-KEM-768 + X25519 + Ed25519)",
)]
pub struct Cli {
    /// Path to config.toml
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,

    /// Increase verbosity (-v = debug, -vv = trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start as server (wait for incoming connections)
    Server {
        #[arg(long)]
        bind: Option<SocketAddr>,
    },
    /// Start as client (connect to server)
    Client {
        #[arg(long)]
        server: Option<SocketAddr>,
    },
    /// Generate a new Ed25519 keypair (print to stdout)
    Keygen,
    /// Validate the configuration file
    Check,
}

// ── Config-structs ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub identity: IdentityConfig,
    pub network: NetworkConfig,
    pub tun: TunConfig,
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub obfuscation: ObfuscationConfig,
    #[serde(default)]
    pub traffic: TrafficConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    /// Own Ed25519 seed: 32 bytes as a lowercase hex string.
    pub ed25519_seed_hex: String,
    /// Peer's pre-shared public key: 32 bytes hex.
    pub peer_ed25519_pub_hex: String,
    /// Own ML-DSA-65 secret key (hex). Optional: present => hybrid
    /// (Ed25519 + ML-DSA) peer authentication; absent => Ed25519 only.
    /// Must be set together with `peer_mldsa_pub_hex`.
    #[serde(default)]
    pub mldsa_secret_hex: Option<String>,
    /// Peer's pre-shared ML-DSA-65 public key (hex).
    #[serde(default)]
    pub peer_mldsa_pub_hex: Option<String>,
}

impl IdentityConfig {
    pub fn seed_bytes(&self) -> Result<Zeroizing<[u8; 32]>> {
        // Zeroizing: the private seed is wiped as soon as the caller drops it,
        // so it doesn't linger in a core dump/swap.
        Ok(Zeroizing::new(hex_to_32(
            &self.ed25519_seed_hex,
            "identity.ed25519_seed_hex",
        )?))
    }
    pub fn peer_pub_bytes(&self) -> Result<[u8; 32]> {
        hex_to_32(&self.peer_ed25519_pub_hex, "identity.peer_ed25519_pub_hex")
    }

    /// Own ML-DSA secret key as bytes, if configured. Zeroizing so the
    /// secret key is wiped from memory on drop.
    pub fn mldsa_secret_bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.mldsa_secret_hex
            .as_deref()
            .map(|s| hex_to_vec(s, "identity.mldsa_secret_hex").map(Zeroizing::new))
            .transpose()
    }

    /// Peer's pre-shared ML-DSA public key as bytes, if configured.
    pub fn peer_mldsa_pub_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.peer_mldsa_pub_hex
            .as_deref()
            .map(|s| hex_to_vec(s, "identity.peer_mldsa_pub_hex"))
            .transpose()
    }

    /// True if both ML-DSA fields are set (hybrid auth requested).
    pub fn has_mldsa(&self) -> bool {
        self.mldsa_secret_hex.is_some() && self.peer_mldsa_pub_hex.is_some()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_bind")]
    pub bind_addr: SocketAddr,
    pub server_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TunConfig {
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_tun_addr")]
    pub address: String,
    #[serde(default = "default_netmask")]
    pub netmask: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Full-tunnel routing (client): on connect, route ALL traffic through the
    /// tunnel (WireGuard `AllowedIPs = 0.0.0.0/0`) and pin the server endpoint to
    /// the physical gateway so tunnel packets don't loop; undo it all on
    /// disconnect. Requires `peer_address`. Default off (split-tunnel).
    #[serde(default)]
    pub route_all: bool,
    /// The peer's TUN address (the server side, e.g. `10.99.0.1`) — the gateway
    /// the client routes through when `route_all` is set.
    #[serde(default)]
    pub peer_address: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_linger")]
    pub batch_linger_us: u64,
    /// Number of crypto worker threads for parallel seal/open (Phase C).
    /// 0 = automatic = all logical cores. Lower it to keep cores free
    /// for the reactor/TUN. Only affects the fast (unpaced) path.
    #[serde(default)]
    pub workers: usize,
    /// UDP GSO on send (multiple datagrams in one syscall). Default OFF: it
    /// bundles already-sealed datagrams into one large segmented send, which
    /// on some paths (e.g. a Hyper-V vSwitch or NIC offload that doesn't pass
    /// Linux GSO) causes MASSIVE packet loss — measured: a download that
    /// collapsed from 300 to 47 Mbit with 8000 retransmits. Per-packet send
    /// (off) is correct everywhere; GSO's throughput gain is moreover only
    /// real when the per-packet syscall path is the bottleneck, not the
    /// crypto/CPU. Set `true` only on a proven-clean Linux↔Linux path.
    #[serde(default)]
    pub gso: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            batch_linger_us: default_linger(),
            workers: 0,
            gso: false,
        }
    }
}

// ── Obfuscation (traffic-analysis resistance on the data path) ───────────────

/// Padding policy for the obfuscated data path. Hides the packet size
/// (which otherwise leaks the exact plaintext length) at the cost of bandwidth.
/// Maps to `obf::PadPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaddingPolicy {
    /// No padding — lowest overhead, size leaks the length.
    Off,
    /// Pad to size classes — hides the exact length, moderate overhead.
    #[default]
    Bucketed,
    /// Pad every packet to the MTU-safe maximum size — best obfuscation,
    /// highest bandwidth cost.
    Full,
}

/// `[obfuscation]` section. Default ON with bucketed padding (clean break from
/// 0.1.0; see also the PROTO_VERSION bump). Set `enabled = false` for the
/// classic, non-obfuscated data-path frame (e.g. for debugging).
#[derive(Debug, Clone, Deserialize)]
pub struct ObfuscationConfig {
    #[serde(default = "default_obf_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub padding: PaddingPolicy,
    /// Also obfuscate the handshake envelope (Phase 2, hsobf.rs). Default on;
    /// changes the wire format, so both sides must have this enabled.
    #[serde(default = "default_hs_obf_enabled")]
    pub handshake: bool,
    /// Optional shared obfuscation secret (hex) for the handshake. Absent =>
    /// the handshake obfuscation key is derived from the pre-shared
    /// Ed25519 pubkeys (zero config). Present => stronger (an adversary who
    /// only has the pubkeys then cannot de-obfuscate). Identical on both sides.
    #[serde(default)]
    pub psk_hex: Option<String>,
}

impl ObfuscationConfig {
    /// The optional handshake obfuscation secret as bytes, if set.
    pub fn psk_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.psk_hex
            .as_deref()
            .map(|s| hex_to_vec(s, "obfuscation.psk_hex"))
            .transpose()
    }
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            enabled: default_obf_enabled(),
            padding: PaddingPolicy::default(),
            handshake: default_hs_obf_enabled(),
            psk_hex: None,
        }
    }
}

// ── Traffic shaping (timing/cover-traffic obfuscation, Phase 3) ──────────────

/// Shape mode for the constant-rate pacer. Maps to `pacer::ShapeMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficMode {
    /// Constant bit-rate: always at tempo, even when idle. Strongest timing
    /// concealment, but constant bandwidth cost 24/7 (even when nothing flows).
    Cbr,
    /// Adaptive: pace during activity + cooldown, silent when truly idle.
    /// The DEFAULT: no bandwidth at rest, but burst concealment during
    /// activity. Coarse active-vs-idle leaks again (deliberate trade-off vs. CBR).
    #[default]
    Adaptive,
}

/// Predefined traffic profile: sets `mode`/`rate_pps`/`burst` correctly in
/// one go so a user doesn't have to work out the throughput-vs-concealment
/// trade-off themselves. The profile WINS; the individual fields below apply
/// only with `custom`. See `effective()` for the exact values per profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficProfile {
    /// Max anti-analysis: CBR, low ceiling (~5 Mbit/s), constant bandwidth 24/7.
    /// For light traffic where invisibility outweighs speed.
    Stealth,
    /// Adaptive, generous ceiling (~115 Mbit/s), SILENT at rest. Timing hidden
    /// during use; good general VPN experience. Opt-in for timing resistance.
    Balanced,
    /// Max speed with timing pacing: adaptive, high ceiling (~460 Mbit/s).
    /// For those who put speed above maximal concealment but still want cover.
    Throughput,
    /// DEFAULT: NO timing shaping (pacer off). Native timing and speed — the
    /// WireGuard-comparable profile (packet-shape obfuscation via [obfuscation]
    /// stays on). No protection against timing/burst analysis; choose
    /// `balanced`/`stealth` if you want that trade-off the other way.
    #[default]
    Off,
    /// Use the individual `enabled`/`mode`/`rate_pps`/`burst` fields below.
    Custom,
}

impl TrafficProfile {
    /// All profiles in fixed order — for UI selection lists (client GUI).
    pub const ALL: [TrafficProfile; 5] = [
        TrafficProfile::Stealth,
        TrafficProfile::Balanced,
        TrafficProfile::Throughput,
        TrafficProfile::Off,
        TrafficProfile::Custom,
    ];
}

impl std::fmt::Display for TrafficProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TrafficProfile::Stealth => "stealth",
            TrafficProfile::Balanced => "balanced",
            TrafficProfile::Throughput => "throughput",
            TrafficProfile::Off => "off",
            TrafficProfile::Custom => "custom",
        })
    }
}

/// The final, resolved traffic parameters after the profile has been
/// applied. This is what the data path (`tunnel_loops`) actually uses.
#[derive(Debug, Clone, Copy)]
pub struct EffectiveTraffic {
    pub enabled: bool,
    pub mode: TrafficMode,
    pub rate_pps: u32,
    pub burst: u16,
    pub cooldown_ms: u64,
}

/// `[traffic]` section: constant-rate pacing + cover traffic against timing
/// analysis. Choose a `profile` (default `off`); only with `profile = "custom"`
/// do the individual `mode`/`rate_pps`/`burst` fields apply. The effective rate
/// (`rate_pps` × `burst`) is BOTH the constant bandwidth (CBR) AND the
/// throughput ceiling.
#[derive(Debug, Clone, Deserialize)]
pub struct TrafficConfig {
    /// Predefined profile; default `off`. Wins over the individual fields
    /// unless set to `custom`.
    #[serde(default)]
    pub profile: TrafficProfile,
    #[serde(default = "default_traffic_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub mode: TrafficMode,
    /// Emission slots per second (the ticker's tempo).
    #[serde(default = "default_rate_pps")]
    pub rate_pps: u32,
    /// Packets per slot (token-bucket depth). Constant rate = rate_pps × burst.
    #[serde(default = "default_burst")]
    pub burst: u16,
    /// Adaptive: how long cover keeps running after the last real packet (ms).
    #[serde(default = "default_cooldown_ms")]
    pub cooldown_ms: u64,
}

impl Default for TrafficConfig {
    fn default() -> Self {
        Self {
            profile: TrafficProfile::default(),
            enabled: default_traffic_enabled(),
            mode: TrafficMode::default(),
            rate_pps: default_rate_pps(),
            burst: default_burst(),
            cooldown_ms: default_cooldown_ms(),
        }
    }
}

impl TrafficConfig {
    /// Resolve the profile into concrete parameters. The preset profiles
    /// ignore the individual `enabled`/`mode`/`rate_pps`/`burst` fields
    /// (except `cooldown_ms`); only `custom` uses them directly.
    pub fn effective(&self) -> EffectiveTraffic {
        use TrafficProfile::*;
        let cd = self.cooldown_ms;
        match self.profile {
            // 256×2 = 512 pps × ~1232 B ≈ 5 Mbit/s, constant.
            Stealth => EffectiveTraffic {
                enabled: true,
                mode: TrafficMode::Cbr,
                rate_pps: 256,
                burst: 2,
                cooldown_ms: cd,
            },
            // 3000×4 = 12k pps × ~1232 B ≈ 115 Mbit/s, only during activity.
            Balanced => EffectiveTraffic {
                enabled: true,
                mode: TrafficMode::Adaptive,
                rate_pps: 3000,
                burst: 4,
                cooldown_ms: cd,
            },
            // 6000×8 = 48k pps × ~1232 B ≈ 460 Mbit/s, only during activity.
            Throughput => EffectiveTraffic {
                enabled: true,
                mode: TrafficMode::Adaptive,
                rate_pps: 6000,
                burst: 8,
                cooldown_ms: cd,
            },
            // Pacer off — WireGuard-comparable (native timing/speed).
            Off => EffectiveTraffic {
                enabled: false,
                mode: self.mode,
                rate_pps: self.rate_pps,
                burst: self.burst,
                cooldown_ms: cd,
            },
            // Fully manual.
            Custom => EffectiveTraffic {
                enabled: self.enabled,
                mode: self.mode,
                rate_pps: self.rate_pps,
                burst: self.burst,
                cooldown_ms: cd,
            },
        }
    }
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
    // MTU-safe for the obfuscated data path: packet + obf overhead must fit
    // in one ≤1280-byte datagram (see SAFE_TUN_MTU in validate). Like
    // WireGuard (tunnel MTU = path − overhead) we don't send larger than fits.
    1200
}
fn default_linger() -> u64 {
    200
}
fn default_obf_enabled() -> bool {
    true
}
fn default_hs_obf_enabled() -> bool {
    true
}
fn default_traffic_enabled() -> bool {
    true
}
fn default_rate_pps() -> u32 {
    256
}
fn default_burst() -> u16 {
    2
}
fn default_cooldown_ms() -> u64 {
    500
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
        // ML-DSA is optional, but the two fields belong together: a half
        // configuration (only secret or only peer-pub) is almost certainly a
        // mistake and would silently fall back to Ed25519 only.
        match (
            &self.identity.mldsa_secret_hex,
            &self.identity.peer_mldsa_pub_hex,
        ) {
            (Some(_), Some(_)) | (None, None) => {
                // Validate that the keys parse if they are present.
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
        // Upper bound for the obfuscated data path: an IP packet + the
        // obf overhead must fit in one MTU-safe datagram (1280), otherwise
        // IP fragments — which breaks the constant size and is itself a
        // fingerprint. 1280 − header(13) − max AEAD tag(32, AEGIS) − inner(3)
        // = 1232. (WireGuard does the same: tunnel MTU never larger than fits.)
        const SAFE_TUN_MTU: u16 = 1232;
        if self.obfuscation.enabled && self.tun.mtu > SAFE_TUN_MTU {
            return Err(ChameleonError::Handshake {
                state: "config".into(),
                msg: format!(
                    "tun.mtu {} exceeds the obfuscation-safe maximum {}: a larger \
                     MTU would fragment the obfuscated data path (breaking the \
                     constant-size property and adding a fingerprint). Lower tun.mtu.",
                    self.tun.mtu, SAFE_TUN_MTU
                ),
            });
        }
        // Optional handshake obfuscation PSK: if set, it must parse and
        // not be absurdly short (too little entropy would weaken the obfuscation).
        if let Some(psk) = self.obfuscation.psk_bytes()? {
            if psk.len() < 16 {
                return Err(ChameleonError::Handshake {
                    state: "config".into(),
                    msg: format!(
                        "obfuscation.psk_hex is only {} bytes; use at least 16",
                        psk.len()
                    ),
                });
            }
        }
        // Handshake obfuscation without data-path obfuscation is pointless and
        // breaks the demux (cleartext data would be dropped as handshake noise).
        if self.obfuscation.handshake && !self.obfuscation.enabled {
            return Err(ChameleonError::Handshake {
                state: "config".into(),
                msg: "obfuscation.handshake requires obfuscation.enabled = true".into(),
            });
        }
        // Traffic shaping (Phase 3): cover packets ride on the obfuscated
        // data path, so it requires obfuscation.enabled; rate/burst must be >= 1.
        // Validate on the EFFECTIVE values (after profile resolution), so a
        // `custom` profile with nonsense values is still caught.
        let eff = self.traffic.effective();
        if eff.enabled {
            if !self.obfuscation.enabled {
                return Err(ChameleonError::Handshake {
                    state: "config".into(),
                    msg: "traffic (profile != off) requires obfuscation.enabled = true".into(),
                });
            }
            if eff.rate_pps < 1 || eff.burst < 1 {
                return Err(ChameleonError::Handshake {
                    state: "config".into(),
                    msg: "traffic.rate_pps and traffic.burst must both be >= 1".into(),
                });
            }
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

/// Decode a hex string of arbitrary (even) length into bytes.
/// Used for ML-DSA keys, which are much larger than 32 bytes.
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

    #[test]
    fn default_traffic_profile_is_off() {
        let t = TrafficConfig::default();
        assert_eq!(t.profile, TrafficProfile::Off);
        // "off" resolves to no pacing (WireGuard-comparable): max speed, payload
        // obfuscation stays on but there is no timing/cover traffic.
        let e = t.effective();
        assert!(!e.enabled);
    }

    #[test]
    fn profiles_resolve_to_expected_params() {
        let eff = |p: TrafficProfile| {
            TrafficConfig {
                profile: p,
                ..Default::default()
            }
            .effective()
        };
        // stealth: CBR, low ceiling.
        let s = eff(TrafficProfile::Stealth);
        assert!(s.enabled && s.mode == TrafficMode::Cbr && s.rate_pps == 256 && s.burst == 2);
        // throughput: adaptive, high ceiling.
        let th = eff(TrafficProfile::Throughput);
        assert!(
            th.enabled && th.mode == TrafficMode::Adaptive && th.rate_pps == 6000 && th.burst == 8
        );
        // off: pacer off (WireGuard-comparable).
        assert!(!eff(TrafficProfile::Off).enabled);
    }

    #[test]
    fn custom_profile_uses_raw_fields() {
        let t = TrafficConfig {
            profile: TrafficProfile::Custom,
            enabled: true,
            mode: TrafficMode::Cbr,
            rate_pps: 1234,
            burst: 7,
            cooldown_ms: 250,
        };
        let e = t.effective();
        assert!(e.enabled && e.mode == TrafficMode::Cbr && e.rate_pps == 1234 && e.burst == 7);
    }

    #[test]
    fn profile_parses_from_toml() {
        let t: TrafficConfig = toml::from_str(r#"profile = "throughput""#).unwrap();
        assert_eq!(t.profile, TrafficProfile::Throughput);
        let off: TrafficConfig = toml::from_str(r#"profile = "off""#).unwrap();
        assert!(!off.effective().enabled);
        // Empty section → default off.
        let empty: TrafficConfig = toml::from_str("").unwrap();
        assert_eq!(empty.profile, TrafficProfile::Off);
    }
}
