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
use zeroize::Zeroizing;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name    = "chameleon-pq",
    version = env!("CARGO_PKG_VERSION"),
    about   = "Hybrid post-quantum VPN (ML-KEM-768 + X25519 + Ed25519)",
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
    pub fn seed_bytes(&self) -> Result<Zeroizing<[u8; 32]>> {
        // Zeroizing: de private seed wordt gewist zodra de caller 'm laat vallen,
        // zodat hij niet in een core dump/swap achterblijft.
        Ok(Zeroizing::new(hex_to_32(
            &self.ed25519_seed_hex,
            "identity.ed25519_seed_hex",
        )?))
    }
    pub fn peer_pub_bytes(&self) -> Result<[u8; 32]> {
        hex_to_32(&self.peer_ed25519_pub_hex, "identity.peer_ed25519_pub_hex")
    }

    /// Eigen ML-DSA secret key als bytes, indien geconfigureerd. Zeroizing zodat
    /// de secret key bij drop uit het geheugen wordt gewist.
    pub fn mldsa_secret_bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.mldsa_secret_hex
            .as_deref()
            .map(|s| hex_to_vec(s, "identity.mldsa_secret_hex").map(Zeroizing::new))
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_linger")]
    pub batch_linger_us: u64,
    /// Aantal crypto-worker-threads voor parallelle seal/open (Fase C).
    /// 0 = automatisch = alle logische cores. Verlaag om cores vrij te houden
    /// voor de reactor/TUN. Alleen van invloed op het snelle (unpaced) pad.
    #[serde(default)]
    pub workers: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            batch_linger_us: default_linger(),
            workers: 0,
        }
    }
}

// ── Obfuscatie (verkeersanalyse-weerstand op het datapad) ────────────────────

/// Padding-beleid voor het geobfusceerde datapad. Verbergt de pakketgrootte
/// (die anders exact de plaintext-lengte lekt) ten koste van bandbreedte.
/// Wordt afgebeeld op `obf::PadPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaddingPolicy {
    /// Geen padding — laagste overhead, grootte lekt de lengte.
    Off,
    /// Pad naar grootteklassen — verbergt de exacte lengte, matige overhead.
    #[default]
    Bucketed,
    /// Pad elk pakket naar de MTU-veilige maximumgrootte — beste obfuscatie,
    /// hoogste bandbreedte-kost.
    Full,
}

/// `[obfuscation]`-sectie. Standaard AAN met bucketed padding (clean break t.o.v.
/// 0.1.0; zie ook de PROTO_VERSION-bump). Zet `enabled = false` voor het
/// klassieke, niet-geobfusceerde datapad-frame (bv. voor debugging).
#[derive(Debug, Clone, Deserialize)]
pub struct ObfuscationConfig {
    #[serde(default = "default_obf_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub padding: PaddingPolicy,
    /// Obfusceer óók de handshake-envelope (Fase 2, hsobf.rs). Standaard aan;
    /// wijzigt het wireformat, dus beide kanten moeten dit aan hebben staan.
    #[serde(default = "default_hs_obf_enabled")]
    pub handshake: bool,
    /// Optioneel gedeeld obfuscatie-geheim (hex) voor de handshake. Afwezig =>
    /// de handshake-obfuscatiesleutel wordt afgeleid uit de voorgedeelde
    /// Ed25519-pubkeys (nul config). Aanwezig => sterker (een tegenstander die
    /// alleen de pubkeys heeft kan dan niet de-obfusceren). Op beide kanten gelijk.
    #[serde(default)]
    pub psk_hex: Option<String>,
}

impl ObfuscationConfig {
    /// Het optionele handshake-obfuscatie-geheim als bytes, indien gezet.
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

// ── Traffic shaping (timing-/cover-traffic-obfuscatie, Fase 3) ───────────────

/// Vorm-modus voor de constant-rate pacer. Afgebeeld op `pacer::ShapeMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficMode {
    /// Constant bit-rate: altijd op tempo, ook idle. Sterkste timing-verberging,
    /// maar constante bandbreedtekost 24/7 (ook wanneer er niets stroomt).
    Cbr,
    /// Adaptief: pace tijdens activiteit + cooldown, stil wanneer echt idle.
    /// De STANDAARD: geen bandbreedte in rust, wél burst-verberging tijdens
    /// activiteit. Grof actief-vs-idle lekt weer (bewuste afweging vs. CBR).
    #[default]
    Adaptive,
}

/// `[traffic]`-sectie: constant-rate pacing + cover-traffic tegen timing-analyse.
/// Standaard AAN met CBR. Dit voegt cover-pakketten toe (constante bandbreedte)
/// en vertraagt echte pakketten tot slot-grenzen. De geconfigureerde rate
/// (`rate_pps` × `burst`) is ZOWEL de constante bandbreedte ALS het
/// doorvoerplafond — stem 'm af op je link.
#[derive(Debug, Clone, Deserialize)]
pub struct TrafficConfig {
    #[serde(default = "default_traffic_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub mode: TrafficMode,
    /// Emissie-slots per seconde (het tempo van de ticker).
    #[serde(default = "default_rate_pps")]
    pub rate_pps: u32,
    /// Pakketten per slot (token-bucket-diepte). Constante rate = rate_pps × burst.
    #[serde(default = "default_burst")]
    pub burst: u16,
    /// Adaptive: hoelang na het laatste echte pakket cover blijft doorlopen (ms).
    #[serde(default = "default_cooldown_ms")]
    pub cooldown_ms: u64,
}

impl Default for TrafficConfig {
    fn default() -> Self {
        Self {
            enabled: default_traffic_enabled(),
            mode: TrafficMode::default(),
            rate_pps: default_rate_pps(),
            burst: default_burst(),
            cooldown_ms: default_cooldown_ms(),
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
    // MTU-veilig voor het geobfusceerde datapad: pakket + obf-overhead moet in
    // één ≤1280-byte datagram passen (zie SAFE_TUN_MTU in validate). Net als
    // WireGuard (tunnel-MTU = pad − overhead) sturen we niet groter dan past.
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
        // Bovengrens voor het geobfusceerde datapad: een IP-pakket + de
        // obf-overhead moet in één MTU-veilig datagram (1280) passen, anders
        // fragmenteert IP — dat breekt de constante grootte én is zelf een
        // vingerafdruk. 1280 − header(13) − max AEAD-tag(32, AEGIS) − inner(3)
        // = 1232. (WireGuard doet hetzelfde: tunnel-MTU nooit groter dan past.)
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
        // Optioneel handshake-obfuscatie-PSK: als gezet, moet hij parseren en
        // niet absurd kort zijn (te weinig entropie zou de obfuscatie verzwakken).
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
        // Handshake-obfuscatie zonder datapad-obfuscatie is zinloos én breekt de
        // demux (cleartext data zou als handshake-ruis worden gedropt).
        if self.obfuscation.handshake && !self.obfuscation.enabled {
            return Err(ChameleonError::Handshake {
                state: "config".into(),
                msg: "obfuscation.handshake requires obfuscation.enabled = true".into(),
            });
        }
        // Traffic shaping (Fase 3): cover-pakketten rijden op het geobfusceerde
        // datapad, dus vereist obfuscation.enabled; rate/burst moeten >= 1.
        if self.traffic.enabled {
            if !self.obfuscation.enabled {
                return Err(ChameleonError::Handshake {
                    state: "config".into(),
                    msg: "traffic.enabled requires obfuscation.enabled = true".into(),
                });
            }
            if self.traffic.rate_pps < 1 || self.traffic.burst < 1 {
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
