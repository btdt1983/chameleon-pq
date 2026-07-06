//! Chameleon-PQ — main entry point.
//!
//! ARCHITECTUUR VAN DE MAIN LOOPS (kristalhelder):
//!
//!  ┌─────────┐   plaintext    ┌──────────────┐  encrypted frame  ┌──────────┐
//!  │   TUN   │ ─────────────► │ CryptoEngine │ ─────────────────► │   UDP    │
//!  │ (kernel)│                │    (CPU)     │                    │  socket  │
//!  │         │ ◄───────────── │              │ ◄───────────────── │          │
//!  └─────────┘   plaintext    └──────────────┘  encrypted frame   └──────────┘
//!
//!  TUN ─► engine.encrypt_batch() ─► (obf wire) ─► socket.send_to()
//!  socket.recv_from() ─► sessions.decrypt_obf()  ─► TUN
//!                         └─(bij mislukking)─► frame.decode() ─► handshake/rekey
//!
//! Het datapad is standaard geobfusceerd (obf.rs, QUIC-stijl header-protection):
//! de inbound-loop probeert eerst decrypt_obf() en valt alleen terug op het
//! cleartext-frame voor de (nog cleartext) handshake/rekey-berichten.

use chameleon::config::{AppConfig, Cli, Command};
use chameleon::crypto::{Authenticator, Ed25519Auth, MlDsaAuth};
use chameleon::engine::CryptoEngine;
use chameleon::net::{run_handshake_initiator, run_handshake_responder};
use chameleon::obf::PadPolicy;
use chameleon::session::SessionManager;
use chameleon::tun_iface::TunPair;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    match &cli.command {
        Command::Keygen => {
            run_keygen();
            return Ok(());
        }
        Command::Check => {
            let cfg = AppConfig::load(&cli.config)?;
            println!(
                "Config OK — bind={} tun={}",
                cfg.network.bind_addr, cfg.tun.name
            );
            return Ok(());
        }
        _ => {}
    }

    let cfg = AppConfig::load(&cli.config)?;
    if !cfg.obfuscation.enabled {
        warn!(
            "obfuscation.enabled = false: het datapad is ONGEOBFUSCEERD én de \
             control-frames (KeepAlive/Close/Handshake) zijn ONGEAUTHENTICEERD. Een \
             peer-spoofende of on-path aanvaller kan frames injecteren. Gebruik \
             obf-off alleen voor debugging op een vertrouwd netwerk (L-7)."
        );
    }
    let auth = build_auth(&cfg)?;
    init_rayon_pool(&cfg);

    match &cli.command {
        Command::Server { bind } => {
            let addr = bind.unwrap_or(cfg.network.bind_addr);
            run_server(cfg, addr, auth).await?;
        }
        Command::Client { server } => {
            let addr = server.or(cfg.network.server_addr).ok_or_else(|| {
                anyhow::anyhow!(
                    "server address required (--server or network.server_addr in config)"
                )
            })?;
            run_client(cfg, addr, auth).await?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

// ── Server ───────────────────────────────────────────────────────────────────

async fn run_server(
    cfg: AppConfig,
    bind: SocketAddr,
    auth: Arc<dyn Authenticator>,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    info!("server listening on {bind}");

    let hs_obf = hs_obf_key_from_cfg(&cfg)?;
    let (session, peer) = run_handshake_responder(&socket, auth.as_ref(), hs_obf.as_ref()).await?;
    info!("session {} established with {peer}", session.session_id);

    let tun = TunPair::create(&cfg.tun)?;
    let engine = build_engine(session, &cfg);
    chameleon::tunnel_loops::run_tunnel_loops(
        socket,
        engine,
        tun,
        peer,
        chameleon::tunnel_loops::TunnelParams::from_config(&cfg),
        auth.clone(),
        hs_obf,
        Arc::new(chameleon::tunnel_loops::TunnelStats::default()),
    )
    .await;
    Ok(())
}

// ── Client ───────────────────────────────────────────────────────────────────

async fn run_client(
    cfg: AppConfig,
    server: SocketAddr,
    auth: Arc<dyn Authenticator>,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    info!("connecting to {server}");

    let hs_obf = hs_obf_key_from_cfg(&cfg)?;
    let session = run_handshake_initiator(&socket, server, auth.as_ref(), hs_obf.as_ref()).await?;
    info!("session {} established with {server}", session.session_id);

    let tun = TunPair::create(&cfg.tun)?;
    let engine = build_engine(session, &cfg);
    chameleon::tunnel_loops::run_tunnel_loops(
        socket,
        engine,
        tun,
        server,
        chameleon::tunnel_loops::TunnelParams::from_config(&cfg),
        auth.clone(),
        hs_obf,
        Arc::new(chameleon::tunnel_loops::TunnelStats::default()),
    )
    .await;
    Ok(())
}

// ── Gedeelde tunnel-loops ────────────────────────────────────────────────────

fn build_engine(session: chameleon::session::Session, cfg: &AppConfig) -> Arc<CryptoEngine> {
    let mgr = Arc::new(SessionManager::new(session));
    let pad_policy: PadPolicy = cfg.obfuscation.padding.into();
    Arc::new(CryptoEngine::new(mgr, cfg.obfuscation.enabled, pad_policy))
}

/// Initialiseer de globale rayon-thread-pool voor parallelle crypto (Fase C).
/// `workers = 0` => automatisch alle logische cores. Eenmalig per proces; een
/// tweede aanroep (bv. rayon al lazily geïnitialiseerd) faalt stil.
fn init_rayon_pool(cfg: &AppConfig) {
    let workers = if cfg.engine.workers > 0 {
        cfg.engine.workers
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    };
    match rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build_global()
    {
        Ok(()) => info!("crypto worker pool: {workers} thread(s)"),
        Err(e) => warn!("rayon pool already initialised ({e}); using existing"),
    }
}

/// Leid de statische handshake-obfuscatiesleutel af uit de config (Fase 2).
/// `None` als handshake-obfuscatie uit staat; dan valt de handshake terug op het
/// klassieke cleartext-frame. De sleutel komt uit de voorgedeelde Ed25519-pubkeys
/// (eigen afgeleid uit de seed, peer uit config) of, indien gezet, uit psk_hex.
fn hs_obf_key_from_cfg(cfg: &AppConfig) -> anyhow::Result<Option<[u8; 32]>> {
    if !cfg.obfuscation.handshake {
        return Ok(None);
    }
    let own_pub = Ed25519Auth::derive_public(&cfg.identity.seed_bytes()?[..]);
    let peer_pub = cfg.identity.peer_pub_bytes()?;
    let psk = cfg.obfuscation.psk_bytes()?;
    if psk.is_none() {
        warn!(
            "obfuscation.psk_hex is niet gezet: de handshake-obfuscatiesleutel wordt \
             afgeleid uit de PUBLIEKE Ed25519-sleutels. Een tegenstander die die \
             pubkeys kent kan de handshake de-obfusceren én geldige obf-envelopes \
             vervalsen — dat geeft geen DoS-gating tegen zulke tegenstanders (dure \
             rekey-crypto/amplificatie). Zet obfuscation.psk_hex (>= 16 bytes) aan \
             BEIDE kanten voor een echt geheime obfuscatiesleutel."
        );
    }
    Ok(Some(chameleon::hsobf::derive_hs_obf_key(
        &own_pub,
        &peer_pub,
        psk.as_deref(),
    )))
}

/// Bouw de peer-authenticator uit de config. Met ML-DSA-sleutels wordt het
/// een HYBRIDE schema (Ed25519 + ML-DSA): de handshake-handtekening geldt pas
/// als beide legs valideren, zodat de authenticatie kwantum-bestendig wordt
/// zonder de klassieke garantie op te geven. Zonder ML-DSA-sleutels valt het
/// terug op Ed25519-only (klassiek).
fn build_auth(cfg: &AppConfig) -> anyhow::Result<Arc<dyn Authenticator>> {
    // De feitelijke opbouw staat in de lib (chameleon::client), zodat de binary
    // en elke andere client dezelfde auth-logica delen. Hier alleen de logging.
    let auth = chameleon::client::build_auth(cfg)?;
    if cfg.identity.has_mldsa() {
        info!("peer-auth: hybrid Ed25519 + ML-DSA-65 (post-quantum signatures)");
    } else {
        warn!(
            "peer-auth: Ed25519 only — no ML-DSA keys configured (classical, \
               not post-quantum). Run `keygen` and set the mldsa_* fields for hybrid auth."
        );
    }
    Ok(auth)
}

// ── Keygen ───────────────────────────────────────────────────────────────────

fn run_keygen() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };

    // Ed25519 (klassieke leg): seed via OsRng, daaruit de publieke sleutel.
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let ed_pub_hex = hex(kp.public_key().as_ref());
    let ed_seed_hex = hex(&seed);

    // ML-DSA-65 (post-quantum leg): vol keypair (geen seed-afleiding).
    let (mldsa_pub, mldsa_sk) = MlDsaAuth::generate();
    let mldsa_pub_hex = hex(&mldsa_pub);
    let mldsa_sk_hex = hex(&mldsa_sk);

    println!("# ── Voeg toe aan config.toml van DEZE node (GEHEIM houden) ──");
    println!("[identity]");
    println!("ed25519_seed_hex   = \"{ed_seed_hex}\"");
    println!("mldsa_secret_hex   = \"{mldsa_sk_hex}\"");
    println!();
    println!("# ── Geef deze twee publieke sleutels aan de PEER (out-of-band) ──");
    println!("# (in de config van de peer onder [identity]:)");
    println!("peer_ed25519_pub_hex = \"{ed_pub_hex}\"");
    println!("peer_mldsa_pub_hex   = \"{mldsa_pub_hex}\"");
    println!();
    println!("# Laat de mldsa_*-velden weg aan BEIDE kanten voor klassieke (Ed25519-only) auth.");
}

// ── Logging init ─────────────────────────────────────────────────────────────

fn init_logging(verbosity: u8) {
    use tracing_subscriber::{fmt, EnvFilter};
    let level = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let _ = fmt()
        .with_env_filter(EnvFilter::new(level))
        .with_target(true)
        .with_thread_ids(false)
        .try_init();
}
