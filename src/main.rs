//! Chameleon-PQ — main entry point.
//!
//! ARCHITECTURE OF THE MAIN LOOPS (crystal-clear):
//!
//!  ┌─────────┐   plaintext    ┌──────────────┐  encrypted frame  ┌──────────┐
//!  │   TUN   │ ─────────────► │ CryptoEngine │ ─────────────────► │   UDP    │
//!  │ (kernel)│                │    (CPU)     │                    │  socket  │
//!  │         │ ◄───────────── │              │ ◄───────────────── │          │
//!  └─────────┘   plaintext    └──────────────┘  encrypted frame   └──────────┘
//!
//!  TUN ─► engine.encrypt_batch() ─► (obf wire) ─► socket.send_to()
//!  socket.recv_from() ─► sessions.decrypt_obf()  ─► TUN
//!                         └─(on failure)─► frame.decode() ─► handshake/rekey
//!
//! The data path is obfuscated by default (obf.rs, QUIC-style header-protection):
//! the inbound loop first tries decrypt_obf() and only falls back to the
//! cleartext frame for the (still cleartext) handshake/rekey messages.

use chameleon::config::{AppConfig, Cli, Command, KillSwitchAction};
use chameleon::crypto::{Authenticator, Ed25519Auth, MlDsaAuth};
use chameleon::engine::CryptoEngine;
use chameleon::frame::FrameType;
use chameleon::net::{run_handshake_initiator, run_handshake_responder};
use chameleon::obf::PadPolicy;
use chameleon::session::SessionManager;
use chameleon::tun_iface::TunPair;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;
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
        Command::Init {
            server_addr,
            out_dir,
            bind,
            tun_net,
            mtu,
            split_tunnel,
            kill_switch,
            profile,
            force,
        } => {
            run_init(
                *server_addr,
                out_dir,
                *bind,
                tun_net,
                *mtu,
                *split_tunnel,
                *kill_switch,
                profile,
                *force,
            )?;
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
        // Escape hatch: control the kill switch without a config, so a user
        // stranded offline (client crashed while engaged) can always recover.
        Command::KillSwitch { action } => {
            match action {
                KillSwitchAction::Off => {
                    chameleon::killswitch::KillSwitch::clear();
                    println!("kill switch removed — connectivity restored");
                }
                KillSwitchAction::Status => {
                    let on = chameleon::killswitch::KillSwitch::is_engaged();
                    println!(
                        "kill switch: {}",
                        if on {
                            "ENGAGED (traffic blocked)"
                        } else {
                            "off"
                        }
                    );
                }
            }
            return Ok(());
        }
        _ => {}
    }

    let cfg = AppConfig::load(&cli.config)?;
    if !cfg.obfuscation.enabled {
        warn!(
            "obfuscation.enabled = false: the data path is UNOBFUSCATED and the \
             control frames (KeepAlive/Close/Handshake) are UNAUTHENTICATED. A \
             peer-spoofing or on-path attacker can inject frames. Only use \
             obf-off for debugging on a trusted network (L-7)."
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
    let hs_obf = hs_obf_key_from_cfg(&cfg)?;

    // Serve sequential sessions: after one tunnel ends, listen for the next
    // client instead of exiting. (Concurrent multi-client would need per-peer
    // socket demux — a larger change; this alone removes restart-per-reconnect.)
    //
    // Bind a FRESH socket per session. The tunnel enables UDP_GRO on the socket
    // for throughput, and quinn-udp does not clear it afterwards — so on the
    // re-listen the handshake responder's `recv_from` would read GRO-coalesced
    // super-buffers (several variable-size handshake fragments glued together),
    // which the reassembler cannot decode → the reconnect handshake never
    // completes. A fresh socket starts GRO-clean; the old one is dropped (closed)
    // at the end of each iteration.
    loop {
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        chameleon::udp::enlarge_socket_buffers(&socket);
        info!("server listening on {bind}");
        let (session, peer) =
            match run_handshake_responder(&socket, auth.as_ref(), hs_obf.as_ref()).await {
                Ok(ok) => ok,
                Err(e) => {
                    warn!("handshake failed: {e}; re-listening");
                    continue;
                }
            };
        let session_id = session.session_id;
        info!("session {session_id} established with {peer}");

        let tun = match TunPair::create(&cfg.tun) {
            Ok(t) => t,
            Err(e) => {
                warn!("TUN create failed: {e}; waiting for next client");
                // Best-effort authenticated teardown: without this the peer
                // has already completed a real handshake and believes the
                // session is live, so it would sit out its dead-peer timeout
                // before retrying. Only meaningful with obfuscation on (a
                // cleartext Close is unauthenticated and ignored) — mirrors
                // Client::disconnect()'s Close-before-abort.
                if cfg.obfuscation.enabled {
                    let pad: PadPolicy = cfg.obfuscation.padding.into();
                    if let Ok(wire) = session.seal_obf(FrameType::Close as u8, b"", pad) {
                        let _ = socket.send_to(&wire, peer).await;
                    }
                }
                continue;
            }
        };
        let engine = build_engine(session, &cfg);
        // CLI server: no live re-profiling, but keep a sender alive for the
        // session so the outbound loop's control arm parks instead of erroring.
        let (_traffic_tx, traffic_rx) = watch::channel(cfg.traffic.effective());
        chameleon::tunnel_loops::run_tunnel_loops(
            socket.clone(),
            engine,
            tun,
            peer,
            chameleon::tunnel_loops::TunnelParams::from_config(&cfg),
            auth.clone(),
            hs_obf,
            Arc::new(chameleon::tunnel_loops::TunnelStats::default()),
            traffic_rx,
        )
        .await;
        info!("session {session_id} ended — listening for next client");
    }
}

// ── Client ───────────────────────────────────────────────────────────────────

async fn run_client(
    cfg: AppConfig,
    server: SocketAddr,
    auth: Arc<dyn Authenticator>,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    chameleon::udp::enlarge_socket_buffers(&socket);
    info!("connecting to {server}");

    let hs_obf = hs_obf_key_from_cfg(&cfg)?;
    let session = run_handshake_initiator(&socket, server, auth.as_ref(), hs_obf.as_ref()).await?;
    info!("session {} established with {server}", session.session_id);

    let tun = TunPair::create(&cfg.tun)?;
    let engine = build_engine(session, &cfg);
    // CLI client: keep a traffic sender alive for the session (no live UI control).
    let (_traffic_tx, traffic_rx) = watch::channel(cfg.traffic.effective());
    chameleon::tunnel_loops::run_tunnel_loops(
        socket,
        engine,
        tun,
        server,
        chameleon::tunnel_loops::TunnelParams::from_config(&cfg),
        auth.clone(),
        hs_obf,
        Arc::new(chameleon::tunnel_loops::TunnelStats::default()),
        traffic_rx,
    )
    .await;
    Ok(())
}

// ── Shared tunnel loops ──────────────────────────────────────────────────────

fn build_engine(session: chameleon::session::Session, cfg: &AppConfig) -> Arc<CryptoEngine> {
    let mgr = Arc::new(SessionManager::new(session));
    let pad_policy: PadPolicy = cfg.obfuscation.padding.into();
    Arc::new(CryptoEngine::new(mgr, cfg.obfuscation.enabled, pad_policy))
}

/// Initialise the global rayon thread pool for parallel crypto (Phase C).
/// `workers = 0` => automatically all logical cores. Once per process; a
/// second call (e.g. rayon already lazily initialised) fails silently.
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

/// Derive the static handshake-obfuscation key from the config (Phase 2).
/// `None` if handshake obfuscation is off; then the handshake falls back to the
/// classic cleartext frame. The key comes from the pre-shared Ed25519 pubkeys
/// (own derived from the seed, peer from config) or, if set, from psk_hex.
fn hs_obf_key_from_cfg(cfg: &AppConfig) -> anyhow::Result<Option<[u8; 32]>> {
    if !cfg.obfuscation.handshake {
        return Ok(None);
    }
    let own_pub = Ed25519Auth::derive_public(&cfg.identity.seed_bytes()?[..]);
    let peer_pub = cfg.identity.peer_pub_bytes()?;
    let psk = cfg.obfuscation.psk_bytes()?;
    if psk.is_none() {
        warn!(
            "obfuscation.psk_hex is not set: the handshake obfuscation key is \
             derived from the PUBLIC Ed25519 keys. An adversary who knows those \
             pubkeys can de-obfuscate the handshake and forge valid obf envelopes \
             — that gives no DoS gating against such adversaries (expensive \
             rekey crypto/amplification). Set obfuscation.psk_hex (>= 16 bytes) on \
             BOTH sides for a truly secret obfuscation key."
        );
    }
    Ok(Some(chameleon::hsobf::derive_hs_obf_key(
        &own_pub,
        &peer_pub,
        psk.as_deref(),
    )))
}

/// Build the peer authenticator from the config. With ML-DSA keys it becomes
/// a HYBRID scheme (Ed25519 + ML-DSA): the handshake signature is valid only
/// once both legs validate, so the authentication becomes quantum-resistant
/// without giving up the classical guarantee. Without ML-DSA keys it falls
/// back to Ed25519-only (classical).
fn build_auth(cfg: &AppConfig) -> anyhow::Result<Arc<dyn Authenticator>> {
    // The real construction lives in the lib (chameleon::client), so the binary
    // and every other client share the same auth logic. Only the logging here.
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

    // Ed25519 (classical leg): seed via OsRng, then the public key from it.
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let ed_pub_hex = hex(kp.public_key().as_ref());
    let ed_seed_hex = hex(&seed);

    // ML-DSA-65 (post-quantum leg): full keypair (no seed derivation).
    let (mldsa_pub, mldsa_sk) = MlDsaAuth::generate();
    let mldsa_pub_hex = hex(&mldsa_pub);
    let mldsa_sk_hex = hex(&mldsa_sk);

    println!("# ── Add to config.toml on THIS node (keep SECRET) ──");
    println!("[identity]");
    println!("ed25519_seed_hex   = \"{ed_seed_hex}\"");
    println!("mldsa_secret_hex   = \"{mldsa_sk_hex}\"");
    println!();
    println!("# ── Give these two public keys to the PEER (out-of-band) ──");
    println!("# (in the peer's config under [identity]:)");
    println!("peer_ed25519_pub_hex = \"{ed_pub_hex}\"");
    println!("peer_mldsa_pub_hex   = \"{mldsa_pub_hex}\"");
    println!();
    println!("# Omit the mldsa_* fields on BOTH sides for classic (Ed25519-only) auth.");
}

// ── Guided setup (init) ──────────────────────────────────────────────────────

/// Generate a matched server + client config pair and write both files.
#[allow(clippy::too_many_arguments)]
fn run_init(
    server_addr: Option<SocketAddr>,
    out_dir: &std::path::Path,
    bind: SocketAddr,
    tun_net: &str,
    mtu: u16,
    split_tunnel: bool,
    kill_switch: bool,
    profile: &str,
    force: bool,
) -> anyhow::Result<()> {
    use chameleon::setup::{init_pair, parse_tun_net, PairParams};

    let full_tunnel = !split_tunnel;
    if kill_switch && !full_tunnel {
        anyhow::bail!("--kill-switch requires full-tunnel; drop --split-tunnel");
    }
    const PROFILES: [&str; 5] = ["off", "balanced", "stealth", "throughput", "custom"];
    if !PROFILES.contains(&profile) {
        anyhow::bail!(
            "--profile '{profile}' must be one of: {}",
            PROFILES.join(", ")
        );
    }
    let tun_net = parse_tun_net(tun_net)?;

    // The server address is the one thing we cannot guess — prompt if missing.
    let server_addr = match server_addr {
        Some(a) => a,
        None => prompt_server_addr()?,
    };

    let params = PairParams {
        server_addr,
        bind_addr: bind,
        tun_net,
        mtu,
        full_tunnel,
        kill_switch,
        profile: profile.to_string(),
    };
    let (server_toml, client_toml) = init_pair(&params);

    // Self-check: a generated config must parse AND pass full validation before
    // we write it (catches any template mistake up front).
    AppConfig::from_toml_str(&server_toml)
        .map_err(|e| anyhow::anyhow!("generated server config failed validation: {e}"))?;
    AppConfig::from_toml_str(&client_toml)
        .map_err(|e| anyhow::anyhow!("generated client config failed validation: {e}"))?;

    let server_path = out_dir.join("server-config.toml");
    let client_path = out_dir.join("client-config.toml");
    write_secret(&server_path, &server_toml, force)?;
    write_secret(&client_path, &client_toml, force)?;

    println!("✔ Generated a matched key pair (Ed25519 + ML-DSA-65) and a shared obfuscation PSK.");
    println!("✔ Both configs validated OK. Wrote (mode 0600 on Unix — keep them SECRET):");
    println!("    {}   → run on the SERVER", server_path.display());
    println!("    {}   → run on the CLIENT", client_path.display());
    println!();
    println!("Next steps:");
    println!(
        "  SERVER:  chameleon-pq --config {} server",
        server_path.display()
    );
    if full_tunnel {
        println!("           # full-tunnel internet breakout also needs, once (Linux):");
        println!("           sudo sysctl -w net.ipv4.ip_forward=1");
        println!("           sudo nft add table ip nat");
        println!(
            "           sudo nft 'add chain ip nat post {{ type nat hook postrouting priority 100; }}'"
        );
        println!("           sudo nft add rule ip nat post oifname != \"lo\" masquerade");
    }
    println!(
        "  CLIENT:  chameleon-pq --config {} client",
        client_path.display()
    );
    println!(
        "           # or load {} in the desktop GUI",
        client_path.display()
    );
    Ok(())
}

/// Prompt for the server address on stdin (`init` without `--server-addr`).
fn prompt_server_addr() -> anyhow::Result<SocketAddr> {
    use std::io::Write;
    print!("Server address the client connects to (e.g. 203.0.113.5:51820): ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    line.trim().parse::<SocketAddr>().map_err(|_| {
        anyhow::anyhow!(
            "not a valid host:port — re-run with --server-addr <ip:port> (a numeric IP, not a hostname)"
        )
    })
}

/// Write a secrets file, refusing to clobber an existing one unless `force`.
/// Created with 0600 permissions on Unix so private keys aren't world-readable.
fn write_secret(path: &std::path::Path, contents: &str, force: bool) -> anyhow::Result<()> {
    use std::io::Write;
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists — pass --force to overwrite",
            path.display()
        );
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", path.display()))?;
    f.write_all(contents.as_bytes())?;
    Ok(())
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
