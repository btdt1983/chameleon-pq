//! `chameleon-pq setup` — guided server installation on Linux.
//!
//! `init` only writes a config pair. `setup` takes a freshly installed package
//! (or bare binary) to a RUNNING full-tunnel server: service user, config,
//! IP forwarding, firewall/NAT, MSS clamp and the systemd units — each step
//! shown first and confirmed (`--yes` to skip, `--dry-run` to only look).
//!
//! Every step is idempotent: it first checks whether its end state already
//! holds and skips if so, so re-running `setup` after a partial failure (or on
//! an existing install) is safe. An existing server config is KEPT unless
//! `--force` is given — regenerating it invalidates every client config.
//!
//! No shell is ever involved: external tools run via `Command` with an
//! argument vector, and every interpolated value is a validated number/IP or a
//! compile-time constant.

use crate::config::AppConfig;
use crate::setup::{init_pair, parse_tun_net, PairParams};
use anyhow::{anyhow, bail, Context, Result};
use std::io::{IsTerminal, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Unprivileged account the service runs as (created by the package, or by
/// `setup` when installed from a bare binary).
pub const SERVICE_USER: &str = "chameleon-pq";
/// Interface name baked into generated server configs (`setup::build_pair`).
const DEFAULT_CONFIG_DIR: &str = "/etc/chameleon-pq";
const TUN_NAME: &str = "chameleon0";
const NFT_TABLE: &str = "chameleon_pq";
const MAIN_UNIT: &str = "chameleon-pq.service";
const NFT_UNIT: &str = "chameleon-pq-nft.service";

/// Everything `setup` can be told on the command line.
pub struct SetupArgs {
    pub server_addr: Option<SocketAddr>,
    pub bind: SocketAddr,
    pub tun_net: String,
    pub mtu: u16,
    pub split_tunnel: bool,
    pub kill_switch: bool,
    pub profile: String,
    pub config_dir: PathBuf,
    pub client_out: PathBuf,
    pub yes: bool,
    pub dry_run: bool,
    pub force: bool,
    pub no_firewall: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Firewall {
    Firewalld,
    Ufw,
    /// Nothing active — we own NAT via our own nftables table.
    Nft,
}

/// What a generated or existing server config means for the system rules.
struct ServerFacts {
    port: u16,
    /// e.g. `10.99.0.0/24`
    tun_cidr: String,
}

struct Step {
    title: String,
    detail: Vec<String>,
    done: Box<dyn Fn() -> bool>,
    apply: Box<dyn FnOnce() -> Result<()>>,
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub fn run(args: SetupArgs) -> Result<()> {
    if !args.dry_run && capture("id", &["-u"])?.trim() != "0" {
        bail!("setup changes system configuration — run it as root (sudo chameleon-pq setup)");
    }
    if !args.dry_run && args.config_dir != Path::new(DEFAULT_CONFIG_DIR) {
        bail!(
            "--config-dir other than {DEFAULT_CONFIG_DIR} is only for --dry-run: the systemd \
             units read their files from there"
        );
    }
    if args.bind.port() < 1024 {
        bail!(
            "--bind port {} is privileged; the service runs unprivileged. Use a port >= 1024 \
             (or grant CAP_NET_BIND_SERVICE in the unit yourself)",
            args.bind.port()
        );
    }
    let interactive = std::io::stdin().is_terminal() && !args.yes;
    let (egress_dev, egress_src) = detect_egress();
    let firewall = if args.no_firewall {
        None
    } else {
        Some(detect_firewall())
    };

    let server_cfg_path = args.config_dir.join("server-config.toml");
    let client_cfg_path = args.client_out.join("chameleon-pq-client.toml");
    let keep_existing = server_cfg_path.exists() && !args.force;
    // Fail before anything is written, not halfway through.
    if !keep_existing && client_cfg_path.exists() && !args.force {
        bail!(
            "{} already exists — pass --force to overwrite it, or pick another --client-out",
            client_cfg_path.display()
        );
    }

    // ── Gather the choices (only needed when we are generating) ──────────────
    let (server_toml, client_toml, facts) = if keep_existing {
        let cfg = AppConfig::load(&server_cfg_path)
            .with_context(|| format!("existing {} is invalid", server_cfg_path.display()))?;
        println!(
            "• Keeping the existing server config {} (use --force to regenerate — that \
             invalidates all client configs).",
            server_cfg_path.display()
        );
        let facts = ServerFacts {
            port: cfg.network.bind_addr.port(),
            tun_cidr: cidr_of(&cfg.tun.address, &cfg.tun.netmask)?,
        };
        (None, None, facts)
    } else {
        let server_addr = match args.server_addr {
            Some(a) => a,
            None if interactive => prompt_server_addr(egress_src, args.bind.port())?,
            None => bail!("--server-addr <public-ip:port> is required in non-interactive mode"),
        };
        let tun_net = if interactive && args.tun_net == "10.99.0" {
            prompt_tun_net(&args.tun_net)?
        } else {
            args.tun_net.clone()
        };
        let net = parse_tun_net(&tun_net)?;
        if let Some(clash) = route_clash(&tun_net) {
            println!("! Warning: {tun_net}.0/24 overlaps an existing route:\n    {clash}");
            if interactive && !confirm("Continue anyway?", false)? {
                bail!("aborted — re-run with --tun-net <other /24 base>");
            }
        }
        let params = PairParams {
            server_addr,
            bind_addr: args.bind,
            tun_net: net,
            mtu: args.mtu,
            full_tunnel: !args.split_tunnel,
            kill_switch: args.kill_switch,
            profile: args.profile.clone(),
        };
        let (s, c) = init_pair(&params);
        AppConfig::from_toml_str(&s)
            .map_err(|e| anyhow!("generated server config invalid: {e}"))?;
        AppConfig::from_toml_str(&c)
            .map_err(|e| anyhow!("generated client config invalid: {e}"))?;
        let facts = ServerFacts {
            port: args.bind.port(),
            tun_cidr: format!("{}.{}.{}.0/24", net[0], net[1], net[2]),
        };
        (Some(s), Some(c), facts)
    };

    // ── Build the plan ───────────────────────────────────────────────────────
    let mut steps: Vec<Step> = Vec::new();
    steps.push(step_user());
    steps.push(step_config_dir(&args.config_dir));
    if let (Some(s), Some(c)) = (server_toml, client_toml) {
        steps.push(step_identity(
            &server_cfg_path,
            s,
            &client_cfg_path,
            c,
            args.force,
        ));
    }
    steps.push(step_sysctl());
    if let Some(fw) = firewall {
        steps.extend(steps_firewall(fw, &facts, egress_dev.as_deref()));
    }
    steps.push(step_nft_file(
        &args.config_dir,
        &facts,
        firewall == Some(Firewall::Nft) || firewall == Some(Firewall::Ufw),
    ));
    if !units_packaged() {
        steps.push(step_units(args.dry_run)?);
    }
    // A freshly written config needs a (re)start; an untouched one must not
    // bounce a running VPN just because setup was re-run.
    steps.push(step_services(!keep_existing));

    // ── Run it ───────────────────────────────────────────────────────────────
    println!(
        "Setup plan: {} step(s){}.\n",
        steps.len(),
        if args.dry_run { " (dry run)" } else { "" }
    );
    let total = steps.len();
    for (i, step) in steps.into_iter().enumerate() {
        println!("[{}/{}] {}", i + 1, total, step.title);
        for line in &step.detail {
            println!("      {line}");
        }
        if (step.done)() {
            println!("      ✔ already in place — skipping\n");
            continue;
        }
        if args.dry_run {
            println!("      (dry run — not applied)\n");
            continue;
        }
        if !args.yes && !confirm("      Apply?", true)? {
            println!("      skipped by user\n");
            continue;
        }
        (step.apply)().with_context(|| format!("step failed: {}", step.title))?;
        println!("      ✔ done\n");
    }

    if args.dry_run {
        println!("Dry run finished — nothing was changed.");
        return Ok(());
    }
    verify_and_report(&args, &facts, keep_existing)
}

// ── Steps ────────────────────────────────────────────────────────────────────

fn step_user() -> Step {
    Step {
        title: format!("Service account '{SERVICE_USER}'"),
        detail: vec![format!(
            "useradd --system --user-group --no-create-home --shell /usr/sbin/nologin {SERVICE_USER}"
        )],
        done: Box::new(|| succeeds("id", &["-u", SERVICE_USER])),
        apply: Box::new(|| {
            run_cmd(
                "useradd",
                &[
                    "--system",
                    "--user-group",
                    "--no-create-home",
                    "--home-dir",
                    "/nonexistent",
                    "--shell",
                    "/usr/sbin/nologin",
                    SERVICE_USER,
                ],
            )
        }),
    }
}

fn step_config_dir(dir: &Path) -> Step {
    let d = dir.to_path_buf();
    let d2 = d.clone();
    Step {
        title: format!("Config directory {}", d.display()),
        detail: vec![format!("mode 0750, owner root:{SERVICE_USER}")],
        done: Box::new(move || {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&d2)
                .map(|m| m.is_dir() && m.permissions().mode() & 0o777 == 0o750)
                .unwrap_or(false)
        }),
        apply: Box::new({
            let d = dir.to_path_buf();
            move || {
                std::fs::create_dir_all(&d)?;
                set_mode_owner(&d, 0o750)
            }
        }),
    }
}

/// Server + matching client config as ONE step. Splitting them stranded the
/// server keys whenever the client half failed or was declined: the next run
/// kept the server config and could never produce its client again. The
/// client file is written first, so a failure there leaves the server
/// untouched.
fn step_identity(
    server_path: &Path,
    server_toml: String,
    client_path: &Path,
    client_toml: String,
    force: bool,
) -> Step {
    let sp = server_path.to_path_buf();
    let cp = client_path.to_path_buf();
    Step {
        title: format!(
            "Generate server config {} and the matching client config",
            sp.display()
        ),
        detail: vec![
            "new Ed25519 + ML-DSA-65 identities and a fresh obfuscation PSK".into(),
            format!(
                "server: {} — mode 0640, owner root:{SERVICE_USER} (private keys inside)",
                sp.display()
            ),
            format!(
                "client: {} — mode 0600, owner root (private keys inside)",
                cp.display()
            ),
            "copy the client config to the client over a secure channel, then DELETE it here"
                .into(),
            if force && sp.exists() {
                "existing server config is backed up first (--force)".into()
            } else {
                "no existing server config".into()
            },
        ],
        done: Box::new(|| false),
        apply: Box::new(move || {
            if cp.exists() && !force {
                bail!(
                    "{} already exists — pass --force to overwrite",
                    cp.display()
                );
            }
            if let Some(dir) = cp.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("cannot create {}", dir.display()))?;
            }
            write_file(&cp, &client_toml, 0o600, false)?;
            if sp.exists() {
                let bak = sp.with_extension(format!("toml.bak-{}", unix_ts()));
                std::fs::copy(&sp, &bak)?;
                set_mode_owner(&bak, 0o640)?;
                println!("      backed up old config to {}", bak.display());
            }
            write_file(&sp, &server_toml, 0o640, true)
        }),
    }
}

fn step_sysctl() -> Step {
    const FILE: &str = "/etc/sysctl.d/99-chameleon-pq.conf";
    const BODY: &str =
        "# Chameleon-PQ full-tunnel server: forward tunnel traffic to the internet.\n\
                        net.ipv4.ip_forward = 1\n";
    Step {
        title: "Enable IPv4 forwarding (persistent)".into(),
        detail: vec![
            format!("write {FILE}: net.ipv4.ip_forward = 1"),
            "sysctl -w net.ipv4.ip_forward=1".into(),
        ],
        done: Box::new(|| {
            std::fs::read_to_string(FILE)
                .map(|c| c == BODY)
                .unwrap_or(false)
                && std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
                    .map(|v| v.trim() == "1")
                    .unwrap_or(false)
        }),
        apply: Box::new(|| {
            write_file(Path::new(FILE), BODY, 0o644, false)?;
            run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"])
        }),
    }
}

fn steps_firewall(fw: Firewall, facts: &ServerFacts, egress_dev: Option<&str>) -> Vec<Step> {
    let port = facts.port;
    let pspec = format!("{port}/udp");
    match fw {
        Firewall::Firewalld => {
            let changed = std::rc::Rc::new(std::cell::Cell::new(false));
            let zone = egress_dev
                .and_then(|d| capture("firewall-cmd", &["--get-zone-of-interface", d]).ok())
                .map(|z| z.trim().to_string())
                .filter(|z| !z.is_empty())
                .or_else(|| {
                    capture("firewall-cmd", &["--get-default-zone"])
                        .ok()
                        .map(|z| z.trim().to_string())
                })
                .unwrap_or_else(|| "public".into());
            vec![
                fw_step(
                    &changed,
                    format!("firewalld: open UDP {port} in zone '{zone}'"),
                    &[
                        "--permanent",
                        &format!("--zone={zone}"),
                        &format!("--add-port={pspec}"),
                    ],
                    &[
                        "--permanent",
                        &format!("--zone={zone}"),
                        &format!("--query-port={pspec}"),
                    ],
                ),
                fw_step(
                    &changed,
                    format!("firewalld: masquerade (NAT) in zone '{zone}'"),
                    &["--permanent", &format!("--zone={zone}"), "--add-masquerade"],
                    &[
                        "--permanent",
                        &format!("--zone={zone}"),
                        "--query-masquerade",
                    ],
                ),
                fw_step(
                    &changed,
                    format!("firewalld: trust the tunnel interface {TUN_NAME}"),
                    &[
                        "--permanent",
                        "--zone=trusted",
                        &format!("--add-interface={TUN_NAME}"),
                    ],
                    &[
                        "--permanent",
                        "--zone=trusted",
                        &format!("--query-interface={TUN_NAME}"),
                    ],
                ),
                Step {
                    title: "firewalld: reload".into(),
                    detail: vec!["firewall-cmd --reload".into()],
                    // Only needed when a step above changed the permanent config.
                    done: Box::new({
                        let changed = changed.clone();
                        move || !changed.get()
                    }),
                    apply: Box::new(|| run_cmd("firewall-cmd", &["--reload"])),
                },
            ]
        }
        Firewall::Ufw => {
            let mut route: Vec<String> = ["route", "allow", "in", "on", TUN_NAME]
                .iter()
                .map(|s| s.to_string())
                .collect();
            if let Some(d) = egress_dev {
                route.extend(["out".to_string(), "on".to_string(), d.to_string()]);
            }
            let route_check = route.join(" ");
            vec![
                Step {
                    title: format!("ufw: allow UDP {port}"),
                    detail: vec![format!("ufw allow {pspec}")],
                    done: Box::new({
                        let pspec = pspec.clone();
                        move || {
                            capture("ufw", &["status"])
                                .map(|s| {
                                    s.lines()
                                        .any(|l| l.starts_with(&pspec) && l.contains("ALLOW"))
                                })
                                .unwrap_or(false)
                        }
                    }),
                    apply: Box::new(move || run_cmd("ufw", &["allow", &pspec])),
                },
                Step {
                    title: format!("ufw: allow forwarding from {TUN_NAME}"),
                    detail: vec![format!("ufw {route_check}")],
                    done: Box::new({
                        let dev = egress_dev.unwrap_or("").to_string();
                        move || {
                            capture("ufw", &["status", "verbose"])
                                .map(|s| {
                                    s.contains(TUN_NAME) && (dev.is_empty() || s.contains(&dev))
                                })
                                .unwrap_or(false)
                        }
                    }),
                    apply: Box::new(move || {
                        let r: Vec<&str> = route.iter().map(String::as_str).collect();
                        run_cmd("ufw", &r)
                    }),
                },
            ]
        }
        Firewall::Nft => Vec::new(), // NAT lives in our own table, see step_nft_file
    }
}

/// One `firewall-cmd` change guarded by a `--query-*` check.
fn fw_step(
    changed: &std::rc::Rc<std::cell::Cell<bool>>,
    title: String,
    add: &[&str],
    query: &[&str],
) -> Step {
    let changed = changed.clone();
    let add: Vec<String> = add.iter().map(|s| s.to_string()).collect();
    let query: Vec<String> = query.iter().map(|s| s.to_string()).collect();
    Step {
        detail: vec![format!("firewall-cmd {}", add.join(" "))],
        title,
        done: Box::new(move || {
            let q: Vec<&str> = query.iter().map(String::as_str).collect();
            succeeds("firewall-cmd", &q)
        }),
        apply: Box::new(move || {
            let a: Vec<&str> = add.iter().map(String::as_str).collect();
            run_cmd("firewall-cmd", &a)?;
            changed.set(true);
            Ok(())
        }),
    }
}

fn step_nft_file(config_dir: &Path, facts: &ServerFacts, with_nat: bool) -> Step {
    let path = config_dir.join("chameleon-pq.nft");
    let body = render_nft(&facts.tun_cidr, with_nat);
    let p = path.clone();
    let b = body.clone();
    Step {
        title: format!("nftables rules {}", path.display()),
        detail: if with_nat {
            vec![
                "TCP MSS clamp on the tunnel (avoids the PMTU black hole / upload collapse)".into(),
                format!("masquerade for {}", facts.tun_cidr),
                format!("loaded at boot by {NFT_UNIT}; lives in its own table 'inet {NFT_TABLE}'"),
            ]
        } else {
            vec![
                "TCP MSS clamp on the tunnel (avoids the PMTU black hole / upload collapse)".into(),
                format!("loaded at boot by {NFT_UNIT}; own table 'inet {NFT_TABLE}', NAT is firewalld's"),
            ]
        },
        done: Box::new(move || std::fs::read_to_string(&p).map(|c| c == b).unwrap_or(false)),
        apply: Box::new(move || write_file(&path, &body, 0o644, false)),
    }
}

fn step_services(restart: bool) -> Step {
    Step {
        title: "Enable and start the services".into(),
        detail: vec![
            "systemctl daemon-reload".into(),
            format!("systemctl enable {NFT_UNIT} {MAIN_UNIT}"),
            format!("systemctl restart {NFT_UNIT} {MAIN_UNIT}"),
        ],
        done: Box::new(move || {
            !restart
                && succeeds("systemctl", &["is-active", "--quiet", MAIN_UNIT])
                && succeeds("systemctl", &["is-enabled", "--quiet", MAIN_UNIT])
                && succeeds("systemctl", &["is-active", "--quiet", NFT_UNIT])
        }),
        apply: Box::new(|| {
            run_cmd("systemctl", &["daemon-reload"])?;
            run_cmd("systemctl", &["enable", NFT_UNIT, MAIN_UNIT])?;
            run_cmd("systemctl", &["restart", NFT_UNIT, MAIN_UNIT])
        }),
    }
}

// ── systemd units for a bare-binary install ─────────────────────────────────

const UNIT_MAIN_SRC: &str = include_str!("../packaging/linux/chameleon-pq.service");
const UNIT_NFT_SRC: &str = include_str!("../packaging/linux/chameleon-pq-nft.service");
const UNIT_DIR_LOCAL: &str = "/etc/systemd/system";

/// Did a .deb/.rpm already install the units?
fn units_packaged() -> bool {
    ["/usr/lib/systemd/system", "/lib/systemd/system"]
        .iter()
        .any(|d| Path::new(d).join(MAIN_UNIT).exists())
}

/// The unit's `ExecStart` points at the packaged `/usr/bin` path; for a bare
/// binary point it at wherever the binary actually lives.
fn render_unit(template: &str, exe: &Path) -> String {
    template
        .lines()
        .map(|l| {
            if l.starts_with("ExecStart=/usr/bin/chameleon-pq ") {
                l.replacen("/usr/bin/chameleon-pq", &exe.display().to_string(), 1)
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// The unit sandboxes the service (ProtectHome, PrivateTmp): a binary under
/// these paths can be run by hand but not by the service.
fn exe_hidden_from_service(exe: &Path) -> bool {
    ["/home", "/root", "/tmp", "/var/tmp", "/run/user"]
        .iter()
        .any(|p| exe.starts_with(p))
}

fn step_units(dry_run: bool) -> Result<Step> {
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("cannot determine the path of this binary")?;
    if exe_hidden_from_service(&exe) && dry_run {
        println!(
            "! Note: {} is not reachable from the sandboxed service; a real run would ask you \
             to install the binary to /usr/local/bin first.",
            exe.display()
        );
    } else if exe_hidden_from_service(&exe) {
        bail!(
            "{} is not reachable from the sandboxed service (it hides /home, /root and /tmp).\n\
             Install it first, e.g.:  sudo install -m 0755 {} /usr/local/bin/chameleon-pq\n\
             then run /usr/local/bin/chameleon-pq setup",
            exe.display(),
            exe.display()
        );
    }
    let main_body = render_unit(UNIT_MAIN_SRC, &exe);
    let nft_body = UNIT_NFT_SRC.to_string();
    let dir = PathBuf::from(UNIT_DIR_LOCAL);
    let (mp, np) = (dir.join(MAIN_UNIT), dir.join(NFT_UNIT));
    let (mp2, np2, mb2, nb2) = (mp.clone(), np.clone(), main_body.clone(), nft_body.clone());
    let exe2 = exe.clone();
    Ok(Step {
        title: format!("Install the systemd units into {UNIT_DIR_LOCAL}"),
        detail: vec![
            format!("{MAIN_UNIT} (runs {} as {SERVICE_USER})", exe.display()),
            format!("{NFT_UNIT} (loads the nftables rules)"),
            "no package installed them, so setup writes them itself".into(),
        ],
        done: Box::new(move || {
            std::fs::read_to_string(&mp2)
                .map(|c| c == mb2)
                .unwrap_or(false)
                && std::fs::read_to_string(&np2)
                    .map(|c| c == nb2)
                    .unwrap_or(false)
        }),
        apply: Box::new(move || {
            write_file(&mp, &main_body, 0o644, false)?;
            write_file(&np, &nft_body, 0o644, false)?;
            // A binary moved in from a home directory keeps that SELinux
            // label and systemd then cannot exec it. Best effort: restorecon
            // simply does not exist on hosts without SELinux.
            let _ = run_cmd("restorecon", &["-F", &exe2.display().to_string()]);
            Ok(())
        }),
    })
}

// ── Verification & report ────────────────────────────────────────────────────

fn verify_and_report(args: &SetupArgs, facts: &ServerFacts, kept: bool) -> Result<()> {
    std::thread::sleep(std::time::Duration::from_secs(2));
    let active = succeeds("systemctl", &["is-active", "--quiet", MAIN_UNIT]);
    let listening = capture("ss", &["-H", "-ulnp"])
        .map(|s| s.contains(&format!(":{}", facts.port)))
        .unwrap_or(false);
    println!("Result:");
    println!(
        "  service {MAIN_UNIT}: {}",
        if active { "RUNNING" } else { "NOT running" }
    );
    println!(
        "  UDP :{}: {}",
        facts.port,
        if listening {
            "listening"
        } else {
            "not seen listening"
        }
    );
    if !active {
        println!("\nLast log lines:");
        if let Ok(log) = capture("journalctl", &["-u", MAIN_UNIT, "-n", "15", "--no-pager"]) {
            println!("{log}");
        }
        bail!("service did not start — see the log above");
    }
    println!();
    if !kept {
        let client = args.client_out.join("chameleon-pq-client.toml");
        println!("Client config: {}", client.display());
        println!("  1. Copy it to the client (scp / USB) and import it there");
        println!(
            "  2. Then DELETE it from this server: shred -u {}",
            client.display()
        );
    }
    println!("Status:   systemctl status {MAIN_UNIT}");
    println!("Logs:     journalctl -u {MAIN_UNIT} -f");
    Ok(())
}

// ── Pure helpers (unit-tested) ───────────────────────────────────────────────

/// nftables ruleset in its own table. `add`+`delete`+recreate makes loading
/// idempotent without clobbering anyone else's rules.
fn render_nft(tun_cidr: &str, with_nat: bool) -> String {
    let mut s = format!(
        "# Managed by `chameleon-pq setup` — safe to re-run, only touches table inet {NFT_TABLE}.\n\
         add table inet {NFT_TABLE}\n\
         delete table inet {NFT_TABLE}\n\
         table inet {NFT_TABLE} {{\n\
         \x20   chain mss {{\n\
         \x20       type filter hook forward priority mangle; policy accept;\n\
         \x20       tcp flags & (syn | rst) == syn oifname \"{TUN_NAME}\" tcp option maxseg size set rt mtu\n\
         \x20       tcp flags & (syn | rst) == syn iifname \"{TUN_NAME}\" tcp option maxseg size set rt mtu\n\
         \x20   }}\n"
    );
    if with_nat {
        s.push_str(&format!(
            "    chain postrouting {{\n\
             \x20       type nat hook postrouting priority srcnat; policy accept;\n\
             \x20       ip saddr {tun_cidr} oifname != \"{TUN_NAME}\" oifname != \"lo\" masquerade\n\
             \x20   }}\n"
        ));
    }
    s.push_str("}\n");
    s
}

/// `ip -4 route get 1.1.1.1` → `(dev, src)`.
fn parse_route_get(out: &str) -> (Option<String>, Option<Ipv4Addr>) {
    let toks: Vec<&str> = out.split_whitespace().collect();
    let after = |key: &str| {
        toks.iter()
            .position(|t| *t == key)
            .and_then(|i| toks.get(i + 1))
            .map(|s| s.to_string())
    };
    (after("dev"), after("src").and_then(|s| s.parse().ok()))
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64)
}

/// `10.99.0.1` + `255.255.255.0` → `10.99.0.0/24`.
fn cidr_of(addr: &str, mask: &str) -> Result<String> {
    let a: Ipv4Addr = addr
        .parse()
        .with_context(|| format!("bad tun address {addr}"))?;
    let m: Ipv4Addr = mask
        .parse()
        .with_context(|| format!("bad netmask {mask}"))?;
    let (ai, mi) = (u32::from(a), u32::from(m));
    if mi.leading_ones() + mi.trailing_zeros() != 32 {
        bail!("netmask {mask} is not a contiguous mask");
    }
    Ok(format!("{}/{}", Ipv4Addr::from(ai & mi), mi.leading_ones()))
}

// ── System helpers ───────────────────────────────────────────────────────────

fn detect_egress() -> (Option<String>, Option<Ipv4Addr>) {
    capture("ip", &["-4", "-o", "route", "get", "1.1.1.1"])
        .map(|o| parse_route_get(&o))
        .unwrap_or((None, None))
}

fn detect_firewall() -> Firewall {
    if succeeds("firewall-cmd", &["--state"]) {
        return Firewall::Firewalld;
    }
    if capture("ufw", &["status"])
        .map(|s| s.trim_start().starts_with("Status: active"))
        .unwrap_or(false)
    {
        return Firewall::Ufw;
    }
    Firewall::Nft
}

/// Any existing route/address inside `<net>.0/24`? (Would clash with the tunnel.)
fn route_clash(tun_net: &str) -> Option<String> {
    let prefix = format!("{tun_net}.");
    ["route", "addr"].iter().find_map(|what| {
        capture("ip", &["-4", "-o", what, "show"])
            .ok()
            .and_then(|out| {
                out.lines()
                    .find(|l| {
                        l.split_whitespace().any(|t| t.starts_with(&prefix))
                            && !l.contains(TUN_NAME)
                    })
                    .map(|l| l.trim().to_string())
            })
    })
}

fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn service_ids() -> Result<(u32, u32)> {
    let uid = capture("id", &["-u", SERVICE_USER])?.trim().parse()?;
    let gid = capture("id", &["-g", SERVICE_USER])?.trim().parse()?;
    Ok((uid, gid))
}

/// `root:chameleon-pq` with the given mode.
fn set_mode_owner(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let (_, gid) = service_ids().context("service account missing")?;
    std::os::unix::fs::chown(path, Some(0), Some(gid))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Write via a temp file + rename so a crash never leaves a half-written
/// secret. `group_service`: give group ownership to the service account.
fn write_file(path: &Path, contents: &str, mode: u32, group_service: bool) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .with_context(|| format!("cannot create {}", tmp.display()))?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    drop(f);
    if group_service {
        let (_, gid) = service_ids().context("service account missing")?;
        std::os::unix::fs::chown(&tmp, Some(0), Some(gid))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn capture(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("cannot run {program}"))?;
    if !out.status.success() {
        bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    capture(program, args).map(|_| ())
}

// ── Prompts ──────────────────────────────────────────────────────────────────

fn read_line() -> Result<String> {
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn confirm(question: &str, default_yes: bool) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!("not a terminal — re-run with --yes to apply without asking");
    }
    print!(
        "{question} {} ",
        if default_yes { "[Y/n]" } else { "[y/N]" }
    );
    Ok(match read_line()?.to_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" | "j" | "ja" => true,
        _ => false,
    })
}

fn prompt_server_addr(detected: Option<Ipv4Addr>, port: u16) -> Result<SocketAddr> {
    println!("Which address will clients connect to? (the server's PUBLIC ip:port)");
    let default = detected.map(|ip| {
        if is_private_v4(ip) {
            println!("  detected {ip}, but that is a private/NAT address — clients on the internet need your public IP");
        } else {
            println!("  detected {ip}");
        }
        SocketAddr::new(ip.into(), port)
    });
    match default {
        Some(d) => print!("Server address [{d}]: "),
        None => print!("Server address (e.g. 203.0.113.5:{port}): "),
    }
    let line = read_line()?;
    if line.is_empty() {
        return default.ok_or_else(|| anyhow!("a server address is required"));
    }
    line.parse()
        .map_err(|_| anyhow!("not a valid ip:port (a numeric IP, not a hostname)"))
}

fn prompt_tun_net(default: &str) -> Result<String> {
    print!("Tunnel network /24 base [{default}]: ");
    let line = read_line()?;
    Ok(if line.is_empty() {
        default.to_string()
    } else {
        line
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_with_nat_has_mss_and_masquerade() {
        let r = render_nft("10.99.0.0/24", true);
        assert!(r.contains("tcp option maxseg size set rt mtu"));
        assert!(r.contains("ip saddr 10.99.0.0/24"));
        assert!(r.contains("masquerade"));
        // delete-then-recreate keeps loading idempotent without touching other tables
        assert!(r.contains("add table inet chameleon_pq\ndelete table inet chameleon_pq\n"));
    }

    #[test]
    fn nft_without_nat_leaves_nat_to_the_firewall() {
        let r = render_nft("10.99.0.0/24", false);
        assert!(r.contains("maxseg"));
        assert!(!r.contains("masquerade"));
    }

    #[test]
    fn route_get_is_parsed() {
        let o = "1.1.1.1 via 188.68.59.1 dev eth0 src 188.68.59.87 uid 0 \\    cache";
        assert_eq!(
            parse_route_get(o),
            (Some("eth0".into()), Some("188.68.59.87".parse().unwrap()))
        );
        assert_eq!(parse_route_get(""), (None, None));
    }

    #[test]
    fn private_addresses_are_flagged() {
        for ip in [
            "10.0.0.5",
            "192.168.1.2",
            "172.16.4.4",
            "100.64.1.1",
            "127.0.0.1",
        ] {
            assert!(is_private_v4(ip.parse().unwrap()), "{ip}");
        }
        assert!(!is_private_v4("188.68.59.87".parse().unwrap()));
    }

    #[test]
    fn unit_execstart_is_rewritten_for_a_bare_binary() {
        let u = render_unit(UNIT_MAIN_SRC, Path::new("/usr/local/bin/chameleon-pq"));
        assert!(u.contains(
            "ExecStart=/usr/local/bin/chameleon-pq --config /etc/chameleon-pq/server-config.toml server\n"
        ));
        assert!(!u.contains("/usr/bin/chameleon-pq"));
        // everything else is preserved
        assert!(u.contains("AmbientCapabilities=CAP_NET_ADMIN"));
        assert!(u.contains("User=chameleon-pq"));
    }

    #[test]
    fn binaries_the_sandbox_hides_are_refused() {
        for p in [
            "/home/u/chameleon-pq",
            "/root/chameleon-pq",
            "/tmp/x/chameleon-pq",
        ] {
            assert!(exe_hidden_from_service(Path::new(p)), "{p}");
        }
        for p in [
            "/usr/local/bin/chameleon-pq",
            "/usr/bin/chameleon-pq",
            "/opt/c/chameleon-pq",
        ] {
            assert!(!exe_hidden_from_service(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn cidr_from_address_and_mask() {
        assert_eq!(
            cidr_of("10.99.0.1", "255.255.255.0").unwrap(),
            "10.99.0.0/24"
        );
        assert_eq!(cidr_of("10.98.7.9", "255.255.0.0").unwrap(), "10.98.0.0/16");
        assert!(cidr_of("10.99.0.1", "255.0.255.0").is_err());
    }
}
