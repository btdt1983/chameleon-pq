//! DNS-leak protection for the full-tunnel client (WireGuard-style `DNS =`).
//!
//! Without this, the OS keeps using its own resolver — typically the LAN router,
//! which forwards to the ISP — so DNS queries leak outside the tunnel even with
//! full-tunnel routing and the kill switch on (the kill switch permits LAN, and
//! the router does the leaking). When `[tun] dns` lists resolvers, the client —
//! while connected — forces DNS through the tunnel instead:
//!
//!   * it sets those resolvers ON THE TUN INTERFACE. They are public IPs, and
//!     with full-tunnel routing every IPv4 packet — including to the resolver —
//!     travels through the tunnel, so the query exits at the server, not the ISP.
//!   * on Windows it disables "smart multi-homed name resolution" (the policy
//!     `DisableSmartNameResolution`) — exactly what WireGuard does. That default
//!     behaviour fans every query out over ALL interfaces at once, so the
//!     physical NIC's resolver (the ISP/router) still sees them; with it off,
//!     Windows uses only the primary interface's DNS, which is the tun.
//!   * on Linux it points `/etc/resolv.conf` at those resolvers.
//!
//! RAII: like `route::FullTunnelRoutes`, the previous DNS setup is restored when
//! the guard is dropped (a deliberate disconnect, or the `Client` being dropped).
//! It is fail-OPEN on its own; pair it with `kill_switch = true` for the
//! fail-closed guarantee that nothing leaks if the tunnel drops unexpectedly.

use crate::error::{ChameleonError, Result};
use std::net::IpAddr;
use tracing::info;

/// A live DNS override that restores the previous configuration on drop.
pub struct DnsGuard {
    restore: Restore,
    // Windows only: periodically re-covers non-tun adapters that come up AFTER
    // install (Wi-Fi reconnect, a new virtual NIC) — see `start_refresher`.
    #[cfg(target_os = "windows")]
    refresher: Refresher,
}

impl DnsGuard {
    /// Force DNS through the tunnel using `servers`, restoring the prior setup on
    /// drop. `tun` is the tunnel interface name. Requires the same privileges as
    /// route/kill-switch install (admin / root).
    pub fn install(servers: &[IpAddr], tun: &str) -> Result<Self> {
        if servers.is_empty() {
            return Err(ChameleonError::Dns("no DNS servers configured".into()));
        }
        // Reject a tun name we cannot safely embed in a command string. The name
        // comes from config, so this is belt-and-braces (mirrors killswitch.rs).
        if tun.contains(['"', '\'', '\n', '\r', '\\']) {
            return Err(ChameleonError::Dns(format!(
                "refusing unsafe tun name '{tun}'"
            )));
        }
        let restore = install_backend(servers, tun)?;
        info!(
            "DNS-leak protection ON — {} resolver(s) forced through the tunnel",
            servers.len()
        );
        #[cfg(target_os = "windows")]
        let refresher = start_refresher(servers.to_vec(), tun.to_string(), restore.saved.clone());
        Ok(Self {
            restore,
            #[cfg(target_os = "windows")]
            refresher,
        })
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        self.refresher.stop();
        restore_backend(&self.restore);
        info!("DNS-leak protection off — previous DNS restored");
    }
}

// ── Linux / non-Windows back-end (/etc/resolv.conf) ──────────────────────────

#[cfg(not(target_os = "windows"))]
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// What `/etc/resolv.conf` was before we touched it, so drop can put it back.
#[cfg(not(target_os = "windows"))]
enum Restore {
    /// Was a regular file with these bytes → write them back.
    File(Vec<u8>),
    /// Was a symlink to this target (e.g. systemd-resolved stub) → recreate it.
    Symlink(std::path::PathBuf),
    /// Did not exist → remove the file we wrote.
    Absent,
}

#[cfg(not(target_os = "windows"))]
fn install_backend(servers: &[IpAddr], _tun: &str) -> Result<Restore> {
    apply_resolv_conf(std::path::Path::new(RESOLV_CONF), servers)
}

#[cfg(not(target_os = "windows"))]
fn restore_backend(restore: &Restore) {
    restore_resolv_conf(std::path::Path::new(RESOLV_CONF), restore);
}

/// Render the `resolv.conf` body pointing at `servers` (pure, so it is testable).
#[cfg(not(target_os = "windows"))]
fn resolv_conf_body(servers: &[IpAddr]) -> String {
    let mut s =
        String::from("# Written by Chameleon-PQ (DNS-leak protection); restored on disconnect.\n");
    for ip in servers {
        s.push_str(&format!("nameserver {ip}\n"));
    }
    s
}

/// Back up whatever `path` currently is, then write our resolver list.
#[cfg(not(target_os = "windows"))]
fn apply_resolv_conf(path: &std::path::Path, servers: &[IpAddr]) -> Result<Restore> {
    use std::fs;
    let restore = match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            let target = fs::read_link(path)
                .map_err(|e| ChameleonError::Dns(format!("read_link {}: {e}", path.display())))?;
            // Replace the symlink with a regular file: writing THROUGH a symlink
            // to e.g. systemd-resolved's stub would corrupt it.
            fs::remove_file(path)
                .map_err(|e| ChameleonError::Dns(format!("remove {}: {e}", path.display())))?;
            Restore::Symlink(target)
        }
        Ok(_) => {
            let bytes = fs::read(path)
                .map_err(|e| ChameleonError::Dns(format!("read {}: {e}", path.display())))?;
            Restore::File(bytes)
        }
        Err(_) => Restore::Absent,
    };
    fs::write(path, resolv_conf_body(servers))
        .map_err(|e| ChameleonError::Dns(format!("write {}: {e}", path.display())))?;
    Ok(restore)
}

/// Put `path` back the way `apply_resolv_conf` found it. Best-effort.
#[cfg(not(target_os = "windows"))]
fn restore_resolv_conf(path: &std::path::Path, restore: &Restore) {
    use std::fs;
    let _ = match restore {
        Restore::File(bytes) => fs::write(path, bytes),
        Restore::Symlink(target) => {
            let _ = fs::remove_file(path);
            std::os::unix::fs::symlink(target, path)
        }
        Restore::Absent => fs::remove_file(path),
    };
}

// ── Windows back-end (per-interface DNS + DisableSmartNameResolution) ─────────
//
// A multi-homed Windows host — e.g. a Hyper-V host with several vEthernet /
// physical adapters — keeps querying the ISP resolver configured on those
// adapters, so setting DNS on the tun alone leaves a PARTIAL leak (measured:
// ~half the queries still reached the ISP). We therefore point EVERY up, non-tun
// IPv4 adapter at the tunnel resolvers (capturing each original so drop can
// restore it), also set the tun's own resolver, and disable smart multi-homed
// name resolution — the combination WireGuard uses.

#[cfg(target_os = "windows")]
const DNSCLIENT_POLICY_KEY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";

/// PowerShell that, for each up non-tun IPv4 adapter, prints `ifIndex|a,b` (its
/// current resolvers) and then overrides it with ours. `__TUN__` / `__LIST__` are
/// substituted before running; both are validated/sanitised by the caller.
#[cfg(target_os = "windows")]
const SET_ALL_SCRIPT: &str = r#"$ErrorActionPreference='SilentlyContinue'
Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne '__TUN__' } | ForEach-Object {
  $i = $_.ifIndex
  $o = (Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses -join ','
  Write-Output ("{0}|{1}" -f $i, $o)
  Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses (__LIST__)
}"#;

/// Per-interface original IPv4 DNS servers to put back on drop (an empty list =
/// the interface was on DHCP/none → reset it). Shared with the refresher thread
/// (`Arc<Mutex<..>>`), which APPENDS newly-covered adapters as they appear —
/// it never touches an entry already here, since by the time it runs, that
/// adapter's "current" DNS is already OURS, not the real original.
#[cfg(target_os = "windows")]
struct Restore {
    saved: std::sync::Arc<std::sync::Mutex<Vec<(u32, Vec<IpAddr>)>>>,
}

#[cfg(target_os = "windows")]
fn install_backend(servers: &[IpAddr], tun: &str) -> Result<Restore> {
    // 1. The tun's own resolver (ephemeral — dies with the interface, no restore).
    let name_arg = format!("name={tun}");
    let primary_arg = format!("address={}", servers[0]);
    let _ = run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            name_arg.as_str(),
            "source=static",
            primary_arg.as_str(),
            "register=primary",
            "validate=no",
        ],
    );
    for (i, s) in servers.iter().enumerate().skip(1) {
        let addr_arg = format!("address={s}");
        let idx_arg = format!("index={}", i + 1);
        let _ = run_cmd(
            "netsh",
            &[
                "interface",
                "ipv4",
                "add",
                "dnsservers",
                name_arg.as_str(),
                addr_arg.as_str(),
                idx_arg.as_str(),
                "validate=no",
            ],
        );
    }

    // 2. Every up non-tun IPv4 adapter: capture its original DNS, then set ours.
    //    This is the piece that closes the multi-homed leak (the tun alone isn't
    //    enough — the ISP resolver on the physical/vEthernet adapters still leaks).
    let script = SET_ALL_SCRIPT
        .replace("__TUN__", tun)
        .replace("__LIST__", &ps_server_list(servers));
    let saved = parse_saved(&run_powershell_capture(&script)?);

    // 3. Defence in depth: stop Windows fanning queries out over every interface.
    let _ = run_cmd(
        "reg",
        &[
            "add",
            DNSCLIENT_POLICY_KEY,
            "/v",
            "DisableSmartNameResolution",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ],
    );
    let _ = run_cmd("ipconfig", &["/flushdns"]);
    Ok(Restore {
        saved: std::sync::Arc::new(std::sync::Mutex::new(saved)),
    })
}

#[cfg(target_os = "windows")]
fn restore_backend(restore: &Restore) {
    // Put every interface's original IPv4 DNS back (reset to DHCP if it had none),
    // re-enable smart resolution, and flush. Best-effort.
    let saved = restore
        .saved
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    let mut script = String::from("$ErrorActionPreference='SilentlyContinue'\n");
    for (idx, orig) in &saved {
        if orig.is_empty() {
            script.push_str(&format!(
                "Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses\n"
            ));
        } else {
            script.push_str(&format!(
                "Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses ({})\n",
                ps_server_list(orig)
            ));
        }
    }
    let _ = run_powershell_capture(&script);
    let _ = run_cmd(
        "reg",
        &[
            "delete",
            DNSCLIENT_POLICY_KEY,
            "/v",
            "DisableSmartNameResolution",
            "/f",
        ],
    );
    let _ = run_cmd("ipconfig", &["/flushdns"]);
}

// ── Refresher: cover adapters that come up AFTER install ──────────────────────
//
// `install_backend` only sees a snapshot of "up" adapters at connect time. A
// Wi-Fi reconnect (sleep/wake, roaming), or a new virtual adapter (Docker/
// Hyper-V/another VPN) appearing later keeps its own DHCP/ISP resolver for the
// rest of the session — the exact multi-homed leak this module exists to
// close, just delayed instead of prevented. This background thread re-checks
// periodically and covers anything new, WITHOUT re-touching adapters already
// in `saved` (re-capturing those would save OUR OWN servers as the "original"
// and corrupt the restore).

#[cfg(target_os = "windows")]
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// PowerShell: one ifIndex per line, for every currently up non-tun adapter.
/// Cheap — used to detect newly-appeared adapters without touching their DNS.
#[cfg(target_os = "windows")]
const LIST_UP_SCRIPT: &str = r#"$ErrorActionPreference='SilentlyContinue'
Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne '__TUN__' } | ForEach-Object { $_.ifIndex }"#;

/// Capture `idx`'s current (pre-Chameleon) DNS and point it at `servers`, in
/// one script so there is no window between "read" and "set". `idx` is a
/// `u32` parsed from our own `Get-NetAdapter` output, so it is safe to
/// interpolate directly (never attacker/config-controlled text).
#[cfg(target_os = "windows")]
fn cover_adapter(idx: u32, servers: &[IpAddr]) -> Option<Vec<IpAddr>> {
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'\n\
         $o = (Get-DnsClientServerAddress -InterfaceIndex {idx} -AddressFamily IPv4).ServerAddresses -join ','\n\
         Write-Output $o\n\
         Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses ({})\n",
        ps_server_list(servers)
    );
    let out = run_powershell_capture(&script).ok()?;
    Some(
        out.trim()
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .collect(),
    )
}

/// One refresh pass: find up non-tun adapters not already in `saved`, cover
/// each, and append its captured original to `saved`.
#[cfg(target_os = "windows")]
fn refresh_tick(
    tun: &str,
    servers: &[IpAddr],
    saved: &std::sync::Arc<std::sync::Mutex<Vec<(u32, Vec<IpAddr>)>>>,
) {
    let script = LIST_UP_SCRIPT.replace("__TUN__", tun);
    let Ok(out) = run_powershell_capture(&script) else {
        return;
    };
    let up: Vec<u32> = out.lines().filter_map(|l| l.trim().parse().ok()).collect();
    for idx in up {
        // Cheap check-then-cover: a small TOCTOU (another adapter could appear
        // between the check and the lock below) is harmless — worst case it
        // waits one more `REFRESH_INTERVAL` tick to be covered.
        let already_covered = saved
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .iter()
            .any(|(i, _)| *i == idx);
        if already_covered {
            continue;
        }
        if let Some(orig) = cover_adapter(idx, servers) {
            info!("DNS-leak protection: covering newly-up adapter (ifIndex {idx})");
            saved
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push((idx, orig));
        }
    }
}

/// Background thread handle for the periodic refresh. No `Drop` impl of its
/// own — `DnsGuard::drop` calls `stop()` explicitly before restoring DNS, so
/// the refresher cannot race a restore that is already in flight.
#[cfg(target_os = "windows")]
struct Refresher {
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "windows")]
impl Refresher {
    /// Ask the thread to stop. Does not block: the thread notices within one
    /// `REFRESH_INTERVAL` and exits on its own; we don't join it (DnsGuard's
    /// Drop must not hang on a PowerShell call that happens to be in flight).
    fn stop(&mut self) {
        self.stop_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.handle = None; // detach; the thread outlives this handle, briefly
    }
}

#[cfg(target_os = "windows")]
fn start_refresher(
    servers: Vec<IpAddr>,
    tun: String,
    saved: std::sync::Arc<std::sync::Mutex<Vec<(u32, Vec<IpAddr>)>>>,
) -> Refresher {
    let stop_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thread = stop_flag.clone();
    let handle = std::thread::spawn(move || {
        while !stop_thread.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(REFRESH_INTERVAL);
            if stop_thread.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            refresh_tick(&tun, &servers, &saved);
        }
    });
    Refresher {
        stop_flag,
        handle: Some(handle),
    }
}

/// Run a command with no console window (the GUI is a windowed subsystem app, so
/// a child would otherwise flash a console). Mirrors `route::command`.
#[cfg(target_os = "windows")]
fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new(program)
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .args(args)
        .output()
        .map_err(|e| ChameleonError::Dns(format!("spawning {program} failed: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(ChameleonError::Dns(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Run PowerShell and return its stdout (no console window). Best-effort content:
/// only a spawn failure errors; per-command failures inside the script are
/// swallowed (`$ErrorActionPreference='SilentlyContinue'`).
#[cfg(target_os = "windows")]
fn run_powershell_capture(script: &str) -> Result<String> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("powershell")
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| ChameleonError::Dns(format!("spawning PowerShell failed: {e}")))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// Pure helpers for the Windows back-end. Compiled everywhere (not just Windows)
// so the parsing/formatting can be unit-tested on the dev box.

/// Format IPs as a PowerShell address list, e.g. `'1.1.1.1','1.0.0.1'`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn ps_server_list(servers: &[IpAddr]) -> String {
    servers
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Parse the capture script's stdout: one `ifIndex|a.b.c.d,e.f.g.h` line per
/// adapter (an empty right side = the adapter had no IPv4 DNS). Malformed lines
/// and non-IP tokens are skipped.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_saved(stdout: &str) -> Vec<(u32, Vec<IpAddr>)> {
    stdout
        .lines()
        .filter_map(|line| {
            let (idx, rest) = line.split_once('|')?;
            let idx: u32 = idx.trim().parse().ok()?;
            let servers = rest
                .split(',')
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .collect();
            Some((idx, servers))
        })
        .collect()
}

// ── Tests (Linux resolv.conf logic is pure enough to exercise for real) ──────

#[cfg(all(test, not(target_os = "windows")))]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn servers() -> Vec<IpAddr> {
        vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()]
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("chameleon_dns_{}_{}", std::process::id(), name))
    }

    #[test]
    fn body_lists_every_nameserver() {
        let b = resolv_conf_body(&servers());
        assert!(b.contains("nameserver 1.1.1.1"));
        assert!(b.contains("nameserver 1.0.0.1"));
    }

    #[test]
    fn regular_file_is_backed_up_and_restored() {
        let p = tmp("regular");
        std::fs::write(&p, b"nameserver 192.168.0.1\n").unwrap();
        let restore = apply_resolv_conf(&p, &servers()).unwrap();
        // Our resolvers are now in place.
        let now = std::fs::read_to_string(&p).unwrap();
        assert!(now.contains("nameserver 1.1.1.1"));
        assert!(!now.contains("192.168.0.1"));
        // Restore brings the original bytes back exactly.
        restore_resolv_conf(&p, &restore);
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "nameserver 192.168.0.1\n"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn symlink_is_replaced_then_recreated() {
        let target = tmp("symlink_target");
        let link = tmp("symlink_link");
        std::fs::write(&target, b"nameserver 9.9.9.9\n").unwrap();
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let restore = apply_resolv_conf(&link, &servers()).unwrap();
        // The link is now a regular file with our content (the target untouched).
        assert!(!std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(std::fs::read_to_string(&link).unwrap().contains("1.1.1.1"));
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "nameserver 9.9.9.9\n"
        );

        // Restore recreates the symlink pointing back at the original target.
        restore_resolv_conf(&link, &restore);
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_link(&link).unwrap(), target);

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
    }

    #[test]
    fn absent_file_is_removed_on_restore() {
        let p = tmp("absent");
        let _ = std::fs::remove_file(&p);
        let restore = apply_resolv_conf(&p, &servers()).unwrap();
        assert!(p.exists());
        restore_resolv_conf(&p, &restore);
        assert!(!p.exists());
    }

    #[test]
    fn empty_servers_rejected() {
        assert!(DnsGuard::install(&[], "chameleon0").is_err());
    }

    #[test]
    fn unsafe_tun_name_rejected() {
        assert!(DnsGuard::install(&servers(), "tun\"; rm -rf /").is_err());
    }

    #[test]
    fn ps_list_quotes_each_ip() {
        assert_eq!(ps_server_list(&servers()), "'1.1.1.1','1.0.0.1'");
    }

    #[test]
    fn parse_saved_reads_index_and_servers() {
        // Windows capture output: "ifIndex|comma,list"; empty right = DHCP/none,
        // malformed lines are skipped.
        let out = "13|\n5|217.237.150.101,1.1.1.1\n   \nbad line\n7|8.8.8.8";
        let got = parse_saved(out);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], (13, vec![]));
        assert_eq!(
            got[1],
            (
                5,
                vec![
                    "217.237.150.101".parse().unwrap(),
                    "1.1.1.1".parse().unwrap()
                ]
            )
        );
        assert_eq!(got[2], (7, vec!["8.8.8.8".parse().unwrap()]));
    }
}
