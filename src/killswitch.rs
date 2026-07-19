//! VPN kill switch: block all traffic if the tunnel drops, so nothing leaks in
//! cleartext outside the full-tunnel VPN.
//!
//! DELIBERATELY the OPPOSITE of `route::FullTunnelRoutes`. Those routes are RAII
//! — torn down on drop, i.e. FAIL-OPEN: if the `Client` is dropped (which the
//! GUI does the instant the tunnel loops die) the routes vanish and traffic
//! falls back to the physical NIC in cleartext. That is exactly the leak this
//! module closes. So the kill switch is FAIL-CLOSED: it is NOT removed on Drop.
//! When the tunnel dies unexpectedly (or the whole client crashes) the firewall
//! STAYS engaged and keeps blocking. It comes down only on an explicit
//! `disengage()` (a deliberate user disconnect) or the `killswitch off` escape
//! hatch (`KillSwitch::clear`).
//!
//! While engaged, only these egress paths are permitted; everything else
//! outbound is dropped:
//!   - loopback,
//!   - the tunnel transport — all traffic to the server endpoint, so the
//!     encrypted tunnel packets (and a reconnect handshake) still get out,
//!   - the TUN interface — so traffic already routed into the tunnel flows,
//!   - the local subnet + DHCP — so LAN devices and the DHCP lease keep working.
//!
//! IPv6 internet egress is intentionally dropped too (the tunnel is IPv4-only,
//! so leaving v6 open would be a cleartext leak); only link-local v6 + neighbour
//! discovery are kept so the local link does not wedge.
//!
//! Back-ends mirror `route.rs`: nftables (`nft`) on Linux, Windows Firewall
//! (PowerShell `*-NetFirewallRule` + default-outbound=Block) on Windows.

use crate::error::{ChameleonError, Result};
use std::net::SocketAddr;
use std::process::Command;
use tracing::info;

/// A firewall lock-down that blocks all traffic except the tunnel's own paths.
///
/// Held by the frontend (NOT by `Client`) so that an unexpected tunnel drop —
/// which drops the `Client` — does NOT take the kill switch down with it. There
/// is deliberately no `Drop` impl: closing the app while engaged leaves the
/// switch in place (fail-closed); the next launch detects it via `is_engaged`
/// and offers to clear it, and `KillSwitch::clear` / `killswitch off` is always
/// available as an escape hatch.
pub struct KillSwitch {
    engaged: bool,
    /// Count of pre-existing, non-Chameleon outbound "Allow" firewall rules
    /// detected at engage time. Windows only (`None` elsewhere): Windows
    /// Firewall lets ANY matching Allow rule win over the profile's
    /// default-block action (see the Windows back-end doc below), so a
    /// non-zero count here means traffic matching one of those rules can
    /// bypass the kill switch. `nft`'s `policy drop` has no such gap, so this
    /// is always `Some(0)`-equivalent (reported as `None`, nothing to warn
    /// about) on Linux. Best-effort: `None` if it could not be determined.
    pub other_allow_rules: Option<usize>,
}

impl KillSwitch {
    /// Engage the kill switch: install firewall rules that block all outbound
    /// traffic except loopback, the LAN + DHCP, and the tunnel's own paths (the
    /// `tun` interface and everything to the `server` endpoint). Requires the
    /// same privileges as route install (admin / CAP_NET_ADMIN).
    pub fn engage(server: SocketAddr, tun: &str) -> Result<Self> {
        // Reject a tun name we cannot safely embed in a shell/nft string. The
        // name comes from config, so this is belt-and-braces.
        if tun.contains(['"', '\'', '\n', '\r', '\\']) {
            return Err(ChameleonError::KillSwitch(format!(
                "refusing unsafe tun name '{tun}'"
            )));
        }
        engage_backend(server, tun)?;
        let other_allow_rules = other_allow_rules_hint();
        if let Some(n) = other_allow_rules {
            if n > 0 {
                tracing::warn!(
                    "kill switch: {n} pre-existing outbound Allow firewall rule(s) detected — \
                     Windows lets a matching Allow rule override the default-block action, so \
                     traffic matching one of those rules is NOT guaranteed to be blocked"
                );
            }
        }
        info!("kill switch ENGAGED — all traffic blocked except the tunnel, LAN and DHCP");
        Ok(Self {
            engaged: true,
            other_allow_rules,
        })
    }

    /// Disengage: remove the rules we installed and restore normal connectivity.
    /// Idempotent. Call this on a DELIBERATE disconnect only — never rely on drop.
    pub fn disengage(&mut self) {
        if !self.engaged {
            return;
        }
        self.engaged = false;
        teardown();
        info!("kill switch disengaged — connectivity restored");
    }

    /// Whether a kill switch is currently installed (ours, by group/table name).
    /// Best-effort: on any error (e.g. not privileged to query) returns `false`.
    /// Used at startup to detect a switch left over from a crash or app close.
    pub fn is_engaged() -> bool {
        backend_is_engaged()
    }

    /// Escape hatch: force-remove the kill switch without owning an instance.
    /// Backs the `killswitch off` CLI command and the GUI "disable" button, so a
    /// user stranded offline (client crashed while engaged) can always recover.
    pub fn clear() {
        teardown();
        info!("kill switch cleared (escape hatch)");
    }
}

/// Best-effort count of pre-existing outbound Allow rules that could bypass
/// the kill switch. Windows only — see `KillSwitch::other_allow_rules`.
#[cfg(not(target_os = "windows"))]
fn other_allow_rules_hint() -> Option<usize> {
    None
}

// ── nftables back-end (Linux / non-Windows) ──────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn engage_backend(server: SocketAddr, tun: &str) -> Result<()> {
    // LAN: the physical interface's own subnet, so local devices stay reachable.
    // If we cannot determine it, skip it (fail-closed: LAN off, but no leak).
    let lan = local_subnet();
    if lan.is_none() {
        tracing::warn!("kill switch: local subnet not found — LAN access blocked while engaged");
    }
    nft_apply(&build_ruleset(server, tun, lan))
}

/// Build the nftables ruleset for the given tunnel. Pure (no I/O) so it can be
/// syntax-checked and unit-tested. `lan` is the physical subnet to permit, if
/// known.
#[cfg(not(target_os = "windows"))]
fn build_ruleset(server: SocketAddr, tun: &str, lan: Option<(std::net::Ipv4Addr, u8)>) -> String {
    // Idempotent flush idiom: `add` never errors if the table exists, then we
    // delete and recreate it fresh so a re-engage cannot stack duplicate rules.
    let mut lines = vec![
        "add table inet chameleon_ks".to_string(),
        "delete table inet chameleon_ks".to_string(),
        "table inet chameleon_ks {".to_string(),
        "\tchain output {".to_string(),
        "\t\ttype filter hook output priority 0; policy drop;".to_string(),
        "\t\toifname \"lo\" accept".to_string(),
        format!("\t\toifname \"{tun}\" accept"),
        // IPv6 neighbour discovery + link-local, so the local link keeps working
        // while v6 internet egress stays blocked (no cleartext v6 leak).
        "\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, \
         nd-router-solicit, nd-router-advert, echo-request } accept"
            .to_string(),
        "\t\tip6 daddr fe80::/10 accept".to_string(),
        // DHCP client, so the lease can renew.
        "\t\tudp sport 68 udp dport 67 accept".to_string(),
    ];
    // The tunnel transport: allow ALL traffic to the server host (handshake,
    // keepalive, reconnect) — it is the trusted endpoint, and being too strict
    // here would stop the tunnel from ever re-establishing.
    match server.ip() {
        std::net::IpAddr::V4(ip) => lines.push(format!("\t\tip daddr {ip} accept")),
        std::net::IpAddr::V6(ip) => lines.push(format!("\t\tip6 daddr {ip} accept")),
    }
    if let Some((net, prefix)) = lan {
        lines.push(format!("\t\tip daddr {net}/{prefix} accept"));
    }
    lines.push("\t}".to_string());
    lines.push("}".to_string());
    lines.join("\n")
}

/// Feed a ruleset to `nft -f -` on stdin (applied atomically).
#[cfg(not(target_os = "windows"))]
fn nft_apply(ruleset: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ChameleonError::KillSwitch(format!("spawning nft failed: {e}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| ChameleonError::KillSwitch("nft stdin unavailable".into()))?
        .write_all(ruleset.as_bytes())
        .map_err(|e| ChameleonError::KillSwitch(format!("writing nft ruleset failed: {e}")))?;
    let out = child
        .wait_with_output()
        .map_err(|e| ChameleonError::KillSwitch(format!("nft failed: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    Err(ChameleonError::KillSwitch(format!(
        "nft rejected the ruleset: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

#[cfg(not(target_os = "windows"))]
fn teardown() {
    // Ignore failure: the table may already be gone (idempotent).
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "chameleon_ks"])
        .output();
}

#[cfg(not(target_os = "windows"))]
fn backend_is_engaged() -> bool {
    Command::new("nft")
        .args(["list", "table", "inet", "chameleon_ks"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The physical default-route interface's own IPv4 subnet (network address +
/// prefix), for the LAN allow rule. `None` if it cannot be determined.
#[cfg(not(target_os = "windows"))]
fn local_subnet() -> Option<(std::net::Ipv4Addr, u8)> {
    let dev = default_route_dev()?;
    iface_ipv4_cidr(&dev)
}

#[cfg(not(target_os = "windows"))]
fn default_route_dev() -> Option<String> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut it = text.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "dev" {
            return it.next().map(|s| s.to_string());
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn iface_ipv4_cidr(dev: &str) -> Option<(std::net::Ipv4Addr, u8)> {
    let out = Command::new("ip")
        .args(["-o", "-f", "inet", "addr", "show", "dev", dev])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "inet" {
                if let Some((ip_s, pfx_s)) = it.next().and_then(|c| c.split_once('/')) {
                    if let (Ok(ip), Ok(pfx)) =
                        (ip_s.parse::<std::net::Ipv4Addr>(), pfx_s.parse::<u8>())
                    {
                        return Some((ipv4_network(ip, pfx), pfx));
                    }
                }
            }
        }
    }
    None
}

/// The network (base) address of `ip` under a `/prefix` mask.
#[cfg(not(target_os = "windows"))]
fn ipv4_network(ip: std::net::Ipv4Addr, prefix: u8) -> std::net::Ipv4Addr {
    let mask = match prefix {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - p),
    };
    std::net::Ipv4Addr::from(u32::from(ip) & mask)
}

// ── Windows Firewall back-end ─────────────────────────────────────────────────
//
// We standardise on PowerShell `*-NetFirewallRule`, not `netsh`: only PowerShell
// can scope an allow rule to the TUN by interface name (`-InterfaceAlias`), and
// it can flip the outbound DEFAULT to Block without rewriting the inbound policy.
//
// Rule precedence matters: in Windows Firewall a Block rule beats an Allow rule,
// so we do NOT add a block rule (it would beat our allows). Instead the profile
// DEFAULT outbound action becomes Block (lowest precedence) and our per-path
// Allow rules win over it. Restore sets the default back to Allow (the Windows
// factory default).
//
// KNOWN GAP: this composes correctly for OUR rules, but the same precedence
// applies to EVERYONE's rules — a pre-existing, unrelated outbound Allow rule
// (installed by other software, or one of Windows' own built-in "Core
// Networking" rules) also wins over our default-block, and there is no
// standard-cmdlet way to make an Allow rule scoped to (say) the physical
// interface lose to a Block rule scoped to the same interface without ALSO
// blocking our own tunnel traffic on that interface (the tunnel's UDP to the
// server leaves via the physical NIC, not the tun). Actually closing this
// requires WFP-level weighted filters, not `New-NetFirewallRule`. Until that
// exists, `other_allow_rules_hint` at least makes the residual exposure
// visible instead of silent.

#[cfg(target_os = "windows")]
fn engage_backend(server: SocketAddr, tun: &str) -> Result<()> {
    let ip = server.ip();
    // Allow rules FIRST, default-block LAST, so there is no window where even the
    // tunnel is black-holed before its allow rule exists.
    let script = format!(
        "$ErrorActionPreference='Stop';\
         Remove-NetFirewallRule -Group 'ChameleonKS' -ErrorAction SilentlyContinue;\
         New-NetFirewallRule -DisplayName 'Chameleon-KS tun' -Group 'ChameleonKS' \
           -Direction Outbound -InterfaceAlias '{tun}' -Action Allow | Out-Null;\
         New-NetFirewallRule -DisplayName 'Chameleon-KS server' -Group 'ChameleonKS' \
           -Direction Outbound -RemoteAddress '{ip}' -Action Allow | Out-Null;\
         New-NetFirewallRule -DisplayName 'Chameleon-KS lan' -Group 'ChameleonKS' \
           -Direction Outbound -RemoteAddress LocalSubnet -Action Allow | Out-Null;\
         New-NetFirewallRule -DisplayName 'Chameleon-KS dhcp' -Group 'ChameleonKS' \
           -Direction Outbound -Protocol UDP -LocalPort 68 -RemotePort 67 -Action Allow | Out-Null;\
         Set-NetFirewallProfile -All -DefaultOutboundAction Block"
    );
    run_powershell(&script)
}

/// Count enabled outbound Allow rules NOT owned by us. See the KNOWN GAP note
/// above: Windows lets any one of these override our default-block, so this
/// is surfaced to the user rather than silently trusted. Best-effort:
/// `None` if the query itself fails (e.g. insufficient privilege to list).
#[cfg(target_os = "windows")]
fn other_allow_rules_hint() -> Option<usize> {
    let script = "(Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow | \
                   Where-Object { $_.Group -ne 'ChameleonKS' }).Count";
    run_powershell_capture(script).ok()?.trim().parse().ok()
}

#[cfg(target_os = "windows")]
fn teardown() {
    // Restore the default FIRST (so connectivity is back even if rule removal
    // hiccups), then drop our allow rules. Best-effort.
    let script = "Set-NetFirewallProfile -All -DefaultOutboundAction Allow;\
         Remove-NetFirewallRule -Group 'ChameleonKS' -ErrorAction SilentlyContinue";
    let _ = run_powershell(script);
}

#[cfg(target_os = "windows")]
fn backend_is_engaged() -> bool {
    let script = "if (Get-NetFirewallRule -Group 'ChameleonKS' -ErrorAction SilentlyContinue) \
         { 'ENGAGED' } else { 'off' }";
    run_powershell_capture(script)
        .map(|out| out.contains("ENGAGED"))
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn run_powershell(script: &str) -> Result<()> {
    let out = command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| ChameleonError::KillSwitch(format!("spawning PowerShell failed: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    Err(ChameleonError::KillSwitch(format!(
        "firewall command failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

#[cfg(target_os = "windows")]
fn run_powershell_capture(script: &str) -> Result<String> {
    let out = command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| ChameleonError::KillSwitch(format!("spawning PowerShell failed: {e}")))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Build a `Command` that never flashes a console window on Windows — the GUI
/// runs on the `windows` subsystem, so every child would otherwise pop a console.
/// (Mirrors `route::command`.) No-op elsewhere.
#[cfg(target_os = "windows")]
fn command(program: &str) -> Command {
    use std::os::windows::process::CommandExt;
    let mut cmd = Command::new(program);
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    cmd
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn ipv4_network_masks_host_bits() {
        use super::ipv4_network;
        use std::net::Ipv4Addr;
        assert_eq!(
            ipv4_network(Ipv4Addr::new(192, 168, 0, 139), 24),
            Ipv4Addr::new(192, 168, 0, 0)
        );
        assert_eq!(
            ipv4_network(Ipv4Addr::new(10, 1, 2, 3), 8),
            Ipv4Addr::new(10, 0, 0, 0)
        );
        assert_eq!(
            ipv4_network(Ipv4Addr::new(172, 16, 200, 5), 12),
            Ipv4Addr::new(172, 16, 0, 0)
        );
        // /32 keeps the whole address; /0 collapses to 0.0.0.0.
        assert_eq!(
            ipv4_network(Ipv4Addr::new(1, 2, 3, 4), 32),
            Ipv4Addr::new(1, 2, 3, 4)
        );
        assert_eq!(
            ipv4_network(Ipv4Addr::new(1, 2, 3, 4), 0),
            Ipv4Addr::new(0, 0, 0, 0)
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn ruleset_has_all_allow_paths_and_drop_policy() {
        use super::build_ruleset;
        use std::net::{Ipv4Addr, SocketAddr};
        let server: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let rs = build_ruleset(
            server,
            "chameleon0",
            Some((Ipv4Addr::new(192, 168, 0, 0), 24)),
        );
        // Default-drop with only the intended egress paths permitted.
        assert!(rs.contains("policy drop"));
        assert!(rs.contains("oifname \"lo\" accept"));
        assert!(rs.contains("oifname \"chameleon0\" accept"));
        assert!(rs.contains("ip daddr 203.0.113.7 accept")); // tunnel transport
        assert!(rs.contains("ip daddr 192.168.0.0/24 accept")); // LAN
        assert!(rs.contains("udp sport 68 udp dport 67 accept")); // DHCP
                                                                  // The idempotent flush idiom must precede the fresh table.
        assert!(rs.starts_with("add table inet chameleon_ks\ndelete table inet chameleon_ks\n"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn ruleset_without_lan_omits_lan_rule() {
        use super::build_ruleset;
        use std::net::SocketAddr;
        let server: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let rs = build_ruleset(server, "chameleon0", None);
        assert!(!rs.contains("192.168"));
        // Server + DHCP paths are still present (fail-closed only drops LAN).
        assert!(rs.contains("ip daddr 203.0.113.7 accept"));
    }

    #[test]
    fn unsafe_tun_name_is_rejected() {
        use super::KillSwitch;
        use std::net::SocketAddr;
        let server: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        assert!(KillSwitch::engage(server, "tun\"; rm -rf /").is_err());
        assert!(KillSwitch::engage(server, "bad'name").is_err());
    }
}
