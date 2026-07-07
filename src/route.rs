//! Full-tunnel route management for the client — WireGuard-style, so no manual
//! `route add` in PowerShell.
//!
//! On connect we (1) pin the server's UDP endpoint to the physical default
//! gateway ONLY for a genuinely remote server (an on-link/LAN server needs none
//! and pinning it would hairpin through the router), then (2) add `0.0.0.0/1` +
//! `128.0.0.0/1` via the peer's TUN address. Those two halves cover all of
//! `0.0.0.0/0` but are MORE specific than the real default route, so they
//! capture everything without deleting it. On disconnect (or drop) we remove
//! exactly the routes we added.
//!
//! Routes are BOUND TO THE TUN INTERFACE explicitly (Windows `IF <idx>`, Linux
//! `dev <name>`): right after connect the wintun IP is not always configured, so
//! without an explicit interface Windows binds the route to the wrong NIC and
//! the gateway becomes unreachable. Install therefore also RETRIES (the tun may
//! not be ready for a moment). Back-ends: `route` on Windows, `ip route` else.

use crate::error::{ChameleonError, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use tracing::{info, warn};

/// Routes installed for a full-tunnel session; removed on `remove()` or on drop
/// (RAII), so a disconnect — however it happens — always tears them down.
pub struct FullTunnelRoutes {
    peer_gw: Ipv4Addr,
    tun: String,
    /// The pinned server endpoint, if the pin succeeded (else `None`).
    endpoint: Option<IpAddr>,
    removed: bool,
}

impl FullTunnelRoutes {
    /// Route all traffic through the tunnel via `peer_gw` (the peer TUN address),
    /// binding the routes to the `tun` interface. Rolls back on partial failure.
    pub fn install(peer_gw: Ipv4Addr, endpoint: IpAddr, tun: &str) -> Result<Self> {
        let mut me = Self {
            peer_gw,
            tun: tun.to_string(),
            endpoint: None,
            removed: false,
        };

        // 1. Endpoint pin — ONLY for a remote (via-gateway) server, never on-link.
        if let Some(gw) = default_gateway() {
            if endpoint_is_remote(endpoint, gw) {
                match route_op(Op::Add, &format!("{endpoint}/32"), &gw.to_string(), None) {
                    Ok(()) => me.endpoint = Some(endpoint),
                    Err(e) => warn!("endpoint pin via {gw} failed ({e})"),
                }
            } else {
                info!("server {endpoint} is on-link — no endpoint pin needed");
            }
        }

        // 2. Full-tunnel /1 routes via the peer TUN address, on the tun interface.
        route_op(Op::Add, "0.0.0.0/1", &peer_gw.to_string(), Some(tun))?;
        if let Err(e) = route_op(Op::Add, "128.0.0.0/1", &peer_gw.to_string(), Some(tun)) {
            let _ = route_op(Op::Delete, "0.0.0.0/1", &peer_gw.to_string(), Some(tun));
            if let Some(ep) = me.endpoint {
                let _ = route_op(Op::Delete, &format!("{ep}/32"), &peer_gw.to_string(), None);
            }
            return Err(e);
        }
        info!("full-tunnel routes installed (all traffic via {peer_gw} on {tun})");
        Ok(me)
    }

    /// Remove the routes we installed. Idempotent; also runs on drop.
    pub fn remove(&mut self) {
        if self.removed {
            return;
        }
        self.removed = true;
        let gw = self.peer_gw.to_string();
        let tun = self.tun.clone();
        let _ = route_op(Op::Delete, "0.0.0.0/1", &gw, Some(&tun));
        let _ = route_op(Op::Delete, "128.0.0.0/1", &gw, Some(&tun));
        if let Some(ep) = self.endpoint {
            let _ = route_op(Op::Delete, &format!("{ep}/32"), &gw, None);
        }
        info!("full-tunnel routes removed");
    }
}

impl Drop for FullTunnelRoutes {
    fn drop(&mut self) {
        self.remove();
    }
}

#[derive(Clone, Copy)]
enum Op {
    Add,
    Delete,
}

impl Op {
    fn verb(self) -> &'static str {
        match self {
            Op::Add => "add",
            Op::Delete => "delete",
        }
    }
}

// ── Platform back-ends ───────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn route_op(op: Op, cidr: &str, gw: &str, tun: Option<&str>) -> Result<()> {
    let (dst, mask) = cidr_to_dst_mask(cidr)?;
    let mut cmd = Command::new("route");
    match op {
        // metric 1 so our routes win; `IF <idx>` binds to the tun (not a NIC).
        // If the tun has no ifindex yet it is not ready — fail so the caller
        // retries instead of letting Windows bind the route to the wrong NIC.
        Op::Add => {
            cmd.args(["add", &dst, "mask", &mask, gw]);
            if let Some(name) = tun {
                match tun_ifindex(name) {
                    Some(idx) => {
                        cmd.args(["IF", &idx.to_string()]);
                    }
                    None => {
                        return Err(ChameleonError::Route(format!(
                            "tun '{name}' not ready (no interface index yet)"
                        )));
                    }
                }
            }
            cmd.args(["metric", "1"]);
        }
        Op::Delete => {
            cmd.args(["delete", &dst, "mask", &mask]);
        }
    }
    run(cmd, op, cidr)
}

#[cfg(not(target_os = "windows"))]
fn route_op(op: Op, cidr: &str, gw: &str, tun: Option<&str>) -> Result<()> {
    let mut cmd = Command::new("ip");
    match op {
        Op::Add => {
            cmd.args(["route", "add", cidr, "via", gw]);
            if let Some(name) = tun {
                cmd.args(["dev", name]);
            }
        }
        Op::Delete => {
            cmd.args(["route", "del", cidr]);
        }
    }
    run(cmd, op, cidr)
}

/// The current IPv4 default gateway, for the endpoint pin.
#[cfg(target_os = "windows")]
fn default_gateway() -> Option<Ipv4Addr> {
    let out = Command::new("route")
        .args(["print", "-4", "0.0.0.0"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" {
            if let Ok(gw) = f[2].parse::<Ipv4Addr>() {
                return Some(gw);
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn default_gateway() -> Option<Ipv4Addr> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut it = text.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "via" {
            return it.next().and_then(|g| g.parse().ok());
        }
    }
    None
}

/// The Windows interface index of the TUN adapter, by name, via
/// `netsh interface ipv4 show interfaces` (Idx is the first column).
#[cfg(target_os = "windows")]
fn tun_ifindex(name: &str) -> Option<u32> {
    let out = Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        // "  Idx  Met  MTU  State  Name" — Name is the remainder after 4 columns.
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 5 {
            if let Ok(idx) = f[0].parse::<u32>() {
                let iface_name = f[4..].join(" ");
                if iface_name.eq_ignore_ascii_case(name) {
                    return Some(idx);
                }
            }
        }
    }
    None
}

/// Whether the server endpoint is reached via the gateway (remote) rather than
/// on-link. Heuristic: on-link when it shares the default gateway's `/24` — the
/// common LAN case, and exactly when a pin would be harmful.
fn endpoint_is_remote(endpoint: IpAddr, gw: Ipv4Addr) -> bool {
    match endpoint {
        IpAddr::V4(ep) => ep.octets()[..3] != gw.octets()[..3],
        IpAddr::V6(_) => false, // full-tunnel here is IPv4-only; don't pin
    }
}

/// Convert a CIDR (`0.0.0.0/1`, `1.2.3.4/32`) to the dotted (destination, mask)
/// pair that Windows `route` expects.
#[cfg(target_os = "windows")]
fn cidr_to_dst_mask(cidr: &str) -> Result<(String, String)> {
    let (ip, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| ChameleonError::Route(format!("bad CIDR '{cidr}'")))?;
    let p: u32 = prefix
        .parse()
        .map_err(|_| ChameleonError::Route(format!("bad prefix in '{cidr}'")))?;
    if p > 32 {
        return Err(ChameleonError::Route(format!("prefix >32 in '{cidr}'")));
    }
    let mask = if p == 0 { 0u32 } else { u32::MAX << (32 - p) };
    Ok((ip.to_string(), Ipv4Addr::from(mask).to_string()))
}

fn run(mut cmd: Command, op: Op, what: &str) -> Result<()> {
    let out = cmd
        .output()
        .map_err(|e| ChameleonError::Route(format!("spawning route command failed: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    Err(ChameleonError::Route(format!(
        "route {} {what} failed: {}",
        op.verb(),
        stderr.trim()
    )))
}
