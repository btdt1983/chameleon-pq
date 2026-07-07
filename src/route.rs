//! Full-tunnel route management for the client — WireGuard-style, so no manual
//! `route add` in PowerShell.
//!
//! On connect we (1) pin the server's UDP endpoint to the physical default
//! gateway so the tunnel's own encrypted packets don't recurse back into the
//! tunnel, then (2) add `0.0.0.0/1` + `128.0.0.0/1` via the peer's TUN address.
//! Those two halves cover all of `0.0.0.0/0` but are MORE specific than the
//! real default route, so they capture everything without deleting it — and a
//! server on the local LAN stays reachable via its own on-link `/24`. On
//! disconnect (or drop) we remove exactly the routes we added.
//!
//! Best-effort: a server that is already on-link needs no endpoint pin, so a
//! failing pin is logged and ignored. Platform back-ends: `route` on Windows,
//! `ip route` elsewhere.

use crate::error::{ChameleonError, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use tracing::{info, warn};

/// Routes installed for a full-tunnel session; removed on `remove()` or on drop
/// (RAII), so a disconnect — however it happens — always tears them down.
pub struct FullTunnelRoutes {
    peer_gw: Ipv4Addr,
    /// The pinned server endpoint, if the pin succeeded (else `None`).
    endpoint: Option<IpAddr>,
    removed: bool,
}

impl FullTunnelRoutes {
    /// Route all traffic through the tunnel: pin `endpoint` to the physical
    /// gateway, then send `0.0.0.0/1` + `128.0.0.0/1` via `peer_gw` (the peer's
    /// TUN address). Rolls back on partial failure.
    pub fn install(peer_gw: Ipv4Addr, endpoint: IpAddr) -> Result<Self> {
        let mut me = Self {
            peer_gw,
            endpoint: None,
            removed: false,
        };

        // 1. Endpoint pin (best-effort — an on-link/LAN server needs none).
        match default_gateway() {
            Some(gw) => match route_op(Op::Add, &format!("{endpoint}/32"), &gw.to_string()) {
                Ok(()) => me.endpoint = Some(endpoint),
                Err(e) => warn!("endpoint pin via {gw} failed ({e}); assuming on-link server"),
            },
            None => warn!("no default gateway found; skipping endpoint pin (assuming on-link)"),
        }

        // 2. Full-tunnel /1 routes via the peer TUN address. Roll back the first
        //    if the second fails, so we never leave a half-applied full tunnel.
        route_op(Op::Add, "0.0.0.0/1", &peer_gw.to_string())?;
        if let Err(e) = route_op(Op::Add, "128.0.0.0/1", &peer_gw.to_string()) {
            let _ = route_op(Op::Delete, "0.0.0.0/1", &peer_gw.to_string());
            if let Some(ep) = me.endpoint {
                let _ = route_op(Op::Delete, &format!("{ep}/32"), &peer_gw.to_string());
            }
            return Err(e);
        }
        info!("full-tunnel routes installed (all traffic via {peer_gw})");
        Ok(me)
    }

    /// Remove the routes we installed. Idempotent; also runs on drop.
    pub fn remove(&mut self) {
        if self.removed {
            return;
        }
        self.removed = true;
        let gw = self.peer_gw.to_string();
        let _ = route_op(Op::Delete, "0.0.0.0/1", &gw);
        let _ = route_op(Op::Delete, "128.0.0.0/1", &gw);
        if let Some(ep) = self.endpoint {
            let _ = route_op(Op::Delete, &format!("{ep}/32"), &gw);
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
fn route_op(op: Op, cidr: &str, gw: &str) -> Result<()> {
    let (dst, mask) = cidr_to_dst_mask(cidr)?;
    let mut cmd = Command::new("route");
    match op {
        // metric 1 so our routes win over the existing default route.
        Op::Add => {
            cmd.args(["add", &dst, "mask", &mask, gw, "metric", "1"]);
        }
        // A delete matches on destination; the gateway is not required.
        Op::Delete => {
            cmd.args(["delete", &dst, "mask", &mask]);
        }
    }
    run(cmd, op, cidr)
}

#[cfg(not(target_os = "windows"))]
fn route_op(op: Op, cidr: &str, gw: &str) -> Result<()> {
    let mut cmd = Command::new("ip");
    match op {
        Op::Add => {
            cmd.args(["route", "add", cidr, "via", gw]);
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
    // `route print -4 0.0.0.0`: the active-routes line "0.0.0.0 0.0.0.0 <gw> ..."
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
    // `ip route show default`: "default via <gw> dev <if> ..."
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
