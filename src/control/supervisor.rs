//! Owns the tunnel lifecycle: connect, disconnect, kill switch, drop detection.
//!
//! This is the logic that used to live inside the GUI's `update()`. It is moved
//! here verbatim so the same code can later run inside a Windows service. Two
//! halves, split so no lock is ever held across an await and the connect future
//! stays `Send + 'static` (the GUI hands it to an async task runner):
//!
//! * [`connect`]: free async function, the former `Task::perform` body. Pure
//!   side effects, no shared state; returns a [`ConnectOutcome`].
//! * [`Supervisor`]: owned state plus synchronous methods that apply an outcome
//!   or a user action. They return the user-facing log lines as data, so a
//!   frontend only has to render them.
//!
//! Invariants carried over unchanged (do not "tidy" these):
//! * Connect order: build_auth, `TunPair::create`, kill-switch engage, `Client::connect`.
//! * The client and the kill switch are held separately: an unexpected tunnel
//!   drop clears the client but leaves the kill switch engaged (fail-closed).
//!   A failed connect likewise leaves an already-engaged kill switch up.
//! * Only a deliberate [`Supervisor::disconnect`] takes the kill switch down.

use crate::client::{build_auth, Client, Status};
use crate::config::{AppConfig, TrafficConfig};
use crate::killswitch::KillSwitch;
use crate::tun_iface::TunPair;
use std::net::SocketAddr;
use std::sync::Arc;

/// `(connect outcome, kill-switch engage outcome)`, produced by [`connect`].
/// The two are independent: if the kill switch engaged but the connect itself
/// then failed, we must still learn about the engaged switch.
pub type ConnectOutcome = (
    Result<Arc<Client>, String>,
    Option<Result<KillSwitch, String>>,
);

/// Establish the tunnel: auth, TUN adapter, optional kill switch, handshake.
///
/// `cfg` must already carry the effective traffic profile. Needs the same
/// privileges as TUN/route creation (admin / `CAP_NET_ADMIN`).
pub async fn connect(cfg: AppConfig, server: SocketAddr, want_kill_switch: bool) -> ConnectOutcome {
    // Log step by step: if the process dies hard (a native access violation in
    // wintun/quinn-udp does NOT fire the Rust panic hook), the last line in the
    // log points to exactly which step caused the crash.
    tracing::info!("connect: step 1/3 build_auth");
    let auth = match build_auth(&cfg) {
        Ok(a) => a,
        Err(e) => return (Err(e.to_string()), None),
    };
    tracing::info!("connect: step 2/3 TunPair::create (Windows: admin + wintun.dll next to .exe)");
    let tun = match TunPair::create(&cfg.tun) {
        Ok(t) => t,
        Err(e) => return (Err(e.to_string()), None),
    };

    // Engage the kill switch now: the tun interface exists (needed: Windows'
    // New-NetFirewallRule -InterfaceAlias errors "interface not found" against
    // an adapter that isn't registered yet), but full-tunnel routing/DNS haven't
    // been installed by Client::connect below yet, so there's still no window
    // where they're live without fail-closed backing. A couple of retries: the
    // adapter can take a brief moment to become visible to Windows right after
    // creation (same settling delay Client::connect's own route-install retries
    // around).
    let ks: Option<Result<KillSwitch, String>> = if want_kill_switch {
        if cfg.tun.route_all {
            let mut attempt = KillSwitch::engage(server, &cfg.tun.name);
            for _ in 0..4 {
                if attempt.is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                attempt = KillSwitch::engage(server, &cfg.tun.name);
            }
            Some(attempt.map_err(|e| e.to_string()))
        } else {
            Some(Err(
                "skipped: needs full-tunnel (tun.route_all = true)".into()
            ))
        }
    } else {
        None
    };

    tracing::info!("connect: step 3/3 Client::connect → {server}");
    let res = Client::connect(&cfg, server, auth, tun)
        .await
        .map(Arc::new)
        .map_err(|e| e.to_string());
    tracing::info!("connect: done (ok={})", res.is_ok());
    (res, ks)
}

/// Tunnel lifecycle state. Not `Clone`: it owns the kill-switch guard.
#[derive(Debug)]
pub struct Supervisor {
    client: Option<Arc<Client>>,
    status: Option<Status>,
    connecting: bool,
    /// The active kill-switch guard. Held HERE (not in `Client`) on purpose: an
    /// unexpected drop clears `client`, and the switch must survive that. `Some`
    /// only while engaged.
    ks: Option<KillSwitch>,
    /// A kill switch detected at construction that we did NOT create this
    /// session (left over from a crash / app close).
    ks_orphan: bool,
    /// Where the user finds the reason for a dropped tunnel; embedded in the
    /// "Tunnel closed" log line. The GUI's default names its own log file.
    log_hint: String,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Supervisor {
    /// Probes for an orphaned kill switch (`KillSwitch::is_engaged`).
    pub fn new() -> Self {
        Self::with_orphan(KillSwitch::is_engaged())
    }

    /// An idle supervisor that does not probe the firewall. For a frontend that
    /// delegates to the service and never uses its own supervisor.
    pub fn new_unprobed() -> Self {
        Self::with_orphan(false)
    }

    pub(super) fn with_orphan(ks_orphan: bool) -> Self {
        Self {
            log_hint: "chameleon-gui.log next to the binary".into(),
            client: None,
            status: None,
            connecting: false,
            ks: None,
            ks_orphan,
        }
    }

    /// Override the log location named in the "Tunnel closed" line.
    pub fn set_log_hint(&mut self, hint: impl Into<String>) {
        self.log_hint = hint.into();
    }

    pub fn is_connecting(&self) -> bool {
        self.connecting
    }

    pub fn is_connected(&self) -> bool {
        self.client.is_some()
    }

    pub fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }

    /// Kill switch engaged by this supervisor.
    pub fn kill_switch_engaged(&self) -> bool {
        self.ks.is_some()
    }

    /// Kill switch left over from an earlier run.
    pub fn kill_switch_orphan(&self) -> bool {
        self.ks_orphan
    }

    /// Mark a [`connect`] as in flight. Call right before spawning it.
    pub fn begin_connect(&mut self) {
        self.connecting = true;
    }

    /// Apply the result of [`connect`]. Returns the log lines to show.
    pub fn on_connected(&mut self, outcome: ConnectOutcome) -> Vec<String> {
        let (client_res, ks) = outcome;
        let mut log = Vec::new();
        self.connecting = false;
        match ks {
            Some(Ok(k)) => {
                log.push("Kill switch engaged — traffic is locked to the tunnel.".into());
                // Windows only: a pre-existing outbound Allow rule (from other
                // software, or a Windows built-in) can override our
                // default-block — see killswitch.rs. Surface that instead of
                // implying full protection.
                if let Some(n) = k.other_allow_rules {
                    if n > 0 {
                        log.push(format!(
                            "⚠ {n} other outbound-allow firewall rule(s) found — \
                             traffic matching one of those could bypass the kill switch."
                        ));
                    }
                }
                self.ks = Some(k);
                self.ks_orphan = false;
            }
            Some(Err(e)) => log.push(format!("Kill switch: {e}")),
            None => {}
        }
        match client_res {
            Ok(client) => {
                log.push(format!(
                    "Connected — session {}",
                    client.status().session_id
                ));
                // The kill switch (if requested) was already engaged above,
                // before Client::connect started.
                self.status = Some(client.status());
                self.client = Some(client);
            }
            Err(e) => {
                log.push(format!("Connection failed: {e}"));
                // The kill switch was engaged pre-emptively (set into self.ks by
                // the `ks` match just above); a failed attempt leaves no tunnel,
                // so it stays up fail-closed rather than being silently dropped
                // — make that visible instead of leaving the user to wonder why
                // they're offline.
                if self.ks.is_some() {
                    log.push(
                        "⚠ Kill switch still ACTIVE — traffic stays blocked. Retry, \
                         or disable the kill switch to go online without the VPN."
                            .into(),
                    );
                }
            }
        }
        log
    }

    /// Deliberate disconnect. Normally takes the kill switch down too (fail-open
    /// is correct HERE: the user asked to stop). With `keep_kill_switch` (policy
    /// `enforced`) the tunnel closes but the kill switch stays engaged, so the
    /// user is offline rather than unprotected. Returns the log lines.
    pub fn disconnect(&mut self, keep_kill_switch: bool) -> Vec<String> {
        let mut log = Vec::new();
        if let Some(c) = &self.client {
            c.disconnect();
        }
        self.client = None;
        self.status = None;
        if keep_kill_switch {
            if self.ks.is_some() {
                log.push("Kill switch stays engaged (enforced by your administrator).".into());
            }
        } else if let Some(mut k) = self.ks.take() {
            k.disengage();
            log.push("Kill switch disengaged.".into());
        }
        log.push("Disconnected.".into());
        log
    }

    /// Orderly teardown for a process that is exiting (service stop). Unlike
    /// [`Self::disconnect`] this does not return until the tunnel task has
    /// fully dropped, so routes, DNS and the TUN adapter are restored before the
    /// caller reports "stopped". Then the kill switch is released (an admin
    /// stopping the service is a deliberate stop; a crash never gets here and
    /// leaves it engaged).
    pub async fn shutdown(&mut self) -> Vec<String> {
        let mut log = Vec::new();
        if let Some(c) = self.client.take() {
            c.disconnect_and_wait().await;
        }
        self.status = None;
        self.connecting = false;
        if let Some(mut k) = self.ks.take() {
            k.disengage();
            log.push("Kill switch disengaged.".into());
        }
        log.push("Stopped.".into());
        log
    }

    /// Periodic refresh (the GUI's 1 s tick). Detects a tunnel that died in the
    /// background and refreshes the status otherwise. Returns log lines.
    pub fn poll(&mut self) -> Vec<String> {
        let mut log = Vec::new();
        if let Some(c) = &self.client {
            let st = c.status();
            // The tunnel loops run in the background; if they die (TUN/socket
            // error, dead peer, peer close) `connected` flips to false. Make
            // that visible instead of silently freezing — the reason is in the
            // log file.
            if !st.connected {
                tracing::warn!("tunnel loops stopped — see the log file for the reason");
                log.push(format!(
                    "Tunnel closed (background loops stopped). Details are in {}.",
                    self.log_hint
                ));
                self.client = None;
                self.status = None;
                // Do NOT disengage the kill switch here: this is exactly the
                // unexpected-drop case it exists for. It stays engaged
                // (fail-closed); the frontend offers a way to disable it.
                if self.ks.is_some() {
                    log.push(
                        "⚠ Kill switch ACTIVE — traffic is blocked. Reconnect, \
                         or disable the kill switch to go online without the VPN."
                            .into(),
                    );
                }
            } else {
                self.status = Some(st);
            }
        }
        log
    }

    /// Re-profile the running tunnel without reconnecting. Returns `false` when
    /// there is no tunnel (the profile then takes effect at the next connect).
    pub fn apply_traffic(&self, traffic: &TrafficConfig) -> bool {
        match &self.client {
            Some(client) => {
                client.set_traffic(traffic.effective());
                true
            }
            None => false,
        }
    }

    /// Escape hatch: force-remove the kill switch and restore connectivity,
    /// whether or not this supervisor engaged it.
    pub fn clear_kill_switch(&mut self) {
        KillSwitch::clear();
        self.ks = None;
        self.ks_orphan = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Scope note: these cover the state transitions that need no network, TUN
    // or privileges. A full `connect()` needs a live responder and root/admin
    // for the adapter, so it is exercised by the manual end-to-end run, not here.

    #[test]
    fn new_state_is_idle() {
        let s = Supervisor::with_orphan(false);
        assert!(!s.is_connected() && !s.is_connecting());
        assert!(!s.kill_switch_engaged() && !s.kill_switch_orphan());
        assert!(s.status().is_none());
    }

    #[test]
    fn begin_connect_sets_connecting_and_failure_clears_it() {
        let mut s = Supervisor::with_orphan(false);
        s.begin_connect();
        assert!(s.is_connecting());
        let log = s.on_connected((Err("boom".into()), None));
        assert!(!s.is_connecting() && !s.is_connected());
        assert_eq!(log, vec!["Connection failed: boom".to_string()]);
        assert!(!s.kill_switch_engaged());
    }

    #[test]
    fn kill_switch_error_is_reported_and_not_held() {
        let mut s = Supervisor::with_orphan(false);
        let log = s.on_connected((
            Err("x".into()),
            Some(Err(
                "skipped: needs full-tunnel (tun.route_all = true)".into()
            )),
        ));
        assert_eq!(
            log,
            vec![
                "Kill switch: skipped: needs full-tunnel (tun.route_all = true)".to_string(),
                "Connection failed: x".to_string(),
            ]
        );
        assert!(!s.kill_switch_engaged());
    }

    #[test]
    fn disconnect_while_idle_is_a_noop_that_still_reports() {
        let mut s = Supervisor::with_orphan(false);
        assert_eq!(s.disconnect(false), vec!["Disconnected.".to_string()]);
        assert_eq!(s.disconnect(true), vec!["Disconnected.".to_string()]);
        assert!(!s.is_connected());
    }

    #[test]
    fn poll_while_idle_is_silent() {
        let mut s = Supervisor::with_orphan(false);
        assert!(s.poll().is_empty());
    }

    #[test]
    fn apply_traffic_without_tunnel_reports_false() {
        let s = Supervisor::with_orphan(false);
        assert!(!s.apply_traffic(&TrafficConfig::default()));
    }

    #[test]
    fn orphan_flag_is_kept_until_cleared_by_a_successful_engage() {
        let mut s = Supervisor::with_orphan(true);
        assert!(s.kill_switch_orphan());
        // A failed connect without a kill switch does not touch the flag.
        s.on_connected((Err("x".into()), None));
        assert!(s.kill_switch_orphan());
    }
}
