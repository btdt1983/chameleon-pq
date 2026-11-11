//! Chameleon-PQ desktop GUI (iced, pure Rust). Wired to the client core
//! (`chameleon::client::Client`): load config → secure-by-default warnings →
//! connect (async) → live status (↑tx/↓rx, uptime, last receive).
//!
//! Build (standalone from the core crate): `cargo build --manifest-path gui/Cargo.toml`.
//! NOTE: a real tunnel needs privileges for the TUN adapter (Linux:
//! CAP_NET_ADMIN/sudo; Windows: admin + wintun.dll next to the binary).

// Release builds detach from the console subsystem so NO cmd window opens
// alongside the GUI on Windows. Debug keeps the console for dev output. Nothing
// is lost: all library/tracing output already goes to chameleon-gui.log and the
// panic hook. (Harmless / ignored on non-Windows targets.)
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use chameleon::client::security_warnings;
use chameleon::config::{AppConfig, TrafficProfile};
use chameleon::control::client::ServiceClient;
use chameleon::control::protocol::{
    ErrorCode, KillSwitchState, Phase, PolicySummary, Request, Response, StateSnapshot,
};
use chameleon::control::supervisor::{self, ConnectOutcome, Supervisor};
use iced::widget::{
    button, checkbox, column, container, markdown, pick_list, row, scrollable, svg, text,
    text_input,
};
use iced::{Alignment, Background, Border, Color, Element, Length, Subscription, Task, Theme};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The project's GitHub page (linked from the GUI header).
const REPO_URL: &str = "https://github.com/btdt1983/chameleon-pq";
/// GitHub API endpoint for the latest release — used only when the user
/// presses "Check for updates" (never automatically, never on launch).
const LATEST_RELEASE_API: &str =
    "https://api.github.com/repos/btdt1983/chameleon-pq/releases/latest";

/// One line per profile: what it hides and what it costs. The server follows the
/// profile chosen here (0.9.3+; an older server keeps its own), so the numbers
/// apply in both directions.
fn profile_hint(p: TrafficProfile) -> &'static str {
    match p {
        TrafficProfile::Off => {
            "No timing shaping: full line speed. Burst and idle patterns stay visible."
        }
        TrafficProfile::Balanced => {
            "Hides when you are active, with a small cover-traffic budget. Capped at ~118 Mbit/s each way."
        }
        TrafficProfile::Throughput => {
            "Like Balanced, capped at ~460 Mbit/s. About 20% slower than Fastest on a 300/150 line."
        }
        TrafficProfile::Stealth => {
            "Constant traffic 24/7, capped at ~5 Mbit/s: downloads slow to ~5-10 Mbit/s and it uses bandwidth while connected."
        }
        TrafficProfile::Custom => "Uses the individual [traffic] fields of your config.",
    }
}

pub fn main() -> iced::Result {
    // Diagnostics first: a Windows GUI has no console, so without this every
    // error/panic vanishes with the window. We log to a file NEXT to the binary
    // (and, if present, also to stderr).
    init_diagnostics();
    // Window/taskbar icon (top-left title bar): the chameleon mark.
    let icon =
        iced::window::icon::from_file_data(include_bytes!("../assets/chameleon-icon.png"), None)
            .ok();
    // Window title carries the version too (see chameleon::VERSION doc) — a
    // bug report naming the title bar already tells us the build. iced's
    // `Title` trait wants either a `&'static str` or a closure, not a
    // `String` — a closure is the natural fit here.
    iced::application(
        |_: &App| format!("Chameleon-PQ v{}", chameleon::VERSION),
        App::update,
        App::view,
    )
    .theme(App::theme)
    .window(iced::window::Settings {
        icon,
        ..Default::default()
    })
    .subscription(App::subscription)
    .run_with(App::new)
}

/// Path of the diagnostics log file: next to the executable (on Windows where the
/// user launches the .exe), falling back to the current directory.
fn log_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("chameleon-gui.log")))
        .unwrap_or_else(|| PathBuf::from("chameleon-gui.log"))
}

/// A `Write`/`MakeWriter` that writes to the shared log file.
#[derive(Clone)]
struct FileSink(Arc<Mutex<std::fs::File>>);

impl Write for FileSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.0.lock() {
            Ok(mut f) => f.write(buf),
            Err(_) => Ok(buf.len()), // never panic from the logger
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self.0.lock() {
            Ok(mut f) => f.flush(),
            Err(_) => Ok(()),
        }
    }
}

/// Set up tracing to a log file AND install a panic hook that writes the panic
/// (with location) to that same file. This way the NEXT reproduction records what
/// went wrong — even on a Windows GUI without a console, where nothing is visible
/// right now. The core crate (client + tunnel loops) logs via `tracing`, so once
/// this is set you see handshake, TUN and socket errors in the file.
fn init_diagnostics() {
    use tracing_subscriber::EnvFilter;

    let path = log_path();
    // Windows: catch NATIVE exceptions (access violation / stack overflow) that the
    // Rust panic hook does NOT see — exactly why the window used to vanish without
    // a trace and the log stopped mid-line. The handler writes the exception code,
    // the fault address AND the MODULE (wintun.dll? the .exe itself?) to the log
    // file, so the next crash names itself.
    #[cfg(windows)]
    win_crash::install(path.clone());
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return; // no log file possible -> just let the GUI run
    };
    let sink = FileSink(Arc::new(Mutex::new(file)));

    // Default: info + debug for our own crate. Overridable via RUST_LOG.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,chameleon=debug"));
    let writer_sink = sink.clone();
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(filter)
        .with_writer(move || writer_sink.clone())
        .try_init();

    // Panic hook: write the panic (which would otherwise vanish with the window)
    // to the log file AND stderr, then call the default hook.
    let default_hook = std::panic::take_hook();
    let panic_sink = sink;
    std::panic::set_hook(Box::new(move |info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".into());
        // Capture a backtrace — `force_capture()` ignores RUST_BACKTRACE (which is
        // never set on a double-clicked Windows GUI), so we ALWAYS see the exact
        // crash site, even deep inside tun/wintun or quinn-udp.
        let bt = std::backtrace::Backtrace::force_capture();
        let line = format!("\n=== GUI PANIC @ {loc} ===\n{info}\nbacktrace:\n{bt}\n");
        // best effort: never panic inside the hook
        let mut s = panic_sink.clone();
        let _ = s.write_all(line.as_bytes());
        let _ = s.flush();
        eprintln!("{line}");
        default_hook(info);
    }));

    tracing::info!("Chameleon-PQ GUI started — log: {}", path.display());
}

/// Windows-only: a top-level exception filter that records native crashes (that
/// the Rust panic hook doesn't catch — access violation 0xC0000005, stack overflow
/// 0xC00000FD, etc.). Without this the log just stops and the window vanishes;
/// with it we know the exception code, the fault address AND which module (e.g.
/// `wintun.dll` or the `.exe` itself, into which quinn-udp is compiled) it went
/// wrong in. Purely diagnostic: we log and then let the process crash as usual
/// (EXCEPTION_CONTINUE_SEARCH).
#[cfg(windows)]
mod win_crash {
    use std::io::Write;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::sync::OnceLock;

    static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

    #[allow(dead_code)] // FFI layout: not every field is read
    #[repr(C)]
    struct ExceptionRecord {
        code: u32,
        flags: u32,
        record: *mut ExceptionRecord,
        address: *mut core::ffi::c_void,
        number_parameters: u32,
        information: [usize; 15],
    }
    #[allow(dead_code)] // context_record is not read
    #[repr(C)]
    struct ExceptionPointers {
        exception_record: *mut ExceptionRecord,
        context_record: *mut core::ffi::c_void,
    }
    type Hmodule = *mut core::ffi::c_void;
    type Filter = Option<unsafe extern "system" fn(*mut ExceptionPointers) -> i32>;

    // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | _UNCHANGED_REFCOUNT
    const FROM_ADDRESS: u32 = 0x4;
    const UNCHANGED_REFCOUNT: u32 = 0x2;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetUnhandledExceptionFilter(filter: Filter) -> Filter;
        fn GetModuleHandleExW(flags: u32, addr: *const u16, module: *mut Hmodule) -> i32;
        fn GetModuleFileNameW(module: Hmodule, buf: *mut u16, size: u32) -> u32;
    }

    unsafe extern "system" fn filter(info: *mut ExceptionPointers) -> i32 {
        let (code, addr) = if !info.is_null() && !(*info).exception_record.is_null() {
            let r = (*info).exception_record;
            ((*r).code, (*r).address)
        } else {
            (0u32, core::ptr::null_mut())
        };

        // Which loaded module does the fault address fall in? That names the culprit.
        let mut module: Hmodule = core::ptr::null_mut();
        let mut name = String::from("(unknown)");
        if !addr.is_null()
            && GetModuleHandleExW(
                FROM_ADDRESS | UNCHANGED_REFCOUNT,
                addr as *const u16,
                &mut module,
            ) != 0
        {
            let mut buf = [0u16; 260];
            let n = GetModuleFileNameW(module, buf.as_mut_ptr(), buf.len() as u32) as usize;
            if n > 0 && n <= buf.len() {
                name = std::ffi::OsString::from_wide(&buf[..n])
                    .to_string_lossy()
                    .into_owned();
            }
        }

        if let Some(path) = LOG_PATH.get() {
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(
                    f,
                    "\n=== NATIVE EXCEPTION code=0x{code:08X} addr={addr:p} module={name} ==="
                );
                let _ = f.flush();
            }
        }
        0 // EXCEPTION_CONTINUE_SEARCH: log written, let the process crash normally
    }

    /// Remember the log path and install the filter. Idempotent.
    pub fn install(log_path: PathBuf) {
        let _ = LOG_PATH.set(log_path);
        unsafe {
            SetUnhandledExceptionFilter(Some(filter));
        }
    }
}

/// Talking to the Windows service. Windows-only in practice; the stubs keep the
/// rest of the GUI platform-neutral (and compilable on Linux).
mod svc {
    use super::ServiceClient;

    #[cfg_attr(not(windows), allow(dead_code))]
    pub enum Detect {
        /// The service is installed: all privileged work happens there.
        Installed,
        /// Not installed: run standalone (needs administrator on Windows).
        Absent,
        /// Could not ask; treated as standalone.
        Unknown(String),
    }

    #[cfg(windows)]
    pub fn detect() -> Detect {
        use chameleon::control::service_windows::{installed, Installed};
        match installed() {
            Installed::Yes { .. } => Detect::Installed,
            Installed::No => Detect::Absent,
            Installed::Unknown(e) => Detect::Unknown(e),
        }
    }

    #[cfg(windows)]
    pub async fn connect() -> Result<(ServiceClient, String), String> {
        chameleon::control::pipe_windows::connect_client(
            chameleon::control::pipe_windows::PIPE_NAME,
        )
        .await
    }

    #[cfg(not(windows))]
    pub fn detect() -> Detect {
        Detect::Absent
    }

    #[cfg(not(windows))]
    pub async fn connect() -> Result<(ServiceClient, String), String> {
        Err("the service mode is Windows-only".into())
    }
}

/// How this window gets its tunnel. Decided once at startup from whether the
/// service is INSTALLED (not from whether its pipe answers), and never changed
/// mid-session: a service restart must not flip an administrator's window into
/// standalone mode and start a second tunnel next to the service.
enum Mode {
    /// In-process supervisor (Linux, development, or no service installed).
    Direct,
    /// A thin client of the service.
    Service(ServiceLink),
}

#[derive(Default)]
struct ServiceLink {
    client: Option<ServiceClient>,
    state: Option<StateSnapshot>,
    /// Highest service-log sequence number already shown.
    log_seq: u64,
    /// A connection attempt is in flight.
    linking: bool,
    /// The dropdown has been seeded from the service's profile.
    profile_seeded: bool,
    /// Last connection error shown, to avoid repeating it every second.
    last_error: Option<String>,
}

/// What the status card draws, whichever mode produced it.
struct TunnelView {
    peer: String,
    session_id: u32,
    tx_bytes: u64,
    rx_bytes: u64,
    last_recv_epoch: u64,
    uptime_secs: u64,
}

struct App {
    mode: Mode,
    config_path: String,
    config: Option<AppConfig>,
    server: String,
    /// Selected traffic profile; wins over the config at Connect.
    profile: TrafficProfile,
    /// Owns the tunnel, the kill switch and drop detection (see
    /// `chameleon::control::supervisor`). The GUI only renders its state.
    sup: Supervisor,
    /// Kill switch preference (mirrors config `tun.kill_switch`): engage a
    /// fail-closed firewall while connected so a tunnel drop blocks traffic
    /// instead of leaking to the physical NIC.
    kill_switch: bool,
    warnings: Vec<String>,
    log: Vec<String>,
    /// "Check for updates" outcome, shown in the sidebar. Only ever changes in
    /// response to the user pressing the button — no automatic/startup check.
    update_status: UpdateStatus,
    /// The checked release's notes, pre-parsed for the markdown widget.
    /// `None` until a check has completed successfully at least once.
    release_notes: Option<Vec<markdown::Item>>,
    /// The checked release's page, for the "Open release" link.
    latest_release_url: Option<String>,
}

#[derive(Debug, Clone, Default)]
enum UpdateStatus {
    #[default]
    NotChecked,
    Checking,
    UpToDate,
    Available(String),
    Error(String),
}

/// The subset of a GitHub release API response this app uses.
#[derive(Debug, Clone, serde::Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    body: String,
    html_url: String,
}

/// Parse a `vX.Y.Z` / `X.Y.Z` tag into a comparable tuple. `None` for anything
/// that doesn't fit that shape (so a malformed/unexpected tag degrades to "no
/// comparison possible" instead of a wrong verdict).
fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// Fetch the latest GitHub release. Only ever called from the
/// `Message::CheckForUpdates` handler — on-demand, not on launch.
async fn fetch_latest_release() -> Result<GhRelease, String> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("chameleon-gui/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(LATEST_RELEASE_API)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GitHub API returned {}", resp.status()));
    }
    resp.json::<GhRelease>()
        .await
        .map_err(|e| format!("unexpected response: {e}"))
}

#[derive(Debug, Clone)]
enum Message {
    ConfigPathChanged(String),
    ServerChanged(String),
    /// Open the native file dialog to pick a config.
    BrowseConfig,
    /// Result of the dialog (None = cancelled).
    ConfigPicked(Option<String>),
    /// Profile chosen in the dropdown.
    ProfileChanged(TrafficProfile),
    LoadConfig,
    Connect,
    /// `(connect outcome, kill-switch engage outcome)` — independent of each
    /// other: if the kill switch engaged but the connect itself then failed,
    /// we must still learn about the engaged switch (see the handler).
    Connected(ConnectOutcome),
    Disconnect,
    Tick,
    /// Toggle the kill-switch preference (checkbox).
    ToggleKillSwitch(bool),
    /// Escape hatch: tear the kill switch down and restore connectivity.
    DisableKillSwitch,
    /// A connection attempt to the service finished.
    ServiceConnected(Result<(ServiceClient, String), String>),
    /// The service answered a Connect/Disconnect/SetProfile request.
    ServiceReply(Result<Response, String>),
    /// New service log lines.
    ServiceLogged(Result<Response, String>),
    /// Open the project's GitHub page in the default browser.
    OpenRepo,
    /// User pressed "Check for updates" in the sidebar.
    CheckForUpdates,
    /// The update check completed.
    UpdateChecked(Result<GhRelease, String>),
    /// A link inside the rendered release notes was clicked.
    LinkClicked(markdown::Url),
    /// "Open release ↗" in the sidebar — opens `latest_release_url`.
    OpenLatestRelease,
}

impl App {
    fn new() -> (Self, Task<Message>) {
        // A kill switch still installed at startup means a previous run left it
        // engaged (crash or window-close while connected) — surface it so the
        // user can clear it and get back online.
        let (mode, mut log, first_task) = match svc::detect() {
            svc::Detect::Installed => (
                Mode::Service(ServiceLink {
                    linking: true,
                    ..Default::default()
                }),
                vec!["Connecting to the Chameleon-PQ service …".to_string()],
                Task::perform(svc::connect(), Message::ServiceConnected),
            ),
            other => {
                let mut log = vec!["Load a config and connect.".to_string()];
                if let svc::Detect::Unknown(e) = other {
                    log.push(format!("Could not query the service manager: {e}"));
                }
                (Mode::Direct, log, Task::none())
            }
        };
        let sup = match mode {
            // The service owns the kill switch; do not probe the firewall here.
            Mode::Service(_) => Supervisor::new_unprobed(),
            Mode::Direct => Supervisor::new(),
        };
        if sup.kill_switch_orphan() {
            log.push("⚠ Kill switch is still active from a previous session.".into());
        }
        (
            App {
                mode,
                config_path: "config.toml".into(),
                config: None,
                server: String::new(),
                profile: TrafficProfile::default(),
                sup,
                warnings: Vec::new(),
                log,
                kill_switch: false,
                update_status: UpdateStatus::NotChecked,
                release_notes: None,
                latest_release_url: None,
            },
            first_task,
        )
    }

    // ── View-model: one answer whichever mode is active ──────────────────────

    fn is_connected(&self) -> bool {
        match &self.mode {
            Mode::Direct => self.sup.is_connected(),
            Mode::Service(l) => l
                .state
                .as_ref()
                .is_some_and(|s| s.phase == Phase::Connected),
        }
    }

    fn is_connecting(&self) -> bool {
        match &self.mode {
            Mode::Direct => self.sup.is_connecting(),
            Mode::Service(l) => l
                .state
                .as_ref()
                .is_some_and(|s| s.phase == Phase::Connecting),
        }
    }

    /// Kill switch engaged (or left over) while there is no tunnel.
    fn ks_stranded(&self) -> bool {
        match &self.mode {
            Mode::Direct => {
                !self.sup.is_connected()
                    && !self.sup.is_connecting()
                    && (self.sup.kill_switch_orphan() || self.sup.kill_switch_engaged())
            }
            Mode::Service(l) => l.state.as_ref().is_some_and(|s| {
                s.phase == Phase::Disconnected && s.kill_switch != KillSwitchState::Off
            }),
        }
    }

    /// The administrator policy, in service mode once the service has reported it.
    /// Standalone mode has no policy: everything is allowed.
    fn policy(&self) -> Option<&PolicySummary> {
        match &self.mode {
            Mode::Service(l) => l.state.as_ref().map(|s| &s.policy),
            Mode::Direct => None,
        }
    }

    fn may_disconnect(&self) -> bool {
        self.policy().map_or(true, |p| p.allow_user_disconnect)
    }

    fn may_check_updates(&self) -> bool {
        match &self.mode {
            Mode::Direct => true,
            // Until the policy is known, stay on the safe side.
            Mode::Service(_) => self.policy().is_some_and(|p| p.allow_update_check),
        }
    }

    /// Profiles to offer in the dropdown.
    fn profiles(&self) -> Vec<TrafficProfile> {
        TrafficProfile::ALL
            .iter()
            .copied()
            .filter(|p| self.policy().map_or(true, |pol| pol.profile_allowed(*p)))
            .collect()
    }

    fn tunnel(&self) -> Option<TunnelView> {
        match &self.mode {
            Mode::Direct => self
                .sup
                .status()
                .filter(|s| s.connected)
                .map(|s| TunnelView {
                    peer: s.peer.to_string(),
                    session_id: s.session_id,
                    tx_bytes: s.tx_bytes,
                    rx_bytes: s.rx_bytes,
                    last_recv_epoch: s.last_recv_epoch,
                    uptime_secs: s.uptime_secs,
                }),
            Mode::Service(l) => {
                l.state
                    .as_ref()
                    .and_then(|s| s.tunnel.as_ref())
                    .map(|t| TunnelView {
                        peer: t.peer.clone(),
                        session_id: t.session_id,
                        tx_bytes: t.tx_bytes,
                        rx_bytes: t.rx_bytes,
                        last_recv_epoch: t.last_recv_epoch,
                        uptime_secs: t.uptime_secs,
                    })
            }
        }
    }

    /// Once a second in service mode: reconnect if needed, take the pushed
    /// state, pull new log lines.
    fn service_tick(&mut self) -> Task<Message> {
        let Mode::Service(link) = &mut self.mode else {
            return Task::none();
        };
        let Some(client) = link.client.clone() else {
            if link.linking {
                return Task::none();
            }
            link.linking = true;
            return Task::perform(svc::connect(), Message::ServiceConnected);
        };
        if client.is_closed() {
            link.client = None;
            link.state = None;
            let line = "Lost the connection to the service; reconnecting …";
            self.log(line);
            return Task::none();
        }
        let state = client.state();
        if !link.profile_seeded {
            link.profile_seeded = true;
            self.profile = state.profile;
        }
        self.warnings = state.warnings.clone();
        link.state = Some(state);
        let since = link.log_seq;
        Task::perform(
            async move {
                client
                    .request(Request::GetLog { since })
                    .await
                    .map_err(|e| e.to_string())
            },
            Message::ServiceLogged,
        )
    }

    /// Fire-and-log request to the service (Connect/Disconnect/SetProfile).
    fn service_request(&self, req: Request) -> Task<Message> {
        match &self.mode {
            Mode::Service(ServiceLink {
                client: Some(client),
                ..
            }) => {
                let client = client.clone();
                Task::perform(
                    async move { client.request(req).await.map_err(|e| e.to_string()) },
                    Message::ServiceReply,
                )
            }
            _ => Task::none(),
        }
    }

    fn log(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        if self.log.len() > 200 {
            self.log.remove(0);
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        // Refresh the status every second while there is a client.
        // Service mode always ticks: it reconnects, redraws pushed state and
        // pulls the service log.
        if matches!(self.mode, Mode::Service(_)) || self.sup.is_connected() {
            iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ConfigPathChanged(v) => self.config_path = v,
            Message::ServerChanged(v) => self.server = v,
            Message::OpenRepo => {
                let _ = open::that(REPO_URL);
            }
            Message::BrowseConfig => {
                // Open the native dialog async; the result comes back as ConfigPicked.
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .add_filter("TOML config", &["toml"])
                            .set_title("Choose a Chameleon config")
                            .pick_file()
                            .await
                            .map(|h| h.path().to_string_lossy().into_owned())
                    },
                    Message::ConfigPicked,
                );
            }
            Message::ConfigPicked(picked) => {
                if let Some(path) = picked {
                    self.config_path = path;
                    // Load right away — the user explicitly picked a file.
                    return self.update(Message::LoadConfig);
                }
            }
            Message::ProfileChanged(p) if matches!(self.mode, Mode::Service(_)) => {
                self.profile = p;
                self.log(format!("Profile: {p}"));
                return self.service_request(Request::SetProfile { profile: p });
            }
            Message::ProfileChanged(p) => {
                self.profile = p;
                if let Some(cfg) = &mut self.config {
                    cfg.traffic.profile = p;
                }
                // Recompute the security banner: the "traffic profile off" warning
                // depends on the profile, so switching to a paced profile must clear
                // it (and vice versa). Warnings were otherwise only refreshed on load.
                self.warnings = self
                    .config
                    .as_ref()
                    .map(security_warnings)
                    .unwrap_or_default();
                // Apply live when connected; otherwise it takes effect at Connect.
                let mut tc = self
                    .config
                    .as_ref()
                    .map(|c| c.traffic.clone())
                    .unwrap_or_default();
                tc.profile = p;
                if self.sup.apply_traffic(&tc) {
                    self.log(format!("Profile changed live → {p}"));
                } else {
                    self.log(format!("Profile: {p}"));
                }
            }
            Message::LoadConfig => match AppConfig::load(std::path::Path::new(&self.config_path)) {
                Ok(cfg) => {
                    self.warnings = security_warnings(&cfg);
                    // Adopt the config's server address on every Load. Previously
                    // this only filled an EMPTY field, so after you'd set a server
                    // once, re-loading a config with a CHANGED ip silently kept the
                    // old one — a confusing "it ignores my config" gotcha.
                    if let Some(s) = cfg.network.server_addr {
                        self.server = s.to_string();
                    }
                    // Show the config's profile in the dropdown.
                    self.profile = cfg.traffic.profile;
                    // Mirror the config's kill-switch preference into the toggle.
                    self.kill_switch = cfg.tun.kill_switch;
                    self.log(format!(
                        "Config loaded: {} (profile: {}, kill switch: {})",
                        self.config_path,
                        cfg.traffic.profile,
                        if cfg.tun.kill_switch { "on" } else { "off" }
                    ));
                    self.config = Some(cfg);
                }
                Err(e) => self.log(format!("Config error: {e}")),
            },
            Message::Connect if matches!(self.mode, Mode::Service(_)) => {
                let profile = Some(self.profile);
                if !matches!(&self.mode, Mode::Service(l) if l.client.is_some()) {
                    self.log("Not connected to the service yet.");
                    return Task::none();
                }
                return self.service_request(Request::Connect { profile });
            }
            Message::Connect => {
                let cfg = match &self.config {
                    Some(c) => {
                        // The profile chosen in the dropdown wins over the config.
                        let mut c = c.clone();
                        c.traffic.profile = self.profile;
                        c
                    }
                    None => {
                        self.log("Load a config first.");
                        return Task::none();
                    }
                };
                let server: Option<SocketAddr> =
                    self.server.parse().ok().or(cfg.network.server_addr);
                let Some(server) = server else {
                    self.log("No valid server address (host:port).");
                    return Task::none();
                };
                self.sup.begin_connect();
                self.log(format!("Connecting to {server} …"));
                let want_kill_switch = self.kill_switch;
                return Task::perform(
                    supervisor::connect(cfg, server, want_kill_switch),
                    Message::Connected,
                );
            }
            Message::Connected(outcome) => {
                for line in self.sup.on_connected(outcome) {
                    self.log(line);
                }
            }
            Message::Disconnect if matches!(self.mode, Mode::Service(_)) => {
                return self.service_request(Request::Disconnect {});
            }
            Message::Disconnect => {
                for line in self.sup.disconnect(false) {
                    self.log(line);
                }
            }
            Message::ToggleKillSwitch(on) => {
                self.kill_switch = on;
                if let Some(cfg) = &mut self.config {
                    cfg.tun.kill_switch = on;
                }
                self.log(format!(
                    "Kill switch preference: {}",
                    if on { "on" } else { "off" }
                ));
            }
            Message::DisableKillSwitch if matches!(self.mode, Mode::Service(_)) => {
                self.log(
                    "The service owns the kill switch. An administrator can remove it with: \
                     chameleon-pq killswitch off",
                );
            }
            Message::DisableKillSwitch => {
                self.sup.clear_kill_switch();
                self.log("Kill switch disabled — connectivity restored.");
            }
            Message::Tick if matches!(self.mode, Mode::Service(_)) => {
                return self.service_tick();
            }
            Message::Tick => {
                for line in self.sup.poll() {
                    self.log(line);
                }
            }
            Message::ServiceConnected(res) => {
                let mut line = None;
                if let Mode::Service(link) = &mut self.mode {
                    link.linking = false;
                    match res {
                        Ok((client, note)) => {
                            link.last_error = None;
                            link.state = Some(client.state());
                            link.client = Some(client);
                            line = Some(format!("Connected to the service — {note}"));
                        }
                        Err(e) => {
                            if link.last_error.as_deref() != Some(&e) {
                                line = Some(format!("Service not reachable: {e}"));
                                link.last_error = Some(e);
                            }
                        }
                    }
                }
                if let Some(l) = line {
                    self.log(l);
                }
            }
            Message::ServiceReply(res) => match res {
                Ok(Response::Error { code, message }) => {
                    let what = match code {
                        ErrorCode::Busy => "Busy",
                        ErrorCode::Denied => "Not allowed",
                        ErrorCode::Protocol | ErrorCode::Internal => "Service error",
                    };
                    self.log(format!("{what}: {message}"));
                }
                Ok(_) => {}
                Err(e) => self.log(format!("Service: {e}")),
            },
            Message::ServiceLogged(res) => {
                if let Ok(Response::Log { lines }) = res {
                    for l in lines {
                        if let Mode::Service(link) = &mut self.mode {
                            link.log_seq = link.log_seq.max(l.seq);
                        }
                        self.log(l.text);
                    }
                }
            }
            Message::CheckForUpdates if !self.may_check_updates() => {
                self.log("Update checks are turned off by your administrator.");
            }
            Message::CheckForUpdates => {
                self.update_status = UpdateStatus::Checking;
                return Task::perform(fetch_latest_release(), Message::UpdateChecked);
            }
            Message::UpdateChecked(res) => match res {
                Ok(release) => {
                    self.release_notes = Some(markdown::parse(&release.body).collect());
                    self.latest_release_url = Some(release.html_url.clone());
                    self.update_status = match (
                        parse_semver(&release.tag_name),
                        parse_semver(chameleon::VERSION),
                    ) {
                        (Some(latest), Some(current)) if latest > current => {
                            UpdateStatus::Available(release.tag_name)
                        }
                        (Some(_), Some(_)) => UpdateStatus::UpToDate,
                        _ => UpdateStatus::Error("couldn't compare version numbers".into()),
                    };
                }
                Err(e) => self.update_status = UpdateStatus::Error(e),
            },
            Message::LinkClicked(url) => {
                let _ = open::that(url.to_string());
            }
            Message::OpenLatestRelease => {
                if let Some(url) = &self.latest_release_url {
                    let _ = open::that(url);
                }
            }
        }
        Task::none()
    }

    fn theme(&self) -> Theme {
        // Custom dark palette with a chameleon-green accent; iced derives the
        // button/border shades from these.
        Theme::custom(
            "Chameleon".to_string(),
            iced::theme::Palette {
                background: Color::from_rgb8(0x14, 0x17, 0x1b),
                text: Color::from_rgb8(0xe6, 0xe8, 0xea),
                primary: Color::from_rgb8(0x2e, 0xc1, 0x6b),
                success: Color::from_rgb8(0x2e, 0xc1, 0x6b),
                danger: Color::from_rgb8(0xe5, 0x48, 0x4d),
            },
        )
    }

    fn view(&self) -> Element<'_, Message> {
        let muted = Color::from_rgb8(0x8a, 0x93, 0x9c);

        // Header: chameleon logo + wordmark.
        let logo = svg(svg::Handle::from_memory(
            include_bytes!("../assets/chameleon.svg").as_slice(),
        ))
        .width(Length::Fixed(46.0))
        .height(Length::Fixed(46.0));
        let header = row![
            logo,
            column![
                text(format!("Chameleon-PQ v{}", chameleon::VERSION)).size(24),
                text("Post-quantum VPN").size(12).color(muted),
            ]
            .spacing(1),
            iced::widget::horizontal_space(),
            button(text("GitHub ↗").size(13))
                .style(button::text)
                .on_press(Message::OpenRepo),
        ]
        .spacing(12)
        .align_y(Alignment::Center);

        // Connection settings, grouped in a card.
        let label = |s: &'static str| text(s).size(13).color(muted).width(Length::Fixed(58.0));
        let config_row = row![
            label("Config"),
            text_input("config.toml", &self.config_path).on_input(Message::ConfigPathChanged),
            button(text("Browse…"))
                .style(button::secondary)
                .on_press(Message::BrowseConfig),
            button(text("Load"))
                .style(button::secondary)
                .on_press(Message::LoadConfig),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let server_row = row![
            label("Server"),
            text_input("1.2.3.4:51820", &self.server).on_input(Message::ServerChanged),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let profile_row = row![
            label("Profile"),
            pick_list(self.profiles(), Some(self.profile), Message::ProfileChanged),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        // What the selected profile costs. The numbers are measured on a 300/150
        // Mbit/s line (Telekom speed test) with a server that follows the client.
        let profile_hint = row![
            label(""),
            text(profile_hint(self.profile))
                .size(12)
                .color(muted)
                .width(Length::Fill),
        ]
        .spacing(8);
        let ks_row = row![
            label("Safety"),
            checkbox(
                "Kill switch — block traffic if the tunnel drops (needs full-tunnel)",
                self.kill_switch,
            )
            .on_toggle(Message::ToggleKillSwitch),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let settings = if matches!(self.mode, Mode::Service(_)) {
            // Managed: the administrator's config decides server, keys and kill
            // switch. The user only picks a profile.
            let managed = row![
                label(""),
                text("Managed by the Chameleon-PQ service. Server, keys and kill switch are set by your administrator.")
                    .size(12)
                    .color(muted)
                    .width(Length::Fill),
            ]
            .spacing(8);
            column![managed, profile_row, profile_hint].spacing(10)
        } else {
            column![config_row, server_row, profile_row, profile_hint, ks_row].spacing(10)
        };
        let settings = container(settings)
            .padding(16)
            .width(Length::Fill)
            .style(card_style);

        // Big action button: Connect / Disconnect / (busy).
        let action: Element<Message> = if self.is_connecting() {
            button(text("Connecting …")).padding([10, 22]).into()
        } else if self.is_connected() && !self.may_disconnect() {
            // Shown but inert: the administrator does not allow disconnecting.
            button(text("Disconnect (not allowed)"))
                .style(button::secondary)
                .padding([10, 22])
                .into()
        } else if self.is_connected() {
            button(text("Disconnect"))
                .style(button::danger)
                .padding([10, 22])
                .on_press(Message::Disconnect)
                .into()
        } else {
            button(text("Connect"))
                .style(button::primary)
                .padding([10, 22])
                .on_press(Message::Connect)
                .into()
        };

        // Kill-switch recovery banner: shown when the switch is engaged but the
        // tunnel is NOT connected (an unexpected drop, or a leftover from a
        // previous session). Offers a one-click way back online.
        let ks_stranded = self.ks_stranded();
        let managed = matches!(self.mode, Mode::Service(_));
        let ks_banner: Element<Message> = if ks_stranded {
            container(
                column![
                    text("🔒  Kill switch active — traffic is blocked").size(14),
                    text(if managed {
                        "The tunnel is down. Reconnect to stay protected. To go online \
                         WITHOUT the VPN an administrator can run: chameleon-pq killswitch off"
                    } else {
                        "The tunnel is down. Reconnect to stay protected, or disable the \
                         kill switch to go online WITHOUT the VPN."
                    })
                    .size(12),
                ]
                .push_maybe((!managed).then(|| {
                    button(text("Disable kill switch"))
                        .style(button::danger)
                        .on_press(Message::DisableKillSwitch)
                }))
                .spacing(8),
            )
            .padding([10, 12])
            .width(Length::Fill)
            .style(|_: &Theme| {
                banner_style(
                    Color::from_rgb8(0x53, 0x1b, 0x1b),
                    Color::from_rgb8(0xff, 0xb4, 0xb4),
                )
            })
            .into()
        } else {
            iced::widget::Space::with_height(Length::Shrink).into()
        };

        // Security banner: green when everything is on, red otherwise.
        let banner: Element<Message> = if self.warnings.is_empty() {
            container(text("🛡  Security: fully on"))
                .padding([8, 12])
                .width(Length::Fill)
                .style(|_: &Theme| {
                    banner_style(
                        Color::from_rgb8(0x14, 0x4d, 0x2b),
                        Color::from_rgb8(0x8c, 0xf5, 0xbb),
                    )
                })
                .into()
        } else {
            let mut col = column![text("⚠  Security warnings")].spacing(4);
            for w in &self.warnings {
                col = col.push(text(format!("•  {w}")).size(13));
            }
            container(col)
                .padding([8, 12])
                .width(Length::Fill)
                .style(|_: &Theme| {
                    banner_style(
                        Color::from_rgb8(0x53, 0x1b, 0x1b),
                        Color::from_rgb8(0xff, 0xb4, 0xb4),
                    )
                })
                .into()
        };

        // Status card.
        let tunnel = self.tunnel();
        let waiting = matches!(&self.mode, Mode::Service(l) if l.client.is_none());
        let status_card: Element<Message> = match tunnel {
            Some(s) => container(
                column![
                    text("● Connected")
                        .size(15)
                        .color(Color::from_rgb8(0x39, 0xd9, 0x7f)),
                    text(format!("peer {}   ·   session {}", s.peer, s.session_id))
                        .size(13)
                        .color(muted),
                    row![
                        text(format!("↑ {}", human_bytes(s.tx_bytes))).size(14),
                        text(format!("↓ {}", human_bytes(s.rx_bytes))).size(14),
                        text(format!(
                            "uptime {}s   ·   last recv {}",
                            s.uptime_secs,
                            if s.last_recv_epoch == 0 {
                                "—".to_string()
                            } else {
                                format!("{}s ago", now_secs().saturating_sub(s.last_recv_epoch))
                            }
                        ))
                        .size(12)
                        .color(muted),
                    ]
                    .spacing(18),
                ]
                .spacing(6),
            )
            .padding(16)
            .width(Length::Fill)
            .style(card_style)
            .into(),
            None => container(
                text(if waiting {
                    "○  Waiting for the Chameleon-PQ service …"
                } else {
                    "○  Not connected"
                })
                .size(14)
                .color(muted),
            )
            .padding(16)
            .width(Length::Fill)
            .style(card_style)
            .into(),
        };

        // Log card (monospace).
        let log = container(
            scrollable(
                column(
                    self.log
                        .iter()
                        .map(|l| text(l).size(12).font(iced::Font::MONOSPACE).into())
                        .collect::<Vec<_>>(),
                )
                .spacing(2),
            )
            .height(Length::Fixed(150.0)),
        )
        .padding(12)
        .width(Length::Fill)
        .style(card_style);

        let main_column = scrollable(
            container(
                column![
                    header,
                    banner,
                    ks_banner,
                    settings,
                    action,
                    status_card,
                    text("Log").size(13).color(muted),
                    log,
                ]
                .spacing(16),
            )
            .padding(22)
            .max_width(560),
        );

        row![main_column, self.sidebar(muted)]
            .height(Length::Fill)
            .into()
    }

    /// Right-hand panel: current version, an on-demand "Check for updates"
    /// button (never called automatically — see `Message::CheckForUpdates`),
    /// and the checked release's notes.
    fn sidebar(&self, muted: Color) -> Element<'_, Message> {
        let green = Color::from_rgb8(0x39, 0xd9, 0x7f);
        let red = Color::from_rgb8(0xff, 0xb4, 0xb4);

        let update_row: Element<Message> = match &self.update_status {
            _ if !self.may_check_updates() => {
                text("Update checks are turned off by your administrator.")
                    .size(12)
                    .color(muted)
                    .into()
            }
            UpdateStatus::NotChecked => button(text("Check for updates").size(13))
                .style(button::secondary)
                .on_press(Message::CheckForUpdates)
                .into(),
            UpdateStatus::Checking => text("Checking…").size(13).color(muted).into(),
            UpdateStatus::UpToDate => text("✓ Up to date").size(13).color(green).into(),
            UpdateStatus::Available(ver) => column![
                text(format!("⬆ Update available: {ver}"))
                    .size(13)
                    .color(green),
                button(text("Open release ↗").size(12))
                    .style(button::text)
                    .on_press(Message::OpenLatestRelease),
            ]
            .spacing(4)
            .into(),
            UpdateStatus::Error(e) => column![
                text(format!("Check failed: {e}")).size(12).color(red),
                button(text("Retry").size(12))
                    .style(button::secondary)
                    .on_press(Message::CheckForUpdates),
            ]
            .spacing(4)
            .into(),
        };

        let changelog: Element<Message> = match &self.release_notes {
            Some(items) if !items.is_empty() => scrollable(
                markdown::view(
                    items,
                    markdown::Settings::default(),
                    markdown::Style::from_palette(self.theme().palette()),
                )
                .map(Message::LinkClicked),
            )
            .height(Length::Fill)
            .into(),
            Some(_) => text("(no release notes)").size(12).color(muted).into(),
            None => text("Press \"Check for updates\" to see what's new.")
                .size(12)
                .color(muted)
                .into(),
        };

        container(
            column![
                text("What's new").size(16),
                text(format!("You're on v{}", chameleon::VERSION))
                    .size(12)
                    .color(muted),
                update_row,
                iced::widget::horizontal_rule(1),
                changelog,
            ]
            .spacing(12),
        )
        .padding(16)
        .width(Length::Fixed(280.0))
        .height(Length::Fill)
        .style(card_style)
        .into()
    }
}

/// A settings/status "card": a subtly-raised panel with a rounded border.
fn card_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgb8(0x1e, 0x22, 0x28))),
        border: Border {
            radius: 10.0.into(),
            width: 1.0,
            color: Color::from_rgb8(0x2b, 0x31, 0x39),
        },
        ..Default::default()
    }
}

/// A colored status banner (background + foreground text color).
fn banner_style(bg: Color, fg: Color) -> container::Style {
    container::Style {
        text_color: Some(fg),
        background: Some(Background::Color(bg)),
        border: Border {
            radius: 8.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chameleon::control::policy::Policy;
    use chameleon::control::protocol::TunnelInfo;

    fn snap(phase: Phase, ks: KillSwitchState, tunnel: bool) -> StateSnapshot {
        StateSnapshot {
            phase,
            tunnel: tunnel.then(|| TunnelInfo {
                peer: "203.0.113.5:51820".into(),
                session_id: 9,
                tx_bytes: 1,
                rx_bytes: 2,
                last_recv_epoch: 0,
                uptime_secs: 3,
            }),
            kill_switch: ks,
            profile: TrafficProfile::default(),
            warnings: vec![],
            policy: PolicySummary::from(&Policy::default()),
        }
    }

    fn service_app(state: Option<StateSnapshot>) -> App {
        let (mut app, _) = App::new();
        app.mode = Mode::Service(ServiceLink {
            state,
            ..Default::default()
        });
        app
    }

    #[test]
    fn service_mode_view_model_follows_the_pushed_state() {
        let app = service_app(Some(snap(Phase::Connected, KillSwitchState::Engaged, true)));
        assert!(app.is_connected() && !app.is_connecting() && !app.ks_stranded());
        assert_eq!(app.tunnel().unwrap().session_id, 9);

        let app = service_app(Some(snap(
            Phase::Connecting,
            KillSwitchState::Engaged,
            false,
        )));
        assert!(app.is_connecting() && !app.is_connected() && !app.ks_stranded());

        // Tunnel down but the kill switch still blocks traffic: show the banner.
        let app = service_app(Some(snap(
            Phase::Disconnected,
            KillSwitchState::Engaged,
            false,
        )));
        assert!(app.ks_stranded() && app.tunnel().is_none());
        let app = service_app(Some(snap(
            Phase::Disconnected,
            KillSwitchState::Orphaned,
            false,
        )));
        assert!(app.ks_stranded());
        let app = service_app(Some(snap(Phase::Disconnected, KillSwitchState::Off, false)));
        assert!(!app.ks_stranded());

        // No service connection yet: nothing is claimed.
        let app = service_app(None);
        assert!(!app.is_connected() && !app.is_connecting() && !app.ks_stranded());
    }

    fn with_policy(text: &str) -> App {
        let mut st = snap(Phase::Connected, KillSwitchState::Engaged, true);
        st.policy = PolicySummary::from(&Policy::parse(text, "t").unwrap());
        service_app(Some(st))
    }

    #[test]
    fn the_gui_follows_the_policy_it_is_told() {
        // Standalone / default: everything offered, except update checks in
        // service mode (off by default for a managed machine).
        let app = with_policy("");
        assert!(app.may_disconnect());
        assert!(!app.may_check_updates());
        assert_eq!(app.profiles().len(), TrafficProfile::ALL.len());

        let app = with_policy("allow_user_disconnect = false\nallow_update_check = true");
        assert!(!app.may_disconnect());
        assert!(app.may_check_updates());

        let app = with_policy("allowed_profiles = [\"balanced\", \"stealth\"]");
        assert_eq!(
            app.profiles(),
            vec![TrafficProfile::Stealth, TrafficProfile::Balanced]
        );

        // Before the service has reported anything, do not phone out.
        let app = service_app(None);
        assert!(!app.may_check_updates());

        // Standalone mode has no policy at all.
        let (app, _) = App::new();
        assert!(app.may_disconnect() && app.may_check_updates());
    }

    #[test]
    fn update_check_is_refused_when_the_policy_says_so() {
        let mut app = with_policy("");
        let _ = app.update(Message::CheckForUpdates);
        assert!(app
            .log
            .iter()
            .any(|l| l.contains("turned off by your administrator")));
        assert!(matches!(app.update_status, UpdateStatus::NotChecked));
    }

    #[test]
    fn service_errors_reach_the_log_with_a_readable_prefix() {
        let mut app = service_app(None);
        let _ = app.update(Message::ServiceReply(Ok(Response::Error {
            code: ErrorCode::Denied,
            message: "no".into(),
        })));
        let _ = app.update(Message::ServiceReply(Ok(Response::Error {
            code: ErrorCode::Busy,
            message: "later".into(),
        })));
        assert!(app.log.iter().any(|l| l == "Not allowed: no"));
        assert!(app.log.iter().any(|l| l == "Busy: later"));
    }

    #[test]
    fn connect_without_a_service_connection_does_not_start_anything() {
        let mut app = service_app(None);
        let _ = app.update(Message::Connect);
        assert!(app
            .log
            .iter()
            .any(|l| l == "Not connected to the service yet."));
        // Standalone supervisor untouched: the mode never switches.
        assert!(!app.sup.is_connecting());
        assert!(matches!(app.mode, Mode::Service(_)));
    }

    #[test]
    fn clearing_the_kill_switch_in_service_mode_points_to_the_admin_command() {
        let mut app = service_app(None);
        let _ = app.update(Message::DisableKillSwitch);
        assert!(app.log.iter().any(|l| l.contains("killswitch off")));
    }

    use super::parse_semver;

    #[test]
    fn parses_with_and_without_v_prefix() {
        assert_eq!(parse_semver("v0.8.2"), Some((0, 8, 2)));
        assert_eq!(parse_semver("0.8.2"), Some((0, 8, 2)));
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(parse_semver("not-a-version"), None);
        assert_eq!(parse_semver("v1.2"), None);
        assert_eq!(parse_semver(""), None);
    }

    #[test]
    fn orders_by_numeric_value_not_lexically() {
        // The whole reason for a real parse instead of string compare:
        // "0.9.0" < "0.10.0" lexically flips the wrong way, "10" < "9".
        assert!(parse_semver("0.10.0") > parse_semver("0.9.0"));
        assert!(parse_semver("1.0.0") > parse_semver("0.99.99"));
    }
}
