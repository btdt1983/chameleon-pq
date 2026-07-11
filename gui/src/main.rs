//! Chameleon-PQ desktop GUI (iced, pure Rust). Wired to the client core
//! (`chameleon::client::Client`): load config → secure-by-default warnings →
//! connect (async) → live status (↑tx/↓rx, uptime, last receive).
//!
//! Build (standalone from the core crate): `cargo build --manifest-path gui/Cargo.toml`.
//! NOTE: a real tunnel needs privileges for the TUN adapter (Linux:
//! CAP_NET_ADMIN/sudo; Windows: admin + wintun.dll next to the binary).

use chameleon::client::{build_auth, security_warnings, Client, Status};
use chameleon::config::{AppConfig, TrafficConfig, TrafficProfile};
use chameleon::tun_iface::TunPair;
use iced::widget::{button, column, container, pick_list, row, scrollable, text, text_input};
use iced::{Color, Element, Length, Subscription, Task};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub fn main() -> iced::Result {
    // Diagnostics first: a Windows GUI has no console, so without this every
    // error/panic vanishes with the window. We log to a file NEXT to the binary
    // (and, if present, also to stderr).
    init_diagnostics();
    iced::application("Chameleon-PQ", App::update, App::view)
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

struct App {
    config_path: String,
    config: Option<AppConfig>,
    server: String,
    /// Selected traffic profile; wins over the config at Connect.
    profile: TrafficProfile,
    client: Option<Arc<Client>>,
    status: Option<Status>,
    warnings: Vec<String>,
    log: Vec<String>,
    connecting: bool,
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
    Connected(Result<Arc<Client>, String>),
    Disconnect,
    Tick,
}

impl App {
    fn new() -> (Self, Task<Message>) {
        (
            App {
                config_path: "config.toml".into(),
                config: None,
                server: String::new(),
                profile: TrafficProfile::default(),
                client: None,
                status: None,
                warnings: Vec::new(),
                log: vec!["Load a config and connect.".into()],
                connecting: false,
            },
            Task::none(),
        )
    }

    fn log(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        if self.log.len() > 200 {
            self.log.remove(0);
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        // Refresh the status every second while there is a client.
        if self.client.is_some() {
            iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ConfigPathChanged(v) => self.config_path = v,
            Message::ServerChanged(v) => self.server = v,
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
                if let Some(client) = &self.client {
                    let mut tc = self
                        .config
                        .as_ref()
                        .map(|c| c.traffic.clone())
                        .unwrap_or_default();
                    tc.profile = p;
                    client.set_traffic(tc.effective());
                    self.log(format!("Profile changed live → {p}"));
                } else {
                    self.log(format!("Profile: {p}"));
                }
            }
            Message::LoadConfig => match AppConfig::load(std::path::Path::new(&self.config_path)) {
                Ok(cfg) => {
                    self.warnings = security_warnings(&cfg);
                    if self.server.is_empty() {
                        if let Some(s) = cfg.network.server_addr {
                            self.server = s.to_string();
                        }
                    }
                    // Show the config's profile in the dropdown.
                    self.profile = cfg.traffic.profile;
                    self.log(format!(
                        "Config loaded: {} (profile: {})",
                        self.config_path, cfg.traffic.profile
                    ));
                    self.config = Some(cfg);
                }
                Err(e) => self.log(format!("Config error: {e}")),
            },
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
                self.connecting = true;
                self.log(format!("Connecting to {server} …"));
                return Task::perform(
                    async move {
                        // Log step by step: if the process dies hard (a native
                        // access violation in wintun/quinn-udp does NOT fire the
                        // Rust panic hook), the last line in the log points to
                        // exactly which step caused the crash.
                        tracing::info!("connect: step 1/3 build_auth");
                        let auth = build_auth(&cfg).map_err(|e| e.to_string())?;
                        tracing::info!("connect: step 2/3 TunPair::create (Windows: admin + wintun.dll next to .exe)");
                        let tun = TunPair::create(&cfg.tun).map_err(|e| e.to_string())?;
                        tracing::info!("connect: step 3/3 Client::connect → {server}");
                        let res = Client::connect(&cfg, server, auth, tun)
                            .await
                            .map(Arc::new)
                            .map_err(|e| e.to_string());
                        tracing::info!("connect: done (ok={})", res.is_ok());
                        res
                    },
                    Message::Connected,
                );
            }
            Message::Connected(res) => {
                self.connecting = false;
                match res {
                    Ok(client) => {
                        self.log(format!(
                            "Connected — session {}",
                            client.status().session_id
                        ));
                        self.status = Some(client.status());
                        self.client = Some(client);
                    }
                    Err(e) => self.log(format!("Connection failed: {e}")),
                }
            }
            Message::Disconnect => {
                if let Some(c) = &self.client {
                    c.disconnect();
                }
                self.client = None;
                self.status = None;
                self.log("Disconnected.");
            }
            Message::Tick => {
                if let Some(c) = &self.client {
                    let st = c.status();
                    // The tunnel loops run in the background; if they die (TUN/socket
                    // error, dead peer, peer close) `connected` flips to false. Make
                    // that visible instead of silently freezing — the reason is in
                    // the log file (see init_diagnostics).
                    if !st.connected {
                        tracing::warn!("tunnel loops stopped — see the log file for the reason");
                        self.log(
                            "Tunnel closed (background loops stopped). \
                             Details are in chameleon-gui.log next to the binary.",
                        );
                        self.client = None;
                        self.status = None;
                    } else {
                        self.status = Some(st);
                    }
                }
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let config_row = row![
            text("Config:").width(Length::Fixed(70.0)),
            text_input("config.toml", &self.config_path).on_input(Message::ConfigPathChanged),
            button(text("Browse…")).on_press(Message::BrowseConfig),
            button(text("Load")).on_press(Message::LoadConfig),
        ]
        .spacing(8);

        let server_row = row![
            text("Server:").width(Length::Fixed(70.0)),
            text_input("1.2.3.4:51820", &self.server).on_input(Message::ServerChanged),
        ]
        .spacing(8);

        // Profile picker with a live ceiling indication (computed via effective()).
        let eff = TrafficConfig {
            profile: self.profile,
            ..Default::default()
        }
        .effective();
        let ceiling = if eff.enabled {
            let pps = eff.rate_pps as u64 * eff.burst as u64;
            format!("≈ {} Mbit/s ceiling", pps * 1232 * 8 / 1_000_000)
        } else {
            "no shaping — WireGuard-comparable".to_string()
        };
        let profile_row = row![
            text("Profile:").width(Length::Fixed(70.0)),
            pick_list(
                &TrafficProfile::ALL[..],
                Some(self.profile),
                Message::ProfileChanged
            ),
            text(ceiling).size(13),
        ]
        .spacing(8);

        // Big action button: Connect / Disconnect / (busy).
        let action: Element<Message> = if self.connecting {
            button(text("Connecting …")).into()
        } else if self.client.is_some() {
            button(text("Disconnect"))
                .on_press(Message::Disconnect)
                .into()
        } else {
            button(text("Connect")).on_press(Message::Connect).into()
        };

        // Status panel.
        let status_panel: Element<Message> = match &self.status {
            Some(s) if s.connected => container(
                column![
                    text("● Connected").color(Color::from_rgb(0.1, 0.7, 0.2)),
                    text(format!("peer: {}   session: {}", s.peer, s.session_id)),
                    text(format!(
                        "↑ {}   ↓ {}",
                        human_bytes(s.tx_bytes),
                        human_bytes(s.rx_bytes)
                    )),
                    text(format!(
                        "uptime: {}s   last received: {}",
                        s.uptime_secs,
                        if s.last_recv_epoch == 0 {
                            "—".to_string()
                        } else {
                            format!("{}s ago", now_secs().saturating_sub(s.last_recv_epoch))
                        }
                    )),
                ]
                .spacing(4),
            )
            .padding(8)
            .into(),
            _ => text("○ Not connected").into(),
        };

        // Security banner: red if something is weaker, green if everything is on.
        let banner: Element<Message> = if self.warnings.is_empty() {
            container(text("Security: fully on").color(Color::WHITE))
                .padding(8)
                .style(|_| box_style(Color::from_rgb(0.12, 0.45, 0.18)))
                .width(Length::Fill)
                .into()
        } else {
            let mut col = column![text("⚠ Security warnings").color(Color::WHITE)].spacing(4);
            for w in &self.warnings {
                col = col.push(text(format!("• {w}")).color(Color::WHITE));
            }
            container(col)
                .padding(8)
                .style(|_| box_style(Color::from_rgb(0.55, 0.13, 0.13)))
                .width(Length::Fill)
                .into()
        };

        let log = scrollable(
            column(
                self.log
                    .iter()
                    .map(|l| text(l).size(13).into())
                    .collect::<Vec<_>>(),
            )
            .spacing(2),
        )
        .height(Length::Fixed(150.0));

        container(
            column![
                text("Chameleon-PQ").size(26),
                banner,
                config_row,
                server_row,
                profile_row,
                action,
                status_panel,
                text("Log:"),
                log,
            ]
            .spacing(12),
        )
        .padding(16)
        .into()
    }
}

/// Background color for a banner (white text on top).
fn box_style(bg: Color) -> container::Style {
    container::Style {
        text_color: Some(Color::WHITE),
        background: Some(iced::Background::Color(bg)),
        border: iced::Border {
            radius: 6.0.into(),
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
