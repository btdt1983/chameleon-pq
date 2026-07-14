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

use chameleon::client::{build_auth, security_warnings, Client, Status};
use chameleon::config::{AppConfig, TrafficConfig, TrafficProfile};
use chameleon::tun_iface::TunPair;
use iced::widget::{button, column, container, pick_list, row, scrollable, svg, text, text_input};
use iced::{Alignment, Background, Border, Color, Element, Length, Subscription, Task, Theme};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The project's GitHub page (linked from the GUI header).
const REPO_URL: &str = "https://github.com/btdt1983/chameleon-pq";

pub fn main() -> iced::Result {
    // Diagnostics first: a Windows GUI has no console, so without this every
    // error/panic vanishes with the window. We log to a file NEXT to the binary
    // (and, if present, also to stderr).
    init_diagnostics();
    // Window/taskbar icon (top-left title bar): the chameleon mark.
    let icon =
        iced::window::icon::from_file_data(include_bytes!("../assets/chameleon-icon.png"), None)
            .ok();
    iced::application("Chameleon-PQ", App::update, App::view)
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
    /// Open the project's GitHub page in the default browser.
    OpenRepo,
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
                text("Chameleon-PQ").size(24),
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
            label("Profile"),
            pick_list(
                &TrafficProfile::ALL[..],
                Some(self.profile),
                Message::ProfileChanged
            ),
            text(ceiling).size(12).color(muted),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let settings = container(column![config_row, server_row, profile_row].spacing(10))
            .padding(16)
            .width(Length::Fill)
            .style(card_style);

        // Big action button: Connect / Disconnect / (busy).
        let action: Element<Message> = if self.connecting {
            button(text("Connecting …")).padding([10, 22]).into()
        } else if self.client.is_some() {
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
        let status_card: Element<Message> = match &self.status {
            Some(s) if s.connected => container(
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
            _ => container(text("○  Not connected").size(14).color(muted))
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

        scrollable(
            container(
                column![
                    header,
                    banner,
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
        )
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
