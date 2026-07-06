//! Chameleon-PQ desktop-GUI (iced, pure Rust). Bedraad aan de client-core
//! (`chameleon::client::Client`): config laden → secure-by-default waarschuwingen
//! → verbinden (async) → live status (↑tx/↓rx, uptime, laatste ontvangst).
//!
//! Bouwen (los van de core-crate): `cargo build --manifest-path gui/Cargo.toml`.
//! LET OP: een echte tunnel vereist rechten voor de TUN-adapter (Linux:
//! CAP_NET_ADMIN/sudo; Windows: admin + wintun.dll naast de binary).

use chameleon::client::{build_auth, security_warnings, Client, Status};
use chameleon::config::AppConfig;
use chameleon::tun_iface::TunPair;
use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Color, Element, Length, Subscription, Task};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub fn main() -> iced::Result {
    // Diagnostiek eerst: een Windows-GUI heeft geen console, dus zonder dit
    // verdwijnt élke fout/panic met het venster. We loggen naar een bestand
    // NAAST de binary (en, indien aanwezig, ook naar stderr).
    init_diagnostics();
    iced::application("Chameleon-PQ", App::update, App::view)
        .subscription(App::subscription)
        .run_with(App::new)
}

/// Pad van het diagnostiek-logbestand: naast de executable (op Windows waar de
/// gebruiker de .exe start), met terugval op de huidige map.
fn log_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("chameleon-gui.log")))
        .unwrap_or_else(|| PathBuf::from("chameleon-gui.log"))
}

/// Een `Write`/`MakeWriter` die naar het gedeelde logbestand schrijft.
#[derive(Clone)]
struct FileSink(Arc<Mutex<std::fs::File>>);

impl Write for FileSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.0.lock() {
            Ok(mut f) => f.write(buf),
            Err(_) => Ok(buf.len()), // nooit paniceren vanuit de logger
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self.0.lock() {
            Ok(mut f) => f.flush(),
            Err(_) => Ok(()),
        }
    }
}

/// Zet tracing naar een logbestand op én installeer een panic-hook die de panic
/// (met locatie) naar datzelfde bestand schrijft. Zo legt de VOLGENDE reproductie
/// vast wát er misgaat — ook op een Windows-GUI zonder console, waar nu niets
/// zichtbaar is. De core-crate (client + tunnel-loops) logt via `tracing`, dus
/// zodra dit staat zie je handshake-, TUN- en socket-fouten in het bestand.
fn init_diagnostics() {
    use tracing_subscriber::EnvFilter;

    let path = log_path();
    // Windows: vang NATIVE exceptions (access violation / stack overflow) die de
    // Rust-panic-hook NIET ziet — precies waarom het venster tot nu toe spoorloos
    // verdween en het log midden in een regel stopte. De handler schrijft de
    // exception-code, het fault-adres én de MODULE (wintun.dll? de .exe zelf?)
    // naar het logbestand, zodat de volgende crash zichzelf benoemt.
    #[cfg(windows)]
    win_crash::install(path.clone());
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return; // geen logbestand mogelijk -> laat de GUI gewoon draaien
    };
    let sink = FileSink(Arc::new(Mutex::new(file)));

    // Standaard: info + debug voor onze eigen crate. Te overrulen via RUST_LOG.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,chameleon=debug"));
    let writer_sink = sink.clone();
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(filter)
        .with_writer(move || writer_sink.clone())
        .try_init();

    // Panic-hook: schrijf de panic (die anders met het venster verdwijnt) naar
    // het logbestand én stderr, en roep daarna de standaard-hook aan.
    let default_hook = std::panic::take_hook();
    let panic_sink = sink;
    std::panic::set_hook(Box::new(move |info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "onbekend".into());
        // Backtrace meepakken — `force_capture()` negeert RUST_BACKTRACE (dat
        // op een dubbelgeklikte Windows-GUI nooit gezet is), zodat we ALTIJD de
        // exacte crash-plek zien, ook diep in tun/wintun of quinn-udp.
        let bt = std::backtrace::Backtrace::force_capture();
        let line = format!("\n=== GUI PANIC @ {loc} ===\n{info}\nbacktrace:\n{bt}\n");
        // best-effort: nooit zelf paniceren in de hook
        let mut s = panic_sink.clone();
        let _ = s.write_all(line.as_bytes());
        let _ = s.flush();
        eprintln!("{line}");
        default_hook(info);
    }));

    tracing::info!("Chameleon-PQ GUI gestart — log: {}", path.display());
}

/// Windows-only: een top-level exception-filter die native crashes (die de
/// Rust-panic-hook niet vangt — access violation 0xC0000005, stack overflow
/// 0xC00000FD, enz.) vastlegt. Zonder dit stopt het log gewoon en verdwijnt het
/// venster; mét dit weten we de exception-code, het fault-adres én in wélke
/// module (bv. `wintun.dll` of de `.exe` zelf, waar quinn-udp in mee-compileert)
/// het misging. Puur diagnostisch: we loggen en laten het proces daarna gewoon
/// crashen (EXCEPTION_CONTINUE_SEARCH).
#[cfg(windows)]
mod win_crash {
    use std::io::Write;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::sync::OnceLock;

    static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

    #[allow(dead_code)] // FFI-layout: niet elk veld wordt gelezen
    #[repr(C)]
    struct ExceptionRecord {
        code: u32,
        flags: u32,
        record: *mut ExceptionRecord,
        address: *mut core::ffi::c_void,
        number_parameters: u32,
        information: [usize; 15],
    }
    #[allow(dead_code)] // context_record wordt niet gelezen
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

        // In wélke geladen module valt het fault-adres? Dat benoemt de dader.
        let mut module: Hmodule = core::ptr::null_mut();
        let mut name = String::from("(onbekend)");
        if !addr.is_null()
            && GetModuleHandleExW(FROM_ADDRESS | UNCHANGED_REFCOUNT, addr as *const u16, &mut module)
                != 0
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
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(
                    f,
                    "\n=== NATIVE EXCEPTION code=0x{code:08X} addr={addr:p} module={name} ==="
                );
                let _ = f.flush();
            }
        }
        0 // EXCEPTION_CONTINUE_SEARCH: log gezet, laat het proces normaal crashen
    }

    /// Onthoud het logpad en installeer de filter. Idempotent.
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
                client: None,
                status: None,
                warnings: Vec::new(),
                log: vec!["Laad een config en verbind.".into()],
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
        // Ververs de status elke seconde zolang er een client is.
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
            Message::LoadConfig => match AppConfig::load(std::path::Path::new(&self.config_path)) {
                Ok(cfg) => {
                    self.warnings = security_warnings(&cfg);
                    if self.server.is_empty() {
                        if let Some(s) = cfg.network.server_addr {
                            self.server = s.to_string();
                        }
                    }
                    self.log(format!("Config geladen: {}", self.config_path));
                    self.config = Some(cfg);
                }
                Err(e) => self.log(format!("Config-fout: {e}")),
            },
            Message::Connect => {
                let cfg = match &self.config {
                    Some(c) => c.clone(),
                    None => {
                        self.log("Laad eerst een config.");
                        return Task::none();
                    }
                };
                let server: Option<SocketAddr> =
                    self.server.parse().ok().or(cfg.network.server_addr);
                let Some(server) = server else {
                    self.log("Geen geldig server-adres (host:poort).");
                    return Task::none();
                };
                self.connecting = true;
                self.log(format!("Verbinden met {server} …"));
                return Task::perform(
                    async move {
                        // Stap-voor-stap loggen: als het proces hard sterft (een
                        // native access-violation in wintun/quinn-udp vuurt de
                        // Rust-panic-hook NIET), wijst de laatste regel in het log
                        // exact aan wélke stap de crash veroorzaakte.
                        tracing::info!("connect: stap 1/3 build_auth");
                        let auth = build_auth(&cfg).map_err(|e| e.to_string())?;
                        tracing::info!("connect: stap 2/3 TunPair::create (Windows: admin + wintun.dll naast .exe)");
                        let tun = TunPair::create(&cfg.tun).map_err(|e| e.to_string())?;
                        tracing::info!("connect: stap 3/3 Client::connect → {server}");
                        let res = Client::connect(&cfg, server, auth, tun)
                            .await
                            .map(Arc::new)
                            .map_err(|e| e.to_string());
                        tracing::info!("connect: klaar (ok={})", res.is_ok());
                        res
                    },
                    Message::Connected,
                );
            }
            Message::Connected(res) => {
                self.connecting = false;
                match res {
                    Ok(client) => {
                        self.log(format!("Verbonden — sessie {}", client.status().session_id));
                        self.status = Some(client.status());
                        self.client = Some(client);
                    }
                    Err(e) => self.log(format!("Verbinden mislukt: {e}")),
                }
            }
            Message::Disconnect => {
                if let Some(c) = &self.client {
                    c.disconnect();
                }
                self.client = None;
                self.status = None;
                self.log("Verbinding verbroken.");
            }
            Message::Tick => {
                if let Some(c) = &self.client {
                    let st = c.status();
                    // De tunnel-loops draaien op de achtergrond; als ze sterven
                    // (TUN-/socket-fout, dode peer, peer-close) valt `connected`
                    // terug op false. Maak dat zichtbaar i.p.v. stil te bevriezen —
                    // de reden staat in het logbestand (zie init_diagnostics).
                    if !st.connected {
                        tracing::warn!("tunnel-loops gestopt — zie logbestand voor de reden");
                        self.log(
                            "Tunnel gesloten (achtergrond-loops gestopt). \
                             Details staan in chameleon-gui.log naast de binary.",
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
            button(text("Laden")).on_press(Message::LoadConfig),
        ]
        .spacing(8);

        let server_row = row![
            text("Server:").width(Length::Fixed(70.0)),
            text_input("1.2.3.4:51820", &self.server).on_input(Message::ServerChanged),
        ]
        .spacing(8);

        // Grote actie-knop: Connect / Disconnect / (bezig).
        let action: Element<Message> = if self.connecting {
            button(text("Verbinden …")).into()
        } else if self.client.is_some() {
            button(text("Disconnect"))
                .on_press(Message::Disconnect)
                .into()
        } else {
            button(text("Connect")).on_press(Message::Connect).into()
        };

        // Status-paneel.
        let status_panel: Element<Message> = match &self.status {
            Some(s) if s.connected => container(
                column![
                    text("● Verbonden").color(Color::from_rgb(0.1, 0.7, 0.2)),
                    text(format!("peer: {}   sessie: {}", s.peer, s.session_id)),
                    text(format!(
                        "↑ {}   ↓ {}",
                        human_bytes(s.tx_bytes),
                        human_bytes(s.rx_bytes)
                    )),
                    text(format!(
                        "uptime: {}s   laatste ontvangst: {}",
                        s.uptime_secs,
                        if s.last_recv_epoch == 0 {
                            "—".to_string()
                        } else {
                            format!("{}s geleden", now_secs().saturating_sub(s.last_recv_epoch))
                        }
                    )),
                ]
                .spacing(4),
            )
            .padding(8)
            .into(),
            _ => text("○ Niet verbonden").into(),
        };

        // Beveiligingsbanner: rood als er iets zwakker staat, groen als alles aan.
        let banner: Element<Message> = if self.warnings.is_empty() {
            container(text("Beveiliging: volledig aan").color(Color::WHITE))
                .padding(8)
                .style(|_| box_style(Color::from_rgb(0.12, 0.45, 0.18)))
                .width(Length::Fill)
                .into()
        } else {
            let mut col =
                column![text("⚠ Beveiligingswaarschuwingen").color(Color::WHITE)].spacing(4);
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

/// Achtergrond-kleur voor een banner (witte tekst erop).
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
