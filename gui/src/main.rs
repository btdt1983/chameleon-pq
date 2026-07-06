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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub fn main() -> iced::Result {
    iced::application("Chameleon-PQ", App::update, App::view)
        .subscription(App::subscription)
        .run_with(App::new)
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
                        let auth = build_auth(&cfg).map_err(|e| e.to_string())?;
                        let tun = TunPair::create(&cfg.tun).map_err(|e| e.to_string())?;
                        Client::connect(&cfg, server, auth, tun)
                            .await
                            .map(Arc::new)
                            .map_err(|e| e.to_string())
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
                    self.status = Some(c.status());
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
