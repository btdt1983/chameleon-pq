//! Netwerk-glue: UDP-socket loops die de handshake en het datapad bedraden.
//!
//! KRISTALHELDERE API-PUNTEN (waar pakketten in/uit gaan):
//!   • inbound  : socket.recv -> dispatch_inbound()  -> TUN-write kanaal
//!   • outbound : TUN-read kanaal -> batch -> engine -> socket.send
//!
//! De TUN-driver zelf zit hier NIET in (platform-afhankelijk). In plaats
//! daarvan exposeren we twee mpsc-kanalen die de TUN-laag aankoppelt:
//!   tun_to_net  (Receiver<Bytes>) : plaintext IP-pakketten van de TUN
//!   net_to_tun  (Sender<Bytes>)   : plaintext IP-pakketten naar de TUN

use crate::crypto::Authenticator;
use crate::engine::{CryptoEngine, OutboundPacket};
use crate::error::{ChameleonError, Result};
use crate::frame::{Frame, FrameType};
use crate::hsobf;
use crate::tunnel::{fragment, Handshake, Reassembler};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout, Duration};
use tracing::{debug, error, info, warn};

const UDP_BUF: usize = 65_536;
const MAX_BATCH: usize = 256;
const BATCH_LINGER: Duration = Duration::from_micros(200);

/// Timeouts voor de INITIËLE handshake (M-2). De initiator herverzendt zijn init
/// bij uitblijvende response (bounded retry, ephemeral sleutels blijven gelijk).
/// De responder wacht bounded op de Confirm en gaat daarna terug naar luisteren,
/// zodat een bogus/incomplete init hem niet permanent kan vastzetten.
const HS_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(800);
const HS_MAX_ATTEMPTS: usize = 8;
const HS_CONFIRM_TIMEOUT: Duration = Duration::from_secs(2);

/// Genereert oplopende session-ids voor nieuwe sessies (rekey).
static SESSION_COUNTER: AtomicU32 = AtomicU32::new(1);
pub fn alloc_session_id() -> u32 {
    next_session_id()
}
fn next_session_id() -> u32 {
    SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Het lopende geheel zodra een sessie tot stand is gekomen.
///
/// LEGACY/ONGEBRUIKT: de binary draait zijn eigen in/outbound-loops in
/// `main.rs::run_tunnel_loops`; dáár leeft de obfuscatie-integratie (obf.rs).
/// Deze struct is een oudere parallelle variant die niet is bedraad. Behouden
/// als referentie; `run_inbound` hieronder gebruikt nog het klassieke
/// (niet-geobfusceerde) pad.
pub struct Tunnel {
    socket: Arc<UdpSocket>,
    engine: Arc<CryptoEngine>,
    peer: SocketAddr,
}

impl Tunnel {
    pub fn new(socket: Arc<UdpSocket>, engine: Arc<CryptoEngine>, peer: SocketAddr) -> Self {
        Self {
            socket,
            engine,
            peer,
        }
    }

    /// OUTBOUND: plaintext van de TUN -> versleutel (batched) -> UDP.
    /// Dit is de low-latency/high-throughput splitsing: de engine kiest CPU/GPU.
    pub async fn run_outbound(&self, mut tun_to_net: mpsc::Receiver<Bytes>) {
        let mut pending: Vec<OutboundPacket> = Vec::with_capacity(MAX_BATCH);
        let mut tick = interval(BATCH_LINGER);

        loop {
            tokio::select! {
                maybe = tun_to_net.recv() => {
                    match maybe {
                        Some(pkt) => {
                            pending.push(OutboundPacket { plaintext: pkt });
                            if pending.len() >= MAX_BATCH {
                                self.flush(&mut pending).await;
                            }
                        }
                        None => break, // TUN-kanaal gesloten
                    }
                }
                _ = tick.tick() => {
                    if !pending.is_empty() {
                        self.flush(&mut pending).await;
                    }
                    if self.engine.sessions().needs_rekey() {
                        info!("rekey threshold reached (rekey trigger hook)");
                        // Hier zou run_handshake_initiator opnieuw draaien en
                        // engine.sessions().install_new_session() aanroepen.
                    }
                }
            }
        }
    }

    async fn flush(&self, pending: &mut Vec<OutboundPacket>) {
        let batch = std::mem::take(pending);
        match self.engine.encrypt_batch(batch) {
            Ok(wires) => {
                for wire in wires {
                    if let Err(e) = self.socket.send_to(&wire, self.peer).await {
                        error!("udp send error: {e}");
                    }
                }
            }
            Err(e) => error!("batch encrypt failed: {e}"),
        }
    }

    /// INBOUND: UDP -> ontsleutel -> plaintext naar de TUN.
    pub async fn run_inbound(&self, net_to_tun: mpsc::Sender<Bytes>) {
        let mut buf = vec![0u8; UDP_BUF];
        loop {
            let (n, _src) = match self.socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    error!("recv error: {e}");
                    continue;
                }
            };
            let frame = match Frame::decode(Bytes::copy_from_slice(&buf[..n])) {
                Ok(f) => f,
                Err(e) => {
                    warn!("bad frame: {e}");
                    continue;
                }
            };
            if frame.frame_type != FrameType::Data {
                continue; // handshake-frames worden in de setup-fase afgehandeld
            }
            match self
                .engine
                .sessions()
                .decrypt(frame.session_id, frame.sequence, &frame.payload)
            {
                Ok(plain) => {
                    if net_to_tun.send(plain).await.is_err() {
                        break; // TUN-kanaal gesloten
                    }
                }
                Err(e) => debug!("decrypt drop (replay/bad): {e}"),
            }
        }
    }
}

// ── Handshake-bedrading over UDP (met fragmentatie) ──────────────────────────

/// Bouw de wire-klare datagrammen voor een handshake-bericht: geobfusceerd via
/// hsobf (statische sleutel, wrap-then-fragment) als `hs_obf` gezet is, anders
/// het klassieke cleartext `Frame::new_handshake`-pad. Los van het versturen,
/// zodat een rekey-retry dezelfde datagrammen kan herverzenden.
pub(crate) fn build_handshake_datagrams(
    session_id: u32,
    wire: &[u8],
    hs_obf: Option<&[u8; 32]>,
) -> Result<Vec<Bytes>> {
    match hs_obf {
        Some(k) => hsobf::seal_and_fragment(k, wire),
        None => fragment(session_id, wire)
            .into_iter()
            .map(|frag| Frame::new_handshake(frag).encode())
            .collect(),
    }
}

/// Verstuur een handshake-bericht over de wire (obf of cleartext, zie
/// `build_handshake_datagrams`).
pub(crate) async fn send_handshake(
    socket: &UdpSocket,
    peer: SocketAddr,
    session_id: u32,
    wire: &[u8],
    hs_obf: Option<&[u8; 32]>,
) -> Result<()> {
    for datagram in build_handshake_datagrams(session_id, wire, hs_obf)? {
        socket.send_to(&datagram, peer).await?;
    }
    Ok(())
}

/// Push één binnengekomen datagram in de handshake-reassembler; geef het volledige
/// bericht terug zodra compleet. Op het obf-pad is dit RUIS-TOLERANT: korte of
/// onbekende datagrammen (en zelfs een compleet-maar-niet-openend blob) leveren
/// `Ok(None)` op, zodat losse ruis de handshake nooit afbreekt.
pub(crate) fn push_handshake(
    reasm: &mut Reassembler,
    raw: &[u8],
    hs_obf: Option<&[u8; 32]>,
) -> Result<Option<Bytes>> {
    match hs_obf {
        Some(k) => {
            let (mid, idx, tot, chunk) = match hsobf::unmask_fragment(k, raw) {
                Some(v) => v,
                None => return Ok(None),
            };
            match reasm.push_parts(mid, idx, tot, chunk) {
                Ok(Some(blob)) => Ok(hsobf::open(k, &blob).ok()),
                _ => Ok(None),
            }
        }
        None => {
            let frame = Frame::decode(Bytes::copy_from_slice(raw))?;
            if frame.frame_type != FrameType::Handshake {
                return Ok(None);
            }
            reasm.push(&frame.payload)
        }
    }
}

/// CLIENT/INITIATOR: voer de handshake uit en geef de Established sessie terug.
/// M-2: bounded retry — bij uitblijvende response wordt hetzelfde init opnieuw
/// verstuurd; na `HS_MAX_ATTEMPTS` faalt de handshake schoon i.p.v. te hangen.
/// De response wordt alleen van de `peer` geaccepteerd.
pub async fn run_handshake_initiator(
    socket: &UdpSocket,
    peer: SocketAddr,
    auth: &dyn Authenticator,
    hs_obf: Option<&[u8; 32]>,
) -> Result<crate::session::Session> {
    let session_id = next_session_id();
    let (hs, init_wire) = Handshake::start(auth)?;
    // Bouw de init-datagrammen één keer en herverzend dezelfde bytes per poging
    // (ephemeral sleutels blijven constant, net als in de rekey-driver).
    let init_datagrams = build_handshake_datagrams(session_id, &init_wire, hs_obf)?;

    let mut buf = vec![0u8; UDP_BUF];
    let mut resp_wire = None;
    for attempt in 1..=HS_MAX_ATTEMPTS {
        for datagram in &init_datagrams {
            socket.send_to(datagram, peer).await?;
        }
        let mut reasm = Reassembler::default();
        let got = timeout(HS_ATTEMPT_TIMEOUT, async {
            loop {
                let (n, src) = socket.recv_from(&mut buf).await?;
                if src != peer {
                    continue; // accepteer de response alleen van de peer
                }
                if let Some(w) = push_handshake(&mut reasm, &buf[..n], hs_obf)? {
                    return Ok::<Option<Bytes>, ChameleonError>(Some(w));
                }
            }
        })
        .await;
        match got {
            Ok(Ok(Some(w))) => {
                resp_wire = Some(w);
                break;
            }
            Ok(Ok(None)) => unreachable!("closure geeft Some of een fout"),
            Ok(Err(e)) => return Err(e), // socket-fout
            Err(_) => debug!("handshake init attempt {attempt} timed out, retrying"),
        }
    }
    let resp_wire = resp_wire.ok_or(ChameleonError::Handshake {
        state: "initiator".into(),
        msg: "no handshake response after retries (peer unreachable?)".into(),
    })?;

    // finalize verifieert de responder EN geeft het Confirm-bericht terug.
    match hs.finalize(resp_wire, session_id, auth)? {
        (Handshake::Established { session }, confirm_wire) => {
            // Verstuur het Confirm-bericht zodat de responder óns kan
            // authenticeren (wederzijdse auth).
            send_handshake(socket, peer, session_id, &confirm_wire, hs_obf).await?;
            info!("handshake complete (initiator, mutual), session {session_id}");
            Ok(session)
        }
        _ => Err(ChameleonError::Handshake {
            state: "initiator".into(),
            msg: "handshake failed (auth/MAC)".into(),
        }),
    }
}

/// SERVER/RESPONDER: wacht op init, stuur response, wacht op confirm,
/// authenticeer de initiator, geef dan pas de vertrouwde sessie terug.
///
/// M-2: robuust tegen een bogus/incomplete init. Fase 1 wacht (onbegrensd — een
/// server luistert nu eenmaal op zijn peer) op een init die opent én door
/// `respond` komt; een init die dat niet doet wordt overgeslagen i.p.v. de
/// server te laten crashen. Fase 2 wacht BOUNDED (`HS_CONFIRM_TIMEOUT`) op de
/// Confirm van dat ene adres; bij timeout of een ongeldige Confirm vervalt de
/// half-open handshake en luisteren we opnieuw — zo kan een aanvaller ons niet
/// permanent vastzetten.
pub async fn run_handshake_responder(
    socket: &UdpSocket,
    auth: &dyn Authenticator,
    hs_obf: Option<&[u8; 32]>,
) -> Result<(crate::session::Session, SocketAddr)> {
    let session_id = next_session_id();
    let mut buf = vec![0u8; UDP_BUF];

    'listen: loop {
        // Fase 1: wacht op een complete, verwerkbare Init.
        let mut reasm = Reassembler::default();
        let (hs, peer_addr) = loop {
            let (n, src) = socket.recv_from(&mut buf).await?;
            match push_handshake(&mut reasm, &buf[..n], hs_obf) {
                Ok(Some(init_wire)) => match Handshake::respond(init_wire, session_id, auth) {
                    Ok((hs, resp_wire)) => {
                        send_handshake(socket, src, session_id, &resp_wire, hs_obf).await?;
                        break (hs, src);
                    }
                    // Ongeldige init (bv. kapotte Kyber-key): overslaan, blijf luisteren.
                    Err(e) => {
                        warn!("ignoring bad handshake init from {src}: {e}");
                        reasm = Reassembler::default();
                    }
                },
                Ok(None) => {}
                Err(e) => debug!("handshake reassembly drop: {e}"),
            }
        };

        // Fase 2: wacht bounded op de Confirm van peer_addr.
        let mut confirm_reasm = Reassembler::default();
        let confirmed = timeout(HS_CONFIRM_TIMEOUT, async {
            loop {
                let (n, src) = socket.recv_from(&mut buf).await?;
                if src != peer_addr {
                    continue; // negeer andere bronnen tijdens de confirm-fase
                }
                if let Some(w) = push_handshake(&mut confirm_reasm, &buf[..n], hs_obf)? {
                    return Ok::<Bytes, ChameleonError>(w);
                }
            }
        })
        .await;

        match confirmed {
            Ok(Ok(confirm_wire)) => match hs.confirm(confirm_wire, auth) {
                Ok(Handshake::Established { session }) => {
                    info!("handshake complete (responder, mutual), session {session_id}");
                    return Ok((session, peer_addr));
                }
                Ok(_) => {
                    warn!("responder: confirm did not establish — re-listening");
                    continue 'listen;
                }
                Err(e) => {
                    warn!("responder: confirm from {peer_addr} rejected ({e}) — re-listening");
                    continue 'listen;
                }
            },
            Ok(Err(e)) => return Err(e), // socket-fout
            Err(_) => {
                warn!("responder: timed out awaiting confirm from {peer_addr} — re-listening");
                continue 'listen;
            }
        }
    }
}
