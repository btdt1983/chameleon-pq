//! Netwerk-glue: de UDP-bedrading van de INITIËLE handshake (initiator +
//! responder, met fragmentatie/obfuscatie) plus kleine helpers. De live in/
//! outbound-datapadloops draaien in `main.rs::run_tunnel_loops`; die is de enige
//! socket-lezer (sole-reader-invariant, zie rekey.rs).

use crate::crypto::Authenticator;
use crate::error::{ChameleonError, Result};
use crate::frame::{Frame, FrameType};
use crate::hsobf;
use crate::tunnel::{
    fragment, Handshake, HandshakeMessage, HandshakeType, Reassembler, HANDSHAKE_MSG_LEN,
};
use bytes::Bytes;
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

const UDP_BUF: usize = 65_536;

/// Timeouts voor de INITIËLE handshake (M-2). De initiator herverzendt zijn init
/// bij uitblijvende response (bounded retry, ephemeral sleutels blijven gelijk).
/// De responder wacht bounded op de Confirm en gaat daarna terug naar luisteren,
/// zodat een bogus/incomplete init hem niet permanent kan vastzetten.
const HS_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(800);
const HS_MAX_ATTEMPTS: usize = 8;
const HS_CONFIRM_TIMEOUT: Duration = Duration::from_secs(2);

/// Geldigheidsvenster van een return-routability cookie (L-4). Een handshake is
/// binnen seconden rond, dus 120s is ruim; we accepteren huidig + vorig venster.
const COOKIE_WINDOW_SECS: u64 = 120;

/// Stateless cookie-uitgifte voor de responder (L-4). Eén per-proces geheim; de
/// cookie zelf = HMAC(geheim, src ‖ tijdvenster), dus er is GEEN per-initiator
/// state vóór de cookie valideert — precies wat de anti-DoS-eigenschap geeft.
struct CookieState {
    secret: [u8; 32],
}

impl CookieState {
    fn new() -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Self { secret }
    }

    fn bucket() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / COOKIE_WINDOW_SECS)
            .unwrap_or(0)
    }

    fn issue(&self, src: &SocketAddr) -> [u8; 16] {
        crate::crypto::compute_cookie(&self.secret, src, Self::bucket())
    }

    /// Geldig als de cookie matcht met het huidige of vorige tijdvenster (zodat
    /// een cookie rond een vensterwissel niet meteen ongeldig wordt). Constant-
    /// time vergelijking — het is een MAC-vergelijking, dus een timing-lek zou
    /// byte-voor-byte forging toelaten.
    fn valid(&self, src: &SocketAddr, cookie: &[u8; 16]) -> bool {
        let b = Self::bucket();
        let ct_eq = |bucket: u64| {
            let expected = crate::crypto::compute_cookie(&self.secret, src, bucket);
            let mut diff = 0u8;
            for i in 0..16 {
                diff |= cookie[i] ^ expected[i];
            }
            diff == 0
        };
        ct_eq(b) || ct_eq(b.wrapping_sub(1))
    }
}

/// Genereert oplopende session-ids voor nieuwe sessies (rekey).
static SESSION_COUNTER: AtomicU32 = AtomicU32::new(1);
pub fn alloc_session_id() -> u32 {
    next_session_id()
}
fn next_session_id() -> u32 {
    SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
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
    // (ephemeral sleutels blijven constant, net als in de rekey-driver). Bij een
    // CookieChallenge (L-4) worden ze herbouwd met de cookie erin.
    let mut init_datagrams = build_handshake_datagrams(session_id, &init_wire, hs_obf)?;

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
                // L-4: een CookieChallenge i.p.v. een Response — echo de cookie in
                // de Init en herverzend (volgende lus-iteratie). Zo bewijzen we
                // return-routability vóór de responder dure crypto doet.
                if w.len() == HANDSHAKE_MSG_LEN && w[1] == HandshakeType::CookieChallenge as u8 {
                    if let Ok(ch) = HandshakeMessage::decode(w) {
                        let mut m = HandshakeMessage::decode(init_wire.clone())?;
                        m.cookie = ch.cookie;
                        init_datagrams =
                            build_handshake_datagrams(session_id, &m.encode()?, hs_obf)?;
                        debug!("handshake: got cookie challenge, resending init with cookie");
                    }
                } else {
                    resp_wire = Some(w);
                    break;
                }
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
    match hs.finalize(resp_wire, auth)? {
        (Handshake::Established { session }, confirm_wire) => {
            // Verstuur het Confirm-bericht zodat de responder óns kan
            // authenticeren (wederzijdse auth).
            send_handshake(socket, peer, session_id, &confirm_wire, hs_obf).await?;
            info!(
                "handshake complete (initiator, mutual), session {}",
                session.session_id
            );
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
    // L-4: per-proces cookie-geheim. De responder doet pas dure crypto ná een
    // geldige return-routability cookie (zie CookieState).
    let cookies = CookieState::new();

    'listen: loop {
        // Fase 1: wacht op een complete, verwerkbare Init.
        let mut reasm = Reassembler::default();
        let (hs, peer_addr) = loop {
            let (n, src) = socket.recv_from(&mut buf).await?;
            match push_handshake(&mut reasm, &buf[..n], hs_obf) {
                Ok(Some(init_wire)) => {
                    // Decode goedkoop om het type + de cookie te lezen VÓÓR we dure
                    // ML-KEM/DH/ML-DSA-crypto doen (L-4).
                    let init_msg = match HandshakeMessage::decode(init_wire.clone()) {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("ignoring bad handshake init from {src}: {e}");
                            reasm = Reassembler::default();
                            continue;
                        }
                    };
                    if init_msg.msg_type != HandshakeType::Init {
                        reasm = Reassembler::default();
                        continue;
                    }
                    // Geen geldige cookie -> stuur een goedkope CookieChallenge en
                    // wacht op een herzonden Init. Zo doet een gespoofte bron ons
                    // NOOIT de dure crypto/grote Response ontlokken.
                    if !cookies.valid(&src, &init_msg.cookie) {
                        match HandshakeMessage::new_cookie_challenge(cookies.issue(&src)) {
                            Ok(ch) => match ch.encode() {
                                Ok(wire) => {
                                    let _ = send_handshake(socket, src, session_id, &wire, hs_obf)
                                        .await;
                                }
                                Err(e) => warn!("cookie challenge encode: {e}"),
                            },
                            Err(e) => warn!("cookie challenge build: {e}"),
                        }
                        reasm = Reassembler::default();
                        continue;
                    }
                    // Geldige cookie -> return-routable -> doe de dure handshake.
                    match Handshake::respond(init_wire, auth) {
                        Ok((hs, resp_wire)) => {
                            send_handshake(socket, src, session_id, &resp_wire, hs_obf).await?;
                            break (hs, src);
                        }
                        // Ongeldige init (bv. kapotte ML-KEM-key): overslaan.
                        Err(e) => {
                            warn!("ignoring bad handshake init from {src}: {e}");
                            reasm = Reassembler::default();
                        }
                    }
                }
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
                    info!(
                        "handshake complete (responder, mutual), session {}",
                        session.session_id
                    );
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
