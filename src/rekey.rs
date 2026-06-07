//! Rekey-driver die het gedeelde-socket-probleem oplost.
//!
//! HET PROBLEEM
//!   run_handshake_initiator leest zelf van de socket (recv_from). Tijdens een
//!   live tunnel leest de inbound-loop óók van diezelfde socket. Twee lezers op
//!   één socket = race: de rekey-response wordt door de data-loop opgegeten en
//!   als data-frame gedropt. De rekey hangt dan voor altijd.
//!
//! DE OPLOSSING
//!   De inbound-loop blijft de ENIGE lezer. Wanneer hij een Handshake-frame ziet
//!   midden in een sessie, stuurt hij dat via een kanaal naar deze driver. De
//!   driver verstuurt zelf (send_to mag wél vanuit meerdere taken) maar ONTVANGT
//!   uitsluitend via het kanaal. Zo is er precies één socket-lezer.

use crate::crypto::Authenticator;
use crate::error::Result;
use crate::frame::Frame;
use crate::session::SessionManager;
use crate::tunnel::{fragment, Handshake, Reassembler};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, info};

/// Een binnengekomen handshake-fragment, doorgegeven door de inbound-loop.
pub type HandshakeFrameRx = mpsc::Receiver<Bytes>;
pub type HandshakeFrameTx = mpsc::Sender<Bytes>;

/// Per-poging wachttijd op de response; bij verlies sturen we het init
/// opnieuw. Totale tijd = MAX_REKEY_RETRIES * PER_ATTEMPT_TIMEOUT.
const PER_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(800);
const MAX_REKEY_RETRIES: usize = 4;

/// Voer als INITIATOR een rekey uit zonder zelf de socket te lezen.
/// Response-fragmenten komen binnen via `hs_rx` (gevoed door de inbound-loop).
/// Bij verlies van het init- of response-pakket wordt het init opnieuw
/// verstuurd (bounded retry). De ephemeral sleutels blijven over retries
/// heen constant — alleen de verzending wordt herhaald.
pub async fn rekey_as_initiator(
    socket: &UdpSocket,
    peer: SocketAddr,
    auth: &dyn Authenticator,
    sessions: &SessionManager,
    new_session_id: u32,
    hs_rx: &mut HandshakeFrameRx,
) -> Result<()> {
    let (hs, init_wire) = Handshake::start(auth)?;
    let frags: Vec<_> = fragment(new_session_id, &init_wire);

    // Retry-lus: stuur init, wacht op response; bij timeout opnieuw sturen.
    // De Reassembler wordt per poging vers opgezet zodat een halve oude
    // response geen latere poging vervuilt.
    let mut last_err = crate::error::ChameleonError::Handshake {
        state: "rekey".into(),
        msg: "no attempts made".into(),
    };

    for attempt in 1..=MAX_REKEY_RETRIES {
        // (Her)verstuur het init-bericht.
        for frag in &frags {
            socket
                .send_to(&Frame::new_handshake(frag.clone()).encode()?, peer)
                .await?;
        }

        let mut reasm = Reassembler::default();
        let attempt_result = timeout(PER_ATTEMPT_TIMEOUT, async {
            while let Some(frag_payload) = hs_rx.recv().await {
                if let Some(resp_wire) = reasm.push(&frag_payload)? {
                    return Ok(Some(resp_wire));
                }
            }
            Err::<Option<Bytes>, _>(crate::error::ChameleonError::ChannelClosed)
        })
        .await;

        match attempt_result {
            Ok(Ok(Some(resp_wire))) => {
                // finalize verifieert de responder en geeft het Confirm-bericht.
                return match hs.finalize(resp_wire, new_session_id, auth)? {
                    (Handshake::Established { session }, confirm_wire) => {
                        // Verstuur Confirm zodat de responder ons authenticeert.
                        for frag in fragment(new_session_id, &confirm_wire) {
                            socket
                                .send_to(&Frame::new_handshake(frag).encode()?, peer)
                                .await?;
                        }
                        sessions.install_new_session(session);
                        info!(
                            "rekey complete after {attempt} attempt(s), mutual — \
                               now on session {new_session_id}"
                        );
                        Ok(())
                    }
                    _ => Err(crate::error::ChameleonError::Handshake {
                        state: "rekey".into(),
                        msg: "rekey handshake failed (auth/MAC)".into(),
                    }),
                };
            }
            Ok(Ok(None)) => unreachable!("timeout closure returns Some or Err"),
            Ok(Err(e)) => {
                last_err = e;
                break;
            } // kanaal dicht: stoppen
            Err(_) => {
                // Timeout op deze poging: log en probeer opnieuw.
                debug!("rekey attempt {attempt} timed out, retrying");
                last_err = crate::error::ChameleonError::Handshake {
                    state: "rekey".into(),
                    msg: format!("timed out after {attempt} attempts"),
                };
            }
        }
    }

    Err(last_err)
}

/// Plan het opruimen van de vorige sessie na een grace-periode.
/// Aangeroepen vanuit de tunnel-loop die een Arc<SessionManager> heeft.
pub fn schedule_retire(sessions: Arc<SessionManager>) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        sessions.retire_previous();
        info!("previous session retired (grace period elapsed)");
    });
}

/// RESPONDER-kant van een mid-sessie rekey, fase 1: verwerk de binnengekomen
/// init en stuur de response terug. Installeert de sessie nog NIET — die wordt
/// pas vertrouwd na een geldige Confirm (fase 2). Geeft de pending handshake
/// terug zodat de inbound-loop 'm vasthoudt tot de Confirm binnenkomt.
///
/// Dit tweetraps-model past bij het feit dat de inbound-loop de enige lezer
/// van de socket is: hij voert eerst de init hierheen, en later de Confirm
/// naar `rekey_responder_confirm`.
pub async fn rekey_as_responder(
    socket: &UdpSocket,
    peer: SocketAddr,
    auth: &dyn Authenticator,
    new_session_id: u32,
    init_wire: Bytes,
) -> Result<Handshake> {
    match Handshake::respond(init_wire, new_session_id, auth)? {
        (hs @ Handshake::SentResponse { .. }, resp_wire) => {
            for frag in fragment(new_session_id, &resp_wire) {
                socket
                    .send_to(&Frame::new_handshake(frag).encode()?, peer)
                    .await?;
            }
            info!(
                "rekey (responder) response sent — awaiting confirm for session {new_session_id}"
            );
            Ok(hs)
        }
        _ => Err(crate::error::ChameleonError::Handshake {
            state: "rekey-responder".into(),
            msg: "respond did not yield SentResponse".into(),
        }),
    }
}

/// RESPONDER-kant van een mid-sessie rekey, fase 2: verwerk de Confirm,
/// authenticeer de initiator, en installeer dan pas de nieuwe sessie.
/// Zonder geldige Confirm wordt de rekey-sessie nooit vertrouwd.
pub fn rekey_responder_confirm(
    hs: Handshake,
    auth: &dyn Authenticator,
    sessions: &SessionManager,
    new_session_id: u32,
    confirm_wire: Bytes,
) -> Result<()> {
    match hs.confirm(confirm_wire, auth)? {
        Handshake::Established { session } => {
            sessions.install_new_session(session);
            info!("rekey (responder) complete, mutual — now on session {new_session_id}");
            Ok(())
        }
        _ => Err(crate::error::ChameleonError::Handshake {
            state: "rekey-responder".into(),
            msg: "confirm did not establish session".into(),
        }),
    }
}

/// Hulpconstructie: maak het kanaal waarmee de inbound-loop handshake-frames
/// naar een lopende rekey-driver doorgeeft.
pub fn handshake_channel() -> (HandshakeFrameTx, HandshakeFrameRx) {
    mpsc::channel(16)
}
