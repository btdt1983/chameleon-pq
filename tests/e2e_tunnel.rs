//! End-to-end tunnel-test over loopback-UDP met een mock-TUN. Draait de ECHTE
//! tunnel-loops (`chameleon::tunnel_loops::run_tunnel_loops`) aan beide kanten en
//! stuurt plaintext door de tunnel — dit dekt het volledige datapad dat de
//! unit-tests niet raken: handshake → encrypt/seal → GSO-send → GRO-recv →
//! decrypt → mock-TUN, plus de bounded queue / batch-linger flush.

use chameleon::config::AppConfig;
use chameleon::crypto::{Authenticator, Ed25519Auth};
use chameleon::engine::CryptoEngine;
use chameleon::net::{run_handshake_initiator, run_handshake_responder};
use chameleon::obf::PadPolicy;
use chameleon::session::SessionManager;
use chameleon::tun_iface::TunPair;
use chameleon::tunnel_loops::run_tunnel_loops;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Minimale config: data-obfuscatie AAN, handshake-obfuscatie UIT, pacing UIT
/// (deterministisch, meteen flushen via de batch-linger). De identity-hex is
/// dummy — run_tunnel_loops gebruikt alleen [engine]/[obfuscation]/[traffic].
fn test_config() -> AppConfig {
    let toml = r#"
[identity]
ed25519_seed_hex     = "0101010101010101010101010101010101010101010101010101010101010101"
peer_ed25519_pub_hex = "0202020202020202020202020202020202020202020202020202020202020202"
[network]
bind_addr = "127.0.0.1:0"
[tun]
name = "test0"
[engine]
batch_linger_us = 200
workers = 2
[obfuscation]
enabled = true
handshake = false
[traffic]
enabled = false
"#;
    toml::from_str(toml).expect("test-config parseert")
}

fn build_engine(session: chameleon::session::Session) -> Arc<CryptoEngine> {
    let mgr = Arc::new(SessionManager::new(session));
    Arc::new(CryptoEngine::new(mgr, true, PadPolicy::Bucketed))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_e2e_data_flows_both_ways() {
    // ── Sleutels: server S, client C; beide kennen elkaars pubkey. ──
    let s_seed = [11u8; 32];
    let c_seed = [22u8; 32];
    let s_pub = Ed25519Auth::derive_public(&s_seed);
    let c_pub = Ed25519Auth::derive_public(&c_seed);
    let server_auth: Arc<dyn Authenticator> = Arc::new(Ed25519Auth::new(&s_seed, c_pub).unwrap());
    let client_auth: Arc<dyn Authenticator> = Arc::new(Ed25519Auth::new(&c_seed, s_pub).unwrap());

    // ── Sockets op loopback. ──
    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_sock.local_addr().unwrap();

    // ── Handshake: beide kanten concurrent (join! op deze taak, geen spawn, dus
    //    de sockets hoeven niet 'static te zijn). De initiator retryt + doet de
    //    L-4-cookie-round-trip tegen de meelopende responder. ──
    let (resp_res, init_res) = tokio::join!(
        run_handshake_responder(&server_sock, server_auth.as_ref(), None),
        run_handshake_initiator(&client_sock, server_addr, client_auth.as_ref(), None),
    );
    let (server_session, client_addr) = resp_res.expect("responder handshake ok");
    let client_session = init_res.expect("initiator handshake ok");
    // I-13: beide kanten leiden hetzelfde session_id af → het obf-datapad matcht.
    assert_eq!(server_session.session_id, client_session.session_id);

    // ── Engines + mock-TUNs. ──
    let server_engine = build_engine(server_session);
    let client_engine = build_engine(client_session);
    let (server_tun, mut server_handles) = TunPair::new_mock();
    let (client_tun, mut client_handles) = TunPair::new_mock();

    // ── Draai de ECHTE tunnel-loops aan beide kanten (gespawned; cfg wordt
    //    'static geleaked, prima in een test). ──
    let cfg: &'static AppConfig = Box::leak(Box::new(test_config()));
    tokio::spawn(run_tunnel_loops(
        server_sock.clone(),
        server_engine,
        server_tun,
        client_addr,
        cfg,
        server_auth.clone(),
        None,
    ));
    tokio::spawn(run_tunnel_loops(
        client_sock.clone(),
        client_engine,
        client_tun,
        server_addr,
        cfg,
        client_auth.clone(),
        None,
    ));

    // ── Client → server: injecteer in de client-TUN, lees uit de server-TUN. ──
    let up = bytes::Bytes::from_static(b"client says hello through the pq tunnel");
    client_handles.inject_tx.send(up.clone()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), server_handles.drain_rx.recv())
        .await
        .expect("server-TUN kreeg binnen 5s data")
        .expect("kanaal open");
    assert_eq!(got, up, "client→server plaintext komt intact aan");

    // ── Server → client (andere richting). ──
    let down = bytes::Bytes::from_static(b"server replies over the same tunnel");
    server_handles.inject_tx.send(down.clone()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), client_handles.drain_rx.recv())
        .await
        .expect("client-TUN kreeg binnen 5s data")
        .expect("kanaal open");
    assert_eq!(got, down, "server→client plaintext komt intact aan");
}
