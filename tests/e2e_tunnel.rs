//! End-to-end tunnel test over loopback UDP with a mock TUN. Runs the REAL
//! tunnel loops (`chameleon::tunnel_loops::run_tunnel_loops`) on both sides and
//! sends plaintext through the tunnel — this covers the full data path that the
//! unit tests don't touch: handshake → encrypt/seal → GSO-send → GRO-recv →
//! decrypt → mock-TUN, plus the bounded queue / batch-linger flush.

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

/// Minimal config: data obfuscation ON, handshake obfuscation OFF, pacing OFF
/// (deterministic, flush immediately via the batch-linger). The identity hex is
/// dummy — run_tunnel_loops only uses [engine]/[obfuscation]/[traffic].
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
    toml::from_str(toml).expect("test config parses")
}

fn build_engine(session: chameleon::session::Session) -> Arc<CryptoEngine> {
    let mgr = Arc::new(SessionManager::new(session));
    Arc::new(CryptoEngine::new(mgr, true, PadPolicy::Bucketed))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_e2e_data_flows_both_ways() {
    // ── Keys: server S, client C; both know each other's pubkey. ──
    let s_seed = [11u8; 32];
    let c_seed = [22u8; 32];
    let s_pub = Ed25519Auth::derive_public(&s_seed);
    let c_pub = Ed25519Auth::derive_public(&c_seed);
    let server_auth: Arc<dyn Authenticator> = Arc::new(Ed25519Auth::new(&s_seed, c_pub).unwrap());
    let client_auth: Arc<dyn Authenticator> = Arc::new(Ed25519Auth::new(&c_seed, s_pub).unwrap());

    // ── Sockets on loopback. ──
    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_sock.local_addr().unwrap();

    // ── Handshake: both sides concurrent (join! on this task, no spawn, so the
    //    sockets don't need to be 'static). The initiator retries + does the
    //    L-4 cookie round-trip against the concurrent responder. ──
    let (resp_res, init_res) = tokio::join!(
        run_handshake_responder(&server_sock, server_auth.as_ref(), None),
        run_handshake_initiator(&client_sock, server_addr, client_auth.as_ref(), None),
    );
    let (server_session, client_addr) = resp_res.expect("responder handshake ok");
    let client_session = init_res.expect("initiator handshake ok");
    // I-13: both sides derive the same session_id → the obf data path matches.
    assert_eq!(server_session.session_id, client_session.session_id);

    // ── Engines + mock-TUNs. ──
    let server_engine = build_engine(server_session);
    let client_engine = build_engine(client_session);
    let (server_tun, mut server_handles) = TunPair::new_mock();
    let (client_tun, mut client_handles) = TunPair::new_mock();

    // ── Run the REAL tunnel loops on both sides (spawned; TunnelParams is
    //    owned, so no more Box::leak needed). ──
    let params = chameleon::tunnel_loops::TunnelParams::from_config(&test_config());
    let server_stats = Arc::new(chameleon::tunnel_loops::TunnelStats::default());
    let client_stats = Arc::new(chameleon::tunnel_loops::TunnelStats::default());
    // Keep a traffic sender per side alive for the test so the outbound loop's
    // live-control arm parks instead of erroring; no live re-profiling here.
    let eff = test_config().traffic.effective();
    let (_server_traffic_tx, server_traffic_rx) = tokio::sync::watch::channel(eff);
    let (_client_traffic_tx, client_traffic_rx) = tokio::sync::watch::channel(eff);
    tokio::spawn(run_tunnel_loops(
        server_sock.clone(),
        server_engine,
        server_tun,
        client_addr,
        params.clone(),
        server_auth.clone(),
        None,
        server_stats.clone(),
        server_traffic_rx,
    ));
    tokio::spawn(run_tunnel_loops(
        client_sock.clone(),
        client_engine,
        client_tun,
        server_addr,
        params.clone(),
        client_auth.clone(),
        None,
        client_stats.clone(),
        client_traffic_rx,
    ));

    // ── Client → server: inject into the client-TUN, read from the server-TUN. ──
    let up = bytes::Bytes::from_static(b"client says hello through the pq tunnel");
    client_handles.inject_tx.send(up.clone()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), server_handles.drain_rx.recv())
        .await
        .expect("server-TUN received data within 5s")
        .expect("channel open");
    assert_eq!(got, up, "client→server plaintext arrives intact");

    // ── Server → client (other direction). ──
    let down = bytes::Bytes::from_static(b"server replies over the same tunnel");
    server_handles.inject_tx.send(down.clone()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), client_handles.drain_rx.recv())
        .await
        .expect("client-TUN received data within 5s")
        .expect("channel open");
    assert_eq!(got, down, "server→client plaintext arrives intact");

    // ── Stats: both sides registered traffic (for the client UI). ──
    use std::sync::atomic::Ordering;
    assert!(client_stats.connected.load(Ordering::Relaxed));
    assert!(
        client_stats.tx_bytes.load(Ordering::Relaxed) >= up.len() as u64,
        "client counted the sent bytes"
    );
    assert!(
        client_stats.rx_bytes.load(Ordering::Relaxed) >= down.len() as u64,
        "client counted the received bytes"
    );
    assert!(client_stats.last_recv_epoch.load(Ordering::Relaxed) > 0);
}

/// The client core (`chameleon::client::Client`) connects via the public API and
/// sends data through the tunnel; the server side is set up manually.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_core_connects_and_flows() {
    use chameleon::client::Client;
    use chameleon::net::run_handshake_responder;
    use chameleon::tunnel_loops::{run_tunnel_loops, TunnelParams, TunnelStats};

    let s_seed = [31u8; 32];
    let c_seed = [32u8; 32];
    let s_pub = Ed25519Auth::derive_public(&s_seed);
    let c_pub = Ed25519Auth::derive_public(&c_seed);
    let server_auth: Arc<dyn Authenticator> = Arc::new(Ed25519Auth::new(&s_seed, c_pub).unwrap());
    let client_auth: Arc<dyn Authenticator> = Arc::new(Ed25519Auth::new(&c_seed, s_pub).unwrap());

    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_sock.local_addr().unwrap();
    let (server_tun, mut server_handles) = TunPair::new_mock();

    // Server: responder handshake + tunnel loops in the background.
    let params = TunnelParams::from_config(&test_config());
    let sa = server_auth.clone();
    let (_srv_traffic_tx, srv_traffic_rx) =
        tokio::sync::watch::channel(test_config().traffic.effective());
    tokio::spawn(async move {
        let (session, client_addr) = run_handshake_responder(&server_sock, sa.as_ref(), None)
            .await
            .expect("responder ok");
        let engine = build_engine(session);
        run_tunnel_loops(
            server_sock,
            engine,
            server_tun,
            client_addr,
            params,
            sa,
            None,
            Arc::new(TunnelStats::default()),
            srv_traffic_rx,
        )
        .await;
    });

    // Client: via the client-core API (binds its own socket, does the handshake,
    // starts the tunnel loops, returns with a handle).
    let (client_tun, client_handles) = TunPair::new_mock();
    let client = Client::connect(&test_config(), server_addr, client_auth, client_tun)
        .await
        .expect("client connects");
    let st = client.status();
    assert!(st.connected, "client reports connected");
    assert_eq!(st.peer, server_addr);

    // Data client → server via the mock-TUN.
    let msg = bytes::Bytes::from_static(b"via the client-core");
    client_handles.inject_tx.send(msg.clone()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), server_handles.drain_rx.recv())
        .await
        .expect("server received data")
        .expect("channel open");
    assert_eq!(got, msg);

    // The client UI sees the counters go up.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        client.status().tx_bytes >= msg.len() as u64,
        "tx_bytes counted"
    );

    client.disconnect();
}

/// Reconnect: after a client disconnects (graceful Close), the server's session
/// loop must fully tear down and accept a fresh connection on the same socket.
/// Regression test for the JoinSet `shutdown().await` + TUN teardown fix — a
/// teardown that hangs or leaves a lingering reader would make this hang/fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_reconnects_to_looping_server() {
    use chameleon::client::Client;
    use chameleon::net::run_handshake_responder;
    use chameleon::tunnel_loops::{run_tunnel_loops, TunnelParams, TunnelStats};

    let s_seed = [41u8; 32];
    let c_seed = [42u8; 32];
    let s_pub = Ed25519Auth::derive_public(&s_seed);
    let c_pub = Ed25519Auth::derive_public(&c_seed);
    let server_auth: Arc<dyn Authenticator> = Arc::new(Ed25519Auth::new(&s_seed, c_pub).unwrap());
    let client_auth: Arc<dyn Authenticator> = Arc::new(Ed25519Auth::new(&c_seed, s_pub).unwrap());

    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_sock.local_addr().unwrap();

    // Server that serves sequential sessions on one socket, like `run_server`:
    // each received plaintext packet is forwarded to `recv_rx` for the test.
    let (recv_tx, mut recv_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(16);
    let sa = server_auth.clone();
    tokio::spawn(async move {
        loop {
            let (session, client_addr) =
                match run_handshake_responder(&server_sock, sa.as_ref(), None).await {
                    Ok(x) => x,
                    Err(_) => continue,
                };
            let engine = build_engine(session);
            let (server_tun, mut server_handles) = TunPair::new_mock();
            let fwd_tx = recv_tx.clone();
            let fwd = tokio::spawn(async move {
                while let Some(pkt) = server_handles.drain_rx.recv().await {
                    if fwd_tx.send(pkt).await.is_err() {
                        break;
                    }
                }
            });
            let (_tx, rx) = tokio::sync::watch::channel(test_config().traffic.effective());
            run_tunnel_loops(
                server_sock.clone(),
                engine,
                server_tun,
                client_addr,
                TunnelParams::from_config(&test_config()),
                sa.clone(),
                None,
                Arc::new(TunnelStats::default()),
                rx,
            )
            .await;
            fwd.abort();
        }
    });

    // ── First connection: connect + data flows. ──
    let (client_tun, client_handles) = TunPair::new_mock();
    let client = Client::connect(&test_config(), server_addr, client_auth.clone(), client_tun)
        .await
        .expect("first connect");
    client_handles
        .inject_tx
        .send(bytes::Bytes::from_static(b"first session"))
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), recv_rx.recv())
        .await
        .expect("first data within 5s")
        .expect("channel open");
    assert_eq!(&got[..], b"first session");

    // Graceful disconnect → server tears down and re-listens.
    client.disconnect();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ── Reconnect on the same server socket: what broke before the fix. ──
    let (client_tun2, client_handles2) = TunPair::new_mock();
    let client2 = tokio::time::timeout(
        Duration::from_secs(5),
        Client::connect(
            &test_config(),
            server_addr,
            client_auth.clone(),
            client_tun2,
        ),
    )
    .await
    .expect("reconnect must not hang")
    .expect("reconnect");
    assert!(
        client2.status().connected,
        "reconnected client is connected"
    );
    client_handles2
        .inject_tx
        .send(bytes::Bytes::from_static(b"second session"))
        .await
        .unwrap();
    let got2 = tokio::time::timeout(Duration::from_secs(5), recv_rx.recv())
        .await
        .expect("reconnect data within 5s")
        .expect("channel open");
    assert_eq!(&got2[..], b"second session");
    client2.disconnect();
}
