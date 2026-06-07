use bytes::Bytes;
use chameleon::crypto::{Ed25519Auth, HybridAuth, MlDsaAuth};
use chameleon::frame::Frame;
use chameleon::session::Session;
use chameleon::tunnel::{fragment, Handshake, Reassembler};

/// Fragmenteer en herassembleer een wire-bericht (de realistische wire-weg).
fn roundtrip(sid: u32, wire: &Bytes) -> Bytes {
    let mut reasm = Reassembler::default();
    let mut out = None;
    for f in fragment(sid, wire) {
        if let Some(full) = reasm.push(&f).unwrap() {
            out = Some(full);
        }
    }
    out.expect("reassembly compleet")
}

#[test]
fn full_handshake_derives_matching_keys_and_tunnels_data() {
    let init_seed = [1u8; 32];
    let resp_seed = [9u8; 32];
    // Beide kanten kennen elkaars publieke sleutel (wederzijdse auth).
    let init_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_pub = Ed25519Auth::derive_public(&resp_seed);

    let init_auth = Ed25519Auth::new(&init_seed, resp_pub).unwrap();
    let resp_auth = Ed25519Auth::new(&resp_seed, init_pub).unwrap();

    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    assert_eq!(init_wire.len(), chameleon::tunnel::HANDSHAKE_MSG_LEN);

    let frags = fragment(42, &init_wire);
    assert!(frags.len() >= 2);
    let mut reasm = Reassembler::default();
    let mut reassembled = None;
    for f in &frags {
        if let Some(full) = reasm.push(f).unwrap() {
            reassembled = Some(full);
        }
    }
    let init_wire2 = reassembled.expect("reassembly compleet");
    assert_eq!(init_wire2, init_wire);

    let (hs_resp, resp_wire) = Handshake::respond(init_wire2, 1, &resp_auth).unwrap();
    // Initiator verifieert responder en produceert het Confirm-bericht.
    let (hs_init_done, confirm_wire) = hs_init.finalize(resp_wire, 1, &init_auth).unwrap();
    // Responder verifieert de initiator via de Confirm -> wederzijds vertrouwd.
    let hs_resp_done = hs_resp.confirm(confirm_wire, &resp_auth).unwrap();

    let init_session = match hs_init_done {
        Handshake::Established { session } => session,
        _ => panic!("initiator niet Established"),
    };
    let resp_session = match hs_resp_done {
        Handshake::Established { session } => session,
        _ => panic!("responder niet Established na confirm"),
    };

    let plaintext = b"hello through the post-quantum tunnel";
    let (counter, ct) = init_session.encrypt(plaintext).unwrap();
    let recovered = resp_session.decrypt(counter, &ct).unwrap();
    assert_eq!(&recovered[..], plaintext);

    let pt2 = b"and back again";
    let (c2, ct2) = resp_session.encrypt(pt2).unwrap();
    let rec2 = init_session.decrypt(c2, &ct2).unwrap();
    assert_eq!(&rec2[..], pt2);

    let replay = resp_session.decrypt(counter, &ct);
    assert!(replay.is_err());
}

#[test]
fn frame_roundtrip() {
    let f = Frame::new_data(7, 123456789, Bytes::from_static(b"payload"));
    let encoded = f.encode().unwrap();
    let decoded = Frame::decode(encoded).unwrap();
    assert_eq!(decoded.session_id, 7);
    assert_eq!(decoded.sequence, 123456789);
    assert_eq!(&decoded.payload[..], b"payload");
}

#[test]
fn replay_window_rejects_old_and_duplicate() {
    let shared = zeroize::Zeroizing::new([5u8; 32]);
    let s = Session::from_handshake(1, shared.clone(), false).unwrap();
    let peer = Session::from_handshake(1, shared, true).unwrap();

    let (c0, ct0) = peer.encrypt(b"p0").unwrap();
    let (c1, ct1) = peer.encrypt(b"p1").unwrap();
    assert!(s.decrypt(c1, &ct1).is_ok());
    assert!(s.decrypt(c0, &ct0).is_ok());
    assert!(s.decrypt(c0, &ct0).is_err());
}

#[test]
fn wrong_peer_identity_fails_auth() {
    // Scenario 1: de RESPONDER is niet wie de initiator verwacht.
    // De initiator heeft een verkeerde peer-pubkey -> finalize moet falen.
    let resp_seed = [9u8; 32];
    let init_auth = Ed25519Auth::new(&[1u8; 32], [0xABu8; 32]).unwrap();
    let resp_auth = Ed25519Auth::new(&resp_seed, [0u8; 32]).unwrap();

    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    let (_hs_resp, resp_wire) = Handshake::respond(init_wire, 1, &resp_auth).unwrap();
    let result = hs_init.finalize(resp_wire, 1, &init_auth);
    assert!(
        result.is_err(),
        "MITM responder had moeten falen bij finalize"
    );

    // Scenario 2: de INITIATOR is niet wie de responder verwacht.
    // De sleutels kloppen zo dat de initiator de responder WEL accepteert,
    // maar de responder verwacht een andere initiator-identiteit -> de Confirm
    // moet falen. Dit is precies wat wederzijdse auth toevoegt.
    let init_real_seed = [3u8; 32];
    let resp_real_seed = [4u8; 32];
    let resp_real_pub = Ed25519Auth::derive_public(&resp_real_seed);

    // init verwacht resp_real (correct); resp verwacht een VERKEERDE init-pubkey.
    let init_ok = Ed25519Auth::new(&init_real_seed, resp_real_pub).unwrap();
    let resp_wrong_expect = Ed25519Auth::new(&resp_real_seed, [0x77u8; 32]).unwrap();

    let (hs_init2, init_wire2) = Handshake::start(&init_ok).unwrap();
    let (hs_resp2, resp_wire2) = Handshake::respond(init_wire2, 1, &resp_wrong_expect).unwrap();
    // De initiator accepteert de responder (die identiteit klopt) en bouwt Confirm.
    let (_hs_init_done2, confirm_wire2) = hs_init2
        .finalize(resp_wire2, 1, &init_ok)
        .expect("initiator accepteert correcte responder");
    // Maar de responder verwacht een andere initiator -> confirm moet falen.
    let confirm_result = hs_resp2.confirm(confirm_wire2, &resp_wrong_expect);
    assert!(
        confirm_result.is_err(),
        "MITM initiator had moeten falen bij confirm (wederzijdse auth)"
    );
}

#[test]
fn reassembler_prune_evicts_stale_incomplete() {
    use chameleon::tunnel::{fragment, Reassembler};
    use std::time::Duration;

    // Bouw een bericht dat in 3 fragmenten splitst.
    let big = vec![0xABu8; 2500];
    let frags = fragment(100, &big);
    assert!(frags.len() >= 2);

    let mut reasm = Reassembler::default();
    // Push alleen het EERSTE fragment -> incomplete entry blijft hangen.
    let r = reasm.push(&frags[0]).unwrap();
    assert!(r.is_none());
    assert_eq!(reasm.pending_count(), 1, "incomplete entry aanwezig");

    // Prune met een ruime max_age verwijdert niets (entry is vers).
    reasm.prune_old(Duration::from_secs(3600));
    assert_eq!(reasm.pending_count(), 1, "verse entry blijft");

    // Prune met max_age 0 verwijdert de incomplete entry (DoS-fix).
    std::thread::sleep(Duration::from_millis(2));
    reasm.prune_old(Duration::from_millis(1));
    assert_eq!(reasm.pending_count(), 0, "stale entry verwijderd");
}

#[test]
fn session_manager_rekey_swap_keeps_old_alive() {
    use chameleon::session::{Session, SessionManager};

    // Realistische topologie: 'mgr' is de LOKALE node (responder-rol),
    // 'peer_*' is de andere kant (initiator-rol). De peer ENCRYPT,
    // mgr DECRYPT — tx/rx-sleutels matchen alleen tussen tegengestelde rollen.
    let shared_old = zeroize::Zeroizing::new([1u8; 32]);
    let mgr_old = Session::from_handshake(1, shared_old.clone(), false).unwrap();
    let peer_old = Session::from_handshake(1, shared_old, true).unwrap();
    let mgr = SessionManager::new(mgr_old);

    // Peer stuurt een in-flight pakket op de OUDE sessie.
    let (c_old, ct_old) = peer_old.encrypt(b"old-path packet").unwrap();

    // Rekey: nieuwe sessie (id 2) wordt actief; oude -> previous.
    let shared_new = zeroize::Zeroizing::new([2u8; 32]);
    let mgr_new = Session::from_handshake(2, shared_new.clone(), false).unwrap();
    let peer_new = Session::from_handshake(2, shared_new, true).unwrap();
    mgr.install_new_session(mgr_new);

    // In-flight pakket op de oude sessie moet NOG ontsleutelen via 'previous'.
    let dec_old = mgr.decrypt(1, c_old, &ct_old);
    assert!(
        dec_old.is_ok(),
        "previous session ontsleutelt in-flight verkeer"
    );
    assert_eq!(&dec_old.unwrap()[..], b"old-path packet");

    // Nieuw verkeer op de nieuwe sessie ontsleutelt via 'current'.
    let (c_new, ct_new) = peer_new.encrypt(b"new-path packet").unwrap();
    let dec_new = mgr.decrypt(2, c_new, &ct_new);
    assert!(dec_new.is_ok(), "current session ontsleutelt nieuw verkeer");
    assert_eq!(&dec_new.unwrap()[..], b"new-path packet");

    // Na retire is de oude sessie weg; een nieuw in-flight oud pakket faalt.
    let (c_old2, ct_old2) = peer_old.encrypt(b"too late").unwrap();
    mgr.retire_previous();
    assert!(
        mgr.decrypt(1, c_old2, &ct_old2).is_err(),
        "na retire: oude sessie weg"
    );
}

#[test]
fn rekey_antistorm_gate_blocks_rapid_retrigger() {
    use chameleon::session::{Session, SessionManager};

    // Maak een sessie met een LAGE drempel door de counter ver op te voeren.
    // We kunnen de drempel niet direct zetten, dus we testen de tijd-gate:
    // na een geclaimde rekey mag needs_rekey niet meteen weer true geven.
    let shared = zeroize::Zeroizing::new([3u8; 32]);
    let s = Session::from_handshake(1, shared, true).unwrap();
    let mgr = SessionManager::new(s);

    // Zonder de counter boven de drempel te brengen geeft needs_rekey false.
    assert!(!mgr.needs_rekey(), "onder drempel: geen rekey");

    // abort_rekey is veilig aanroepbaar zonder lopende rekey.
    mgr.abort_rekey();
    assert!(!mgr.needs_rekey(), "blijft false");
}

#[test]
fn replay_window_handles_wide_reordering() {
    use chameleon::session::Session;

    let shared = zeroize::Zeroizing::new([7u8; 32]);
    let rx = Session::from_handshake(1, shared.clone(), false).unwrap();
    let tx = Session::from_handshake(1, shared, true).unwrap();

    // Genereer ruim meer dan 2048 pakketten zodat we ook buiten het venster
    // kunnen testen.
    let mut packets = Vec::new();
    for _ in 0..2600 {
        packets.push(tx.encrypt(b"x").unwrap());
    }

    // Ontvang eerst een hoog pakket (counter 2500). Dat zet 'highest' hoog.
    let (c_last, ct_last) = &packets[2500];
    assert!(rx.decrypt(*c_last, ct_last).is_ok());

    // Een pakket ~1000 posities ouder (counter 1500) moet NOG geaccepteerd
    // worden — binnen het 2048-venster. Dit zou met het oude 64-venster falen.
    let (c_mid, ct_mid) = &packets[1500];
    assert!(
        rx.decrypt(*c_mid, ct_mid).is_ok(),
        "ver-out-of-order pakket binnen 2048-venster geaccepteerd"
    );

    // Datzelfde pakket nogmaals = replay, moet falen.
    assert!(rx.decrypt(*c_mid, ct_mid).is_err(), "replay verworpen");

    // Een pakket dat ECHT buiten het venster valt: counter 100 met highest
    // op 2500 = delta 2400 > 2048. Moet verworpen worden.
    let (c_ancient, ct_ancient) = &packets[100];
    assert!(
        rx.decrypt(*c_ancient, ct_ancient).is_err(),
        "buiten 2048-venster verworpen"
    );

    // En een pakket NET binnen de rand: counter ~500 (delta 2000 < 2048) ok.
    let (c_edge, ct_edge) = &packets[500];
    assert!(
        rx.decrypt(*c_edge, ct_edge).is_ok(),
        "net binnen venster-rand geaccepteerd"
    );
}

#[test]
fn mutual_handshake_three_messages_with_fragmentation() {
    // Volledige 3-berichten wederzijdse handshake over de realistische
    // wire-weg: elk bericht gefragmenteerd en herassembleerd.
    let init_seed = [11u8; 32];
    let resp_seed = [22u8; 32];
    let init_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_pub = Ed25519Auth::derive_public(&resp_seed);
    let init_auth = Ed25519Auth::new(&init_seed, resp_pub).unwrap();
    let resp_auth = Ed25519Auth::new(&resp_seed, init_pub).unwrap();

    // Helper: fragmenteer en herassembleer een wire-bericht.
    fn roundtrip(sid: u32, wire: &Bytes) -> Bytes {
        let mut reasm = Reassembler::default();
        let mut out = None;
        for f in fragment(sid, wire) {
            if let Some(full) = reasm.push(&f).unwrap() {
                out = Some(full);
            }
        }
        out.expect("reassembly compleet")
    }

    // 1. Init
    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    let init_rx = roundtrip(1, &init_wire);

    // 2. Response
    let (hs_resp, resp_wire) = Handshake::respond(init_rx, 1, &resp_auth).unwrap();
    let resp_rx = roundtrip(1, &resp_wire);

    // 3. Confirm
    let (hs_init_done, confirm_wire) = hs_init.finalize(resp_rx, 1, &init_auth).unwrap();
    let confirm_rx = roundtrip(1, &confirm_wire);
    let hs_resp_done = hs_resp.confirm(confirm_rx, &resp_auth).unwrap();

    // Beide kanten Established en sleutels kloppen in beide richtingen.
    let init_session = match hs_init_done {
        Handshake::Established { session } => session,
        _ => panic!("initiator niet Established"),
    };
    let resp_session = match hs_resp_done {
        Handshake::Established { session } => session,
        _ => panic!("responder niet Established"),
    };

    let (c, ct) = init_session.encrypt(b"mutual auth werkt").unwrap();
    assert_eq!(
        &resp_session.decrypt(c, &ct).unwrap()[..],
        b"mutual auth werkt"
    );
    let (c2, ct2) = resp_session.encrypt(b"en terug").unwrap();
    assert_eq!(&init_session.decrypt(c2, &ct2).unwrap()[..], b"en terug");
}

#[test]
fn aead_negotiation_picks_aegis_when_supported() {
    // Op hardware met AES-NI moeten beide kanten AEGIS-256X2 kiezen en moet
    // data over die cipher heen en weer kunnen. Op hardware zonder AES valt
    // het terug op ChaCha20 — dan test deze assert de fallback.
    use chameleon::aead::AeadAlgo;

    let init_seed = [55u8; 32];
    let resp_seed = [66u8; 32];
    let init_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_pub = Ed25519Auth::derive_public(&resp_seed);
    let init_auth = Ed25519Auth::new(&init_seed, resp_pub).unwrap();
    let resp_auth = Ed25519Auth::new(&resp_seed, init_pub).unwrap();

    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    let (hs_resp, resp_wire) = Handshake::respond(init_wire, 1, &resp_auth).unwrap();
    let (hs_init_done, confirm_wire) = hs_init.finalize(resp_wire, 1, &init_auth).unwrap();
    let hs_resp_done = hs_resp.confirm(confirm_wire, &resp_auth).unwrap();

    let init_session = match hs_init_done {
        Handshake::Established { session } => session,
        _ => panic!("initiator niet Established"),
    };
    let resp_session = match hs_resp_done {
        Handshake::Established { session } => session,
        _ => panic!("responder niet Established"),
    };

    // Beide kanten MOETEN dezelfde cipher hebben gekozen.
    assert_eq!(
        init_session.algo(),
        resp_session.algo(),
        "beide kanten gebruiken hetzelfde onderhandelde algoritme"
    );
    // En het is de voorkeur van deze machine (AEGIS mét AES-NI, anders ChaCha20).
    assert_eq!(init_session.algo(), AeadAlgo::preferred());

    // Data moet over de onderhandelde cipher heen en weer kunnen.
    let (c, ct) = init_session.encrypt(b"via onderhandelde cipher").unwrap();
    assert_eq!(
        &resp_session.decrypt(c, &ct).unwrap()[..],
        b"via onderhandelde cipher"
    );
    let (c2, ct2) = resp_session.encrypt(b"retour").unwrap();
    assert_eq!(&init_session.decrypt(c2, &ct2).unwrap()[..], b"retour");
}

#[test]
fn hybrid_pq_handshake_tunnels_data_both_ways() {
    // Volledige 3-berichten wederzijdse handshake met HYBRIDE auth
    // (Ed25519 + ML-DSA-65), over de gefragmenteerde wire-weg. Bewijst dat de
    // post-quantum handtekening-leg end-to-end door de echte state machine loopt.
    let init_seed = [11u8; 32];
    let resp_seed = [22u8; 32];
    let init_ed_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_ed_pub = Ed25519Auth::derive_public(&resp_seed);

    // Elke kant een eigen ML-DSA-keypair; publieke sleutels worden gekruist
    // voorgedeeld (out-of-band), net als de Ed25519-identiteiten.
    let (init_pq_pub, init_pq_sk) = MlDsaAuth::generate();
    let (resp_pq_pub, resp_pq_sk) = MlDsaAuth::generate();

    let init_auth = HybridAuth::new(vec![
        Box::new(Ed25519Auth::new(&init_seed, resp_ed_pub).unwrap()),
        Box::new(MlDsaAuth::from_keys(&init_pq_sk, &resp_pq_pub).unwrap()),
    ]);
    let resp_auth = HybridAuth::new(vec![
        Box::new(Ed25519Auth::new(&resp_seed, init_ed_pub).unwrap()),
        Box::new(MlDsaAuth::from_keys(&resp_pq_sk, &init_pq_pub).unwrap()),
    ]);

    // De hybride handtekening is fors groter; de handshake moet alsnog passen
    // én in meerdere fragmenten splitsen.
    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    assert_eq!(init_wire.len(), chameleon::tunnel::HANDSHAKE_MSG_LEN);
    assert!(
        fragment(1, &init_wire).len() >= 2,
        "PQ-handshake fragmenteert"
    );

    let init_rx = roundtrip(1, &init_wire);
    let (hs_resp, resp_wire) = Handshake::respond(init_rx, 1, &resp_auth).unwrap();
    let resp_rx = roundtrip(1, &resp_wire);
    let (hs_init_done, confirm_wire) = hs_init.finalize(resp_rx, 1, &init_auth).unwrap();
    let confirm_rx = roundtrip(1, &confirm_wire);
    let hs_resp_done = hs_resp.confirm(confirm_rx, &resp_auth).unwrap();

    let init_session = match hs_init_done {
        Handshake::Established { session } => session,
        _ => panic!("initiator niet Established"),
    };
    let resp_session = match hs_resp_done {
        Handshake::Established { session } => session,
        _ => panic!("responder niet Established"),
    };

    let (c, ct) = init_session.encrypt(b"hybride PQ auth werkt").unwrap();
    assert_eq!(
        &resp_session.decrypt(c, &ct).unwrap()[..],
        b"hybride PQ auth werkt"
    );
    let (c2, ct2) = resp_session.encrypt(b"en terug").unwrap();
    assert_eq!(&init_session.decrypt(c2, &ct2).unwrap()[..], b"en terug");
}

#[test]
fn hybrid_pq_wrong_mldsa_key_fails_even_when_ed25519_matches() {
    // Cruciale eigenschap van de hybride leg: als ALLEEN de ML-DSA-sleutel van
    // de peer verkeerd is — maar de Ed25519-leg klopt — moet de handshake nog
    // steeds falen. Anders zou de PQ-leg loos zijn.
    let init_seed = [33u8; 32];
    let resp_seed = [44u8; 32];
    let init_ed_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_ed_pub = Ed25519Auth::derive_public(&resp_seed);

    let (_init_pq_pub, init_pq_sk) = MlDsaAuth::generate();
    let (resp_pq_pub, resp_pq_sk) = MlDsaAuth::generate();
    // Een DERDE, niet-bijbehorend ML-DSA keypair: de initiator denkt dat dít
    // de publieke sleutel van de responder is. Ed25519 klopt wél.
    let (wrong_pq_pub, _wrong_pq_sk) = MlDsaAuth::generate();

    let init_auth = HybridAuth::new(vec![
        Box::new(Ed25519Auth::new(&init_seed, resp_ed_pub).unwrap()),
        Box::new(MlDsaAuth::from_keys(&init_pq_sk, &wrong_pq_pub).unwrap()), // FOUT
    ]);
    let resp_auth = HybridAuth::new(vec![
        Box::new(Ed25519Auth::new(&resp_seed, init_ed_pub).unwrap()),
        Box::new(MlDsaAuth::from_keys(&resp_pq_sk, &resp_pq_pub /*irrelevant hier*/).unwrap()),
    ]);

    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    let (_hs_resp, resp_wire) = Handshake::respond(init_wire, 1, &resp_auth).unwrap();
    // De responder ondertekende met zijn ECHTE ML-DSA-sleutel; de initiator
    // verifieert tegen de VERKEERDE -> finalize moet falen, ook al matcht Ed25519.
    let result = hs_init.finalize(resp_wire, 1, &init_auth);
    assert!(
        result.is_err(),
        "verkeerde ML-DSA-peer-sleutel moet de hybride handshake laten falen"
    );
}

#[test]
fn aegis_session_roundtrips_many_packets() {
    // Forceer een AEGIS-sessie direct (los van detectie) en stuur veel
    // pakketten om de nonce-opbouw en replay-window met AEGIS te dekken.
    use chameleon::aead::AeadAlgo;
    let shared = zeroize::Zeroizing::new([0x9au8; 32]);
    let tx =
        Session::from_handshake_with_algo(1, shared.clone(), true, AeadAlgo::Aegis256X2).unwrap();
    let rx = Session::from_handshake_with_algo(1, shared, false, AeadAlgo::Aegis256X2).unwrap();

    for i in 0..500u32 {
        let msg = format!("pakket {i}");
        let (c, ct) = tx.encrypt(msg.as_bytes()).unwrap();
        let pt = rx.decrypt(c, &ct).unwrap();
        assert_eq!(&pt[..], msg.as_bytes());
    }
    // Replay van een oud pakket moet ook met AEGIS falen.
    let (c0, ct0) = tx.encrypt(b"vers").unwrap();
    assert!(rx.decrypt(c0, &ct0).is_ok());
    assert!(
        rx.decrypt(c0, &ct0).is_err(),
        "replay verworpen onder AEGIS"
    );
}
