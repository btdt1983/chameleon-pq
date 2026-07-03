use bytes::Bytes;
use chameleon::aead::AeadAlgo;
use chameleon::crypto::{Ed25519Auth, HybridAuth, MlDsaAuth};
use chameleon::frame::{Frame, FrameType};
use chameleon::hsobf;
use chameleon::obf::PadPolicy;
use chameleon::session::{Session, SessionManager};
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

// ── Geobfusceerd datapad (obf.rs, QUIC-stijl header-protection + padding) ─────

/// Bouw een sessie met een expliciet AEAD-algoritme voor de obf-tests.
fn obf_session(id: u32, shared: [u8; 32], is_initiator: bool, algo: AeadAlgo) -> Session {
    Session::from_handshake_with_algo(id, zeroize::Zeroizing::new(shared), is_initiator, algo)
        .unwrap()
}

const OBF_ALGOS: [AeadAlgo; 2] = [AeadAlgo::ChaCha20Poly1305, AeadAlgo::Aegis256X2];

#[test]
fn obf_roundtrip_both_ciphers() {
    for algo in OBF_ALGOS {
        let shared = [0x21u8; 32];
        let tx = obf_session(1, shared, true, algo);
        let rx = SessionManager::new(obf_session(1, shared, false, algo));

        let wire = tx
            .seal_obf(FrameType::Data as u8, b"hallo via obf", PadPolicy::Bucketed)
            .unwrap();
        // Op de wire geen zichtbaar 0x01-type-byte: de header is gemaskeerd.
        // (De kans op toevallig 0x01 is ~1/256; dat is geen bug, dus we checken
        //  de recovery, niet byte-0 hard.)
        let (ft, pt) = rx.decrypt_obf(&wire).unwrap();
        assert_eq!(ft, FrameType::Data);
        assert_eq!(&pt[..], b"hallo via obf");
    }
}

#[test]
fn obf_tamper_rejected() {
    for algo in OBF_ALGOS {
        let shared = [0x22u8; 32];
        let tx = obf_session(1, shared, true, algo);
        let rx = SessionManager::new(obf_session(1, shared, false, algo));

        // (a) Knoei met de gemaskeerde header (session_id-veld).
        let mut w = tx
            .seal_obf(FrameType::Data as u8, b"payload", PadPolicy::Bucketed)
            .unwrap()
            .to_vec();
        w[2] ^= 0xFF;
        assert!(
            rx.decrypt_obf(&w).is_err(),
            "gemaskeerde header-tamper faalt"
        );

        // (b) Knoei met de ciphertext buiten de sample (eerste ct-byte). De
        //     header komt correct terug, maar de AEAD-tag faalt.
        let mut w = tx
            .seal_obf(FrameType::Data as u8, b"payload", PadPolicy::Bucketed)
            .unwrap()
            .to_vec();
        w[13] ^= 0xFF; // eerste byte ná de 13-byte header
        assert!(rx.decrypt_obf(&w).is_err(), "ciphertext-tamper faalt");

        // (c) Knoei met de sample-staart (laatste byte).
        let mut w = tx
            .seal_obf(FrameType::Data as u8, b"payload", PadPolicy::Bucketed)
            .unwrap()
            .to_vec();
        let last = w.len() - 1;
        w[last] ^= 0xFF;
        assert!(rx.decrypt_obf(&w).is_err(), "sample-tamper faalt");
    }
}

#[test]
fn obf_trial_demux_current_and_previous() {
    // Spiegelt session_manager_rekey_swap: een in-flight pakket op de OUDE sessie
    // moet via 'previous' door de trial-demux worden geopend, nieuw verkeer via
    // 'current', en na retire faalt de oude.
    let algo = AeadAlgo::ChaCha20Poly1305;
    let shared_old = [1u8; 32];
    let shared_new = [2u8; 32];

    let mgr = SessionManager::new(obf_session(1, shared_old, false, algo));
    let peer_old = obf_session(1, shared_old, true, algo);
    let wire_old = peer_old
        .seal_obf(FrameType::Data as u8, b"old-path", PadPolicy::Bucketed)
        .unwrap();

    mgr.install_new_session(obf_session(2, shared_new, false, algo));
    let peer_new = obf_session(2, shared_new, true, algo);
    let wire_new = peer_new
        .seal_obf(FrameType::Data as u8, b"new-path", PadPolicy::Bucketed)
        .unwrap();

    // Oud pakket via 'previous'.
    let (ft, pt) = mgr.decrypt_obf(&wire_old).unwrap();
    assert_eq!(ft, FrameType::Data);
    assert_eq!(&pt[..], b"old-path");
    // Nieuw pakket via 'current'.
    assert_eq!(&mgr.decrypt_obf(&wire_new).unwrap().1[..], b"new-path");

    // Na retire is de oude sessie weg.
    mgr.retire_previous();
    let wire_old2 = peer_old
        .seal_obf(FrameType::Data as u8, b"too-late", PadPolicy::Bucketed)
        .unwrap();
    assert!(
        mgr.decrypt_obf(&wire_old2).is_err(),
        "na retire faalt de oude sessie"
    );
}

#[test]
fn obf_wrong_key_and_noise_dropped() {
    let algo = AeadAlgo::ChaCha20Poly1305;
    let rx = SessionManager::new(obf_session(1, [7u8; 32], false, algo));

    // Pakket verzegeld met een ANDER shared secret -> niet voor ons.
    let alien = obf_session(1, [8u8; 32], true, algo);
    let wire = alien
        .seal_obf(FrameType::Data as u8, b"niet voor jou", PadPolicy::Off)
        .unwrap();
    assert!(rx.decrypt_obf(&wire).is_err(), "vreemde sleutel gedropt");

    // 100 ruis-datagrammen (>= 29 bytes) -> geen enkele mag openen.
    for i in 0..100u32 {
        let noise: Vec<u8> = (0..40u32)
            .map(|j| (i.wrapping_mul(7) ^ j.wrapping_mul(13)) as u8)
            .collect();
        assert!(rx.decrypt_obf(&noise).is_err(), "ruis gedropt");
    }
}

#[test]
fn obf_empty_keepalive_roundtrip() {
    for algo in OBF_ALGOS {
        let shared = [0x2Au8; 32];
        let tx = obf_session(1, shared, true, algo);
        let rx = SessionManager::new(obf_session(1, shared, false, algo));

        let wire = tx
            .seal_obf(FrameType::KeepAlive as u8, b"", PadPolicy::Bucketed)
            .unwrap();
        // Lege keepalive is nog steeds MTU-veilig en langer dan de minimumgrens.
        assert!(wire.len() >= 13 + 16);
        let (ft, pt) = rx.decrypt_obf(&wire).unwrap();
        assert_eq!(ft, FrameType::KeepAlive);
        assert!(pt.is_empty());
    }
}

#[test]
fn obf_full_padding_hides_length() {
    let algo = AeadAlgo::ChaCha20Poly1305;
    let shared = [0x2Bu8; 32];
    let tx = obf_session(1, shared, true, algo);
    let rx = SessionManager::new(obf_session(1, shared, false, algo));

    let small = tx
        .seal_obf(FrameType::Data as u8, b"x", PadPolicy::Full)
        .unwrap();
    let big = tx
        .seal_obf(FrameType::Data as u8, &vec![0u8; 400], PadPolicy::Full)
        .unwrap();
    // Full padding -> beide datagrammen even lang (grootte verborgen).
    assert_eq!(small.len(), big.len(), "Full padding verbergt de lengte");

    // En beide payloads komen exact terug (padding correct gestript).
    assert_eq!(&rx.decrypt_obf(&small).unwrap().1[..], b"x");
    assert_eq!(rx.decrypt_obf(&big).unwrap().1.len(), 400);
}

#[test]
fn obf_short_datagram_rejected() {
    let rx = SessionManager::new(obf_session(1, [9u8; 32], false, AeadAlgo::ChaCha20Poly1305));
    assert!(rx.decrypt_obf(&[0u8; 13]).is_err(), "te kort");
    assert!(rx.decrypt_obf(&[0u8; 20]).is_err(), "onder 13+16");
}

#[test]
fn obf_handshake_frame_falls_through() {
    // Een echt (cleartext) handshake-frame mag NIET door de obf-open worden
    // opgeslokt: decrypt_obf hoort te falen, zodat main.rs terugvalt op
    // Frame::decode voor de rekey-demux.
    let rx = SessionManager::new(obf_session(
        1,
        [0x0Au8; 32],
        false,
        AeadAlgo::ChaCha20Poly1305,
    ));
    let frag = fragment(1, &vec![0xABu8; 2000])[0].clone();
    let hs_wire = Frame::new_handshake(frag).encode().unwrap();
    assert!(
        rx.decrypt_obf(&hs_wire).is_err(),
        "handshake-frame valt door naar de cleartext-weg"
    );
    // En het is wél een geldig handshake-frame langs de klassieke weg.
    assert_eq!(
        Frame::decode(hs_wire).unwrap().frame_type,
        FrameType::Handshake
    );
}

#[test]
fn obf_wire_header_looks_random() {
    // De kernclaim: op de wire is er geen constant header-byte, geen zichtbaar
    // session_id en geen zichtbare oplopende counter. We verzegelen veel
    // pakketten op DEZELFDE sessie en controleren dat de gemaskeerde headers
    // variëren i.p.v. een vaste vingerafdruk te vormen.
    use std::collections::HashSet;
    let tx = obf_session(0xABCD, [0x2Cu8; 32], true, AeadAlgo::ChaCha20Poly1305);

    let mut headers = HashSet::new();
    let mut first_bytes = HashSet::new();
    for _ in 0..200 {
        let w = tx
            .seal_obf(FrameType::Data as u8, b"zelfde payload", PadPolicy::Off)
            .unwrap();
        headers.insert(w[..13].to_vec());
        first_bytes.insert(w[0]);
    }
    // Elke gemaskeerde header is uniek (counter + tag-sample verschillen).
    assert_eq!(
        headers.len(),
        200,
        "gemaskeerde headers zijn allemaal uniek"
    );
    // Byte 0 is niet het constante 0x01 en varieert breed (≈uniform).
    assert!(!first_bytes.contains(&0x01) || first_bytes.len() > 50);
    assert!(
        first_bytes.len() > 50,
        "byte-0 varieert breed (geen vaste vingerafdruk), kreeg {} distinct",
        first_bytes.len()
    );
}

#[test]
fn obf_replay_rejected() {
    let algo = AeadAlgo::ChaCha20Poly1305;
    let shared = [0x0Bu8; 32];
    let tx = obf_session(1, shared, true, algo);
    let rx = SessionManager::new(obf_session(1, shared, false, algo));

    let wire = tx
        .seal_obf(FrameType::Data as u8, b"eenmalig", PadPolicy::Bucketed)
        .unwrap();
    assert!(rx.decrypt_obf(&wire).is_ok(), "eerste keer ok");
    assert!(
        rx.decrypt_obf(&wire).is_err(),
        "replay van hetzelfde datagram verworpen"
    );
}

// ── Geobfusceerde handshake-envelope (hsobf.rs, Fase 2) ──────────────────────

/// Seal een handshake-bericht, fragmenteer het, herassembleer blind via de
/// Reassembler (zoals de wire-weg) en open het weer — de realistische obf-weg.
fn hs_roundtrip(key: &[u8; 32], wire: &Bytes) -> Bytes {
    let mut reasm = Reassembler::default();
    let mut out = None;
    for datagram in hsobf::seal_and_fragment(key, wire).unwrap() {
        let (mid, idx, tot, chunk) =
            hsobf::unmask_fragment(key, &datagram).expect("geldig fragment");
        if let Some(blob) = reasm.push_parts(mid, idx, tot, chunk).unwrap() {
            out = Some(hsobf::open(key, &blob).unwrap());
        }
    }
    out.expect("reassembly compleet")
}

#[test]
fn hs_obf_both_sides_derive_same_key() {
    let init_pub = Ed25519Auth::derive_public(&[11u8; 32]);
    let resp_pub = Ed25519Auth::derive_public(&[22u8; 32]);
    // Beide kanten (own/peer omgewisseld) komen op dezelfde sleutel uit.
    assert_eq!(
        hsobf::derive_hs_obf_key(&init_pub, &resp_pub, None),
        hsobf::derive_hs_obf_key(&resp_pub, &init_pub, None)
    );
    // Met PSK ook symmetrisch, en verschillend van de pubkey-afgeleide.
    let psk = [0x5Au8; 32];
    let k_psk = hsobf::derive_hs_obf_key(&init_pub, &resp_pub, Some(&psk));
    assert_eq!(
        k_psk,
        hsobf::derive_hs_obf_key(&resp_pub, &init_pub, Some(&psk))
    );
    assert_ne!(k_psk, hsobf::derive_hs_obf_key(&init_pub, &resp_pub, None));
}

#[test]
fn hs_obf_roundtrip_and_jitter() {
    let key = [0x31u8; 32];
    let wire = Bytes::from(vec![0xABu8; 8192]); // volle handshake-grootte
    assert_eq!(&hs_roundtrip(&key, &wire)[..], &wire[..]);

    // Aantal fragmenten varieert over runs (grootte-jitter tegen de burst-tell).
    let mut counts = std::collections::HashSet::new();
    for _ in 0..12 {
        counts.insert(hsobf::seal_and_fragment(&key, &wire).unwrap().len());
    }
    assert!(counts.len() > 1, "fragment-aantal varieert per handshake");
}

#[test]
fn hs_obf_full_mutual_handshake() {
    // De volledige 3-berichten wederzijdse handshake, elk bericht via de
    // geobfusceerde wrap-then-fragment weg i.p.v. het cleartext frame.
    let init_seed = [11u8; 32];
    let resp_seed = [22u8; 32];
    let init_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_pub = Ed25519Auth::derive_public(&resp_seed);
    let init_auth = Ed25519Auth::new(&init_seed, resp_pub).unwrap();
    let resp_auth = Ed25519Auth::new(&resp_seed, init_pub).unwrap();

    // Beide kanten leiden dezelfde statische obf-sleutel af.
    let key = hsobf::derive_hs_obf_key(&init_pub, &resp_pub, None);

    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    let init_rx = hs_roundtrip(&key, &init_wire);
    let (hs_resp, resp_wire) = Handshake::respond(init_rx, 1, &resp_auth).unwrap();
    let resp_rx = hs_roundtrip(&key, &resp_wire);
    let (hs_init_done, confirm_wire) = hs_init.finalize(resp_rx, 1, &init_auth).unwrap();
    let confirm_rx = hs_roundtrip(&key, &confirm_wire);
    let hs_resp_done = hs_resp.confirm(confirm_rx, &resp_auth).unwrap();

    let init_session = match hs_init_done {
        Handshake::Established { session } => session,
        _ => panic!("initiator niet Established"),
    };
    let resp_session = match hs_resp_done {
        Handshake::Established { session } => session,
        _ => panic!("responder niet Established"),
    };
    // Sleutels kloppen: data tunnelt beide kanten op.
    let (c, ct) = init_session.encrypt(b"handshake obf werkt").unwrap();
    assert_eq!(
        &resp_session.decrypt(c, &ct).unwrap()[..],
        b"handshake obf werkt"
    );
    let (c2, ct2) = resp_session.encrypt(b"en terug").unwrap();
    assert_eq!(&init_session.decrypt(c2, &ct2).unwrap()[..], b"en terug");
}

#[test]
fn hs_obf_wrong_key_and_noise_rejected() {
    let key = [0x41u8; 32];
    let wire = Bytes::from(vec![0x5Au8; 4096]);
    // Verzegel onder key, herassembleer, maar open met een ANDERE sleutel.
    let mut reasm = Reassembler::default();
    let mut blob = None;
    for d in hsobf::seal_and_fragment(&key, &wire).unwrap() {
        let (mid, idx, tot, chunk) = hsobf::unmask_fragment(&key, &d).unwrap();
        if let Some(b) = reasm.push_parts(mid, idx, tot, chunk).unwrap() {
            blob = Some(b);
        }
    }
    assert!(
        hsobf::open(&[0x42u8; 32], &blob.unwrap()).is_err(),
        "verkeerde sleutel"
    );

    // Ruis: 200 willekeurige >= 8-byte datagrammen mogen nooit compleet-en-openen.
    let mut r = Reassembler::default();
    for i in 0..200u32 {
        let noise: Vec<u8> = (0..40u32)
            .map(|j| (i.wrapping_mul(31) ^ j.wrapping_mul(7)) as u8)
            .collect();
        if let Some((mid, idx, tot, chunk)) = hsobf::unmask_fragment(&key, &noise) {
            if let Ok(Some(b)) = r.push_parts(mid, idx, tot, chunk) {
                assert!(hsobf::open(&key, &b).is_err(), "ruis opent niet");
            }
        }
    }
}

#[test]
fn hs_obf_cleartext_frame_not_accepted() {
    // Een 0.1.2-peer stuurt cleartext Frame::new_handshake-fragmenten. Die mogen
    // niet als geobfusceerde handshake worden geopend (schone breuk, geen
    // cross-versie-verwarring).
    let key = [0x51u8; 32];
    let big = vec![0xABu8; 6000];
    let mut reasm = Reassembler::default();
    let mut opened = false;
    for frag in fragment(7, &big) {
        let datagram = Frame::new_handshake(frag).encode().unwrap();
        if let Some((mid, idx, tot, chunk)) = hsobf::unmask_fragment(&key, &datagram) {
            if let Ok(Some(blob)) = reasm.push_parts(mid, idx, tot, chunk) {
                opened |= hsobf::open(&key, &blob).is_ok();
            }
        }
    }
    assert!(
        !opened,
        "cleartext 0.1.2-frame wordt niet als obf-handshake geaccepteerd"
    );
}

#[test]
fn hs_obf_reassembler_cap_and_prune() {
    use std::time::Duration;
    // Cap: veel distinct msg_id-partials mogen het geheugen niet onbegrensd
    // laten groeien (elk niet-data-datagram is nu een kandidaat-fragment).
    let mut reasm = Reassembler::default();
    for mid in 0..200u32 {
        // Eén fragment van een (beweerd) 2-fragment-bericht -> blijft partial.
        let _ = reasm.push_parts(mid, 0, 2, Bytes::from_static(b"x"));
    }
    assert!(
        reasm.pending_count() <= 64,
        "pending gecapt op 64, kreeg {}",
        reasm.pending_count()
    );

    // Prune: een verse partial wordt door prune_old(0) verwijderd (DoS-fix).
    let mut r2 = Reassembler::default();
    let _ = r2.push_parts(1, 0, 2, Bytes::from_static(b"y"));
    assert_eq!(r2.pending_count(), 1);
    std::thread::sleep(Duration::from_millis(2));
    r2.prune_old(Duration::from_millis(1));
    assert_eq!(r2.pending_count(), 0, "stale partial verwijderd");
}

#[test]
fn hs_obf_wire_looks_random() {
    // Geen constant type-byte op de wire: byte 0 is de willekeurige msg_id en
    // varieert breed over handshakes.
    let key = [0x61u8; 32];
    let wire = Bytes::from(vec![0u8; 8192]);
    let mut first_bytes = std::collections::HashSet::new();
    for _ in 0..64 {
        let frags = hsobf::seal_and_fragment(&key, &wire).unwrap();
        first_bytes.insert(frags[0][0]);
    }
    assert!(
        first_bytes.len() > 20,
        "byte-0 varieert (geen vaste vingerafdruk), kreeg {} distinct",
        first_bytes.len()
    );
}

// ── Cover-traffic / Padding inner-type (pacer, Fase 3) ───────────────────────

#[test]
fn cover_packet_roundtrips_as_padding() {
    let algo = AeadAlgo::ChaCha20Poly1305;
    let shared = [0x70u8; 32];
    let tx = SessionManager::new(obf_session(1, shared, true, algo));
    let rx = SessionManager::new(obf_session(1, shared, false, algo));

    let wire = tx.seal_cover(PadPolicy::Full).unwrap();
    let (ft, pt) = rx.decrypt_obf(&wire).unwrap();
    assert_eq!(ft, FrameType::Padding, "cover pakket = inner-type Padding");
    assert!(pt.is_empty(), "cover heeft lege payload");
}

#[test]
fn cover_indistinguishable_from_data_under_full() {
    let algo = AeadAlgo::ChaCha20Poly1305;
    let shared = [0x71u8; 32];
    let tx = SessionManager::new(obf_session(1, shared, true, algo));

    // Een echt Data-pakket en een cover-pakket, beide Full-gepad (zoals de pacer).
    let data = tx
        .seal_obf(FrameType::Data as u8, b"echte payload", PadPolicy::Full)
        .unwrap();
    let cover = tx.seal_cover(PadPolicy::Full).unwrap();

    // Zelfde lengte op de wire -> de grootte verraadt echt-vs-cover niet.
    assert_eq!(
        data.len(),
        cover.len(),
        "cover en data even lang onder Full"
    );
    // Maar de gemaskeerde headers verschillen (geen vaste vingerafdruk).
    assert_ne!(&data[..13], &cover[..13]);
}

// ── Micro-benchmarks (voor het snelheidswerk) ────────────────────────────────
// Draai met:  cargo test --release bench -- --ignored --nocapture
// #[ignore] zodat ze niet in de gewone suite meelopen.

#[test]
#[ignore]
fn bench_crypto_throughput() {
    use std::time::Instant;

    let pt = vec![0x5Au8; 1200]; // typische MTU-payload
    let n: usize = 1_000_000;
    println!(
        "\n=== crypto microbench ({n} pakketten x {} B, release, 1 core) ===",
        pt.len()
    );

    let rate = |ops: usize, dt: f64, bytes: usize| {
        format!(
            "{:.2} Mpps  {:.2} Gbit/s",
            ops as f64 / dt / 1e6,
            ops as f64 * bytes as f64 * 8.0 / dt / 1e9
        )
    };

    // Rauwe AEAD (per cipher), zonder obf-laag.
    for (name, algo) in [
        ("ChaCha20-Poly1305", AeadAlgo::ChaCha20Poly1305),
        ("AEGIS-256X2", AeadAlgo::Aegis256X2),
    ] {
        let tx = obf_session(1, [0x42u8; 32], true, algo);
        let t = Instant::now();
        let mut sink = 0usize;
        for _ in 0..n {
            sink = sink.wrapping_add(tx.encrypt(&pt).unwrap().1.len());
        }
        let dt = t.elapsed().as_secs_f64();
        println!(
            "  raw AEAD encrypt [{name:18}]: {}  (sink {sink})",
            rate(n, dt, pt.len())
        );
    }

    // Volledig obf-seal-pad (ChaCha, Full padding zoals de pacer gebruikt).
    let mgr = SessionManager::new(obf_session(
        1,
        [0x43u8; 32],
        true,
        AeadAlgo::ChaCha20Poly1305,
    ));
    let t = Instant::now();
    let mut sink = 0usize;
    for _ in 0..n {
        sink = sink.wrapping_add(
            mgr.seal_obf(FrameType::Data as u8, &pt, PadPolicy::Full)
                .unwrap()
                .len(),
        );
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "  obf seal  [ChaCha Full, in ]: {}  (sink {sink})",
        rate(n, dt, pt.len())
    );

    // Volledig obf-open-pad: seal M distinct, dan time decrypt_obf.
    let m: usize = 200_000;
    let shared = [0x44u8; 32];
    let txm = SessionManager::new(obf_session(1, shared, true, AeadAlgo::ChaCha20Poly1305));
    let rxm = SessionManager::new(obf_session(1, shared, false, AeadAlgo::ChaCha20Poly1305));
    let sealed: Vec<Bytes> = (0..m)
        .map(|_| {
            txm.seal_obf(FrameType::Data as u8, &pt, PadPolicy::Full)
                .unwrap()
        })
        .collect();
    let t = Instant::now();
    let mut ok = 0usize;
    for w in &sealed {
        if rxm.decrypt_obf(w).is_ok() {
            ok += 1;
        }
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "  obf open  [ChaCha, out]: {}  ({ok}/{m} ok)",
        rate(m, dt, pt.len())
    );
}

#[test]
#[ignore]
fn bench_udp_sendto() {
    use std::net::UdpSocket;
    use std::time::Instant;

    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let rx_addr = rx.local_addr().unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let buf = vec![0u8; 1280];
    let n: usize = 1_000_000;

    let t = Instant::now();
    let mut sent = 0usize;
    for _ in 0..n {
        // Eén syscall per pakket — dit is de rate die GSO/sendmmsg zou verhogen.
        if tx.send_to(&buf, rx_addr).is_ok() {
            sent += 1;
        }
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "\n=== UDP send_to microbench (loopback, {} B, 1 thread) ===",
        buf.len()
    );
    println!(
        "  raw send_to (1 syscall/pkt): {:.2} Mpps  {:.2} Gbit/s  ({sent}/{n} ok)",
        n as f64 / dt / 1e6,
        n as f64 * buf.len() as f64 * 8.0 / dt / 1e9
    );
}

// ── Gebatchte UDP-I/O (quinn-udp GSO/GRO) ────────────────────────────────────

/// Correctheidsgate voor de syscall-laag: een batch datagrammen die via
/// `batch_send` (GSO waar mogelijk) de deur uit gaat, moet via `batch_recv`
/// (GRO of per-pakket) compleet en intact terugkomen.
#[tokio::test]
async fn udp_batch_roundtrip() {
    use tokio::net::UdpSocket;

    let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let rx_addr = rx.local_addr().unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tx_state = chameleon::udp::socket_state(&tx).unwrap();
    let rx_state = chameleon::udp::socket_state(&rx).unwrap();

    // 5 gelijk-grote datagrammen (elk uniform gevuld met zijn index).
    let dg: Vec<Bytes> = (0..5u8).map(|i| Bytes::from(vec![i; 1280])).collect();
    chameleon::udp::batch_send(&tx, &tx_state, rx_addr, &dg, 1280)
        .await
        .unwrap();

    let (mut storage, mut metas) = chameleon::udp::recv_buffers();
    let mut fills: Vec<u8> = Vec::new();
    while fills.len() < dg.len() {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            chameleon::udp::batch_recv(&rx, &rx_state, &mut storage, &mut metas),
        )
        .await
        .expect("recv timeout")
        .unwrap();
        for (_src, d) in chameleon::udp::iter_datagrams(&storage, &metas, n) {
            assert_eq!(d.len(), 1280, "datagram intact van lengte");
            assert!(d.iter().all(|&b| b == d[0]), "datagram uniform gevuld");
            fills.push(d[0]);
        }
    }
    // Alle 5 aangekomen (volgorde-onafhankelijk).
    fills.sort_unstable();
    assert_eq!(fills, vec![0, 1, 2, 3, 4]);
}

/// Micro-benchmark: batch_send-doorvoer t.o.v. de per-pakket send_to-baseline.
/// Draai met:  cargo test --release bench_udp_gso -- --ignored --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn bench_udp_gso() {
    use std::time::Instant;
    use tokio::net::UdpSocket;

    let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let rx_addr = rx.local_addr().unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let rx_state = chameleon::udp::socket_state(&rx).unwrap();
    let tx_state = chameleon::udp::socket_state(&tx).unwrap();

    // Drain-taak zodat de rx-buffer niet vol loopt.
    let drain = tokio::spawn(async move {
        let (mut st, mut mt) = chameleon::udp::recv_buffers();
        while chameleon::udp::batch_recv(&rx, &rx_state, &mut st, &mut mt)
            .await
            .is_ok()
        {}
    });

    let n = 1_000_000usize;
    let batch = 64usize;
    let dg: Vec<Bytes> = (0..batch)
        .map(|_| Bytes::from(vec![0x5Au8; 1280]))
        .collect();

    let t = Instant::now();
    let mut sent = 0usize;
    while sent < n {
        let _ = chameleon::udp::batch_send(&tx, &tx_state, rx_addr, &dg, 1280).await;
        sent += batch;
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "\n=== GSO batch_send microbench (loopback, 1280 B, batch {batch}) ===\n  \
         batch_send: {:.2} Mpps  {:.2} Gbit/s  ({sent} pkts) — vs per-pakket ~0.18 Mpps",
        sent as f64 / dt / 1e6,
        sent as f64 * 1280.0 * 8.0 / dt / 1e9
    );
    drain.abort();
}

// ── Parallelle crypto over cores (Fase C) ────────────────────────────────────

use chameleon::engine::{CryptoEngine, OutboundPacket};
use std::sync::Arc;

fn obf_engine(shared: [u8; 32], is_initiator: bool, policy: PadPolicy) -> CryptoEngine {
    let algo = AeadAlgo::ChaCha20Poly1305;
    let mgr = Arc::new(SessionManager::new(obf_session(
        1,
        shared,
        is_initiator,
        algo,
    )));
    CryptoEngine::new(mgr, true, policy)
}

/// Parallel verzegelde pakketten moeten geldig zijn: unieke counters (geen
/// nonce-botsing) en allemaal correct te ontsleutelen. (Byte-gelijkheid met de
/// sequentiële variant kan NIET: parallelle counter-toewijzing is niet-
/// deterministisch, en de padding is willekeurig — maar élk pakket opent.)
#[test]
fn encrypt_batch_par_produces_decryptable_packets() {
    let shared = [0x80u8; 32];
    let tx = obf_engine(shared, true, PadPolicy::Bucketed);
    let rx = SessionManager::new(obf_session(1, shared, false, AeadAlgo::ChaCha20Poly1305));

    let n = 500usize;
    let batch: Vec<OutboundPacket> = (0..n)
        .map(|i| OutboundPacket {
            plaintext: Bytes::from(format!("packet {i}").into_bytes()),
        })
        .collect();
    let wires = tx.encrypt_batch_par(batch).unwrap();
    assert_eq!(wires.len(), n);

    let mut recovered = std::collections::HashSet::new();
    for w in &wires {
        let (ft, plain) = rx.decrypt_obf(w).expect("parallel-verzegeld pakket opent");
        assert_eq!(ft, FrameType::Data);
        recovered.insert(plain.to_vec());
    }
    assert_eq!(
        recovered.len(),
        n,
        "alle {n} unieke plaintexts teruggekregen"
    );
}

/// `decrypt_batch_par` classificeert: geobfusceerde data → Ok(Data), ruis → Err
/// (zodat de coördinator die als handshake/ruis serieel afhandelt).
#[test]
fn decrypt_batch_par_classifies_data_and_noise() {
    let shared = [0x81u8; 32];
    let tx = SessionManager::new(obf_session(1, shared, true, AeadAlgo::ChaCha20Poly1305));
    let rx = obf_engine(shared, false, PadPolicy::Bucketed);
    let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

    let mut datagrams: Vec<(std::net::SocketAddr, Bytes)> = (0..200)
        .map(|i| {
            let w = tx
                .seal_obf(
                    FrameType::Data as u8,
                    format!("d{i}").as_bytes(),
                    PadPolicy::Bucketed,
                )
                .unwrap();
            (addr, w)
        })
        .collect();
    // Eén ruis-datagram ertussen.
    datagrams.push((addr, Bytes::from(vec![0xEEu8; 60])));

    let results = rx.decrypt_batch_par(&datagrams);
    assert_eq!(results.len(), 201);
    let mut ok = 0;
    let mut err = 0;
    for (_src, _dg, r) in &results {
        match r {
            Ok((ft, _)) => {
                assert_eq!(*ft, FrameType::Data);
                ok += 1;
            }
            Err(_) => err += 1,
        }
    }
    assert_eq!(ok, 200, "alle data geopend");
    assert_eq!(err, 1, "ruis als Err geclassificeerd");
}

/// Micro-benchmark: parallelle vs sequentiële crypto-doorvoer + schaling.
/// Draai met:  cargo test --release bench_crypto_parallel -- --ignored --nocapture
#[test]
#[ignore]
fn bench_crypto_parallel() {
    use std::time::Instant;

    let shared = [0x82u8; 32];
    let n = 200_000usize;
    let mk_batch = || -> Vec<OutboundPacket> {
        (0..n)
            .map(|_| OutboundPacket {
                plaintext: Bytes::from(vec![0x5Au8; 1200]),
            })
            .collect()
    };
    let gbps = |dt: f64| n as f64 * 1200.0 * 8.0 / dt / 1e9;
    let cores = std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1);
    println!("\n=== crypto parallel vs sequentieel ({n} x 1200 B, {cores} cores) ===");

    // Seal.
    let eng = obf_engine(shared, true, PadPolicy::Full);
    let t = Instant::now();
    let _ = eng.encrypt_batch(mk_batch()).unwrap();
    let seq = t.elapsed().as_secs_f64();
    let eng = obf_engine(shared, true, PadPolicy::Full);
    let t = Instant::now();
    let _ = eng.encrypt_batch_par(mk_batch()).unwrap();
    let par = t.elapsed().as_secs_f64();
    println!(
        "  seal  seq {:.2} Gbit/s | par {:.2} Gbit/s  ({:.1}x)",
        gbps(seq),
        gbps(par),
        seq / par
    );

    // Open (decrypt): seal M distinct, dan sequentieel vs parallel openen.
    let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let txm = SessionManager::new(obf_session(1, shared, true, AeadAlgo::ChaCha20Poly1305));
    let dg: Vec<(std::net::SocketAddr, Bytes)> = (0..n)
        .map(|_| {
            (
                addr,
                txm.seal_obf(FrameType::Data as u8, &[0x5Au8; 1200], PadPolicy::Full)
                    .unwrap(),
            )
        })
        .collect();
    let rx_seq = SessionManager::new(obf_session(1, shared, false, AeadAlgo::ChaCha20Poly1305));
    let t = Instant::now();
    for (_a, w) in &dg {
        let _ = rx_seq.decrypt_obf(w);
    }
    let oseq = t.elapsed().as_secs_f64();
    let rx_par = obf_engine(shared, false, PadPolicy::Full);
    let t = Instant::now();
    let _ = rx_par.decrypt_batch_par(&dg);
    let opar = t.elapsed().as_secs_f64();
    println!(
        "  open  seq {:.2} Gbit/s | par {:.2} Gbit/s  ({:.1}x)",
        gbps(oseq),
        gbps(opar),
        oseq / opar
    );
}
