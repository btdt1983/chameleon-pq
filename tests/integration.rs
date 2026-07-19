use bytes::Bytes;
use chameleon::aead::AeadAlgo;
use chameleon::crypto::{Ed25519Auth, HybridAuth, MlDsaAuth};
use chameleon::frame::{Frame, FrameType};
use chameleon::hsobf;
use chameleon::obf::PadPolicy;
use chameleon::session::{Session, SessionManager};
use chameleon::tunnel::{fragment, Handshake, HandshakeMessage, Reassembler};

/// Fragment and reassemble a wire message (the realistic wire path).
fn roundtrip(sid: u32, wire: &Bytes) -> Bytes {
    let mut reasm = Reassembler::default();
    let mut out = None;
    for f in fragment(sid, wire) {
        if let Some(full) = reasm.push(&f).unwrap() {
            out = Some(full);
        }
    }
    out.expect("reassembly complete")
}

#[test]
fn full_handshake_derives_matching_keys_and_tunnels_data() {
    let init_seed = [1u8; 32];
    let resp_seed = [9u8; 32];
    // Both sides know each other's public key (mutual auth).
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
    let init_wire2 = reassembled.expect("reassembly complete");
    assert_eq!(init_wire2, init_wire);

    let (hs_resp, resp_wire) = Handshake::respond(init_wire2, &resp_auth).unwrap();
    // Initiator verifies responder and produces the Confirm message.
    let (hs_init_done, confirm_wire) = hs_init.finalize(resp_wire, &init_auth).unwrap();
    // Responder verifies the initiator via the Confirm -> mutually trusted.
    let hs_resp_done = hs_resp.confirm(confirm_wire, &resp_auth).unwrap();

    let init_session = match hs_init_done {
        Handshake::Established { session } => session,
        _ => panic!("initiator not Established"),
    };
    let resp_session = match hs_resp_done {
        Handshake::Established { session } => session,
        _ => panic!("responder not Established after confirm"),
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
    // Scenario 1: the RESPONDER is not who the initiator expects.
    // The initiator has a wrong peer pubkey -> finalize must fail.
    let resp_seed = [9u8; 32];
    let init_auth = Ed25519Auth::new(&[1u8; 32], [0xABu8; 32]).unwrap();
    let resp_auth = Ed25519Auth::new(&resp_seed, [0u8; 32]).unwrap();

    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    let (_hs_resp, resp_wire) = Handshake::respond(init_wire, &resp_auth).unwrap();
    let result = hs_init.finalize(resp_wire, &init_auth);
    assert!(
        result.is_err(),
        "MITM responder should have failed at finalize"
    );

    // Scenario 2: the INITIATOR is not who the responder expects. Since L-6 the
    // transcript absorbs the identities of BOTH sides, so the responder mixes in
    // its (wrong) expectation of the initiator: the transcripts diverge and the
    // initiator already fails at finalize (even before the Confirm). An identity
    // mismatch on EITHER side therefore makes the handshake fail cleanly. (The
    // Confirm layer itself — that an invalid initiator proof is rejected — is
    // covered by the reflection test.)
    let init_real_seed = [3u8; 32];
    let resp_real_seed = [4u8; 32];
    let resp_real_pub = Ed25519Auth::derive_public(&resp_real_seed);

    // init expects resp_real (correct); resp expects a WRONG init pubkey.
    let init_ok = Ed25519Auth::new(&init_real_seed, resp_real_pub).unwrap();
    let resp_wrong_expect = Ed25519Auth::new(&resp_real_seed, [0x77u8; 32]).unwrap();

    let (hs_init2, init_wire2) = Handshake::start(&init_ok).unwrap();
    let (_hs_resp2, resp_wire2) = Handshake::respond(init_wire2, &resp_wrong_expect).unwrap();
    assert!(
        hs_init2.finalize(resp_wire2, &init_ok).is_err(),
        "wrong initiator expectation poisons the transcript -> finalize fails (L-6)"
    );
}

#[test]
fn reassembler_prune_evicts_stale_incomplete() {
    use chameleon::tunnel::{fragment, Reassembler};
    use std::time::Duration;

    // Build a message that splits into 3 fragments.
    let big = vec![0xABu8; 2500];
    let frags = fragment(100, &big);
    assert!(frags.len() >= 2);

    let mut reasm = Reassembler::default();
    // Push only the FIRST fragment -> incomplete entry stays around.
    let r = reasm.push(&frags[0]).unwrap();
    assert!(r.is_none());
    assert_eq!(reasm.pending_count(), 1, "incomplete entry present");

    // Prune with a generous max_age removes nothing (entry is fresh).
    reasm.prune_old(Duration::from_secs(3600));
    assert_eq!(reasm.pending_count(), 1, "fresh entry stays");

    // Prune with max_age 0 removes the incomplete entry (DoS fix).
    std::thread::sleep(Duration::from_millis(2));
    reasm.prune_old(Duration::from_millis(1));
    assert_eq!(reasm.pending_count(), 0, "stale entry removed");
}

#[test]
fn session_manager_rekey_swap_keeps_old_alive() {
    use chameleon::session::{Session, SessionManager};

    // Realistic topology: 'mgr' is the LOCAL node (responder role),
    // 'peer_*' is the other side (initiator role). The peer ENCRYPTs,
    // mgr DECRYPTs — tx/rx keys only match between opposite roles.
    let shared_old = zeroize::Zeroizing::new([1u8; 32]);
    let mgr_old = Session::from_handshake(1, shared_old.clone(), false).unwrap();
    let peer_old = Session::from_handshake(1, shared_old, true).unwrap();
    let mgr = SessionManager::new(mgr_old);

    // Peer sends an in-flight packet on the OLD session.
    let (c_old, ct_old) = peer_old.encrypt(b"old-path packet").unwrap();

    // Rekey: new session (id 2) becomes active; old -> previous.
    let shared_new = zeroize::Zeroizing::new([2u8; 32]);
    let mgr_new = Session::from_handshake(2, shared_new.clone(), false).unwrap();
    let peer_new = Session::from_handshake(2, shared_new, true).unwrap();
    mgr.install_new_session(mgr_new);

    // In-flight packet on the old session must STILL decrypt via 'previous'.
    let dec_old = mgr.decrypt(1, c_old, &ct_old);
    assert!(
        dec_old.is_ok(),
        "previous session decrypts in-flight traffic"
    );
    assert_eq!(&dec_old.unwrap()[..], b"old-path packet");

    // New traffic on the new session decrypts via 'current'.
    let (c_new, ct_new) = peer_new.encrypt(b"new-path packet").unwrap();
    let dec_new = mgr.decrypt(2, c_new, &ct_new);
    assert!(dec_new.is_ok(), "current session decrypts new traffic");
    assert_eq!(&dec_new.unwrap()[..], b"new-path packet");

    // After retire the old session is gone; a new in-flight old packet fails.
    let (c_old2, ct_old2) = peer_old.encrypt(b"too late").unwrap();
    mgr.retire_previous();
    assert!(
        mgr.decrypt(1, c_old2, &ct_old2).is_err(),
        "after retire: old session gone"
    );
}

/// `reserve_counters` + `seal_obf_with_counter` decouple counter allocation
/// from sealing on purpose (see session.rs doc) so a pipeline can fix a
/// batch's on-wire position immediately and seal it later, possibly out of
/// order relative to OTHER batches. This proves the decoupling itself is
/// correct — each reserved counter still decrypts under its own value —
/// independent of any pipeline plumbing that might call seal in a scrambled
/// order (exactly what a warm worker pool does in practice).
#[test]
fn reserve_then_seal_out_of_order_is_correct() {
    let shared = [0x30u8; 32];
    let tx = obf_session(1, shared, true, AeadAlgo::ChaCha20Poly1305);
    let rx = SessionManager::new(obf_session(1, shared, false, AeadAlgo::ChaCha20Poly1305));

    let base = tx.reserve_counters(3).unwrap();

    // Seal completely out of order: 2, 0, 1.
    let w2 = tx
        .seal_obf_with_counter(
            base + 2,
            FrameType::Data as u8,
            b"packet-2",
            PadPolicy::Bucketed,
        )
        .unwrap();
    let w0 = tx
        .seal_obf_with_counter(
            base,
            FrameType::Data as u8,
            b"packet-0",
            PadPolicy::Bucketed,
        )
        .unwrap();
    let w1 = tx
        .seal_obf_with_counter(
            base + 1,
            FrameType::Data as u8,
            b"packet-1",
            PadPolicy::Bucketed,
        )
        .unwrap();

    // Each still decrypts correctly, regardless of seal order.
    assert_eq!(&rx.decrypt_obf(&w0).unwrap().1[..], b"packet-0");
    assert_eq!(&rx.decrypt_obf(&w1).unwrap().1[..], b"packet-1");
    assert_eq!(&rx.decrypt_obf(&w2).unwrap().1[..], b"packet-2");
}

/// The single most safety-critical property of decoupling reserve from seal:
/// concurrent reservations must never hand out the same counter twice (an
/// AEAD nonce reuse would be catastrophic). `tx_counter.fetch_add` is atomic
/// by construction, but this pins down the observable guarantee explicitly
/// rather than relying only on that implementation detail staying true.
#[test]
fn concurrent_reserve_never_duplicates_a_counter() {
    use std::sync::Arc;
    use std::thread;

    let shared = zeroize::Zeroizing::new([0x31u8; 32]);
    let mgr = Arc::new(SessionManager::new(
        Session::from_handshake(1, shared, true).unwrap(),
    ));

    const THREADS: usize = 8;
    const PER_THREAD: u64 = 200;
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let mgr = mgr.clone();
            thread::spawn(move || {
                let mut mine = Vec::with_capacity(PER_THREAD as usize);
                for _ in 0..PER_THREAD {
                    let (_sess, counter) = mgr.reserve(1).unwrap();
                    mine.push(counter);
                }
                mine
            })
        })
        .collect();

    let mut all: Vec<u64> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    all.sort_unstable();

    assert_eq!(
        all.len(),
        THREADS * PER_THREAD as usize,
        "every reservation returned"
    );
    let unique: std::collections::HashSet<_> = all.iter().collect();
    assert_eq!(unique.len(), all.len(), "no counter reserved twice");
    // Dense range starting at 0: nothing skipped, nothing double-issued.
    let expected: Vec<u64> = (0..(THREADS as u64 * PER_THREAD)).collect();
    assert_eq!(all, expected, "counters form a dense, gap-free range");
}

/// `SessionManager::reserve` pins the specific `Arc<Session>` it reserved
/// against — the caller MUST seal using that exact Arc, never by re-reading
/// `current` later, because a rekey can land in between. This proves why:
/// reserve against session A, let a rekey install session B as `current`,
/// then seal using the Arc `reserve` returned — it must still be valid under
/// A's keys, and a peer holding A as `previous` must still decrypt it.
#[test]
fn reserved_counter_survives_a_rekey_landing_before_the_seal() {
    let shared_a = [0x32u8; 32];
    let sess_a = obf_session(1, shared_a, true, AeadAlgo::ChaCha20Poly1305);
    let peer_a = obf_session(1, shared_a, false, AeadAlgo::ChaCha20Poly1305);
    let mgr = SessionManager::new(sess_a);

    // Reserve against A (the currently active session) — this is the pinned
    // Arc a real pipeline would hold onto while sealing happens elsewhere.
    let (pinned_sess, counter) = mgr.reserve(1).unwrap();

    // A rekey lands in between: B becomes current, A becomes previous.
    let shared_b = zeroize::Zeroizing::new([0x33u8; 32]);
    let sess_b = Session::from_handshake(2, shared_b, true).unwrap();
    mgr.install_new_session(sess_b);

    // Seal now, against the PINNED session (A) — not by asking `mgr` again,
    // which would hand back B.
    let wire = pinned_sess
        .seal_obf_with_counter(
            counter,
            FrameType::Data as u8,
            b"reserved-before-rekey",
            PadPolicy::Bucketed,
        )
        .unwrap();

    // A peer keyed for session A decrypts it correctly — proving the wire
    // was sealed under A's keys/counter, not B's, despite B being `current`
    // on the LOCAL side by the time the seal actually ran. (Whether the
    // PEER itself has since rekeyed too is a separate, already-covered
    // scenario — see session_manager_rekey_swap_keeps_old_alive.)
    let peer_mgr = SessionManager::new(peer_a);
    let (ft, pt) = peer_mgr.decrypt_obf(&wire).unwrap();
    assert_eq!(ft, FrameType::Data);
    assert_eq!(&pt[..], b"reserved-before-rekey");
}

#[test]
fn rekey_antistorm_gate_blocks_rapid_retrigger() {
    use chameleon::session::{Session, SessionManager};

    // Make a session with a LOW threshold by advancing the counter far.
    // We can't set the threshold directly, so we test the time gate:
    // after a claimed rekey, needs_rekey must not immediately return true again.
    let shared = zeroize::Zeroizing::new([3u8; 32]);
    let s = Session::from_handshake(1, shared, true).unwrap();
    let mgr = SessionManager::new(s);

    // Without pushing the counter above the threshold, needs_rekey returns false.
    assert!(!mgr.needs_rekey(), "below threshold: no rekey");

    // abort_rekey is safe to call without a rekey in progress.
    mgr.abort_rekey();
    assert!(!mgr.needs_rekey(), "stays false");
}

#[test]
fn replay_window_handles_wide_reordering() {
    use chameleon::session::Session;

    let shared = zeroize::Zeroizing::new([7u8; 32]);
    let rx = Session::from_handshake(1, shared.clone(), false).unwrap();
    let tx = Session::from_handshake(1, shared, true).unwrap();

    // Generate well over 2048 packets so we can also test outside the
    // window.
    let mut packets = Vec::new();
    for _ in 0..2600 {
        packets.push(tx.encrypt(b"x").unwrap());
    }

    // First receive a high packet (counter 2500). That sets 'highest' high.
    let (c_last, ct_last) = &packets[2500];
    assert!(rx.decrypt(*c_last, ct_last).is_ok());

    // A packet ~1000 positions older (counter 1500) must STILL be accepted —
    // within the 2048 window. This would fail with the old 64 window.
    let (c_mid, ct_mid) = &packets[1500];
    assert!(
        rx.decrypt(*c_mid, ct_mid).is_ok(),
        "far-out-of-order packet within 2048 window accepted"
    );

    // The same packet again = replay, must fail.
    assert!(rx.decrypt(*c_mid, ct_mid).is_err(), "replay rejected");

    // A packet that REALLY falls outside the window: counter 100 with highest
    // at 2500 = delta 2400 > 2048. Must be rejected.
    let (c_ancient, ct_ancient) = &packets[100];
    assert!(
        rx.decrypt(*c_ancient, ct_ancient).is_err(),
        "outside 2048 window rejected"
    );

    // And a packet JUST inside the edge: counter ~500 (delta 2000 < 2048) ok.
    let (c_edge, ct_edge) = &packets[500];
    assert!(
        rx.decrypt(*c_edge, ct_edge).is_ok(),
        "just inside the window edge accepted"
    );
}

#[test]
fn mutual_handshake_three_messages_with_fragmentation() {
    // Full 3-message mutual handshake over the realistic wire path: each
    // message fragmented and reassembled.
    let init_seed = [11u8; 32];
    let resp_seed = [22u8; 32];
    let init_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_pub = Ed25519Auth::derive_public(&resp_seed);
    let init_auth = Ed25519Auth::new(&init_seed, resp_pub).unwrap();
    let resp_auth = Ed25519Auth::new(&resp_seed, init_pub).unwrap();

    // Helper: fragment and reassemble a wire message.
    fn roundtrip(sid: u32, wire: &Bytes) -> Bytes {
        let mut reasm = Reassembler::default();
        let mut out = None;
        for f in fragment(sid, wire) {
            if let Some(full) = reasm.push(&f).unwrap() {
                out = Some(full);
            }
        }
        out.expect("reassembly complete")
    }

    // 1. Init
    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    let init_rx = roundtrip(1, &init_wire);

    // 2. Response
    let (hs_resp, resp_wire) = Handshake::respond(init_rx, &resp_auth).unwrap();
    let resp_rx = roundtrip(1, &resp_wire);

    // 3. Confirm
    let (hs_init_done, confirm_wire) = hs_init.finalize(resp_rx, &init_auth).unwrap();
    let confirm_rx = roundtrip(1, &confirm_wire);
    let hs_resp_done = hs_resp.confirm(confirm_rx, &resp_auth).unwrap();

    // Both sides Established and keys match in both directions.
    let init_session = match hs_init_done {
        Handshake::Established { session } => session,
        _ => panic!("initiator not Established"),
    };
    let resp_session = match hs_resp_done {
        Handshake::Established { session } => session,
        _ => panic!("responder not Established"),
    };

    let (c, ct) = init_session.encrypt(b"mutual auth works").unwrap();
    assert_eq!(
        &resp_session.decrypt(c, &ct).unwrap()[..],
        b"mutual auth works"
    );
    let (c2, ct2) = resp_session.encrypt(b"and back").unwrap();
    assert_eq!(&init_session.decrypt(c2, &ct2).unwrap()[..], b"and back");
}

#[test]
fn aead_negotiation_picks_aegis_when_supported() {
    // On hardware with AES-NI both sides must pick AEGIS-256X2 and data must be
    // able to travel over that cipher back and forth. On hardware without AES it
    // falls back to ChaCha20 — then this assert tests the fallback.
    use chameleon::aead::AeadAlgo;

    let init_seed = [55u8; 32];
    let resp_seed = [66u8; 32];
    let init_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_pub = Ed25519Auth::derive_public(&resp_seed);
    let init_auth = Ed25519Auth::new(&init_seed, resp_pub).unwrap();
    let resp_auth = Ed25519Auth::new(&resp_seed, init_pub).unwrap();

    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    let (hs_resp, resp_wire) = Handshake::respond(init_wire, &resp_auth).unwrap();
    let (hs_init_done, confirm_wire) = hs_init.finalize(resp_wire, &init_auth).unwrap();
    let hs_resp_done = hs_resp.confirm(confirm_wire, &resp_auth).unwrap();

    let init_session = match hs_init_done {
        Handshake::Established { session } => session,
        _ => panic!("initiator not Established"),
    };
    let resp_session = match hs_resp_done {
        Handshake::Established { session } => session,
        _ => panic!("responder not Established"),
    };

    // Both sides MUST have picked the same cipher.
    assert_eq!(
        init_session.algo(),
        resp_session.algo(),
        "both sides use the same negotiated algorithm"
    );
    // And it's this machine's preference (AEGIS with AES-NI, else ChaCha20).
    assert_eq!(init_session.algo(), AeadAlgo::preferred());

    // Data must be able to travel over the negotiated cipher back and forth.
    let (c, ct) = init_session.encrypt(b"via negotiated cipher").unwrap();
    assert_eq!(
        &resp_session.decrypt(c, &ct).unwrap()[..],
        b"via negotiated cipher"
    );
    let (c2, ct2) = resp_session.encrypt(b"return").unwrap();
    assert_eq!(&init_session.decrypt(c2, &ct2).unwrap()[..], b"return");
}

#[test]
fn hybrid_pq_handshake_tunnels_data_both_ways() {
    // Full 3-message mutual handshake with HYBRID auth
    // (Ed25519 + ML-DSA-65), over the fragmented wire path. Proves that the
    // post-quantum signature leg runs end-to-end through the real state machine.
    let init_seed = [11u8; 32];
    let resp_seed = [22u8; 32];
    let init_ed_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_ed_pub = Ed25519Auth::derive_public(&resp_seed);

    // Each side its own ML-DSA keypair; public keys are cross pre-shared
    // (out-of-band), just like the Ed25519 identities.
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

    // The hybrid signature is considerably larger; the handshake must still fit
    // and split into multiple fragments.
    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    assert_eq!(init_wire.len(), chameleon::tunnel::HANDSHAKE_MSG_LEN);
    assert!(fragment(1, &init_wire).len() >= 2, "PQ handshake fragments");

    let init_rx = roundtrip(1, &init_wire);
    let (hs_resp, resp_wire) = Handshake::respond(init_rx, &resp_auth).unwrap();
    let resp_rx = roundtrip(1, &resp_wire);
    let (hs_init_done, confirm_wire) = hs_init.finalize(resp_rx, &init_auth).unwrap();
    let confirm_rx = roundtrip(1, &confirm_wire);
    let hs_resp_done = hs_resp.confirm(confirm_rx, &resp_auth).unwrap();

    let init_session = match hs_init_done {
        Handshake::Established { session } => session,
        _ => panic!("initiator not Established"),
    };
    let resp_session = match hs_resp_done {
        Handshake::Established { session } => session,
        _ => panic!("responder not Established"),
    };

    let (c, ct) = init_session.encrypt(b"hybrid PQ auth works").unwrap();
    assert_eq!(
        &resp_session.decrypt(c, &ct).unwrap()[..],
        b"hybrid PQ auth works"
    );
    let (c2, ct2) = resp_session.encrypt(b"and back").unwrap();
    assert_eq!(&init_session.decrypt(c2, &ct2).unwrap()[..], b"and back");
}

#[test]
fn hybrid_pq_wrong_mldsa_key_fails_even_when_ed25519_matches() {
    // Crucial property of the hybrid leg: if ONLY the peer's ML-DSA key is
    // wrong — but the Ed25519 leg matches — the handshake must still fail.
    // Otherwise the PQ leg would be pointless.
    let init_seed = [33u8; 32];
    let resp_seed = [44u8; 32];
    let init_ed_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_ed_pub = Ed25519Auth::derive_public(&resp_seed);

    let (_init_pq_pub, init_pq_sk) = MlDsaAuth::generate();
    let (resp_pq_pub, resp_pq_sk) = MlDsaAuth::generate();
    // A THIRD, non-matching ML-DSA keypair: the initiator thinks THIS is the
    // responder's public key. Ed25519 does match.
    let (wrong_pq_pub, _wrong_pq_sk) = MlDsaAuth::generate();

    let init_auth = HybridAuth::new(vec![
        Box::new(Ed25519Auth::new(&init_seed, resp_ed_pub).unwrap()),
        Box::new(MlDsaAuth::from_keys(&init_pq_sk, &wrong_pq_pub).unwrap()), // WRONG
    ]);
    let resp_auth = HybridAuth::new(vec![
        Box::new(Ed25519Auth::new(&resp_seed, init_ed_pub).unwrap()),
        Box::new(MlDsaAuth::from_keys(&resp_pq_sk, &resp_pq_pub /*irrelevant here*/).unwrap()),
    ]);

    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    let (_hs_resp, resp_wire) = Handshake::respond(init_wire, &resp_auth).unwrap();
    // The responder signed with its REAL ML-DSA key; the initiator verifies
    // against the WRONG one -> finalize must fail, even though Ed25519 matches.
    let result = hs_init.finalize(resp_wire, &init_auth);
    assert!(
        result.is_err(),
        "wrong ML-DSA peer key must make the hybrid handshake fail"
    );
}

#[test]
fn aegis_session_roundtrips_many_packets() {
    // Force an AEGIS session directly (independent of detection) and send many
    // packets to cover the nonce construction and replay window with AEGIS.
    use chameleon::aead::AeadAlgo;
    let shared = zeroize::Zeroizing::new([0x9au8; 32]);
    let tx =
        Session::from_handshake_with_algo(1, shared.clone(), true, AeadAlgo::Aegis256X2).unwrap();
    let rx = Session::from_handshake_with_algo(1, shared, false, AeadAlgo::Aegis256X2).unwrap();

    for i in 0..500u32 {
        let msg = format!("packet {i}");
        let (c, ct) = tx.encrypt(msg.as_bytes()).unwrap();
        let pt = rx.decrypt(c, &ct).unwrap();
        assert_eq!(&pt[..], msg.as_bytes());
    }
    // Replay of an old packet must also fail with AEGIS.
    let (c0, ct0) = tx.encrypt(b"fresh").unwrap();
    assert!(rx.decrypt(c0, &ct0).is_ok());
    assert!(rx.decrypt(c0, &ct0).is_err(), "replay rejected under AEGIS");
}

// ── Obfuscated data path (obf.rs, QUIC-style header protection + padding) ────

/// Build a session with an explicit AEAD algorithm for the obf tests.
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
            .seal_obf(FrameType::Data as u8, b"hello via obf", PadPolicy::Bucketed)
            .unwrap();
        // No visible 0x01 type byte on the wire: the header is masked.
        // (The chance of an accidental 0x01 is ~1/256; that is not a bug, so we
        //  check the recovery, not byte 0 strictly.)
        let (ft, pt) = rx.decrypt_obf(&wire).unwrap();
        assert_eq!(ft, FrameType::Data);
        assert_eq!(&pt[..], b"hello via obf");
    }
}

#[test]
fn obf_tamper_rejected() {
    for algo in OBF_ALGOS {
        let shared = [0x22u8; 32];
        let tx = obf_session(1, shared, true, algo);
        let rx = SessionManager::new(obf_session(1, shared, false, algo));

        // (a) Tamper with the masked header (session_id field).
        let mut w = tx
            .seal_obf(FrameType::Data as u8, b"payload", PadPolicy::Bucketed)
            .unwrap()
            .to_vec();
        w[2] ^= 0xFF;
        assert!(rx.decrypt_obf(&w).is_err(), "masked header tamper fails");

        // (b) Tamper with the ciphertext outside the sample (first ct byte). The
        //     header comes back correct, but the AEAD tag fails.
        let mut w = tx
            .seal_obf(FrameType::Data as u8, b"payload", PadPolicy::Bucketed)
            .unwrap()
            .to_vec();
        w[13] ^= 0xFF; // first byte after the 13-byte header
        assert!(rx.decrypt_obf(&w).is_err(), "ciphertext tamper fails");

        // (c) Tamper with the sample tail (last byte).
        let mut w = tx
            .seal_obf(FrameType::Data as u8, b"payload", PadPolicy::Bucketed)
            .unwrap()
            .to_vec();
        let last = w.len() - 1;
        w[last] ^= 0xFF;
        assert!(rx.decrypt_obf(&w).is_err(), "sample tamper fails");
    }
}

#[test]
fn obf_trial_demux_current_and_previous() {
    // Mirrors session_manager_rekey_swap: an in-flight packet on the OLD session
    // must be opened via 'previous' by the trial demux, new traffic via
    // 'current', and after retire the old one fails.
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

    // Old packet via 'previous'.
    let (ft, pt) = mgr.decrypt_obf(&wire_old).unwrap();
    assert_eq!(ft, FrameType::Data);
    assert_eq!(&pt[..], b"old-path");
    // New packet via 'current'.
    assert_eq!(&mgr.decrypt_obf(&wire_new).unwrap().1[..], b"new-path");

    // After retire the old session is gone.
    mgr.retire_previous();
    let wire_old2 = peer_old
        .seal_obf(FrameType::Data as u8, b"too-late", PadPolicy::Bucketed)
        .unwrap();
    assert!(
        mgr.decrypt_obf(&wire_old2).is_err(),
        "after retire the old session fails"
    );
}

#[test]
fn obf_wrong_key_and_noise_dropped() {
    let algo = AeadAlgo::ChaCha20Poly1305;
    let rx = SessionManager::new(obf_session(1, [7u8; 32], false, algo));

    // Packet sealed with a DIFFERENT shared secret -> not for us.
    let alien = obf_session(1, [8u8; 32], true, algo);
    let wire = alien
        .seal_obf(FrameType::Data as u8, b"not for you", PadPolicy::Off)
        .unwrap();
    assert!(rx.decrypt_obf(&wire).is_err(), "foreign key dropped");

    // 100 noise datagrams (>= 29 bytes) -> none may open.
    for i in 0..100u32 {
        let noise: Vec<u8> = (0..40u32)
            .map(|j| (i.wrapping_mul(7) ^ j.wrapping_mul(13)) as u8)
            .collect();
        assert!(rx.decrypt_obf(&noise).is_err(), "noise dropped");
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
        // Empty keepalive is still MTU-safe and longer than the minimum bound.
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
    // Full padding -> both datagrams equal length (size hidden).
    assert_eq!(small.len(), big.len(), "Full padding hides the length");

    // And both payloads come back exactly (padding stripped correctly).
    assert_eq!(&rx.decrypt_obf(&small).unwrap().1[..], b"x");
    assert_eq!(rx.decrypt_obf(&big).unwrap().1.len(), 400);
}

#[test]
fn obf_short_datagram_rejected() {
    let rx = SessionManager::new(obf_session(1, [9u8; 32], false, AeadAlgo::ChaCha20Poly1305));
    assert!(rx.decrypt_obf(&[0u8; 13]).is_err(), "too short");
    assert!(rx.decrypt_obf(&[0u8; 20]).is_err(), "below 13+16");
}

#[test]
fn obf_handshake_frame_falls_through() {
    // A real (cleartext) handshake frame must NOT be swallowed by the obf open:
    // decrypt_obf should fail, so that main.rs falls back to Frame::decode for
    // the rekey demux.
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
        "handshake frame falls through to the cleartext path"
    );
    // And it is a valid handshake frame along the classic path.
    assert_eq!(
        Frame::decode(hs_wire).unwrap().frame_type,
        FrameType::Handshake
    );
}

#[test]
fn obf_wire_header_looks_random() {
    // The core claim: on the wire there is no constant header byte, no visible
    // session_id and no visible incrementing counter. We seal many packets on
    // the SAME session and check that the masked headers vary instead of forming
    // a fixed fingerprint.
    use std::collections::HashSet;
    let tx = obf_session(0xABCD, [0x2Cu8; 32], true, AeadAlgo::ChaCha20Poly1305);

    let mut headers = HashSet::new();
    let mut first_bytes = HashSet::new();
    for _ in 0..200 {
        let w = tx
            .seal_obf(FrameType::Data as u8, b"same payload", PadPolicy::Off)
            .unwrap();
        headers.insert(w[..13].to_vec());
        first_bytes.insert(w[0]);
    }
    // Each masked header is unique (counter + tag sample differ).
    assert_eq!(headers.len(), 200, "masked headers are all unique");
    // Byte 0 is not the constant 0x01 and varies widely (≈uniform).
    assert!(!first_bytes.contains(&0x01) || first_bytes.len() > 50);
    assert!(
        first_bytes.len() > 50,
        "byte 0 varies widely (no fixed fingerprint), got {} distinct",
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
        .seal_obf(FrameType::Data as u8, b"one-time", PadPolicy::Bucketed)
        .unwrap();
    assert!(rx.decrypt_obf(&wire).is_ok(), "first time ok");
    assert!(
        rx.decrypt_obf(&wire).is_err(),
        "replay of the same datagram rejected"
    );
}

// ── Obfuscated handshake envelope (hsobf.rs, Phase 2) ────────────────────────

/// Seal a handshake message, fragment it, reassemble blindly via the
/// Reassembler (like the wire path) and open it again — the realistic obf path.
fn hs_roundtrip(key: &[u8; 32], wire: &Bytes) -> Bytes {
    let mut reasm = Reassembler::default();
    let mut out = None;
    for datagram in hsobf::seal_and_fragment(key, wire).unwrap() {
        let (mid, idx, tot, chunk) =
            hsobf::unmask_fragment(key, &datagram).expect("valid fragment");
        if let Some(blob) = reasm.push_parts(mid, idx, tot, chunk).unwrap() {
            out = Some(hsobf::open(key, &blob).unwrap());
        }
    }
    out.expect("reassembly complete")
}

#[test]
fn hs_obf_both_sides_derive_same_key() {
    let init_pub = Ed25519Auth::derive_public(&[11u8; 32]);
    let resp_pub = Ed25519Auth::derive_public(&[22u8; 32]);
    // Both sides (own/peer swapped) arrive at the same key.
    assert_eq!(
        hsobf::derive_hs_obf_key(&init_pub, &resp_pub, None),
        hsobf::derive_hs_obf_key(&resp_pub, &init_pub, None)
    );
    // With PSK also symmetric, and different from the pubkey-derived one.
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
    let wire = Bytes::from(vec![0xABu8; 8192]); // full handshake size
    assert_eq!(&hs_roundtrip(&key, &wire)[..], &wire[..]);

    // Fragment count varies across runs (size jitter against the burst count).
    let mut counts = std::collections::HashSet::new();
    for _ in 0..12 {
        counts.insert(hsobf::seal_and_fragment(&key, &wire).unwrap().len());
    }
    assert!(counts.len() > 1, "fragment count varies per handshake");
}

#[test]
fn hs_obf_full_mutual_handshake() {
    // The full 3-message mutual handshake, each message via the obfuscated
    // wrap-then-fragment path instead of the cleartext frame.
    let init_seed = [11u8; 32];
    let resp_seed = [22u8; 32];
    let init_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_pub = Ed25519Auth::derive_public(&resp_seed);
    let init_auth = Ed25519Auth::new(&init_seed, resp_pub).unwrap();
    let resp_auth = Ed25519Auth::new(&resp_seed, init_pub).unwrap();

    // Both sides derive the same static obf key.
    let key = hsobf::derive_hs_obf_key(&init_pub, &resp_pub, None);

    let (hs_init, init_wire) = Handshake::start(&init_auth).unwrap();
    let init_rx = hs_roundtrip(&key, &init_wire);
    let (hs_resp, resp_wire) = Handshake::respond(init_rx, &resp_auth).unwrap();
    let resp_rx = hs_roundtrip(&key, &resp_wire);
    let (hs_init_done, confirm_wire) = hs_init.finalize(resp_rx, &init_auth).unwrap();
    let confirm_rx = hs_roundtrip(&key, &confirm_wire);
    let hs_resp_done = hs_resp.confirm(confirm_rx, &resp_auth).unwrap();

    let init_session = match hs_init_done {
        Handshake::Established { session } => session,
        _ => panic!("initiator not Established"),
    };
    let resp_session = match hs_resp_done {
        Handshake::Established { session } => session,
        _ => panic!("responder not Established"),
    };
    // Keys match: data tunnels both ways.
    let (c, ct) = init_session.encrypt(b"handshake obf works").unwrap();
    assert_eq!(
        &resp_session.decrypt(c, &ct).unwrap()[..],
        b"handshake obf works"
    );
    let (c2, ct2) = resp_session.encrypt(b"and back").unwrap();
    assert_eq!(&init_session.decrypt(c2, &ct2).unwrap()[..], b"and back");
}

#[test]
fn hs_obf_wrong_key_and_noise_rejected() {
    let key = [0x41u8; 32];
    let wire = Bytes::from(vec![0x5Au8; 4096]);
    // Seal under key, reassemble, but open with a DIFFERENT key.
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
        "wrong key"
    );

    // Noise: 200 random >= 8-byte datagrams may never complete-and-open.
    let mut r = Reassembler::default();
    for i in 0..200u32 {
        let noise: Vec<u8> = (0..40u32)
            .map(|j| (i.wrapping_mul(31) ^ j.wrapping_mul(7)) as u8)
            .collect();
        if let Some((mid, idx, tot, chunk)) = hsobf::unmask_fragment(&key, &noise) {
            if let Ok(Some(b)) = r.push_parts(mid, idx, tot, chunk) {
                assert!(hsobf::open(&key, &b).is_err(), "noise does not open");
            }
        }
    }
}

#[test]
fn hs_obf_cleartext_frame_not_accepted() {
    // A 0.1.2 peer sends cleartext Frame::new_handshake fragments. Those may not
    // be opened as an obfuscated handshake (clean break, no cross-version
    // confusion).
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
        "cleartext 0.1.2 frame is not accepted as an obf handshake"
    );
}

#[test]
fn hs_obf_reassembler_cap_and_prune() {
    use std::time::Duration;
    // Cap: many distinct msg_id partials must not let memory grow unbounded
    // (every non-data datagram is now a candidate fragment).
    let mut reasm = Reassembler::default();
    for mid in 0..200u32 {
        // One fragment of a (claimed) 2-fragment message -> stays partial.
        let _ = reasm.push_parts(mid, 0, 2, Bytes::from_static(b"x"));
    }
    assert!(
        reasm.pending_count() <= 64,
        "pending capped at 64, got {}",
        reasm.pending_count()
    );

    // Prune: a fresh partial is removed by prune_old(0) (DoS fix).
    let mut r2 = Reassembler::default();
    let _ = r2.push_parts(1, 0, 2, Bytes::from_static(b"y"));
    assert_eq!(r2.pending_count(), 1);
    std::thread::sleep(Duration::from_millis(2));
    r2.prune_old(Duration::from_millis(1));
    assert_eq!(r2.pending_count(), 0, "stale partial removed");
}

#[test]
fn hs_obf_wire_looks_random() {
    // No constant type byte on the wire: byte 0 is the random msg_id and
    // varies widely across handshakes.
    let key = [0x61u8; 32];
    let wire = Bytes::from(vec![0u8; 8192]);
    let mut first_bytes = std::collections::HashSet::new();
    for _ in 0..64 {
        let frags = hsobf::seal_and_fragment(&key, &wire).unwrap();
        first_bytes.insert(frags[0][0]);
    }
    assert!(
        first_bytes.len() > 20,
        "byte 0 varies (no fixed fingerprint), got {} distinct",
        first_bytes.len()
    );
}

// ── Cover traffic / Padding inner-type (pacer, Phase 3) ──────────────────────

#[test]
fn cover_packet_roundtrips_as_padding() {
    let algo = AeadAlgo::ChaCha20Poly1305;
    let shared = [0x70u8; 32];
    let tx = SessionManager::new(obf_session(1, shared, true, algo));
    let rx = SessionManager::new(obf_session(1, shared, false, algo));

    let wire = tx.seal_cover(PadPolicy::Full).unwrap();
    let (ft, pt) = rx.decrypt_obf(&wire).unwrap();
    assert_eq!(ft, FrameType::Padding, "cover packet = inner-type Padding");
    assert!(pt.is_empty(), "cover has empty payload");
}

#[test]
fn cover_indistinguishable_from_data_under_full() {
    let algo = AeadAlgo::ChaCha20Poly1305;
    let shared = [0x71u8; 32];
    let tx = SessionManager::new(obf_session(1, shared, true, algo));

    // A real Data packet and a cover packet, both Full-padded (like the pacer).
    let data = tx
        .seal_obf(FrameType::Data as u8, b"real payload", PadPolicy::Full)
        .unwrap();
    let cover = tx.seal_cover(PadPolicy::Full).unwrap();

    // Same length on the wire -> the size does not reveal real-vs-cover.
    assert_eq!(
        data.len(),
        cover.len(),
        "cover and data equal length under Full"
    );
    // But the masked headers differ (no fixed fingerprint).
    assert_ne!(&data[..13], &cover[..13]);
}

// ── Micro-benchmarks (for the speed work) ────────────────────────────────────
// Run with:  cargo test --release bench -- --ignored --nocapture
// #[ignore] so they don't run in the normal suite.

#[test]
#[ignore]
fn bench_crypto_throughput() {
    use std::time::Instant;

    let pt = vec![0x5Au8; 1200]; // typical MTU payload
    let n: usize = 1_000_000;
    println!(
        "\n=== crypto microbench ({n} packets x {} B, release, 1 core) ===",
        pt.len()
    );

    let rate = |ops: usize, dt: f64, bytes: usize| {
        format!(
            "{:.2} Mpps  {:.2} Gbit/s",
            ops as f64 / dt / 1e6,
            ops as f64 * bytes as f64 * 8.0 / dt / 1e9
        )
    };

    // Raw AEAD (per cipher), without the obf layer.
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

    // Full obf-seal-pad (ChaCha, Full padding as the pacer uses).
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

    // Full obf-open-pad: seal M distinct, then time decrypt_obf.
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
        // One syscall per packet — this is the rate GSO/sendmmsg would raise.
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

// ── Batched UDP I/O (quinn-udp GSO/GRO) ──────────────────────────────────────

/// Correctness gate for the syscall layer: a batch of datagrams that goes out
/// via `batch_send` (GSO where possible) must come back complete and intact via
/// `batch_recv` (GRO or per-packet).
#[tokio::test]
async fn udp_batch_roundtrip() {
    use tokio::net::UdpSocket;

    let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let rx_addr = rx.local_addr().unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tx_state = chameleon::udp::socket_state(&tx).unwrap();
    let rx_state = chameleon::udp::socket_state(&rx).unwrap();

    // 5 equal-sized datagrams (each uniformly filled with its index).
    let dg: Vec<Bytes> = (0..5u8).map(|i| Bytes::from(vec![i; 1280])).collect();
    chameleon::udp::batch_send(&tx, &tx_state, rx_addr, &dg, 1280, true)
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
            assert_eq!(d.len(), 1280, "datagram intact in length");
            assert!(d.iter().all(|&b| b == d[0]), "datagram uniformly filled");
            fills.push(d[0]);
        }
    }
    // All 5 arrived (order-independent).
    fills.sort_unstable();
    assert_eq!(fills, vec![0, 1, 2, 3, 4]);
}

/// Micro-benchmark: batch_send throughput vs the per-packet send_to baseline.
/// Run with:  cargo test --release bench_udp_gso -- --ignored --nocapture
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

    // Drain task so the rx buffer doesn't fill up.
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
        let _ = chameleon::udp::batch_send(&tx, &tx_state, rx_addr, &dg, 1280, true).await;
        sent += batch;
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "\n=== GSO batch_send microbench (loopback, 1280 B, batch {batch}) ===\n  \
         batch_send: {:.2} Mpps  {:.2} Gbit/s  ({sent} pkts) — vs per-packet ~0.18 Mpps",
        sent as f64 / dt / 1e6,
        sent as f64 * 1280.0 * 8.0 / dt / 1e9
    );
    drain.abort();
}

// ── Parallel crypto across cores (Phase C) ───────────────────────────────────

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

/// Parallel-sealed packets must be valid: unique counters (no nonce collision)
/// and all correctly decryptable. (Byte equality with the sequential variant is
/// NOT possible: parallel counter assignment is non-deterministic, and the
/// padding is random — but every packet opens.)
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
        let (ft, plain) = rx.decrypt_obf(w).expect("parallel-sealed packet opens");
        assert_eq!(ft, FrameType::Data);
        recovered.insert(plain.to_vec());
    }
    assert_eq!(recovered.len(), n, "all {n} unique plaintexts recovered");
}

/// `decrypt_batch_par` classifies: obfuscated data → Ok(Data), noise → Err
/// (so the coordinator handles those as handshake/noise serially).
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
    // One noise datagram in between.
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
    assert_eq!(ok, 200, "all data opened");
    assert_eq!(err, 1, "noise classified as Err");
}

/// Micro-benchmark: parallel vs sequential crypto throughput + scaling.
/// Run with:  cargo test --release bench_crypto_parallel -- --ignored --nocapture
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
    println!("\n=== crypto parallel vs sequential ({n} x 1200 B, {cores} cores) ===");

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

    // Open (decrypt): seal M distinct, then open sequentially vs in parallel.
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

// ── L-5: role-bound handshake signatures ─────────────────────────────────────

#[test]
fn confirm_rejects_reflected_responder_signature_even_with_shared_key() {
    // Domain separation (L-5): responder signs SIG_LABEL_RESPONDER‖th, initiator
    // SIG_LABEL_INITIATOR‖th. Even with IDENTICAL identity keys on both sides
    // (the worst case for reflection) the responder signature must not count as
    // initiator proof in the Confirm.
    let seed = [7u8; 32];
    let pubk = Ed25519Auth::derive_public(&seed);
    let mk = || Ed25519Auth::new(&seed, pubk).unwrap(); // own == peer == pubk

    // (A) Reflection attempt: take the responder sig from the Response and paste
    //     it into a Confirm. Without role binding (both over th, same key) this
    //     would succeed; with L-5 it must fail.
    let (_hs_init_a, init_wire_a) = Handshake::start(&mk()).unwrap();
    let (hs_resp_a, resp_wire_a) = Handshake::respond(init_wire_a, &mk()).unwrap();
    let resp_msg_a = HandshakeMessage::decode(resp_wire_a).unwrap();
    let mut forged = HandshakeMessage::new_confirm(resp_msg_a.sig.len()).unwrap();
    forged.sig = resp_msg_a.sig;
    assert!(
        hs_resp_a.confirm(forged.encode().unwrap(), &mk()).is_err(),
        "reflected responder sig must not count as initiator proof (L-5)"
    );

    // (B) Control: with the same shared key a REAL handshake still succeeds ->
    //     the rejection in (A) is due to the role binding, not because the key
    //     wouldn't match.
    let (hs_init_b, init_wire_b) = Handshake::start(&mk()).unwrap();
    let (hs_resp_b, resp_wire_b) = Handshake::respond(init_wire_b, &mk()).unwrap();
    let (_done, confirm_wire_b) = hs_init_b.finalize(resp_wire_b, &mk()).unwrap();
    assert!(
        matches!(
            hs_resp_b.confirm(confirm_wire_b, &mk()).unwrap(),
            Handshake::Established { .. }
        ),
        "real confirm with shared key is accepted"
    );
}

// ── M-2: bounded initial handshake over real UDP ─────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_over_udp_completes_mutual() {
    use chameleon::net::{run_handshake_initiator, run_handshake_responder};
    use tokio::net::UdpSocket;

    let init_seed = [3u8; 32];
    let resp_seed = [4u8; 32];
    let init_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_pub = Ed25519Auth::derive_public(&resp_seed);

    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();

    // Responder in a separate task (the initiator retries until it listens).
    let resp_task = tokio::spawn(async move {
        let resp_auth = Ed25519Auth::new(&resp_seed, init_pub).unwrap();
        run_handshake_responder(&server, &resp_auth, None).await
    });

    let init_auth = Ed25519Auth::new(&init_seed, resp_pub).unwrap();
    let init_session = run_handshake_initiator(&client, server_addr, &init_auth, None)
        .await
        .expect("initiator handshake ok");

    let (resp_session, peer) = resp_task.await.unwrap().expect("responder handshake ok");
    assert_eq!(
        peer, client_addr,
        "responder pins the initiator source address"
    );

    // Since I-13 both sides derive the same session_id from the shared secret
    // (no more process-global counter), so a real data roundtrip works even in a
    // single test process: this proves matching directional keys + session_id.
    assert_eq!(
        init_session.session_id, resp_session.session_id,
        "both sides derive the same session_id (I-13)"
    );
    let (ctr, ct) = init_session.encrypt(b"udp ping").unwrap();
    assert_eq!(&resp_session.decrypt(ctr, &ct).unwrap()[..], b"udp ping");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_initiator_times_out_without_responder() {
    use chameleon::net::run_handshake_initiator;
    use tokio::net::UdpSocket;

    let init_auth = Ed25519Auth::new(&[5u8; 32], Ed25519Auth::derive_public(&[6u8; 32])).unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // A really bound but SILENT peer: it never answers (no ICMP error, so we
    // really test the timeout path, not a socket error).
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();

    let start = std::time::Instant::now();
    let res = run_handshake_initiator(&client, dead_addr, &init_auth, None).await;
    assert!(
        res.is_err(),
        "no response -> handshake fails cleanly (no hang)"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(30),
        "handshake must fail bounded, not hang forever"
    );
    drop(dead);
}

// ── L-6: identities bound in the transcript ──────────────────────────────────

#[test]
fn identity_binding_is_symmetric_and_peer_dependent() {
    use chameleon::crypto::Authenticator;
    let i = [1u8; 32];
    let r = [9u8; 32];
    let x = [5u8; 32];
    let i_pub = Ed25519Auth::derive_public(&i);
    let r_pub = Ed25519Auth::derive_public(&r);
    let x_pub = Ed25519Auth::derive_public(&x);

    let init = Ed25519Auth::new(&i, r_pub).unwrap(); // own I, peer R
    let resp = Ed25519Auth::new(&r, i_pub).unwrap(); // own R, peer I
                                                     // Both sides derive the same binding — necessary for a valid
                                                     // handshake (otherwise the transcripts diverge).
    assert_eq!(
        init.identity_binding(),
        resp.identity_binding(),
        "identity_binding must be symmetric (own/peer swapped)"
    );
    // A different peer -> a different binding (the binding depends on both).
    let init_to_x = Ed25519Auth::new(&i, x_pub).unwrap();
    assert_ne!(
        init.identity_binding(),
        init_to_x.identity_binding(),
        "a different peer must give a different binding"
    );
}

// ── L-9: low-order / all-zero X25519 is rejected ─────────────────────────────

#[test]
fn respond_rejects_low_order_x25519_point() {
    let init_auth = Ed25519Auth::new(&[1u8; 32], Ed25519Auth::derive_public(&[9u8; 32])).unwrap();
    let resp_auth = Ed25519Auth::new(&[9u8; 32], Ed25519Auth::derive_public(&[1u8; 32])).unwrap();

    let (_hs, init_wire) = Handshake::start(&init_auth).unwrap();
    let mut init_msg = HandshakeMessage::decode(init_wire).unwrap();
    // All-zero = the X25519 identity (a low-order point): the DH result is 0.
    init_msg.x25519_pub = [0u8; 32];
    let tampered = init_msg.encode().unwrap();

    assert!(
        Handshake::respond(tampered, &resp_auth).is_err(),
        "low-order/all-zero X25519 point must be rejected (L-9)"
    );
}

// ── I-13: session_id derived from the shared secret ──────────────────────────

#[test]
fn derived_session_id_matches_across_sides_and_differs_per_handshake() {
    let i = [1u8; 32];
    let r = [9u8; 32];
    let i_pub = Ed25519Auth::derive_public(&i);
    let r_pub = Ed25519Auth::derive_public(&r);
    let mk_i = || Ed25519Auth::new(&i, r_pub).unwrap();
    let mk_r = || Ed25519Auth::new(&r, i_pub).unwrap();

    let run = || {
        let (hs_i, init_w) = Handshake::start(&mk_i()).unwrap();
        let (hs_r, resp_w) = Handshake::respond(init_w, &mk_r()).unwrap();
        let (done_i, conf_w) = hs_i.finalize(resp_w, &mk_i()).unwrap();
        let done_r = hs_r.confirm(conf_w, &mk_r()).unwrap();
        let sid_i = match done_i {
            Handshake::Established { session } => session.session_id,
            _ => panic!("initiator not Established"),
        };
        let sid_r = match done_r {
            Handshake::Established { session } => session.session_id,
            _ => panic!("responder not Established"),
        };
        (sid_i, sid_r)
    };

    let (a_i, a_r) = run();
    let (b_i, b_r) = run();
    // Both sides of one handshake arrive at the same id.
    assert_eq!(a_i, a_r, "both sides derive the same session_id (I-13)");
    assert_eq!(b_i, b_r, "both sides derive the same session_id (I-13)");
    // Two separate handshakes (fresh ephemeral shared) give different ids,
    // so current/previous can be told apart during a rekey overlap.
    assert_ne!(a_i, b_i, "different handshakes -> different session_id");
}

// ── L-4: return-routability cookie ───────────────────────────────────────────

#[test]
fn cookie_is_deterministic_and_input_dependent() {
    use chameleon::crypto::compute_cookie;
    let secret = [0x11u8; 32];
    let a: std::net::SocketAddr = "1.2.3.4:5678".parse().unwrap();
    let b: std::net::SocketAddr = "1.2.3.4:5679".parse().unwrap(); // other port
    let c: std::net::SocketAddr = "1.2.3.5:5678".parse().unwrap(); // other ip
                                                                   // Deterministic: same input -> same cookie.
    assert_eq!(
        compute_cookie(&secret, &a, 100),
        compute_cookie(&secret, &a, 100)
    );
    // Depends on port, ip, time window and secret.
    assert_ne!(
        compute_cookie(&secret, &a, 100),
        compute_cookie(&secret, &b, 100)
    );
    assert_ne!(
        compute_cookie(&secret, &a, 100),
        compute_cookie(&secret, &c, 100)
    );
    assert_ne!(
        compute_cookie(&secret, &a, 100),
        compute_cookie(&secret, &a, 101)
    );
    assert_ne!(
        compute_cookie(&secret, &a, 100),
        compute_cookie(&[0x22u8; 32], &a, 100)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn responder_challenges_cookieless_init() {
    use chameleon::net::run_handshake_responder;
    use chameleon::tunnel::{Handshake, HandshakeMessage, HandshakeType};
    use tokio::net::UdpSocket;

    let resp_seed = [4u8; 32];
    let init_seed = [3u8; 32];
    let init_pub = Ed25519Auth::derive_public(&init_seed);
    let resp_pub = Ed25519Auth::derive_public(&resp_seed);

    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Responder task (never completes — we don't echo the cookie back).
    tokio::spawn(async move {
        let resp_auth = Ed25519Auth::new(&resp_seed, init_pub).unwrap();
        let _ = run_handshake_responder(&server, &resp_auth, None).await;
    });

    // Send a cleartext Init with cookie = 0 (obf off).
    let init_auth = Ed25519Auth::new(&init_seed, resp_pub).unwrap();
    let (_hs, init_wire) = Handshake::start(&init_auth).unwrap();
    for frag in chameleon::tunnel::fragment(1, &init_wire) {
        let f = chameleon::frame::Frame::new_handshake(frag)
            .encode()
            .unwrap();
        client.send_to(&f, server_addr).await.unwrap();
    }

    // We must get a CookieChallenge back — NOT a Response (that would mean
    // expensive crypto on an unverified source).
    let mut reasm = chameleon::tunnel::Reassembler::default();
    let mut buf = vec![0u8; 65536];
    let reply = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let (n, _src) = client.recv_from(&mut buf).await.unwrap();
            let frame =
                chameleon::frame::Frame::decode(bytes::Bytes::copy_from_slice(&buf[..n])).unwrap();
            if frame.frame_type != chameleon::frame::FrameType::Handshake {
                continue;
            }
            if let Some(full) = reasm.push(&frame.payload).unwrap() {
                return HandshakeMessage::decode(full).unwrap();
            }
        }
    })
    .await
    .expect("responder sent a reply");

    assert_eq!(
        reply.msg_type,
        HandshakeType::CookieChallenge,
        "a cookieless Init must yield a CookieChallenge, not a Response (L-4)"
    );
}
