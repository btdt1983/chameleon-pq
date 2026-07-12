//! Stable fuzz/robustness harness for the parsers of ATTACKER-controlled
//! input. Throws lots of seeded-random + adversarial bytes at each parser and
//! fails the moment one panics (out-of-bounds, overflow, unwrap, …).
//!
//! This is the regression guard that runs on stable (also in CI). The
//! coverage-guided variant lives in `fuzz/` (cargo-fuzz, nightly) and covers
//! the same surface more deeply. The invariant is the same for both: no byte
//! sequence may make a parser panic — it should cleanly return `Err`/`None`/`Ok`.

use bytes::Bytes;
use chameleon::frame::Frame;
use chameleon::hsobf;
use chameleon::obf;
use chameleon::session::{Session, SessionManager};
use chameleon::tunnel::{HandshakeMessage, Reassembler};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use zeroize::Zeroizing;

const ITERS: usize = 10_000;

/// Fixed edge cases (around known boundary values) + many seeded-random buffers
/// of varying length. The seed makes it reproducible; a crash is therefore
/// always exactly replayable.
fn corpus(seed: u64) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();

    // Boundary values: just under/at/over the header and message sizes the
    // parsers handle (HEADER_LEN=13, HP_HEADER_LEN+SAMPLE_LEN=29,
    // HS_FRAG_HEADER_LEN=8, HS_NONCE+TAG=28, HANDSHAKE_MSG_LEN=8192, …).
    let boundaries = [
        0usize, 1, 2, 3, 7, 8, 9, 12, 13, 14, 16, 27, 28, 29, 30, 63, 64, 65, 127, 128, 1023, 1024,
        1279, 1280, 1281, 8191, 8192, 8193,
    ];
    for &n in &boundaries {
        out.push(vec![0u8; n]); // all-zero
        out.push(vec![0xFFu8; n]); // all-ones (max u16 length fields etc.)
        let mut alt = vec![0u8; n];
        for (i, b) in alt.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        out.push(alt); // ascending pattern
    }

    // Seeded-random buffers up to ~MTU size, plus an occasional large message.
    let mut rng = StdRng::seed_from_u64(seed);
    for i in 0..ITERS {
        let cap = if i % 97 == 0 { 9000 } else { 1400 };
        let len = (rng.next_u32() as usize) % cap;
        let mut b = vec![0u8; len];
        rng.fill_bytes(&mut b);
        out.push(b);
    }
    out
}

#[test]
fn fuzz_frame_decode() {
    for buf in corpus(1) {
        let _ = Frame::decode(Bytes::from(buf));
    }
}

#[test]
fn fuzz_handshake_decode() {
    for buf in corpus(2) {
        let _ = HandshakeMessage::decode(Bytes::from(buf));
    }
}

#[test]
fn fuzz_obf_parsers() {
    let key = [0x42u8; 32];
    for buf in corpus(3) {
        // unmask is the safe gate; ct_slice is only valid after a successful unmask.
        if obf::unmask(&key, &buf).is_some() {
            let _ = obf::ct_slice(&buf);
        }
        let _ = obf::unpack_inner(&buf);
    }
}

#[test]
fn fuzz_hsobf_parsers() {
    let key = [0x37u8; 32];
    for buf in corpus(4) {
        let _ = hsobf::unmask_fragment(&key, &buf);
        let _ = hsobf::open(&key, &buf);
    }
}

#[test]
fn fuzz_reassembler() {
    // Feed random fragments into a single reassembler; the DoS cap + prune must
    // keep memory bounded without ever panicking.
    let mut reasm = Reassembler::default();
    for (i, buf) in corpus(5).into_iter().enumerate() {
        let _ = reasm.push(&buf);
        if i % 500 == 0 {
            reasm.prune_old(std::time::Duration::from_secs(0));
        }
    }
}

#[test]
fn fuzz_session_decrypt() {
    // A real session; throw random datagrams at both inbound paths.
    let sess = Session::from_handshake(1, Zeroizing::new([7u8; 32]), true).unwrap();
    let mgr = SessionManager::new(sess);
    for buf in corpus(6) {
        // Obfuscated data path (obf.rs → AEAD).
        let _ = mgr.decrypt_obf(&buf);
        // Classic data path: random session_id/counter + random ciphertext.
        if buf.len() >= 12 {
            let sid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let ctr = u64::from_le_bytes([
                buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
            ]);
            let _ = mgr.decrypt(sid, ctr, &buf[12..]);
        }
    }
}
