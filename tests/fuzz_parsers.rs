//! Stabiele fuzz-/robuustheids-harness voor de parsers van ATTACKER-
//! gecontroleerde input. Gooit veel seeded-random + adversariële bytes naar elke
//! parser en faalt zodra er één panic't (out-of-bounds, overflow, unwrap, …).
//!
//! Dit is de op-stable draaiende regressiewacht (ook in CI). De coverage-guided
//! variant staat in `fuzz/` (cargo-fuzz, nightly) en dekt hetzelfde oppervlak
//! dieper. De invariant is voor beide gelijk: geen enkele bytereeks mag een
//! parser laten panieken — hij hoort netjes `Err`/`None`/`Ok` te geven.

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

/// Vaste edge-cases (rond bekende grenswaarden) + veel seeded-random buffers van
/// wisselende lengte. De seed maakt het reproduceerbaar; een crash is dus altijd
/// exact opnieuw af te spelen.
fn corpus(seed: u64) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();

    // Grenswaarden: net onder/op/boven de header- en berichtgroottes die de
    // parsers hanteren (HEADER_LEN=13, HP_HEADER_LEN+SAMPLE_LEN=29,
    // HS_FRAG_HEADER_LEN=8, HS_NONCE+TAG=28, HANDSHAKE_MSG_LEN=8192, …).
    let boundaries = [
        0usize, 1, 2, 3, 7, 8, 9, 12, 13, 14, 16, 27, 28, 29, 30, 63, 64, 65, 127, 128, 1023, 1024,
        1279, 1280, 1281, 8191, 8192, 8193,
    ];
    for &n in &boundaries {
        out.push(vec![0u8; n]); // all-zero
        out.push(vec![0xFFu8; n]); // all-ones (max u16-lengtevelden etc.)
        let mut alt = vec![0u8; n];
        for (i, b) in alt.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        out.push(alt); // oplopend patroon
    }

    // Seeded-random buffers tot ~MTU-grootte, plus af en toe een groot bericht.
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
        // unmask is de veilige poort; ct_slice mag pas ná een geslaagde unmask.
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
    // Voed willekeurige fragmenten in één reassembler; de DoS-cap + prune moeten
    // het geheugen begrensd houden zonder ooit te panieken.
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
    // Een echte sessie; gooi random datagrammen naar beide inbound-paden.
    let sess = Session::from_handshake(1, Zeroizing::new([7u8; 32]), true).unwrap();
    let mgr = SessionManager::new(sess);
    for buf in corpus(6) {
        // Geobfusceerd datapad (obf.rs → AEAD).
        let _ = mgr.decrypt_obf(&buf);
        // Klassiek datapad: random session_id/counter + willekeurige ciphertext.
        if buf.len() >= 12 {
            let sid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let ctr = u64::from_le_bytes([
                buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
            ]);
            let _ = mgr.decrypt(sid, ctr, &buf[12..]);
        }
    }
}
