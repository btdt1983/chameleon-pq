#![no_main]
//! Fuzz het volledige inbound datapad (session.rs): trial-decryptie van een
//! geobfusceerd datagram over de actieve sessie (unmask → session_id-filter →
//! AEAD-open → inner unpack). Attacker-input: elk inkomend datagram.
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static MGR: OnceLock<chameleon::session::SessionManager> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let mgr = MGR.get_or_init(|| {
        let sess =
            chameleon::session::Session::from_handshake(1, zeroize::Zeroizing::new([7u8; 32]), true)
                .unwrap();
        chameleon::session::SessionManager::new(sess)
    });
    let _ = mgr.decrypt_obf(data);
});
