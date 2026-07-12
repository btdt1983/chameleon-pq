#![no_main]
//! Fuzz the full inbound data path (session.rs): trial-decryption of an
//! obfuscated datagram over the active session (unmask → session_id filter →
//! AEAD-open → inner unpack). Attacker input: any incoming datagram.
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
