#![no_main]
//! Fuzz de handshake-berichtparser (tunnel.rs HandshakeMessage::decode).
//! Attacker-input: een (mogelijk ge-de-obfusceerde) handshake-blob.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = chameleon::tunnel::HandshakeMessage::decode(bytes::Bytes::copy_from_slice(data));
});
