#![no_main]
//! Fuzz the handshake message parser (tunnel.rs HandshakeMessage::decode).
//! Attacker input: a (possibly de-obfuscated) handshake blob.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = chameleon::tunnel::HandshakeMessage::decode(bytes::Bytes::copy_from_slice(data));
});
