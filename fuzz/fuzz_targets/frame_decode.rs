#![no_main]
//! Fuzz het cleartext datapad-/handshake-frame (frame.rs). Attacker-input:
//! elk UDP-datagram in obf-off-modus of een cleartext-handshake-fragment.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = chameleon::frame::Frame::decode(bytes::Bytes::copy_from_slice(data));
});
