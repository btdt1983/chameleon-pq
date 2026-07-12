#![no_main]
//! Fuzz the cleartext data-path / handshake frame (frame.rs). Attacker input:
//! any UDP datagram in obf-off mode or a cleartext handshake fragment.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = chameleon::frame::Frame::decode(bytes::Bytes::copy_from_slice(data));
});
