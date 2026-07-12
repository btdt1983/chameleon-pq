#![no_main]
//! Fuzz the handshake-obfuscation parsers (hsobf.rs): fragment unmasking and
//! opening the static-key envelope. This is the most exposed surface — it
//! processes PRE-AUTH datagrams (gated only by the static obf key).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = [0x37u8; 32];
    let _ = chameleon::hsobf::unmask_fragment(&key, data);
    let _ = chameleon::hsobf::open(&key, data);
});
