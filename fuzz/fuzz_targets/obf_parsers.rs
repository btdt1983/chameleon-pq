#![no_main]
//! Fuzz the data-path obfuscation parsers (obf.rs): header unmasking and the
//! inner framing. Attacker input: any obfuscated data-path datagram / opened blob.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = [0x42u8; 32];
    // unmask is the length-gated entry; ct_slice may only run after a successful unmask.
    if chameleon::obf::unmask(&key, data).is_some() {
        let _ = chameleon::obf::ct_slice(data);
    }
    // The inner framing is applied to the (elsewhere) decrypted plaintext.
    let _ = chameleon::obf::unpack_inner(data);
});
