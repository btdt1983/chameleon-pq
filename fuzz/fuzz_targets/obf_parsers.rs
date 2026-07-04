#![no_main]
//! Fuzz de datapad-obfuscatie-parsers (obf.rs): header-unmasking en de inner
//! framing. Attacker-input: elk geobfusceerd datapad-datagram / geopende blob.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = [0x42u8; 32];
    // unmask is de lengte-gepoorte entry; ct_slice mag pas ná een geslaagde unmask.
    if chameleon::obf::unmask(&key, data).is_some() {
        let _ = chameleon::obf::ct_slice(data);
    }
    // De inner framing wordt op de (elders) ontsleutelde plaintext toegepast.
    let _ = chameleon::obf::unpack_inner(data);
});
