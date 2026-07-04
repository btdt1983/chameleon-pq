#![no_main]
//! Fuzz de handshake-obfuscatie-parsers (hsobf.rs): fragment-unmasking en het
//! openen van de statische-sleutel-envelope. Dit is het meest blootgestelde
//! oppervlak — het verwerkt PRE-AUTH datagrammen (alleen door de statische
//! obf-sleutel gepoort).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = [0x37u8; 32];
    let _ = chameleon::hsobf::unmask_fragment(&key, data);
    let _ = chameleon::hsobf::open(&key, data);
});
