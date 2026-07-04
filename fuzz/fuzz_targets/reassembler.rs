#![no_main]
//! Fuzz de fragment-reassembler (tunnel.rs). Splitst de input in stukken en
//! voedt ze als fragmenten in één reassembler, zodat de accumulatie-/cap-/
//! prune-logica op willekeurige (msg_id, index, total, payload) getest wordt.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reasm = chameleon::tunnel::Reassembler::default();
    // Wisselende chunk-grootte laat libfuzzer variabele fragment-headers vormen.
    for chunk in data.chunks(37) {
        let _ = reasm.push(chunk);
    }
});
