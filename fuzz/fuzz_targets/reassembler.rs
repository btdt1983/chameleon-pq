#![no_main]
//! Fuzz the fragment reassembler (tunnel.rs). Splits the input into chunks and
//! feeds them as fragments into one reassembler, so the accumulation / cap /
//! prune logic is tested on arbitrary (msg_id, index, total, payload).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reasm = chameleon::tunnel::Reassembler::default();
    // Varying the chunk size lets libfuzzer form variable fragment headers.
    for chunk in data.chunks(37) {
        let _ = reasm.push(chunk);
    }
});
