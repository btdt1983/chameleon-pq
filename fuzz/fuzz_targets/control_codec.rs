#![no_main]
//! Fuzz the control-pipe codec (control/protocol.rs) and the policy parser.
//! Attacker input: any bytes a local user (or malware running as one) can write
//! to the service's named pipe, and, in principle, a planted policy.toml.
//!
//! Invariants: no input may panic or allocate beyond MAX_FRAME; a body that
//! decodes must encode again and decode to the same value (so a message cannot
//! mean one thing to the codec and another once re-serialised).
use chameleon::control::policy::Policy;
use chameleon::control::protocol::{decode, encode, parse_len, ClientMessage, ServerMessage};
use libfuzzer_sys::fuzz_target;

fn roundtrip<T>(body: &[u8])
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    if let Ok(msg) = decode::<T>(body) {
        let frame = encode(&msg).expect("a decoded message encodes");
        let again: T = decode(&frame[4..]).expect("an encoded message decodes");
        assert_eq!(msg, again);
    }
}

fuzz_target!(|data: &[u8]| {
    // The length header is validated before anything is allocated.
    if data.len() >= 4 {
        let _ = parse_len([data[0], data[1], data[2], data[3]]);
    }
    roundtrip::<ClientMessage>(data);
    roundtrip::<ServerMessage>(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Policy::parse(text, "fuzz");
    }
});
