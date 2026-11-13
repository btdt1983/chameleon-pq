//! Reconnect policy for the service: when to try again after a failed attempt
//! or a dropped tunnel. Pure functions and a small state struct, so the
//! schedule is testable without a controller, a clock or a network.
//!
//! See `docs/DESIGN-windows-service.md` section 12.1.

use std::time::Duration;

/// A connection that lasted at least this long counts as good: the next drop
/// starts again from the shortest delay.
pub const STABLE_AFTER: Duration = Duration::from_secs(30);

/// Longest wait between attempts for a plain network failure.
const NETWORK_CAP_SECS: u64 = 30;
/// First and longest wait after the peer's identity check failed. A wrong pinned
/// key does not fix itself, so do not hammer the server.
const REJECTED_FIRST_SECS: u64 = 15;
const REJECTED_CAP_SECS: u64 = 300;
/// +-20% so a fleet that lost its server at the same moment does not return in step.
const JITTER: f64 = 0.2;

/// Why an attempt failed, as far as retrying is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailClass {
    /// Unreachable, timeout, adapter not ready yet: retry, at most every 30 s.
    Network,
    /// The server answered but failed our identity check (wrong pinned key or
    /// MITM). A server that does not trust *us* simply stays silent, which is
    /// indistinguishable from `Network` on the client side.
    Rejected,
    /// The config is unusable. Retrying cannot help; stop and say so.
    Permanent,
}

/// Prefix `supervisor::connect` puts on errors caused by the config itself.
pub const CONFIG_ERROR_PREFIX: &str = "configuration error: ";

/// Classify a connect error message. The outcome type carries a `String` shared
/// with the GUI, so this reads the few stable phrases that matter; anything
/// unknown is `Network`, which is the safe default (it keeps retrying, slowly).
/// The tests pin the phrases so a rewording upstream fails loudly here.
pub fn classify(message: &str) -> FailClass {
    if message.starts_with(CONFIG_ERROR_PREFIX) {
        FailClass::Permanent
    } else if message.contains("verification failed") {
        FailClass::Rejected
    } else {
        FailClass::Network
    }
}

/// Seconds to wait before attempt number `attempt` (1 = the first retry),
/// before jitter.
pub fn base_delay_secs(class: FailClass, attempt: u32) -> u64 {
    let step = attempt.saturating_sub(1).min(16);
    let doubling = |first: u64, cap: u64| first.saturating_mul(1u64 << step).min(cap);
    match class {
        FailClass::Network => doubling(1, NETWORK_CAP_SECS),
        FailClass::Rejected => doubling(REJECTED_FIRST_SECS, REJECTED_CAP_SECS),
        FailClass::Permanent => 0,
    }
}

/// [`base_delay_secs`] with jitter. `unit` is a random value in `[0, 1)`
/// (injected so tests are deterministic).
pub fn delay(class: FailClass, attempt: u32, unit: f64) -> Duration {
    let base = base_delay_secs(class, attempt) as f64;
    let factor = 1.0 + JITTER * (2.0 * unit.clamp(0.0, 1.0) - 1.0);
    Duration::from_secs_f64(base * factor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_schedule_doubles_to_the_cap() {
        let s: Vec<u64> = (1..=8)
            .map(|a| base_delay_secs(FailClass::Network, a))
            .collect();
        assert_eq!(s, vec![1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn rejected_schedule_is_slow_and_capped_at_five_minutes() {
        let s: Vec<u64> = (1..=7)
            .map(|a| base_delay_secs(FailClass::Rejected, a))
            .collect();
        assert_eq!(s, vec![15, 30, 60, 120, 240, 300, 300]);
    }

    #[test]
    fn huge_attempt_counts_do_not_overflow() {
        assert_eq!(base_delay_secs(FailClass::Network, u32::MAX), 30);
        assert_eq!(base_delay_secs(FailClass::Rejected, u32::MAX), 300);
    }

    #[test]
    fn jitter_stays_within_twenty_percent() {
        assert_eq!(delay(FailClass::Network, 5, 0.5), Duration::from_secs(16));
        assert_eq!(
            delay(FailClass::Network, 5, 0.0),
            Duration::from_secs_f64(12.8)
        );
        assert_eq!(
            delay(FailClass::Network, 5, 1.0),
            Duration::from_secs_f64(19.2)
        );
        // Out-of-range input is clamped, never produces a wild delay.
        assert_eq!(
            delay(FailClass::Network, 5, 9.0),
            delay(FailClass::Network, 5, 1.0)
        );
    }

    // These phrases come from other modules (net.rs, tunnel.rs, crypto.rs and
    // supervisor::connect). If one of them is reworded, this test must fail.
    #[test]
    fn classification_pins_the_upstream_phrases() {
        assert_eq!(
            classify("Handshake error in state 'initiator': no handshake response after retries (peer unreachable?)"),
            FailClass::Network
        );
        assert_eq!(
            classify("UDP / IO error: Network is unreachable"),
            FailClass::Network
        );
        assert_eq!(
            classify("Handshake error in state 'Ed25519': Ed25519 verification failed (MITM or wrong peer)"),
            FailClass::Rejected
        );
        assert_eq!(
            classify("Handshake error in state 'initiator': MAC verification failed"),
            FailClass::Rejected
        );
        assert_eq!(
            classify("configuration error: Key derivation failed: invalid Ed25519 seed"),
            FailClass::Permanent
        );
        assert_eq!(
            classify("something nobody has seen before"),
            FailClass::Network
        );
    }
}
