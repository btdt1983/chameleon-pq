//! Constant-rate pacer (Phase 3): timing / cover-traffic obfuscation.
//!
//! BACKGROUND: Phases 1 and 2 made every datagram unrecognisable in SHAPE (no
//! visible fields, hidden sizes). What remained is the TIMING: a passive
//! observer still sees WHEN data flows (bursts, idle gaps). This layer sends
//! packets at a FIXED rhythm and fills empty slots with dummy/cover packets
//! that the receiver silently discards, so bursts and idle-vs-active dissolve
//! into an even stream.
//!
//! This module holds only the PURE decision logic (no tokio), so it can be
//! unit-tested deterministically. The async loop in main.rs owns the ticker
//! and calls `next_emit` per emission slot.
//!
//! HONEST LIMIT: constant-rate hides the SHAPE of the traffic, not the
//! EXISTENCE of the tunnel (the endpoints are known, site-to-site) or the total
//! duration. It costs constant bandwidth and adds up to ~1/rate latency per
//! packet; the configured rate is both the floor and the ceiling.

use std::time::{Duration, Instant};

/// Shape mode of the pacer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeMode {
    /// Constant bit-rate: fill EVERY slot with a packet (real or cover), even
    /// when idle. Strongest timing concealment; constant bandwidth cost.
    Cbr,
    /// Adaptive: pace during activity and for `cooldown` afterwards; go quiet
    /// when truly idle. Cheaper, but coarse active-vs-idle leaks again.
    Adaptive,
}

/// What must happen in one emission slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emit {
    /// A real packet is ready → send it.
    Real,
    /// No real packet → send a cover/dummy packet.
    Cover,
    /// No real packet and no cover needed (Adaptive, idle) → send nothing.
    Idle,
}

/// The pure pacer state. Tracks only when the last REAL packet left, for the
/// Adaptive cooldown.
pub struct Pacer {
    mode: ShapeMode,
    cooldown: Duration,
    last_real: Option<Instant>,
}

impl Pacer {
    pub fn new(mode: ShapeMode, cooldown: Duration) -> Self {
        Self {
            mode,
            cooldown,
            last_real: None,
        }
    }

    /// Decide (and record) what happens in one emission slot.
    /// `has_real` = whether a real packet is queued RIGHT NOW;
    /// `now` = current time (drives the Adaptive cooldown). A `Real` resets
    /// the cooldown immediately, so cover traffic keeps running for `cooldown`
    /// after the last real activity.
    pub fn next_emit(&mut self, has_real: bool, now: Instant) -> Emit {
        if has_real {
            self.last_real = Some(now);
            return Emit::Real;
        }
        match self.mode {
            ShapeMode::Cbr => Emit::Cover,
            ShapeMode::Adaptive => match self.last_real {
                Some(t) if now.duration_since(t) < self.cooldown => Emit::Cover,
                _ => Emit::Idle,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbr_covers_when_idle() {
        let mut p = Pacer::new(ShapeMode::Cbr, Duration::from_millis(500));
        let now = Instant::now();
        // Real packet ready -> Real.
        assert_eq!(p.next_emit(true, now), Emit::Real);
        // Nothing ready, CBR -> always Cover (even idle).
        assert_eq!(p.next_emit(false, now), Emit::Cover);
        assert_eq!(
            p.next_emit(false, now + Duration::from_secs(3600)),
            Emit::Cover
        );
    }

    #[test]
    fn adaptive_cover_within_cooldown_then_idle() {
        let mut p = Pacer::new(ShapeMode::Adaptive, Duration::from_millis(500));
        let t0 = Instant::now();
        assert_eq!(p.next_emit(true, t0), Emit::Real);
        // Within the cooldown after the last real packet -> still Cover.
        assert_eq!(
            p.next_emit(false, t0 + Duration::from_millis(100)),
            Emit::Cover
        );
        // Past the cooldown -> Idle (quiet).
        assert_eq!(
            p.next_emit(false, t0 + Duration::from_millis(600)),
            Emit::Idle
        );
    }

    #[test]
    fn adaptive_idle_from_start() {
        let mut p = Pacer::new(ShapeMode::Adaptive, Duration::from_millis(500));
        // Never a real packet yet -> Idle right away.
        assert_eq!(p.next_emit(false, Instant::now()), Emit::Idle);
    }

    #[test]
    fn real_resets_adaptive_cooldown() {
        let mut p = Pacer::new(ShapeMode::Adaptive, Duration::from_millis(500));
        let t0 = Instant::now();
        assert_eq!(p.next_emit(true, t0), Emit::Real);
        // Just past cooldown with no real traffic -> Idle.
        assert_eq!(
            p.next_emit(false, t0 + Duration::from_millis(600)),
            Emit::Idle
        );
        // A new real packet resets the clock -> Cover again within cooldown.
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(p.next_emit(true, t1), Emit::Real);
        assert_eq!(
            p.next_emit(false, t1 + Duration::from_millis(100)),
            Emit::Cover
        );
    }
}
