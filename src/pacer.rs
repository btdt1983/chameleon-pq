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

/// How much cover an Adaptive pacer may emit. Without a limit, every empty
/// slot of the cooldown after ANY real packet is filled at the profile's full
/// ceiling: one stray background packet then costs megabytes (measured on a
/// phone: tens of MB per minute at idle, enough to starve a 150 Mbit/s uplink's
/// ACKs). Mainstream defenses (WTF-PAD, FRONT, Maybenot) bound padding by a
/// budget for the same reason. Ignored in CBR, whose whole point is a constant
/// rate.
#[derive(Debug, Clone, Copy)]
pub struct CoverBudget {
    /// Cover packets one activity burst (a "trigger") may start with.
    pub per_trigger: u32,
    /// Extra cover packets earned per real packet in the same burst.
    pub ratio: f32,
}

impl CoverBudget {
    /// No limit: the previous behaviour (fill every slot up to the ceiling).
    pub const UNLIMITED: CoverBudget = CoverBudget {
        per_trigger: u32::MAX,
        ratio: 0.0,
    };
}

/// The pure pacer state. Tracks when the last REAL packet left (Adaptive
/// cooldown) and how much cover the current activity burst may still spend.
pub struct Pacer {
    mode: ShapeMode,
    cooldown: Duration,
    budget: CoverBudget,
    last_real: Option<Instant>,
    /// Cover packets still available in the current activity burst.
    allowance: f32,
}

impl Pacer {
    pub fn new(mode: ShapeMode, cooldown: Duration, budget: CoverBudget) -> Self {
        Self {
            mode,
            cooldown,
            budget,
            last_real: None,
            allowance: 0.0,
        }
    }

    /// Decide (and record) what happens in one emission slot.
    /// `has_real` = whether a real packet is queued RIGHT NOW;
    /// `now` = current time (drives the Adaptive cooldown). A `Real` resets
    /// the cooldown immediately, so cover traffic keeps running for `cooldown`
    /// after the last real activity.
    pub fn next_emit(&mut self, has_real: bool, now: Instant) -> Emit {
        if has_real {
            // A real packet after the cooldown has lapsed (or the first one
            // ever) starts a new activity burst with a fresh budget.
            let new_trigger = match self.last_real {
                Some(t) => now.duration_since(t) >= self.cooldown,
                None => true,
            };
            if new_trigger {
                self.allowance = self.budget.per_trigger as f32;
            }
            self.allowance += self.budget.ratio;
            self.last_real = Some(now);
            return Emit::Real;
        }
        match self.mode {
            ShapeMode::Cbr => Emit::Cover,
            ShapeMode::Adaptive => match self.last_real {
                Some(t) if now.duration_since(t) < self.cooldown && self.allowance >= 1.0 => {
                    self.allowance -= 1.0;
                    Emit::Cover
                }
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
        let mut p = Pacer::new(
            ShapeMode::Cbr,
            Duration::from_millis(500),
            CoverBudget::UNLIMITED,
        );
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
        let mut p = Pacer::new(
            ShapeMode::Adaptive,
            Duration::from_millis(500),
            CoverBudget::UNLIMITED,
        );
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
        let mut p = Pacer::new(
            ShapeMode::Adaptive,
            Duration::from_millis(500),
            CoverBudget::UNLIMITED,
        );
        // Never a real packet yet -> Idle right away.
        assert_eq!(p.next_emit(false, Instant::now()), Emit::Idle);
    }

    #[test]
    fn real_resets_adaptive_cooldown() {
        let mut p = Pacer::new(
            ShapeMode::Adaptive,
            Duration::from_millis(500),
            CoverBudget::UNLIMITED,
        );
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

    #[test]
    fn budget_caps_cover_per_trigger() {
        let b = CoverBudget {
            per_trigger: 3,
            ratio: 0.0,
        };
        let mut p = Pacer::new(ShapeMode::Adaptive, Duration::from_millis(500), b);
        let t0 = Instant::now();
        assert_eq!(p.next_emit(true, t0), Emit::Real);
        // Exactly the budget, then silence even though the cooldown is still running.
        for _ in 0..3 {
            assert_eq!(
                p.next_emit(false, t0 + Duration::from_millis(10)),
                Emit::Cover
            );
        }
        assert_eq!(
            p.next_emit(false, t0 + Duration::from_millis(20)),
            Emit::Idle
        );
    }

    #[test]
    fn new_trigger_refills_the_budget() {
        let b = CoverBudget {
            per_trigger: 2,
            ratio: 0.0,
        };
        let mut p = Pacer::new(ShapeMode::Adaptive, Duration::from_millis(500), b);
        let t0 = Instant::now();
        p.next_emit(true, t0);
        assert_eq!(p.next_emit(false, t0), Emit::Cover);
        assert_eq!(p.next_emit(false, t0), Emit::Cover);
        assert_eq!(p.next_emit(false, t0), Emit::Idle);
        // Quiet for longer than the cooldown, then a stray packet: a new trigger.
        let t1 = t0 + Duration::from_secs(5);
        assert_eq!(p.next_emit(true, t1), Emit::Real);
        assert_eq!(p.next_emit(false, t1), Emit::Cover);
        assert_eq!(p.next_emit(false, t1), Emit::Cover);
        assert_eq!(p.next_emit(false, t1), Emit::Idle);
    }

    #[test]
    fn budget_does_not_accumulate_across_triggers() {
        let b = CoverBudget {
            per_trigger: 2,
            ratio: 0.0,
        };
        let mut p = Pacer::new(ShapeMode::Adaptive, Duration::from_millis(500), b);
        let t0 = Instant::now();
        // Ten stray packets, each a separate trigger, never spending any cover.
        for i in 0..10u64 {
            p.next_emit(true, t0 + Duration::from_secs(i * 10));
        }
        let t = t0 + Duration::from_secs(100);
        p.next_emit(true, t);
        let covers = (0..100)
            .filter(|_| p.next_emit(false, t) == Emit::Cover)
            .count();
        assert_eq!(covers, 2, "only this trigger's own budget is available");
    }

    #[test]
    fn ratio_earns_cover_proportional_to_real_traffic() {
        let b = CoverBudget {
            per_trigger: 0,
            ratio: 0.5,
        };
        let mut p = Pacer::new(ShapeMode::Adaptive, Duration::from_millis(500), b);
        let t = Instant::now();
        for _ in 0..10 {
            p.next_emit(true, t);
        }
        let covers = (0..100)
            .filter(|_| p.next_emit(false, t) == Emit::Cover)
            .count();
        assert_eq!(
            covers, 5,
            "10 real packets at ratio 0.5 earn 5 cover packets"
        );
    }

    #[test]
    fn cbr_ignores_the_budget() {
        let b = CoverBudget {
            per_trigger: 0,
            ratio: 0.0,
        };
        let mut p = Pacer::new(ShapeMode::Cbr, Duration::from_millis(500), b);
        let now = Instant::now();
        assert_eq!(p.next_emit(false, now), Emit::Cover);
    }
}
