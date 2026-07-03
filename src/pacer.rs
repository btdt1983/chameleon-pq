//! Constant-rate pacer (Fase 3): timing-/cover-traffic-obfuscatie.
//!
//! ACHTERGROND: Fase 1 en 2 maakten elk datagram qua VORM onherkenbaar (geen
//! zichtbare velden, verborgen groottes). Wat overbleef is de TIMING: een
//! passieve waarnemer ziet nog steeds WANNEER data stroomt (bursts, idle-gaten).
//! Deze laag verstuurt pakketten op een VAST ritme en vult lege slots met
//! dummy/cover-pakketten die de ontvanger stil weggooit, zodat bursts en
//! idle-vs-actief oplossen in een gelijkmatige stroom.
//!
//! Deze module bevat alleen de PURE beslislogica (geen tokio), zodat ze
//! deterministisch te unit-testen is. De async-lus in main.rs bezit de ticker
//! en roept `next_emit` per emissie-slot aan.
//!
//! EERLIJKE GRENS: constant-rate verbergt de VORM van het verkeer, niet het
//! BESTAAN van de tunnel (de endpoints zijn bekend, site-to-site) of de totale
//! duur. Het kost constante bandbreedte en voegt tot ~1/rate latency per pakket
//! toe; de geconfigureerde rate is zowel de bodem als het plafond.

use std::time::{Duration, Instant};

/// Vorm-modus van de pacer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeMode {
    /// Constant bit-rate: vul ELK slot met een pakket (echt of cover), ook
    /// wanneer idle. Sterkste timing-verberging; constante bandbreedtekost.
    Cbr,
    /// Adaptief: pace tijdens activiteit en nog `cooldown` daarna; ga stil
    /// wanneer echt idle. Goedkoper, maar grof actief-vs-idle lekt weer.
    Adaptive,
}

/// Wat er in één emissie-slot moet gebeuren.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emit {
    /// Er staat een echt pakket klaar → stuur dat.
    Real,
    /// Geen echt pakket → stuur een cover/dummy-pakket.
    Cover,
    /// Geen echt pakket en geen cover nodig (Adaptive, idle) → stuur niets.
    Idle,
}

/// De pure pacer-toestand. Houdt alleen bij wanneer het laatste ECHTE pakket
/// vertrok, voor de Adaptive-cooldown.
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

    /// Beslis (en registreer) wat er in één emissie-slot gebeurt.
    /// `has_real` = of er NU nog een echt pakket in de wachtrij staat;
    /// `now` = huidige tijd (bepaalt de Adaptive-cooldown). Een `Real` reset
    /// meteen de cooldown, zodat cover-verkeer nog `cooldown` doorloopt na de
    /// laatste echte activiteit.
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
        // Echt pakket klaar -> Real.
        assert_eq!(p.next_emit(true, now), Emit::Real);
        // Niets klaar, CBR -> altijd Cover (ook idle).
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
        // Binnen de cooldown na het laatste echte pakket -> nog Cover.
        assert_eq!(
            p.next_emit(false, t0 + Duration::from_millis(100)),
            Emit::Cover
        );
        // Voorbij de cooldown -> Idle (stil).
        assert_eq!(
            p.next_emit(false, t0 + Duration::from_millis(600)),
            Emit::Idle
        );
    }

    #[test]
    fn adaptive_idle_from_start() {
        let mut p = Pacer::new(ShapeMode::Adaptive, Duration::from_millis(500));
        // Nog nooit een echt pakket -> meteen Idle.
        assert_eq!(p.next_emit(false, Instant::now()), Emit::Idle);
    }

    #[test]
    fn real_resets_adaptive_cooldown() {
        let mut p = Pacer::new(ShapeMode::Adaptive, Duration::from_millis(500));
        let t0 = Instant::now();
        assert_eq!(p.next_emit(true, t0), Emit::Real);
        // Net voorbij cooldown zonder echt verkeer -> Idle.
        assert_eq!(
            p.next_emit(false, t0 + Duration::from_millis(600)),
            Emit::Idle
        );
        // Nieuw echt pakket reset de klok -> daarna weer Cover binnen cooldown.
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(p.next_emit(true, t1), Emit::Real);
        assert_eq!(
            p.next_emit(false, t1 + Duration::from_millis(100)),
            Emit::Cover
        );
    }
}
