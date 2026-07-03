//! Actieve sessie: per-richting sleutels, nonce-beheer, AEAD via ring,
//! sliding-window replay-bescherming, en een SessionManager voor rekey.

use crate::aead::{make_directional, AeadAlgo, DirectionalAead};
use crate::error::{ChameleonError, Result};
use crate::frame::FrameType;
use crate::obf::{self, PadPolicy};
use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use zeroize::Zeroizing;

// ── Sliding-window replay-bescherming ────────────────────────────────────────
//
// Venster van 2048 pakketten (WireGuard-schaal), opgeslagen als een bitset
// van 32 u64-woorden. Ruim genoeg voor paden met flinke herordening.
// De logica is identiek aan de oude 64-bits versie; alleen de bit-indexering
// loopt nu over (woord, bit-in-woord) i.p.v. één u64.

const WINDOW_BITS: u64 = 2048;
const WINDOW_WORDS: usize = (WINDOW_BITS / 64) as usize; // 32

struct ReplayWindow {
    highest: u64,
    /// bit i (gemeten als afstand onder `highest`) gezet = counter gezien.
    bitmap: [u64; WINDOW_WORDS],
    seeded: bool,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0u64; WINDOW_WORDS],
            seeded: false,
        }
    }

    /// Test of een bit op `delta` posities onder `highest` gezet is.
    fn bit_is_set(&self, delta: u64) -> bool {
        let word = (delta / 64) as usize;
        let bit = delta % 64;
        (self.bitmap[word] >> bit) & 1 == 1
    }

    /// Zet de bit op `delta` posities onder `highest`.
    fn set_bit(&mut self, delta: u64) {
        let word = (delta / 64) as usize;
        let bit = delta % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    /// Schuif het hele venster `shift` posities op (richting nieuwere counters).
    /// Bits die buiten het venster vallen verdwijnen; nieuwe posities zijn 0.
    fn shift_window(&mut self, shift: u64) {
        if shift >= WINDOW_BITS {
            // Venster volledig voorbij: alles wissen.
            self.bitmap = [0u64; WINDOW_WORDS];
            return;
        }
        let word_shift = (shift / 64) as usize;
        let bit_shift = shift % 64;

        if bit_shift == 0 {
            // Hele-woord-verschuiving, geen bit-carry nodig.
            for i in (0..WINDOW_WORDS).rev() {
                self.bitmap[i] = if i >= word_shift {
                    self.bitmap[i - word_shift]
                } else {
                    0
                };
            }
        } else {
            for i in (0..WINDOW_WORDS).rev() {
                let mut v = 0u64;
                if i >= word_shift {
                    v = self.bitmap[i - word_shift] << bit_shift;
                    if i > word_shift {
                        v |= self.bitmap[i - word_shift - 1] >> (64 - bit_shift);
                    }
                }
                self.bitmap[i] = v;
            }
        }
    }

    /// Goedkope pre-check. Wijzigt niets; commit gebeurt apart na decryptie.
    fn check(&self, counter: u64) -> Result<()> {
        if !self.seeded {
            return Ok(());
        }
        if counter > self.highest {
            return Ok(());
        }
        let delta = self.highest - counter;
        if delta >= WINDOW_BITS {
            return Err(ChameleonError::DecryptionFailed);
        }
        if self.bit_is_set(delta) {
            return Err(ChameleonError::DecryptionFailed);
        }
        Ok(())
    }

    /// Commit ná succesvolle decryptie.
    fn commit(&mut self, counter: u64) {
        if !self.seeded {
            self.seeded = true;
            self.highest = counter;
            self.bitmap = [0u64; WINDOW_WORDS];
            self.set_bit(0); // huidige positie
            return;
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            self.shift_window(shift);
            self.highest = counter;
            self.set_bit(0); // nieuwe hoogste = delta 0
        } else {
            let delta = self.highest - counter;
            if delta < WINDOW_BITS {
                self.set_bit(delta);
            }
        }
    }
}

// ── Session ──────────────────────────────────────────────────────────────────

pub struct Session {
    pub session_id: u32,
    algo: AeadAlgo,
    tx_aead: Box<dyn DirectionalAead>,
    rx_aead: Box<dyn DirectionalAead>,
    tx_counter: AtomicU64,
    tx_salt: [u8; 4],
    rx_salt: [u8; 4],
    rekey_at: u64,
    replay: Mutex<ReplayWindow>,
    /// Per-richting header-protection sleutels voor de obfuscatie-laag (obf.rs).
    /// Los van de AEAD-sleutels, afgeleid uit hetzelfde shared secret met eigen
    /// HKDF-labels. Opgeslagen als plain [u8;32] (ze gaan als &[u8;32] naar de
    /// obf-laag) maar worden bij drop expliciet gewist — zie `impl Drop`.
    tx_obf_key: [u8; 32],
    rx_obf_key: [u8; 32],
}

impl Session {
    /// Bouw een sessie met de standaard-onderhandelde cipher (ChaCha20 tenzij
    /// elders anders gekozen). Behouden voor bestaande call-sites/tests.
    pub fn from_handshake(
        session_id: u32,
        shared: Zeroizing<[u8; 32]>,
        is_initiator: bool,
    ) -> Result<Self> {
        // Default: ChaCha20-Poly1305 (veilig op alle hardware). De handshake
        // kiest expliciet via `from_handshake_with_algo` zodra AEGIS in beeld is.
        Self::from_handshake_with_algo(session_id, shared, is_initiator, AeadAlgo::ChaCha20Poly1305)
    }

    /// Bouw een sessie met een EXPLICIET onderhandeld AEAD-algoritme.
    pub fn from_handshake_with_algo(
        session_id: u32,
        shared: Zeroizing<[u8; 32]>,
        is_initiator: bool,
        algo: AeadAlgo,
    ) -> Result<Self> {
        let (tx_bytes, rx_bytes) = derive_directional_keys(&shared, is_initiator)?;

        let tx_aead = make_directional(algo, &tx_bytes)?;
        let rx_aead = make_directional(algo, &rx_bytes)?;

        let (tx_obf_key, rx_obf_key) = derive_obf_keys(&shared, is_initiator)?;

        let (tx_salt, rx_salt) = if is_initiator {
            ([0x01, 0, 0, 0], [0x02, 0, 0, 0])
        } else {
            ([0x02, 0, 0, 0], [0x01, 0, 0, 0])
        };

        Ok(Self {
            session_id,
            algo,
            tx_aead,
            rx_aead,
            tx_counter: AtomicU64::new(0),
            tx_salt,
            rx_salt,
            rekey_at: 1 << 48,
            replay: Mutex::new(ReplayWindow::new()),
            tx_obf_key,
            rx_obf_key,
        })
    }

    pub fn algo(&self) -> AeadAlgo {
        self.algo
    }

    pub fn tx_counter_value(&self) -> u64 {
        self.tx_counter.load(Ordering::Relaxed)
    }

    pub fn rekey_at(&self) -> u64 {
        self.rekey_at
    }

    /// Versleutel een uitgaand pakket. Geeft (counter, ciphertext+tag).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(u64, Bytes)> {
        let counter = self.tx_counter.fetch_add(1, Ordering::Relaxed);
        if counter >= self.rekey_at {
            return Err(ChameleonError::RekeyRequired);
        }
        let nonce = self.make_nonce(self.tx_salt, counter);
        let aad = self.data_aad(counter);
        let ct = self.tx_aead.seal(&nonce, &aad, plaintext)?;
        Ok((counter, Bytes::from(ct)))
    }

    /// Ontsleutel een inkomend pakket. Volgorde: check → decrypt → commit.
    pub fn decrypt(&self, counter: u64, ciphertext: &[u8]) -> Result<Bytes> {
        {
            let win = self.replay.lock();
            win.check(counter)?;
        }
        let nonce = self.make_nonce(self.rx_salt, counter);
        let aad = self.data_aad(counter);
        let plain = self.rx_aead.open(&nonce, &aad, ciphertext)?;
        let plain = Bytes::from(plain);
        {
            let mut win = self.replay.lock();
            win.check(counter)?; // her-check onder lock = race-veilig
            win.commit(counter);
        }
        Ok(plain)
    }

    /// Bouw de nonce op de juiste breedte voor het gekozen algoritme:
    /// salt (4 bytes) gevolgd door de little-endian counter, rechts met nullen
    /// aangevuld tot de nonce-lengte van het algoritme (12 of 32 bytes).
    fn make_nonce(&self, salt: [u8; 4], counter: u64) -> Vec<u8> {
        let len = self.algo.nonce_len();
        let mut n = vec![0u8; len];
        n[..4].copy_from_slice(&salt);
        n[4..12].copy_from_slice(&counter.to_le_bytes());
        n
    }

    /// Associated data voor een Data-frame: de zichtbare frame-header
    /// (type-domeinscheiding ‖ session_id ‖ counter). Door deze als AAD mee te
    /// authenticeren breekt elke wijziging aan de cleartext-header de AEAD-tag,
    /// dus een actieve aanvaller kan de header niet ongemerkt aanpassen.
    fn data_aad(&self, counter: u64) -> [u8; 13] {
        let mut aad = [0u8; 13];
        aad[0] = 0x01; // FrameType::Data — domeinscheiding tegen type-confusie
        aad[1..5].copy_from_slice(&self.session_id.to_le_bytes());
        aad[5..13].copy_from_slice(&counter.to_le_bytes());
        aad
    }

    // ── Geobfusceerd datapad (obf.rs-laag bovenop de AEAD-kern) ──────────────

    /// Verzegel een uitgaand datapad-datagram met obfuscatie: verpak het echte
    /// `inner_type` + de plaintext in de inner framing (met padding), versleutel
    /// dat via de ONGEWIJZIGDE AEAD-kern, en maskeer de header. Geeft het
    /// wire-klare datagram terug (masked_header ‖ ct).
    pub fn seal_obf(&self, inner_type: u8, plaintext: &[u8], policy: PadPolicy) -> Result<Bytes> {
        let max_framed = obf::max_framed(self.algo.tag_len());
        let framed = obf::pack_inner(inner_type, plaintext, policy, max_framed);
        let (counter, ct) = self.encrypt(&framed)?;
        Ok(obf::seal_wire(
            &self.tx_obf_key,
            self.session_id,
            counter,
            &ct,
        ))
    }

    /// Probeer een inkomend datagram als geobfusceerd datapad-pakket voor DEZE
    /// sessie te openen. Geeft:
    ///   • Ok(Some((type, plaintext))) — geopend en geauthenticeerd voor ons;
    ///   • Ok(None)                    — niet voor deze sessie (te kort, ander
    ///                                    session_id, of AEAD-open faalt) → de
    ///                                    aanroeper probeert een andere kandidaat;
    ///   • Err(..)                     — geauthenticeerd maar de inner framing is
    ///                                    corrupt/onbekend (protocolfout).
    fn try_open_obf(&self, datagram: &[u8]) -> Result<Option<(FrameType, Bytes)>> {
        let rec = match obf::unmask(&self.rx_obf_key, datagram) {
            Some(r) => r,
            None => return Ok(None), // te kort / ruis
        };
        // Goedkope voorfilter: het session_id moet matchen. Dit is een
        // performance-poort, niet de veiligheidsgrens — die is de AEAD-tag.
        if rec.session_id != self.session_id {
            return Ok(None);
        }
        match self.decrypt(rec.counter, obf::ct_slice(datagram)) {
            Ok(framed) => {
                let (inner_type, pt) = obf::unpack_inner(&framed)?;
                Ok(Some((FrameType::from_u8(inner_type)?, pt)))
            }
            // Tag-mismatch/replay: niet (meer) voor ons — laat de aanroeper de
            // volgende kandidaat proberen; anders wordt het uiteindelijk gedropt.
            Err(_) => Ok(None),
        }
    }
}

// Wis de obfuscatie-header-sleutels bij drop. De AEAD-sleutels zelf zitten in de
// Box<dyn DirectionalAead> en worden daar gewist (ring / AegisDir::drop); de
// afgeleide directional key-bytes zijn Zeroizing. Zo blijft geen enkele
// sessie-sleutel na drop in het geheugen staan.
impl Drop for Session {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.tx_obf_key.zeroize();
        self.rx_obf_key.zeroize();
    }
}

/// Per-richting sleutelpaar (tx, rx), beide zeroized bij drop.
type DirectionalKeys = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

fn derive_directional_keys(shared: &[u8; 32], is_initiator: bool) -> Result<DirectionalKeys> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"Chameleon-PQ-v1-directional"), shared);
    let mut a = Zeroizing::new([0u8; 32]);
    let mut b = Zeroizing::new([0u8; 32]);
    hk.expand(b"key-A->B", a.as_mut())
        .map_err(|_| ChameleonError::Kdf("A".into()))?;
    hk.expand(b"key-B->A", b.as_mut())
        .map_err(|_| ChameleonError::Kdf("B".into()))?;
    // Initiator stuurt op A->B en ontvangt op B->A; responder omgekeerd.
    if is_initiator {
        Ok((a, b))
    } else {
        Ok((b, a))
    }
}

/// Per-richting header-protection sleutels voor de obfuscatie-laag. Uit
/// hetzelfde shared secret en dezelfde HKDF-context als de AEAD-sleutels, maar
/// met EIGEN info-labels — HKDF-Expand met verschillende `info` levert
/// onafhankelijke sleutels, dus schone domeinscheiding t.o.v. `key-A->B`/`B->A`.
fn derive_obf_keys(shared: &[u8; 32], is_initiator: bool) -> Result<([u8; 32], [u8; 32])> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"Chameleon-PQ-v1-directional"), shared);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    hk.expand(b"obf-A->B", &mut a)
        .map_err(|_| ChameleonError::Kdf("obf-A".into()))?;
    hk.expand(b"obf-B->A", &mut b)
        .map_err(|_| ChameleonError::Kdf("obf-B".into()))?;
    // Zelfde richting-swap als de AEAD-sleutels: (tx_obf, rx_obf).
    if is_initiator {
        Ok((a, b))
    } else {
        Ok((b, a))
    }
}

// ── SessionManager: actieve + vorige sessie tijdens rekey ────────────────────

const REKEY_AFTER_FRACTION_NUM: u64 = 3;
const REKEY_AFTER_FRACTION_DEN: u64 = 4;

pub struct SessionManager {
    current: RwLock<Arc<Session>>,
    previous: RwLock<Option<Arc<Session>>>,
    rekey_threshold: u64,
    rekey_in_progress: AtomicU64,
    /// Tijdstip van de laatste rekey-poging. Voorkomt een rekey-storm:
    /// na een mislukte of net-voltooide rekey mag er niet onmiddellijk
    /// een nieuwe starten. Opgeslagen als Mutex<Instant> omdat Instant
    /// niet atomair is.
    last_rekey_attempt: Mutex<std::time::Instant>,
}

/// Minimuminterval tussen twee rekey-pogingen. Een mislukte rekey
/// kan hierdoor niet in een strakke lus opnieuw afvuren.
const MIN_REKEY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

impl SessionManager {
    pub fn new(initial: Session) -> Self {
        let rekey_at = initial.rekey_at();
        Self {
            current: RwLock::new(Arc::new(initial)),
            previous: RwLock::new(None),
            rekey_threshold: rekey_at / REKEY_AFTER_FRACTION_DEN * REKEY_AFTER_FRACTION_NUM,
            rekey_in_progress: AtomicU64::new(0),
            // Begin ver in het verleden zodat de eerste rekey niet geblokkeerd wordt.
            last_rekey_attempt: Mutex::new(std::time::Instant::now() - MIN_REKEY_INTERVAL * 2),
        }
    }

    pub fn current_session_id(&self) -> u32 {
        self.current.read().session_id
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(u32, u64, Bytes)> {
        let sess = self.current.read().clone();
        let (counter, ct) = sess.encrypt(plaintext)?;
        Ok((sess.session_id, counter, ct))
    }

    pub fn decrypt(&self, session_id: u32, counter: u64, ct: &[u8]) -> Result<Bytes> {
        {
            let cur = self.current.read();
            if cur.session_id == session_id {
                return cur.decrypt(counter, ct);
            }
        }
        let prev = self.previous.read();
        if let Some(p) = prev.as_ref() {
            if p.session_id == session_id {
                return p.decrypt(counter, ct);
            }
        }
        Err(ChameleonError::DecryptionFailed)
    }

    // ── Geobfusceerd datapad ─────────────────────────────────────────────────

    /// Verzegel een uitgaand datapad-datagram met obfuscatie op de HUIDIGE
    /// sessie. `inner_type` is het echte frame-type (Data/KeepAlive/Close).
    pub fn seal_obf(&self, inner_type: u8, plaintext: &[u8], policy: PadPolicy) -> Result<Bytes> {
        let sess = self.current.read().clone();
        sess.seal_obf(inner_type, plaintext, policy)
    }

    /// Verzegel een cover/dummy-datagram (Fase 3): een geobfusceerd datapad-
    /// pakket met inner-type Padding en lege payload. De ontvanger gooit het
    /// stil weg (telt wél als teken van leven). Vult lege slots in de
    /// constant-rate pacer, zodat burst-/idle-patronen verdwijnen.
    pub fn seal_cover(&self, policy: PadPolicy) -> Result<Bytes> {
        let sess = self.current.read().clone();
        sess.seal_obf(FrameType::Padding as u8, b"", policy)
    }

    /// Open een inkomend geobfusceerd datagram via trial-decryptie over de
    /// actieve sessies (huidige eerst, dan de vorige tijdens een rekey-overlap).
    /// De trial-set is ≤2; een pakket dat bij geen van beide opent, wordt
    /// gedropt (ziet er uit als ruis). Geeft (echt frame-type, plaintext).
    pub fn decrypt_obf(&self, datagram: &[u8]) -> Result<(FrameType, Bytes)> {
        let current = self.current.read().clone();
        if let Some(res) = current.try_open_obf(datagram)? {
            return Ok(res);
        }
        let previous = self.previous.read().clone();
        if let Some(p) = previous {
            if let Some(res) = p.try_open_obf(datagram)? {
                return Ok(res);
            }
        }
        Err(ChameleonError::DecryptionFailed)
    }

    /// True (eenmalig) zodra de tx-counter de drempel passeert ÉN er sinds
    /// de vorige poging genoeg tijd is verstreken (anti-storm). De aanroeper
    /// MOET bij mislukking `abort_rekey()` aanroepen om de claim vrij te geven,
    /// of `install_new_session()` bij succes.
    pub fn needs_rekey(&self) -> bool {
        if self.current.read().tx_counter_value() < self.rekey_threshold {
            return false;
        }
        // Anti-storm: respecteer het minimuminterval sinds de vorige poging.
        {
            let last = self.last_rekey_attempt.lock();
            if last.elapsed() < MIN_REKEY_INTERVAL {
                return false;
            }
        }
        // Claim de rekey-slot atomair; alleen de eerste aanroeper wint.
        let won = self
            .rekey_in_progress
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if won {
            *self.last_rekey_attempt.lock() = std::time::Instant::now();
        }
        won
    }

    /// Geef de rekey-claim vrij na een MISLUKTE poging, zodat een latere
    /// poging (na het interval) opnieuw kan starten. De timestamp blijft
    /// staan, dus de storm-bescherming geldt nog steeds.
    pub fn abort_rekey(&self) {
        self.rekey_in_progress.store(0, Ordering::Release);
    }

    pub fn install_new_session(&self, new_session: Session) {
        let new_arc = Arc::new(new_session);
        let old = {
            let mut cur = self.current.write();
            let old = cur.clone();
            *cur = new_arc;
            old
        };
        *self.previous.write() = Some(old);
        self.rekey_in_progress.store(0, Ordering::Release);
    }

    pub fn retire_previous(&self) {
        *self.previous.write() = None;
    }
}
