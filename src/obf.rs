//! Obfuscatie-laag voor het DATApad: QUIC-stijl header-protection + padding.
//!
//! ACHTERGROND: het oude datapad-frame (frame.rs) toonde op de wire nog steeds
//! een constant type-byte (0x01), een constant session_id voor de hele sessie
//! en een monotoon oplopende counter. Dat is — ook zónder statische magic — een
//! triviaal matchbare stroom-vingerafdruk, en de pakketlengte lekte exact de
//! plaintext-lengte. Deze laag maakt elk datapad-datagram op de wire tot een
//! uniform-ogende willekeurige bytereeks: geen vast byte, geen zichtbaar
//! session_id, geen zichtbare counter, geen zichtbaar frame-type, en (via
//! padding) geen exacte lengte.
//!
//! HOE (naar RFC 9001 §5.4, QUIC header-protection):
//!   1. De inner AEAD/nonce/replay-kern in session.rs blijft ONGEWIJZIGD. We
//!      versleutelen de plaintext precies als voorheen (aad = de logische
//!      header H = [0x01, session_id, counter]).
//!   2. Uit de resulterende ciphertext+tag nemen we een `sample` (de laatste 16
//!      bytes, altijd bínnen de AEAD-tag) en leiden daaruit een 13-byte masker
//!      af: mask = HMAC-SHA256(obf_key, sample)[..13].
//!   3. De zichtbare header wordt masked_H = H XOR mask. Wire = masked_H ‖ ct.
//!
//! De integriteit van de header komt NIET van het (malleable) XOR-masker maar
//! van het feit dat de ontvanger de teruggewonnen H als AEAD-aad meegeeft:
//! knoeien met masked_H óf met ct levert een verkeerde counter/sessie of een
//! kapotte tag op — in beide gevallen faalt de AEAD-verificatie. Exact zoals
//! QUIC: het masker is puur vertrouwelijkheid, de tag is de authenticatie.
//!
//! Het échte frame-type (Data/KeepAlive/Close) zit in de INNER framing
//! (pack_inner), versleuteld binnen de AEAD-plaintext, zodat op de wire elk
//! datagram structureel identiek is en het type nooit lekt.

use crate::error::{ChameleonError, Result};
use crate::frame::HEADER_LEN;
use bytes::Bytes;
use rand::RngCore;
use ring::hmac;

/// Aantal bytes dat we uit de ciphertext-staart bemonsteren voor het masker.
/// 16 past altijd binnen de AEAD-tag (ChaCha20 tag = 16, AEGIS = 32), óók bij
/// lege plaintext (keepalive), dus het is uniform over beide ciphers.
pub const SAMPLE_LEN: usize = 16;

/// Lengte van de gemaskeerde header op de wire — gelijk aan de oude cleartext
/// frame-header (type ‖ session_id ‖ counter), zodat de wire-overhead +0 is.
pub const HP_HEADER_LEN: usize = HEADER_LEN; // 13

/// MTU-veilige wire-grootte voor het datapad (frame::MAX_PAYLOAD + HEADER_LEN).
pub const MTU_WIRE: usize = 1280;

/// Op de wire draagt elk geobfusceerd datagram ALTIJD het Data-domein (0x01).
/// Het echte type zit versleuteld in de inner framing. Dit is óók de aad-type-
/// byte die session.rs::data_aad hardcodeert, dus de gemaskeerde header maskeert
/// exact de bytes die als aad worden meegeauthenticeerd.
const WIRE_TYPE_DATA: u8 = 0x01;

/// Minimale grootte van de inner framing: inner_type(1) + real_len(2).
const INNER_HEADER_LEN: usize = 3;

/// Padding-beleid voor het datapad. Instelbaar via config; verbergt de
/// pakketgrootte (die anders exact de plaintext-lengte lekt) ten koste van
/// bandbreedte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PadPolicy {
    /// Geen padding — laagste overhead, maar de grootte verraadt de lengte.
    Off,
    /// Pad naar grootteklassen (zie `BUCKETS`): verbergt de exacte lengte,
    /// matige overhead. De standaard.
    Bucketed,
    /// Pad elk pakket naar de maximale MTU-veilige grootte: beste grootte-
    /// obfuscatie, hoogste bandbreedte-kost.
    Full,
}

impl From<crate::config::PaddingPolicy> for PadPolicy {
    fn from(p: crate::config::PaddingPolicy) -> Self {
        match p {
            crate::config::PaddingPolicy::Off => PadPolicy::Off,
            crate::config::PaddingPolicy::Bucketed => PadPolicy::Bucketed,
            crate::config::PaddingPolicy::Full => PadPolicy::Full,
        }
    }
}

/// Grootteklassen (op de INNER framed-lengte) voor Bucketed padding. Bewust
/// klein gehouden: allemaal ruim onder de MTU-veilige limiet, zodat padding de
/// datagrammen nooit over de MTU duwt (extra IP-fragmentatie is zelf een
/// vingerafdruk). Pakketten groter dan de bovenste klasse worden niet gepad.
const BUCKETS: [usize; 5] = [64, 128, 256, 512, 1024];

/// Maximale inner framed-lengte die nog in een MTU-veilig wire-datagram past,
/// gegeven de tag-lengte van de gekozen cipher.
pub fn max_framed(tag_len: usize) -> usize {
    MTU_WIRE
        .saturating_sub(HP_HEADER_LEN)
        .saturating_sub(tag_len)
}

/// Wat de ontvanger uit de gemaskeerde header terugwint. Bevat GEEN plaintext:
/// de AEAD-open (in session.rs) gebeurt daarna met de teruggewonnen counter.
pub struct Recovered {
    /// Wire-type-domein (hoort 0x01 = Data te zijn). Puur ter sanity-check;
    /// de echte authenticatie is de AEAD-tag.
    pub wire_type: u8,
    pub session_id: u32,
    pub counter: u64,
}

/// Leid het 13-byte header-masker af uit de ciphertext-sample.
fn header_mask(obf_key: &[u8; 32], sample: &[u8]) -> [u8; HP_HEADER_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, obf_key);
    let tag = hmac::sign(&key, sample);
    let mut mask = [0u8; HP_HEADER_LEN];
    mask.copy_from_slice(&tag.as_ref()[..HP_HEADER_LEN]);
    mask
}

/// De ciphertext-staart die als sample dient. Aanname: `ct.len() >= SAMPLE_LEN`
/// (altijd waar — de AEAD-tag alleen al is ≥16 bytes).
fn sample_of(ct: &[u8]) -> &[u8] {
    &ct[ct.len() - SAMPLE_LEN..]
}

/// UITGAAND: gegeven de reeds-verzegelde ciphertext+tag, bouw het wire-datagram
/// `masked_H ‖ ct`. `counter`/`session_id` horen bij de nonce/aad waarmee `ct`
/// is verzegeld.
pub fn seal_wire(obf_key: &[u8; 32], session_id: u32, counter: u64, ct: &[u8]) -> Bytes {
    debug_assert!(ct.len() >= SAMPLE_LEN, "ct minstens één AEAD-tag lang");
    let mut h = [0u8; HP_HEADER_LEN];
    h[0] = WIRE_TYPE_DATA;
    h[1..5].copy_from_slice(&session_id.to_le_bytes());
    h[5..13].copy_from_slice(&counter.to_le_bytes());

    let mask = header_mask(obf_key, sample_of(ct));
    for i in 0..HP_HEADER_LEN {
        h[i] ^= mask[i];
    }

    let mut out = Vec::with_capacity(HP_HEADER_LEN + ct.len());
    out.extend_from_slice(&h);
    out.extend_from_slice(ct);
    Bytes::from(out)
}

/// INKOMEND: win uit één kandidaat-obf_key de header terug. Doet GEEN AEAD-open
/// (dat doet session.rs met de teruggewonnen counter). Geeft `None` bij een te
/// kort datagram — een goedkope, panic-vrije poort tegen ruis/korte pakketten.
pub fn unmask(obf_key: &[u8; 32], datagram: &[u8]) -> Option<Recovered> {
    if datagram.len() < HP_HEADER_LEN + SAMPLE_LEN {
        return None;
    }
    let mask = header_mask(obf_key, sample_of(datagram));
    let mut h = [0u8; HP_HEADER_LEN];
    for i in 0..HP_HEADER_LEN {
        h[i] = datagram[i] ^ mask[i];
    }
    Some(Recovered {
        wire_type: h[0],
        session_id: u32::from_le_bytes(h[1..5].try_into().unwrap()),
        counter: u64::from_le_bytes(h[5..13].try_into().unwrap()),
    })
}

/// De ciphertext (na de 13-byte header) van een inkomend datagram.
/// Aanroeper moet zelf de minimumlengte al via `unmask` hebben afgevangen.
pub fn ct_slice(datagram: &[u8]) -> &[u8] {
    &datagram[HP_HEADER_LEN..]
}

/// Verpak de plaintext in de inner framing (die daarna wordt verzegeld):
/// `inner_type(1) ‖ real_len(2 LE) ‖ plaintext ‖ random_pad`. Het echte type
/// zit hier ingebakken, dus het lekt niet op de wire. `max_framed` begrenst de
/// padding zodat het wire-datagram MTU-veilig blijft.
pub fn pack_inner(
    inner_type: u8,
    plaintext: &[u8],
    policy: PadPolicy,
    max_framed: usize,
) -> Vec<u8> {
    // Datapad-payloads zijn MTU-begrensd; real_len past ruim in een u16.
    debug_assert!(plaintext.len() <= u16::MAX as usize);
    let real_len = plaintext.len();
    let base = INNER_HEADER_LEN + real_len;
    let target = pad_target(base, policy, max_framed);

    let mut buf = Vec::with_capacity(target);
    buf.push(inner_type);
    buf.extend_from_slice(&(real_len as u16).to_le_bytes());
    buf.extend_from_slice(plaintext);
    if target > base {
        let mut pad = vec![0u8; target - base];
        rand::rngs::OsRng.fill_bytes(&mut pad);
        buf.extend_from_slice(&pad);
    }
    buf
}

/// Kies de doel-lengte voor de inner framing volgens het padding-beleid.
fn pad_target(base: usize, policy: PadPolicy, max_framed: usize) -> usize {
    match policy {
        PadPolicy::Off => base,
        PadPolicy::Full => {
            if base <= max_framed {
                max_framed
            } else {
                base // al groter dan MTU-veilig: niet verder opblazen
            }
        }
        PadPolicy::Bucketed => {
            for &b in BUCKETS.iter() {
                if b >= base && b <= max_framed {
                    return b;
                }
            }
            base // groter dan de bovenste klasse (of dan MTU): niet padden
        }
    }
}

/// Pak de inner framing weer uit na een geslaagde AEAD-open: geef
/// (inner_type, plaintext) terug, met de padding gestript.
pub fn unpack_inner(framed: &[u8]) -> Result<(u8, Bytes)> {
    if framed.len() < INNER_HEADER_LEN {
        return Err(ChameleonError::PacketTooShort {
            got: framed.len(),
            need: INNER_HEADER_LEN,
        });
    }
    let inner_type = framed[0];
    let real_len = u16::from_le_bytes([framed[1], framed[2]]) as usize;
    let end = INNER_HEADER_LEN + real_len;
    if end > framed.len() {
        // real_len wijst voorbij de buffer — corrupt/kwaadwillig.
        return Err(ChameleonError::DecryptionFailed);
    }
    Ok((
        inner_type,
        Bytes::copy_from_slice(&framed[INNER_HEADER_LEN..end]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Een nep-ciphertext van >= SAMPLE_LEN bytes voor de masking-tests
    // (de masking-laag is onafhankelijk van de AEAD; de end-to-end AEAD-tests
    // staan in tests/integration.rs).
    fn fake_ct(len: usize, fill: u8) -> Vec<u8> {
        vec![fill; len]
    }

    #[test]
    fn seal_unmask_roundtrip() {
        let key = [0x11u8; 32];
        let ct = fake_ct(40, 0xAB);
        let wire = seal_wire(&key, 0xDEADBEEF, 0x0102030405060708, &ct);
        // Header is 13 bytes; rest == ct.
        assert_eq!(wire.len(), HP_HEADER_LEN + ct.len());
        assert_eq!(ct_slice(&wire), &ct[..]);

        let rec = unmask(&key, &wire).expect("lang genoeg");
        assert_eq!(rec.wire_type, WIRE_TYPE_DATA);
        assert_eq!(rec.session_id, 0xDEADBEEF);
        assert_eq!(rec.counter, 0x0102030405060708);
    }

    #[test]
    fn wire_header_is_not_plaintext_0x01() {
        // Het eerste byte op de wire mag NIET het constante 0x01 zijn: het is
        // gemaskeerd. (Kans dat het toevallig 0x01 is, is ~1/256 — we kiezen een
        // ct waarbij dat niet zo is en checken vooral dat het van H[0] verschilt.)
        let key = [0x22u8; 32];
        let ct = fake_ct(32, 0x5C);
        let wire = seal_wire(&key, 7, 1, &ct);
        let mask = header_mask(&key, sample_of(&ct));
        assert_eq!(wire[0], WIRE_TYPE_DATA ^ mask[0]);
    }

    #[test]
    fn tamper_masked_header_changes_recovery() {
        let key = [0x33u8; 32];
        let ct = fake_ct(48, 0x77);
        let mut wire = seal_wire(&key, 100, 200, &ct).to_vec();
        // Knoei met het session_id-veld in de gemaskeerde header.
        wire[2] ^= 0xFF;
        let rec = unmask(&key, &wire).unwrap();
        // De teruggewonnen sessie verschilt -> in de praktijk valt hij buiten de
        // kandidaat en/of faalt de AEAD-open. Hier: recovery != origineel.
        assert_ne!(rec.session_id, 100);
    }

    #[test]
    fn min_length_gate_returns_none() {
        let key = [0x44u8; 32];
        assert!(unmask(&key, &[0u8; HP_HEADER_LEN]).is_none());
        assert!(unmask(&key, &[0u8; HP_HEADER_LEN + SAMPLE_LEN - 1]).is_none());
        assert!(unmask(&key, &[0u8; HP_HEADER_LEN + SAMPLE_LEN]).is_some());
    }

    #[test]
    fn pack_unpack_roundtrip_no_pad() {
        let framed = pack_inner(0x03, b"", PadPolicy::Off, max_framed(16));
        // Off: alleen inner header (3) + 0 plaintext.
        assert_eq!(framed.len(), INNER_HEADER_LEN);
        let (t, pt) = unpack_inner(&framed).unwrap();
        assert_eq!(t, 0x03);
        assert!(pt.is_empty());

        let framed = pack_inner(0x01, b"hallo", PadPolicy::Off, max_framed(16));
        let (t, pt) = unpack_inner(&framed).unwrap();
        assert_eq!(t, 0x01);
        assert_eq!(&pt[..], b"hallo");
    }

    #[test]
    fn bucketed_padding_rounds_up_and_strips() {
        let mf = max_framed(16);
        let framed = pack_inner(0x01, b"kort", PadPolicy::Bucketed, mf);
        // base = 3 + 4 = 7 -> eerste bucket 64.
        assert_eq!(framed.len(), 64);
        let (t, pt) = unpack_inner(&framed).unwrap();
        assert_eq!(t, 0x01);
        assert_eq!(&pt[..], b"kort");
    }

    #[test]
    fn full_padding_hides_length() {
        let mf = max_framed(16);
        let a = pack_inner(0x01, b"x", PadPolicy::Full, mf);
        let b = pack_inner(0x01, &vec![0u8; 500], PadPolicy::Full, mf);
        // Beide gepad tot dezelfde max_framed -> gelijke lengte (grootte verborgen).
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), mf);
        // En de payloads komen exact terug.
        assert_eq!(&unpack_inner(&a).unwrap().1[..], b"x");
        assert_eq!(unpack_inner(&b).unwrap().1.len(), 500);
    }

    #[test]
    fn unpack_rejects_bad_length() {
        // real_len wijst voorbij de buffer.
        let mut framed = vec![0x01u8, 0xFF, 0xFF]; // len=65535 maar buffer is 3
        framed.extend_from_slice(b"tiny");
        assert!(unpack_inner(&framed).is_err());
        // Te kort voor zelfs de inner header.
        assert!(unpack_inner(&[0x01u8, 0x00]).is_err());
    }
}
