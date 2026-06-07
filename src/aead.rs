//! Pluggable AEAD-laag voor het datapad.
//!
//! Het datapad gebruikt één AEAD-cipher per sessie. Twee opties zitten achter
//! de `Aead`-trait:
//!
//!   • ChaCha20-Poly1305 (via `ring`) — constant-time op ALLE hardware, de
//!     veilige universele standaard en terugval.
//!   • AEGIS-256X2 — sneller én een sterkere AEAD dan AES-GCM op CPU's MET
//!     AES-hardware-instructies; CAESAR-winnaar, open, IETF-draft voor TLS 1.3.
//!     Zonder AES-hardware valt AEGIS terug op software-AES (trager én
//!     timing-gevoelig), dus we kiezen 'm ALLEEN als de CPU het ondersteunt.
//!
//! De keuze valt bij sessie-opbouw via `AeadAlgo::preferred()`, die de CPU
//! bevraagt. De gekozen algoritme-id wordt in de handshake-transcript gebonden
//! (zie tunnel.rs), zodat een aanvaller de keuze niet naar de zwakkere optie
//! kan downgraden zonder de MAC te breken.

use crate::error::{ChameleonError, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use zeroize::Zeroizing;

/// Welke AEAD een sessie gebruikt. Het wire-id (u8) wordt in het transcript
/// gebonden, dus de getallen zijn stabiel en mogen niet wijzigen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AeadAlgo {
    ChaCha20Poly1305 = 0x01,
    Aegis256X2 = 0x02,
}

impl AeadAlgo {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::ChaCha20Poly1305),
            0x02 => Ok(Self::Aegis256X2),
            _ => Err(ChameleonError::Handshake {
                state: "aead".into(),
                msg: format!("unknown AEAD id {v}"),
            }),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Nonce-lengte in bytes voor dit algoritme.
    pub fn nonce_len(self) -> usize {
        match self {
            AeadAlgo::ChaCha20Poly1305 => 12, // 96-bit
            AeadAlgo::Aegis256X2 => 32,       // 256-bit
        }
    }

    /// De voorkeurskeuze voor DEZE machine. AEGIS alleen als de CPU AES-
    /// hardware heeft; anders de veilige, constant-time ChaCha20.
    ///
    /// Belangrijk: dit is een lokale voorkeur. Beide peers moeten hetzelfde
    /// algoritme draaien (zie `negotiate`), want de sessiesleutels en nonce-
    /// lengtes verschillen per cipher.
    pub fn preferred() -> Self {
        if cpu_has_aes() {
            AeadAlgo::Aegis256X2
        } else {
            AeadAlgo::ChaCha20Poly1305
        }
    }

    /// Onderhandel het te gebruiken algoritme tussen de eigen voorkeur en die
    /// van de peer. Regel: gebruik AEGIS alleen als BEIDE kanten het kunnen;
    /// val anders terug op ChaCha20. Zo werkt een sterke server samen met een
    /// zwakke client zonder dat iemand een onveilige software-AES draait.
    pub fn negotiate(local: Self, peer: Self) -> Self {
        if local == AeadAlgo::Aegis256X2 && peer == AeadAlgo::Aegis256X2 {
            AeadAlgo::Aegis256X2
        } else {
            AeadAlgo::ChaCha20Poly1305
        }
    }
}

/// Detecteer of de CPU hardware-AES-instructies heeft.
/// x86/x86_64: AES-NI. aarch64: de AES-crypto-extensie.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpu_has_aes() -> bool {
    std::arch::is_x86_feature_detected!("aes")
}

#[cfg(target_arch = "aarch64")]
fn cpu_has_aes() -> bool {
    std::arch::is_aarch64_feature_detected!("aes")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
fn cpu_has_aes() -> bool {
    false // onbekende architectuur: kies de veilige, universele cipher
}

// ── De Aead-trait ────────────────────────────────────────────────────────────

/// Eén richting (tx óf rx) van een sessie-cipher. Versleutelt/ontsleutelt
/// in-place-achtig met een per-pakket nonce die uit (salt, counter) komt.
/// `aad` (associated data) wordt mee-geauthenticeerd maar niet versleuteld;
/// het datapad bindt hier de frame-header in (type/session_id/counter), zodat
/// knoeien met de zichtbare header de tag-verificatie laat falen.
pub trait DirectionalAead: Send + Sync {
    /// Versleutel `plaintext`, geef ciphertext+tag terug.
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    /// Ontsleutel `ciphertext` (incl. tag), geef plaintext terug.
    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

// ── ChaCha20-Poly1305 via ring ───────────────────────────────────────────────

pub struct ChaChaDir {
    key: LessSafeKey,
}

impl ChaChaDir {
    pub fn new(key_bytes: &Zeroizing<[u8; 32]>) -> Result<Self> {
        let key = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &**key_bytes)
                .map_err(|_| ChameleonError::Kdf("chacha key".into()))?,
        );
        Ok(Self { key })
    }
}

impl DirectionalAead for ChaChaDir {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| ChameleonError::DecryptionFailed)?;
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| ChameleonError::DecryptionFailed)?;
        Ok(buf)
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| ChameleonError::DecryptionFailed)?;
        let mut buf = ciphertext.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| ChameleonError::DecryptionFailed)?;
        Ok(plain.to_vec())
    }
}

// ── AEGIS-256X2 ──────────────────────────────────────────────────────────────

use aegis::aegis256x2::Aegis256X2;

const AEGIS_TAG_LEN: usize = 32; // we gebruiken de 256-bit tag

pub struct AegisDir {
    key: [u8; 32],
}

impl AegisDir {
    pub fn new(key_bytes: &Zeroizing<[u8; 32]>) -> Result<Self> {
        Ok(Self { key: **key_bytes })
    }
}

impl DirectionalAead for AegisDir {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 32 {
            return Err(ChameleonError::DecryptionFailed);
        }
        let mut n = [0u8; 32];
        n.copy_from_slice(nonce);
        let cipher = Aegis256X2::<AEGIS_TAG_LEN>::new(&self.key, &n);
        let (mut ct, tag) = cipher.encrypt(plaintext, aad);
        // Wire-formaat: ciphertext || tag (zelfde stijl als ring's append-tag).
        ct.extend_from_slice(&tag);
        Ok(ct)
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 32 || ciphertext.len() < AEGIS_TAG_LEN {
            return Err(ChameleonError::DecryptionFailed);
        }
        let mut n = [0u8; 32];
        n.copy_from_slice(nonce);
        let split = ciphertext.len() - AEGIS_TAG_LEN;
        let (ct, tag_bytes) = ciphertext.split_at(split);
        let mut tag = [0u8; AEGIS_TAG_LEN];
        tag.copy_from_slice(tag_bytes);
        let cipher = Aegis256X2::<AEGIS_TAG_LEN>::new(&self.key, &n);
        cipher
            .decrypt(ct, &tag, aad)
            .map_err(|_| ChameleonError::DecryptionFailed)
    }
}

// ── Constructor: bouw de juiste richting-cipher voor een algoritme ───────────

pub fn make_directional(
    algo: AeadAlgo,
    key_bytes: &Zeroizing<[u8; 32]>,
) -> Result<Box<dyn DirectionalAead>> {
    match algo {
        AeadAlgo::ChaCha20Poly1305 => Ok(Box::new(ChaChaDir::new(key_bytes)?)),
        AeadAlgo::Aegis256X2 => Ok(Box::new(AegisDir::new(key_bytes)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha_roundtrip() {
        let key = Zeroizing::new([0x11u8; 32]);
        let dir = ChaChaDir::new(&key).unwrap();
        let nonce = [0x22u8; 12];
        let ct = dir.seal(&nonce, b"hdr", b"geheim bericht").unwrap();
        let pt = dir.open(&nonce, b"hdr", &ct).unwrap();
        assert_eq!(&pt[..], b"geheim bericht");
    }

    #[test]
    fn aegis_roundtrip() {
        let key = Zeroizing::new([0x33u8; 32]);
        let dir = AegisDir::new(&key).unwrap();
        let nonce = [0x44u8; 32];
        let ct = dir.seal(&nonce, b"hdr", b"geheim bericht").unwrap();
        let pt = dir.open(&nonce, b"hdr", &ct).unwrap();
        assert_eq!(&pt[..], b"geheim bericht");
    }

    #[test]
    fn aegis_rejects_tampered() {
        let key = Zeroizing::new([0x55u8; 32]);
        let dir = AegisDir::new(&key).unwrap();
        let nonce = [0x66u8; 32];
        let mut ct = dir.seal(&nonce, b"hdr", b"abc").unwrap();
        ct[0] ^= 0xFF; // knoei met de ciphertext
        assert!(dir.open(&nonce, b"hdr", &ct).is_err());
    }

    #[test]
    fn aad_mismatch_is_rejected() {
        // Geauthenticeerde header: wijzigen van de AAD (bv. een vervalst
        // session_id/type in de frame-header) moet de verificatie laten falen.
        // ChaCha20: 12-byte nonce.
        let c = ChaChaDir::new(&Zeroizing::new([0x77u8; 32])).unwrap();
        let ct = c.seal(&[0x01u8; 12], b"header-A", b"payload").unwrap();
        assert!(
            c.open(&[0x01u8; 12], b"header-B", &ct).is_err(),
            "ChaCha: andere AAD moet falen"
        );
        assert_eq!(
            &c.open(&[0x01u8; 12], b"header-A", &ct).unwrap()[..],
            b"payload"
        );

        // AEGIS: 32-byte nonce.
        let a = AegisDir::new(&Zeroizing::new([0x88u8; 32])).unwrap();
        let ct = a.seal(&[0x02u8; 32], b"header-A", b"payload").unwrap();
        assert!(
            a.open(&[0x02u8; 32], b"header-B", &ct).is_err(),
            "AEGIS: andere AAD moet falen"
        );
        assert_eq!(
            &a.open(&[0x02u8; 32], b"header-A", &ct).unwrap()[..],
            b"payload"
        );
    }

    #[test]
    fn negotiate_requires_both_for_aegis() {
        use AeadAlgo::*;
        assert_eq!(AeadAlgo::negotiate(Aegis256X2, Aegis256X2), Aegis256X2);
        assert_eq!(
            AeadAlgo::negotiate(Aegis256X2, ChaCha20Poly1305),
            ChaCha20Poly1305
        );
        assert_eq!(
            AeadAlgo::negotiate(ChaCha20Poly1305, Aegis256X2),
            ChaCha20Poly1305
        );
        assert_eq!(
            AeadAlgo::negotiate(ChaCha20Poly1305, ChaCha20Poly1305),
            ChaCha20Poly1305
        );
    }
}
