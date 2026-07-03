//! Cryptografische kern: pluggable peer-authenticatie (Authenticator-trait),
//! het handshake-transcript, en key-derivation helpers.

use crate::error::{ChameleonError, Result};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// ── Authenticator-trait: het uitbreidingspunt voor hybride auth ──────────────

/// Een ondertekenings-/verificatieschema voor het handshake-transcript.
/// ML-DSA klikt er later naast via HybridAuth zonder de state machine te raken.
pub trait Authenticator: Send + Sync {
    fn sign(&self, transcript_hash: &[u8; 32]) -> Result<Vec<u8>>;
    fn verify(&self, transcript_hash: &[u8; 32], signature: &[u8]) -> Result<()>;
    fn signature_len(&self) -> usize;
    fn scheme(&self) -> &'static str;

    /// Een SYMMETRISCHE binding aan de identiteiten van beide partijen (eigen +
    /// peer, byte-lexicografisch gesorteerd zodat initiator en responder dezelfde
    /// waarde afleiden). Wordt in het transcript geabsorbeerd (L-6) zodat de
    /// handtekeningen niet alleen de ephemeral sleutels binden maar ook WIE er
    /// tekent — dat sluit unknown-key-share af. Mag leeg zijn voor een leg die
    /// geen symmetrische binding kan leveren (bv. ML-DSA, dat de eigen pub niet
    /// bewaart); een andere leg draagt de binding dan.
    fn identity_binding(&self) -> Vec<u8>;
}

// ── Ed25519 via ring ─────────────────────────────────────────────────────────

pub const ED25519_SIG_LEN: usize = 64;
pub const ED25519_PUB_LEN: usize = 32;

/// Eigen keypair + VOORGEDEELDE peer-pub (uit config, out-of-band).
pub struct Ed25519Auth {
    keypair: Ed25519KeyPair,
    peer_pub: [u8; ED25519_PUB_LEN],
}

impl Ed25519Auth {
    pub fn new(seed: &[u8], peer_pub: [u8; ED25519_PUB_LEN]) -> Result<Self> {
        let keypair = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|_| ChameleonError::Kdf("invalid Ed25519 seed".into()))?;
        Ok(Self { keypair, peer_pub })
    }

    pub fn public_key(&self) -> &[u8] {
        self.keypair.public_key().as_ref()
    }

    /// Leid de publieke sleutel af uit een seed, zonder een peer-sleutel nodig
    /// te hebben. Handig voor keygen en voor tests die beide kanten opzetten.
    pub fn derive_public(seed: &[u8]) -> [u8; ED25519_PUB_LEN] {
        let keypair = Ed25519KeyPair::from_seed_unchecked(seed)
            .expect("invalid Ed25519 seed in derive_public");
        let mut out = [0u8; ED25519_PUB_LEN];
        out.copy_from_slice(keypair.public_key().as_ref());
        out
    }
}

impl Authenticator for Ed25519Auth {
    fn sign(&self, transcript_hash: &[u8; 32]) -> Result<Vec<u8>> {
        Ok(self.keypair.sign(transcript_hash).as_ref().to_vec())
    }

    fn verify(&self, transcript_hash: &[u8; 32], signature: &[u8]) -> Result<()> {
        if signature.len() != ED25519_SIG_LEN {
            return Err(ChameleonError::Handshake {
                state: "verify".into(),
                msg: format!("Ed25519 sig len {} != {ED25519_SIG_LEN}", signature.len()),
            });
        }
        UnparsedPublicKey::new(&ED25519, &self.peer_pub)
            .verify(transcript_hash, signature)
            .map_err(|_| ChameleonError::Handshake {
                state: "verify".into(),
                msg: "Ed25519 verification failed (MITM or wrong peer)".into(),
            })
    }

    fn signature_len(&self) -> usize {
        ED25519_SIG_LEN
    }
    fn scheme(&self) -> &'static str {
        "ed25519"
    }

    fn identity_binding(&self) -> Vec<u8> {
        // Sorteer eigen + peer Ed25519-pubkey zodat beide kanten dezelfde binding
        // afleiden (symmetrisch: initiator en responder hebben own/peer omgekeerd).
        let own: &[u8] = self.public_key();
        let peer: &[u8] = &self.peer_pub;
        let (lo, hi) = if own <= peer {
            (own, peer)
        } else {
            (peer, own)
        };
        let mut v = Vec::with_capacity(ED25519_PUB_LEN * 2);
        v.extend_from_slice(lo);
        v.extend_from_slice(hi);
        v
    }
}

// ── ML-DSA-65 (FIPS 204) via pqcrypto-mldsa ──────────────────────────────────
//
// De post-quantum tegenhanger van Ed25519. ML-DSA's veiligheid berust op
// roostergebaseerde aannames die (anders dan de discrete-log van Ed25519)
// naar verwachting óók tegen een kwantumcomputer standhouden. We draaien 'm
// als TWEEDE leg naast Ed25519 in een HybridAuth: de handtekening geldt pas
// als BEIDE legs valideren, dus de authenticatie blijft staan zolang er ten
// minste één schema heel is. Sleutels zijn voorgedeeld (out-of-band), net als
// de Ed25519-identiteiten — er is dus geen trust-on-first-use-venster.

pub struct MlDsaAuth {
    secret: mldsa65::SecretKey,
    peer_pub: mldsa65::PublicKey,
}

impl MlDsaAuth {
    /// Genereer een nieuw ML-DSA-65 keypair. Geeft (public, secret) als rauwe
    /// bytes terug — geschikt om hex te coderen voor keygen/config.
    pub fn generate() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = mldsa65::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }

    /// Bouw uit de eigen secret key en de VOORGEDEELDE publieke sleutel van
    /// de peer (beide rauwe bytes, bv. uit hex in config).
    pub fn from_keys(secret: &[u8], peer_pub: &[u8]) -> Result<Self> {
        let secret = mldsa65::SecretKey::from_bytes(secret)
            .map_err(|_| ChameleonError::Kdf("invalid ML-DSA secret key".into()))?;
        let peer_pub = mldsa65::PublicKey::from_bytes(peer_pub)
            .map_err(|_| ChameleonError::Kdf("invalid ML-DSA peer public key".into()))?;
        Ok(Self { secret, peer_pub })
    }

    /// Verwachte lengtes van de sleutelmaterialen, voor validatie/diagnostiek.
    pub fn public_key_len() -> usize {
        mldsa65::public_key_bytes()
    }
    pub fn secret_key_len() -> usize {
        mldsa65::secret_key_bytes()
    }
}

impl Authenticator for MlDsaAuth {
    fn sign(&self, transcript_hash: &[u8; 32]) -> Result<Vec<u8>> {
        let sig = mldsa65::detached_sign(transcript_hash, &self.secret);
        Ok(sig.as_bytes().to_vec())
    }

    fn verify(&self, transcript_hash: &[u8; 32], signature: &[u8]) -> Result<()> {
        let sig = mldsa65::DetachedSignature::from_bytes(signature).map_err(|_| {
            ChameleonError::Handshake {
                state: "verify".into(),
                msg: "ML-DSA signature malformed".into(),
            }
        })?;
        mldsa65::verify_detached_signature(&sig, transcript_hash, &self.peer_pub).map_err(|_| {
            ChameleonError::Handshake {
                state: "verify".into(),
                msg: "ML-DSA verification failed (MITM or wrong peer)".into(),
            }
        })
    }

    // ML-DSA-handtekeningen hebben een vaste lengte; HybridAuth kan er daarom
    // veilig op offset op slicen.
    fn signature_len(&self) -> usize {
        mldsa65::signature_bytes()
    }
    fn scheme(&self) -> &'static str {
        "ml-dsa-65"
    }

    fn identity_binding(&self) -> Vec<u8> {
        // ML-DSA bewaart alleen de eigen SECRET key (de config levert geen eigen
        // pub, en pqcrypto leidt 'm niet uit de secret af), dus deze leg kan geen
        // symmetrische binding leveren. De Ed25519-leg draagt de identiteitsbinding;
        // beide identiteiten zijn hoe dan ook gepind en worden geverifieerd.
        Vec::new()
    }
}

// ── HybridAuth: combineert N legs, eist dat ALLE valideren ───────────────────

pub struct HybridAuth {
    legs: Vec<Box<dyn Authenticator>>,
}

impl HybridAuth {
    pub fn new(legs: Vec<Box<dyn Authenticator>>) -> Self {
        Self { legs }
    }
    pub fn total_sig_len(&self) -> usize {
        self.legs.iter().map(|a| a.signature_len()).sum()
    }
}

impl Authenticator for HybridAuth {
    fn sign(&self, transcript_hash: &[u8; 32]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.total_sig_len());
        for leg in &self.legs {
            out.extend_from_slice(&leg.sign(transcript_hash)?);
        }
        Ok(out)
    }

    fn verify(&self, transcript_hash: &[u8; 32], signature: &[u8]) -> Result<()> {
        let mut offset = 0;
        for leg in &self.legs {
            let len = leg.signature_len();
            let part =
                signature
                    .get(offset..offset + len)
                    .ok_or_else(|| ChameleonError::Handshake {
                        state: "verify".into(),
                        msg: "hybrid signature truncated".into(),
                    })?;
            leg.verify(transcript_hash, part)?;
            offset += len;
        }
        Ok(())
    }

    fn signature_len(&self) -> usize {
        self.total_sig_len()
    }
    fn scheme(&self) -> &'static str {
        "hybrid"
    }

    fn identity_binding(&self) -> Vec<u8> {
        // Concateneer de bindingen van alle legs (in vaste volgorde). In de
        // praktijk draagt de Ed25519-leg de binding en levert ML-DSA een lege.
        let mut v = Vec::new();
        for leg in &self.legs {
            v.extend_from_slice(&leg.identity_binding());
        }
        v
    }
}

// ── Transcript: rollende hash die de hele handshake bindt ────────────────────

#[derive(Clone)]
pub struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"Chameleon-PQ-v1 transcript");
        Self { hasher }
    }
    pub fn absorb(&mut self, bytes: &[u8]) {
        self.hasher.update((bytes.len() as u32).to_le_bytes());
        self.hasher.update(bytes);
    }
    pub fn hash(&self) -> [u8; 32] {
        self.hasher.clone().finalize().into()
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

// ── Key derivation ───────────────────────────────────────────────────────────

pub fn derive_shared(x_ss: &[u8], kyber_ss: &[u8]) -> Zeroizing<[u8; 32]> {
    use hkdf::Hkdf;
    let mut ikm = Zeroizing::new(Vec::new());
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(kyber_ss);
    let hk = Hkdf::<Sha256>::new(Some(b"Chameleon-PQ-v1-salt"), &ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"chameleon-pq hybrid session key", okm.as_mut())
        .expect("32 is a valid HKDF output length");
    okm
}

/// Bind een transcript-handtekening aan een ROL (initiator vs responder) via
/// domeinscheiding. Zonder dit tekenen beide kanten exact dezelfde transcript-
/// hash `th`, wat een gereflecteerde handtekening zou toelaten als de peers ooit
/// een identiteitssleutel delen. Door per rol een eigen label vóór `th` te
/// hashen gaan de twee handtekeningen aantoonbaar over verschillende berichten.
pub fn role_bound_hash(label: &[u8], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(transcript_hash);
    h.finalize().into()
}

pub fn mac_key_from(shared: &[u8; 32]) -> [u8; 32] {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(Some(b"Chameleon-PQ-v1-mac"), shared);
    let mut k = [0u8; 32];
    hk.expand(b"handshake mac key", &mut k)
        .expect("32 is a valid HKDF output length");
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa_sign_verify_roundtrip() {
        let (a_pub, a_sk) = MlDsaAuth::generate();
        let (b_pub, b_sk) = MlDsaAuth::generate();
        // a ondertekent, b verifieert a's handtekening met a's publieke sleutel.
        let a = MlDsaAuth::from_keys(&a_sk, &b_pub).unwrap();
        let b = MlDsaAuth::from_keys(&b_sk, &a_pub).unwrap();

        let th = [0x42u8; 32];
        let sig = a.sign(&th).unwrap();
        assert_eq!(sig.len(), a.signature_len());
        b.verify(&th, &sig)
            .expect("geldige ML-DSA-handtekening verifieert");

        // Een gewijzigd transcript moet falen.
        let mut other = th;
        other[0] ^= 0xFF;
        assert!(
            b.verify(&other, &sig).is_err(),
            "ander transcript -> verificatie faalt"
        );
    }

    #[test]
    fn hybrid_requires_all_legs() {
        // Hybride van Ed25519 + ML-DSA. De verifier krijgt een GELDIGE Ed25519-leg
        // maar een KAPOTTE ML-DSA-leg -> het geheel moet falen.
        let signer_seed = [7u8; 32];
        let signer_ed_pub = Ed25519Auth::derive_public(&signer_seed);
        let (signer_pq_pub, signer_pq_sk) = MlDsaAuth::generate();
        let (verifier_pq_pub, verifier_pq_sk) = MlDsaAuth::generate();

        let signer = HybridAuth::new(vec![
            Box::new(Ed25519Auth::new(&signer_seed, signer_ed_pub).unwrap()),
            Box::new(MlDsaAuth::from_keys(&signer_pq_sk, &verifier_pq_pub).unwrap()),
        ]);
        // Verifier verwacht signer's Ed25519 (correct) maar een VERKEERDE PQ-pub.
        let (wrong_pq_pub, _) = MlDsaAuth::generate();
        let verifier = HybridAuth::new(vec![
            Box::new(Ed25519Auth::new(&[8u8; 32], signer_ed_pub).unwrap()),
            Box::new(MlDsaAuth::from_keys(&verifier_pq_sk, &wrong_pq_pub).unwrap()),
        ]);

        let th = [0x11u8; 32];
        let sig = signer.sign(&th).unwrap();
        assert_eq!(sig.len(), signer.signature_len());
        // Ed25519-leg klopt, ML-DSA-leg niet -> hybride verificatie faalt.
        assert!(
            verifier.verify(&th, &sig).is_err(),
            "hybride auth moet falen als ook maar één leg niet valideert"
        );
        let _ = signer_pq_pub; // (publieke sleutel van signer, hier niet nodig)
    }
}
