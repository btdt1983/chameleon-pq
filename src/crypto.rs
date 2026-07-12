//! Cryptographic core: pluggable peer authentication (Authenticator trait),
//! the handshake transcript, and key-derivation helpers.

use crate::error::{ChameleonError, Result};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use ring::hmac;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use zeroize::Zeroizing;

// ── Authenticator trait: the extension point for hybrid auth ─────────────────

/// A signing/verification scheme for the handshake transcript. ML-DSA later
/// clicks in alongside via HybridAuth without touching the state machine.
pub trait Authenticator: Send + Sync {
    fn sign(&self, transcript_hash: &[u8; 32]) -> Result<Vec<u8>>;
    fn verify(&self, transcript_hash: &[u8; 32], signature: &[u8]) -> Result<()>;
    fn signature_len(&self) -> usize;
    fn scheme(&self) -> &'static str;

    /// A SYMMETRIC binding to the identities of both parties (own + peer,
    /// byte-lexicographically sorted so initiator and responder derive the same
    /// value). Absorbed into the transcript (L-6) so the signatures bind not
    /// only the ephemeral keys but also WHO is signing — this closes off
    /// unknown-key-share. May be empty for a leg that cannot provide a
    /// symmetric binding (e.g. ML-DSA, which does not keep its own pub);
    /// another leg then carries the binding.
    fn identity_binding(&self) -> Vec<u8>;
}

// ── Ed25519 via ring ─────────────────────────────────────────────────────────

pub const ED25519_SIG_LEN: usize = 64;
pub const ED25519_PUB_LEN: usize = 32;

/// Own keypair + PRE-SHARED peer pub (from config, out-of-band).
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

    /// Derive the public key from a seed, without needing a peer key. Handy
    /// for keygen and for tests that set up both sides.
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
        // Sort own + peer Ed25519 pubkey so both sides derive the same binding
        // (symmetric: initiator and responder have own/peer reversed).
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
// The post-quantum counterpart of Ed25519. ML-DSA's security rests on
// lattice-based assumptions that (unlike the discrete log of Ed25519) are
// expected to hold up against a quantum computer too. We run it as a SECOND
// leg alongside Ed25519 in a HybridAuth: the signature only holds if BOTH
// legs validate, so the authentication stands as long as at least one scheme
// is intact. Keys are pre-shared (out-of-band), just like the Ed25519
// identities — so there is no trust-on-first-use window.

pub struct MlDsaAuth {
    secret: mldsa65::SecretKey,
    peer_pub: mldsa65::PublicKey,
}

impl MlDsaAuth {
    /// Generate a new ML-DSA-65 keypair. Returns (public, secret) as raw
    /// bytes — suitable to hex-encode for keygen/config.
    pub fn generate() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = mldsa65::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }

    /// Build from our own secret key and the PRE-SHARED public key of the
    /// peer (both raw bytes, e.g. from hex in config).
    pub fn from_keys(secret: &[u8], peer_pub: &[u8]) -> Result<Self> {
        let secret = mldsa65::SecretKey::from_bytes(secret)
            .map_err(|_| ChameleonError::Kdf("invalid ML-DSA secret key".into()))?;
        let peer_pub = mldsa65::PublicKey::from_bytes(peer_pub)
            .map_err(|_| ChameleonError::Kdf("invalid ML-DSA peer public key".into()))?;
        Ok(Self { secret, peer_pub })
    }

    /// Expected lengths of the key materials, for validation/diagnostics.
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

    // ML-DSA signatures have a fixed length; HybridAuth can therefore safely
    // slice them at an offset.
    fn signature_len(&self) -> usize {
        mldsa65::signature_bytes()
    }
    fn scheme(&self) -> &'static str {
        "ml-dsa-65"
    }

    fn identity_binding(&self) -> Vec<u8> {
        // ML-DSA only keeps its own SECRET key (the config provides no own pub,
        // and pqcrypto does not derive it from the secret), so this leg cannot
        // provide a symmetric binding. The Ed25519 leg carries the identity
        // binding; both identities are pinned and verified anyway.
        Vec::new()
    }
}

// ── HybridAuth: combines N legs, requires that ALL validate ──────────────────

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
        // Concatenate the bindings of all legs (in fixed order). In practice
        // the Ed25519 leg carries the binding and ML-DSA provides an empty one.
        let mut v = Vec::new();
        for leg in &self.legs {
            v.extend_from_slice(&leg.identity_binding());
        }
        v
    }
}

// ── Transcript: rolling hash binding the entire handshake ────────────────────

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

pub fn derive_shared(x_ss: &[u8], mlkem_ss: &[u8]) -> Zeroizing<[u8; 32]> {
    use hkdf::Hkdf;
    let mut ikm = Zeroizing::new(Vec::new());
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(mlkem_ss);
    let hk = Hkdf::<Sha256>::new(Some(b"Chameleon-PQ-v1-salt"), &ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"chameleon-pq hybrid session key", okm.as_mut())
        .expect("32 is a valid HKDF output length");
    okm
}

/// Bind a transcript signature to a ROLE (initiator vs responder) via domain
/// separation. Without this, both sides sign the exact same transcript hash
/// `th`, which would allow a reflected signature if the peers ever share an
/// identity key. By hashing a per-role label before `th`, the two signatures
/// provably cover different messages.
pub fn role_bound_hash(label: &[u8], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(transcript_hash);
    h.finalize().into()
}

/// Derive a SHARED session_id from the shared secret (I-13). After the
/// handshake both sides have the same `shared` and thus arrive at the same id
/// — no more process-global counter that can desync. Fresh per handshake
/// (ephemeral shared), so unique across rekeys. Non-secret: purely a demux tag,
/// like WireGuard's receiver index; the security is the AEAD tag.
pub fn derive_session_id(shared: &[u8; 32]) -> u32 {
    let mut h = Sha256::new();
    h.update(b"Chameleon-PQ-v1 session-id");
    h.update(shared);
    let d = h.finalize();
    u32::from_le_bytes([d[0], d[1], d[2], d[3]])
}

/// Compute a return-routability cookie for a source address (L-4). Purely an
/// anti-DoS token: proves the sender can receive on `src` before the responder
/// does expensive ML-KEM/DH/ML-DSA crypto or sends a large Response.
/// HMAC-SHA256 over (ip ‖ port ‖ time window), truncated to 16 bytes; not in
/// the transcript (does not affect key derivation).
pub fn compute_cookie(secret: &[u8; 32], src: &SocketAddr, time_bucket: u64) -> [u8; 16] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut ctx = hmac::Context::with_key(&key);
    match src.ip() {
        IpAddr::V4(v4) => ctx.update(&v4.octets()),
        IpAddr::V6(v6) => ctx.update(&v6.octets()),
    }
    ctx.update(&src.port().to_le_bytes());
    ctx.update(&time_bucket.to_le_bytes());
    let tag = ctx.sign();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag.as_ref()[..16]);
    out
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
        // a signs, b verifies a's signature with a's public key.
        let a = MlDsaAuth::from_keys(&a_sk, &b_pub).unwrap();
        let b = MlDsaAuth::from_keys(&b_sk, &a_pub).unwrap();

        let th = [0x42u8; 32];
        let sig = a.sign(&th).unwrap();
        assert_eq!(sig.len(), a.signature_len());
        b.verify(&th, &sig)
            .expect("valid ML-DSA signature verifies");

        // A changed transcript must fail.
        let mut other = th;
        other[0] ^= 0xFF;
        assert!(
            b.verify(&other, &sig).is_err(),
            "different transcript -> verification fails"
        );
    }

    #[test]
    fn hybrid_requires_all_legs() {
        // Hybrid of Ed25519 + ML-DSA. The verifier gets a VALID Ed25519 leg
        // but a BROKEN ML-DSA leg -> the whole thing must fail.
        let signer_seed = [7u8; 32];
        let signer_ed_pub = Ed25519Auth::derive_public(&signer_seed);
        let (signer_pq_pub, signer_pq_sk) = MlDsaAuth::generate();
        let (verifier_pq_pub, verifier_pq_sk) = MlDsaAuth::generate();

        let signer = HybridAuth::new(vec![
            Box::new(Ed25519Auth::new(&signer_seed, signer_ed_pub).unwrap()),
            Box::new(MlDsaAuth::from_keys(&signer_pq_sk, &verifier_pq_pub).unwrap()),
        ]);
        // Verifier expects signer's Ed25519 (correct) but a WRONG PQ pub.
        let (wrong_pq_pub, _) = MlDsaAuth::generate();
        let verifier = HybridAuth::new(vec![
            Box::new(Ed25519Auth::new(&[8u8; 32], signer_ed_pub).unwrap()),
            Box::new(MlDsaAuth::from_keys(&verifier_pq_sk, &wrong_pq_pub).unwrap()),
        ]);

        let th = [0x11u8; 32];
        let sig = signer.sign(&th).unwrap();
        assert_eq!(sig.len(), signer.signature_len());
        // Ed25519 leg valid, ML-DSA leg invalid -> hybrid verification fails.
        assert!(
            verifier.verify(&th, &sig).is_err(),
            "hybrid auth must fail if even a single leg does not validate"
        );
        let _ = signer_pq_pub; // (signer's public key, not needed here)
    }
}
