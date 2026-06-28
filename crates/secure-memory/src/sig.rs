//! Post-quantum digital signatures via **ML-DSA-65** (FIPS 204).
//!
//! ML-DSA-65 is the NIST Category-3 lattice-based signature scheme
//! standardised in FIPS 204 (formerly Dilithium). It is the recommended
//! choice for general-purpose signing where ~AES-192-equivalent security
//! is desired.
//!
//! Secret keys are stored in [`LockedBuffer`]s (mlock'd, guard-paged,
//! wiped on drop). Signing is **deterministic** by default — same message
//! and key always produce the same signature, which avoids side-channels
//! from per-signature randomness leakage.
//!
//! ## Sizes
//! * Verifying key: **1952 bytes** ([`VK_SIZE`])
//! * Signing key:   **4032 bytes** ([`SK_SIZE`])
//! * Signature:     **3309 bytes** ([`SIG_SIZE`])
//!
//! ## Example
//!
//! ```no_run
//! use secure_memory::sig::SigKeyPair;
//!
//! let kp = SigKeyPair::generate().unwrap();
//! let msg = b"important message";
//! let sig = kp.sign(msg).unwrap();
//! assert!(SigKeyPair::verify(&kp.verifying_key(), msg, &sig).unwrap());
//! ```

use ml_dsa::{EncodedSignature, EncodedSigningKey, EncodedVerifyingKey};
use ml_dsa::{KeyGen, MlDsa65, Signature, SigningKey, VerifyingKey};

use crate::buffer::LockedBuffer;
use crate::error::Error;

/// ML-DSA-65 verifying (public) key size.
pub const VK_SIZE: usize = 1952;
/// ML-DSA-65 signing (secret) key size.
pub const SK_SIZE: usize = 4032;
/// ML-DSA-65 signature size.
pub const SIG_SIZE: usize = 3309;

/// An ML-DSA-65 key pair with the secret key in locked memory.
pub struct SigKeyPair {
    signing_key: LockedBuffer,
    verifying_key: Vec<u8>,
}

impl SigKeyPair {
    /// Generate a fresh ML-DSA-65 key pair.
    pub fn generate() -> Result<Self, Error> {
        let mut rng = rand::rngs::OsRng;
        let kp = MlDsa65::key_gen(&mut rng);

        let vk_enc: EncodedVerifyingKey<MlDsa65> = kp.verifying_key().encode();
        let sk_enc: EncodedSigningKey<MlDsa65> = kp.signing_key().encode();

        let mut sk_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&sk_enc).to_vec();
        let signing_key = LockedBuffer::from_bytes_move(&mut sk_bytes)?;

        Ok(Self {
            signing_key,
            verifying_key: AsRef::<[u8]>::as_ref(&vk_enc).to_vec(),
        })
    }

    /// Reconstruct a key pair from previously exported raw FIPS 204 encodings
    /// (e.g. a persisted identity). The signing key is placed back into locked
    /// memory. Callers are responsible for protecting `signing_key` at rest.
    pub fn from_bytes(signing_key: &[u8], verifying_key: &[u8]) -> Result<Self, Error> {
        if signing_key.len() != SK_SIZE {
            return Err(Error::InvalidSize(format!(
                "ML-DSA-65 SK must be {SK_SIZE} bytes, got {}",
                signing_key.len()
            )));
        }
        if verifying_key.len() != VK_SIZE {
            return Err(Error::InvalidSize(format!(
                "ML-DSA-65 VK must be {VK_SIZE} bytes, got {}",
                verifying_key.len()
            )));
        }
        let mut sk = signing_key.to_vec();
        let locked = LockedBuffer::from_bytes_move(&mut sk)?;
        Ok(Self {
            signing_key: locked,
            verifying_key: verifying_key.to_vec(),
        })
    }

    /// Verifying (public) key — safe to share.
    pub fn verifying_key(&self) -> &[u8] {
        &self.verifying_key
    }

    /// The locked-memory signing key (raw FIPS 204 encoding).
    pub fn signing_key(&self) -> &LockedBuffer {
        &self.signing_key
    }

    /// Sign `message` deterministically. Empty context per FIPS 204.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let sk_bytes = self.signing_key.as_slice()?;
        if sk_bytes.len() != SK_SIZE {
            return Err(Error::InvalidSize(format!(
                "ML-DSA-65 SK must be {SK_SIZE} bytes, got {}",
                sk_bytes.len()
            )));
        }
        let sk_enc = EncodedSigningKey::<MlDsa65>::try_from(sk_bytes)
            .map_err(|_| Error::InvalidSize("bad SK length".into()))?;
        let sk = SigningKey::<MlDsa65>::decode(&sk_enc);
        let sig = sk
            .sign_deterministic(message, &[])
            .map_err(|_| Error::EncryptionFailed("ML-DSA signing failed".into()))?;
        let enc: EncodedSignature<MlDsa65> = sig.encode();
        Ok(AsRef::<[u8]>::as_ref(&enc).to_vec())
    }

    /// Verify `signature` over `message` using `verifying_key`.
    /// Returns `Ok(true)` on success, `Ok(false)` on a well-formed but invalid
    /// signature, and `Err(_)` on malformed inputs.
    pub fn verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, Error> {
        if verifying_key.len() != VK_SIZE {
            return Err(Error::InvalidSize(format!(
                "ML-DSA-65 VK must be {VK_SIZE} bytes, got {}",
                verifying_key.len()
            )));
        }
        if signature.len() != SIG_SIZE {
            return Err(Error::InvalidSize(format!(
                "ML-DSA-65 sig must be {SIG_SIZE} bytes, got {}",
                signature.len()
            )));
        }
        let vk_enc = EncodedVerifyingKey::<MlDsa65>::try_from(verifying_key)
            .map_err(|_| Error::InvalidSize("bad VK length".into()))?;
        let vk = VerifyingKey::<MlDsa65>::decode(&vk_enc);

        let sig_enc = EncodedSignature::<MlDsa65>::try_from(signature)
            .map_err(|_| Error::InvalidSize("bad sig length".into()))?;
        let sig = match Signature::<MlDsa65>::decode(&sig_enc) {
            Some(s) => s,
            None => return Ok(false),
        };

        Ok(vk.verify_with_context(message, &[], &sig))
    }
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ML-DSA-65 keygen + sign + verify each take ~2–5 s under Miri (sign uses
    // rejection sampling that may loop). Tests that exercise these primitives
    // are skipped under Miri; native `cargo test` covers them.

    #[cfg_attr(miri, ignore)]
    #[test]
    fn keygen_sizes() {
        let kp = SigKeyPair::generate().unwrap();
        assert_eq!(kp.verifying_key().len(), VK_SIZE);
        assert_eq!(kp.signing_key().len(), SK_SIZE);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn sign_verify_roundtrip() {
        let kp = SigKeyPair::generate().unwrap();
        let msg = b"hello, post-quantum world";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), SIG_SIZE);
        assert!(SigKeyPair::verify(kp.verifying_key(), msg, &sig).unwrap());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn export_import_roundtrip() {
        let kp = SigKeyPair::generate().unwrap();
        let sk = kp.signing_key().as_slice().unwrap().to_vec();
        let vk = kp.verifying_key().to_vec();
        // reload from exported bytes
        let kp2 = SigKeyPair::from_bytes(&sk, &vk).unwrap();
        let sig = kp2.sign(b"persisted identity").unwrap();
        assert!(SigKeyPair::verify(&vk, b"persisted identity", &sig).unwrap());
        // deterministic signing => reloaded key signs identically to the original
        assert_eq!(kp.sign(b"persisted identity").unwrap(), sig);
        // size validation
        assert!(SigKeyPair::from_bytes(&[0u8; 10], &vk).is_err());
        assert!(SigKeyPair::from_bytes(&sk, &[0u8; 10]).is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn deterministic_signing() {
        let kp = SigKeyPair::generate().unwrap();
        let msg = b"determinism check";
        let s1 = kp.sign(msg).unwrap();
        let s2 = kp.sign(msg).unwrap();
        assert_eq!(s1, s2);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn wrong_message_fails_verify() {
        let kp = SigKeyPair::generate().unwrap();
        let sig = kp.sign(b"original").unwrap();
        assert!(!SigKeyPair::verify(kp.verifying_key(), b"tampered", &sig).unwrap());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn flipped_signature_byte_fails_verify() {
        let kp = SigKeyPair::generate().unwrap();
        let mut sig = kp.sign(b"msg").unwrap();
        sig[0] ^= 0x01;
        // Either decode fails (Ok(false)) or verify fails (Ok(false))
        let res = SigKeyPair::verify(kp.verifying_key(), b"msg", &sig).unwrap();
        assert!(!res);
    }

    // bad_*_size_rejected tests still call generate()/sign(), so they're slow
    // under Miri. Gate them too.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn bad_vk_size_rejected() {
        let kp = SigKeyPair::generate().unwrap();
        let sig = kp.sign(b"x").unwrap();
        assert!(SigKeyPair::verify(&[0u8; 100], b"x", &sig).is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn bad_sig_size_rejected() {
        let kp = SigKeyPair::generate().unwrap();
        assert!(SigKeyPair::verify(kp.verifying_key(), b"x", &[0u8; 100]).is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn cross_key_does_not_verify() {
        let kp1 = SigKeyPair::generate().unwrap();
        let kp2 = SigKeyPair::generate().unwrap();
        let sig = kp1.sign(b"msg").unwrap();
        assert!(!SigKeyPair::verify(kp2.verifying_key(), b"msg", &sig).unwrap());
    }

    // Skipped under Miri: each case runs ML-DSA keygen + sign + verify.
    #[cfg(not(miri))]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(8))]

            #[test]
            fn roundtrip_always_verifies(
                msg in proptest::collection::vec(any::<u8>(), 0..256),
            ) {
                let kp = SigKeyPair::generate().unwrap();
                let sig = kp.sign(&msg).unwrap();
                prop_assert!(SigKeyPair::verify(kp.verifying_key(), &msg, &sig).unwrap());
            }
        }
    }
}
