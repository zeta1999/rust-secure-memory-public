//! Hybrid post-quantum + classical key encapsulation: **ML-KEM-768 + X25519**.
//!
//! Combines the FIPS 203 lattice KEM with classical X25519 ECDH so that a break
//! in either primitive on its own does not compromise the shared secret. The
//! 32-byte output is the SHA3-256 of both component secrets together with the
//! ciphertexts, in the spirit of the IETF X-Wing draft — the result is a
//! cryptographically-binding combiner: any tampering with either component
//! ciphertext changes the final shared secret.
//!
//! ## Wire format
//! * Public key   = `ml_kem_pk (1184) || x25519_pk (32)` = **1216 bytes**
//! * Secret key   = (ml_kem_sk in [`LockedBuffer`], x25519_sk in [`LockedBuffer`])
//! * Ciphertext   = `ml_kem_ct (1088) || x25519_ephemeral_pk (32)` = **1120 bytes**
//! * Shared secret = **32 bytes** (in [`LockedBuffer`])
//!
//! ## Example
//!
//! ```no_run
//! use secure_memory::hybrid_kem::{HybridKemKeyPair, encapsulate};
//!
//! let kp = HybridKemKeyPair::generate().unwrap();
//! let (ct, ss_send) = encapsulate(&kp.public_key()).unwrap();
//! let ss_recv = kp.decapsulate(&ct).unwrap();
//! assert_eq!(ss_send.as_slice().unwrap(), ss_recv.as_slice().unwrap());
//! ```

use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Sec};
use zeroize::Zeroize;

use crate::buffer::LockedBuffer;
use crate::error::Error;
use crate::kem::{self, KemKeyPair, CT_SIZE as MLKEM_CT, EK_SIZE as MLKEM_EK};

/// X25519 public key size.
pub const X25519_PK_SIZE: usize = 32;
/// X25519 secret key size.
pub const X25519_SK_SIZE: usize = 32;

/// Combined hybrid public key size: ML-KEM-768 EK (1184) + X25519 PK (32).
pub const HYBRID_PK_SIZE: usize = MLKEM_EK + X25519_PK_SIZE;
/// Combined hybrid ciphertext size: ML-KEM-768 CT (1088) + X25519 ephemeral PK (32).
pub const HYBRID_CT_SIZE: usize = MLKEM_CT + X25519_PK_SIZE;
/// Hybrid shared-secret size (output of SHA3-256).
pub const HYBRID_SS_SIZE: usize = 32;

/// Domain-separation tag mixed into the combiner. Bumping the byte string
/// invalidates all prior shared secrets — treat as a versioning hook.
const COMBINER_TAG: &[u8] = b"secure-memory/hybrid-kem/mlkem768+x25519/v1";

/// Hybrid keypair holding both ML-KEM-768 and X25519 secret keys in locked memory.
pub struct HybridKemKeyPair {
    mlkem: KemKeyPair,
    x25519_sk: LockedBuffer,
    x25519_pk: [u8; X25519_PK_SIZE],
}

impl HybridKemKeyPair {
    /// Generate a fresh hybrid key pair.
    pub fn generate() -> Result<Self, Error> {
        let mlkem = KemKeyPair::generate()?;

        let x_sec = X25519Sec::random_from_rng(rand::rngs::OsRng);
        let x_pub = X25519Pub::from(&x_sec);
        let x25519_pk = *x_pub.as_bytes();

        let mut sk_bytes = x_sec.to_bytes();
        let x25519_sk = LockedBuffer::from_bytes_move(&mut sk_bytes)?;

        Ok(Self {
            mlkem,
            x25519_sk,
            x25519_pk,
        })
    }

    /// Combined public key: `ml_kem_pk || x25519_pk`. Safe to share.
    pub fn public_key(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_PK_SIZE);
        out.extend_from_slice(self.mlkem.public_key());
        out.extend_from_slice(&self.x25519_pk);
        out
    }

    /// Decapsulate `ciphertext`, recovering the 32-byte hybrid shared secret.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<LockedBuffer, Error> {
        if ciphertext.len() != HYBRID_CT_SIZE {
            return Err(Error::InvalidSize(format!(
                "hybrid CT must be {HYBRID_CT_SIZE} bytes, got {}",
                ciphertext.len()
            )));
        }
        let (mlkem_ct, x_ephem_pk) = ciphertext.split_at(MLKEM_CT);

        // ML-KEM half (locked-buffer shared secret).
        let mlkem_ss = self.mlkem.decapsulate(mlkem_ct)?;

        // X25519 half: DH(static_sk, ephemeral_pk).
        let x_ephem_arr: [u8; X25519_PK_SIZE] = x_ephem_pk
            .try_into()
            .map_err(|_| Error::InvalidSize("hybrid CT: bad X25519 PK length".into()))?;
        let x_ephem = X25519Pub::from(x_ephem_arr);

        let mut sk_bytes_arr = [0u8; X25519_SK_SIZE];
        sk_bytes_arr.copy_from_slice(self.x25519_sk.as_slice()?);
        let x_sec = X25519Sec::from(sk_bytes_arr);
        // The original stack copy lingers after the move; wipe it explicitly.
        sk_bytes_arr.zeroize();
        let x_ss = x_sec.diffie_hellman(&x_ephem);
        // x_sec drops here, zeroizing.

        let mut ss = combine(
            mlkem_ss.as_slice()?,
            x_ss.as_bytes(),
            mlkem_ct,
            x_ephem.as_bytes(),
            &self.x25519_pk,
        );
        let mut ss_owned = ss.to_vec();
        let buf = LockedBuffer::from_bytes_move(&mut ss_owned)?;
        ss.zeroize();
        Ok(buf)
    }
}

/// Encapsulate against a hybrid public key.
///
/// Returns `(ciphertext, shared_secret_in_locked_buffer)`.
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, LockedBuffer), Error> {
    if public_key.len() != HYBRID_PK_SIZE {
        return Err(Error::InvalidSize(format!(
            "hybrid PK must be {HYBRID_PK_SIZE} bytes, got {}",
            public_key.len()
        )));
    }
    let (mlkem_pk, x_static_pk) = public_key.split_at(MLKEM_EK);
    let x_static_pk_arr: [u8; X25519_PK_SIZE] = x_static_pk
        .try_into()
        .map_err(|_| Error::InvalidSize("hybrid PK: bad X25519 PK length".into()))?;
    let x_recipient = X25519Pub::from(x_static_pk_arr);

    // ML-KEM half.
    let (mlkem_ct, mlkem_ss) = kem::encapsulate(mlkem_pk)?;

    // X25519 half: ephemeral DH.
    let x_ephem_sec = X25519Sec::random_from_rng(rand::rngs::OsRng);
    let x_ephem_pk = X25519Pub::from(&x_ephem_sec);
    let x_ss = x_ephem_sec.diffie_hellman(&x_recipient);
    // x_ephem_sec drops + zeroizes here.

    let mut ss = combine(
        mlkem_ss.as_slice()?,
        x_ss.as_bytes(),
        &mlkem_ct,
        x_ephem_pk.as_bytes(),
        &x_static_pk_arr,
    );

    let mut out = Vec::with_capacity(HYBRID_CT_SIZE);
    out.extend_from_slice(&mlkem_ct);
    out.extend_from_slice(x_ephem_pk.as_bytes());

    let mut ss_owned = ss.to_vec();
    let ss_buf = LockedBuffer::from_bytes_move(&mut ss_owned)?;
    ss.zeroize();
    Ok((out, ss_buf))
}

/// SHA3-256 combiner that binds both shared secrets to both ciphertexts and
/// the recipient's static X25519 public key. Mirrors the X-Wing combiner style.
fn combine(
    mlkem_ss: &[u8],
    x25519_ss: &[u8],
    mlkem_ct: &[u8],
    x25519_ephem_pk: &[u8],
    x25519_static_pk: &[u8],
) -> [u8; HYBRID_SS_SIZE] {
    let mut h = Sha3_256::new();
    h.update(COMBINER_TAG);
    h.update(mlkem_ss);
    h.update(x25519_ss);
    h.update(mlkem_ct);
    h.update(x25519_ephem_pk);
    h.update(x25519_static_pk);
    let mut digest = h.finalize();
    let mut out = [0u8; HYBRID_SS_SIZE];
    out.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    out
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Hybrid KEM = ML-KEM-768 + X25519. Both are skipped under Miri (slow);
    // see kem.rs for ML-KEM rationale. Native `cargo test` covers them.

    #[cfg_attr(miri, ignore)]
    #[test]
    fn keygen_sizes() {
        let kp = HybridKemKeyPair::generate().unwrap();
        assert_eq!(kp.public_key().len(), HYBRID_PK_SIZE);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn encap_decap_roundtrip() {
        let kp = HybridKemKeyPair::generate().unwrap();
        let pk = kp.public_key();
        let (ct, ss_send) = encapsulate(&pk).unwrap();
        assert_eq!(ct.len(), HYBRID_CT_SIZE);
        assert_eq!(ss_send.len(), HYBRID_SS_SIZE);

        let ss_recv = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss_send.as_slice().unwrap(), ss_recv.as_slice().unwrap());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn shared_secret_can_aead() {
        let kp = HybridKemKeyPair::generate().unwrap();
        let (ct, ss) = encapsulate(&kp.public_key()).unwrap();
        let pt = b"hybrid-protected payload";
        let enc = crate::encrypt(ss.as_slice().unwrap(), pt).unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        let dec = crate::decrypt(ss2.as_slice().unwrap(), &enc).unwrap();
        assert_eq!(dec, pt);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn tampered_mlkem_ct_changes_secret() {
        let kp = HybridKemKeyPair::generate().unwrap();
        let (mut ct, ss_real) = encapsulate(&kp.public_key()).unwrap();
        // flip a byte inside the ML-KEM half
        ct[10] ^= 0xFF;
        let ss_bad = kp.decapsulate(&ct).unwrap();
        assert_ne!(ss_real.as_slice().unwrap(), ss_bad.as_slice().unwrap());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn tampered_x25519_ephemeral_changes_secret() {
        let kp = HybridKemKeyPair::generate().unwrap();
        let (mut ct, ss_real) = encapsulate(&kp.public_key()).unwrap();
        // flip a byte inside the X25519 ephemeral PK (last 32 bytes)
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let ss_bad = kp.decapsulate(&ct).unwrap();
        assert_ne!(ss_real.as_slice().unwrap(), ss_bad.as_slice().unwrap());
    }

    #[test]
    fn bad_pk_size_rejected() {
        assert!(encapsulate(&[0u8; 100]).is_err());
    }

    // bad_ct_size_rejected calls generate(), so it's slow under Miri.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn bad_ct_size_rejected() {
        let kp = HybridKemKeyPair::generate().unwrap();
        assert!(kp.decapsulate(&[0u8; 100]).is_err());
    }

    // Skipped under Miri: each case runs hybrid keygen + encap + decap.
    #[cfg(not(miri))]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(16))]

            #[test]
            fn roundtrip_always_agrees(_ in 0u8..1) {
                let kp = HybridKemKeyPair::generate().unwrap();
                let (ct, ss_send) = encapsulate(&kp.public_key()).unwrap();
                let ss_recv = kp.decapsulate(&ct).unwrap();
                prop_assert_eq!(
                    ss_send.as_slice().unwrap(),
                    ss_recv.as_slice().unwrap()
                );
            }

            #[test]
            fn any_ct_bit_flip_changes_secret(
                index in 0usize..HYBRID_CT_SIZE,
                flip in 1u8..=255u8,
            ) {
                let kp = HybridKemKeyPair::generate().unwrap();
                let (mut ct, ss_real) = encapsulate(&kp.public_key()).unwrap();
                ct[index] ^= flip;
                let ss_bad = kp.decapsulate(&ct).unwrap();
                prop_assert_ne!(
                    ss_real.as_slice().unwrap(),
                    ss_bad.as_slice().unwrap()
                );
            }
        }
    }
}
