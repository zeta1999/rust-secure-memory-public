//! Post-quantum key encapsulation via **ML-KEM-768** (FIPS 203).
//!
//! Secret keys are stored in [`LockedBuffer`]s (mlock'd, guard-paged,
//! wiped on drop). The 32-byte shared secret can be used directly as a
//! key for [`encrypt`](crate::encrypt) / [`decrypt`](crate::decrypt).
//!
//! ## Example
//!
//! ```no_run
//! use secure_memory::kem::{KemKeyPair, encapsulate};
//!
//! let kp = KemKeyPair::generate().unwrap();
//! let (ciphertext, shared_secret) = encapsulate(kp.public_key()).unwrap();
//! let recovered = kp.decapsulate(&ciphertext).unwrap();
//! assert_eq!(shared_secret.as_slice().unwrap(), recovered.as_slice().unwrap());
//! ```

use ml_kem::{
    kem::{DecapsulationKey, EncapsulationKey},
    Ciphertext, EncodedSizeUser, KemCore, MlKem768, MlKem768Params, SharedKey,
};

use crate::buffer::LockedBuffer;
use crate::error::Error;

/// ML-KEM-768 encapsulation key (public): 1184 bytes.
pub const EK_SIZE: usize = 1184;
/// ML-KEM-768 decapsulation key (secret): 2400 bytes.
pub const DK_SIZE: usize = 2400;
/// ML-KEM-768 ciphertext: 1088 bytes.
pub const CT_SIZE: usize = 1088;
/// Shared secret: 32 bytes.
pub const SS_SIZE: usize = 32;

/// An ML-KEM-768 key pair with the secret key in locked memory.
pub struct KemKeyPair {
    secret_key: LockedBuffer,
    public_key: Vec<u8>,
}

impl KemKeyPair {
    /// Generate a fresh ML-KEM-768 key pair.
    pub fn generate() -> Result<Self, Error> {
        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem768::generate(&mut rng);

        let ek_bytes = ek.as_bytes().to_vec();
        let mut dk_bytes = dk.as_bytes().to_vec();
        let secret_key = LockedBuffer::from_bytes_move(&mut dk_bytes)?;

        Ok(KemKeyPair {
            secret_key,
            public_key: ek_bytes,
        })
    }

    /// The public (encapsulation) key — safe to share.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The secret (decapsulation) key in locked memory.
    pub fn secret_key(&self) -> &LockedBuffer {
        &self.secret_key
    }

    /// Decapsulate `ciphertext`, recovering the 32-byte shared secret.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<LockedBuffer, Error> {
        if ciphertext.len() != CT_SIZE {
            return Err(Error::InvalidSize(format!(
                "ML-KEM-768 ciphertext must be {CT_SIZE} bytes, got {}",
                ciphertext.len()
            )));
        }

        let dk_bytes = self.secret_key.as_slice()?;
        let dk_arr = ml_kem::array::Array::try_from(dk_bytes)
            .map_err(|_| Error::InvalidSize("bad DK length".into()))?;
        let dk = DecapsulationKey::<MlKem768Params>::from_bytes(&dk_arr);

        let ct_arr = ml_kem::array::Array::try_from(ciphertext)
            .map_err(|_| Error::InvalidSize("bad CT length".into()))?;

        use ml_kem::kem::Decapsulate;
        let ss: SharedKey<MlKem768> = dk
            .decapsulate(&ct_arr)
            .map_err(|_| Error::DecryptionFailed("ML-KEM decapsulation failed".into()))?;

        let mut ss_bytes = ss.to_vec();
        let buf = LockedBuffer::from_bytes_move(&mut ss_bytes)?;
        Ok(buf)
    }
}

/// Encapsulate: produce `(ciphertext, shared_secret)` for the given public key.
///
/// The 32-byte shared secret is returned in a [`LockedBuffer`].
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, LockedBuffer), Error> {
    if public_key.len() != EK_SIZE {
        return Err(Error::InvalidSize(format!(
            "ML-KEM-768 public key must be {EK_SIZE} bytes, got {}",
            public_key.len()
        )));
    }

    let ek_arr = ml_kem::array::Array::try_from(public_key)
        .map_err(|_| Error::InvalidSize("bad EK length".into()))?;
    let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&ek_arr);

    let mut rng = rand::thread_rng();
    use ml_kem::kem::Encapsulate;
    let (ct, ss): (Ciphertext<MlKem768>, SharedKey<MlKem768>) = ek
        .encapsulate(&mut rng)
        .map_err(|_| Error::EncryptionFailed("ML-KEM encapsulation failed".into()))?;

    let ct_bytes = ct.to_vec();
    let mut ss_bytes = ss.to_vec();
    let ss_buf = LockedBuffer::from_bytes_move(&mut ss_bytes)?;

    Ok((ct_bytes, ss_buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_correct_sizes() {
        let kp = KemKeyPair::generate().unwrap();
        assert_eq!(kp.public_key().len(), EK_SIZE);
        assert_eq!(kp.secret_key().len(), DK_SIZE);
    }

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let kp = KemKeyPair::generate().unwrap();
        let (ct, ss_sender) = encapsulate(kp.public_key()).unwrap();
        assert_eq!(ct.len(), CT_SIZE);
        assert_eq!(ss_sender.len(), SS_SIZE);

        let ss_receiver = kp.decapsulate(&ct).unwrap();
        assert_eq!(
            ss_sender.as_slice().unwrap(),
            ss_receiver.as_slice().unwrap()
        );
    }

    #[test]
    fn wrong_ciphertext_produces_different_secret() {
        let kp = KemKeyPair::generate().unwrap();
        let (real_ct, real_ss) = encapsulate(kp.public_key()).unwrap();
        let bad_ct = vec![0u8; CT_SIZE];
        // ML-KEM implicit rejection: doesn't error, gives different secret
        let bad_ss = kp.decapsulate(&bad_ct).unwrap();
        assert_ne!(real_ss.as_slice().unwrap(), bad_ss.as_slice().unwrap());
    }

    #[test]
    fn bad_key_size_rejected() {
        assert!(encapsulate(&[0u8; 100]).is_err());
    }

    #[test]
    fn shared_secret_can_encrypt() {
        let kp = KemKeyPair::generate().unwrap();
        let (ct, ss) = encapsulate(kp.public_key()).unwrap();

        let plaintext = b"post-quantum secured message";
        let encrypted = crate::encrypt(ss.as_slice().unwrap(), plaintext).unwrap();

        let ss2 = kp.decapsulate(&ct).unwrap();
        let decrypted = crate::decrypt(ss2.as_slice().unwrap(), &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
