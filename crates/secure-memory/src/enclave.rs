//! Enclave — an encrypted-at-rest container for sensitive data.
//!
//! Data inside an `Enclave` is always encrypted with the per-process session
//! key. To access the plaintext you must explicitly [`open`](Enclave::open) it,
//! which returns a frozen (read-only) [`LockedBuffer`].

use zeroize::Zeroize;

use crate::buffer::LockedBuffer;
use crate::crypto;
use crate::error::Error;

/// Sealed container: holds ciphertext encrypted under the session key.
pub struct Enclave {
    /// `nonce || ciphertext || tag`
    ciphertext: Vec<u8>,
    /// Size of the original plaintext (bytes).
    plaintext_size: usize,
}

impl Enclave {
    /// Encrypt `data` into a new Enclave using the session key.
    pub fn new(data: &[u8]) -> Result<Self, Error> {
        let ciphertext = crypto::session_encrypt(data)?;
        Ok(Enclave {
            plaintext_size: data.len(),
            ciphertext,
        })
    }

    /// Create an Enclave containing `size` random bytes.
    pub fn random(size: usize) -> Result<Self, Error> {
        let mut buf = LockedBuffer::random(size)?;
        let enclave = {
            let data = buf.as_slice()?;
            Self::new(data)?
        };
        buf.scramble()?; // extra paranoia: scramble before drop-wipe
        Ok(enclave)
    }

    /// Decrypt and return the data as a **frozen** [`LockedBuffer`].
    pub fn open(&self) -> Result<LockedBuffer, Error> {
        let mut plaintext = crypto::session_decrypt(&self.ciphertext)?;
        let buf = LockedBuffer::from_bytes(&plaintext)?;
        plaintext.zeroize();
        Ok(buf)
    }

    /// Plaintext size in bytes (available without decryption).
    pub fn size(&self) -> usize {
        self.plaintext_size
    }
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"enclave-protected payload";
        let enc = Enclave::new(data).unwrap();
        assert_eq!(enc.size(), data.len());

        let buf = enc.open().unwrap();
        assert!(buf.is_frozen());
        assert_eq!(buf.as_slice().unwrap(), data);
    }

    #[test]
    fn seal_and_open() {
        let mut buf = LockedBuffer::new(16).unwrap();
        buf.as_mut_slice()
            .unwrap()
            .copy_from_slice(b"0123456789abcdef");
        let enc = buf.seal().unwrap();
        let opened = enc.open().unwrap();
        assert_eq!(opened.as_slice().unwrap(), b"0123456789abcdef");
    }

    #[test]
    fn random_enclave() {
        let enc = Enclave::random(64).unwrap();
        assert_eq!(enc.size(), 64);
        let buf = enc.open().unwrap();
        assert!(buf.as_slice().unwrap().iter().any(|&b| b != 0));
    }
}
