//! Cryptographic primitives: AEAD encryption, KDF (Argon2 + VDF),
//! and session-key management.

use std::sync::{LazyLock, Mutex};

use chacha20poly1305::{aead::Aead, aead::KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::buffer::LockedBuffer;
use crate::error::Error;

/// Nonce size for XChaCha20-Poly1305 (bytes).
const NONCE_SIZE: usize = 24;
/// Key size (bytes).
const KEY_SIZE: usize = 32;

// ── Session key ──────────────────────────────────────────────

/// Lazily-initialised session key. Lives in a LockedBuffer (mlock'd,
/// guard-paged). Set to `None` after [`destroy_session_key`].
static SESSION_KEY: LazyLock<Mutex<Option<LockedBuffer>>> = LazyLock::new(|| {
    let key = LockedBuffer::random(KEY_SIZE).expect("failed to allocate session key");
    Mutex::new(Some(key))
});

/// Encrypt `plaintext` with the per-process session key.
/// Returns `nonce (24 B) || ciphertext || tag (16 B)`.
pub fn session_encrypt(plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let guard = SESSION_KEY.lock().unwrap_or_else(|e| e.into_inner());
    let key_buf = guard.as_ref().ok_or(Error::SessionKeyUnavailable)?;
    encrypt(key_buf.as_slice()?, plaintext)
}

/// Decrypt data that was encrypted with [`session_encrypt`].
pub fn session_decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let guard = SESSION_KEY.lock().unwrap_or_else(|e| e.into_inner());
    let key_buf = guard.as_ref().ok_or(Error::SessionKeyUnavailable)?;
    decrypt(key_buf.as_slice()?, ciphertext)
}

/// Destroy the session key, making all existing [`Enclave`](crate::Enclave)s
/// permanently undecryptable.
pub fn destroy_session_key() {
    let mut guard = SESSION_KEY.lock().unwrap_or_else(|e| e.into_inner());
    // Dropping the LockedBuffer wipes and frees the key.
    *guard = None;
}

// ── XChaCha20-Poly1305 AEAD ─────────────────────────────────

/// Encrypt `plaintext` with a 32-byte `key`.
///
/// Returns `nonce (24 B) || ciphertext || tag (16 B)`.
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != KEY_SIZE {
        return Err(Error::InvalidKeySize {
            expected: KEY_SIZE,
            got: key.len(),
        });
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

    let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt data produced by [`encrypt`].
///
/// Input format: `nonce (24 B) || ciphertext || tag (16 B)`.
pub fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != KEY_SIZE {
        return Err(Error::InvalidKeySize {
            expected: KEY_SIZE,
            got: key.len(),
        });
    }
    if data.len() < NONCE_SIZE {
        return Err(Error::DecryptionFailed("data too short".into()));
    }

    let (nonce_bytes, ct) = data.split_at(NONCE_SIZE);
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| Error::DecryptionFailed(e.to_string()))?;
    let nonce = XNonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ct)
        .map_err(|e| Error::DecryptionFailed(e.to_string()))
}

// ── Key Derivation ───────────────────────────────────────────

/// Derive a 32-byte key from `password` + `salt` using **Argon2id**.
///
/// Recommended parameters: `memory_kib = 65536` (64 MiB), `iterations = 3`.
/// `salt` must be ≥ 8 bytes.
pub fn derive_key_argon2(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
) -> Result<[u8; 32], Error> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(memory_kib, iterations, 1, Some(32))
        .map_err(|e| Error::EncryptionFailed(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| Error::EncryptionFailed(format!("argon2: {e}")))?;
    Ok(key)
}

/// **VDF-style** sequential stretching: iterate SHA3-256 `iterations` times.
///
/// Not a true VDF (no efficient verification), but provides provable
/// sequential work that resists parallelisation.
pub fn vdf_stretch(input: &[u8], iterations: u64) -> [u8; 32] {
    let mut hash = Sha3_256::digest(input);
    for _ in 1..iterations {
        hash = Sha3_256::digest(hash);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// **Combined KDF**: Argon2id (memory-hard) then VDF stretch (time-hard).
///
/// This makes brute-force both memory-intensive and provably sequential.
pub fn derive_key_combined(
    password: &[u8],
    salt: &[u8],
    argon2_memory_kib: u32,
    argon2_iterations: u32,
    vdf_iterations: u64,
) -> Result<[u8; 32], Error> {
    let mut argon2_key = derive_key_argon2(password, salt, argon2_memory_kib, argon2_iterations)?;
    let stretched = vdf_stretch(&argon2_key, vdf_iterations);
    argon2_key.zeroize();
    Ok(stretched)
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let pt = b"the quick brown fox";
        let ct = encrypt(&key, pt).unwrap();
        let dec = decrypt(&key, &ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt(&[1u8; 32], b"secret").unwrap();
        assert!(decrypt(&[2u8; 32], &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [0xABu8; 32];
        let mut ct = encrypt(&key, b"data").unwrap();
        // flip a byte in the ciphertext body
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(decrypt(&key, &ct).is_err());
    }

    #[test]
    fn session_encrypt_decrypt() {
        let pt = b"session-protected";
        let ct = session_encrypt(pt).unwrap();
        let dec = session_decrypt(&ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn argon2_deterministic() {
        let pw = b"password";
        let salt = b"saltsaltsaltsalt";
        let k1 = derive_key_argon2(pw, salt, 1024, 1).unwrap();
        let k2 = derive_key_argon2(pw, salt, 1024, 1).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn vdf_deterministic() {
        let r1 = vdf_stretch(b"input", 100);
        let r2 = vdf_stretch(b"input", 100);
        assert_eq!(r1, r2);
        assert_eq!(r1.len(), 32);
    }

    #[test]
    fn combined_kdf() {
        let key = derive_key_combined(b"pass", b"saltsalt", 1024, 1, 10).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn bad_key_size_rejected() {
        assert!(encrypt(&[0u8; 16], b"x").is_err());
        assert!(decrypt(&[0u8; 16], &[0u8; 40]).is_err());
    }

    // ── Property-based tests (proptest) ──────────────────────

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn encrypt_decrypt_roundtrip_prop(
                key in proptest::collection::vec(any::<u8>(), 32),
                plaintext in proptest::collection::vec(any::<u8>(), 0..1024),
            ) {
                let ct = encrypt(&key, &plaintext).unwrap();
                let dec = decrypt(&key, &ct).unwrap();
                prop_assert_eq!(dec, plaintext);
            }

            #[test]
            fn ciphertext_is_nonce_plus_expansion(
                key in proptest::collection::vec(any::<u8>(), 32),
                plaintext in proptest::collection::vec(any::<u8>(), 0..512),
            ) {
                let ct = encrypt(&key, &plaintext).unwrap();
                // nonce (24) + plaintext + poly1305 tag (16)
                prop_assert_eq!(ct.len(), 24 + plaintext.len() + 16);
            }

            #[test]
            fn vdf_is_deterministic(
                input in proptest::collection::vec(any::<u8>(), 1..128),
                iters in 1u64..50,
            ) {
                let a = vdf_stretch(&input, iters);
                let b = vdf_stretch(&input, iters);
                prop_assert_eq!(a, b);
            }
        }
    }
}

// ── Kani verification harnesses ──────────────────────────────

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// decrypt rejects any input shorter than the nonce.
    #[kani::proof]
    fn decrypt_rejects_short_input() {
        let key = [0u8; KEY_SIZE];
        let len: usize = kani::any();
        kani::assume(len < NONCE_SIZE);
        let data = vec![0u8; len];
        assert!(decrypt(&key, &data).is_err());
    }

    /// encrypt rejects keys that are not KEY_SIZE bytes.
    #[kani::proof]
    fn encrypt_rejects_bad_key_len() {
        let len: usize = kani::any();
        kani::assume(len != KEY_SIZE && len <= 64);
        let key = vec![0u8; len];
        assert!(encrypt(&key, b"test").is_err());
    }
}
