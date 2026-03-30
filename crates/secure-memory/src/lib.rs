//! # secure-memory
//!
//! A Rust library for **protecting sensitive data in memory**, inspired by
//! Go's [memguard](https://github.com/awnumar/memguard).
//!
//! ## Core primitives
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`LockedBuffer`] | Mutable or frozen buffer with guard pages, mlock, canary values, and secure wipe-on-drop |
//! | [`Enclave`] | Encrypted-at-rest container — data is only ever in the clear inside a `LockedBuffer` |
//! | [`Stream`] | Chunked encrypted reader/writer for large datasets |
//!
//! ## Cryptography
//!
//! * **AEAD**: XChaCha20-Poly1305
//! * **KDF**: Argon2id (memory-hard) + optional VDF sequential stretching (time-hard)
//! * **Session key**: per-process, stored in a `LockedBuffer`, destroyed by [`purge`]
//!
//! ## Quick start
//!
//! ```no_run
//! use secure_memory::{LockedBuffer, Enclave};
//!
//! // Store a secret in locked memory
//! let mut buf = LockedBuffer::new(32).unwrap();
//! buf.as_mut_slice().unwrap().copy_from_slice(b"my-256-bit-secret-key-here!!\x00\x00\x00\x00");
//! buf.freeze().unwrap(); // read-only
//!
//! // Seal into an Enclave (encrypts, wipes the buffer)
//! let enclave = buf.seal().unwrap();
//!
//! // Later, unseal
//! let opened = enclave.open().unwrap();
//! assert_eq!(&opened.as_slice().unwrap()[..28], b"my-256-bit-secret-key-here!!");
//! ```

pub mod buffer;
pub mod crypto;
pub mod enclave;
pub mod error;
pub mod kem;
pub mod platform;
pub mod stream;

// ── Re-exports ───────────────────────────────────────────────

pub use buffer::LockedBuffer;
pub use enclave::Enclave;
pub use error::Error;
pub use stream::Stream;

pub use crypto::{decrypt, derive_key_argon2, derive_key_combined, encrypt, vdf_stretch};

// ── Global operations ────────────────────────────────────────

/// Wipe all live [`LockedBuffer`]s and destroy the session key.
///
/// After this call every existing [`Enclave`] becomes permanently
/// undecryptable. Individual `LockedBuffer` objects are still safe to drop
/// (they just won't contain useful data).
pub fn purge() {
    buffer::purge_all();
}

/// [`purge`], then exit the process with `code`.
pub fn safe_exit(code: i32) -> ! {
    purge();
    std::process::exit(code)
}

/// [`purge`], then panic with `msg`.
pub fn safe_panic(msg: &str) -> ! {
    purge();
    panic!("{}", msg)
}

// ── Utility functions ────────────────────────────────────────

/// Overwrite `data` with cryptographically-secure random bytes.
pub fn scramble_bytes(data: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(data);
}

/// Overwrite `data` with zeros (using [`zeroize`] to prevent dead-store
/// elimination).
pub fn wipe_bytes(data: &mut [u8]) {
    use zeroize::Zeroize;
    data.zeroize();
}
