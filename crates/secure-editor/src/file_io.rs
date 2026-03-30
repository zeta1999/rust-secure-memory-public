//! File I/O — read/write plaintext or encrypted files.
//!
//! ## File format v2
//! ```text
//! SEDIT\x00\x02\x00 (8 B) || salt (16 B) || nonce (24 B) || ciphertext || tag (16 B)
//! ```
//!
//! v1 files (fixed salt) are still readable but new saves always use v2.

use std::fs;
use std::path::Path;

use secure_memory::{decrypt, encrypt, LockedBuffer};
use zeroize::Zeroize;

const MAGIC_V1: &[u8; 8] = b"SEDIT\x00\x01\x00";
const MAGIC_V2: &[u8; 8] = b"SEDIT\x00\x02\x00";
const SALT_SIZE: usize = 16;
const FIXED_SALT_V1: &[u8; SALT_SIZE] = b"sedit-v1-salt000";

/// Returns `true` if the file starts with a known SEDIT magic header.
pub fn is_encrypted(path: &Path) -> std::io::Result<bool> {
    let data = fs::read(path)?;
    Ok(data.len() >= 8 && (data[..8] == MAGIC_V1[..] || data[..8] == MAGIC_V2[..]))
}

/// Load an encrypted file, returning `(text, derived_key, salt)`.
///
/// Supports both v1 (fixed salt) and v2 (per-file salt) formats.
pub fn load(
    path: &Path,
    password: &LockedBuffer,
) -> anyhow::Result<(String, LockedBuffer, [u8; SALT_SIZE])> {
    let data = fs::read(path)?;

    if data.len() < 8 {
        anyhow::bail!("file too short to be an encrypted sedit file");
    }

    let (salt, ciphertext) = if data[..8] == MAGIC_V2[..] {
        // v2: magic (8) + salt (16) + encrypted data
        if data.len() < 8 + SALT_SIZE {
            anyhow::bail!("corrupted v2 file (too short for salt)");
        }
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&data[8..8 + SALT_SIZE]);
        (salt, &data[8 + SALT_SIZE..])
    } else if data[..8] == MAGIC_V1[..] {
        // v1: magic (8) + encrypted data (fixed salt)
        (*FIXED_SALT_V1, &data[8..])
    } else {
        anyhow::bail!("not a recognized sedit file");
    };

    let key = derive_file_key(password, &salt)?;
    let mut plaintext = decrypt(key.as_slice()?, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong key?"))?;
    let text = String::from_utf8(plaintext.clone())
        .map_err(|_| anyhow::anyhow!("decrypted content is not valid UTF-8"))?;
    plaintext.zeroize();
    Ok((text, key, salt))
}

/// Load a plaintext (unencrypted) file.
pub fn load_plaintext(path: &Path) -> anyhow::Result<String> {
    Ok(String::from_utf8(fs::read(path)?)
        .map_err(|_| anyhow::anyhow!("file is not valid UTF-8"))?)
}

/// Save text as an encrypted v2 file.
pub fn save(
    path: &Path,
    text: &str,
    key: &LockedBuffer,
    salt: &[u8; SALT_SIZE],
) -> anyhow::Result<()> {
    let ct = encrypt(key.as_slice()?, text.as_bytes())?;
    let mut out = Vec::with_capacity(8 + SALT_SIZE + ct.len());
    out.extend_from_slice(MAGIC_V2);
    out.extend_from_slice(salt);
    out.extend_from_slice(&ct);
    fs::write(path, &out)?;
    Ok(())
}

/// Save as plaintext (no encryption).
pub fn save_plaintext(path: &Path, text: &str) -> anyhow::Result<()> {
    fs::write(path, text.as_bytes())?;
    Ok(())
}

/// Generate a random 16-byte salt for a new file.
pub fn new_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    secure_memory::scramble_bytes(&mut salt);
    salt
}

/// Derive a 32-byte encryption key from password + salt.
pub fn derive_file_key(password: &LockedBuffer, salt: &[u8]) -> anyhow::Result<LockedBuffer> {
    eprintln!("Deriving key (this may take a moment)...");
    let mut key = secure_memory::derive_key_combined(
        password.as_slice()?,
        salt,
        65536, // 64 MiB Argon2
        3,     // iterations
        1000,  // VDF rounds
    )?;
    let buf = LockedBuffer::from_bytes_move(&mut key)?;
    Ok(buf)
}
