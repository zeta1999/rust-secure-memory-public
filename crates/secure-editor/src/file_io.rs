//! File I/O — read/write plaintext or encrypted files.
//!
//! ## File format v3 (current writer)
//! ```text
//! header (40 B, plaintext, used as AEAD AAD):
//!     magic       "SEDIT\x00\x03\x00"   8 B
//!     argon2_m    big-endian u32        4 B   (KiB of RAM for Argon2id)
//!     argon2_t    big-endian u32        4 B   (Argon2id iterations)
//!     seq_rounds  big-endian u64        8 B   (sequential SHA3 stretch rounds)
//!     salt        random                16 B
//! body:
//!     nonce       random                24 B
//!     ciphertext  variable
//!     tag         Poly1305              16 B
//! ```
//! The header is **authenticated** as AAD — any flip in magic, KDF
//! parameters, or salt is detected at decryption.
//!
//! v1 (fixed salt) and v2 (per-file salt, no header authentication) files
//! remain readable; new saves always use v3.

use std::fs;
use std::path::Path;

use secure_memory::{decrypt, decrypt_aad, encrypt_aad, LockedBuffer};
use zeroize::Zeroize;

const MAGIC_V1: &[u8; 8] = b"SEDIT\x00\x01\x00";
const MAGIC_V2: &[u8; 8] = b"SEDIT\x00\x02\x00";
const MAGIC_V3: &[u8; 8] = b"SEDIT\x00\x03\x00";
const SALT_SIZE: usize = 16;
const FIXED_SALT_V1: &[u8; SALT_SIZE] = b"sedit-v1-salt000";
/// Length of the v3 plaintext header that is bound as AAD.
const V3_HEADER_LEN: usize = 8 + 4 + 4 + 8 + SALT_SIZE; // 40

/// KDF parameters embedded in v3 file headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Argon2id memory cost (KiB).
    pub argon2_memory_kib: u32,
    /// Argon2id iteration count.
    pub argon2_iterations: u32,
    /// Sequential SHA3-256 stretch rounds applied after Argon2id.
    pub sequential_rounds: u64,
}

impl KdfParams {
    /// Default parameters used for newly-created files: 64 MiB Argon2id,
    /// 3 iterations, 1000 sequential rounds.
    pub const DEFAULT: Self = Self {
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        sequential_rounds: 1000,
    };
}

/// Returns `true` if the file starts with a known SEDIT magic header.
pub fn is_encrypted(path: &Path) -> std::io::Result<bool> {
    let data = fs::read(path)?;
    Ok(data.len() >= 8
        && (data[..8] == MAGIC_V1[..] || data[..8] == MAGIC_V2[..] || data[..8] == MAGIC_V3[..]))
}

/// Load an encrypted file, returning `(text, derived_key, salt, params)`.
///
/// Supports v1 (fixed salt), v2 (per-file salt) and v3 (authenticated
/// header + embedded KDF params) formats. v1 and v2 files are decrypted
/// using the legacy default KDF parameters; v3 files use the parameters
/// stored in the file header.
pub fn load(
    path: &Path,
    password: &LockedBuffer,
) -> anyhow::Result<(String, LockedBuffer, [u8; SALT_SIZE], KdfParams)> {
    let data = fs::read(path)?;

    if data.len() < 8 {
        anyhow::bail!("file too short to be an encrypted sedit file");
    }

    if data[..8] == MAGIC_V3[..] {
        if data.len() < V3_HEADER_LEN {
            anyhow::bail!("corrupted v3 file (too short for header)");
        }
        let header = &data[..V3_HEADER_LEN];
        let argon2_m = u32::from_be_bytes(header[8..12].try_into().unwrap());
        let argon2_t = u32::from_be_bytes(header[12..16].try_into().unwrap());
        let seq_rounds = u64::from_be_bytes(header[16..24].try_into().unwrap());
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&header[24..40]);

        let params = KdfParams {
            argon2_memory_kib: argon2_m,
            argon2_iterations: argon2_t,
            sequential_rounds: seq_rounds,
        };
        let key = derive_file_key(password, &salt, &params)?;

        let body = &data[V3_HEADER_LEN..];
        let mut plaintext = decrypt_aad(key.as_slice()?, body, header)
            .map_err(|_| anyhow::anyhow!("decryption failed — wrong key or tampered header"))?;
        let text = String::from_utf8(plaintext.clone())
            .map_err(|_| anyhow::anyhow!("decrypted content is not valid UTF-8"))?;
        plaintext.zeroize();
        return Ok((text, key, salt, params));
    }

    // ── Legacy v1/v2 paths (no AAD, default KDF params) ─────────
    let (salt, ciphertext) = if data[..8] == MAGIC_V2[..] {
        if data.len() < 8 + SALT_SIZE {
            anyhow::bail!("corrupted v2 file (too short for salt)");
        }
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&data[8..8 + SALT_SIZE]);
        (salt, &data[8 + SALT_SIZE..])
    } else if data[..8] == MAGIC_V1[..] {
        (*FIXED_SALT_V1, &data[8..])
    } else {
        anyhow::bail!("not a recognized sedit file");
    };

    let params = KdfParams::DEFAULT;
    let key = derive_file_key(password, &salt, &params)?;
    let mut plaintext = decrypt(key.as_slice()?, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong key?"))?;
    let text = String::from_utf8(plaintext.clone())
        .map_err(|_| anyhow::anyhow!("decrypted content is not valid UTF-8"))?;
    plaintext.zeroize();
    Ok((text, key, salt, params))
}

/// Load a plaintext (unencrypted) file.
pub fn load_plaintext(path: &Path) -> anyhow::Result<String> {
    String::from_utf8(fs::read(path)?).map_err(|_| anyhow::anyhow!("file is not valid UTF-8"))
}

/// Save text as an encrypted v3 file.
///
/// `key` must be the LockedBuffer that was derived from `password + salt +
/// params`. `params` are written into the header and bound as AAD.
pub fn save(
    path: &Path,
    text: &str,
    key: &LockedBuffer,
    salt: &[u8; SALT_SIZE],
    params: &KdfParams,
) -> anyhow::Result<()> {
    let header = build_v3_header(salt, params);
    let body = encrypt_aad(key.as_slice()?, text.as_bytes(), &header)?;

    let mut out = Vec::with_capacity(header.len() + body.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&body);
    fs::write(path, &out)?;
    Ok(())
}

fn build_v3_header(salt: &[u8; SALT_SIZE], params: &KdfParams) -> [u8; V3_HEADER_LEN] {
    let mut header = [0u8; V3_HEADER_LEN];
    header[..8].copy_from_slice(MAGIC_V3);
    header[8..12].copy_from_slice(&params.argon2_memory_kib.to_be_bytes());
    header[12..16].copy_from_slice(&params.argon2_iterations.to_be_bytes());
    header[16..24].copy_from_slice(&params.sequential_rounds.to_be_bytes());
    header[24..40].copy_from_slice(salt);
    header
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

/// Derive a 32-byte encryption key from `password + salt` using the given
/// KDF parameters. Argon2id (memory-hard) followed by sequential SHA3-256
/// stretching (time-hard).
pub fn derive_file_key(
    password: &LockedBuffer,
    salt: &[u8],
    params: &KdfParams,
) -> anyhow::Result<LockedBuffer> {
    eprintln!("Deriving key (this may take a moment)...");
    let mut key = secure_memory::derive_key_combined(
        password.as_slice()?,
        salt,
        params.argon2_memory_kib,
        params.argon2_iterations,
        params.sequential_rounds,
    )?;
    let buf = LockedBuffer::from_bytes_move(&mut key)?;
    Ok(buf)
}
