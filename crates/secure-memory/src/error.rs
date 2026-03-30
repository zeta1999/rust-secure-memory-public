use thiserror::Error;

/// Errors that can occur during secure memory operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("memory allocation failed")]
    AllocationFailed,

    #[error("failed to lock memory into RAM (mlock)")]
    LockFailed,

    #[error("failed to set memory protection (mprotect)")]
    ProtectFailed,

    #[error("buffer is frozen (read-only)")]
    Frozen,

    #[error("buffer has been destroyed")]
    Destroyed,

    #[error("canary verification failed — possible buffer overflow detected")]
    CanaryViolation,

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("invalid key size: expected {expected}, got {got}")]
    InvalidKeySize { expected: usize, got: usize },

    #[error("invalid size: {0}")]
    InvalidSize(String),

    #[error("session key not available (purged?)")]
    SessionKeyUnavailable,
}
