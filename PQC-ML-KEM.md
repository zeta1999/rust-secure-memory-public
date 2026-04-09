# Post-Quantum Cryptography: ML-KEM-768

This document describes the use of **ML-KEM-768** (Module-Lattice-Based Key Encapsulation Mechanism) in rust-secure-memory, as specified in [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).

---

## Why ML-KEM?

Classical key-exchange algorithms (RSA, ECDH) will be broken by sufficiently powerful quantum computers running Shor's algorithm. ML-KEM is one of NIST's selected post-quantum standards, designed to resist both classical and quantum attacks.

**ML-KEM-768** (security category 3, ~AES-192 equivalent) strikes a balance between key size and security margin. It is the recommended parameter set for most applications.

## Where It Lives

| File | Purpose |
|------|---------|
| `crates/secure-memory/src/kem.rs` | Full implementation — key generation, encapsulation, decapsulation |
| `crates/secure-memory/src/lib.rs` | Re-exports `pub mod kem` |
| `crates/secure-memory/Cargo.toml` | Declares `ml-kem = "0.2"` dependency |
| `crates/secure-memory/src/crypto.rs` | Symmetric `encrypt()` / `decrypt()` that consume the 32-byte shared secret |

## How It Works

### Key Sizes

| Artifact | Size | Description |
|----------|------|-------------|
| Encapsulation key (public) | **1 184 B** | Safe to share — used by the sender |
| Decapsulation key (secret) | **2 400 B** | Stored in `LockedBuffer` (mlock'd, guard-paged, wiped on drop) |
| Ciphertext | **1 088 B** | Sent alongside the encrypted payload |
| Shared secret | **32 B** | Derived independently by both parties — used as a symmetric key |

### Protocol Flow

```
  Alice (sender)                                  Bob (receiver)
  ──────────────                                  ──────────────
                          ← public key (1184 B) ─ KemKeyPair::generate()
  encapsulate(pk)
    → ciphertext (1088 B)  ─────────────────────→ kp.decapsulate(ct)
    → shared_secret (32 B)                         → shared_secret (32 B)
        │                                              │
        └──── same 32-byte key ────────────────────────┘
              ↓                                        ↓
        encrypt(ss, msg)                         decrypt(ss, ct)
        XChaCha20-Poly1305                       XChaCha20-Poly1305
```

1. **Key generation** — Bob calls `KemKeyPair::generate()`. The secret key is immediately moved into a `LockedBuffer` (mlock'd, guard pages, canary sentinels, secure wipe on drop).
2. **Encapsulation** — Alice calls `encapsulate(public_key)`, which returns a `(ciphertext, shared_secret)` tuple. The shared secret is stored in a `LockedBuffer`.
3. **Decapsulation** — Bob calls `kp.decapsulate(&ciphertext)` to recover the same 32-byte shared secret.
4. **Symmetric encryption** — Both parties use the 32-byte shared secret directly as a key for XChaCha20-Poly1305 AEAD encryption.

### Implicit Rejection

Per FIPS 203, if decapsulation receives a corrupted or forged ciphertext it does **not** return an error. Instead it deterministically produces a pseudorandom shared secret that differs from the real one. This prevents chosen-ciphertext oracles — an attacker cannot distinguish "wrong key" from "random output".

## API Usage Examples

### 1. Basic KEM Round-Trip

Generate a key pair, encapsulate, decapsulate — confirm both sides derive the same 32-byte shared secret.

```rust
use secure_memory::kem::{KemKeyPair, encapsulate};

// Bob generates a key pair (secret key lives in LockedBuffer)
let kp = KemKeyPair::generate()?;

// Alice encapsulates against Bob's public key
let (ciphertext, shared_secret) = encapsulate(kp.public_key())?;

// Bob decapsulates to recover the same shared secret
let recovered = kp.decapsulate(&ciphertext)?;

assert_eq!(shared_secret.as_slice()?, recovered.as_slice()?);
// Both sides now hold the same 32-byte symmetric key
```

### 2. KEM + Symmetric Encryption (End-to-End Message)

Use the KEM shared secret directly as a key for XChaCha20-Poly1305 AEAD.

```rust
use secure_memory::kem::{KemKeyPair, encapsulate};
use secure_memory::{encrypt, decrypt};

// --- Bob (receiver) ---
let kp = KemKeyPair::generate()?;
let public_key = kp.public_key().to_vec(); // send this to Alice

// --- Alice (sender) ---
let (kem_ciphertext, ss) = encapsulate(&public_key)?;
let message = b"launch codes: 0000";
let encrypted_msg = encrypt(ss.as_slice()?, message)?;
// Alice sends (kem_ciphertext, encrypted_msg) to Bob

// --- Bob (receiver) ---
let ss2 = kp.decapsulate(&kem_ciphertext)?;
let plaintext = decrypt(ss2.as_slice()?, &encrypted_msg)?;
assert_eq!(plaintext, b"launch codes: 0000");
```

### 3. Encrypt Multiple Messages with One KEM Exchange

A single KEM handshake produces a reusable 32-byte key. Use it to encrypt a sequence of messages.

```rust
use secure_memory::kem::{KemKeyPair, encapsulate};
use secure_memory::{encrypt, decrypt};

let kp = KemKeyPair::generate()?;
let (ct, ss) = encapsulate(kp.public_key())?;
let ss2 = kp.decapsulate(&ct)?;

let key = ss.as_slice()?;     // sender's key
let key2 = ss2.as_slice()?;   // receiver's key

// Encrypt several messages under the same shared secret
let messages = [b"msg-1: hello" as &[u8], b"msg-2: world", b"msg-3: done"];
let encrypted: Vec<Vec<u8>> = messages
    .iter()
    .map(|m| encrypt(key, m).unwrap())
    .collect();

// Decrypt on the other side
for (i, ct) in encrypted.iter().enumerate() {
    let pt = decrypt(key2, ct)?;
    assert_eq!(pt, messages[i]);
}
```

### 4. Store a KEM Shared Secret in an Enclave (Encrypted at Rest)

Seal the shared secret into an `Enclave` so it stays encrypted in memory until needed.

```rust
use secure_memory::kem::{KemKeyPair, encapsulate};
use secure_memory::{Enclave, encrypt, decrypt};

let kp = KemKeyPair::generate()?;
let (kem_ct, ss) = encapsulate(kp.public_key())?;

// Seal the shared secret into an Enclave (encrypts with session key, wipes source)
let sealed = Enclave::new(ss.as_slice()?)?;
// ss is still valid, but you could drop it — the Enclave holds the secret now

// Later, when you need to encrypt...
let opened = sealed.open()?;  // returns a frozen (read-only) LockedBuffer
let encrypted = encrypt(opened.as_slice()?, b"classified payload")?;

// On the receiver side
let ss2 = kp.decapsulate(&kem_ct)?;
let plaintext = decrypt(ss2.as_slice()?, &encrypted)?;
assert_eq!(plaintext, b"classified payload");
```

### 5. KEM Shared Secret as Key for Streaming Encryption

Use the shared secret with `Stream` to encrypt large data in chunks without holding the entire plaintext in memory.

```rust
use secure_memory::kem::{KemKeyPair, encapsulate};
use secure_memory::{encrypt, decrypt};

let kp = KemKeyPair::generate()?;
let (kem_ct, ss) = encapsulate(kp.public_key())?;
let key = ss.as_slice()?;

// Encrypt large data chunk by chunk
let chunks: Vec<&[u8]> = vec![b"chunk-1-data...", b"chunk-2-data...", b"chunk-3-end"];
let encrypted_chunks: Vec<Vec<u8>> = chunks
    .iter()
    .map(|c| encrypt(key, c).unwrap())
    .collect();

// Receiver decapsulates and decrypts each chunk independently
let ss2 = kp.decapsulate(&kem_ct)?;
let key2 = ss2.as_slice()?;
for (i, enc) in encrypted_chunks.iter().enumerate() {
    let pt = decrypt(key2, enc)?;
    assert_eq!(pt, chunks[i]);
}
```

### 6. Public Key Serialization / Wire Format

Extract the public key bytes for transport (network, file, QR code) and reconstruct on the other side.

```rust
use secure_memory::kem::{KemKeyPair, encapsulate, EK_SIZE, CT_SIZE};

// --- Bob generates and exports public key ---
let kp = KemKeyPair::generate()?;
let pk_bytes: Vec<u8> = kp.public_key().to_vec();
assert_eq!(pk_bytes.len(), EK_SIZE); // 1184 bytes

// --- Transport pk_bytes over network/file/QR ---

// --- Alice receives pk_bytes, encapsulates ---
let (kem_ct, ss) = encapsulate(&pk_bytes)?;
assert_eq!(kem_ct.len(), CT_SIZE); // 1088 bytes

// Alice sends kem_ct back to Bob (1088 bytes on the wire)
// Both sides now have the same 32-byte shared secret
```

### 7. Multi-Recipient Encryption

Encrypt a message for multiple recipients, each with their own KEM key pair. Each recipient gets a unique KEM ciphertext but the same plaintext message.

```rust
use secure_memory::kem::{KemKeyPair, encapsulate};
use secure_memory::{encrypt, decrypt};

// Three recipients each generate a key pair
let recipients: Vec<KemKeyPair> = (0..3)
    .map(|_| KemKeyPair::generate().unwrap())
    .collect();

let message = b"broadcast to all agents";

// Sender encapsulates for each recipient and encrypts the message
// with each shared secret individually
let mut bundles: Vec<(Vec<u8>, Vec<u8>)> = Vec::new(); // (kem_ct, encrypted_msg)
for r in &recipients {
    let (kem_ct, ss) = encapsulate(r.public_key())?;
    let enc = encrypt(ss.as_slice()?, message)?;
    bundles.push((kem_ct, enc));
}

// Each recipient decapsulates their own bundle
for (i, r) in recipients.iter().enumerate() {
    let (kem_ct, encrypted_msg) = &bundles[i];
    let ss = r.decapsulate(kem_ct)?;
    let pt = decrypt(ss.as_slice()?, encrypted_msg)?;
    assert_eq!(pt, message);
}
```

### 8. Implicit Rejection — Tamper Detection

Demonstrates ML-KEM's built-in defense against ciphertext manipulation: bad input produces a different (random-looking) shared secret rather than an error, so AEAD decryption fails cleanly.

```rust
use secure_memory::kem::{KemKeyPair, encapsulate, CT_SIZE};
use secure_memory::{encrypt, decrypt};

let kp = KemKeyPair::generate()?;
let (kem_ct, ss) = encapsulate(kp.public_key())?;
let encrypted = encrypt(ss.as_slice()?, b"top secret")?;

// Attacker tampers with the KEM ciphertext
let mut tampered_ct = kem_ct.clone();
tampered_ct[0] ^= 0xFF;

// Bob decapsulates the tampered ciphertext — no error (implicit rejection),
// but the resulting shared secret is different
let bad_ss = kp.decapsulate(&tampered_ct)?;
assert_ne!(ss.as_slice()?, bad_ss.as_slice()?);

// AEAD decryption fails because the key doesn't match
let result = decrypt(bad_ss.as_slice()?, &encrypted);
assert!(result.is_err()); // Poly1305 tag mismatch → authentication failure
```

### 9. Secure Cleanup with `purge()`

Wipe all secrets from memory when done — including any `LockedBuffer` holding KEM keys or shared secrets.

```rust
use secure_memory::kem::{KemKeyPair, encapsulate};

let kp = KemKeyPair::generate()?;
let (_ct, _ss) = encapsulate(kp.public_key())?;

// ... use the shared secret ...

// Nuclear option: wipe every LockedBuffer in the process
// (KEM secret keys, shared secrets, session key — all gone)
secure_memory::purge();
// After this, all Enclaves are permanently undecryptable
```

## Memory Safety

Every secret touched by the KEM module is protected:

| Secret | Protection |
|--------|-----------|
| Decapsulation key (2 400 B) | `LockedBuffer` — mlock, guard pages, canary, zeroize-on-drop |
| Shared secret (32 B) | `LockedBuffer` — same protections |
| Intermediate byte arrays | Zeroed immediately after move via `from_bytes_move()` |

The public encapsulation key and ciphertext are plain `Vec<u8>` — they carry no secret material.

## Integration with the Encryption Pipeline

```
ML-KEM-768
    │
    ▼
32-byte shared secret (in LockedBuffer)
    │
    ▼
encrypt(key, plaintext) — crypto.rs
    │
    ▼
XChaCha20-Poly1305 AEAD
    │
    ▼
[nonce (24 B) ‖ ciphertext ‖ Poly1305 tag (16 B)]
```

> **Note:** This is a standalone ML-KEM scheme, not a hybrid (ML-KEM + ECDH). The 32-byte shared secret feeds directly into the symmetric cipher.

## Tests

Five dedicated tests in `kem.rs`:

| Test | What It Verifies |
|------|-----------------|
| `keygen_produces_correct_sizes` | EK = 1 184 B, DK = 2 400 B |
| `encapsulate_decapsulate_roundtrip` | Sender and receiver derive the same shared secret |
| `wrong_ciphertext_produces_different_secret` | Implicit rejection: bad CT → different (but valid) secret |
| `bad_key_size_rejected` | Encapsulate rejects wrong-sized public keys |
| `shared_secret_can_encrypt` | Full integration: KEM → XChaCha20-Poly1305 → roundtrip |

Run them:

```bash
cargo test --lib kem::
```

## Dependencies

| Crate | Version | Role |
|-------|---------|------|
| `ml-kem` | 0.2 | FIPS 203 ML-KEM-768 implementation |
| `rand` | 0.8 | CSPRNG for key generation and encapsulation |
| `chacha20poly1305` | 0.10 | Symmetric AEAD cipher consuming the shared secret |
| `zeroize` | 1 | Secure wipe of intermediate buffers |

## References

- [FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [`ml-kem` crate on crates.io](https://crates.io/crates/ml-kem)
