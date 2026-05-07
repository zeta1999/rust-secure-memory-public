# Post-Quantum Cryptography

rust-secure-memory ships three NIST-aligned post-quantum primitives plus a
hybrid construction that pairs the lattice KEM with a classical curve:

* **ML-KEM-768** (FIPS 203) — module-lattice key encapsulation
* **Hybrid ML-KEM-768 + X25519** — defence-in-depth KEM
* **ML-DSA-65** (FIPS 204) — module-lattice digital signatures

This document describes the **standalone ML-KEM-768** integration first, then
the hybrid KEM and ML-DSA at the bottom.

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

> **Note:** Use [`hybrid_kem`](#hybrid-kem-ml-kem-768--x25519) below if you want defense-in-depth: the standalone ML-KEM scheme described here relies entirely on lattice-problem hardness, while the hybrid variant survives a break in either ML-KEM or X25519 alone.

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
| `ml-dsa` | 0.0.4 | FIPS 204 ML-DSA-65 signatures |
| `x25519-dalek` | 2 | Classical X25519 ECDH for the hybrid combiner |
| `rand` | 0.8 | `OsRng` access (CSPRNG) for key generation and encapsulation |
| `chacha20poly1305` | 0.10 | AAD-aware AEAD consuming the shared secret |
| `sha3` | 0.10 | Hybrid combiner (SHA3-256) and KDF stretching |
| `zeroize` | 1 | Secure wipe of intermediate buffers |

---

## Hybrid KEM (ML-KEM-768 + X25519)

Module: `crates/secure-memory/src/hybrid_kem.rs`

Combines the FIPS 203 lattice KEM with classical X25519 ECDH so that a break
in either primitive on its own does **not** compromise the shared secret.
The combiner is SHA3-256, in the spirit of the IETF X-Wing draft, and binds
both component shared secrets to both component ciphertexts and the
recipient's static X25519 public key.

### Wire format

| Artifact | Size | Layout |
|----------|------|--------|
| Public key | **1 216 B** | `ml_kem_pk (1184)` ‖ `x25519_pk (32)` |
| Secret key | n/a | ML-KEM SK + X25519 SK, both in separate `LockedBuffer`s |
| Ciphertext | **1 120 B** | `ml_kem_ct (1088)` ‖ `x25519_ephemeral_pk (32)` |
| Shared secret | **32 B** | `LockedBuffer`-wrapped SHA3-256 output |

### Combiner

```text
SS = SHA3-256(
    "secure-memory/hybrid-kem/mlkem768+x25519/v1"
    || ml_kem_ss
    || x25519_ss
    || ml_kem_ct
    || x25519_ephem_pk
    || x25519_static_pk
)
```

Bumping the domain-separation tag invalidates all prior shared secrets — treat it as a versioning hook.

### Example

```rust
use secure_memory::hybrid_kem::{HybridKemKeyPair, encapsulate};

let kp = HybridKemKeyPair::generate()?;
let pk = kp.public_key();                      // 1216 B
let (ct, ss_send) = encapsulate(&pk)?;         // ct = 1120 B, ss = 32 B
let ss_recv = kp.decapsulate(&ct)?;
assert_eq!(ss_send.as_slice()?, ss_recv.as_slice()?);
```

### What it protects against

| Failure mode | Hybrid behaviour |
|--------------|------------------|
| Lattice attack breaks ML-KEM-768 | X25519 still secures the shared secret |
| Cryptanalytic break of X25519 | ML-KEM-768 still secures the shared secret |
| Quantum break of X25519 (Shor) | ML-KEM-768 still secures the shared secret |
| Bit flip in either ciphertext component | SHA3-256 combiner ensures shared secrets diverge |

---

## ML-DSA-65 Signatures (FIPS 204)

Module: `crates/secure-memory/src/sig.rs`

ML-DSA-65 is the NIST Category-3 lattice-based signature standard
(formerly Dilithium). It provides ~AES-192-equivalent security against
both classical and quantum adversaries. Signing is **deterministic**
(per FIPS 204 §3.1) — the same message and key always produce the same
signature, removing the side-channel risk of leaking randomness.

### Sizes

| Artifact | Size |
|----------|------|
| Verifying key (public) | **1 952 B** |
| Signing key (secret) | **4 032 B** — held in a `LockedBuffer` |
| Signature | **3 309 B** |

### Example

```rust
use secure_memory::sig::SigKeyPair;

let kp = SigKeyPair::generate()?;
let msg = b"important message";
let sig = kp.sign(msg)?;
assert!(SigKeyPair::verify(kp.verifying_key(), msg, &sig)?);
```

### When to use

| Use case | Recommended primitive |
|----------|----------------------|
| Authenticate a file at rest | `sig::SigKeyPair::sign(file_bytes)` |
| Authenticate a software update | ML-DSA over the release manifest |
| Authenticate a single message in a session | ML-DSA over the message + transcript |
| Encrypted message confidentiality | Use a (hybrid) KEM, not signatures |

---

## AAD-Aware AEAD

Module: `crates/secure-memory/src/crypto.rs`

The XChaCha20-Poly1305 wrapper is now AAD-aware:

```rust
pub fn encrypt_aad(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;
pub fn decrypt_aad(key: &[u8], data:      &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;
```

The AAD is bound into the Poly1305 tag but **not** stored in the output —
the caller is expected to convey it alongside the ciphertext (e.g. as a
file header). The legacy `encrypt`/`decrypt` are now thin wrappers with
empty AAD, so existing callers keep working.

The `sedit` editor uses this to authenticate its v3 file header (magic +
KDF parameters + salt) — any tampering with KDF parameters or salt is
detected at decryption.

## References

- [FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 — Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [IETF draft — Hybrid Public Key Encryption with X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [`ml-kem` crate on crates.io](https://crates.io/crates/ml-kem)
- [`ml-dsa` crate on crates.io](https://crates.io/crates/ml-dsa)
- [`x25519-dalek` crate on crates.io](https://crates.io/crates/x25519-dalek)
