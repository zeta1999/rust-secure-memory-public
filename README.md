<p align="center">
  <img src="assets/logo.svg" alt="rust-secure-memory" width="96">
</p>

<h1 align="center">rust-secure-memory</h1>

<p align="center">
  <strong>Secure memory management for sensitive data in Rust</strong><br>
  A port of Go's <a href="https://github.com/awnumar/memguard">memguard</a> — with post-quantum cryptography built in.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-2021_edition-orange?logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Crypto-XChaCha20--Poly1305-blue" alt="Crypto">
  <img src="https://img.shields.io/badge/PQC-ML--KEM--768_(FIPS_203)-purple" alt="PQC">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/Platforms-Linux_|_macOS_|_Windows-lightgrey" alt="Platforms">
</p>

---

Includes **`sedit`**, a TUI encrypted text editor that demonstrates the library.

## Architecture

```
crates/
  secure-memory/   Core library — LockedBuffer, Enclave, Stream, KEM, crypto
  secure-editor/   Demo app — sedit encrypted text editor
scripts/
  ci.sh            Lint, format check, and test
  build-all.sh     Cross-compile release binaries
  miri.sh          UB detection with Miri
```

## Core Types

| Type | Purpose |
|------|---------|
| `LockedBuffer` | Mutable/frozen buffer with guard pages, mlock, canary values, secure wipe-on-drop |
| `Enclave` | Encrypted-at-rest container (XChaCha20-Poly1305 session key) |
| `Stream` | Chunked encrypted reader/writer for large data |
| `kem::KemKeyPair` | ML-KEM-768 (FIPS 203) post-quantum key encapsulation |

## Memory Protections

- **Guard pages** (PROT_NONE) before and after data — segfault on overflow
- **mlock / VirtualLock** — pins pages in RAM, prevents swap to disk
- **Canary sentinels** — constant-time verified on drop to detect corruption
- **Freeze / melt** — kernel-level read-only toggle via `mprotect`
- **Secure wipe** via `zeroize` — defeats dead-store elimination
- **Core dump exclusion** (`MADV_DONTDUMP` on Linux)

## Cryptography

| Layer | Algorithm | Details |
|-------|-----------|---------|
| **AEAD** | XChaCha20-Poly1305 | 256-bit key, 192-bit nonce |
| **KDF** | Argon2id + VDF | Memory-hard + sequential SHA3-256 stretching |
| **PQC** | ML-KEM-768 (FIPS 203) | Post-quantum key encapsulation, shared secrets in LockedBuffer |
| **Session key** | Per-process | Stored in LockedBuffer, destroyed by `purge()` |

> See **[PQC-ML-KEM.md](PQC-ML-KEM.md)** for a deep dive on the post-quantum cryptography integration.

**Platforms:** Unix (mmap/mlock/mprotect) and Windows (VirtualAlloc/Lock/Protect)

## Quick Start

```bash
# Build
cargo build --release

# Create a new encrypted file (prompts for key twice)
./target/release/sedit secret.txt

# Open an existing encrypted file (prompts for key once)
./target/release/sedit secret.txt

# Open/create a plaintext file (no encryption)
./target/release/sedit --plaintext notes.txt

# Pipe key from stdin
echo "my-passphrase" | ./target/release/sedit --key-stdin secret.txt

# Use nano-style keybindings
./target/release/sedit --mode nano secret.txt
```

## sedit — Encrypted Text Editor

Secure encrypted text editor with multiple keybinding modes and keyword syntax highlighting.

### Key Bindings

Default (normal) mode. Use `--mode nano|emacs|mcedit` for alternatives.

| Key | Action |
|-----|--------|
| Ctrl-S | Save (encrypted or plaintext, depending on mode) |
| Esc / Ctrl-Q | Quit (press twice to discard unsaved changes) |
| Ctrl-H | Help screen |
| Ctrl-E | Export as plaintext (saves `<file>.plain`) |

<details>
<summary><strong>All keybinding modes</strong></summary>

| Mode | Save | Quit | Help |
|------|------|------|------|
| `normal` (default) | Ctrl-S | Esc / Ctrl-Q | Ctrl-H |
| `nano` | Ctrl-O | Ctrl-X / Esc | Ctrl-G |
| `emacs` | C-x C-s | C-x C-c / Esc | C-h |
| `mcedit` | F2 | F10 / Esc | F1 |

</details>

### Syntax Highlighting

Keyword highlighting is applied automatically based on file extension. Supported:
Rust, Python, JavaScript/TypeScript, C/C++, Go, Shell, Ruby, Java, Lua, Zig, SQL.

### File Format (v2)

```
SEDIT\x00\x02\x00 (8 B) || salt (16 B) || nonce (24 B) || ciphertext || tag (16 B)
```

Per-file random salt. Key derivation: passphrase → Argon2id (64 MiB, 3 iter) → VDF (1000x SHA3-256).
Backward-compatible: v1 files (fixed salt) are still readable.

## Library Usage

```rust
use secure_memory::{LockedBuffer, Enclave};

// Store a secret in locked memory
let mut buf = LockedBuffer::new(32)?;
buf.as_mut_slice()?.copy_from_slice(&my_secret_key);
buf.freeze()?; // read-only

// Seal into an encrypted Enclave (wipes the buffer)
let enclave = buf.seal()?;

// Later, unseal
let opened = enclave.open()?;
assert_eq!(opened.as_slice()?, &my_secret_key);

// Key derivation
let key = secure_memory::derive_key_combined(
    b"passphrase", b"salt-16bytes",
    65536, 3,   // Argon2: 64MiB, 3 iterations
    1000,       // VDF: 1000x SHA3-256
)?;

// Post-quantum key encapsulation
use secure_memory::kem::{KemKeyPair, encapsulate};
let kp = KemKeyPair::generate()?;
let (ciphertext, shared_secret) = encapsulate(kp.public_key())?;
let recovered = kp.decapsulate(&ciphertext)?;

// Nuclear cleanup
secure_memory::purge(); // wipes all buffers + destroys session key
```

## Security Verification

| Method | What It Checks |
|--------|---------------|
| **Unit tests** (38) | Functional correctness of all primitives including ML-KEM-768 |
| **Integration tests** (2) | Encrypted file roundtrip with per-file salt |
| **Property tests** (10) | Roundtrip invariants, determinism, size constraints, KEM implicit rejection |
| **Kani harnesses** (7) | Input validation in encrypt/decrypt/encapsulate/decapsulate, `round_up` safety |
| **cargo-fuzz** (5 targets) | Buffer ops, encrypt/decrypt, enclave, KDF, KEM |
| **Lean4 proofs** (18 theorems) | KEM+AEAD composition, implicit rejection, key separation, buffer wipe/purge |

```bash
./scripts/ci.sh                              # fmt + clippy + test
./scripts/miri.sh                            # UB detection (needs nightly)
cargo fuzz run fuzz_encrypt_decrypt          # fuzzing (needs nightly)
```

## Build Targets

```bash
./scripts/build-all.sh          # all targets
./scripts/build-all.sh native   # current platform only
```

| Target | Triple |
|--------|--------|
| Linux x86_64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS ARM64 | `aarch64-apple-darwin` |
| Windows x86_64 | `x86_64-pc-windows-msvc` |
| Windows ARM64 | `aarch64-pc-windows-msvc` |

## License

MIT
