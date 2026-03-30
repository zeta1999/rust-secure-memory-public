# rust-secure-memory

Secure memory management for sensitive data in Rust — a port of Go's [memguard](https://github.com/awnumar/memguard).

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

### secure-memory (library)

| Type | Purpose |
|------|---------|
| `LockedBuffer` | Mutable/frozen buffer with guard pages, mlock, canary values, secure wipe-on-drop |
| `Enclave` | Encrypted-at-rest container (XChaCha20-Poly1305 session key) |
| `Stream` | Chunked encrypted reader/writer for large data |
| `kem::KemKeyPair` | ML-KEM-768 (FIPS 203) post-quantum key encapsulation |

**Memory protections:**
- Guard pages (PROT_NONE) before and after data — segfault on overflow
- `mlock` / `VirtualLock` — pins pages in RAM, prevents swap to disk
- Canary sentinels — constant-time verified on drop to detect corruption
- Freeze / melt — kernel-level read-only toggle via `mprotect`
- Secure wipe via `zeroize` — defeats dead-store elimination
- Excluded from core dumps (`MADV_DONTDUMP` on Linux)

**Cryptography:**
- **AEAD:** XChaCha20-Poly1305 (256-bit key, 192-bit nonce)
- **KDF:** Argon2id (memory-hard) + VDF sequential SHA3-256 stretching (time-hard)
- **PQC:** ML-KEM-768 (FIPS 203) — post-quantum key encapsulation, shared secrets in LockedBuffer
- **Session key:** per-process, stored in a LockedBuffer, destroyed by `purge()`

**Platforms:** Unix (mmap/mlock/mprotect) and Windows (VirtualAlloc/Lock/Protect)

### sedit (editor)

Secure encrypted text editor with multiple keybinding modes and keyword syntax highlighting.

## Quick start

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

### Key bindings

Default (normal) mode. Use `--mode nano|emacs|mcedit` for alternatives.

| Key | Action |
|-----|--------|
| Ctrl-S | Save (encrypted or plaintext, depending on mode) |
| Esc / Ctrl-Q | Quit (press twice to discard unsaved changes) |
| Ctrl-H | Help screen |
| Ctrl-E | Export as plaintext (saves `<file>.plain`) |

**Keybinding modes:**

| Mode | Save | Quit | Help |
|------|------|------|------|
| `normal` (default) | Ctrl-S | Esc / Ctrl-Q | Ctrl-H |
| `nano` | Ctrl-O | Ctrl-X / Esc | Ctrl-G |
| `emacs` | C-x C-s | C-x C-c / Esc | C-h |
| `mcedit` | F2 | F10 / Esc | F1 |

### Syntax highlighting

Keyword highlighting is applied automatically based on file extension. Supported:
Rust, Python, JavaScript/TypeScript, C/C++, Go, Shell, Ruby, Java, Lua, Zig, SQL.

### File format (v2)

```
SEDIT\x00\x02\x00 (8 B) || salt (16 B) || nonce (24 B) || ciphertext || tag (16 B)
```

Per-file random salt. Key derivation: passphrase → Argon2id (64 MiB, 3 iter) → VDF (1000x SHA3-256).
Backward-compatible: v1 files (fixed salt) are still readable.

## Library usage

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

## Security verification

| Method | What it checks |
|--------|---------------|
| **Unit tests** (38) | Functional correctness of all primitives including ML-KEM-768 |
| **Integration tests** (2) | Encrypted file roundtrip with per-file salt |
| **Property tests** (proptest) | Roundtrip invariants, determinism, size constraints |
| **Kani harnesses** | No-overflow in `round_up`, input validation in encrypt/decrypt |
| **cargo-fuzz** (4 targets) | Buffer ops, encrypt/decrypt, enclave, KDF |

Run locally:
```bash
./scripts/ci.sh                              # fmt + clippy + test
./scripts/miri.sh                            # UB detection (needs nightly)
cargo fuzz run fuzz_encrypt_decrypt          # fuzzing (needs nightly)
```

## Build targets

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
