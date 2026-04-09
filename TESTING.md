# Testing Guide

## Quick check

Run the full CI pipeline (format, lint, test):

```bash
./scripts/ci.sh
```

## Unit & integration tests

```bash
cargo test --all
```

This runs:
- 38 library unit tests (buffer, crypto, enclave, stream, platform, ML-KEM-768)
- 10 property-based tests (proptest roundtrips, invariants, determinism, KEM implicit rejection)
- 2 integration tests (encrypted file roundtrip with per-file salt, wrong-key rejection)
- 2 doc-tests

## Manual editor testing

```bash
cargo build --release

# New encrypted file (prompts for key twice, then opens editor)
./target/release/sedit /tmp/test.txt

# Existing encrypted file (prompts for key once)
./target/release/sedit /tmp/test.txt

# Plaintext mode (no encryption)
./target/release/sedit --plaintext /tmp/notes.txt

# Syntax highlighting (auto-detected from extension)
./target/release/sedit --plaintext /tmp/example.rs

# Pipe key from stdin
echo "my-passphrase" | ./target/release/sedit --key-stdin /tmp/test.txt

# Keybinding modes
./target/release/sedit --mode nano /tmp/test.txt
./target/release/sedit --mode emacs /tmp/test.txt
./target/release/sedit --mode mcedit /tmp/test.txt
```

### Editor keys (default/normal mode)

| Key          | Action                                  |
|--------------|-----------------------------------------|
| Ctrl-S       | Save                                    |
| Esc / Ctrl-Q | Quit (press twice to discard unsaved)   |
| Ctrl-H       | Help                                    |
| Ctrl-E       | Export as plaintext (`<file>.plain`)     |

## Formal verification

### Miri (undefined behavior detection)

Requires Rust nightly:

```bash
rustup toolchain install nightly --component miri
./scripts/miri.sh
```

### Fuzzing

Requires Rust nightly and cargo-fuzz:

```bash
cargo install cargo-fuzz

cd crates/secure-memory

# Run a specific fuzz target (30 seconds)
cargo +nightly fuzz run fuzz_encrypt_decrypt -- -max_total_time=30
cargo +nightly fuzz run fuzz_buffer_ops -- -max_total_time=30
cargo +nightly fuzz run fuzz_enclave -- -max_total_time=30
cargo +nightly fuzz run fuzz_kdf -- -max_total_time=30
cargo +nightly fuzz run fuzz_kem -- -max_total_time=30
```

### Kani (bounded model checking)

Requires [Kani](https://model-checking.github.io/kani/):

```bash
cargo kani -p secure-memory
```

Verifies:
- `round_up` never overflows and is idempotent
- `decrypt` rejects inputs shorter than the nonce
- `encrypt` rejects keys that aren't 32 bytes
- `encapsulate` rejects public keys that aren't 1184 bytes
- `decapsulate` rejects ciphertexts that aren't 1088 bytes
- ML-KEM-768 shared secret is always 32 bytes

### Lean4 formal proofs (protocol composition)

Requires [Lean4](https://leanprover.github.io/lean4/doc/setup.html) and Lake:

```bash
cd proofs/lean4
lake build
```

Proves high-level composition properties (assuming correctness of underlying primitives):

- **KEM+AEAD roundtrip** — composed encrypt/decrypt recovers plaintext
- **IND-CCA2 composition** — IND-CCA2 KEM + (IND-CPA + INT-CTXT) AEAD → IND-CCA2 scheme
- **Implicit rejection → AEAD failure** — tampered KEM CT → different key → auth failure
- **Key separation** — distinct key pairs → independent keys → no cross-decryption
- **Buffer wipe/purge completeness** — purge zeroes all data, secrets are unrecoverable
- **Secret confinement** — no non-zero secret survives purge

See [`proofs/lean4/SecureMemory/Main.lean`](proofs/lean4/SecureMemory/Main.lean) for the full theorem inventory.

## Cross-platform builds

```bash
# Build for current platform only
./scripts/build-all.sh native

# Build all targets (linux/amd64, linux/arm64, darwin/arm64, windows/amd64, windows/arm64)
./scripts/build-all.sh
```

Binaries are placed in `dist/`.
