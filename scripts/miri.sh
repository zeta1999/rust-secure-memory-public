#!/usr/bin/env bash
# miri.sh — detect undefined behavior in unsafe code
#
# Scope of what this checks (and what it doesn't):
#
#   Miri is a Rust MIR interpreter. It validates pointer provenance, Stacked /
#   Tree Borrows aliasing, uninitialized reads, use-after-free, alignment, drop
#   order, and similar memory-safety properties — across the entire algorithmic
#   surface of `secure-memory`, including `LockedBuffer`, `ct_eq`, file format
#   encoding/decoding, AAD handling, and zeroize-on-drop.
#
#   Two parts of the crate are NOT exercised by miri:
#
#   1. **OS-level FFI** (`mmap` / `mlock` / `mprotect` / `madvise`). Miri does
#      not support these foreign calls on macOS and they're inherently outside
#      its memory model anyway. `platform.rs` provides a `#[cfg(miri)]` shim
#      that uses `std::alloc` instead of `mmap` and no-ops the protection
#      calls. Real OS-protection guarantees are validated only at runtime by
#      the kernel.
#
#   2. **Slow cryptographic primitives**: Argon2 KDF, ML-KEM-768, ML-DSA-65,
#      and proptest-driven sweeps over them. Miri's interpreter is roughly
#      100–1000× slower than native and does not use SIMD. A single Argon2
#      derivation can take 10–100 s; an ML-KEM keygen ~1–2 s; proptest fires
#      256 cases per test by default. Tests exercising these are gated with
#      `#[cfg_attr(miri, ignore)]` (or whole modules with `#[cfg(not(miri))]`
#      for proptest blocks). Native `cargo test` covers them — see
#      `scripts/ci.sh`. Cheap input-validation tests (size guards, fixed-input
#      AEAD roundtrips, all `LockedBuffer` unit tests) still run under Miri.
#
# The net result: Miri verifies what it can verify (memory model, provenance,
# drop semantics) on the parts of the code where it's feasible and adds
# information beyond `cargo test`.

set -euo pipefail

# Resolve the workspace root (this script's parent directory).
WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Miri (UB detection) ==="

# `cargo` on PATH may resolve to a real toolchain binary that ignores `+nightly`,
# and the nightly toolchain's bin dir may not be on PATH, so `cargo miri`'s
# subcommand discovery for `cargo-miri` would fail. Use the rustup proxy and
# prepend the nightly bin dir explicitly.
CARGO="${CARGO_HOME:-$HOME/.cargo}/bin/cargo"
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo)")"

# Run from outside the workspace so cargo's upward config search does not pick
# up the workspace's `.cargo/config.toml` (which redirects crates-io to the
# vendored sources) during miri's std sysroot build. The std sysroot pulls
# crates whose versions are tied to the nightly toolchain, not to our lockfile,
# and those versions are not vendored. The test build still picks up the
# workspace config via `--manifest-path`.
#
# MIRIFLAGS rationale:
#   -Zmiri-disable-isolation : allow time/RNG syscalls used by the crypto
#       primitives (e.g. for nonces in `crypto::session_encrypt`).
#   -Zmiri-ignore-leaks      : the `SESSION_KEY` `LazyLock` in crypto.rs is a
#       deliberate process-lifetime singleton and is never deallocated. Miri
#       reports any allocation live at exit as a leak; this flag suppresses
#       that benign report so real leaks elsewhere are still caught at the
#       allocator level (Miri also catches use-after-free / double-free
#       independently of this flag).
cd /
PATH="$NIGHTLY_BIN:$PATH" \
    MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-ignore-leaks" \
    "$CARGO" +nightly miri test \
        --manifest-path "$WORKSPACE_ROOT/Cargo.toml" \
        -p secure-memory
echo "=== Miri passed ==="
