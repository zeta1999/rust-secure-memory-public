#!/usr/bin/env bash
# fuzz.sh — run a libfuzzer target against `secure-memory`.
#
# Usage:
#   ./scripts/fuzz.sh <target> [-- <libfuzzer args>]
#
# Examples:
#   ./scripts/fuzz.sh fuzz_encrypt_decrypt -- -max_total_time=30
#   ./scripts/fuzz.sh fuzz_buffer_ops      -- -max_total_time=60
#
# Why this wrapper exists (the same toolchain plumbing as scripts/miri.sh):
#
#   1. cargo-fuzz requires nightly. Plain `cargo +nightly fuzz …` fails on
#      systems where the `cargo` binary on PATH is the actual stable toolchain
#      cargo (rather than the rustup proxy) — the toolchain cargo doesn't
#      understand the `+toolchain` directive. We invoke the rustup proxy
#      (~/.cargo/bin/cargo) explicitly and prepend the nightly toolchain bin
#      directory so the inner `cargo build` cargo-fuzz spawns also resolves
#      to nightly (otherwise it rejects `-Zsanitizer=address`).
#
#   2. The workspace's `.cargo/config.toml` redirects crates-io to the local
#      `/vendor` directory, but `libfuzzer-sys` is not vendored. Cargo only
#      walks UPWARD when searching for `.cargo/config.toml`, so we run from
#      outside the workspace (cwd `/`) and pass `--fuzz-dir` to point cargo-
#      fuzz back at the project. The inner `cargo build` then walks up from
#      `/` and never sees the workspace's vendor redirect.
#
#      This means fuzzing requires network access on first build (to fetch
#      libfuzzer-sys + transitive deps from crates.io). Once cached, subsequent
#      runs are offline-friendly.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <fuzz_target> [-- <libfuzzer args>]" >&2
    echo "" >&2
    echo "available targets:" >&2
    ls "$(dirname "${BASH_SOURCE[0]}")/../crates/secure-memory/fuzz/fuzz_targets/" 2>/dev/null \
        | sed 's/\.rs$//' | sed 's/^/  /' >&2
    exit 64
fi

TARGET="$1"
shift

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO="${CARGO_HOME:-$HOME/.cargo}/bin/cargo"
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly cargo)")"

FUZZ_DIR="$WORKSPACE_ROOT/crates/secure-memory/fuzz"

cd /
PATH="$NIGHTLY_BIN:$PATH" \
    "$CARGO" +nightly fuzz run --fuzz-dir "$FUZZ_DIR" "$TARGET" "$@"
