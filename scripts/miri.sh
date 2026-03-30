#!/usr/bin/env bash
# miri.sh — detect undefined behavior in unsafe code
set -euo pipefail

echo "=== Miri (UB detection) ==="
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test -p secure-memory
echo "=== Miri passed ==="
