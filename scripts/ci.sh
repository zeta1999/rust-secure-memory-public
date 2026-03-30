#!/usr/bin/env bash
# ci.sh — lint, format check, and test
set -euo pipefail

echo "=== Format check ==="
cargo fmt --all -- --check

echo "=== Clippy ==="
cargo clippy --all-targets --all-features -- -D warnings

echo "=== Tests ==="
cargo test --all

echo "=== All CI checks passed ==="
