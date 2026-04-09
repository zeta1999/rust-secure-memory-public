#!/usr/bin/env bash
set -euo pipefail

echo "==> Installing Rust nightly (for Miri + cargo-fuzz)"
rustup toolchain install nightly --component miri
rustup component add clippy rustfmt

echo "==> Installing cargo-fuzz"
cargo install cargo-fuzz

echo "==> Installing Kani (bounded model checking)"
cargo install --locked kani-verifier
cargo kani setup

echo "==> Installing elan + Lean4 (formal proofs)"
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
export PATH="$HOME/.elan/bin:$PATH"
cd proofs/lean4 && lake build && cd ../..

echo "==> Building project"
cargo build --all
cargo test --all

echo "==> Done. All tools installed:"
echo "    rustc $(rustc --version)"
echo "    cargo-fuzz: $(cargo fuzz --version 2>/dev/null || echo 'installed')"
echo "    cargo-kani: $(cargo kani --version 2>/dev/null || echo 'installed')"
echo "    lean: $(lean --version 2>/dev/null || echo 'installed')"
