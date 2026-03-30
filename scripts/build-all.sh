#!/usr/bin/env bash
# build-all.sh — cross-compile release binaries for all targets
#
# Targets:
#   linux/amd64    x86_64-unknown-linux-gnu
#   linux/arm64    aarch64-unknown-linux-gnu      (needs cross)
#   darwin/arm64   aarch64-apple-darwin
#   windows/amd64  x86_64-pc-windows-msvc
#   windows/arm64  aarch64-pc-windows-msvc
#
# Usage:
#   ./scripts/build-all.sh              # build all targets
#   ./scripts/build-all.sh native       # build only the native target
set -euo pipefail

OUTDIR="dist"
mkdir -p "$OUTDIR"

build_native() {
    local target="$1"
    local artifact="$2"
    echo "=== Building $artifact ($target) ==="
    cargo build --release --target "$target" -p secure-editor
    local ext=""
    [[ "$target" == *windows* ]] && ext=".exe"
    cp "target/${target}/release/sedit${ext}" "${OUTDIR}/${artifact}"
    echo "  -> ${OUTDIR}/${artifact}"
}

build_cross() {
    local target="$1"
    local artifact="$2"
    echo "=== Building $artifact ($target) via cross ==="
    if ! command -v cross &>/dev/null; then
        echo "Installing cross..."
        cargo install cross --git https://github.com/cross-rs/cross
    fi
    cross build --release --target "$target" -p secure-editor
    cp "target/${target}/release/sedit" "${OUTDIR}/${artifact}"
    echo "  -> ${OUTDIR}/${artifact}"
}

if [[ "${1:-all}" == "native" ]]; then
    # Build only for the current platform
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)   build_native x86_64-unknown-linux-gnu   sedit-linux-amd64 ;;
        Linux-aarch64)  build_native aarch64-unknown-linux-gnu  sedit-linux-arm64 ;;
        Darwin-arm64)   build_native aarch64-apple-darwin       sedit-darwin-arm64 ;;
        *)              echo "Unknown platform: $(uname -s)-$(uname -m)"; exit 1 ;;
    esac
else
    # Attempt all targets — skip those that fail (missing toolchains)
    rustup target add x86_64-unknown-linux-gnu   2>/dev/null || true
    rustup target add aarch64-unknown-linux-gnu  2>/dev/null || true
    rustup target add aarch64-apple-darwin       2>/dev/null || true
    rustup target add x86_64-pc-windows-msvc     2>/dev/null || true
    rustup target add aarch64-pc-windows-msvc    2>/dev/null || true

    # Native targets (build what the host can compile)
    build_native aarch64-apple-darwin sedit-darwin-arm64 || echo "  SKIP (not on macOS ARM64)"

    # Cross-compiled targets
    build_cross aarch64-unknown-linux-gnu sedit-linux-arm64 || echo "  SKIP (cross not available)"
    build_native x86_64-unknown-linux-gnu sedit-linux-amd64 || echo "  SKIP (not on Linux x86_64)"

    # Windows (typically needs cross or a Windows host)
    build_native x86_64-pc-windows-msvc  sedit-windows-amd64.exe || echo "  SKIP (not on Windows)"
    build_native aarch64-pc-windows-msvc sedit-windows-arm64.exe || echo "  SKIP (not on Windows)"
fi

echo ""
echo "=== Built binaries in ${OUTDIR}/ ==="
ls -lh "$OUTDIR"/
