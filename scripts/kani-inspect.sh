#!/usr/bin/env bash
# Inspect Kani/CBMC verification state.
#
# Kani writes one goto-binary (.out) and one symtab (.symtab.out) per #[kani::proof].
# Their byte size and symbol count are strong proxies for SAT-encoding cost: tiny
# proofs ship in <50 KB; proofs that drag in heavy library code (crypto, NTT, SHA3)
# blow up to multiple MB and take orders of magnitude longer to solve.
#
# Usage: scripts/kani-inspect.sh
set -euo pipefail

DEPS_DIR="target/kani/aarch64-apple-darwin/debug/deps"

if [[ ! -d "$DEPS_DIR" ]]; then
    echo "no kani build artifacts at $DEPS_DIR — run cargo kani first" >&2
    exit 1
fi

echo "=== Running CBMC processes ==="
ps -o pid,etime,time,%cpu,rss,command -ax | awk 'NR==1 || /[c]bmc / || /cargo-[k]ani/ || /[k]ani-driver/'
echo

echo "=== Proof artifacts (largest first) ==="
printf "%10s  %8s  %s\n" "GOTO" "SYMS" "PROOF"
for f in "$DEPS_DIR"/*.out; do
    [[ "$f" == *.symtab.out ]] && continue
    [[ -f "$f" ]] || continue
    size=$(stat -f%z "$f")
    syms_file="${f%.out}.symtab.out"
    sym_count=$(strings "$syms_file" 2>/dev/null | grep -cE '^_RN' || echo 0)
    # demangle the proof name from the file basename
    name=$(basename "$f" .out | sed -E 's/^.*__RNv//' | sed -E 's/Cs[A-Za-z0-9_]+_//' | sed -E 's/[0-9]+/ /g' | tr -s ' ' | sed -E 's/^ +//')
    printf "%10d  %8d  %s\n" "$size" "$sym_count" "$name"
done | sort -rn -k1
echo

# If CBMC is running, point at the proof it's working on.
running_out=$(ps -o command= -ax | grep -oE "${DEPS_DIR}/[^ ]+\.out" | head -1 || true)
if [[ -n "$running_out" ]]; then
    echo "=== Currently being verified ==="
    base=$(basename "$running_out" .out)
    proof=$(echo "$base" | sed -E 's/^.*kani_proofs[0-9]+//')
    echo "proof name (mangled tail): $proof"
    echo "goto-binary:               $(stat -f%z "$running_out") bytes"
    echo "symtab symbols:            $(strings "${running_out%.out}.symtab.out" 2>/dev/null | grep -cE '^_RN')"
    echo
    echo "Top crates pulled into the symtab (by symbol count):"
    strings "${running_out%.out}.symtab.out" 2>/dev/null \
        | grep -oE '(ml_kem|sha3|keccak|chacha|poly1305|hybrid_array|crypto_common|rand_core|getrandom|alloc|core)::[a-zA-Z_]+' \
        | sort | uniq -c | sort -rn | head -15
fi
