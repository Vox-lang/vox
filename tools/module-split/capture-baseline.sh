#!/bin/bash
# Snapshot the compiler's output BEFORE the refactor. The corpus is every
# examples/*.vox plus every tests/*.vox. Emission is byte-deterministic
# (verified), so this baseline is the ground truth the gate compares against.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
cargo build --release >/dev/null 2>&1 || { echo "baseline: build failed"; exit 1; }
VOX="$ROOT/target/release/vox"
OUT="$ROOT/target/module-split-baseline"
rm -rf "$OUT"; mkdir -p "$OUT/asm"
emit() { # <label> <vox-file>
  local label="$1" src="$2" d
  d="$(mktemp -d)"; cp "$src" "$d/p.vox"
  ( cd "$d" && "$VOX" p.vox --emit-asm -o p >/dev/null 2>&1 )
  [ -f "$d/p.asm" ] && cp "$d/p.asm" "$OUT/asm/$label.asm"
  rm -rf "$d"
}
for f in examples/*.vox tests/*.vox; do
  [ -e "$f" ] || continue
  emit "$(echo "$f" | tr '/' '_')" "$f"
done
./test.sh 2>&1 | grep -E 'Passed:|Failed:|Skipped:|Total:' > "$OUT/test-summary.txt"
echo "baseline captured: $(ls "$OUT/asm" | wc -l) asm snapshots"
cat "$OUT/test-summary.txt"
