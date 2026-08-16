#!/bin/bash
# The per-extraction gate. Exit 0 iff: build clean, asm byte-identical to
# baseline for every corpus program, and test summary matches baseline.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
OUT="$ROOT/target/module-split-baseline"
[ -d "$OUT/asm" ] || { echo "gate: no baseline — run capture-baseline.sh first"; exit 1; }
if ! cargo build --release 2>&1 | tail -1 | grep -q Finished; then
  echo "gate: BUILD FAILED"; exit 1; fi
VOX="$ROOT/target/release/vox"
fail=0
for f in examples/*.vox tests/*.vox; do
  [ -e "$f" ] || continue
  label="$(echo "$f" | tr '/' '_')"; base="$OUT/asm/$label.asm"
  [ -f "$base" ] || continue
  d="$(mktemp -d)"; cp "$f" "$d/p.vox"
  ( cd "$d" && "$VOX" p.vox --emit-asm -o p >/dev/null 2>&1 )
  if ! diff -q "$base" "$d/p.asm" >/dev/null 2>&1; then
    echo "gate: ASM DIFF in $f"; fail=1; fi
  rm -rf "$d"
done
now="$(./test.sh 2>&1 | grep -E 'Passed:|Failed:|Skipped:|Total:')"
if [ "$now" != "$(cat "$OUT/test-summary.txt")" ]; then
  echo "gate: TEST SUMMARY CHANGED"; echo "was:"; cat "$OUT/test-summary.txt"; echo "now: $now"; fail=1; fi
[ "$fail" -eq 0 ] && echo "gate: PASS (asm identical, suite matches baseline)" || echo "gate: FAIL"
exit $fail
