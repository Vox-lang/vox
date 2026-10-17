#!/bin/bash
#
# The vas encoder tests. mechanics_test checks each encoding mechanic on its
# own against the bytes nasm gives; shapes_test encodes the example of every
# row of the shapes table and compares it with nasm's bytes for that row.
# Both build the instruction records with records.vox, so they test the
# encoder alone.
#
# Usage:
#   bash tests/toolchain/vas/encoder/encoder_check.sh
#
# Environment:
#   VOX            the compiler (default: vox on PATH)
#   VOX_CORE_PATH  the coreasm directory (default: this repository's coreasm)
#   VAS_SHAPES_TABLE  the shapes table (default: tests/toolchain/shapes.tsv)

set -uo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
VOX="${VOX:-vox}"
CORE="$(cd "${VOX_CORE_PATH:-$ROOT/coreasm}" && pwd)"
export VOX_CORE_PATH="$CORE"
TABLE="${VAS_SHAPES_TABLE:-$ROOT/tests/toolchain/shapes.tsv}"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# The compiler searches the current directory first, so build in the scratch
# directory.
for check in mechanics_test shapes_test; do
    if ! (cd "$scratch" && "$VOX" "$HERE/$check.vox" -o "$scratch/$check") >"$scratch/$check.log" 2>&1; then
        echo "encoder check: $check did not build:"
        grep -iv '^warning\|^  ' "$scratch/$check.log" | head -20
        exit 1
    fi
done

failed=0
"$scratch/mechanics_test" || failed=1
"$scratch/shapes_test" "$TABLE" || failed=1

if [[ $failed -ne 0 ]]; then
    echo "encoder check: failed"
    exit 1
fi
echo "encoder check: every mechanic and every shape encodes as nasm encodes it"
