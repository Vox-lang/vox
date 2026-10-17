#!/bin/bash
#
# The vas structure check: build records.vox, which writes out the operands
# the vas front end parses, and compare them, instruction by instruction,
# with the ones tests/toolchain/shapes.py reads from `nasm -E`. See
# structure_check.py for what must agree. The corpus files listed in
# refused_corpus_files.tsv, which vas refuses whole, are left out.
#
# The check runs in the Vox repository, with its assembly corpus and its
# shapes script present: the defaults below are that repository's paths.
#
# Usage:
#   bash tests/toolchain/vas/structure_check.sh
#
# Environment:
#   VOX            the compiler (default: vox on PATH)
#   VOX_CORE_PATH  the coreasm directory (default: the repository's coreasm)
#   VAS_CORPUS     the corpus directory, holding MANIFEST (default:
#                  the repository's tests/corpus)
#   VAS_SHAPES     the shapes script (default: the repository's
#                  tests/toolchain/shapes.py)
#
# Prints one summary line, followed by the first differences if there are
# any, and exits non-zero on any difference.

set -uo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
VOX="${VOX:-vox}"

# A missing path is named with the variable that sets it, since a checkout
# without the corpus is the usual reason.
the_path() {
    if [[ ! -e "$1" ]]; then
        echo "structure check: there is no $3 at $1. Set $2 to it; the check runs in the Vox repository, with the corpus present." >&2
        return 1
    fi
    echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
}
if ! command -v "$VOX" >/dev/null; then
    echo "structure check: there is no Vox compiler at $VOX. Set VOX to it." >&2
    exit 1
fi
CORE="$(the_path "${VOX_CORE_PATH:-$ROOT/coreasm}" VOX_CORE_PATH "coreasm directory")" || exit 1
CORPUS="$(the_path "${VAS_CORPUS:-$ROOT/tests/corpus}" VAS_CORPUS "corpus directory")" || exit 1
SHAPES="$(the_path "${VAS_SHAPES:-$ROOT/tests/toolchain/shapes.py}" VAS_SHAPES "shapes script")" || exit 1
export VOX_CORE_PATH="$CORE"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

if ! (cd "$scratch" && "$VOX" "$HERE/records.vox" -o "$scratch/records") >"$scratch/build.log" 2>&1; then
    echo "structure check: the records program did not build:"
    grep -iv '^warning\|^  ' "$scratch/build.log" | head -20
    exit 1
fi

cd "$scratch" && python3 "$HERE/structure_check.py" "$scratch/records" "$SHAPES" "$CORPUS" "$CORE"
