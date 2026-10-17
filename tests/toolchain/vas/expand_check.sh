#!/bin/bash
#
# The vas front-end check: for every file in the assembly corpus, compare
# the expansion vas writes with the one `nasm -E` writes, after both go
# through the same normaliser (normalise.py beside this script). A library
# is preprocessed with PIC defined, on both sides, as the compiler does for
# --shared.
#
# Some corpus files use a construct that only a shared build writes, which
# vas refuses by name: those must be refused, with the message listed for
# each in refused_corpus_files.tsv beside this script, and are counted
# apart.
#
# The check runs in the Vox repository, with its assembly corpus present:
# the defaults below are that repository's paths.
#
# Usage:
#   bash tests/toolchain/vas/expand_check.sh
#
# Environment:
#   VOX            the compiler (default: vox on PATH)
#   VOX_CORE_PATH  the coreasm directory (default: the repository's coreasm)
#   VAS_CORPUS     the corpus directory, holding MANIFEST (default:
#                  the repository's tests/corpus)
#
# Prints a line for each file refused as expected, then one summary line.
# Exits non-zero if any file's expansion differs or a refusal is not the
# expected one.

set -uo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
VOX="${VOX:-vox}"

# A missing path is named with the variable that sets it, since a checkout
# without the corpus is the usual reason.
the_directory() {
    if [[ ! -d "$1" ]]; then
        echo "expand check: there is no $3 at $1. Set $2 to it; the check runs in the Vox repository, with the corpus present." >&2
        return 1
    fi
    (cd "$1" && pwd)
}
if ! command -v "$VOX" >/dev/null; then
    echo "expand check: there is no Vox compiler at $VOX. Set VOX to it." >&2
    exit 1
fi
CORE="$(the_directory "${VOX_CORE_PATH:-$ROOT/coreasm}" VOX_CORE_PATH "coreasm directory")" || exit 1
CORPUS="$(the_directory "${VAS_CORPUS:-$ROOT/tests/corpus}" VAS_CORPUS "corpus directory")" || exit 1
export VOX_CORE_PATH="$CORE"

if [[ ! -f "$CORPUS/MANIFEST" ]]; then
    echo "expand check: there is no MANIFEST in $CORPUS. Set VAS_CORPUS to the corpus directory that holds one." >&2
    exit 1
fi

# The emitted %include lines name coreasm/<arch>/<file>.asm, so nasm
# searches the directory above coreasm, exactly as the compiler's -I does.
INCLUDE="$(cd "$CORE/.." && pwd)/"

declare -A EXPECTED_REFUSALS=()
while IFS=$'\t' read -r file message; do
    [[ -z "$file" || "$file" == \#* ]] && continue
    EXPECTED_REFUSALS[$file]="$message"
done < "$HERE/refused_corpus_files.tsv"

# nasm searches the current directory before -I, and the compiler must not
# run inside another Vox tree, so everything runs from a scratch directory.
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

if ! (cd "$scratch" && "$VOX" "$HERE/expand.vox" -o "$scratch/expand") >"$scratch/build.log" 2>&1; then
    echo "expand check: the vas driver did not build:"
    grep -iv '^warning\|^  ' "$scratch/build.log" | head -20
    exit 1
fi

matched=0
refused=0
failures=()

while IFS=$'\t' read -r file kind _; do
    [[ -z "$file" || "$file" == \#* ]] && continue
    name="${file//\//_}"
    definitions=()
    nasm_definitions=()
    if [[ $kind == library ]]; then
        definitions=(PIC)
        nasm_definitions=(-DPIC)
    fi

    if ! (cd "$scratch" && nasm -E -f elf64 "${nasm_definitions[@]}" "-I$INCLUDE" "$CORPUS/$file") \
            >"$scratch/$name.nasm" 2>"$scratch/$name.nasm.log"; then
        failures+=("$file: nasm -E failed: $(head -1 "$scratch/$name.nasm.log")")
        continue
    fi

    (cd "$scratch" && ./expand "$CORPUS/$file" "$CORE" "$scratch/$name.vas" "${definitions[@]}") \
        2>"$scratch/$name.vas.log"
    status=$?
    expected="${EXPECTED_REFUSALS[$file]:-}"

    if [[ -n "$expected" ]]; then
        if [[ $status -ne 0 ]] && grep -qF "$expected" "$scratch/$name.vas.log"; then
            refused=$((refused + 1))
            echo "refused as expected: $file: $(grep -F "$expected" "$scratch/$name.vas.log" | head -1)"
        else
            failures+=("$file: expected a refusal saying \"$expected\", got exit $status: $(head -1 "$scratch/$name.vas.log")")
        fi
        continue
    fi

    if [[ $status -ne 0 ]]; then
        failures+=("$file: vas failed with $status errors: $(head -1 "$scratch/$name.vas.log")")
        continue
    fi

    if difference="$(python3 "$HERE/normalise.py" --compare "$scratch/$name.nasm" "$scratch/$name.vas")"; then
        matched=$((matched + 1))
    else
        failures+=("$file: $difference")
    fi
done < "$CORPUS/MANIFEST"

total=$((matched + refused + ${#failures[@]}))
if [[ ${#failures[@]} -gt 0 ]]; then
    echo "expand check: $matched of $((total - refused)) expanded files match nasm -E, $refused refused as expected, ${#failures[@]} failed:"
    printf '  %s\n' "${failures[@]}"
    exit 1
fi
echo "expand check: all $matched expanded files match nasm -E; $refused refused as expected ($total corpus files)"
