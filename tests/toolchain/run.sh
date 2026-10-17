#!/bin/bash
#
# Assemble every corpus file with nasm and link it with ld, with the flags
# the compiler uses (src/main.rs), and confirm that each one links. This is
# the first layer of the differential harness: later milestones put vas and
# vox-elf beside nasm and ld and compare what they produce.
#
# Usage:
#   bash tests/toolchain/run.sh
#
# Environment:
#   VOX_CORE_PATH  the coreasm directory to assemble against
#                  (default: this repository's coreasm)
#
# Exits non-zero if any corpus file fails to assemble or link, or if the
# corpus is empty.

set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CORPUS="$ROOT/tests/corpus"
CORE="${VOX_CORE_PATH:-$ROOT/coreasm}"

# The emitted %include lines name coreasm/<arch>/<file>.asm, so nasm
# searches the directory above coreasm, exactly as the compiler's -I does.
INCLUDE="$(cd "$CORE/.." && pwd)/"

# The compiler adds the loader only when a program links a shared library.
LOADER=/lib64/ld-linux-x86-64.so.2

if [[ ! -f "$CORPUS/MANIFEST" ]]; then
    echo "toolchain run: no corpus at $CORPUS (run tests/toolchain/corpus.sh)" >&2
    exit 1
fi

# nasm searches the current directory before -I, so assemble from a scratch
# directory that holds no coreasm/ of its own.
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

declare -A shared_object
linked=0
failures=()

# link_one <file> <kind> <needs>
link_one() {
    local file="$1" kind="$2" needs="$3"
    local name="${file//\//_}"
    name="${name%.asm}"
    local object="$scratch/$name.o" log="$scratch/$name.log"
    local assemble=(nasm -f elf64)
    [[ $kind == library ]] && assemble+=(-DPIC)
    assemble+=("-I$INCLUDE" -o "$object" "$CORPUS/$file")

    if ! (cd "$scratch" && "${assemble[@]}") >"$log" 2>&1; then
        failures+=("$file (nasm: $(grep -m1 . "$log" || echo 'no message'))")
        return
    fi

    local link
    if [[ $kind == library ]]; then
        # The compiler also passes a version script that narrows .dynsym to
        # the exported functions; it changes which symbols are visible, not
        # whether the object links, so this check leaves it out.
        link=(ld -shared -o "$scratch/lib$name.so" "$object")
    elif [[ $needs == - ]]; then
        link=(ld -o "$scratch/$name" "$object")
    elif [[ -n "${shared_object[$needs]:-}" ]]; then
        local library="${shared_object[$needs]}"
        link=(ld -o "$scratch/$name" "$object" -dynamic-linker "$LOADER"
              -rpath "$scratch" "-L$scratch" "-l:$(basename "$library")")
    else
        failures+=("$file (needs $needs, which did not link)")
        return
    fi

    if ! (cd "$scratch" && "${link[@]}") >>"$log" 2>&1; then
        failures+=("$file (ld: $(grep -m1 . "$log" || echo 'no message'))")
        return
    fi
    [[ $kind == library ]] && shared_object[$file]="$scratch/lib$name.so"
    linked=$((linked + 1))
}

# Libraries first, so a program that needs one finds it already linked.
while IFS=$'\t' read -r file kind source needs; do
    link_one "$file" "$kind" "$needs"
done < <(awk -F'\t' '!/^#/ && NF { print ($2 == "library" ? 0 : 1) "\t" $0 }' "$CORPUS/MANIFEST" \
         | sort -s -t$'\t' -k1,1n | cut -f2-)

total=$((linked + ${#failures[@]}))
if [[ $total -eq 0 ]]; then
    echo "toolchain run: the corpus manifest lists no files" >&2
    exit 1
fi
if [[ ${#failures[@]} -gt 0 ]]; then
    echo "toolchain run: ${#failures[@]} of $total corpus files failed to assemble or link with nasm and ld"
    printf '  %s\n' "${failures[@]}"
    exit 1
fi
echo "toolchain run: all $total corpus files assembled and linked with nasm and ld"
