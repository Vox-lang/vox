#!/bin/bash
#
# The vas assembly check: what the passes themselves refuse, and one
# program built from the constructs they handle that the corpus programs
# do not all use.
#
# Each file in assembly/refusals/ is a program vas must refuse in pass one,
# pass two or the writing: exit non-zero, write no executable, and give
# exactly the messages in the .expected file beside it, each naming the
# file and the line.
#
# assembly/features.asm must assemble, give the bytes nasm gives it when
# its jumps are written near and ld links it at the addresses vas chose,
# and run as the executable nasm and ld make of it runs, exiting with 0,
# which it does only when every double it holds has the bits nasm gives
# it.
#
# Usage:
#   bash tests/toolchain/vas/assembly_check.sh
#
# Environment:
#   VOX            the compiler (default: vox on PATH)
#   VOX_CORE_PATH  the coreasm directory (default: the repository's coreasm)
#
# Prints one summary line, after a line for each failure if there are any,
# and exits non-zero on any failure.

set -uo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
VOX="${VOX:-vox}"

if ! command -v "$VOX" >/dev/null; then
    echo "assembly check: there is no Vox compiler at $VOX. Set VOX to it." >&2
    exit 1
fi
CORE="${VOX_CORE_PATH:-$ROOT/coreasm}"
if [[ ! -d "$CORE" ]]; then
    echo "assembly check: there is no coreasm directory at $CORE. Set VOX_CORE_PATH to it; the check runs in the Vox repository." >&2
    exit 1
fi
CORE="$(cd "$CORE" && pwd)"
export VOX_CORE_PATH="$CORE"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

if ! bash "$ROOT/tools/vas/build.sh" "$scratch/build" >"$scratch/build.log" 2>&1; then
    echo "assembly check: vas did not build:"
    grep -iv '^warning\|^  ' "$scratch/build.log" | head -20
    exit 1
fi
VAS="$scratch/build/vas"

passed=0
failures=()

cd "$HERE/assembly/refusals"
for source in *.asm; do
    name="${source%.asm}"
    if [[ ! -f "$name.expected" ]]; then
        failures+=("$source: no $name.expected beside it")
        continue
    fi
    rm -f "$scratch/output"
    timeout 600 "$VAS" "$source" -c "$CORE" -o "$scratch/output" 2>"$scratch/messages"
    status=$?
    if [[ $status -eq 0 ]]; then
        failures+=("$source: vas accepted it")
    elif [[ -e "$scratch/output" ]]; then
        failures+=("$source: vas refused it but wrote the executable anyway")
    elif ! diff -u "$name.expected" "$scratch/messages" >"$scratch/difference"; then
        failures+=("$source: the messages differ: $(grep -m1 '^+[^+]' "$scratch/difference" || echo 'see the .expected file')")
    else
        passed=$((passed + 1))
    fi
done

# The features program. Every section is pinned for ld to the address vas
# gave it, and nasm is given the source with each jump written near, so
# the two must agree byte for byte.
features="$HERE/assembly/features.asm"
cd "$scratch"
if ! timeout 600 "$VAS" "$features" -c "$CORE" -o features.vas 2>features.log; then
    failures+=("features.asm: vas refused it: $(head -1 features.log)")
else
    chmod 755 features.vas
    sed -E 's/^([[:space:]]*([A-Za-z0-9_.@$]+:[[:space:]]*)?)(j[a-z]{1,3})[[:space:]]+/\1\3 near /' \
        "$features" > near.asm
    {
        echo "SECTIONS {"
        readelf -SW features.vas | sed -E 's/^ *\[ *[0-9]+\] //' \
            | awk '$1 ~ /^\.(text|rodata|data|bss)$/ { printf "  %s 0x%s : { *(%s) }\n", $1, $3, $1 }'
        echo "}"
    } > near.ld
    nasm -f elf64 -o near.o near.asm && ld -o features.near -T near.ld near.o 2>near.log
    nasm -f elf64 -o features.o "$features" && ld -o features.ld features.o
    for section in .text .rodata .data; do
        objcopy -O binary --only-section=$section features.vas vas$section
        objcopy -O binary --only-section=$section features.near near$section
        if ! cmp -s vas$section near$section; then
            failures+=("features.asm: its $section differs from nasm's with every jump near")
        fi
    done
    ./features.vas > vas.out 2>&1
    echo $? > vas.status
    ./features.ld > ld.out 2>&1
    echo $? > ld.status
    if [[ "$(cat vas.status)" != 0 ]]; then
        failures+=("features.asm: the vas executable exited with $(cat vas.status), where 0 means every double holds nasm's bits")
    elif ! cmp -s vas.out ld.out || ! cmp -s vas.status ld.status; then
        failures+=("features.asm: the vas executable runs differently from nasm and ld's")
    else
        passed=$((passed + 1))
    fi
fi

if [[ ${#failures[@]} -gt 0 ]]; then
    echo "assembly check: $passed passed, ${#failures[@]} failed:"
    printf '  %s\n' "${failures[@]}"
    exit 1
fi
echo "assembly check: all $passed checks passed: every refusal gives its expected messages, and the features program matches nasm"
