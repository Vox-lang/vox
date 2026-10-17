#!/bin/bash
#
# The vas refusal tests. Each file in refusals/ uses one NASM construct
# outside the subset vas accepts. vas must refuse it: exit non-zero, write
# no output, and give exactly the messages in the .expected file beside it,
# each naming the construct with its file and line.
#
# The check runs in the Vox repository: the default below is that
# repository's coreasm, which the compiler needs to build the driver.
#
# Usage:
#   bash tests/toolchain/vas/refusal_check.sh
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
    echo "refusal check: there is no Vox compiler at $VOX. Set VOX to it." >&2
    exit 1
fi
CORE="${VOX_CORE_PATH:-$ROOT/coreasm}"
if [[ ! -d "$CORE" ]]; then
    echo "refusal check: there is no coreasm directory at $CORE. Set VOX_CORE_PATH to it; the check runs in the Vox repository." >&2
    exit 1
fi
CORE="$(cd "$CORE" && pwd)"
export VOX_CORE_PATH="$CORE"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

if ! (cd "$scratch" && "$VOX" "$HERE/expand.vox" -o "$scratch/expand") >"$scratch/build.log" 2>&1; then
    echo "refusal check: the vas driver did not build:"
    grep -iv '^warning\|^  ' "$scratch/build.log" | head -20
    exit 1
fi

passed=0
failures=()
cd "$HERE/refusals"
for source in *.asm; do
    name="${source%.asm}"
    if [[ ! -f "$name.expected" ]]; then
        failures+=("$source: no $name.expected beside it")
        continue
    fi
    rm -f "$scratch/output"
    "$scratch/expand" "$source" "$CORE" "$scratch/output" 2>"$scratch/messages"
    status=$?
    if [[ $status -eq 0 ]]; then
        failures+=("$source: vas accepted it")
    elif [[ -e "$scratch/output" ]]; then
        failures+=("$source: vas refused it but wrote the output anyway")
    elif ! diff -u "$name.expected" "$scratch/messages" >"$scratch/difference"; then
        failures+=("$source: the messages differ: $(grep -m1 '^+[^+]' "$scratch/difference" || echo 'see the .expected file')")
    else
        passed=$((passed + 1))
    fi
done

if [[ ${#failures[@]} -gt 0 ]]; then
    echo "refusal check: $passed passed, ${#failures[@]} failed:"
    printf '  %s\n' "${failures[@]}"
    exit 1
fi
echo "refusal check: all $passed refused constructs give their expected messages"
