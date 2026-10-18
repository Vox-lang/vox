#!/bin/bash
#
# The vas whole-program check. Every program in the corpus MANIFEST is
# assembled by vas into an executable, linking nothing else, and compared
# with the executable nasm and ld make of it, by the recipe run.sh uses.
# Libraries are shared builds, which vas refuses, so they are left out; so
# is a program that refused_corpus_files.tsv says vas refuses whole, which
# must be refused with the message listed there.
#
# A program counts as identical when the .text and .data bytes of the two
# executables are the same (objcopy -O binary --only-section). nasm encodes
# a jump to a target in reach as rel8, and vas every jump as rel32, so most
# programs differ. For one that does:
#
#   - nasm assembles it again with every jump written near, and ld links
#     that at the addresses vas gave each section: its .text, .rodata and
#     .data must then be vas's byte for byte, which shows the difference is
#     the width of the jumps and nothing else;
#   - both executables run with the same arguments and standard input, the
#     runs tests/toolchain/voxelf/check.sh gives each program, and must
#     write the same standard output and standard error, exit with the same
#     status and leave the same files behind.
#
# Such a program counts as running the same. A program that cannot be run
# here (it needs root, or is PID 1), does not finish, or whose output
# varies from run to run, is listed as not run, with its reason; its bytes
# are still compared with the near-jump build. Anything else fails.
#
# The check runs in the Vox repository, with its assembly corpus present:
# the defaults below are that repository's paths.
#
# Usage:
#   bash tests/toolchain/vas/program_check.sh
#
# Environment:
#   VOX            the compiler (default: vox on PATH)
#   VOX_CORE_PATH  the coreasm directory (default: the repository's coreasm)
#   VAS_CORPUS     the corpus directory, holding MANIFEST (default: the
#                  repository's tests/corpus)
#   VAS_MEMORY_CAP the most memory one vas run or one program run may use,
#                  enforced with systemd-run where a user session has it
#                  (default: 4G)
#   CHECK_TIMEOUT  seconds one program run may take (default: 10); a vas
#                  run may take 600
#
# Prints the time and peak memory of every vas run, then the three counts
# and the programs in each, and exits non-zero if any program failed.

set -uo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
VOX="${VOX:-vox}"
LIMIT="${CHECK_TIMEOUT:-10}"
MEMORY_CAP="${VAS_MEMORY_CAP:-4G}"

# A missing path is named with the variable that sets it, since a checkout
# without the corpus is the usual reason.
the_directory() {
    if [[ ! -d "$1" ]]; then
        echo "program check: there is no $3 at $1. Set $2 to it; the check runs in the Vox repository, with the corpus present." >&2
        return 1
    fi
    (cd "$1" && pwd)
}
if ! command -v "$VOX" >/dev/null; then
    echo "program check: there is no Vox compiler at $VOX. Set VOX to it." >&2
    exit 1
fi
CORE="$(the_directory "${VOX_CORE_PATH:-$ROOT/coreasm}" VOX_CORE_PATH "coreasm directory")" || exit 1
CORPUS="$(the_directory "${VAS_CORPUS:-$ROOT/tests/corpus}" VAS_CORPUS "corpus directory")" || exit 1
export VOX_CORE_PATH="$CORE"
INCLUDE="$(cd "$CORE/.." && pwd)/"

declare -A EXPECTED_REFUSALS=()
while IFS=$'\t' read -r file message; do
    [[ -z "$file" || "$file" == \#* ]] && continue
    EXPECTED_REFUSALS[$file]="$message"
done < "$HERE/refused_corpus_files.tsv"

# nasm and the compiler both search the current directory first, so
# everything runs from a scratch directory.
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# Every run of vas and of a program it built is held to a memory cap and a
# time limit: the Vox runtime keeps every allocation until the program
# ends, so an assembly that goes wrong can grow without bound.
if systemd-run --user --scope -q -p MemoryMax="$MEMORY_CAP" -- true >/dev/null 2>&1; then
    capped() { local seconds=$1; shift; systemd-run --user --scope -q -p MemoryMax="$MEMORY_CAP" -- timeout "$seconds" "$@"; }
else
    echo "program check: systemd-run has no user session here, so runs are held to time limits only" >&2
    capped() { local seconds=$1; shift; timeout "$seconds" "$@"; }
fi

if ! bash "$ROOT/tools/vas/build.sh" "$scratch/build" >"$scratch/build.log" 2>&1; then
    echo "program check: vas did not build:"
    grep -iv '^warning\|^  ' "$scratch/build.log" | head -20
    exit 1
fi
VAS="$scratch/build/vas"

fixtures="$scratch/fixtures"
mkdir -p "$fixtures/hollow"
printf 'Hello, World!\n' > "$fixtures/hello.txt"
printf 'one two three\nfour five\n\nsix\n' > "$fixtures/words.txt"
printf 'no trailing newline' > "$fixtures/nonewline.txt"
printf 'a:b:c:d:e\nnodelim\nx:y\n' > "$fixtures/fields.txt"
printf 'The quick brown fox 0123456789 \x01\x02\x7f\xff end.\n' > "$fixtures/mixed.bin"
printf 'echo hello from the shell\nexit\n' > "$fixtures/script.vsh"

# Programs that cannot run here, with the reason, as voxelf/check.sh has
# them.
reason_not_to_run() {
    case $1 in
        examples/initramfs|voxos/initramfs) echo "an early-userspace init: mounts, switches root, needs root" ;;
        voxos/init) echo "PID 1: needs root and a kernel that hands it control" ;;
        coreutils/mount|coreutils/umount)
            [ "$(id -u)" -eq 0 ] && echo "needs root to do anything, and would act on this machine as root" ;;
    esac
}

# The runs each program gets, as voxelf/check.sh gives them: standard input,
# then the arguments.
cases_for() {
    echo "words.txt|"
    case $1 in
        examples/args_and_env) echo "/dev/null|alpha beta gamma" ;;
        examples/cat|coreutils/cat) echo "/dev/null|-n words.txt hello.txt"; echo "/dev/null|missing.txt" ;;
        examples/greet) echo "/dev/null|Ada" ;;
        examples/sh|voxos/sh) echo "script.vsh|" ;;
        coreutils/echo) echo "/dev/null|hello world"; echo "/dev/null|--help" ;;
        coreutils/wc) echo "/dev/null|words.txt hello.txt"; echo "/dev/null|-l words.txt" ;;
        coreutils/cut) echo "/dev/null|-d : -f 2 fields.txt"; echo "/dev/null|-b 1-3 words.txt" ;;
        coreutils/base64) echo "/dev/null|mixed.bin"; echo "/dev/null|--help" ;;
        coreutils/xxd) echo "/dev/null|mixed.bin"; echo "/dev/null|-p words.txt" ;;
        coreutils/mkdir) echo "/dev/null|fresh"; echo "/dev/null|hollow" ;;
        coreutils/rmdir) echo "/dev/null|hollow"; echo "/dev/null|words.txt" ;;
        coreutils/rm) echo "/dev/null|hello.txt"; echo "/dev/null|missing.txt" ;;
        coreutils/write) echo "words.txt|-o saved.txt" ;;
    esac
}

# One run of one executable in a fresh copy of the fixtures, always at the
# same path, so the two executables see the same files and the same names.
# Leaves standard output and error, the status and what the run left behind
# in $2.*.
run_once() {
    local binary=$1 record=$2 name=$3 stdin=$4; shift 4
    rm -rf "$scratch/sandbox"
    cp -r "$fixtures" "$scratch/sandbox"
    cp "$binary" "$scratch/sandbox/$name"
    ( cd "$scratch/sandbox" && capped "$LIMIT" "./$name" "$@" ) \
        < "$(cd "$fixtures" && realpath "$stdin")" > "$record.out" 2> "$record.err"
    echo $? > "$record.status"
    rm -f "$scratch/sandbox/$name"
    (cd "$scratch/sandbox" && find . -printf '%y %p %s\n' | sort) > "$record.left"
}

same_run() {
    local one=$1 other=$2 part
    for part in out err status left; do
        cmp -s "$one.$part" "$other.$part" || return 1
    done
}

# The sections of an executable, as name and address, from readelf.
sections_of() {
    readelf -SW "$1" | sed -E 's/^ *\[ *[0-9]+\] //' \
        | awk '$1 ~ /^\.(text|rodata|data|bss)$/ { print $1, $3 }'
}

# Do two executables hold the same bytes in each named section?
same_sections() {
    local one=$1 other=$2 section
    shift 2
    for section in "$@"; do
        objcopy -O binary --only-section="$section" "$one" "$one$section" 2>/dev/null
        objcopy -O binary --only-section="$section" "$other" "$other$section" 2>/dev/null
        cmp -s "$one$section" "$other$section" || return 1
    done
}

# nasm's build of the program with every jump written near, linked by ld at
# the addresses vas gave each section. The jumps are found in nasm's own
# expansion, where each is a line of its own, after any label.
near_jump_build() {
    local source=$1 vas_build=$2 output=$3 work=$4
    (cd "$work" && nasm -E -f elf64 "-I$INCLUDE" "$source") > "$work/expanded.asm" 2> "$work/near.log" || return 1
    sed -E 's/^([[:space:]]*([A-Za-z0-9_.@$]+:[[:space:]]*)?)(j[a-z]{1,3})[[:space:]]+/\1\3 near /' \
        "$work/expanded.asm" > "$work/near.asm"
    {
        echo "SECTIONS {"
        sections_of "$vas_build" | awk '{ printf "  %s 0x%s : { *(%s) }\n", $1, $2, $1 }'
        echo "}"
    } > "$work/near.ld"
    (cd "$work" && nasm -f elf64 -o near.o near.asm && ld -o "$output" -T near.ld near.o) >> "$work/near.log" 2>&1
}

identical=() ran_the_same=() not_run=() failed=() refused=()
: > "$scratch/costs"

check_program() {
    local file=$1
    local label=${file%.asm}
    local name="${label//\//_}"
    local work="$scratch/$name"
    mkdir -p "$work"

    (cd "$work" && capped 600 /usr/bin/time -f "%e %M" -o "$work/cost" "$VAS" "$CORPUS/$file" -o "$name.vas") \
        > "$work/vas.log" 2>&1
    local status=$?
    if [[ -f "$work/cost" ]] && [[ "$(wc -l < "$work/cost")" -ge 1 ]]; then
        local seconds kilobytes
        read -r seconds kilobytes < <(tail -1 "$work/cost")
        printf '%s\t%s\t%s\n' "$kilobytes" "$seconds" "$label" >> "$scratch/costs"
    fi

    local expected="${EXPECTED_REFUSALS[$file]:-}"
    if [[ -n "$expected" ]]; then
        if [[ $status -ne 0 && ! -e "$work/$name.vas" ]] && grep -qF "$expected" "$work/vas.log"; then
            refused+=("$label")
        else
            failed+=("$label (expected a refusal saying \"$expected\", got exit $status: $(head -1 "$work/vas.log"))")
        fi
        return
    fi
    if [[ $status -ne 0 || ! -f "$work/$name.vas" ]]; then
        failed+=("$label (vas failed with status $status: $(grep -v '^Command exited' "$work/vas.log" | head -1))")
        return
    fi
    chmod 755 "$work/$name.vas"

    (cd "$work" && nasm -f elf64 "-I$INCLUDE" -o "$name.o" "$CORPUS/$file" && ld -o "$name.ld" "$name.o") \
        > "$work/ld.log" 2>&1 || { failed+=("$label (nasm and ld could not build it)"); return; }

    if same_sections "$work/$name.ld" "$work/$name.vas" .text .data; then
        identical+=("$label")
        return
    fi

    if ! near_jump_build "$CORPUS/$file" "$work/$name.vas" "$work/$name.near" "$work"; then
        failed+=("$label (the near-jump build failed: $(grep -m1 . "$work/near.log"))")
        return
    fi
    if ! same_sections "$work/$name.near" "$work/$name.vas" .text .rodata .data; then
        failed+=("$label (its bytes differ from nasm's with every jump near, so more than jump widths differ)")
        return
    fi

    local reason
    reason=$(reason_not_to_run "$label")
    if [[ -n "$reason" ]]; then
        not_run+=("$label ($reason)")
        return
    fi

    local stdin arguments case_number=0 differed_here=0
    while IFS='|' read -r stdin arguments; do
        case_number=$((case_number + 1))
        local record="$work/case$case_number"
        # shellcheck disable=SC2086
        run_once "$work/$name.ld" "$record.ld" "$name" "$stdin" $arguments
        if [[ "$(cat "$record.ld.status")" -eq 124 ]]; then
            not_run+=("$label (does not finish within $LIMIT seconds; outputs not compared)")
            return
        fi
        # shellcheck disable=SC2086
        run_once "$work/$name.vas" "$record.vas" "$name" "$stdin" $arguments
        # A difference counts only if it holds: each executable runs three
        # more times, and if the nasm one disagrees with itself, or the vas
        # one matches it even once, the output depends on something other
        # than the executable, such as the time.
        local varies=no attempt
        if ! same_run "$record.ld" "$record.vas"; then
            for attempt in 1 2 3; do
                # shellcheck disable=SC2086
                run_once "$work/$name.ld" "$record.again" "$name" "$stdin" $arguments
                same_run "$record.ld" "$record.again" || varies=yes
                # shellcheck disable=SC2086
                run_once "$work/$name.vas" "$record.again" "$name" "$stdin" $arguments
                same_run "$record.ld" "$record.again" && varies=yes
            done
        fi
        if [[ $varies == yes ]]; then
            not_run+=("$label (its output varies from one run to the next; outputs not compared)")
            return
        fi
        if ! same_run "$record.ld" "$record.vas"; then
            differed_here=$((differed_here + 1))
            echo "  DIFFERS $label: stdin $stdin, arguments '$arguments'" >&2
            diff "$record.ld.out" "$record.vas.out" | head -5 >&2
        fi
    done < <(cases_for "$label")
    if [[ $differed_here -gt 0 ]]; then
        failed+=("$label (it runs differently from nasm and ld's executable in $differed_here of $case_number runs)")
    else
        ran_the_same+=("$label")
    fi
}

while IFS=$'\t' read -r file kind _; do
    [[ -z "$file" || "$file" == \#* || $kind != program ]] && continue
    check_program "$file"
done < "$CORPUS/MANIFEST"

echo "vas runs, by peak memory (KB, seconds, program):"
sort -rn "$scratch/costs" | sed 's/^/  /'
for entry in "${refused[@]}"; do echo "refused as expected: $entry"; done
echo "identical: ${#identical[@]}"
for entry in "${identical[@]}"; do echo "  $entry"; done
echo "runs the same: ${#ran_the_same[@]} (bytes differ from nasm and ld's in jump widths only)"
for entry in "${ran_the_same[@]}"; do echo "  $entry"; done
echo "not run: ${#not_run[@]} (bytes differ in jump widths only)"
for entry in "${not_run[@]}"; do echo "  $entry"; done
echo "failed: ${#failed[@]}"
for entry in "${failed[@]}"; do echo "  $entry"; done
echo "program check: ${#identical[@]} identical, ${#ran_the_same[@]} run the same, ${#failed[@]} failed;" \
     "${#not_run[@]} not run, ${#refused[@]} refused as expected"
[[ ${#failed[@]} -eq 0 ]]
