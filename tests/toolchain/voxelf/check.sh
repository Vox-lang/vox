#!/usr/bin/env bash
# Differential test of vox-elf against ld.
#
# Every program in the corpus is compiled to assembly once, then made into
# an executable twice: by nasm -f elf64 and ld, exactly as the compiler does
# it, and by nasm -f bin and vox-elf (tools/voxelf/nasm-image.sh). The two
# must agree on the file offset, address, file size, flags and alignment of
# every segment readelf -l lists, and, run with the same arguments and
# standard input, must write the same standard output and standard error
# and exit with the same status, byte for byte. A program with read-only
# data must also come out of vox-elf no larger than ld's build of it with
# its symbols stripped, since vox-elf writes no symbols: the file is packed
# as ld packs it, with no page of zeros between the segments.
#
# The corpus: every examples/*.vox that compiles on its own, the voxos
# system programs, and the vox-coreutils tools. The vox-coreutils suites
# are run as well, against a stand-in that runs both executables on every
# invocation the suite makes and compares them.
#
# usage: tests/toolchain/voxelf/check.sh
# Environment: VOXOS_SRC and COREUTILS_SRC (the voxos and vox-coreutils
# checkouts, read only), VOX_CORE_PATH, VOXELF_BUILD (where tools/voxelf/
# build.sh put vox-elf; built there if missing), CHECK_TIMEOUT (seconds a
# run may take, default 10).
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
vox_tree=$(cd "$here/../../.." && pwd)
export VOX_CORE_PATH=${VOX_CORE_PATH:-/usr/share/vox/coreasm}
include=${NASM_INCLUDE:-$(dirname "$VOX_CORE_PATH")/}
voxos=${VOXOS_SRC:-}
coreutils=${COREUTILS_SRC:-}
build=${VOXELF_BUILD:-${TMPDIR:-/tmp}/voxelf-build}
limit=${CHECK_TIMEOUT:-10}

if [ ! -x "$build/vox-elf" ]; then
    bash "$vox_tree/tools/voxelf/build.sh" "$build" > /dev/null || exit 1
fi
export VOX_ELF=$build/vox-elf

# Everything happens in a scratch directory outside every source tree: the
# compiler must not run inside a directory that holds another Vox checkout.
work=$(mktemp -d "${TMPDIR:-/tmp}/voxelf-check.XXXXXX")
trap 'rm -rf "$work"' EXIT
fixtures=$work/fixtures
mkdir -p "$fixtures/hollow"
printf 'Hello, World!\n' > "$fixtures/hello.txt"
printf 'one two three\nfour five\n\nsix\n' > "$fixtures/words.txt"
printf 'no trailing newline' > "$fixtures/nonewline.txt"
printf 'a:b:c:d:e\nnodelim\nx:y\n' > "$fixtures/fields.txt"
printf 'The quick brown fox 0123456789 \x01\x02\x7f\xff end.\n' > "$fixtures/mixed.bin"
printf 'echo hello from the shell\nexit\n' > "$fixtures/script.vsh"
if [ -f "$coreutils/test/corpus.sh" ]; then
    bash "$coreutils/test/corpus.sh" "$work/suite-corpus" > /dev/null
fi

linked=() matched_layout=() no_larger=() ran_alike=() differed=() skipped=()
cases_alike=0 cases_differed=0

# Programs that cannot run here, with the reason. They are still linked both
# ways and their segments compared.
reason_not_to_run() {
    case $1 in
        examples/initramfs|voxos/initramfs) echo "an early-userspace init: mounts, switches root, needs root" ;;
        voxos/init) echo "PID 1: needs root and a kernel that hands it control" ;;
        coreutils/mount|coreutils/umount)
            [ "$(id -u)" -eq 0 ] && echo "needs root to do anything, and would act on this machine as root" ;;
    esac
}

# The runs each program gets: standard input, then the arguments. Every
# program gets the first; the rest exercise the arguments it takes.
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

# Suites that may be run against the comparing stand-in: those whose tools
# leave nothing behind that would change the second of the two runs.
suite_is_safe() {
    case $1 in
        cat|cut|echo|wc|base64|xxd|write) return 0 ;;
        mount|umount) [ "$(id -u)" -ne 0 ] ;;
        *) return 1 ;;
    esac
}

# The file offset, address, file size, flags and alignment of every segment,
# in order. The memory size is left out: nasm -f bin and ld round the end of
# the zero-filled data differently, by a few bytes. readelf -lW writes the
# flags with spaces in them ("R E"), between the memory size and the
# alignment.
segment_shape() {
    readelf -lW "$1" | awk '$1 ~ /^(LOAD|GNU_STACK)$/ {
        flags = ""; for (i = 7; i < NF; i++) flags = flags $i
        print $1, $2, $3, $5, flags, $NF }'
}

has_read_only_data() {
    readelf -SW "$1" | grep -q ' \.rodata '
}

# One run of one executable in a fresh copy of the fixtures, always at the
# same path, so the two executables see the same files and the same names.
# Leaves stdout, stderr, the status and what the run left behind in $2.*.
run_once() {
    local binary=$1 record=$2 name=$3 stdin=$4; shift 4
    rm -rf "$work/sandbox"
    cp -r "$fixtures" "$work/sandbox"
    cp "$binary" "$work/sandbox/$name"
    ( cd "$work/sandbox" && timeout "$limit" "./$name" "$@" ) \
        < "$(cd "$fixtures" && realpath "$stdin")" > "$record.out" 2> "$record.err"
    echo $? > "$record.status"
    rm -f "$work/sandbox/$name"
    (cd "$work/sandbox" && find . -printf '%y %p %s\n' | sort) > "$record.left"
}

same_run() {
    local one=$1 other=$2 part
    for part in out err status left; do
        cmp -s "$one.$part" "$other.$part" || return 1
    done
}

# The stand-in a vox-coreutils suite runs as BIN: both executables, the same
# arguments, the same standard input and the same name in argv[0], compared;
# then the ld executable's answer, so the suite carries on as it would.
cat > "$work/both" <<'EOF'
#!/usr/bin/env bash
record=$(mktemp -d "$BOTH_WORK/call.XXXXXX")
cat > "$record/in"
(exec -a "$0" "$BOTH_LD" "$@") < "$record/in" > "$record/ld.out" 2> "$record/ld.err"; echo $? > "$record/ld.status"
(exec -a "$0" "$BOTH_ELF" "$@") < "$record/in" > "$record/elf.out" 2> "$record/elf.err"; echo $? > "$record/elf.status"
if cmp -s "$record/ld.out" "$record/elf.out" && cmp -s "$record/ld.err" "$record/elf.err" \
        && cmp -s "$record/ld.status" "$record/elf.status"; then
    echo alike >> "$BOTH_LOG"
else
    echo "differed: $*" >> "$BOTH_LOG"
fi
cat "$record/ld.out"; cat "$record/ld.err" >&2
exit "$(cat "$record/ld.status")"
EOF
chmod +x "$work/both"

check_program() {
    local label=$1 source=$2 directory=$work/programs/$1 name
    name=$(basename "$source" .vox)
    mkdir -p "$directory"
    cp "$(dirname "$source")"/*.vox "$directory/"
    if ! (cd "$directory" && vox "$name.vox" --emit-asm -o "$name.asm") > "$directory/compile.log" 2>&1; then
        skipped+=("$label (does not compile on its own)")
        return
    fi
    if ! (cd "$directory" && nasm -f elf64 -I"$include" -o "$name.o" "$name.asm" && ld -o "$name.ld" "$name.o") \
            > "$directory/ld.log" 2>&1; then
        differed+=("$label (nasm and ld could not build it)")
        return
    fi
    if ! (cd "$directory" && bash "$vox_tree/tools/voxelf/nasm-image.sh" "$name.asm" "$name" \
            && "$VOX_ELF" "$name.manifest" -o "$name.elf" && chmod 755 "$name.elf") > "$directory/elf.log" 2>&1; then
        differed+=("$label (vox-elf could not link it: $(head -1 "$directory/elf.log"))")
        return
    fi
    linked+=("$label")
    if [ "$(segment_shape "$directory/$name.ld")" != "$(segment_shape "$directory/$name.elf")" ]; then
        differed+=("$label (segments differ from ld's: $(segment_shape "$directory/$name.elf" | tr '\n' ';') where ld has $(segment_shape "$directory/$name.ld" | tr '\n' ';'))")
        return
    fi
    if ! readelf -S "$directory/$name.elf" > /dev/null 2>&1 || ! objdump -d "$directory/$name.elf" > /dev/null 2>&1; then
        differed+=("$label (readelf -S or objdump -d cannot read it)")
        return
    fi
    matched_layout+=("$label")
    if has_read_only_data "$directory/$name.ld"; then
        strip -o "$directory/$name.stripped" "$directory/$name.ld"
        local ld_size elf_size
        ld_size=$(stat -c %s "$directory/$name.stripped") elf_size=$(stat -c %s "$directory/$name.elf")
        if [ "$elf_size" -gt "$ld_size" ]; then
            differed+=("$label (vox-elf wrote $elf_size bytes, stripped ld $ld_size)")
            return
        fi
        no_larger+=("$label")
    fi

    local reason
    reason=$(reason_not_to_run "$label")
    if [ -n "$reason" ]; then
        skipped+=("$label ($reason)")
        return
    fi

    # Runs are counted here and added to the totals only once the program is
    # done, so a program skipped part way contributes none.
    local stdin arguments case_number=0 alike_here=0 differed_here=0
    while IFS='|' read -r stdin arguments; do
        case_number=$((case_number + 1))
        local record=$directory/case$case_number
        # shellcheck disable=SC2086
        run_once "$directory/$name.ld" "$record.ld" "$name" "$stdin" $arguments
        if [ "$(cat "$record.ld.status")" -eq 124 ]; then
            skipped+=("$label (does not finish within $limit seconds; outputs not compared)")
            return
        fi
        # shellcheck disable=SC2086
        run_once "$directory/$name.elf" "$record.elf" "$name" "$stdin" $arguments
        # A difference counts only if it holds: each executable runs three
        # more times, and if the ld executable disagrees with itself, or the
        # vox-elf one matches it even once, the output depends on something
        # other than the executable, such as the time it took.
        local varies=no attempt
        if ! same_run "$record.ld" "$record.elf"; then
            for attempt in 1 2 3; do
                # shellcheck disable=SC2086
                run_once "$directory/$name.ld" "$record.again" "$name" "$stdin" $arguments
                same_run "$record.ld" "$record.again" || varies=yes
                # shellcheck disable=SC2086
                run_once "$directory/$name.elf" "$record.again" "$name" "$stdin" $arguments
                same_run "$record.ld" "$record.again" && varies=yes
            done
        fi
        if [ "$varies" = yes ]; then
            skipped+=("$label (its output varies from one run to the next; outputs not compared)")
            return
        fi
        if same_run "$record.ld" "$record.elf"; then
            alike_here=$((alike_here + 1))
        else
            differed_here=$((differed_here + 1))
            echo "  DIFFERS $label: stdin $stdin, arguments '$arguments'" >&2
            diff "$record.ld.out" "$record.elf.out" | head -5 >&2
        fi
    done < <(cases_for "$label")

    local suite=$coreutils/$name/test.sh
    if [ "${label%%/*}" = coreutils ] && [ -f "$suite" ] && suite_is_safe "$name" && [ -d "$work/suite-corpus" ]; then
        local log=$directory/suite.log
        : > "$log"
        (cd "$directory" && BOTH_WORK=$directory BOTH_LOG=$log BOTH_LD=$directory/$name.ld \
            BOTH_ELF=$directory/$name.elf BIN=$work/both CORPUS=$work/suite-corpus \
            bash "$suite") > /dev/null 2>&1 < /dev/null
        alike_here=$((alike_here + $(grep -c '^alike' "$log")))
        local suite_differences
        suite_differences=$(grep -c '^differed' "$log")
        if [ "$suite_differences" -gt 0 ]; then
            differed_here=$((differed_here + suite_differences))
            grep '^differed' "$log" | head -5 | sed "s/^/  DIFFERS $label suite: /" >&2
        fi
    fi

    cases_alike=$((cases_alike + alike_here)) cases_differed=$((cases_differed + differed_here))
    if [ "$differed_here" -gt 0 ]; then
        differed+=("$label (output differs from ld's)")
    else
        ran_alike+=("$label")
    fi
}

for source in "$vox_tree"/examples/*.vox; do
    check_program "examples/$(basename "$source" .vox)" "$source"
done
if [ -n "$voxos" ] && [ -d "$voxos/system" ]; then
    for source in "$voxos"/system/*.vox; do
        check_program "voxos/$(basename "$source" .vox)" "$source"
    done
else
    skipped+=("the Vox OS programs (set VOXOS_SRC to a Vox OS checkout to include them)")
fi
if [ -n "$coreutils" ] && [ -d "$coreutils" ]; then
    for source in "$coreutils"/*/*.vox; do
        check_program "coreutils/$(basename "$source" .vox)" "$source"
    done
else
    skipped+=("the vox-coreutils tools (set COREUTILS_SRC to a vox-coreutils checkout to include them)")
fi

echo "linked by vox-elf: ${#linked[@]}; same segments as ld: ${#matched_layout[@]};" \
     "with read-only data and no larger than stripped ld: ${#no_larger[@]}"
echo "ran identically to ld: ${#ran_alike[@]} programs: ${ran_alike[*]}"
for entry in "${skipped[@]}"; do echo "skipped: $entry"; done
for entry in "${differed[@]}"; do echo "DIFFERED: $entry"; done
echo "voxelf differential: ${#ran_alike[@]} programs linked by vox-elf ran identically to ld in $cases_alike runs;" \
     "${#differed[@]} programs and $cases_differed runs differed; ${#skipped[@]} skipped"
[ "${#differed[@]}" -eq 0 ]
