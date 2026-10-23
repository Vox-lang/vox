#!/usr/bin/env bash
# Differential test of vox-elf against ld.
#
# Every program in the corpus is compiled to assembly once, then made into
# an executable twice: by nasm -f elf64 and ld, exactly as the compiler does
# it, and by nasm -f bin and vox-elf (tools/voxelf/nasm-image.sh). The
# reference is ld's output and nothing else: a program that nasm or ld
# refuses to build fails the check, with what it said. The two
# must be the same, byte for byte, in everything the loader reads
# (same-bytes.sh): the ELF header, every program header, and every byte of
# every loadable segment. Only what the loader never reads may differ: the
# section headers, the section names and ld's symbol table. A program with
# read-only data must also come out of vox-elf no larger than ld's build of
# it with its symbols stripped.
#
# Then both are run, once each, with the same arguments and standard input,
# and must write the same standard output and standard error, exit with the
# same status and leave the same files behind. A run that does not finish
# within the time limit is a failure. A program that cannot be run here is
# still linked and compared byte for byte, and is listed with the reason it
# is not run.
#
# The corpus: every examples/*.vox, the Vox OS system programs, and the
# vox-coreutils tools. A program that sees a library's .lib has that library
# built beside it first, from the source in its directory that declares it.
# The vox-coreutils suites are run as well, against a stand-in that runs
# both executables on every invocation the suite makes and compares them.
#
# What voxelf supports is decided by measurement, not by a list of names: a
# program whose ld build has a PT_INTERP or a PT_DYNAMIC program header needs
# dynamic linking, which voxelf does not do yet (ROADMAP.md, Milestone 8,
# Shared-library output). Such a
# program is reported as not supported yet when voxelf refuses it; when
# voxelf links it, it is compared like any other program, and must pass.
#
# Nothing is left out quietly. A program that is left out for any reason, a
# missing checkout or a program that does not compile, fails the check, with
# the reason.
#
# vox-elf and nasm-image.sh run under the trace in ld-trace.sh, which sees
# every program they start, so the count of ld pass-throughs, the times
# voxelf's side started ld, is measured, not assumed: it must be 0.
#
# The check passes when every static program passes, nothing is left out,
# and the count of ld pass-throughs is 0.
#
# usage: tests/toolchain/voxelf/check.sh
# Environment: VOXOS_SRC and COREUTILS_SRC (the Vox OS and vox-coreutils
# checkouts, read only; the check fails without them), VOX_CORE_PATH,
# VOXELF_BUILD (where tools/voxelf/build.sh put vox-elf; built there if
# missing), CHECK_TIMEOUT (seconds a run may take, default 10).
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

linked=() same_bytes=() no_larger=() ran_alike=() differed=() not_run=() left_out=() not_supported=()
cases_alike=0 cases_differed=0 reference_links=0 static_programs=0 static_same_bytes=0

if [ -n "$coreutils" ] && [ -f "$coreutils/test/corpus.sh" ]; then
    bash "$coreutils/test/corpus.sh" "$work/suite-corpus" > /dev/null \
        || left_out+=("the vox-coreutils suites (test/corpus.sh in $coreutils could not build their corpus)")
elif [ -n "$coreutils" ]; then
    left_out+=("the vox-coreutils suites ($coreutils has no test/corpus.sh to build their corpus from)")
fi

source "$here/ld-trace.sh"

# Programs that are not run here, with the reason. Their bytes are still
# compared with ld's, which is what decides how a program runs.
reason_not_to_run() {
    case $1 in
        examples/initramfs|voxos/initramfs) echo "an early-userspace init: it mounts filesystems and switches root, which needs root" ;;
        voxos/init) echo "it is PID 1: it needs root and a kernel that hands it control" ;;
        examples/time) echo "it prints the time it is run, so two runs differ whatever links them" ;;
        examples/life) echo "it prints how many milliseconds it took, so two runs differ whatever links them" ;;
        coreutils/mount|coreutils/umount)
            [ "$(id -u)" -eq 0 ] && echo "run as root, it would act on this machine's mounts" ;;
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

has_read_only_data() {
    readelf -SW "$1" | grep -q ' \.rodata '
}

# Measured on ld's build: an interpreter or a dynamic section is what a
# dynamically linked program carries, and a static one never does.
needs_dynamic_linking() {
    readelf -lW "$1" | grep -qE '^ +(INTERP|DYNAMIC) '
}

# Builds each library a program sees through a .lib, from the source in the
# program's directory whose Library line names it, so the program compiles
# as its author compiles it. A library with no source there is not built,
# and the program then does not compile, which is reported with the reason.
#
# Leaves in library_arguments what ld needs to link the program against the
# libraries, the arguments the compiler gives ld for a program that sees a
# .lib: the dynamic loader, and for each library its directory as a search
# path and as the run path, and its file by name.
build_the_libraries_it_sees() {
    local directory=$1 name=$2 library version interface source library_file
    library_arguments=()
    while read -r library version interface; do
        source=$(grep -lE "^Library +'?$library'? +version +\"$version\"" "$directory"/*.vox | head -1)
        [ -n "$source" ] || continue
        (cd "$directory" && vox "$(basename "$source")" --shared -o "${interface%.lib}.so") >> "$directory/library.log" 2>&1
        library_file=$(cd "$directory" && realpath -m "${interface%.lib}.so")
        library_arguments+=(-rpath "$(dirname "$library_file")" -L"$(dirname "$library_file")" -l:"$(basename "$library_file")")
    done < <(sed -nE "s/^see +'?([^' ]+)'? +version +\"([^\"]+)\" +from +\"([^\"]+)\.lib\".*/\1 \2 \3.lib/Ip" "$directory/$name.vox")
    if [ "${#library_arguments[@]}" -gt 0 ]; then
        library_arguments=(-dynamic-linker /lib64/ld-linux-x86-64.so.2 "${library_arguments[@]}")
    fi
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
# then the ld executable's answer, so the suite carries on as it would. A
# call that does not finish within the time limit is a difference.
cat > "$work/both" <<'EOF'
#!/usr/bin/env bash
record=$(mktemp -d "$BOTH_WORK/call.XXXXXX")
cat > "$record/in"
named() { local name=$1; shift; timeout "$BOTH_LIMIT" bash -c 'name=$1; shift; exec -a "$name" "$@"' named "$name" "$@"; }
named "$0" "$BOTH_LD" "$@" < "$record/in" > "$record/ld.out" 2> "$record/ld.err"; echo $? > "$record/ld.status"
named "$0" "$BOTH_ELF" "$@" < "$record/in" > "$record/elf.out" 2> "$record/elf.err"; echo $? > "$record/elf.status"
if [ "$(cat "$record/ld.status")" -eq 124 ] || [ "$(cat "$record/elf.status")" -eq 124 ]; then
    echo "differed: did not finish: $*" >> "$BOTH_LOG"
elif cmp -s "$record/ld.out" "$record/elf.out" && cmp -s "$record/ld.err" "$record/elf.err" \
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
    build_the_libraries_it_sees "$directory" "$name"
    if ! (cd "$directory" && vox "$name.vox" --emit-asm -o "$name.asm") > "$directory/compile.log" 2>&1; then
        left_out+=("$label (it does not compile: $(grep -m1 -i error "$directory/compile.log" | sed 's/\x1b\[[0-9;]*m//g'))")
        return
    fi
    # The reference is ld's output and nothing else: nasm -f elf64, then ld
    # with the arguments the compiler gives it, the libraries' among them.
    # When either refuses, the program fails the check with what it said;
    # nothing else is ever taken as the reference in its place.
    if ! (cd "$directory" && nasm -f elf64 -I"$include" -o "$name.o" "$name.asm") > "$directory/nasm.log" 2>&1; then
        differed+=("$label (nasm -f elf64 could not assemble the reference: $(head -1 "$directory/nasm.log"))")
        return
    fi
    if ! (cd "$directory" && ld -o "$name.ld" "$name.o" "${library_arguments[@]}") > "$directory/ld.log" 2>&1; then
        differed+=("$label (ld could not link the reference: $(head -1 "$directory/ld.log"))")
        return
    fi
    reference_links=$((reference_links + 1))
    local dynamic=no
    if needs_dynamic_linking "$directory/$name.ld"; then
        dynamic=yes
    else
        static_programs=$((static_programs + 1))
    fi
    if ! (cd "$directory" && guarded bash "$vox_tree/tools/voxelf/nasm-image.sh" "$name.asm" "$name" \
            && guarded "$VOX_ELF" "$name.manifest" -o "$name.elf" && chmod 755 "$name.elf") > "$directory/elf.log" 2>&1; then
        if [ "$dynamic" = yes ]; then
            not_supported+=("$label (ld's build needs dynamic linking, which voxelf does not do yet, M8; voxelf's side said: $(head -1 "$directory/elf.log"))")
        else
            differed+=("$label (vox-elf could not link it: $(head -1 "$directory/elf.log"))")
        fi
        return
    fi
    linked+=("$label")
    local difference
    if ! difference=$(bash "$here/same-bytes.sh" "$directory/$name.ld" "$directory/$name.elf"); then
        differed+=("$label (not the same bytes as ld's: $difference)")
        return
    fi
    if ! readelf -S "$directory/$name.elf" > /dev/null 2>&1 || ! objdump -d "$directory/$name.elf" > /dev/null 2>&1; then
        differed+=("$label (readelf -S or objdump -d cannot read it)")
        return
    fi
    same_bytes+=("$label")
    [ "$dynamic" = no ] && static_same_bytes=$((static_same_bytes + 1))
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
        not_run+=("$label ($reason)")
        return
    fi

    local stdin arguments case_number=0 alike_here=0 differed_here=0
    while IFS='|' read -r stdin arguments; do
        case_number=$((case_number + 1))
        local record=$directory/case$case_number
        # shellcheck disable=SC2086
        run_once "$directory/$name.ld" "$record.ld" "$name" "$stdin" $arguments
        # shellcheck disable=SC2086
        run_once "$directory/$name.elf" "$record.elf" "$name" "$stdin" $arguments
        if [ "$(cat "$record.ld.status")" -eq 124 ] || [ "$(cat "$record.elf.status")" -eq 124 ]; then
            differed_here=$((differed_here + 1))
            echo "  DID NOT FINISH $label within $limit seconds: stdin $stdin, arguments '$arguments'" >&2
        elif same_run "$record.ld" "$record.elf"; then
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
        (cd "$directory" && BOTH_WORK=$directory BOTH_LOG=$log BOTH_LD=$directory/$name.ld BOTH_LIMIT=$limit \
            BOTH_ELF=$directory/$name.elf BIN=$work/both CORPUS=$work/suite-corpus \
            bash "$suite") > /dev/null 2>&1 < /dev/null
        alike_here=$((alike_here + $(grep -c '^alike' "$log")))
        local suite_differences
        suite_differences=$(grep -c '^differed' "$log")
        if [ "$suite_differences" -gt 0 ]; then
            differed_here=$((differed_here + suite_differences))
            grep '^differed' "$log" | head -5 | while read -r line; do echo "  DIFFERS $label suite: $line"; done >&2
        fi
    fi

    cases_alike=$((cases_alike + alike_here)) cases_differed=$((cases_differed + differed_here))
    if [ "$differed_here" -gt 0 ]; then
        differed+=("$label (it runs differently from ld's build, or does not finish)")
    else
        ran_alike+=("$label")
    fi
}

for source in "$vox_tree"/examples/*.vox; do
    check_program "examples/$(basename "$source" .vox)" "$source"
done
if [ -z "$voxos" ]; then
    left_out+=("the Vox OS programs (VOXOS_SRC is not set; set it to a Vox OS checkout)")
elif [ ! -d "$voxos/system" ]; then
    left_out+=("the Vox OS programs (VOXOS_SRC is $voxos, which has no system directory)")
else
    for source in "$voxos"/system/*.vox; do
        check_program "voxos/$(basename "$source" .vox)" "$source"
    done
fi
if [ -z "$coreutils" ]; then
    left_out+=("the vox-coreutils tools (COREUTILS_SRC is not set; set it to a vox-coreutils checkout)")
elif [ ! -d "$coreutils" ]; then
    left_out+=("the vox-coreutils tools (COREUTILS_SRC is $coreutils, which is not a directory)")
else
    for source in "$coreutils"/*/*.vox; do
        check_program "coreutils/$(basename "$source" .vox)" "$source"
    done
fi

handed_to_ld=$(ld_pass_throughs)
if [ "$handed_to_ld" -ne 0 ]; then differed+=("voxelf's side called ld $handed_to_ld times: $(ld_execs | head -3 | tr '\n' ';')"); fi

echo "linked by vox-elf: ${#linked[@]}, with $handed_to_ld ld pass-throughs; built by ld to compare with: $reference_links"
echo "the same bytes as ld's build: ${#same_bytes[@]} of ${#linked[@]}; with read-only data and no larger than stripped ld: ${#no_larger[@]}"
echo "ran identically to ld's build: ${#ran_alike[@]} programs: ${ran_alike[*]}"
for entry in "${not_run[@]}"; do echo "compared byte for byte, not run: $entry"; done
for entry in "${not_supported[@]}"; do echo "not supported yet: $entry"; done
for entry in "${left_out[@]}"; do echo "LEFT OUT, which fails the check: $entry"; done
for entry in "${differed[@]}"; do echo "DIFFERED: $entry"; done
echo "voxelf differential: same bytes $static_same_bytes of $static_programs static; ${#not_supported[@]} not supported (dynamic, M8);" \
     "$handed_to_ld ld pass-throughs; ${#ran_alike[@]} ran identically in $cases_alike runs and $cases_differed runs differed;" \
     "${#not_run[@]} not run, compared byte for byte only; ${#left_out[@]} left out; ${#differed[@]} failed"
[ "${#differed[@]}" -eq 0 ] && [ "${#left_out[@]}" -eq 0 ] && [ "$static_same_bytes" -eq "$static_programs" ] && [ "$handed_to_ld" -eq 0 ]
