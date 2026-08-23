#!/bin/bash
#
# vox test runner - pytest-style testing for the Vox compiler
#
# Usage:
#   ./test.sh              Run all tests
#   ./test.sh tests/       Run tests in specific directory
#   ./test.sh file.vox      Run a single test
#   ./test.sh -v           Verbose mode (show diff on failure)
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Counters
PASSED=0
FAILED=0
SKIPPED=0

# Options
VERBOSE=0
TEST_DIR="tests"
SPECIFIC_FILE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options] [test_file_or_dir]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose    Show diff output on failures"
            echo "  -h, --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0               Run all tests in tests/"
            echo "  $0 tests/        Run tests in specific directory"
            echo "  $0 tests/hello.vox  Run a single test"
            exit 0
            ;;
        *)
            if [[ -d "$1" ]]; then
                TEST_DIR="$1"
            elif [[ -f "$1" ]]; then
                SPECIFIC_FILE="$1"
            else
                echo "Unknown option or file: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

# Get script directory (where vox project lives)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use the in-repo coreasm library so local runtime changes are exercised
# without requiring a system install. The compiler reads VOX_CORE_PATH
# (the documented name; EC_CORE_PATH is a deprecated fallback that prints
# a note on every run) and expects the coreasm directory itself, so point
# it at $SCRIPT_DIR/coreasm. Without this the override was a no-op and a
# present system install at /usr/local/share/vox/coreasm would shadow
# the in-repo runtime. VOX_CORE_PATH (not EC_CORE_PATH) is used here so
# the deprecation note does not pollute the output that the name-res
# "only-one" subcase (and any test asserting empty stderr) captures.
export VOX_CORE_PATH="$SCRIPT_DIR/coreasm"

VOX_BIN="$SCRIPT_DIR/target/release/vox"

# Build compiler if needed
echo -e "${BLUE}${BOLD}=== vox test runner ===${NC}"
echo ""

echo -e "${YELLOW}Building compiler...${NC}"
make build
echo ""

cargo_test() {
    echo -e "${YELLOW}Running cargo tests...${NC}"
    cargo test
    err=$?
    # The compile_fail corpus runs inside one cargo test
    # (compile_fail_corpus_reports_errors), which walks every .vox in
    # tests/compile_fail and asserts each one is rejected with its expected
    # message. Report the count, or the corpus is invisible here and silently
    # dropping cases would look identical to passing.
    local cf_dir="$SCRIPT_DIR/tests/compile_fail"
    if [[ -d "$cf_dir" ]]; then
        local cf_cases cf_errs
        cf_cases=$(find "$cf_dir" -name '*.vox' | wc -l)
        cf_errs=$(find "$cf_dir" -name '*.err' | wc -l)
        echo -e "  compile_fail corpus: ${cf_cases} cases (checked by cargo test)"
        if [[ "$cf_cases" -ne "$cf_errs" ]]; then
            echo -e "  ${RED}WARN${NC} $cf_cases .vox but $cf_errs .err - every case needs both"
        fi
    fi
    echo ""
    return $err
}

# Function to run a single test
run_test() {
    local test_file="$1"
    local test_name="${test_file%.vox}"
    local expected_file="${test_name}.expected"
    local expected_exit_file="${test_name}.exit"
    local args_file="${test_name}.args"
    local basename=$(basename "$test_name")
    
    # Check if expected file exists
    if [[ ! -f "$expected_file" ]]; then
        echo -e "  ${YELLOW}SKIP${NC} $basename (no .expected file)"
        ((SKIPPED++))
        return
    fi
    
    # Create temp files for output
    local tmp_out=$(mktemp)
    local tmp_err=$(mktemp)
    
    # Load runtime arguments from optional .args file (one arg per non-empty line)
    local run_args=()
    if [[ -f "$args_file" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            run_args+=("$line")
        done < "$args_file"
    fi

    # Compile then run the produced executable so we can pass runtime args
    local actual_exit=0
    local exe_path="$SCRIPT_DIR/$basename"
    "$VOX_BIN" "$test_file" > "$tmp_err" 2>&1 || actual_exit=$?

    if [[ "$actual_exit" == "0" ]]; then
        "$exe_path" "${run_args[@]}" > "$tmp_out" 2>> "$tmp_err" || actual_exit=$?
    fi
    
    # Check expected exit code if specified
    local expected_exit=0
    if [[ -f "$expected_exit_file" ]]; then
        expected_exit=$(cat "$expected_exit_file" | tr -d '[:space:]')
    fi
    
    # Compare output
    if diff -q "$expected_file" "$tmp_out" > /dev/null 2>&1 && [[ "$actual_exit" == "$expected_exit" ]]; then
        echo -e "  ${GREEN}PASS${NC} $basename"
        ((PASSED++))
    else
        echo -e "  ${RED}FAIL${NC} $basename"
        ((FAILED++))
        
        if [[ $VERBOSE -eq 1 ]]; then
            if ! diff -q "$expected_file" "$tmp_out" > /dev/null 2>&1; then
                echo -e "    ${YELLOW}Output diff:${NC}"
                diff -u "$expected_file" "$tmp_out" | head -20 | sed 's/^/    /'
            fi
            if [[ "$actual_exit" != "$expected_exit" ]]; then
                echo -e "    ${YELLOW}Exit code: expected $expected_exit, got $actual_exit${NC}"
            fi
            if [[ -s "$tmp_err" ]]; then
                echo -e "    ${YELLOW}Stderr:${NC}"
                head -5 "$tmp_err" | sed 's/^/    /'
            fi
        fi
    fi
    
    # Cleanup temp files and generated executable
    rm -f "$exe_path"
    rm -f "$tmp_out" "$tmp_err"
}

# Collect test files
if [[ -n "$SPECIFIC_FILE" ]]; then
    TEST_FILES=("$SPECIFIC_FILE")
else
    mapfile -t TEST_FILES < <(find "$SCRIPT_DIR/$TEST_DIR" -maxdepth 1 -name "*.vox" -type f | sort)
fi

# Run tests
echo -e "${BOLD}Running tests...${NC}"
echo ""

# Run cargo unit tests
if ! cargo_test
then
    exit 1
fi

# Packaging invariant: vox.spec's vendored build path hand-lists every crate
# it bundles as `Provides: bundled(crate(...))`, and that list is only true
# for as long as it matches Cargo.lock. The spec cannot be generated (Copr
# builds one SRPM for every chroot), so this is what stops the two drifting.
if [[ -x "$SCRIPT_DIR/scripts/check-spec-bundled.sh" ]]; then
    echo -e "${YELLOW}Checking vox.spec bundled crates...${NC}"
    if "$SCRIPT_DIR/scripts/check-spec-bundled.sh"; then
        echo -e "  ${GREEN}PASS${NC} vox.spec bundled() matches Cargo.lock"
        ((PASSED++))
    else
        echo -e "  ${RED}FAIL${NC} vox.spec bundled() disagrees with Cargo.lock"
        ((FAILED++))
    fi
    echo ""
fi

for test_file in "${TEST_FILES[@]}"; do
    run_test "$test_file"
done

# Runtime-level tests: invariants no Vox program can express, checked by
# assembling a driver directly against coreasm. Uses only nasm and ld, which
# building Vox already requires, so this always runs - never silently skipped.
run_runtime_test() {
    local name="$1"
    local src="$SCRIPT_DIR/tests/runtime/${name}.asm"
    [ -f "$src" ] || return 0

    local work
    work="$(mktemp -d)"
    if nasm -f elf64 -i "$SCRIPT_DIR/" -o "$work/t.o" "$src" >"$work/log" 2>&1 \
       && ld -o "$work/t" "$work/t.o" >>"$work/log" 2>&1 \
       && "$work/t" >>"$work/log" 2>&1; then
        echo -e "  ${GREEN}PASS${NC} runtime/$name"
        ((PASSED++))
    else
        echo -e "  ${RED}FAIL${NC} runtime/$name"
        sed 's/^/      /' "$work/log" | head -20
        ((FAILED++))
    fi
    rm -rf "$work"
}

for runtime_test in "$SCRIPT_DIR"/tests/runtime/*.asm; do
    [ -e "$runtime_test" ] || break
    # shared_lib_driver and two_version_driver are cross-boundary drivers that
    # must be linked against a .so. They are built and run — always, never
    # skipped — by run_shared_library_test / run_two_version_library_test
    # below, which assemble them with the .so on the link line. The plain
    # nasm+ld here has no .so to resolve their externs, so skip them in this
    # loop rather than report undefined-symbol errors as a fail.
    case "$(basename "$runtime_test" .asm)" in
        shared_lib_driver|two_version_driver) continue ;;
    esac
    run_runtime_test "$(basename "$runtime_test" .asm)"
done

# Shared-library boundary test (plan 200, Phase 2; plan 230 stage A1 mangling).
# Builds tests/shared/libmath.vox as a .so, asserts the dynamic export set is
# EXACTLY the three mangled function labels (a presence grep would pass while
# runtime symbols leak — Phase 0's version script is only honest if this is a
# set equality), asserts a valid dynamic section, then links an assembly
# driver and calls across the boundary. The driver is assembly precisely so
# nasm+ld — already required to build Vox — run it on every host. It must
# never report "skipped".
run_shared_library_test() {
    local work lib_src driver
    lib_src="$SCRIPT_DIR/tests/shared/libmath.vox"
    driver="$SCRIPT_DIR/tests/runtime/shared_lib_driver.asm"
    work="$(mktemp -d)"

    local fail_msg=""
    local fail_log=""

    # 1. Build the shared library.
    if ! "$VOX_BIN" "$lib_src" --shared -o "$work/libmath.so" >"$work/build.log" 2>&1; then
        fail_msg="shared/libmath (build)"; fail_log="$work/build.log"
    # 2. Exact export set: nm -D --defined-only must list exactly the three
    #    exports and nothing else. Compare as a sorted set, not a grep.
    else
        local got exp
        got=$(nm -D --defined-only "$work/libmath.so" | awk '{print $3}' | sort)
        exp=$(printf '%s\n' mathkit_1_0_add_two_numbers mathkit_1_0_greet mathkit_1_0_makebuf | sort)
        # 2b. A3: the .lib interface file is written beside the .so. Assert its
        #     exact content — a drift in the emitted format fails here, not at
        #     A4. `makebuf` is a multi-statement body (`Return` follows a
        #     `Create`/`Append` pair, not the function's first statement), so
        #     plan 280 S1's Gate B fix is what makes its ToC entry carry
        #     `, returning a number` at all — before that fix, Gate B parsed
        #     the typed `Return a number, ...` but never wrote it back into
        #     the function's declared return type, so this entry silently
        #     read `To makebuf.` (void). The other two are single-line defs
        #     whose typed `Return a number, ...` was always captured (Gate A).
        local lib_exp
        lib_exp=$(printf 'Library mathkit version "1.0".\nLocation "./libmath.so".\n\nTable of Contents:\n    To '\''add two numbers'\'' with a number called n, returning a number.\n    To greet.\n    To makebuf, returning a number.\n')
        if ! diff -u <(printf '%s\n' "$lib_exp") "$work/libmath.lib" >"$work/libdiff.log" 2>&1; then
            fail_msg="shared/libmath (.lib content mismatch)"; fail_log="$work/libdiff.log"
        elif [[ "$got" != "$exp" ]]; then
            fail_msg="shared/libmath (export set is not exactly {mathkit_1_0_add_two_numbers, mathkit_1_0_greet, mathkit_1_0_makebuf})"
            { echo "expected:"; echo "$exp" | sed 's/^/  /'; echo "got:"; echo "$got" | sed 's/^/  /'; } >"$work/diff.log"
            fail_log="$work/diff.log"
        # 3. readelf -d reports a parseable dynamic section.
        elif ! readelf -d "$work/libmath.so" >"$work/dyn.log" 2>&1 \
              || ! grep -q "Dynamic section" "$work/dyn.log"; then
            fail_msg="shared/libmath (no valid dynamic section)"; fail_log="$work/dyn.log"
        # 4. Assemble and link the driver against the .so, then run it.
        elif ! nasm -f elf64 -i "$SCRIPT_DIR/" -o "$work/driver.o" "$driver" >"$work/nasm.log" 2>&1; then
            fail_msg="shared/libmath (driver nasm)"; fail_log="$work/nasm.log"
        elif ! ld -dynamic-linker /lib64/ld-linux-x86-64.so.2 -rpath "$work" \
                -o "$work/driver" "$work/driver.o" -L"$work" -lmath >"$work/ld.log" 2>&1; then
            fail_msg="shared/libmath (driver link)"; fail_log="$work/ld.log"
        else
            local out rc
            out=$("$work/driver" 2>"$work/run.err")
            rc=$?
            if [[ $rc -ne 0 ]]; then
                case "$rc" in
                    2) fail_msg="shared/libmath (driver: add_two_numbers(40) != 42)" ;;
                    3) fail_msg="shared/libmath (driver: makebuf() != 5)" ;;
                    *) fail_msg="shared/libmath (driver exited $rc)" ;;
                esac
                fail_log="$work/run.err"
            elif [[ "$out" != "hello from libmath" ]]; then
                fail_msg="shared/libmath (driver stdout mismatch)"
                { echo "expected: hello from libmath"; echo "got: $out"; } >"$work/out.log"
                fail_log="$work/out.log"
            fi
        fi
    fi

    if [[ -n "$fail_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} $fail_msg"
        [ -s "$fail_log" ] && sed 's/^/      /' "$fail_log" | head -30
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} shared/libmath"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_shared_library_test

# C-interop boundary test. LANGUAGE.md promises a .so is "callable from Vox —
# or from C" and "loadable from C, Rust, or any other host"; SYMBOL_MANGLING.md
# promises a standalone .so "must be callable from C". Nothing in the suite
# checked any of that until now. Builds tests/cinterop/{mathkit,strkit}.vox
# (two libraries, one .so — the same multi-input path as tests/shared) with
# one numeric export and one text export, compiles tests/cinterop/driver.c
# against it with gcc, and runs the result. Asserts: the .so has zero NEEDED
# entries (freestanding — no libc pulled in on the Vox side, so it links into
# a C program without conflict); both mangled exports (math_kit_1_0_add_two,
# strkit_1_0_greet) are present in .dynsym; the C build produces zero
# warnings; and the driver's exact stdout, not just its exit status. gcc is a
# required part of this project's toolchain (already needed to build/test
# elsewhere) and is present on every host that can run this suite — if it is
# ever missing this FAILS loudly rather than skipping, because a silent skip
# here would drop the only coverage of a promise the docs make three times.
run_c_interop_test() {
    local work fail_msg="" fail_log=""
    work="$(mktemp -d)"

    if ! command -v gcc >/dev/null 2>&1; then
        fail_msg="c-interop (gcc not found - required toolchain, not optional)"
    # 1. Build the .so from two libraries: one numeric export, one text export.
    elif ! "$VOX_BIN" "$SCRIPT_DIR/tests/cinterop/mathkit.vox" "$SCRIPT_DIR/tests/cinterop/strkit.vox" \
            --shared -o "$work/libcinterop.so" >"$work/build.log" 2>&1; then
        fail_msg="c-interop (library build)"; fail_log="$work/build.log"
    # 2. No NEEDED entries: the .so must be freestanding, pulling in no libc
    #    of its own, so it links into a C program without conflict.
    elif readelf -d "$work/libcinterop.so" 2>"$work/needed.log" | grep -q NEEDED; then
        fail_msg="c-interop (.so has NEEDED entries - not freestanding)"
        readelf -d "$work/libcinterop.so" >"$work/needed.log" 2>&1
        fail_log="$work/needed.log"
    else
        # 3. Both mangled exports present in .dynsym.
        local dynsyms
        dynsyms=$(nm -D --defined-only "$work/libcinterop.so" | awk '{print $3}')
        if ! grep -qx "math_kit_1_0_add_two" <<<"$dynsyms" || ! grep -qx "strkit_1_0_greet" <<<"$dynsyms"; then
            fail_msg="c-interop (mangled exports missing from .dynsym)"
            { echo "expected: math_kit_1_0_add_two, strkit_1_0_greet"; echo "got:"; echo "$dynsyms"; } >"$work/dynsym.log"
            fail_log="$work/dynsym.log"
        # 4. Compile the C driver against the .so with gcc. -Werror turns any
        #    warning into a build failure, so "zero build warnings" is enforced
        #    by the exit code, not a separate log scrape.
        elif ! gcc -Wall -Wextra -Werror -std=c11 "$SCRIPT_DIR/tests/cinterop/driver.c" \
                -L"$work" -l:libcinterop.so -Wl,-rpath,"$work" -o "$work/cmain" >"$work/gcc.log" 2>&1; then
            fail_msg="c-interop (gcc build)"; fail_log="$work/gcc.log"
        else
            # 5. Run it; assert the exact expected output, not just exit status.
            local out rc
            out=$("$work/cmain" 2>"$work/run.err")
            rc=$?
            if [[ $rc -ne 0 ]]; then
                fail_msg="c-interop (driver exited $rc)"; fail_log="$work/run.err"
            elif [[ "$out" != "42 hello from vox" ]]; then
                fail_msg="c-interop (driver stdout mismatch)"
                { echo "expected: 42 hello from vox"; echo "got: $out"; } >"$work/out.log"
                fail_log="$work/out.log"
            fi
        fi
    fi

    if [[ -n "$fail_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} $fail_msg"
        [ -s "$fail_log" ] && sed 's/^/      /' "$fail_log" | head -30
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} c-interop (gcc-linked .so: add_two(40)=42, greet()='hello from vox', no NEEDED)"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_c_interop_test

# Two-version shared-library boundary test (plan 230 stage A2). This is the
# backwards-compatibility case the entire multi-version design exists for: TWO
# VERSIONS of one library (flags 0.1 and flags 1.0) in ONE .so, both defining
# `hasflag`, both independently callable and resolving to different code. It
# builds the .so from two sources with the real CLI end to end
# (`vox a.vox b.vox --shared -o lib.so`), then asserts:
#   1. nm -D --defined-only is EXACTLY {flags_0_1_hasflag, flags_1_0_hasflag}
#      — a set equality, not a presence grep, so a regression that drops or
#      renames one version's export fails here;
#   2. readelf -d reports a valid dynamic section;
#   3. readelf -r has ZERO absolute relocations (the PIC invariant, which a
#      per-library runtime — the design going wrong — would break);
#   4. an assembly driver linked against the .so calls flags_0_1_hasflag(5)
#      (== 6) and flags_1_0_hasflag(5) (== 105) and exits 0 — proving the two
#      versions coexist and resolve to different bodies. A collision that let
#      the second library's signature overwrite the first's (the A1 finding)
#      makes one call return the other's value, so BOTH are checked.
# It must never report "skipped": the two-version property is the one most
# likely to regress silently, and a case that only ever existed in a
# transcript is a case that stops being true.
run_two_version_library_test() {
    local work src0 src1 driver
    src0="$SCRIPT_DIR/tests/shared/flags_0_1.vox"
    src1="$SCRIPT_DIR/tests/shared/flags_1_0.vox"
    driver="$SCRIPT_DIR/tests/runtime/two_version_driver.asm"
    work="$(mktemp -d)"

    local fail_msg=""
    local fail_log=""

    # 1. Build the two-version .so from two sources in one link step.
    if ! "$VOX_BIN" "$src0" "$src1" --shared -o "$work/libflags.so" >"$work/build.log" 2>&1; then
        fail_msg="two-version flags (build)"; fail_log="$work/build.log"
    # 2. Exact export set: both mangled labels and nothing else.
    else
        local got exp
        got=$(nm -D --defined-only "$work/libflags.so" | awk '{print $3}' | sort)
        exp=$(printf '%s\n' flags_0_1_hasflag flags_1_0_hasflag | sort)
        # 2b. A3: the .lib interface file carries both versions' signatures —
        #     the round-trip artifact A4 will parse. Pin its exact content so a
        #     formatting drift fails here. Both `hasflag` defs are single-line
        #     (`To ... . Return a number, ...`), so each carries `, returning a
        #     number`; one Library block per version, `Location` relative.
        local lib_exp
        lib_exp=$(printf 'Library flags version "0.1".\nLocation "./libflags.so".\n\nTable of Contents:\n    To hasflag with a number called n, returning a number.\n\nLibrary flags version "1.0".\nLocation "./libflags.so".\n\nTable of Contents:\n    To hasflag with a number called n, returning a number.\n')
        if ! diff -u <(printf '%s\n' "$lib_exp") "$work/libflags.lib" >"$work/libdiff.log" 2>&1; then
            fail_msg="two-version flags (.lib content mismatch)"; fail_log="$work/libdiff.log"
        elif [[ "$got" != "$exp" ]]; then
            fail_msg="two-version flags (export set is not exactly {flags_0_1_hasflag, flags_1_0_hasflag})"
            { echo "expected:"; echo "$exp" | sed 's/^/  /'; echo "got:"; echo "$got" | sed 's/^/  /'; } >"$work/diff.log"
            fail_log="$work/diff.log"
        # 3. readelf -d reports a parseable dynamic section.
        elif ! readelf -d "$work/libflags.so" >"$work/dyn.log" 2>&1 \
              || ! grep -q "Dynamic section" "$work/dyn.log"; then
            fail_msg="two-version flags (no valid dynamic section)"; fail_log="$work/dyn.log"
        # 4. Zero absolute relocations on the multi-library .so.
        elif [[ $(readelf -r "$work/libflags.so" | grep -cE "R_X86_64_(32|32S)") -ne 0 ]]; then
            fail_msg="two-version flags (absolute relocations present)"; fail_log="$work/reloc.log"
            readelf -r "$work/libflags.so" >"$work/reloc.log" 2>&1
        # 5. Assemble and link the driver against the .so, then run it.
        elif ! nasm -f elf64 -i "$SCRIPT_DIR/" -o "$work/driver.o" "$driver" >"$work/nasm.log" 2>&1; then
            fail_msg="two-version flags (driver nasm)"; fail_log="$work/nasm.log"
        elif ! ld -dynamic-linker /lib64/ld-linux-x86-64.so.2 -rpath "$work" \
                -o "$work/driver" "$work/driver.o" -L"$work" -lflags >"$work/ld.log" 2>&1; then
            fail_msg="two-version flags (driver link)"; fail_log="$work/ld.log"
        else
            local rc
            "$work/driver" >"$work/run.out" 2>"$work/run.err"
            rc=$?
            if [[ $rc -ne 0 ]]; then
                case "$rc" in
                    2) fail_msg="two-version flags (driver: flags_0_1_hasflag(5) != 6)" ;;
                    3) fail_msg="two-version flags (driver: flags_1_0_hasflag(5) != 105)" ;;
                    *) fail_msg="two-version flags (driver exited $rc)" ;;
                esac
                fail_log="$work/run.err"
            fi
        fi
    fi

    if [[ -n "$fail_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} $fail_msg"
        [ -s "$fail_log" ] && sed 's/^/      /' "$fail_log" | head -30
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} two-version/flags"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_two_version_library_test

# A library can be rebuilt. A `--shared` build writes `<stem>.lib` as a
# declared output — derived from `-o`, like the `.so` and `.asm`, and
# overwritten on a rebuild. The earlier refusal (plan 230 A3, borrowed from
# plan 210 P1's source-derived `.map` collision) made a library buildable
# once and then never again: every edit-build loop hit "not overwriting
# existing file". The `.lib` name comes from `-o`, which the user chose, so
# overwriting is correct (the `.map` hazard was a *source*-derived name that
# could collide with an unrelated file). This builds the same library twice
# and asserts the second run succeeds and the `.lib` matches `nm -D` of the
# `.so` afterwards — the pair must never disagree, which is what the
# `.dynsym` verification exists to catch. It also pre-seeds a hand-written
# sentinel `.lib` to confirm it is overwritten, not refused. It must never
# report "skipped": a library that can't be rebuilt is a loud failure.
run_lib_rebuild_test() {
    local work lib_src fail_msg fail_log nm_count toc_count
    lib_src="$SCRIPT_DIR/tests/shared/libmath.vox"
    work="$(mktemp -d)"
    fail_msg=""; fail_log=""

    # Seed a hand-written sentinel .lib. The old code refused to overwrite it;
    # the new code treats it as a declared output and replaces it.
    printf 'THIS IS A HAND-WRITTEN .lib — DO NOT OVERWRITE\n' > "$work/libmath.lib"

    # First build: overwrites the sentinel, writes the .so.
    if ! "$VOX_BIN" "$lib_src" --shared -o "$work/libmath.so" >"$work/build1.log" 2>&1; then
        fail_msg="rebuild (first build failed)"; fail_log="$work/build1.log"
    elif grep -q "not overwriting" "$work/build1.log"; then
        fail_msg="rebuild (first build refused the .lib)"; fail_log="$work/build1.log"
    elif [[ ! -e "$work/libmath.so" ]]; then
        fail_msg="rebuild (no .so after first build)"; fail_log="$work/build1.log"
    # Second build: the real test — a rebuild into the existing .lib must succeed.
    elif ! "$VOX_BIN" "$lib_src" --shared -o "$work/libmath.so" >"$work/build2.log" 2>&1; then
        fail_msg="rebuild (second build failed)"; fail_log="$work/build2.log"
    elif grep -q "not overwriting" "$work/build2.log"; then
        fail_msg="rebuild (second build refused — library not rebuildable)"; fail_log="$work/build2.log"
    else
        # The .lib must match the .so: ToC entry count == nm -D defined count.
        nm_count=$(nm -D --defined-only "$work/libmath.so" | awk '{print $3}' | grep -c .)
        toc_count=$(grep -c '^    To ' "$work/libmath.lib")
        if [[ -z "$nm_count" || -z "$toc_count" || "$nm_count" != "$toc_count" || "$nm_count" -eq 0 ]]; then
            fail_msg="rebuild (.lib ToC ${toc_count:-?} != nm -D ${nm_count:-?})"
            { echo "nm -D --defined-only:"; nm -D --defined-only "$work/libmath.so" | awk '{print $3}' | sort | sed 's/^/  /'; echo ".lib ToC:"; grep '^    To ' "$work/libmath.lib" | sed 's/^/  /'; } >"$work/diff.log"
            fail_log="$work/diff.log"
        fi
    fi

    if [[ -n "$fail_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} $fail_msg"
        [ -s "$fail_log" ] && sed 's/^/      /' "$fail_log" | head -30
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} rebuild/lib (second build ok, .lib == nm -D: $nm_count)"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_lib_rebuild_test

# A3 table-of-contents completeness (plan 230). A bodyless function —
# `To greet.` with no body and no separating blank line — used to absorb the
# following `To c ...` as a nested definition, so `c` was exported by the .so
# but missing from the .lib ToC: a silent .lib/.so mismatch and the one property
# this stage exists for. This builds tests/shared/toc_count.vox (a bodyless
# function in the middle and two bodyless in a row, no blank lines between them
# so the absorption path is exercised) and asserts the .lib ToC entry count
# EQUALS the `nm -D --defined-only` count. A count equality, not a name list —
# it catches the whole class, so any function dropped from the ToC while still
# exported fails here, whichever one it is. It must never report "skipped": a
# silent ToC/.so mismatch is the one failure most worth a loud test.
run_lib_toc_count_test() {
    local work lib_src nm_count toc_count
    lib_src="$SCRIPT_DIR/tests/shared/toc_count.vox"
    work="$(mktemp -d)"

    local fail_msg=""
    local fail_log=""

    if ! "$VOX_BIN" "$lib_src" --shared -o "$work/libtoc.so" >"$work/build.log" 2>&1; then
        fail_msg="toc-count (build)"; fail_log="$work/build.log"
    else
        nm_count=$(nm -D --defined-only "$work/libtoc.so" | awk '{print $3}' | grep -c .)
        toc_count=$(grep -c '^    To ' "$work/libtoc.lib")
        if [[ -z "$nm_count" || -z "$toc_count" || "$nm_count" != "$toc_count" || "$nm_count" -eq 0 ]]; then
            fail_msg="toc-count (ToC entries ${toc_count:-?} != nm -D exports ${nm_count:-?})"
            { echo "nm -D --defined-only:"; nm -D --defined-only "$work/libtoc.so" | awk '{print $3}' | sort | sed 's/^/  /'; echo ".lib ToC:"; grep '^    To ' "$work/libtoc.lib" | sed 's/^/  /'; } >"$work/diff.log"
            fail_log="$work/diff.log"
        fi
    fi

    if [[ -n "$fail_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} $fail_msg"
        [ -s "$fail_log" ] && sed 's/^/      /' "$fail_log" | head -30
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} toc-count/lib ($nm_count == $toc_count)"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_lib_toc_count_test

# Stage A4 consumer tests (plan 230). The producer side (A1-A3: mangle,
# multi-input, emit .lib) is proven above; these prove the consumer side —
# a pure-Vox program `see`s a `.lib` the compiler itself produced, the
# promised symbols are verified against the `.so`'s `.dynsym`, the signatures
# register so calls type-check, and the `.so` plus `-rpath` land on the link
# line. This is the goal of plans 200 and 230; until it passes, nothing before
# it delivered its purpose.

# A4.1 — the goal: a pure-Vox program calls a pure-Vox library through `see`
# and prints the right answer. Builds tests/shared/mathkit_lib.vox into a
# .so/.lib pair, then a consumer `see`s the `.lib` and calls `add two numbers`
# of 3 and 4, which must print 7. Every link in the chain is exercised:
# .lib resolution, block selection by name AND version, .dynsym verification,
# signature registration, `extern <mangled>`, and the .so + -rpath on the link
# line. It must never report "skipped".
run_see_consumer_test() {
    local work lib_src
    lib_src="$SCRIPT_DIR/tests/shared/mathkit_lib.vox"
    work="$(mktemp -d)"

    local fail_msg=""
    local fail_log=""

    if ! "$VOX_BIN" "$lib_src" --shared -o "$work/libmathkit.so" >"$work/build.log" 2>&1; then
        fail_msg="see/consumer (library build)"; fail_log="$work/build.log"
    elif [[ ! -f "$work/libmathkit.lib" ]]; then
        fail_msg="see/consumer (.lib not emitted beside the .so)"
    else
        # The consumer sits in the same dir as the .lib so `see` resolves
        # relative to the source, and Location resolves relative to the .lib.
        cat >"$work/use_mathkit.vox" <<'EOF'
see mathkit version "1.0" from "./libmathkit.lib".

A number called sum is 'add two numbers' of 3 and 4.
Print the sum.
EOF
        if ! "$VOX_BIN" "$work/use_mathkit.vox" -o "$work/use_mathkit" >"$work/consumer.log" 2>&1; then
            fail_msg="see/consumer (consumer build)"; fail_log="$work/consumer.log"
        else
            local out
            out=$("$work/use_mathkit" 2>"$work/run.log")
            if [[ "$out" != "7" ]]; then
                fail_msg="see/consumer (add two numbers of 3 and 4 printed '$out', not 7)"
                { echo "stdout: $out"; cat "$work/run.log"; } >"$work/out.log"
                fail_log="$work/out.log"
            fi
        fi
    fi

    if [[ -n "$fail_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} $fail_msg"
        [ -s "$fail_log" ] && sed 's/^/      /' "$fail_log" | head -25
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} see/consumer (3 + 4 = 7 through a .lib)"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_see_consumer_test

# A4.3 — a DECLARED float, map and buffer return, printed straight from an
# imported function. The consumer never routes the result through a variable,
# so the only thing that can supply the type is the `returning a <type>` clause
# the `.lib` states. Builds tests/shared/collections_lib.vox, then a consumer
# that prints all three directly; before BUGS_FOUND #67 the map row printed the
# map's heap address, because the imports return-type table had no `map` arm.
# Must never report "skipped".
run_see_collection_return_test() {
    local work lib_src
    lib_src="$SCRIPT_DIR/tests/shared/collections_lib.vox"
    work="$(mktemp -d)"

    local fail_msg=""
    local fail_log=""

    if ! "$VOX_BIN" "$lib_src" --shared -o "$work/libcollections.so" >"$work/build.log" 2>&1; then
        fail_msg="see/collection-return (library build)"; fail_log="$work/build.log"
    elif [[ ! -f "$work/libcollections.lib" ]]; then
        fail_msg="see/collection-return (.lib not emitted beside the .so)"
    else
        cat >"$work/use_collections.vox" <<'EOF'
see collections version "1.0" from "./libcollections.lib".

Print 'give float'.
Print 'give map'.
Print 'give buffer'.
EOF
        if ! "$VOX_BIN" "$work/use_collections.vox" -o "$work/use_collections" >"$work/consumer.log" 2>&1; then
            fail_msg="see/collection-return (consumer build)"; fail_log="$work/consumer.log"
        else
            local out expected
            out=$("$work/use_collections" 2>"$work/run.log")
            expected=$'2.5\n{"ann": 30}\nbytes'
            if [[ "$out" != "$expected" ]]; then
                fail_msg="see/collection-return (printed '$out', not the three declared types)"
                { echo "stdout: $out"; cat "$work/run.log"; } >"$work/out.log"
                fail_log="$work/out.log"
            fi
        fi
    fi

    if [[ -n "$fail_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} $fail_msg"
        [ -s "$fail_log" ] && sed 's/^/      /' "$fail_log" | head -25
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} see/collection-return (float, map and buffer through a .lib)"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_see_collection_return_test

# A4.4 / docs/BUGS_FOUND.md #97 — a list handed ACROSS the .lib boundary to a
# function that appends to it. A `.lib` is a signature, not a body, so nothing
# on the consumer's side can prove what an imported function writes into a list
# it is given; a list passed to one is widened conservatively, and every read
# of it dispatches on the slot's own runtime tag. Before #97 the consumer proved
# the list homogeneous and `'s last` printed the appended text's address as a
# number. Builds tests/shared/noting_lib.vox, then a consumer that appends
# through the import and reads the list back every way. Must never skip.
run_see_list_parameter_test() {
    local work lib_src
    lib_src="$SCRIPT_DIR/tests/shared/noting_lib.vox"
    work="$(mktemp -d)"

    local fail_msg=""
    local fail_log=""

    if ! "$VOX_BIN" "$lib_src" --shared -o "$work/libnoting.so" >"$work/build.log" 2>&1; then
        fail_msg="see/list-parameter (library build)"; fail_log="$work/build.log"
    elif [[ ! -f "$work/libnoting.lib" ]]; then
        fail_msg="see/list-parameter (.lib not emitted beside the .so)"
    else
        cat >"$work/use_noting.vox" <<'EOF'
see noting version "1.0" from "./libnoting.lib".

a list called noted is [].
'note whatever' of noted and "through a library".
'note whatever' of noted and "and again".
Print "last: {noted's last}".
Print "first: {noted's first}".
Print "element 2: {element 2 of noted}".
'report the size' of noted.

(A library function that widens the list and whose .lib says bare `list`.)
a list called stashed is [].
'stash a local' of stashed.
Print "stashed: {stashed's last}".

(A caller's list proven to hold NUMBERS, handed a text by the library. The
 .lib promises `list of text` to every caller; trusting it here read the
 integer 1 as a text pointer and segfaulted.)
a list called tally is [1, 2, 3].
'note whatever' of tally and "four".
Print "tally first: {tally's first}".
Print "tally last: {tally's last}".
EOF
        if ! "$VOX_BIN" "$work/use_noting.vox" -o "$work/use_noting" >"$work/consumer.log" 2>&1; then
            fail_msg="see/list-parameter (consumer build)"; fail_log="$work/consumer.log"
        else
            local out expected
            out=$("$work/use_noting" 2>"$work/run.log")
            expected=$'last: and again\nfirst: through a library\nelement 2: and again\nsize: 2\nstashed: borrowed\ntally first: 1\ntally last: four'
            if [[ "$out" != "$expected" ]]; then
                fail_msg="see/list-parameter (a text appended through an imported function did not read back as text)"
                { echo "stdout:"; echo "$out"; echo "expected:"; echo "$expected"; cat "$work/run.log"; } >"$work/out.log"
                fail_log="$work/out.log"
            fi
        fi
    fi

    if [[ -n "$fail_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} $fail_msg"
        [ -s "$fail_log" ] && sed 's/^/      /' "$fail_log" | head -25
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} see/list-parameter (a list widened across the .lib boundary)"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_see_list_parameter_test

# A4.2 — two versions of one library in one .so, each consumed from its own
# program. Reuses the A2 flags .so (flags 0.1 and 1.0 in one binary); two
# consumers `see` different versions and call hasflag(5), which must print 6
# from 0.1 and 105 from 1.0 — proving the .dynsym verification and the `extern`
# emission pick the version's OWN mangled symbol (flags_0_1_hasflag vs
# flags_1_0_hasflag), not a shared one. Both consumers read the SAME .lib
# (one file, two blocks); the version selects the block. Must never skip.
run_see_two_version_test() {
    local work src0 src1
    src0="$SCRIPT_DIR/tests/shared/flags_0_1.vox"
    src1="$SCRIPT_DIR/tests/shared/flags_1_0.vox"
    work="$(mktemp -d)"

    local fail_msg=""
    local fail_log=""

    if ! "$VOX_BIN" "$src0" "$src1" --shared -o "$work/libflags.so" >"$work/build.log" 2>&1; then
        fail_msg="see/two-version (library build)"; fail_log="$work/build.log"
    elif [[ ! -f "$work/libflags.lib" ]]; then
        fail_msg="see/two-version (.lib not emitted)"
    else
        cat >"$work/use_0_1.vox" <<'EOF'
see flags version "0.1" from "./libflags.lib".
A number called r is hasflag of 5.
Print the r.
EOF
        cat >"$work/use_1_0.vox" <<'EOF'
see flags version "1.0" from "./libflags.lib".
A number called r is hasflag of 5.
Print the r.
EOF
        local out01 out10
        if ! "$VOX_BIN" "$work/use_0_1.vox" -o "$work/use_0_1" >"$work/c01.log" 2>&1; then
            fail_msg="see/two-version (0.1 consumer build)"; fail_log="$work/c01.log"
        elif ! out01=$("$work/use_0_1" 2>/dev/null) || [[ "$out01" != "6" ]]; then
            fail_msg="see/two-version (hasflag(5) from 0.1 printed '$out01', not 6)"
        elif ! "$VOX_BIN" "$work/use_1_0.vox" -o "$work/use_1_0" >"$work/c10.log" 2>&1; then
            fail_msg="see/two-version (1.0 consumer build)"; fail_log="$work/c10.log"
        elif ! out10=$("$work/use_1_0" 2>/dev/null) || [[ "$out10" != "105" ]]; then
            fail_msg="see/two-version (hasflag(5) from 1.0 printed '$out10', not 105)"
        fi
    fi

    if [[ -n "$fail_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} $fail_msg"
        [ -s "$fail_log" ] && sed 's/^/      /' "$fail_log" | head -25
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} see/two-version (6 from 0.1, 105 from 1.0)"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_see_two_version_test

# A4.3 — the six diagnostics. Each failure mode must have its OWN message
# naming the file and what was expected; they are half the deliverable. Built
# off the flags .so/.lib so the good state is known. Each sub-check is its own
# assertion with its own fail_msg, so a regression names exactly which one
# broke. The diagnostics, in order: missing .lib (paths tried, --lib-path
# exists); absent library (lists what the .lib does contain); version mismatch
# (lists the versions on offer); missing .so at Location (the resolved path);
# symbol absent from .dynsym (names the symbol — the stale-.lib case); wrong
# arity and wrong type at a call site (compile errors). Must never skip.
run_see_diagnostics_test() {
    local work src0 src1
    src0="$SCRIPT_DIR/tests/shared/flags_0_1.vox"
    src1="$SCRIPT_DIR/tests/shared/flags_1_0.vox"
    work="$(mktemp -d)"

    local sub_msg=""
    local err=""

    # Known-good .so/.lib pair to diagnose against.
    "$VOX_BIN" "$src0" "$src1" --shared -o "$work/libflags.so" >"$work/build.log" 2>&1 \
        || sub_msg="diagnostics (library build)"

    # Each sub-case runs from its own subdir so `see` paths and Location
    # resolve relative to it. $1 = subdir name, $2 = consumer body on stdin.
    # Sets $err to the combined stderr and leaves prog.vox in the subdir.
    run_case() {
        local name="$1" d="$work/$1"
        mkdir -p "$d"
        cat >"$d/prog.vox"
        err=$( { cd "$d" && "$VOX_BIN" prog.vox -o prog ; } 2>&1 )
    }

    if [[ -z "$sub_msg" ]]; then

    # 1. missing .lib — names the path tried and mentions --lib-path. The
    #    consumer's own dir has no .lib, so the search fails immediately.
    run_case missing_lib <<'EOF'
see flags version "0.1" from "./nonexistent.lib".
A number called r is hasflag of 5.
Print the r.
EOF
    if [[ "$err" != *"could not find the library interface file"* ]] \
        || [[ "$err" != *"nonexistent.lib"* ]] || [[ "$err" != *"--lib-path"* ]] \
        || [[ "$err" == *"././"* ]]; then
        sub_msg="diagnostics (missing .lib)"; printf '%s\n' "$err" >"$work/missing_lib.fail"
    fi

    # 2. absent library — lists what the .lib DOES contain.
    mkdir -p "$work/absent_lib"
    cp "$work/libflags.lib" "$work/absent_lib/libflags.lib"
    run_case absent_lib <<'EOF'
see nope version "0.1" from "./libflags.lib".
A number called r is hasflag of 5.
Print the r.
EOF
    if [[ "$err" != *'has no library named "nope"'* ]] \
        || [[ "$err" != *'It declares'* ]] \
        || [[ "$err" != *'"flags" version "0.1"'* ]]; then
        sub_msg="diagnostics (absent library)"; printf '%s\n' "$err" >"$work/absent_lib.fail"
    fi

    # 3. version mismatch — lists the versions on offer.
    mkdir -p "$work/ver_mismatch"
    cp "$work/libflags.lib" "$work/ver_mismatch/libflags.lib"
    run_case ver_mismatch <<'EOF'
see flags version "2.0" from "./libflags.lib".
A number called r is hasflag of 5.
Print the r.
EOF
    if [[ "$err" != *'not version "2.0"'* ]] \
        || [[ "$err" != *"available versions"* ]] \
        || [[ "$err" != *'"0.1"'* ]] || [[ "$err" != *'"1.0"'* ]]; then
        sub_msg="diagnostics (version mismatch)"; printf '%s\n' "$err" >"$work/ver_mismatch.fail"
    fi

    # 4. missing .so at Location — names the resolved path. The .lib is
    #    alone in a dir with no .so, so Location "./libflags.so" misses there.
    mkdir -p "$work/missing_so"
    cp "$work/libflags.lib" "$work/missing_so/libflags.lib"
    run_case missing_so <<'EOF'
see flags version "0.1" from "./libflags.lib".
A number called r is hasflag of 5.
Print the r.
EOF
    if [[ "$err" != *"does not exist at the resolved path"* ]] \
        || [[ "$err" != *"./libflags.so"* ]] || [[ "$err" == *"././"* ]]; then
        sub_msg="diagnostics (missing .so)"; printf '%s\n' "$err" >"$work/missing_so.fail"
    fi

    # 5. stale ToC — a hand-edited .lib promises a symbol the .so does not
    #    export. The diagnostic NAMES THE SYMBOL (flags_0_1_ghostflag).
    mkdir -p "$work/stale"
    cp "$work/libflags.so" "$work/stale/libflags.so"
    sed 's/To hasflag/To ghostflag/' "$work/libflags.lib" >"$work/stale/libflags.lib"
    run_case stale <<'EOF'
see flags version "0.1" from "./libflags.lib".
A number called r is ghostflag of 5.
Print the r.
EOF
    if [[ "$err" != *"does not export it"* ]] \
        || [[ "$err" != *"flags_0_1_ghostflag"* ]] || [[ "$err" != *"stale"* ]] \
        || [[ "$err" == *"././"* ]]; then
        sub_msg="diagnostics (stale ToC)"; printf '%s\n' "$err" >"$work/stale.fail"
    fi

    # 6a. wrong arity — an imported function called with the wrong count is a
    #     compile error (the .lib's signature is the authority here). The .so
    #     must be present: arity is checked in the analyzer, AFTER resolution
    #     and .dynsym verification succeed.
    mkdir -p "$work/arity"
    cp "$work/libflags.so" "$work/arity/libflags.so"
    cp "$work/libflags.lib" "$work/arity/libflags.lib"
    run_case arity <<'EOF'
see flags version "0.1" from "./libflags.lib".
A number called r is hasflag of 5 and 6.
Print the r.
EOF
    if [[ "$err" != *"expects 1 argument"* ]] || [[ "$err" != *"called with 2"* ]]; then
        sub_msg="diagnostics (wrong arity)"; printf '%s\n' "$err" >"$work/arity.fail"
    fi

    # 6b. wrong type — a text argument to a number parameter is a compile
    #     error naming the function, the expected type, and the actual type.
    #     As with arity, the .so must be present (this is an analyzer error).
    mkdir -p "$work/wrongtype"
    cp "$work/libflags.so" "$work/wrongtype/libflags.so"
    cp "$work/libflags.lib" "$work/wrongtype/libflags.lib"
    run_case wrongtype <<'EOF'
see flags version "0.1" from "./libflags.lib".
A number called r is hasflag of "hello".
Print the r.
EOF
    if [[ "$err" != *"expects a number"* ]] \
        || [[ "$err" != *"argument 1"* ]] || [[ "$err" != *"called with text"* ]]; then
        sub_msg="diagnostics (wrong type)"; printf '%s\n' "$err" >"$work/wrongtype.fail"
    fi
    fi

    if [[ -n "$sub_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} see/$sub_msg"
        local cand
        for cand in "$work/missing_lib.fail" "$work/absent_lib.fail" \
                    "$work/ver_mismatch.fail" "$work/missing_so.fail" \
                    "$work/stale.fail" "$work/arity.fail" "$work/wrongtype.fail"; do
            [[ -f "$cand" ]] && { echo "      --- $(basename "$cand") ---"; sed 's/^/      /' "$cand" | head -15; }
        done
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} see/diagnostics (all six named)"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_see_diagnostics_test

# A5 — retire the abandoned `see` syntax. The canonical form
#   see "<lib>" version "<x.y>" from "<path>.lib".
# is the only library import that survives. A bare `see "<path>.vox".` is a
# source include and must keep working. Every other form errors with the
# canonical form — never a silent compile, which was the trap that made the
# stale direct-`.so` docs hazardous.
run_see_retired_forms_test() {
    local work err=""
    work="$(mktemp -d)"
    local sub_msg=""

    # $1 = case name; the program comes on stdin. err captures combined
    # output. None of these should produce a `prog` binary — a silent compile
    # of a retired form is exactly the bug this stage closes.
    run_case() {
        local name="$1" d="$work/$1"
        mkdir -p "$d"
        cat >"$d/prog.vox"
        err=$( { cd "$d" && "$VOX_BIN" prog.vox -o prog ; } 2>&1 )
    }

    if [[ -z "$sub_msg" ]]; then

    # 1. see of a .so — the abandoned direct import. Must say so, show the
    #    canonical form, and point at the .lib. Never compiles silently.
    run_case see_so <<'EOF'
see "./libflags.so".
Print "hi".
EOF
    if [[ -f "$work/see_so/prog" ]] || [[ "$err" != *"see of a .so"* ]] \
        || [[ "$err" != *"Canonical form"* ]] || [[ "$err" != *".lib"* ]]; then
        sub_msg="retired forms (see of .so)"; printf '%s\n' "$err" >"$work/see_so.fail"
    fi

    # 2. retired `from` form (no version): see "<lib>" from "<path>".
    run_case retired_from <<'EOF'
see "flags" from "./libflags.lib".
Print "hi".
EOF
    if [[ -f "$work/retired_from/prog" ]] || [[ "$err" != *"no longer supported"* ]] \
        || [[ "$err" != *"from"* ]] || [[ "$err" != *".lib"* ]]; then
        sub_msg="retired forms (from)"; printf '%s\n' "$err" >"$work/retired_from.fail"
    fi

    # 3. retired `for` form: see "<path>" for "<lib>" version "<ver>".
    run_case retired_for <<'EOF'
see "./libflags.so" for "flags" version "0.1".
Print "hi".
EOF
    if [[ -f "$work/retired_for/prog" ]] || [[ "$err" != *"no longer supported"* ]] \
        || [[ "$err" != *"for"* ]] || [[ "$err" != *".lib"* ]]; then
        sub_msg="retired forms (for)"; printf '%s\n' "$err" >"$work/retired_for.fail"
    fi

    # 4. canonical structure but a .so path — name and version are present, so
    #    this would have compiled silently under the old `process_includes`
    #    marker path. The .so check must still fire.
    run_case canonical_so_path <<'EOF'
see flags version "0.1" from "./libflags.so".
Print "hi".
EOF
    if [[ -f "$work/canonical_so_path/prog" ]] || [[ "$err" != *"see of a .so"* ]] \
        || [[ "$err" != *"Canonical form"* ]]; then
        sub_msg="retired forms (canonical .so path)"; printf '%s\n' "$err" >"$work/canonical_so_path.fail"
    fi

    # 5. .vox source include is unaffected — compiles, runs, prints the value.
    mkdir -p "$work/vox_ok"
    cat >"$work/vox_ok/helper.vox" <<'EOF'
To inc with a number called n. Return a number, n add 1.
EOF
    cat >"$work/vox_ok/prog.vox" <<'EOF'
see "./helper.vox".
A number called r is inc of 41.
Print the r.
EOF
    if ! ( cd "$work/vox_ok" && "$VOX_BIN" prog.vox -o prog >"$work/vox_ok/log" 2>&1 ); then
        sub_msg="retired forms (.vox include compile)"
        { echo "--- prog.vox ---"; cat "$work/vox_ok/prog.vox"; echo "--- log ---"; cat "$work/vox_ok/log"; } >"$work/vox_ok.fail"
    elif ! "$work/vox_ok/prog" >"$work/vox_ok/out" 2>&1 || [[ "$(cat "$work/vox_ok/out")" != "42" ]]; then
        sub_msg="retired forms (.vox include output)"
        { echo "--- out ---"; cat "$work/vox_ok/out"; } >"$work/vox_ok.fail"
    fi

    fi

    if [[ -n "$sub_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} see/$sub_msg"
        local cand
        for cand in "$work"/*.fail; do
            [[ -f "$cand" ]] && { echo "      --- $(basename "$cand") ---"; sed 's/^/      /' "$cand" | head -15; }
        done
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} see/retired forms (all error with canonical; .vox unaffected)"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_see_retired_forms_test

# A4.4 — name resolution. `see` puts foreign names into scope for the first
# time, so two collisions become possible and each has a rule (plan 230, "Name
# resolution"): a LOCAL definition wins over an import, but never silently
# (a warning names the shadowed library); two imports exporting the same name
# are ambiguous and a compile error names the call, both libraries and both
# versions; and a name present in only ONE of two imported versions resolves
# correctly and does not warn (ambiguity is per-name, not per-import). The
# first two are acceptance; the third is the dual that proves the per-name
# rule. Must never skip.
run_see_name_resolution_test() {
    local work math_src other_src p0 p1
    math_src="$SCRIPT_DIR/tests/shared/mathkit_lib.vox"
    other_src="$SCRIPT_DIR/tests/shared/other_lib.vox"
    p0="$SCRIPT_DIR/tests/shared/parts_0_1.vox"
    p1="$SCRIPT_DIR/tests/shared/parts_1_0.vox"
    work="$(mktemp -d)"

    local fail_msg=""
    local fail_log=""

    # Build the three .so/.lib pairs the cases need.
    "$VOX_BIN" "$math_src" --shared -o "$work/libmathkit.so" >"$work/b1.log" 2>&1 || \
        { fail_msg="name-res (mathkit build)"; fail_log="$work/b1.log"; }
    if [[ -z "$fail_msg" ]]; then
    "$VOX_BIN" "$other_src" --shared -o "$work/libother.so" >"$work/b2.log" 2>&1 || \
        { fail_msg="name-res (other build)"; fail_log="$work/b2.log"; }
    fi
    if [[ -z "$fail_msg" ]]; then
    "$VOX_BIN" "$p0" "$p1" --shared -o "$work/libparts.so" >"$work/b3.log" 2>&1 || \
        { fail_msg="name-res (parts build)"; fail_log="$work/b3.log"; }
    fi

    if [[ -z "$fail_msg" ]]; then
    # 1. Shadowing: a local `greet` wins over the imported one. The build
    #    must WARN naming the shadowed library, and the program must call its
    #    OWN greet (print "local greet wins"), not the library's.
    cat >"$work/shadow.vox" <<'EOF'
see mathkit version "1.0" from "./libmathkit.lib".

To greet.
  Print "local greet wins".

greet.
EOF
    if ! "$VOX_BIN" "$work/shadow.vox" -o "$work/shadow" >"$work/shadow_build.log" 2>&1; then
        fail_msg="name-res (shadow build)"; fail_log="$work/shadow_build.log"
    else
        local sb out
        sb=$(cat "$work/shadow_build.log")
        out=$("$work/shadow" 2>/dev/null)
        if [[ "$sb" != *"warning"* ]] || [[ "$sb" != *'library "mathkit" version "1.0"'* ]]; then
            fail_msg="name-res (shadow must WARN naming mathkit 1.0)"
            { echo "build stderr:"; echo "$sb"; } >"$work/shadow.fail"
            fail_log="$work/shadow.fail"
        elif [[ "$out" != "local greet wins" ]]; then
            fail_msg="name-res (shadow called the library, printed '$out')"
            { echo "stdout: $out"; } >"$work/shadow.fail"
            fail_log="$work/shadow.fail"
        fi
    fi
    fi

    if [[ -z "$fail_msg" ]]; then
    # 2. Ambiguity: two imports both exporting `greet` is a compile error
    #    naming both libraries AND both versions.
    cat >"$work/ambig.vox" <<'EOF'
see mathkit version "1.0" from "./libmathkit.lib".
see other version "1.0" from "./libother.lib".

greet.
EOF
    local aerr
    aerr=$("$VOX_BIN" "$work/ambig.vox" -o "$work/ambig" 2>&1)
    local arc=$?
    if [[ $arc -eq 0 ]]; then
        fail_msg="name-res (ambiguity compiled instead of erroring)"
        { echo "built; stdout:"; "$work/ambig" 2>&1; } >"$work/ambig.fail"
        fail_log="$work/ambig.fail"
    elif [[ "$aerr" != *"Call to 'greet' is ambiguous"* ]] \
        || [[ "$aerr" != *'library "mathkit" version "1.0"'* ]] \
        || [[ "$aerr" != *'library "other" version "1.0"'* ]]; then
        fail_msg="name-res (ambiguity error must name both libraries/versions)"
        printf '%s\n' "$aerr" >"$work/ambig.fail"
        fail_log="$work/ambig.fail"
    fi
    fi

    if [[ -z "$fail_msg" ]]; then
    # 3. Function present in only ONE of two imported versions resolves
    #    correctly and does not warn. `only one` is in parts 1.0 only.
    cat >"$work/onlyone.vox" <<'EOF'
see parts version "0.1" from "./libparts.lib".
see parts version "1.0" from "./libparts.lib".
A number called x is 'only one' of 0.
Print the x.
EOF
    if ! "$VOX_BIN" "$work/onlyone.vox" -o "$work/onlyone" >"$work/onlyone_build.log" 2>&1; then
        fail_msg="name-res (only-one build)"; fail_log="$work/onlyone_build.log"
    else
        local ob out
        ob=$(cat "$work/onlyone_build.log")
        out=$("$work/onlyone" 2>/dev/null)
        # Must NOT warn (no local definition, no ambiguity), and must print 42.
        if [[ -n "$ob" ]]; then
            fail_msg="name-res (only-one emitted unexpected output: '$ob')"
            printf 'build stderr: %s\n' "$ob" >"$work/onlyone.fail"
            fail_log="$work/onlyone.fail"
        elif [[ "$out" != "42" ]]; then
            fail_msg="name-res (only-one printed '$out', not 42)"
            { echo "stdout: $out"; } >"$work/onlyone.fail"
            fail_log="$work/onlyone.fail"
        fi
    fi
    fi

    if [[ -n "$fail_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} $fail_msg"
        [ -s "$fail_log" ] && sed 's/^/      /' "$fail_log" | head -20
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} see/name-res (shadow warns, ambiguity errors, only-one resolves)"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_see_name_resolution_test

# A4.5 — BUGS_FOUND #62: a `.lib` entry with no `, returning` clause returns
# nothing (LANGUAGE.md:4963-4965), and step 5 of consuming a library promises
# its calls "type-check like any other function" (LANGUAGE.md:4990). Reading
# such a call's result used to compile silently and hand the consumer whatever
# the call left in the return register — `a number called n is greet.` printed
# 1. The parameter side of that same promise already worked (A4.3's arity and
# type checks), so this closes the return side. Built from the same
# mathkit_lib.vox as A4.1, whose `greet` is exactly the bare entry in
# question; the .lib is asserted bare first, so the case cannot quietly stop
# testing what it claims to. Must never skip.
run_see_void_result_test() {
    local work lib_src
    lib_src="$SCRIPT_DIR/tests/shared/mathkit_lib.vox"
    work="$(mktemp -d)"

    local fail_msg=""
    local fail_log=""

    if ! "$VOX_BIN" "$lib_src" --shared -o "$work/libmathkit.so" >"$work/build.log" 2>&1; then
        fail_msg="see/void-result (library build)"; fail_log="$work/build.log"
    elif ! grep -q '^    To greet\.$' "$work/libmathkit.lib"; then
        fail_msg="see/void-result (greet's .lib entry is no longer the bare void one)"
        fail_log="$work/libmathkit.lib"
    else
        # 1. The bug: greet's result read into a typed variable.
        cat >"$work/read_void.vox" <<'EOF'
see mathkit version "1.0" from "./libmathkit.lib".

a number called n is greet.
Print n.
EOF
        local err rc
        err=$( { cd "$work" && "$VOX_BIN" read_void.vox -o read_void ; } 2>&1 )
        rc=$?
        if [[ $rc -eq 0 ]]; then
            fail_msg="see/void-result (reading a void .lib entry compiled instead of erroring)"
            { echo "built; ran:"; "$work/read_void" 2>&1; } >"$work/read_void.fail"
            fail_log="$work/read_void.fail"
        elif [[ "$err" != *"'greet' has no declared return type in its .lib entry"* ]] \
            || [[ "$err" != *"cannot be used as a value here"* ]] \
            || [[ "$err" != *"read_void.vox:3:22"* ]] \
            || [[ "$err" != *"returning a <type>"* ]] \
            || [[ "$err" != *"call 'greet' as a statement"* ]]; then
            fail_msg="see/void-result (diagnostic must name greet, its .lib entry, the use site and both ways out)"
            printf '%s\n' "$err" >"$work/read_void.fail"
            fail_log="$work/read_void.fail"
        else
            # 2. The controls, in one program: the same void entry CALLED as a
            #    statement, and an entry that does declare a return type read
            #    as a value. Both must still compile and answer.
            cat >"$work/call_void.vox" <<'EOF'
see mathkit version "1.0" from "./libmathkit.lib".

greet.
a number called sum is 'add two numbers' of 3 and 4.
Print sum.
EOF
            if ! ( cd "$work" && "$VOX_BIN" call_void.vox -o call_void ) >"$work/control.log" 2>&1; then
                fail_msg="see/void-result (statement call of a void entry must stay legal)"
                fail_log="$work/control.log"
            else
                local out
                out=$("$work/call_void" 2>"$work/control_run.log")
                if [[ "$out" != $'hi from mathkit\n7' ]]; then
                    fail_msg="see/void-result (control printed '$out', not 'hi from mathkit' then 7)"
                    { echo "stdout: $out"; cat "$work/control_run.log"; } >"$work/control.fail"
                    fail_log="$work/control.fail"
                fi
            fi
        fi
    fi

    if [[ -n "$fail_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} $fail_msg"
        [ -s "$fail_log" ] && sed 's/^/      /' "$fail_log" | head -25
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} see/void-result (a void .lib entry's result is refused, calling it is not)"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_see_void_result_test

# Plan 282: examples/ was never compiled by this test runner at all, which
# is exactly the gap that let a real regression (examples/sh.vox breaking
# under the while-ParagraphBreak fix) ship undetected until someone found
# it by hand. Every .vox under examples/ must compile. mathkit_lib.vox and
# mathkit_consumer.vox are a library/consumer pair (mathkit_consumer.vox
# needs a prebuilt libmathkit.lib next to it, per its own `see` statement)
# so they get built together in a temp dir instead of standalone.
run_examples_compile_check() {
    local examples_dir="$SCRIPT_DIR/examples"
    local fail_list=()
    local f base

    for f in "$examples_dir"/*.vox; do
        base=$(basename "$f" .vox)
        case "$base" in
            mathkit_lib|mathkit_consumer) continue ;;
        esac
        if ! "$VOX_BIN" "$f" -o "$SCRIPT_DIR/.examples_check_bin" >"$SCRIPT_DIR/.examples_check.log" 2>&1; then
            fail_list+=("$base")
        fi
        rm -f "$SCRIPT_DIR/.examples_check_bin"
    done

    # mathkit_lib.vox / mathkit_consumer.vox: build the library, then the
    # consumer against it, in a scratch dir so the produced .lib/.so don't
    # land in examples/ itself.
    local work
    work=$(mktemp -d)
    if ! "$VOX_BIN" "$examples_dir/mathkit_lib.vox" --shared -o "$work/libmathkit.so" >"$work/lib_build.log" 2>&1; then
        fail_list+=("mathkit_lib")
    else
        cp "$examples_dir/mathkit_consumer.vox" "$work/mathkit_consumer.vox"
        if ! ( cd "$work" && "$VOX_BIN" mathkit_consumer.vox -o mathkit_consumer_bin >"$work/consumer_build.log" 2>&1 ); then
            fail_list+=("mathkit_consumer")
        fi
    fi
    rm -rf "$work"
    rm -f "$SCRIPT_DIR/.examples_check.log"

    if [[ ${#fail_list[@]} -gt 0 ]]; then
        echo -e "  ${RED}FAIL${NC} examples/ compile check (${#fail_list[@]} failed: ${fail_list[*]})"
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} examples/ compile check (all .vox under examples/ compile)"
        ((PASSED++))
    fi
}
run_examples_compile_check

# Summary
echo ""
echo -e "${BOLD}=== Summary ===${NC}"
TOTAL=$((PASSED + FAILED + SKIPPED))
echo -e "  ${GREEN}Passed:${NC}  $PASSED"
echo -e "  ${RED}Failed:${NC}  $FAILED"
echo -e "  ${YELLOW}Skipped:${NC} $SKIPPED"
echo -e "  Total:   $TOTAL"
echo ""

# Cleanup all test artifacts (in tests dir and root dir)
rm -f "$SCRIPT_DIR/$TEST_DIR"/*.asm "$SCRIPT_DIR/$TEST_DIR"/*.o 2>/dev/null
rm -f "$SCRIPT_DIR"/*.asm "$SCRIPT_DIR"/*.o 2>/dev/null
find "$SCRIPT_DIR/$TEST_DIR" -maxdepth 1 -type f -executable -delete 2>/dev/null
find "$SCRIPT_DIR" -maxdepth 1 -name "0*" -type f -executable -delete 2>/dev/null

if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}${BOLD}TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL TESTS PASSED${NC}"
    exit 0
fi
