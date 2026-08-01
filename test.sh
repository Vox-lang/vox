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
# without requiring a system install. The compiler reads EC_CORE_PATH
# (not VOX_CORE_PATH) and expects the coreasm directory itself, so point
# it at $SCRIPT_DIR/coreasm. Without this the override was a no-op and a
# present system install at /usr/local/share/vox/coreasm would shadow
# the in-repo runtime.
export EC_CORE_PATH="$SCRIPT_DIR/coreasm"

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
        #     A4. `makebuf` is a multi-statement body, so the parser does not
        #     capture its return type (a known A3 gap, see the report); its ToC
        #     entry reads `To "makebuf".` with no `, returning` clause. The
        #     other two are single-line defs whose typed `Return a number, ...`
        #     is captured, so they carry `, returning a number`.
        local lib_exp
        lib_exp=$(printf 'Library "mathkit" version "1.0".\nLocation "./libmath.so".\n\nTable of Contents:\n    To "add two numbers" with a number called "n", returning a number.\n    To "greet".\n    To "makebuf".\n')
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
        lib_exp=$(printf 'Library "flags" version "0.1".\nLocation "./libflags.so".\n\nTable of Contents:\n    To "hasflag" with a number called "n", returning a number.\n\nLibrary "flags" version "1.0".\nLocation "./libflags.so".\n\nTable of Contents:\n    To "hasflag" with a number called "n", returning a number.\n')
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

# A3 clobber-refusal test (plan 230 stage A3; the same hazard class as plan 210
# P1, where `--shared` silently destroyed a user's `.map`). A `--shared` build
# writes `<stem>.lib` beside the `.so`; if that `.lib` already exists, vox must
# refuse to overwrite it and abort *before* building, rather than silently
# destroying a file it did not create. Pre-creates a sentinel `.lib`, runs a
# shared build that would target it, and asserts the build errored, the
# sentinel is untouched, and no `.so` was produced (so the pair cannot disagree).
# It must never report "skipped": clobbering a file the user owns is the one
# silent failure most worth a loud test.
run_lib_clobber_refusal_test() {
    local work lib_src sentinel rc fail_msg
    lib_src="$SCRIPT_DIR/tests/shared/libmath.vox"
    work="$(mktemp -d)"
    sentinel="THIS IS A HAND-WRITTEN .lib — DO NOT OVERWRITE"
    printf '%s\n' "$sentinel" > "$work/libmath.lib"

    "$VOX_BIN" "$lib_src" --shared -o "$work/libmath.so" >"$work/build.log" 2>&1
    rc=$?

    fail_msg=""
    if [[ $rc -eq 0 ]]; then
        fail_msg="clobber-refusal (build succeeded instead of refusing)"
    elif ! diff -q <(printf '%s\n' "$sentinel") "$work/libmath.lib" >/dev/null 2>&1; then
        fail_msg="clobber-refusal (sentinel .lib was modified)"
    elif [[ -e "$work/libmath.so" ]]; then
        fail_msg="clobber-refusal (.so created despite .lib clobber)"
    fi

    if [[ -n "$fail_msg" ]]; then
        echo -e "  ${RED}FAIL${NC} $fail_msg"
        [ -s "$work/build.log" ] && sed 's/^/      /' "$work/build.log" | head -20
        ((FAILED++))
    else
        echo -e "  ${GREEN}PASS${NC} clobber-refusal/lib"
        ((PASSED++))
    fi
    rm -rf "$work"
}
run_lib_clobber_refusal_test

# A3 table-of-contents completeness (plan 230). A bodyless function —
# `To "greet".` with no body and no separating blank line — used to absorb the
# following `To "c" ...` as a nested definition, so `c` was exported by the .so
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
