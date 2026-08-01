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
    run_runtime_test "$(basename "$runtime_test" .asm)"
done

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
