#!/usr/bin/env bash
# Run the compiler's own test runner twice, once with the real nasm and ld
# and once with the stand-ins in this directory first on PATH, so every
# static program the suite builds is linked by vox-elf instead of ld, and
# compare the two runs test by test.
#
# usage: tests/toolchain/shims/compare.sh [REPORT_DIR]
#   REPORT_DIR defaults to a fresh ${TMPDIR:-/tmp}/vox-shim-compare.XXXXXX
#
# The runner is a copy of test.sh with three changes made to it, each
# checked to have taken: it uses the compiler on PATH ($VOX, default vox)
# instead of building one, it skips cargo test (which tests the compiler's
# Rust, not the programs it builds), and it keeps the caller's
# VOX_CORE_PATH. It also records the sha256 of every program it builds,
# before running it. Each run happens in its own scratch copy of this Vox
# tree, outside every source tree, one test at a time: many tests use fixed
# paths under /tmp, so two at once could disturb each other.
#
# Environment: VOX, VOX_CORE_PATH (default /usr/share/vox/coreasm),
# REAL_NASM, REAL_LD, VOXELF_SRC and VOXELF_BUILD (as for the ld stand-in;
# vox-elf is built first if it is missing).
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
vox_tree=$(cd "$here/../../.." && pwd)
export VOX_CORE_PATH=${VOX_CORE_PATH:-/usr/share/vox/coreasm}
export VOX=${VOX:-vox}
export VOXELF_SRC=${VOXELF_SRC:-$vox_tree/tools/voxelf}
export VOXELF_BUILD=${VOXELF_BUILD:-${TMPDIR:-/tmp}/voxelf-build}
report=${1:-$(mktemp -d "${TMPDIR:-/tmp}/vox-shim-compare.XXXXXX")}
mkdir -p "$report"
report=$(cd "$report" && pwd)

started=$(date +%s)
echo "compiler: $(command -v "$VOX") ($("$VOX" --version 2>&1 | head -1))"
echo "runtime:  $VOX_CORE_PATH"
echo "report:   $report"

# vox-elf is built with the real tools, before any stand-in is on PATH.
if [ ! -x "$VOXELF_BUILD/vox-elf" ]; then
    bash "$VOXELF_SRC/build.sh" "$VOXELF_BUILD" > "$report/voxelf-build.log" 2>&1 || {
        echo "could not build vox-elf from $VOXELF_SRC; see $report/voxelf-build.log" >&2
        exit 1
    }
fi
echo "vox-elf:  $VOXELF_BUILD/vox-elf"

# The stand-ins, made executable in a directory of their own.
mkdir -p "$report/shims"
cp "$here/nasm" "$here/ld" "$report/shims/"
chmod 755 "$report/shims/nasm" "$report/shims/ld"

# A scratch copy of the Vox tree for one run. Its coreasm is the runtime the
# compiler uses, so nothing in the copy can stand in for another runtime.
make_copy() {
    local copy=$1
    mkdir -p "$copy"
    tar -C "$vox_tree" --exclude=./.git --exclude=./target --exclude=./coreasm \
        --exclude=./tests/toolchain/shims -cf - . | tar -C "$copy" -xf -
    ln -s "$VOX_CORE_PATH" "$copy/coreasm"
    patch_runner "$copy/test.sh"
}

# Each change replaces one whole line of test.sh, matched exactly, and a
# line that is not found stops the comparison: a runner that has changed
# shape must be looked at, not half patched.
patch_runner() {
    local runner=$1
    replace_line "$runner" 'VOX_BIN="$SCRIPT_DIR/target/release/vox"' \
        'VOX_BIN="$(command -v "${VOX:-vox}")"' || return 1
    replace_line "$runner" 'make build' ': the compiler on PATH is used, so none is built' || return 1
    replace_line "$runner" 'if ! cargo_test' 'if false' || return 1
    replace_line "$runner" 'export VOX_CORE_PATH="$SCRIPT_DIR/coreasm"' 'export VOX_CORE_PATH' || return 1
    replace_line "$runner" '    "$VOX_BIN" "$test_file" > "$tmp_err" 2>&1 || actual_exit=$?' \
        '    "$VOX_BIN" "$test_file" > "$tmp_err" 2>&1 || actual_exit=$?
    if [[ "$actual_exit" == "0" && -f "$exe_path" ]]; then
        echo "$(sha256sum < "$exe_path" | cut -d" " -f1) $basename" >> "$HASH_LOG"
    fi' || return 1
}

replace_line() {
    local file=$1
    if ! OLD=$2 NEW=$3 awk '
            $0 == ENVIRON["OLD"] { print ENVIRON["NEW"]; found = 1; next }
            { print }
            END { exit !found }' "$file" > "$file.patched"; then
        echo "test.sh has no line '$2'; it has changed shape, so the comparison stops" >&2
        exit 1
    fi
    mv "$file.patched" "$file"
}

# One whole run of the runner; its output, with the colours taken out, is
# RUN.log, and the hashes of the programs it built are RUN.hashes.
run_suite() {
    local run=$1 path=$2 copy=$report/$1.tree
    make_copy "$copy"
    : > "$report/$run.hashes"
    local begun=$(date +%s)
    (cd "$copy" && PATH=$path HASH_LOG=$report/$run.hashes SHIM_LOG=$report/$run.shim.log \
        bash ./test.sh -v < /dev/null) 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$report/$run.log"
    echo "$run: $(( $(date +%s) - begun )) seconds"
    rm -rf "$copy"
}

# PASS and FAIL lines as "STATUS KEY". A whole-suite check names itself
# differently when it fails ("two-version flags (driver link)" against
# "two-version/flags"), so its key is its first word, less a trailing
# /lib or /flags.
outcomes() {
    awk '/^  (PASS|FAIL|SKIP) / { key = $2; sub(/\/(lib|flags)$/, "", key); print $1, key }' "$1" \
        | LC_ALL=C sort -k2,2
}

# The verbose block the runner prints under one FAIL line.
failure_block() {
    awk -v key="$2" '
        /^  (PASS|FAIL|SKIP) / { inside = 0 }
        /^  FAIL / { k = $2; sub(/\/(lib|flags)$/, "", k); if (k == key) inside = 1 }
        inside' "$1"
}

: > "$report/baseline.shim.log"
run_suite baseline "$PATH"
run_suite shimmed "$report/shims:$PATH"

outcomes "$report/baseline.log" > "$report/baseline.outcomes"
outcomes "$report/shimmed.log" > "$report/shimmed.outcomes"
LC_ALL=C join -j 2 -a 1 -a 2 -e MISSING -o 0,1.1,2.1 "$report/baseline.outcomes" "$report/shimmed.outcomes" \
    > "$report/joined"

count() { awk -v b="$1" -v s="$2" '$2 ~ b && $3 ~ s' "$report/joined" | wc -l; }
baseline_pass=$(awk '$1 == "PASS"' "$report/baseline.outcomes" | wc -l)
baseline_fail=$(awk '$1 == "FAIL"' "$report/baseline.outcomes" | wc -l)
shimmed_pass=$(awk '$1 == "PASS"' "$report/shimmed.outcomes" | wc -l)
shimmed_fail=$(awk '$1 == "FAIL"' "$report/shimmed.outcomes" | wc -l)
skipped=$(awk '$1 == "SKIP"' "$report/baseline.outcomes" | wc -l)

linked=$(grep -c 'linked with vox-elf' "$report/shimmed.shim.log")
passed_through=$(grep -c 'passed through' "$report/shimmed.shim.log")
link_failures=$(grep -c 'FAILED' "$report/shimmed.shim.log")

# Hashes of the same program built each way.
LC_ALL=C join -j 2 <(LC_ALL=C sort -k2,2 "$report/baseline.hashes") <(LC_ALL=C sort -k2,2 "$report/shimmed.hashes") \
    > "$report/hash-pairs"
hashed=$(wc -l < "$report/hash-pairs")
identical=$(awk '$2 == $3' "$report/hash-pairs" | wc -l)

{
    echo "=== toolchain shim comparison ==="
    echo "baseline (nasm + ld):        $baseline_pass passed, $baseline_fail failed, $skipped skipped"
    echo "shimmed (nasm + vox-elf):    $shimmed_pass passed, $shimmed_fail failed"
    echo "passed in both:              $(count '^PASS$' '^PASS$')"
    echo "failed in both (baseline):   $(count '^FAIL$' '^FAIL$')"
    echo "REGRESSIONS (ld passes, vox-elf fails): $(count '^PASS$' '^FAIL$')"
    echo "fixed (ld fails, vox-elf passes):       $(count '^FAIL$' '^PASS$')"
    echo "in one run only:             $(awk '$2 == "MISSING" || $3 == "MISSING"' "$report/joined" | wc -l)"
    echo "links done by vox-elf:       $linked"
    echo "links passed through to ld:  $passed_through"
    echo "vox-elf link failures:       $link_failures"
    echo "programs hashed both ways:   $hashed, identical sha256: $identical" \
         "(a different hash is expected: vox-elf lays the file out its own way)"
    echo "total time:                  $(( $(date +%s) - started )) seconds"
    echo
    echo "--- failed in both ---"
    awk '$2 == "FAIL" && $3 == "FAIL" { print "  " $1 }' "$report/joined"
    echo "--- in one run only ---"
    awk '$2 == "MISSING" || $3 == "MISSING" { print "  " $1 ": baseline " $2 ", shimmed " $3 }' "$report/joined"
    echo "--- fixed ---"
    awk '$2 == "FAIL" && $3 == "PASS" { print "  " $1 }' "$report/joined"
    echo "--- REGRESSIONS ---"
    awk '$2 == "PASS" && $3 == "FAIL" { print $1 }' "$report/joined" | while read -r key; do
        echo "== $key"
        failure_block "$report/shimmed.log" "$key"
    done
    if [ "$link_failures" -gt 0 ]; then
        echo "--- vox-elf link failures ---"
        grep 'FAILED' "$report/shimmed.shim.log"
    fi
} | tee "$report/summary.txt"

[ "$(count '^PASS$' '^FAIL$')" -eq 0 ]
