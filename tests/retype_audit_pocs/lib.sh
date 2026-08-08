# Shared helpers for the plan 294 retype-audit PoCs.
#
# CONTRACT: every poc.sh exits 0 if and only if the bug it documents is
# still present. When the bug is fixed the same script must exit non-zero.
# That direction is what makes these usable as fix-verification.
#
# Exit 3 is reserved for "could not run the experiment at all" (missing
# compiler, failed temp dir). It is non-zero, so an infrastructure failure
# never reads as "bug present".

set -u

poc_root() { cd "$(dirname "${BASH_SOURCE[1]}")/../../.." && pwd; }

# Compile+run $1 (a .vox path) in a private temp dir. A compiled Vox program
# is dropped in the CWD, so this never runs inside the repo.
# Sets: POC_CRC (compile rc), POC_COUT (compiler output),
#       POC_RRC (run rc), POC_OUT (program stdout+stderr).
poc_run() {
    local src="$1" root vox d
    root="$(cd "$(dirname "${BASH_SOURCE[1]}")/../../.." && pwd)"
    vox="$root/target/release/vox"
    if [ ! -x "$vox" ]; then
        echo "POC-ERROR: no vox binary at $vox (run: cargo build --release)" >&2
        exit 3
    fi
    d="$(mktemp -d /tmp/voxpoc.XXXXXX)" || { echo "POC-ERROR: mktemp failed" >&2; exit 3; }
    cp "$src" "$d/p.vox" || { rm -rf "$d"; echo "POC-ERROR: cannot read $src" >&2; exit 3; }
    # The inner subshell's stderr is discarded so the shell's own
    # "Segmentation fault (core dumped)" job message does not pollute the
    # PoC verdict. The child's own stderr is already captured in run.log.
    (
        cd "$d" || exit 3
        "$vox" p.vox -o p.bin > compile.log 2>&1
        echo "$?" > compile.rc
        if [ -x ./p.bin ]; then
            ./p.bin > run.log 2>&1
            echo "$?" > run.rc
        else
            echo "" > run.log
            echo "-1" > run.rc
        fi
    ) 2>/dev/null
    POC_CRC="$(cat "$d/compile.rc" 2>/dev/null || echo 3)"
    POC_COUT="$(cat "$d/compile.log" 2>/dev/null || true)"
    POC_RRC="$(cat "$d/run.rc" 2>/dev/null || echo -1)"
    POC_OUT="$(cat "$d/run.log" 2>/dev/null || true)"
    rm -rf "$d"
}

# Bug present iff the program died on SIGSEGV (128+11).
poc_expect_segv() {
    if [ "$POC_CRC" -ne 0 ]; then
        echo "NOT REPRODUCED: program no longer compiles (rc=$POC_CRC)"
        echo "$POC_COUT" | head -5
        exit 1
    fi
    if [ "$POC_RRC" -eq 139 ]; then
        echo "REPRODUCED: SIGSEGV (exit 139) - memory-unsafe type confusion present"
        exit 0
    fi
    echo "NOT REPRODUCED: exit=$POC_RRC output=[$POC_OUT]"
    exit 1
}

# Bug present iff the program ran but printed something other than $1.
poc_expect_not() {
    local want="$1"
    if [ "$POC_CRC" -ne 0 ]; then
        echo "NOT REPRODUCED: program no longer compiles (rc=$POC_CRC)"
        echo "$POC_COUT" | head -5
        exit 1
    fi
    if [ "$POC_RRC" -ne 0 ]; then
        echo "REPRODUCED (worse): program crashed, exit=$POC_RRC"
        exit 0
    fi
    if [ "$POC_OUT" = "$want" ]; then
        echo "NOT REPRODUCED: got the correct output [$want]"
        exit 1
    fi
    echo "REPRODUCED: expected [$want], got [$POC_OUT]"
    exit 0
}

# Bug present iff the program printed nothing at all. Used where the stale
# type makes codegen read a freshly-zeroed allocation as a C string: the
# empty output IS the symptom. Correct tracking would print the pointer as
# a number, i.e. something non-empty.
poc_expect_empty_output() {
    if [ "$POC_CRC" -ne 0 ]; then
        echo "NOT REPRODUCED: program no longer compiles (rc=$POC_CRC)"
        echo "$POC_COUT" | head -5
        exit 1
    fi
    if [ "$POC_RRC" -ne 0 ]; then
        echo "REPRODUCED (worse): program crashed, exit=$POC_RRC"
        exit 0
    fi
    if [ -z "$POC_OUT" ]; then
        echo "REPRODUCED: printed nothing - the pointer was rendered as a C string"
        exit 0
    fi
    echo "NOT REPRODUCED: printed [$POC_OUT]"
    exit 1
}

# Bug present iff compilation failed with a message matching $1.
poc_expect_compile_error() {
    local pat="$1"
    if [ "$POC_CRC" -eq 0 ]; then
        echo "NOT REPRODUCED: program compiles now"
        exit 1
    fi
    if echo "$POC_COUT" | grep -qi -- "$pat"; then
        echo "REPRODUCED: spurious compile error matching [$pat]"
        exit 0
    fi
    echo "NOT REPRODUCED: failed, but not with [$pat]:"
    echo "$POC_COUT" | head -5
    exit 1
}
