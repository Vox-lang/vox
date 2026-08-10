#!/bin/bash
# Lint: buffer/list/map header offsets must be named, not literal 24.
# This is the regression guard for the constants refactor in B1.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0

check_empty() {
    local desc="$1"
    shift
    local out
    out="$($@ 2>/dev/null || true)"
    if [[ -n "$out" ]]; then
        echo "FAIL: $desc"
        echo "$out"
        fail=1
    fi
}

# No orphan literal 24 in codegen (allow comments, test attrs, and the named constants).
check_empty "literal 24 remains in src/codegen/mod.rs" \
    sh -c 'grep -nE "\b24\b" src/codegen/mod.rs | grep -v "BUF_DATA_OFFSET\|LIST_DATA_OFFSET\|MAP_HEADER_SIZE\|#\[test\]\|//.*24"'

# io.asm and file.asm must use BUF_DATA, not a literal 24 offset.
check_empty "literal 24 add in coreasm/x86_64/io.asm or file.asm" \
    sh -c 'grep -n "add rsi, 24\|add rdi, 24" coreasm/x86_64/io.asm coreasm/x86_64/file.asm'

if [[ "$fail" -ne 0 ]]; then
    exit 1
fi

echo "PASS: header offsets are named constants, no literal 24 consumers remain"
