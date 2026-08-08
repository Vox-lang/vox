#!/usr/bin/env bash
# CRITICAL: for-range loop variable reusing a text name; codegen never retypes it -> SIGSEGV
# Exits 0 iff the bug is present. See docs/plans/294_retype_audit.md.
. "$(dirname "$0")/../lib.sh"
poc_run "$(dirname "$0")/repro.vox"
poc_expect_segv
