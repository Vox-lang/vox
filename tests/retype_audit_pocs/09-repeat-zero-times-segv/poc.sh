#!/usr/bin/env bash
# CRITICAL: assignment in a 'Repeat 0 times' body retypes the variable -> SIGSEGV
# Exits 0 iff the bug is present. See docs/plans/294_retype_audit.md.
. "$(dirname "$0")/../lib.sh"
poc_run "$(dirname "$0")/repro.vox"
poc_expect_segv
