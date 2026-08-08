#!/usr/bin/env bash
# CRITICAL: 'open a file ... called X' over an existing text name stores an fd but keeps text tracking -> SIGSEGV
# Exits 0 iff the bug is present. See docs/plans/294_retype_audit.md.
. "$(dirname "$0")/../lib.sh"
poc_run "$(dirname "$0")/repro.vox"
poc_expect_segv
