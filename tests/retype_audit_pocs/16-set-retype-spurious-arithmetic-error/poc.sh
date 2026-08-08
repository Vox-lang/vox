#!/usr/bin/env bash
# MEDIUM: after 'Set X to <number>' retypes a text variable at runtime, the analyzer still calls it text and rejects valid arithmetic
# Exits 0 iff the bug is present. See docs/plans/294_retype_audit.md.
. "$(dirname "$0")/../lib.sh"
poc_run "$(dirname "$0")/repro.vox"
poc_expect_compile_error "Cannot use text s in arithmetic"
