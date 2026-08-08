#!/usr/bin/env bash
# HIGH: Decrement on a text-tracked variable moves the pointer before the string and reads out of bounds
# Exits 0 iff the bug is present. See docs/plans/294_retype_audit.md.
. "$(dirname "$0")/../lib.sh"
poc_run "$(dirname "$0")/repro.vox"
poc_expect_not "[hello]"
