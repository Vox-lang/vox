#!/usr/bin/env bash
# HIGH: number variable assigned a text map value keeps integer tracking -> prints the pointer as an integer
# Exits 0 iff the bug is present. See docs/plans/294_retype_audit.md.
. "$(dirname "$0")/../lib.sh"
poc_run "$(dirname "$0")/repro.vox"
poc_expect_not "abc"
