#!/usr/bin/env bash
# HIGH: 'Set X to <text>' updates the value but not the tracked type -> prints the pointer as an integer (Bug B)
# Exits 0 iff the bug is present. See docs/plans/294_retype_audit.md.
. "$(dirname "$0")/../lib.sh"
poc_run "$(dirname "$0")/repro.vox"
poc_expect_not "abc"
