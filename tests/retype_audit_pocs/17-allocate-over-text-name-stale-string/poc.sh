#!/usr/bin/env bash
# LOW: 'Allocate N for X' over a text name drops the analyzer label but leaves codegen tracking it as text
# Exits 0 iff the bug is present. See docs/plans/294_retype_audit.md.
. "$(dirname "$0")/../lib.sh"
poc_run "$(dirname "$0")/repro.vox"
poc_expect_empty_output
