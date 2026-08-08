#!/usr/bin/env bash
# HIGH: casting a `value` whose runtime tag is only known dynamically (here,
# from a map read) does not dispatch on the tag - the raw payload (a string
# pointer) is passed through unconverted instead of being parsed, so it
# prints as a large, address-shaped integer instead of the atoi("hello")=0 a
# real conversion would give. Discovered while verifying finding 18's fix
# (routing a heterogeneous-list loop variable into the same `value`
# mechanism) actually has a working escape hatch - it didn't, because THIS
# was already broken underneath it, for any dynamically-tagged `value`, not
# just loop variables. See docs/plans/294_retype_audit.md, finding 21.
# Exits 0 iff the bug is present (compiles AND silently computes garbage).
. "$(dirname "$0")/../lib.sh"
poc_run "$(dirname "$0")/repro.vox"
poc_expect_not "z=0"
