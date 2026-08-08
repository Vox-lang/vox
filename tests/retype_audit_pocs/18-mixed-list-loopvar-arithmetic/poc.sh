#!/usr/bin/env bash
# HIGH: arithmetic on a for-each loop variable over a HETEROGENEOUS list does
# not dispatch on the element's runtime tag - the text element's pointer is
# used as an integer operand. Printing the same variable DOES dispatch on the
# tag and is correct, which is what makes this easy to miss.
#
# Exits 0 iff the bug is present. See docs/plans/294_retype_audit.md.
#
# Symptom: the second iteration prints a pointer-sized integer. No correct
# behaviour produces that - a fix either rejects the program at compile time
# (poc_run reports the compile failure, and we exit 1) or produces a value
# derived from the text element rather than its address.
. "$(dirname "$0")/../lib.sh"
poc_run "$(dirname "$0")/repro.vox"

if [ "$POC_CRC" -ne 0 ]; then
    echo "NOT REPRODUCED: program no longer compiles (rc=$POC_CRC)"
    echo "$POC_COUT" | head -5
    exit 1
fi
if [ "$POC_RRC" -ne 0 ]; then
    echo "REPRODUCED (worse): program crashed, exit=$POC_RRC"
    exit 0
fi

first=$(echo "$POC_OUT" | sed -n 1p)
second=$(echo "$POC_OUT" | sed -n 2p)

# The numeric element must still work; if it does not, this PoC is measuring
# something else and should not silently claim the bug.
if [ "$first" != "z=43" ]; then
    echo "INCONCLUSIVE: expected first line 'z=43', got '$first'"
    exit 1
fi
if echo "$second" | grep -qE '^z=[0-9]{5,}$'; then
    echo "REPRODUCED: text element's pointer used as an integer operand -> '$second'"
    exit 0
fi
echo "NOT REPRODUCED: second line is '$second'"
exit 1
