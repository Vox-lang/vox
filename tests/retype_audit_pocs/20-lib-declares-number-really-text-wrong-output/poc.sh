#!/usr/bin/env bash
# HIGH: the benign direction of finding 19. A `.lib` declares a NUMBER return
# for a function that really returns text, and nothing checks the `.lib`
# against the `.so` that implements it. The consumer prints the string's
# ADDRESS as an integer instead of the string.
#
# The `.so` is NEVER modified: it is built once from tkit_lib.vox and is
# correct. Only the `.lib`'s plain-text Table of Contents is edited, which is
# what a hand-written, stale, or hostile `.lib` would look like.
#
# `src/lib_file.rs:597-605` does verify every ToC symbol against the `.so`'s
# .dynsym - but the mangled name is `<lib>_<version>_<function>` and carries
# no type information, so symbol verification cannot detect this.
#
# Exits 0 iff the bug is present. Exit 3 = could not run the experiment.
# See docs/plans/294_retype_audit.md (follow-up section).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
vox="$root/target/release/vox"
[ -x "$vox" ] || { echo "POC-ERROR: no vox at $vox (cargo build --release)" >&2; exit 3; }

d="$(mktemp -d /tmp/voxpoc19.XXXXXX)" || { echo "POC-ERROR: mktemp failed" >&2; exit 3; }
trap 'rm -rf "$d"' EXIT
cp "$here/tkit_lib.vox" "$d/" || { echo "POC-ERROR: missing tkit_lib.vox" >&2; exit 3; }
cd "$d" || exit 3

"$vox" tkit_lib.vox --shared -o libtkit.so > build.log 2>&1 || {
    echo "POC-ERROR: library build failed" >&2; sed -n 1,10p build.log >&2; exit 3; }
[ -f libtkit.lib ] || { echo "POC-ERROR: no .lib emitted" >&2; exit 3; }

# The lie: 'give text' really returns "abc", but the .lib now claims number.
sed -e "s/To 'give text', returning a text./To 'give text', returning a number./" \
    libtkit.lib > lying.lib
grep -q "'give text', returning a number" lying.lib || {
    echo "POC-ERROR: .lib format changed; tamper did not apply" >&2
    cat libtkit.lib >&2; exit 3; }

cat > consumer.vox <<'VOX'
see tkit version "1.0" from "./lying.lib".

a number called v is 'give text'.
Print "[{v}]".
VOX

"$vox" consumer.vox -o consumer > consume.log 2>&1
crc=$?
if [ $crc -ne 0 ]; then
    echo "NOT REPRODUCED: consumer no longer compiles (rc=$crc) - the .lib/.so"
    echo "type disagreement is now detected at build time:"
    sed -n 1,6p consume.log
    exit 1
fi

# Run in a child shell whose stderr is discarded, so the shell's own
# "Segmentation fault (core dumped)" job message does not pollute the verdict.
bash -c './consumer > run.log 2>&1' 2>/dev/null
rrc=$?
out="$(cat run.log)"
if [ $rrc -ne 0 ]; then
    echo "REPRODUCED (worse): consumer crashed, exit=$rrc"
    exit 0
fi
# Correct behaviour prints the string. The bug prints its address: a bare
# pointer-sized integer, which no correct rendering of "abc" can produce.
if echo "$out" | grep -qE '^\[[0-9]{6,}\]$'; then
    echo "REPRODUCED: string address printed as an integer -> $out"
    exit 0
fi
echo "NOT REPRODUCED: output=[$out]"
exit 1
