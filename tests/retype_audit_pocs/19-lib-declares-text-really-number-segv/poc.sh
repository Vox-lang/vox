#!/usr/bin/env bash
# CRITICAL: a `.lib` that declares a wrong return type is trusted without any
# check against the `.so` that actually implements it. The consumer then
# dereferences a returned integer as a string pointer -> SIGSEGV.
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

# The lie: 'give number' really returns 42, but the .lib now claims text.
sed -e "s/To 'give number', returning a number./To 'give number', returning a text./" \
    libtkit.lib > lying.lib
grep -q "'give number', returning a text" lying.lib || {
    echo "POC-ERROR: .lib format changed; tamper did not apply" >&2
    cat libtkit.lib >&2; exit 3; }

cat > consumer.vox <<'VOX'
see tkit version "1.0" from "./lying.lib".

a text called t is 'give number'.
Print "[{t}]".
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
if [ $rrc -eq 139 ]; then
    echo "REPRODUCED: SIGSEGV - .lib type lie trusted across the module boundary"
    exit 0
fi
echo "NOT REPRODUCED: exit=$rrc output=[$(cat run.log)]"
exit 1
