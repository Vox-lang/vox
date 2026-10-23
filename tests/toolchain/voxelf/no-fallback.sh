#!/usr/bin/env bash
# The reference check.sh compares with is ld's output and nothing else. This
# runs check.sh on a corpus of three copies of examples/hello.vox, one in each
# place check.sh takes programs from, with an ld first on PATH that refuses to
# link the reference for examples/hello and hands every other call to the real
# ld. The run must fail, name examples/hello and what ld said, and still link
# and compare the other two, so the refusal is the only thing that fails it.
# Nothing may stand in for the reference ld did not write: not the compiler's
# own build, which runs from a copy of the program's directory and is not
# refused here, and not a build left over from before.
#
# usage: tests/toolchain/voxelf/no-fallback.sh
# Environment: as for check.sh, but for VOXOS_SRC and COREUTILS_SRC, which
# this test makes for itself.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
vox_tree=$(cd "$here/../../.." && pwd)
export VOXELF_BUILD=${VOXELF_BUILD:-${TMPDIR:-/tmp}/voxelf-build}
if [ ! -x "$VOXELF_BUILD/vox-elf" ]; then
    bash "$vox_tree/tools/voxelf/build.sh" "$VOXELF_BUILD" > /dev/null || exit 1
fi
work=$(mktemp -d "${TMPDIR:-/tmp}/voxelf-no-fallback.XXXXXX")
trap 'rm -rf "$work"' EXIT
passes=0 failures=0
pass() { passes=$((passes + 1)); }
fail() { failures=$((failures + 1)); printf '  FAIL %s\n' "$1"; }

# A tree with check.sh and what it runs, and the three corpora, each holding
# the one program.
tree=$work/tree
mkdir -p "$tree/tests/toolchain/voxelf" "$tree/tools/voxelf" "$tree/examples" \
    "$work/voxos/system" "$work/coreutils/hello" "$work/coreutils/test"
cp "$here/check.sh" "$here/same-bytes.sh" "$here/ld-trace.sh" "$tree/tests/toolchain/voxelf/"
cp "$vox_tree/tools/voxelf/nasm-image.sh" "$tree/tools/voxelf/"
cp "$vox_tree/examples/hello.vox" "$tree/examples/"
cp "$vox_tree/examples/hello.vox" "$work/voxos/system/"
cp "$vox_tree/examples/hello.vox" "$work/coreutils/hello/"
printf '#!/usr/bin/env bash\nmkdir -p "$1"\n' > "$work/coreutils/test/corpus.sh"

# The planted failure: ld refuses in the directory check.sh links the
# reference for examples/hello in, and nowhere else.
real_ld=$(command -v ld)
mkdir -p "$work/planted"
cat > "$work/planted/ld" <<EOF
#!/usr/bin/env bash
case \$PWD in
    */programs/examples/hello) echo "ld: the reference for examples/hello is refused by this test" >&2; exit 1 ;;
esac
exec "$real_ld" "\$@"
EOF
chmod +x "$work/planted/ld"

PATH=$work/planted:$PATH VOXOS_SRC=$work/voxos COREUTILS_SRC=$work/coreutils \
    bash "$tree/tests/toolchain/voxelf/check.sh" > "$work/said" 2>&1
status=$?

if [ "$status" -ne 0 ]; then pass; else fail "check.sh passed with ld refusing the reference for examples/hello"; fi
if grep -qF "DIFFERED: examples/hello (ld could not link the reference: ld: the reference for examples/hello is refused by this test)" "$work/said"; then
    pass
else
    fail "check.sh did not name examples/hello and what ld said: [$(grep -E 'DIFFERED|differential' "$work/said" | head -5)]"
fi
if grep -qF "voxelf differential: same bytes 2 of 2 static;" "$work/said" && grep -qF "1 failed" "$work/said"; then
    pass
else
    fail "check.sh did not link and compare the other two, with only examples/hello failing: [$(grep 'differential' "$work/said")]"
fi
if grep -q "ran identically to ld's build: 2 programs: voxos/hello coreutils/hello$" "$work/said"; then
    pass
else
    fail "examples/hello was run against something ld did not write: [$(grep 'ran identically' "$work/said")]"
fi

echo "voxelf reference without fallback: $passes passed, $failures failed"
[ "$failures" -eq 0 ]
