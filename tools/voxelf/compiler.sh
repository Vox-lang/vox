# Sourced by tools/voxelf/build.sh and tests/toolchain/voxelf/test.sh. Sets
# $vox to the compiler voxelf is built with, and defines
# check_the_compiler, which refuses a compiler that lacks the fixes voxelf
# needs.
#
# The compiler is $VOX when that is set, else this tree's own
# target/release/vox when it has been built, else the vox on PATH. voxelf
# needs fixes that are on Vox main and in no release up to 0.4.16
# (docs/bugs/unreleased.md, #128, #156 and #160), and a compiler built from
# main before them says it is 0.4.16, as the release does. So the compiler is
# asked, not its version string: fixes-it-needs.vox is compiled and run, and
# must give the answer a compiler with every one of the fixes gives.
voxelf_tree=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
if [ -n "${VOX:-}" ]; then
    vox=$VOX
elif [ -x "$voxelf_tree/target/release/vox" ]; then
    vox=$voxelf_tree/target/release/vox
    # The tree's compiler is built against the tree's own runtime.
    export VOX_CORE_PATH=${VOX_CORE_PATH:-$voxelf_tree/coreasm}
else
    vox=$(command -v vox || echo vox)
fi

check_the_compiler() {
    local probe answer expected
    expected='a named map is a copy: 1
a section read out and appended: [{"name": ".text"}]
after an Otherwise: 2 rounds, then 1 line after the loop'
    probe=$(mktemp -d "${TMPDIR:-/tmp}/voxelf-probe.XXXXXX")
    cp "$voxelf_tree/tools/voxelf/fixes-it-needs.vox" "$probe/"
    # In a scratch directory, so the compiler does not run inside a source tree
    answer=$(cd "$probe" && "$vox" fixes-it-needs.vox -o fixes-it-needs > compile.log 2>&1 \
        && ./fixes-it-needs 2>&1) || answer="$answer (it did not compile, or it stopped with status $?)"
    rm -rf "$probe"
    if [ "$answer" != "$expected" ]; then
        echo "$0: $vox lacks fixes voxelf needs (unreleased after 0.4.16: docs/bugs/unreleased.md #128, #156, #160); build with the vox from this tree, target/release/vox, built from Vox main at or after commit 1aee89e, or with the first release after 0.4.16, which carries them." >&2
        echo "$0: tools/voxelf/fixes-it-needs.vox, built with $vox, answered:" >&2
        printf '%s\n' "$answer" | sed 's/^/  /' >&2
        return 1
    fi
}
