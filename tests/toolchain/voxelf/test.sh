#!/usr/bin/env bash
# Every voxelf test, in order: build the library and the wrapper, the header
# and layout unit tests, the refusals and the path-based surface, the
# hand-written layouts compared with ld byte for byte, then the differential
# test of the corpus against ld.
#
# usage: tests/toolchain/voxelf/test.sh
# Environment: as for check.sh. VOXOS_SRC and COREUTILS_SRC are required,
# so that every run compares the whole corpus.
set -uo pipefail

if [ -z "${VOXOS_SRC:-}" ]; then
    echo "$0: VOXOS_SRC is not set; set it to a Vox OS checkout, whose system programs are part of the corpus." >&2
    exit 1
fi
if [ -z "${COREUTILS_SRC:-}" ]; then
    echo "$0: COREUTILS_SRC is not set; set it to a vox-coreutils checkout, whose tools and suites are part of the corpus." >&2
    exit 1
fi
export VOXOS_SRC COREUTILS_SRC

here=$(cd "$(dirname "$0")" && pwd)
vox_tree=$(cd "$here/../../.." && pwd)
# The compiler is the one build.sh takes, refused as build.sh refuses it
# when it lacks the fixes voxelf needs (tools/voxelf/compiler.sh).
source "$vox_tree/tools/voxelf/compiler.sh"
export VOX_CORE_PATH=${VOX_CORE_PATH:-/usr/share/vox/coreasm}
export VOXELF_BUILD=${VOXELF_BUILD:-${TMPDIR:-/tmp}/voxelf-build}
check_the_compiler || exit 1
failed=0

scratch=$(mktemp -d "${TMPDIR:-/tmp}/voxelf-test.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
# Every test runs that same compiler as vox, first on PATH.
mkdir -p "$scratch/compiler"
ln -s "$(command -v "$vox")" "$scratch/compiler/vox"
export PATH=$scratch/compiler:$PATH VOX=$scratch/compiler/vox

bash "$vox_tree/tools/voxelf/build.sh" "$VOXELF_BUILD" || exit 1

# The unit tests see voxelf.vox by a path relative to themselves, so they
# are compiled where they stand, from a scratch directory, into it.
mkdir -p "$scratch/tests/toolchain/voxelf" "$scratch/tools/voxelf"
cp "$here/headers.vox" "$scratch/tests/toolchain/voxelf/"
cp "$vox_tree/tools/voxelf/voxelf.vox" "$vox_tree/tools/voxelf/voxelf-body.vox" "$scratch/tools/voxelf/"
if (cd "$scratch/tests/toolchain/voxelf" && vox headers.vox -o headers); then
    "$scratch/tests/toolchain/voxelf/headers" || failed=1
else
    echo "headers.vox does not compile"; failed=1
fi

bash "$here/refusals.sh" || failed=1
bash "$here/layouts.sh" || failed=1
bash "$here/no-fallback.sh" || failed=1
bash "$here/check.sh" || failed=1
exit "$failed"
