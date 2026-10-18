#!/usr/bin/env bash
# Every voxelf test, in order: build the library and the wrapper, the header
# and layout unit tests, the refusals and the path-based surface, then the
# differential test against ld.
#
# usage: tests/toolchain/voxelf/test.sh
# Environment: as for check.sh.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
vox_tree=$(cd "$here/../../.." && pwd)
export VOX_CORE_PATH=${VOX_CORE_PATH:-/usr/share/vox/coreasm}
export VOXELF_BUILD=${VOXELF_BUILD:-${TMPDIR:-/tmp}/voxelf-build}
failed=0

bash "$vox_tree/tools/voxelf/build.sh" "$VOXELF_BUILD" || exit 1

# The unit tests see voxelf.vox by a path relative to themselves, so they
# are compiled where they stand, from a scratch directory, into it.
scratch=$(mktemp -d "${TMPDIR:-/tmp}/voxelf-test.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/tests/toolchain/voxelf" "$scratch/tools/voxelf"
cp "$here/headers.vox" "$scratch/tests/toolchain/voxelf/"
cp "$vox_tree/tools/voxelf/voxelf.vox" "$vox_tree/tools/voxelf/voxelf-body.vox" "$scratch/tools/voxelf/"
if (cd "$scratch/tests/toolchain/voxelf" && vox headers.vox -o headers); then
    "$scratch/tests/toolchain/voxelf/headers" || failed=1
else
    echo "headers.vox does not compile"; failed=1
fi

bash "$here/refusals.sh" || failed=1
bash "$here/check.sh" || failed=1
exit "$failed"
