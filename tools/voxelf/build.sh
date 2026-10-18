#!/usr/bin/env bash
# Build the voxelf library both ways it is used, into one build directory:
#   libvoxelf.so and libvoxelf.lib  the shared library and its interface
#   vox-elf                         the static wrapper, voxelf seen as source
#
# usage: tools/voxelf/build.sh [BUILD_DIR]
#   BUILD_DIR defaults to $VOXELF_BUILD, else ${TMPDIR:-/tmp}/voxelf-build.
#
# The sources are copied into the build directory and compiled there, so
# the compiler never runs inside a source tree. Run from a directory that
# holds another Vox checkout, vox can pick up that checkout's runtime
# instead of the one VOX_CORE_PATH names.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
build=${1:-${VOXELF_BUILD:-${TMPDIR:-/tmp}/voxelf-build}}
export VOX_CORE_PATH=${VOX_CORE_PATH:-/usr/share/vox/coreasm}
vox=${VOX:-vox}

mkdir -p "$build"
build=$(cd "$build" && pwd)
cp "$here/voxelf.vox" "$here/voxelf-body.vox" "$here/vox-elf.vox" "$build/"
cd "$build"

"$vox" voxelf.vox --shared -o libvoxelf.so
"$vox" vox-elf.vox -o vox-elf

echo "built $build/libvoxelf.so, $build/libvoxelf.lib and $build/vox-elf"
echo "exported symbols:"
nm -D --defined-only libvoxelf.so | sed 's/^/  /'
