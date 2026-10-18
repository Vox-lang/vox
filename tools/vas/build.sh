#!/usr/bin/env bash
# Build vas both ways it is used, into one build directory:
#   vas                       the static command: the vas library and voxelf,
#                             seen as source, behind vas-command.vox
#   libvas.so and libvas.lib  the shared library and its interface
#
# usage: tools/vas/build.sh [BUILD_DIR]
#   BUILD_DIR defaults to $VAS_BUILD, else ${TMPDIR:-/tmp}/vas-build.
#
# The sources are copied into the build directory, keeping the two
# directories side by side as vas.vox's `see "../voxelf/voxelf-body.vox"`
# needs, and compiled there, so the compiler never runs inside a source
# tree. Run from a directory that holds another Vox checkout, vox can pick
# up that checkout's runtime instead of the one VOX_CORE_PATH names.
#
# The shared build is checked as well as made: it must export the entries
# under vas's own name, so a change that moved them into another library
# fails here rather than in a caller.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
build=${1:-${VAS_BUILD:-${TMPDIR:-/tmp}/vas-build}}
export VOX_CORE_PATH=${VOX_CORE_PATH:-/usr/share/vox/coreasm}
vox=${VOX:-vox}

mkdir -p "$build/source/vas" "$build/source/voxelf"
build=$(cd "$build" && pwd)
cp "$here/vas.vox" "$here/encoder.vox" "$here/assembler.vox" "$here/vas-command.vox" "$build/source/vas/"
cp "$here/../voxelf/voxelf-body.vox" "$build/source/voxelf/"
cd "$build/source/vas"

"$vox" vas-command.vox -o "$build/vas"
"$vox" vas.vox --shared -o "$build/libvas.so"

# The exports are read once: grep -q stops reading at its first match, and
# under pipefail the writer it leaves behind would fail the pipe.
exports=$(nm -D --defined-only "$build/libvas.so")
for entry in assemble_the_file assemble_file_counting_errors expand_file assembler_diagnostics; do
    if ! grep -qw "vas_0_1_$entry" <<<"$exports"; then
        echo "$0: libvas.so does not export vas_0_1_$entry" >&2
        exit 1
    fi
done
if ! grep -q "^Library vas version \"0.1\"\.$" "$build/libvas.lib"; then
    echo "$0: libvas.lib does not name library vas, version 0.1" >&2
    exit 1
fi

echo "built $build/vas, $build/libvas.so and $build/libvas.lib"
