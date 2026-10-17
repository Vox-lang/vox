#!/bin/bash
#
# Regenerate tests/corpus/: the assembly the installed compiler emits for
# every example, every voxos program, every vox-coreutils tool and every
# vox-libs library. The corpus is committed so the assembler and ELF writer
# tests run without the compiler. Run this again after any codegen change.
#
# Usage:
#   bash tests/toolchain/corpus.sh
#
# Environment:
#   VOX            the compiler to run (default: vox from PATH)
#   VOX_COMMIT     the commit the compiler was built from, recorded in the
#                  MANIFEST (default: the contents of a COMMIT file beside
#                  the compiler, if there is one)
#   VOX_CORE_PATH  the coreasm directory the compiler reads
#                  (default: /usr/share/vox/coreasm)
#   VOXOS_SRC      a voxos checkout (required)
#   COREUTILS_SRC  a vox-coreutils checkout (required)
#   VOX_LIBS_SRC   a vox-libs checkout (required)
#
# The compiler's --version line names a release, and a build from an
# unreleased commit prints the release it follows, so the commit is what
# tells two such corpora apart.
#
# `vox <file> --emit-asm` writes <stem>.asm into the current directory and
# ignores -o, so every source is compiled from its own scratch directory and
# the result is moved into place. The scratch directory also keeps nasm (run
# by a full library build) from finding a coreasm/ in the current directory
# before the one VOX_CORE_PATH names.

set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CORPUS="$ROOT/tests/corpus"

VOX="${VOX:-vox}"
export VOX_CORE_PATH="${VOX_CORE_PATH:-/usr/share/vox/coreasm}"
VOXOS_SRC="${VOXOS_SRC:-}"
COREUTILS_SRC="${COREUTILS_SRC:-}"
VOX_LIBS_SRC="${VOX_LIBS_SRC:-}"

for setting in VOXOS_SRC COREUTILS_SRC VOX_LIBS_SRC VOX_CORE_PATH; do
    if [[ -z "${!setting}" ]]; then
        echo "corpus: set $setting to a checkout (see the header of $0)" >&2
        exit 1
    fi
    if [[ ! -d "${!setting}" ]]; then
        echo "corpus: $setting is not a directory: ${!setting}" >&2
        exit 1
    fi
done

if ! compiler_path="$(command -v "$VOX")"; then
    echo "corpus: no compiler at $VOX" >&2
    exit 1
fi

# The compiler prints its version on stderr.
compiler_version="$("$VOX" --version 2>&1 | head -1)"
compiler_commit="${VOX_COMMIT:-}"
if [[ -z "$compiler_commit" && -f "$(dirname "$compiler_path")/COMMIT" ]]; then
    compiler_commit="$(head -1 "$(dirname "$compiler_path")/COMMIT" | tr -d '[:space:]')"
fi
compiler="$compiler_version"
[[ -n "$compiler_commit" ]] && compiler="$compiler_version (commit $compiler_commit)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
: >"$scratch/manifest"
: >"$scratch/skipped"

# Compiler messages are coloured and name absolute paths; the manifest is
# public, so strip the colour and cut the checkout and scratch prefixes back
# to repository-relative paths.
tidy_message() {
    local repo="$1"
    sed -e 's/\x1b\[[0-9;]*m//g' -e "s#$repo/##g" -e "s#$scratch/[^/ ]*/##g" \
        | grep -m3 . | sed 's/^[[:space:]]*//' | paste -sd' ' -
}

# compile_one <origin> <repository> <source> <kind> [<needed library>]
#   kind is program or library. A program that `see`s a .lib is compiled
#   beside a full build of that library, because `see` reads the .lib and
#   checks it against the .so, and --emit-asm writes neither.
compile_one() {
    local origin="$1" repo="$2" source="$3" kind="$4" needs="${5:--}"
    local stem relative work
    stem="$(basename "$source" .vox)"
    relative="${source#"$repo"/}"
    work="$scratch/$origin-$stem"
    mkdir -p "$work"

    local flags=(--emit-asm)
    [[ $kind == library ]] && flags+=(--shared)
    local input="$source"

    if [[ $needs != - ]]; then
        local library_source library_file
        library_source="${needs%%:*}"
        library_file="${needs#*:}"
        if ! (cd "$work" && "$VOX" "$library_source" --shared -o "$work/${library_file%.lib}.so") \
                >"$work/library.log" 2>&1; then
            printf '%s\t%s\n' "$origin/$relative" \
                "its library ${library_source#"$repo"/} did not build: $(tidy_message "$repo" <"$work/library.log")" \
                >>"$scratch/skipped"
            return
        fi
        cp "$source" "$work/$stem.vox"
        input="$work/$stem.vox"
        needs="$origin/$(basename "$library_source" .vox).asm"
    fi

    if (cd "$work" && "$VOX" "$input" "${flags[@]}") >"$work/log" 2>&1 && [[ -f "$work/$stem.asm" ]]; then
        mkdir -p "$CORPUS/$origin"
        mv "$work/$stem.asm" "$CORPUS/$origin/$stem.asm"
        printf '%s\t%s\t%s\t%s\n' "$origin/$stem.asm" "$kind" "$relative" "$needs" >>"$scratch/manifest"
    else
        printf '%s\t%s\n' "$origin/$relative" "$(tidy_message "$repo" <"$work/log")" >>"$scratch/skipped"
    fi
}

# A source is a library when it declares one (LANGUAGE.md, Writing a
# library), against the left margin like the `see` lines below.
is_library() {
    grep -qiE '^Library[[:space:]]' "$1"
}

# For a program that consumes a .lib from its own directory, print
# "<library source>:<.lib file name>", found by matching the `see` line's
# library name against a sibling's `Library` declaration; print nothing for
# a program that consumes no library. A `see` is written against the left
# margin (LANGUAGE.md, The `see` Keyword), so an indented one is inside a
# comment, which is where the libraries show how they are consumed.
needed_library() {
    local source="$1" name file sibling
    read -r name file < <(sed -nE 's/^see[[:space:]]+([A-Za-z0-9_]+)[[:space:]]+version[[:space:]]+"[^"]*"[[:space:]]+from[[:space:]]+"\.\/([^"]+\.lib)".*/\1 \2/Ip' "$source" | head -1) || true
    [[ -n "${name:-}" ]] || return 0
    for sibling in "$(dirname "$source")"/*.vox; do
        [[ $sibling == "$source" ]] && continue
        if grep -qiE "^Library[[:space:]]+$name[[:space:]]" "$sibling"; then
            echo "$sibling:$file"
            return 0
        fi
    done
}

# compile_tree <origin> <repository> <source>...
compile_tree() {
    local origin="$1" repo="$2" source kind needs
    shift 2
    rm -rf "${CORPUS:?}/$origin"
    for source in "$@"; do
        [[ -f "$source" ]] || continue
        kind=program
        is_library "$source" && kind=library
        needs="$(needed_library "$source")"
        compile_one "$origin" "$repo" "$source" "$kind" "${needs:--}"
    done
}

compile_tree examples "$ROOT" "$ROOT"/examples/*.vox
compile_tree voxos "$VOXOS_SRC" "$VOXOS_SRC"/system/*.vox

tools=()
for directory in "$COREUTILS_SRC"/*/; do
    tools+=("$directory$(basename "$directory").vox")
done
compile_tree coreutils "$COREUTILS_SRC" "${tools[@]}"

libraries=()
for directory in "$VOX_LIBS_SRC"/*/; do
    libraries+=("$directory$(basename "$directory").vox")
done
compile_tree vox-libs "$VOX_LIBS_SRC" "${libraries[@]}"

{
    echo "# The assembly corpus, written by tests/toolchain/corpus.sh. Do not edit by hand."
    echo "# compiler: $compiler"
    echo "#"
    echo "# Columns: the .asm file (relative to tests/corpus), how it is built"
    echo "# (program: nasm -f elf64, then ld; library: nasm -f elf64 -DPIC, then"
    echo "# ld -shared), its source (relative to its own repository), and the"
    echo "# corpus library a program links against (- for none)."
    echo "#"
    printf '# file\tkind\tsource\tneeds\n'
    sort "$scratch/manifest"
    if [[ -s "$scratch/skipped" ]]; then
        echo "#"
        echo "# Sources that did not compile, with the compiler's message:"
        sort "$scratch/skipped" | sed 's/^/# skipped: /'
    fi
} >"$CORPUS/MANIFEST"

files=$(grep -vc '^#' "$CORPUS/MANIFEST" || true)
skipped=$(grep -c '^# skipped:' "$CORPUS/MANIFEST" || true)
echo "corpus: $files assembly files written, $skipped sources skipped ($compiler)"
grep '^# skipped:' "$CORPUS/MANIFEST" | sed 's/^# /corpus: /' || true
