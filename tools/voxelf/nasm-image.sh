#!/usr/bin/env bash
# Assemble the .asm the Vox compiler writes into the two files vox-elf links:
# a raw image of the program's section bytes, and the manifest that says
# where each section lies in the image and where it goes in memory.
#
# usage: tools/voxelf/nasm-image.sh PROGRAM.asm STEM [ENTRY]
#   writes STEM.image and STEM.manifest; ENTRY defaults to _start
#
# The addresses come from voxelf, not from nasm. A first assembly measures
# the sections; vox-elf --layout places them; the program is assembled
# again with each section pinned to its place (nasm's bin format takes a
# file position and an address for every section). Sizes do not normally
# depend on addresses, but if a second assembly measures differently the
# sections are placed again, until two rounds agree.
#
# Environment: VOX_ELF (the vox-elf binary, default vox-elf on PATH),
# VOX_CORE_PATH (the compiler's coreasm directory, default
# /usr/share/vox/coreasm), NASM_INCLUDE (default: the directory above it,
# since the compiler's output includes "coreasm/...").
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "usage: $0 PROGRAM.asm STEM [ENTRY]" >&2
    exit 2
fi
asm=$1 stem=$2 entry=${3:-_start}
core=${VOX_CORE_PATH:-/usr/share/vox/coreasm}
include=${NASM_INCLUDE:-$(dirname "$core")/}
vox_elf=${VOX_ELF:-vox-elf}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Assemble with a prelude that declares the sections before the program
# does, which is how nasm takes their placement. The map is the only thing
# read back: section sizes, alignments and file positions, and symbols.
assemble() {
    { echo "bits 64"; echo "[map all $work/map]"; cat "$1"; } > "$work/prelude.asm"
    nasm -f bin -w-other -I"$include" -p "$work/prelude.asm" -o "$work/image" "$asm"
}

# One line per section from the map: name class length start vstart align,
# numbers in decimal. The alignment is nasm's own (raised by any align
# directive inside the section), never less than 16.
sections_of_map() {
    awk '
        function hex(word) { return strtonum("0x" word) }
        /^-- Sections \(summary\)/ { summary = 1; next }
        /^-- Sections \(detailed\)/ { summary = 0; detail = 1; next }
        /^-- Symbols/ { detail = 0 }
        summary && $6 ~ /^\./ { order[++count] = $6; start[$6] = hex($2); vstart[$6] = hex($1)
                                length_of[$6] = hex($4); class[$6] = $5 }
        detail && /^---- Section / { current = $3 }
        detail && ($1 == "align:" || $1 == "valign:") && $2 != "not" {
            if (hex($2) > align[current]) align[current] = hex($2) }
        END {
            for (i = 1; i <= count; i++) {
                name = order[i]; wanted = align[name] > 16 ? align[name] : 16
                print name, class[name], length_of[name], start[name], vstart[name], wanted
            }
        }' "$work/map"
}

kind_of() {
    case $1 in
        .text) echo text ;; .rodata) echo rodata ;; .data) echo data ;; .bss) echo bss ;;
        *) echo "" ;;
    esac
}

# The layout request: every section that holds anything, with its size and
# alignment. An empty section takes no place, as ld drops it.
request_from_map() {
    sections_of_map | while read -r name class size start vstart alignment; do
        [ "$size" -eq 0 ] && continue
        kind=$(kind_of "$name")
        if [ -z "$kind" ]; then
            echo "$0: section $name holds $size bytes, but voxelf knows no kind for it" >&2
            exit 1
        fi
        echo "section $name $kind size $size alignment $alignment"
    done | sort
}

# The prelude that pins every placed section to its file position and
# address. A zero-filled section has only an address: it has no bytes.
prelude_from_layout() {
    awk '$1 == "section" {
        for (i = 4; i < NF; i += 2) value[$i] = $(i + 1)
        if ($3 == "bss") print "section " $2 " nobits vstart=" value["address"]
        else print "section " $2 " progbits start=" value["file-offset"] " vstart=" value["address"] " align=" value["alignment"]
    }' "$work/layout"
}

: > "$work/pins"
assemble "$work/pins"
request_from_map > "$work/request"
settled=no
for round in 1 2 3 4; do
    "$vox_elf" --layout "$work/request" -o "$work/layout"
    prelude_from_layout > "$work/pins"
    assemble "$work/pins"
    request_from_map > "$work/measured"
    if cmp -s "$work/request" "$work/measured"; then settled=yes; break; fi
    cp "$work/measured" "$work/request"
done
if [ "$settled" != yes ]; then
    echo "$0: section sizes still change with their addresses after four rounds" >&2
    exit 1
fi

origin=$(awk '/^-- Program origin/ { getline; getline; print strtonum("0x" $1); exit }' "$work/map")
entry_address=$(awk -v entry="$entry" '
    /^-- Symbols/ { symbols = 1; next }
    symbols && NF == 3 && $3 == entry { print "0x" $2; exit }' "$work/map")
if [ -z "$entry_address" ]; then
    echo "$0: $asm defines no symbol called $entry" >&2
    exit 1
fi

cp "$work/image" "$stem.image"
{
    echo "# The sections of $(basename "$asm"), assembled by nasm -f bin for vox-elf"
    echo "image $(basename "$stem").image"
    grep '^base ' "$work/layout"
    sections_of_map | while read -r name class size start vstart alignment; do
        [ "$size" -eq 0 ] && continue
        kind=$(kind_of "$name")
        if [ "$kind" = bss ]; then
            printf 'section %s %s size %d alignment %d address 0x%x\n' "$name" "$kind" "$size" "$alignment" "$vstart"
        else
            printf 'section %s %s size %d alignment %d address 0x%x offset %d\n' \
                "$name" "$kind" "$size" "$alignment" "$vstart" $((start - origin))
        fi
    done
    echo "symbol $entry $entry_address"
} > "$stem.manifest"
