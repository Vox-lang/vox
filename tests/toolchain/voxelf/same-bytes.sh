#!/usr/bin/env bash
# Compare what the loader reads of two static executables, byte for byte:
# the ELF header, every program header, and every byte the loadable
# segments map from the file. Section headers, the section name table and
# the symbol table are not loaded, and vox-elf writes no symbol table, so
# the three ELF header fields that locate the section headers (e_shoff,
# e_shnum and e_shstrndx) are left out, and so is everything outside the
# loadable segments. Prints the first difference and exits 1 when there is
# one.
#
# usage: tests/toolchain/voxelf/same-bytes.sh REFERENCE CANDIDATE
set -uo pipefail

reference=$1 candidate=$2

# bytes FILE OFFSET COUNT: the bytes as hexadecimal, one line of 16 per row.
bytes() { od -An -v -tx1 -j "$2" -N "$3" "$1"; }

# The ELF header without e_shoff (offset 40, 8 bytes) and without e_shnum
# and e_shstrndx (offset 60, 4 bytes).
for range in "0 40" "48 12"; do
    set -- $range
    if [ "$(bytes "$reference" "$1" "$2")" != "$(bytes "$candidate" "$1" "$2")" ]; then
        echo "the ELF headers differ in the $2 bytes at offset $1"
        exit 1
    fi
done

header_count=$(od -An -tu2 -j 56 -N 2 "$reference" | tr -d ' ')
table_end=$((64 + 56 * header_count))
if [ "$(bytes "$reference" 64 $((56 * header_count)))" != "$(bytes "$candidate" 64 $((56 * header_count)))" ]; then
    echo "the program headers differ: $(readelf -lW "$candidate" | grep -E '^ +(LOAD|GNU_STACK)' | tr -s ' ' | tr '\n' ';') where the reference has $(readelf -lW "$reference" | grep -E '^ +(LOAD|GNU_STACK)' | tr -s ' ' | tr '\n' ';')"
    exit 1
fi

# The program headers are the same, so the segments are read from the same
# places in both files. The first segment starts with the headers already
# compared.
while read -r offset size; do
    offset=$((offset)) size=$((size))
    if [ "$offset" -lt "$table_end" ]; then
        size=$((size - (table_end - offset))) offset=$table_end
    fi
    [ "$size" -gt 0 ] || continue
    if ! cmp -s <(tail -c +$((offset + 1)) "$reference" | head -c "$size") \
                <(tail -c +$((offset + 1)) "$candidate" | head -c "$size"); then
        first=$(cmp <(tail -c +$((offset + 1)) "$reference" | head -c "$size") \
                    <(tail -c +$((offset + 1)) "$candidate" | head -c "$size") | awk '{print $5}' | tr -d ,)
        printf 'the segment at file offset 0x%x differs, first at its byte %s\n' "$offset" "$first"
        exit 1
    fi
done < <(readelf -lW "$reference" | awk '$1 == "LOAD" { print $2, $5 }')
exit 0
