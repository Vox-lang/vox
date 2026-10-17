#!/usr/bin/env bash
# What vox-elf refuses, and that it says why: every refusal must exit with a
# nonzero status, name its reason on standard error, and write no output.
# Then one program that does link, built from hand-written bytes so the
# test needs no compiler: the layout, the link and the run, and the same
# link through libvoxelf.so's path-based surface.
#
# usage: tests/toolchain/voxelf/refusals.sh
# Environment: VOXELF_BUILD (where tools/voxelf/build.sh put its output;
# built there if missing), VOX_CORE_PATH.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
vox_tree=$(cd "$here/../../.." && pwd)
export VOX_CORE_PATH=${VOX_CORE_PATH:-/usr/share/vox/coreasm}
build=${VOXELF_BUILD:-${TMPDIR:-/tmp}/voxelf-build}
if [ ! -x "$build/vox-elf" ]; then
    bash "$vox_tree/tools/voxelf/build.sh" "$build" > /dev/null || exit 1
fi
vox_elf=$build/vox-elf
work=$(mktemp -d "${TMPDIR:-/tmp}/voxelf-refusals.XXXXXX")
trap 'rm -rf "$work"' EXIT
cd "$work"
passes=0 failures=0

pass() { passes=$((passes + 1)); }
fail() { failures=$((failures + 1)); printf '  FAIL %s\n' "$1"; }

# refused NAME EXPECTED-WORDS INPUT [vox-elf options]: links INPUT and
# expects a refusal whose diagnostics contain EXPECTED-WORDS.
refused() {
    local name=$1 expected=$2 input=$3; shift 3
    rm -f out
    "$vox_elf" "$input" -o out "$@" > /dev/null 2> said; local status=$?
    if [ "$status" -eq 0 ]; then fail "$name: exit status 0"; return; fi
    if ! grep -qF -- "$expected" said; then fail "$name: said [$(cat said)], not [$expected]"; return; fi
    if [ -e out ]; then fail "$name: wrote an output anyway"; return; fi
    pass
}

manifest() { printf '%s\n' "$@" > "$work/refused.manifest"; }

# The bytes of a program that exits with status 7: mov eax, 60 (exit);
# mov edi, 7; syscall.
printf '\xb8\x3c\x00\x00\x00\xbf\x07\x00\x00\x00\x0f\x05' > tiny.image

# ELF files of every kind voxelf does not link.
printf 'section .text\nglobal _start\n_start:\n    mov eax, 60\n    syscall\n' > tiny.asm
nasm -f elf64 -o tiny.o tiny.asm
nasm -f elf32 -o tiny32.o tiny.asm
cp tiny.o tiny-aarch64.o
printf '\xb7' | dd of=tiny-aarch64.o bs=1 seek=18 conv=notrunc status=none
refused "a relocatable object" "is a relocatable object" tiny.o
refused "a 32-bit object" "is a 32-bit ELF file" tiny32.o
refused "an object for another machine" "built for ELF machine 183, not x86-64" tiny-aarch64.o
refused "a shared object" "is a shared object" "$build/libvoxelf.so"
refused "a linked executable" "is already a linked executable" "$vox_elf"

# Manifests that ask for what voxelf does not do.
base="section .text text size 12 alignment 16 address 0x401000 offset 0"
manifest "image tiny.image" "$base" "symbol _start 0x401000" "relocation .text 4 R_X86_64_32 str_0"
refused "a relocation" "relocations are not supported" refused.manifest
manifest "image tiny.image" "$base" "symbol _start 0x401000" "interpreter /lib64/ld-linux-x86-64.so.2"
refused "an interpreter" "dynamic linking is not supported" refused.manifest
manifest "image tiny.image" "$base" "symbol _start 0x401000" "needed libc.so.6"
refused "a needed library" "dynamic linking is not supported" refused.manifest
manifest "type shared" "image tiny.image" "$base" "symbol _start 0x401000"
refused "a shared object type" "shared objects are not supported" refused.manifest
manifest "machine aarch64" "image tiny.image" "$base" "symbol _start 0x401000"
refused "another machine" "machine aarch64 is not supported" refused.manifest
manifest "class 32" "image tiny.image" "$base" "symbol _start 0x401000"
refused "32-bit" "32-bit ELF is not supported" refused.manifest
manifest "image tiny.image" "image other.image" "$base" "symbol _start 0x401000"
refused "two images" "linking several objects is not supported" refused.manifest

# Manifests that are wrong in themselves.
manifest "image tiny.image" "$base" "symbol main 0x401000"
refused "no entry symbol" "there is no symbol called _start" refused.manifest
manifest "image tiny.image" "section .text text size 12 alignment 16 address 0x500000 offset 0" "symbol _start 0x500000"
refused "an address that layout does not give" "was assembled for 0x500000 but is placed at 0x4000b0" refused.manifest
manifest "image tiny.image" "section .text text size 99 alignment 16 address 0x4000b0 offset 0" "symbol _start 0x4000b0"
refused "a section longer than the image" "which holds 12 bytes" refused.manifest
manifest "image tiny.image" "section .text text size twelve alignment 16" "symbol _start 0x4000b0"
refused "a size that is not a number" "'twelve' is not a number" refused.manifest
manifest "image tiny.image" "section .text code size 12 alignment 16" "symbol _start 0x4000b0"
refused "a kind that does not exist" "'code' is not a kind of section" refused.manifest
manifest "image tiny.image" "section .text text size 12 alignment 24" "symbol _start 0x4000b0"
refused "an alignment that is not a power of two" "an alignment of 24 is not a power of two" refused.manifest
manifest "image tiny.image" "entry _start" "$base"
refused "a line voxelf does not know" "'entry' is not a manifest statement" refused.manifest
manifest "image tiny.image" "section .text text size 12 alignment 16 address 0x4000b0 offset 0" "symbol _start 0x400000"
refused "an entry point outside the code" "the entry point 0x400000 is not inside a text section" refused.manifest
refused "a manifest that is not there" "there is no such file" missing.manifest

# More errors than an exit status can hold: every one is reported, and the
# status stops at 255 rather than wrapping round to 0.
yes bogus | head -n 256 > many.manifest
rm -f out
"$vox_elf" many.manifest -o out > /dev/null 2> said; status=$?
if [ "$status" -eq 255 ] && [ "$(wc -l < said)" -eq 256 ] && [ ! -e out ]; then
    pass
else
    fail "256 errors: exit status $status, $(wc -l < said) lines of diagnostics"
fi

# One program that links: placed, then linked for the address it was given.
printf 'section .text text size 12 alignment 16\n' > tiny.request
if "$vox_elf" --layout tiny.request -o tiny.layout 2> said && grep -q 'address 0x4000b0 file-offset 0xb0' tiny.layout; then
    pass
else
    fail "the layout of one 12-byte section: [$(cat tiny.layout said 2>/dev/null)]"
fi
printf '%s\n' "image tiny.image" "section .text text size 12 alignment 16 address 0x4000b0 offset 0" \
    "symbol _start 0x4000b0" > tiny.manifest
if "$vox_elf" tiny.manifest -o tiny 2> said; then
    chmod 755 tiny
    ./tiny; status=$?
    if [ "$status" -eq 7 ]; then pass; else fail "the linked program exited $status, not 7"; fi
else
    fail "a manifest that should link: [$(cat said)]"
fi

# The same, through the shared library's path-based surface, from a Vox
# program that sees libvoxelf.lib.
cp "$here/path_surface.vox" .
if vox path_surface.vox --lib-path "$build" -o path_surface > said 2>&1; then
    manifest "image tiny.image" "$base" "symbol main 0x401000"
    ./path_surface "$work/tiny.manifest" "$work/refused.manifest" "$work" > told 2>&1
    expected="the good manifest links with 0 errors
and leaves these diagnostics: []
the bad manifest links with 1 errors:
$work/refused.manifest: there is no symbol called _start, so the program has no entry point
and asked again, it says: []"
    if [ "$(cat told)" = "$expected" ]; then pass; else fail "the path-based surface said [$(cat told)]"; fi
    if [ -e "$work/linked" ] && [ ! -e "$work/refused" ]; then pass; else fail "the path-based surface wrote the wrong files"; fi
else
    fail "path_surface.vox does not compile against libvoxelf.lib: [$(cat said)]"
fi

printf 'voxelf refusals and the path-based surface: %d passed, %d failed\n' "$passes" "$failures"
[ "$failures" -eq 0 ]
