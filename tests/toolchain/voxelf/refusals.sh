#!/usr/bin/env bash
# What vox-elf refuses, and that it says why: every refusal must exit with a
# nonzero status, name its reason on standard error, and write no output.
# Then what it takes at the edges of what it reads: each must link, and the
# program must run, or match ld byte for byte where it cannot run here. Last,
# one program built from hand-written bytes, so the test needs no compiler:
# the layout, the link and the run, and the same link through libvoxelf.so's
# path-based surface.
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
export VOX_ELF=$vox_elf
work=$(mktemp -d "${TMPDIR:-/tmp}/voxelf-refusals.XXXXXX")
trap 'rm -rf "$work"' EXIT
cd "$work"
passes=0 failures=0

# vox-elf and nasm-image.sh run under the trace in ld-trace.sh, so the count
# of links voxelf's side handed to ld is measured rather than assumed.
source "$here/ld-trace.sh"
reference_links=0

pass() { passes=$((passes + 1)); }
fail() { failures=$((failures + 1)); printf '  FAIL %s\n' "$1"; }

# The trace itself: a call to ld by its absolute path, which the stand-in on
# PATH cannot catch, must be counted. The log then starts again empty.
real_ld=$(command -v ld)
guarded "$real_ld" --version > /dev/null 2>&1
if [ "$(ld_pass_throughs)" -eq 1 ]; then pass; else fail "the trace counted $(ld_pass_throughs) calls of $real_ld, not 1"; fi
: > "$work/execs.log"

# refused NAME EXPECTED-WORDS INPUT [vox-elf options]: links INPUT and
# expects a refusal whose diagnostics contain EXPECTED-WORDS.
refused() {
    local name=$1 expected=$2 input=$3; shift 3
    rm -f out
    guarded timeout 60 "$vox_elf" "$input" -o out "$@" > /dev/null 2> said; local status=$?
    if [ "$status" -eq 0 ]; then fail "$name: exit status 0"; return; fi
    if [ "$status" -eq 124 ]; then fail "$name: still running after 60 seconds"; return; fi
    if ! grep -qF -- "$expected" said; then fail "$name: said [$(head -c 400 said)], not [$expected]"; return; fi
    if [ -e out ]; then fail "$name: wrote an output anyway"; return; fi
    pass
}

# runs NAME STATUS INPUT: links INPUT, which must link, and runs the result,
# which must exit with STATUS.
runs() {
    local name=$1 wanted=$2 input=$3
    rm -f out
    if ! guarded "$vox_elf" "$input" -o out > /dev/null 2> said; then fail "$name: refused: [$(cat said)]"; return; fi
    chmod 755 out
    ./out; local status=$?
    if [ "$status" -ne "$wanted" ]; then fail "$name: the program exited $status, not $wanted"; return; fi
    pass
}

manifest() { printf '%s\n' "$@" > "$work/refused.manifest"; }

# The bytes of a program that exits with status 7: mov eax, 60 (exit);
# mov edi, 7; syscall.
printf '\xb8\x3c\x00\x00\x00\xbf\x07\x00\x00\x00\x0f\x05' > tiny.image

# ELF files of every kind voxelf does not read yet.
printf 'section .text\nglobal _start\n_start:\n    mov eax, 60\n    syscall\n' > tiny.asm
nasm -f elf64 -o tiny.o tiny.asm
nasm -f elf32 -o tiny32.o tiny.asm
cp tiny.o tiny-aarch64.o
printf '\xb7' | dd of=tiny-aarch64.o bs=1 seek=18 conv=notrunc status=none
refused "a relocatable object" "is a relocatable object; voxelf does not read relocatable objects or apply relocations yet" tiny.o
refused "a 32-bit object" "is a 32-bit ELF file; voxelf does not read ELF files yet" tiny32.o
refused "an object for another machine" "built for ELF machine 183, not x86-64" tiny-aarch64.o
refused "a shared object" "voxelf does not link shared objects or write position-independent executables yet" "$build/libvoxelf.so"
refused "a linked executable" "is already a linked executable" "$vox_elf"

# Manifests that ask for what voxelf does not do yet.
base="section .text text size 12 alignment 16 address 0x401000 offset 0"
manifest "image tiny.image" "$base" "symbol _start 0x401000" "relocation .text 4 R_X86_64_32 str_0"
refused "a relocation" "voxelf does not apply relocations yet" refused.manifest
manifest "image tiny.image" "$base" "symbol _start 0x401000" "interpreter /lib64/ld-linux-x86-64.so.2"
refused "an interpreter" "voxelf does not link dynamically yet" refused.manifest
manifest "image tiny.image" "$base" "symbol _start 0x401000" "needed libc.so.6"
refused "a needed library" "voxelf does not link dynamically yet" refused.manifest
manifest "type shared" "image tiny.image" "$base" "symbol _start 0x401000"
refused "a shared object type" "voxelf does not write shared objects yet" refused.manifest
manifest "machine aarch64" "image tiny.image" "$base" "symbol _start 0x401000"
refused "another machine" "voxelf does not write executables for aarch64 yet" refused.manifest
manifest "class 32" "image tiny.image" "$base" "symbol _start 0x401000"
refused "32-bit" "voxelf does not write 32-bit ELF files yet" refused.manifest
manifest "image tiny.image" "image other.image" "$base" "symbol _start 0x401000"
refused "two images" "voxelf does not link several images together yet" refused.manifest

# Manifests that are wrong in themselves.
text="section .text text size 12 alignment 16 address 0x4000b0 offset 0"
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
manifest "image tiny.image" "$text" "symbol _start 0x400000"
refused "an entry point outside the code" "the entry point 0x400000 is not inside a text section" refused.manifest
refused "a manifest that is not there" "there is no such file" missing.manifest

# Offsets and sizes near 2^63, where adding two of them wraps round to a
# small number: each must be refused, never written as zeros or as a wrong
# program header.
manifest "image tiny.image" "section .text text size 12 alignment 16 address 0x4000b0 offset 0x7ffffffffffffffa" "symbol _start 0x4000b0"
refused "an image offset whose end wraps round" "runs for 12 bytes from offset 9223372036854775802 in the image, which holds 12 bytes" refused.manifest
manifest "image tiny.image" "section .text text size 4096 alignment 16 address 0x4000b0 offset 0x7ffffffffffff800" "symbol _start 0x4000b0"
refused "a page of image from an offset near 2^63" "in the image, which holds 12 bytes" refused.manifest
manifest "image tiny.image" "section .text text size 12 alignment 16 address 0x4000f0 offset 0" \
    "section .bss bss size 0x7ffffffffffff000 alignment 16 address 0x401000" "symbol _start 0x4000f0"
refused "zero-filled data near 2^63 bytes" "is more than the 140737488355328 bytes of one half of the address space" refused.manifest
printf '%s\n' "section .text text size 12 alignment 16" "section .bss bss size 0x7fffffffffffff00 alignment 4096" > huge.request
refused "laying out zero-filled data near 2^63 bytes" "is more than the 140737488355328 bytes of one half of the address space" huge.request --layout
printf '%s\n' "section .text text size 12 alignment 16" "section .bss bss size 0x600000000000 alignment 16" \
    "section .tbss bss size 0x600000000000 alignment 16" > twice.request
refused "two sections that need more than half the address space together" "the sections need more than the 140737488355328 bytes" twice.request --layout

# Memory between the two halves of the address space, from 0x800000000000 up
# to 0xffff800000000000, where no address is canonical and nothing can be
# mapped, and memory that would wrap round past 2^64. A program lies wholly
# in the lower half or wholly in the upper half.
printf '%s\n' "base 0x800000000000" "section .text text size 12 alignment 16" > hole.request
refused "a load base at 2^47, the first address that is not canonical" "lies between 0x800000000000 and 0xffff800000000000" hole.request --layout
printf '%s\n' "base 0x7ffffffffffff000" "section .text text size 12 alignment 16" "section .bss bss size 0x10000 alignment 16" > crossing.request
refused "a load base just under 2^63, between the halves" "lies between 0x800000000000 and 0xffff800000000000" crossing.request --layout
manifest "base 0x7ffffffffffff000" "image tiny.image" "section .text text size 12 alignment 16 address 0x7ffffffffffff0f0 offset 0" \
    "section .bss bss size 0x10000 alignment 16 address 0x8000000000000000" "symbol _start 0x7ffffffffffff0f0"
refused "a link from just under 2^63, between the halves" "lies between 0x800000000000 and 0xffff800000000000" refused.manifest
printf '%s\n' "base 0x7ffffffff000" "section .text text size 12 alignment 16" "section .bss bss size 0x2000 alignment 16" > last.request
refused "zero-filled data from the last page of the lower half into the hole" "would run past 0x800000000000, the top of the lower half" last.request --layout
printf '%s\n' "base 0x7fffffffe000" "section .text text size 12 alignment 16" "section .bss bss size 0x10000 alignment 16" > past.request
refused "zero-filled data from the last pages of the lower half into the hole" "would run past 0x800000000000, the top of the lower half" past.request --layout
printf '%s\n' "section .text text size 12 alignment 16" "section .bss bss size 0x7fffffc00000 alignment 16" > below.request
refused "zero-filled data from the default base into the hole" "from the load base 0x400000 would run past 0x800000000000" below.request --layout
printf '%s\n' "base 0xfffffffffffff000" "section .text text size 12 alignment 16" "section .bss bss size 0x2000 alignment 16" > top.request
refused "zero-filled data from the top page of the upper half past 2^64" "would run past the top of the address space and wrap round to 0" top.request --layout
# One byte more code than ends exactly at 2^64: the two headers take 0xb0
# bytes of the page, and 3920 bytes of code the rest. ld refuses it too.
printf '%s\n' "base 0xfffffffffffff000" "section .text text size 3921 alignment 16" > wrap.request
refused "code from the top page of the upper half one byte past 2^64" "would run past the top of the address space and wrap round to 0" wrap.request --layout
printf 'section .note.GNU-stack noalloc noexec nowrite progbits\nsection .text\nglobal _start\n_start:\n    times 3921 nop\n' > wrap.asm
nasm -f elf64 -o wrap.o wrap.asm
if ld -Ttext-segment=0xfffffffffffff000 -o wrap.ld wrap.o > said 2>&1; then
    fail "ld links code one byte past 2^64, which vox-elf refuses"
elif grep -q "wraps around address space" said; then
    pass
else
    fail "ld refused code one byte past 2^64 for another reason: [$(cat said)]"
fi

# Every section must say the address it was assembled for: without it,
# nothing shows that the image's code points where the data is placed.
# This code reads its exit status from 0x402000, where it was assembled to
# find its data, but the data is placed at 0x401000.
printf '\x8b\x04\x25\x00\x20\x40\x00\x89\xc7\xb8\x3c\x00\x00\x00\x0f\x05\x2a\x00\x00\x00' > absolute.image
manifest "image absolute.image" "section .text text size 16 alignment 16 offset 0" "section .data data size 4 alignment 4 offset 16" "symbol _start 0x4000f0"
refused "sections that do not say their addresses" "section .text does not say the address it was assembled for" refused.manifest
refused "data that does not say its address" "section .data does not say the address it was assembled for" refused.manifest
manifest "image tiny.image" "section .text text size 12 alignment 16 offset 0" "symbol _start 0x4000b0"
refused "code that does not say its address" "section .text does not say the address it was assembled for" refused.manifest

# Numbers are read whole: no fraction, nothing past 64 bits, nothing at or
# past 2^63 where a size or an offset is wanted.
manifest "image tiny.image" "section .text text size 12.9 alignment 16 address 0x4000b0 offset 0" "symbol _start 0x4000b0"
refused "a size with a fraction" "'12.9' is not a number" refused.manifest
manifest "image tiny.image" "section .text text size 12 alignment 16 address 0x4000b0 offset 0" "symbol _start 0x1000000000000000b0"
refused "an address of more than 64 bits" "has more than 64 bits" refused.manifest
manifest "image tiny.image" "section .text text size 9223372036854775808 alignment 16 address 0x4000b0 offset 0" "symbol _start 0x4000b0"
refused "a decimal size of 2^63" "is 2^63 or more, which voxelf reads only in hexadecimal" refused.manifest
manifest "image tiny.image" "section .text text size 0x8000000000000000 alignment 16 address 0x4000b0 offset 0" "symbol _start 0x4000b0"
refused "a hexadecimal size of 2^63" "more than any size, alignment or offset can be" refused.manifest

# Nothing is said twice, so nothing is quietly taken in place of something
# else.
manifest "image tiny.image" "$text" "symbol _start 0x4000b0" "symbol _start 0x4000b5"
refused "a symbol given twice" "the symbol _start is given a second time" refused.manifest
manifest "image tiny.image" "$text" "$text" "symbol _start 0x4000b0"
refused "a section described twice" "section .text is described more than once" refused.manifest
manifest "image tiny.image" "section .text text size 12 size 13 alignment 16 address 0x4000b0 offset 0" "symbol _start 0x4000b0"
refused "a size said twice on one line" "'size' is said twice" refused.manifest
manifest "image tiny.image" "base 0x400000" "base 0x800000" "$text" "symbol _start 0x4000b0"
refused "a load base given twice" "the load base is given a second time" refused.manifest

# A load base Linux would not map.
manifest "image tiny.image" "base 0" "section .text text size 12 alignment 16 address 0xb0 offset 0" "symbol _start 0xb0"
refused "a load base of 0" "is below 0x10000, where Linux maps nothing by default" refused.manifest

# Input of any size is read only up to a limit, so a file that never ends
# is refused instead of filling the memory.
refused "a manifest that never ends" "/dev/zero: is more than 16777216 bytes long" /dev/zero
manifest "image /dev/zero" "$text" "symbol _start 0x4000b0"
refused "an image that never ends" "/dev/zero: is more than 268435456 bytes long" refused.manifest

# More errors than an exit status can hold: every one is reported, and the
# status stops at 255 rather than wrapping round to 0.
yes bogus | head -n 256 > many.manifest
rm -f out
guarded "$vox_elf" many.manifest -o out > /dev/null 2> said; status=$?
if [ "$status" -eq 255 ] && [ "$(wc -l < said)" -eq 256 ] && [ ! -e out ]; then
    pass
else
    fail "256 errors: exit status $status, $(wc -l < said) lines of diagnostics"
fi

# What it takes at the edges.
printf '%s\r\n' "image tiny.image" "$text" "symbol _start 0x4000b0" > windows.manifest
runs "a manifest with Windows line endings" 7 windows.manifest
printf '%s\n' "image tiny.image" "section .text text size 0XC alignment 0x10 address 0X4000B0 offset 0x0" "symbol _start 0x4000b0" > capitals.manifest
runs "hexadecimal written with capitals" 7 capitals.manifest

# An image named from the manifest's directory may not climb out of it,
# even to an image that is there: these manifests stand one directory below
# tiny.image.
mkdir -p inner/parts
printf '%s\n' "image ../tiny.image" "$text" "symbol _start 0x4000b0" > inner/climbing.manifest
refused "an image path that starts by climbing out" "climbs out of the manifest's directory with '..'" inner/climbing.manifest
printf '%s\n' "image parts/../../tiny.image" "$text" "symbol _start 0x4000b0" > inner/winding.manifest
refused "an image path that climbs out part way along" "climbs out of the manifest's directory with '..'" inner/winding.manifest
mkdir -p parts
cp tiny.image parts/tiny..image
printf '%s\n' "image parts/tiny..image" "$text" "symbol _start 0x4000b0" > dotted.manifest
runs "an image whose name only holds two dots" 7 dotted.manifest

# like_ld NAME BASE LINES...: NAME.asm, written one line to each argument,
# linked at the load base BASE by ld and by nasm-image.sh and vox-elf, and
# compared byte for byte. None of these programs can run here: the stack is
# mapped at the top of the lower half, and the upper half is the kernel's.
like_ld() {
    local name=$1 load_base=$2; shift 2
    printf '%s\n' "default abs" "section .note.GNU-stack noalloc noexec nowrite progbits" "$@" > "$name.asm"
    nasm -f elf64 -o "$name.o" "$name.asm"
    if ! ld -Ttext-segment="$load_base" -o "$name.ld" "$name.o" > said 2>&1; then fail "$name: ld refused it: [$(cat said)]"; return; fi
    reference_links=$((reference_links + 1))
    if guarded bash "$vox_tree/tools/voxelf/nasm-image.sh" "$name.asm" "$name" _start "$load_base" > said 2>&1 \
            && guarded "$vox_elf" "$name.manifest" -o "$name.elf" >> said 2>&1; then
        if bash "$here/same-bytes.sh" "$name.ld" "$name.elf" > compared; then pass; else fail "$name: $(cat compared)"; fi
    else
        fail "$name: [$(cat said)]"
    fi
}

# The last pages of the lower half: code on the page from 0x7fffffffe000, and
# code that fills the page from 0x7ffffffff000 and ends exactly at 2^47.
like_ld last-page-but-one 0x7fffffffe000 "section .text" "global _start" "_start: mov eax, 60" " mov edi, 7" " syscall"
like_ld up-to-the-hole 0x7ffffffff000 "section .text" "global _start" "_start: times 3920 nop"
# A kernel's base, 0xffffffff80000000, with a section of every kind, each
# read by the code, so every address the layout gives is in it.
like_ld at-a-kernels-base 0xffffffff80000000 "section .text" "global _start" "_start: mov rax, [constant]" \
    " mov rax, [variable]" " mov rax, [scratch]" " mov eax, 60" " syscall" \
    "section .rodata" "constant: dq 7" "section .data" "variable: dq 5" "section .bss" "scratch: resb 5000"
# Code from the top page of the upper half that ends exactly at 2^64, which
# ld takes.
like_ld up-to-2-to-the-64 0xfffffffffffff000 "section .text" "global _start" "_start: times 3920 nop"

# One program that links: placed, then linked for the address it was given.
printf 'section .text text size 12 alignment 16\n' > tiny.request
if guarded "$vox_elf" --layout tiny.request -o tiny.layout 2> said && grep -q 'address 0x4000b0 file-offset 0xb0' tiny.layout; then
    pass
else
    fail "the layout of one 12-byte section: [$(cat tiny.layout said 2>/dev/null)]"
fi
printf '%s\n' "image tiny.image" "$text" "symbol _start 0x4000b0" > tiny.manifest
runs "a manifest that should link" 7 tiny.manifest

# The same, through the shared library's path-based surface, from a Vox
# program that sees libvoxelf.lib. The compiler links path_surface itself
# with ld, which is the test's own build, not a link of voxelf's.
cp "$here/path_surface.vox" .
if vox path_surface.vox --lib-path "$build" -o path_surface > said 2>&1; then
    reference_links=$((reference_links + 1))
    manifest "image tiny.image" "$base" "symbol main 0x401000"
    guarded ./path_surface "$work/tiny.manifest" "$work/refused.manifest" "$work" > told 2>&1
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

handed_to_ld=$(ld_pass_throughs)
if [ "$handed_to_ld" -ne 0 ]; then fail "voxelf's side called ld $handed_to_ld times: $(ld_execs | head -3)"; fi
printf 'voxelf refusals and the path-based surface: %d passed, %d failed; %d ld pass-throughs; links by ld: %d for the test itself (references to compare with, and the build of path_surface)\n' \
    "$passes" "$failures" "$handed_to_ld" "$reference_links"
[ "$failures" -eq 0 ]
