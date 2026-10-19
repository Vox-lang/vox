#!/usr/bin/env bash
# Hand-written programs of every shape of section voxelf lays out, linked
# twice: by nasm -f elf64 and ld, and by tools/voxelf/nasm-image.sh and
# vox-elf. The two executables must be the same byte for byte in everything
# the loader reads (same-bytes.sh): the ELF header, every program header,
# and every byte of every loadable segment.
#
# The shapes are a grid of read-only data, initialised data and zero-filled
# data, sized and aligned to fall either side of ld's choices: where the
# writable segment starts, whether a fresh page saves a page of memory, the
# file offset of a segment with no bytes in the file, and the padding at the
# end of .bss. Then a few programs written for one edge each. A program
# whose sections voxelf does not take yet must be refused, with the reason.
#
# usage: tests/toolchain/voxelf/layouts.sh
# Environment: VOXELF_BUILD (where tools/voxelf/build.sh put vox-elf; built
# there if missing), VOX_CORE_PATH.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
vox_tree=$(cd "$here/../../.." && pwd)
export VOX_CORE_PATH=${VOX_CORE_PATH:-/usr/share/vox/coreasm}
build=${VOXELF_BUILD:-${TMPDIR:-/tmp}/voxelf-build}
if [ ! -x "$build/vox-elf" ]; then
    bash "$vox_tree/tools/voxelf/build.sh" "$build" > /dev/null || exit 1
fi
export VOX_ELF=$build/vox-elf
work=$(mktemp -d "${TMPDIR:-/tmp}/voxelf-layouts.XXXXXX")
trap 'rm -rf "$work"' EXIT
cd "$work"

# As in refusals.sh: voxelf's side runs under the trace in ld-trace.sh,
# which counts every call it makes to ld.
source "$here/ld-trace.sh"

passes=0 failures=0 reference_links=0

# both NAME [ENTRY]: NAME.asm linked both ways and compared.
both() {
    local name=$1 entry=${2:-_start}
    if ! { nasm -f elf64 -o "$name.o" "$name.asm" && ld -e "$entry" -o "$name.ld" "$name.o"; } > "$name.log" 2>&1; then
        failures=$((failures + 1)); echo "  FAIL $name: nasm and ld could not build it: $(head -2 "$name.log")"; return
    fi
    reference_links=$((reference_links + 1))
    if ! { guarded bash "$vox_tree/tools/voxelf/nasm-image.sh" "$name.asm" "$name" "$entry" \
            && guarded "$VOX_ELF" "$name.manifest" -o "$name.elf" -e "$entry"; } >> "$name.log" 2>&1; then
        failures=$((failures + 1)); echo "  FAIL $name: vox-elf could not link it: $(tail -2 "$name.log")"; return
    fi
    local difference
    if difference=$(bash "$here/same-bytes.sh" "$name.ld" "$name.elf"); then
        passes=$((passes + 1))
    else
        failures=$((failures + 1)); echo "  FAIL $name: $difference"
    fi
}

# Each program reads one byte of each section it has, so every address the
# layout gives is written into its code.
for read_only in 0 8 52 4100; do
  for data_alignment in 4 64 4096; do
    for data in 0 8 4090 5000; do
      for zeros in 0 100 70000; do
        for zeros_alignment in 4 64 4096; do
          [ "$zeros" -eq 0 ] && [ "$zeros_alignment" -ne 4 ] && continue
          [ "$data" -eq 0 ] && [ "$data_alignment" -ne 4 ] && continue
          name=grid-r$read_only-d$data-a$data_alignment-z$zeros-a$zeros_alignment
          {
            echo "default abs"
            echo "section .note.GNU-stack noalloc noexec nowrite progbits"
            echo "section .text"
            echo "global _start"
            echo "_start:"
            [ "$read_only" -gt 0 ] && echo "    mov rax, [constant]"
            [ "$data" -gt 0 ] && echo "    mov rax, [variable]"
            [ "$zeros" -gt 0 ] && echo "    mov rax, [scratch]"
            echo "    mov eax, 60"
            echo "    xor edi, edi"
            echo "    syscall"
            [ "$read_only" -gt 0 ] && { echo "section .rodata"; echo "constant: times $read_only db 1"; }
            [ "$data" -gt 0 ] && { echo "section .data align=$data_alignment"; echo "variable: times $data db 2"; }
            [ "$zeros" -gt 0 ] && { echo "section .bss"; echo "alignb $zeros_alignment"; echo "scratch: resb $zeros"; }
          } > "$name.asm"
          both "$name"
        done
      done
    done
  done
done

# program NAME LINES...: writes NAME.asm, one line to each argument.
program() { local name=$1; shift; printf '%s\n' "default abs" "section .note.GNU-stack noalloc noexec nowrite progbits" "$@" > "$name.asm"; }

program code-aligned-to-a-page "section .text align=4096" "global _start" "_start: mov rdi, [variable]" " add rdi, [constant]" \
    " mov eax, 60" " syscall" "section .data align=4096" "variable: dq 5" "section .rodata align=64" "constant: dq 7"
both code-aligned-to-a-page
program zeros-after-long-code "section .text" "global _start" "_start: jmp near finish" " times 9000 nop" \
    "finish: mov byte [scratch+99], 3" " mov eax, 60" " syscall" "section .bss" "scratch: resb 100"
both zeros-after-long-code
program entry-past-the-start "section .text" "global _start" "helper: mov edi, 42" " ret" " times 300 nop" \
    "_start: call helper" " mov eax, 60" " syscall"
both entry-past-the-start
program entry-not-called-start "section .text" "global main" " nop" "main: mov eax, 60" " mov edi, 5" " syscall"
both entry-not-called-start main
program empty-sections "section .data" "section .rodata" "section .bss" "section .text" "global _start" \
    "_start: mov eax, 60" " mov edi, 1" " syscall"
both empty-sections
program three-megabytes-of-data "section .data" "bulk: times 3000000 db 0xab" "last: db 9" "section .text" "global _start" \
    "_start: movzx edi, byte [last]" " mov eax, 60" " syscall"
both three-megabytes-of-data
program a-gigabyte-of-zeros "section .data" "start: dq 1" "section .bss" "huge: resb 0x40000000" "tail: resb 8" \
    "section .text" "global _start" "_start: mov qword [tail], 9" " mov rdi, [tail]" " mov eax, 60" " syscall"
both a-gigabyte-of-zeros
program pointers-between-sections "section .rodata" "letters: db \"xyz\", 0" "table: dq letters, letters+1, pointer, _start" \
    "section .data" "pointer: dq table" " dd letters" "section .bss" "scratch: resb 5000" "section .text" "global _start" \
    "_start: mov rax, [pointer]" " mov rax, [rax+8]" " movzx edi, byte [rax]" " mov rbx, scratch" " mov [rbx+4999], dil" \
    " mov eax, 60" " syscall"
both pointers-between-sections
{
    printf '%s\n' "default abs" "section .note.GNU-stack noalloc noexec nowrite progbits" "section .text" "global _start"
    printf '%s\n' "%assign label 0" "%rep 3000" "spot %+ label: nop" "%assign label label+1" "%endrep"
    printf '%s\n' "_start: mov eax, 60" " mov edi, 13" " syscall" "section .data"
    printf '%s\n' "%assign label 0" "%rep 3000" "address %+ label: dq spot %+ label" "%assign label label+1" "%endrep"
} > many-labels.asm
both many-labels

# A section by a name ld does not gather into .text, .rodata, .data or
# .bss: ld places it by its flags, which nasm -f bin does not keep.
program a-section-of-its-own "section .text" "global _start" "_start: mov eax, 60" " mov edi, [value]" " syscall" \
    "section .mydata write" "value: dd 4"
if guarded bash "$vox_tree/tools/voxelf/nasm-image.sh" a-section-of-its-own.asm a-section-of-its-own > said 2>&1; then
    failures=$((failures + 1)); echo "  FAIL a-section-of-its-own: nasm-image.sh took a section voxelf has no kind for"
elif grep -q "voxelf takes only .text, .rodata, .data and .bss so far" said; then
    passes=$((passes + 1))
else
    failures=$((failures + 1)); echo "  FAIL a-section-of-its-own: said [$(cat said)]"
fi

handed_to_ld=$(ld_pass_throughs)
if [ "$handed_to_ld" -ne 0 ]; then failures=$((failures + 1)); echo "  FAIL voxelf's side called ld $handed_to_ld times"; fi
echo "voxelf layouts: $passes passed, $failures failed; $handed_to_ld ld pass-throughs; links by ld: $reference_links references to compare with"
[ "$failures" -eq 0 ]
