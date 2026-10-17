# Instruction shapes of the assembly corpus

Written by `tests/toolchain/shapes.py` from the 46 files in `tests/corpus/` (compiler: vox v0.4.16 By Josjuar Lister 2026 (commit cb407f8)).
Do not edit by hand: regenerate it whenever the corpus changes. The same rows, with their bytes,
are in `shapes.tsv` beside this file, the skeleton of the encoder's test table.

## How it is derived

Each corpus file is preprocessed with `nasm -E -f elf64` (and `-DPIC` for a library, as the
compiler does for `--shared`), with coreasm on the include path, so `%include` and every coreasm
macro is expanded. Every instruction is then classified as a mnemonic and an operand shape:

- `r64`, `r32`, `r16`, `r8`: a general register. A register is named instead (`rax`, `al`, `cl`)
  where the encoding depends on which one it is: the shift count `cl`, the accumulator with an
  immediate where nasm uses the short accumulator form, and `xchg` with the accumulator.
- `xmm`, `st`, `mm`: SSE, x87 and MMX registers.
- `imm8`, `imm16`, `imm32`, `imm32u`, `imm64`: an immediate, by the smallest width that holds its
  value (`imm32u` holds it only as an unsigned 32-bit number). `equ` constants are evaluated where
  their value is known without encoding. `imm(label)` is an immediate that names a symbol. `1` is a
  shift by one, which has its own opcode.
- Memory: `[reg]`, `[reg+disp8]`, `[reg+disp32]`, `[reg+reg*scale+...]`, `[label]`, `[rel label]` and
  `[reg+label]`, prefixed by its size word when the line has one.
- `label`: the target of a jump or call.

Counts are occurrences in the preprocessed corpus, so a coreasm line counts once for every corpus
file that includes it; *Files* is how many corpus files use the shape. Each shape's example line is
assembled on its own with `nasm -f bin` at `org 0x401000`, every constant replaced by its value and
every label placed at the fixed address `0x500000` (far enough that a jump to it needs rel32): that
is *Bytes*. A jump is assembled a second time with its target just after it, to see whether nasm
picks rel8. A line that names a symbol is also assembled into an ELF object with the symbol
defined, and the listing's bytes are *Object bytes*, a relocated field in brackets: that is the form
in a linked program.

## Summary

- 46 corpus files: 58386 lines of compiler output, 231404 lines after preprocessing.
- 138157 instructions, 83 distinct mnemonics, 227 distinct mnemonic-and-shape pairs.
- 27 NASM syntax features and 4 operand forms outside the accepted subset (the next section).
- Jump widths: assembling the whole corpus, nasm encodes 15486 of 16672 jumps to a label as rel8, in 46
  of 46 files. vas encodes every jump as rel32, so those files' bytes will differ from nasm's in
  the whole-program comparison, and are compared by running them instead.

## Decisions: NASM features outside the accepted subset

The assembler brief accepts a fixed subset of NASM and refuses everything else by name. These are
the features the corpus uses that the subset does not list. Each one needs a decision: add it to the
subset, or change the compiler or coreasm so the corpus stops using it.

Syntax features are counted in the raw source the assembler reads: the corpus files and every
coreasm file they include, each coreasm file once. *Files* is how many corpus files reach the feature.

| Feature | Occurrences | Files | First seen |
|---|---:|---:|---|
| `%define` | 159 | 46 | coreasm/x86_64/core.asm:120 |
| `%endif` | 30 | 46 | coreasm/x86_64/io.asm:217 |
| `%ifdef` | 28 | 45 | coreasm/x86_64/io.asm:207 |
| `%else` | 4 | 45 | coreasm/x86_64/io.asm:215 |
| `operator \| (or)` | 5 | 33 | coreasm/x86_64/file.asm:61 |
| `operator ~ (not)` | 4 | 33 | coreasm/x86_64/heap.asm:23 |
| `operator << (shift left)` | 1 | 33 | coreasm/x86_64/resource_buffer.asm:1095 |
| `resd` | 1 | 33 | coreasm/x86_64/resource_fd.asm:45 |
| `section .rodata` | 1 | 33 | coreasm/x86_64/resource_fd.asm:274 |
| `%0 (parameter count)` | 2 | 29 | coreasm/x86_64/funcs.asm:81 |
| `%endrep` | 2 | 29 | coreasm/x86_64/funcs.asm:84 |
| `%rep` | 2 | 29 | coreasm/x86_64/funcs.asm:81 |
| `%rotate` | 2 | 29 | coreasm/x86_64/funcs.asm:83 |
| `%if` | 1 | 29 | coreasm/x86_64/funcs.asm:39 |
| `%ifndef` | 1 | 29 | coreasm/x86_64/funcs.asm:19 |
| `operator & (and)` | 1 | 29 | coreasm/x86_64/funcs.asm:27 |
| `SSE register (xmm)` | 241 | 22 | coreutils/cut.asm:1596 |
| `operator % (modulo)` | 2 | 20 | coreasm/x86_64/file.asm:535 |
| `octal constant` | 1 | 20 | coreasm/x86_64/file.asm:668 |
| `size word word` | 1 | 20 | coreasm/x86_64/file.asm:667 |
| `floating-point constant` | 24 | 10 | coreasm/x86_64/float.asm:18 |
| `align` | 2 | 10 | coreasm/x86_64/float.asm:17 |
| `operator / (divide)` | 1 | 7 | coreasm/x86_64/time.asm:404 |
| `default rel` | 5 | 5 | examples/mathkit_lib.asm:4 |
| `%undef` | 8 | 3 | coreasm/x86_64/format.asm:1504 |
| `section .fini_array progbits alloc write` | 3 | 3 | vox-libs/date.asm:818 |
| `extern` | 2 | 1 | examples/mathkit_consumer.asm:7 |

Operand forms the subset does not list, counted in the preprocessed corpus:

| Operand form | Occurrences | Files | Example | Source |
|---|---:|---:|---|---|
| memory operand [reg+reg*scale] | 1753 | 45 | `mov al, [rsi + rcx]` | coreasm/x86_64/io.asm:86 |
| memory operand [rel label+disp] | 152 | 45 | `lea rdi, [rel int_buffer + 20]` | coreasm/x86_64/io.asm:137 |
| memory operand [reg+reg*scale+disp8] | 489 | 38 | `cmp byte [r12 + 24 + r13], '-'` | coreasm/x86_64/resource_buffer.asm:1083 |
| register class xmm | 1058 | 10 | `movsd [rbp-8], xmm0` | coreasm/x86_64/float.asm:210 |

Features of the subset the corpus does use, for reference: `$ (current address)`, `%%local label`, `%endmacro`, `%include`, `%macro`, `character constant`, `db`, `decimal constant`, `dq`, `equ`, `global`, `hexadecimal constant 0x...`, `label name:`, `local label .name:`, `macro parameter (%1, %2, ...)`, `operator *`, `operator +`, `operator -`, `parentheses`, `rel`, `resb`, `resq`, `section .bss`, `section .data`, `section .note.GNU-stack noalloc noexec nowrite progbits`, `section .text`, `size word byte`, `size word dword`, `size word qword`, `string constant in quotes`.

## Instruction shapes

*Flags* mark what an encoder has to match: `rel8` where nasm would pick a short jump for a target in
reach (vas always encodes rel32), the object form of a symbol operand, nasm's 32-bit encoding of a
64-bit `mov` of a small immediate, the accumulator and shift-by-one short forms, and any warning nasm
printed for the line.

| Mnemonic | Operands | Count | Files | Example | Source | Bytes | Object bytes | Flags |
|---|---|---:|---:|---|---|---|---|---|
| `adc` | `r64, imm8` | 29 | 26 | `adc r12, 0` | coreasm/x86_64/int.asm:236 | `49 83 d4 00` | - |  |
| `add` | `[reg+disp8], r64` | 33 | 33 | `add [r13 + 8], rax` | coreasm/x86_64/resource_buffer.asm:680 | `49 01 45 08` | - |  |
| `add` | `[rel label], r64` | 8 | 8 | `add [rel _mk_next], rbx` | coreasm/x86_64/map.asm:203 | `48 01 1d f9 ef 0f 00` | `48 01 1d [00 00 00 00]` |  |
| `add` | `al, imm8` | 10 | 10 | `add al, '0'` | coreasm/x86_64/float.asm:936 | `04 30` | - | accumulator short form |
| `add` | `byte [reg+reg*scale], imm8` | 1 | 1 | `add byte [rsi + rdi], '0'` | coreasm/x86_64/format.asm:1478 | `80 04 3e 30` | - |  |
| `add` | `r64, [reg+disp8]` | 103 | 33 | `add rsi, [r13 + 8]` | coreasm/x86_64/resource_buffer.asm:669 | `49 03 75 08` | - |  |
| `add` | `r64, imm32` | 206 | 39 | `add rsp, 144` | coreasm/x86_64/resource_fd.asm:108 | `48 81 c4 90 00 00 00` | - |  |
| `add` | `r64, imm8` | 1243 | 43 | `add rax, 8` | coreasm/x86_64/resource_buffer.asm:104 | `48 83 c0 08` | - |  |
| `add` | `r64, r64` | 1195 | 43 | `add r14, rax` | coreasm/x86_64/resource_buffer.asm:681 | `49 01 c6` | - |  |
| `add` | `r8, imm8` | 309 | 45 | `add dl, '0'` | coreasm/x86_64/io.asm:155 | `80 c2 30` | - |  |
| `addsd` | `xmm, xmm` | 8 | 3 | `addsd xmm0, xmm1` | coreasm/x86_64/float.asm:34 | `f2 0f 58 c1` | - |  |
| `and` | `eax, imm32` | 20 | 20 | `and eax, 0o7777` | coreasm/x86_64/file.asm:668 | `25 ff 0f 00 00` | - | accumulator short form |
| `and` | `r16, imm16` | 10 | 10 | `and bx, 0xFCFF` | coreasm/x86_64/float.asm:449 | `66 81 e3 ff fc` | - |  |
| `and` | `r64, imm32` | 146 | 38 | `and r10, 0xF000` | coreasm/x86_64/resource_buffer.asm:718 | `49 81 e2 00 f0 00 00` | - |  |
| `and` | `r64, imm8` | 111 | 34 | `and rdx, 0xF` | coreasm/x86_64/resource_buffer.asm:1271 | `48 83 e2 0f` | - |  |
| `and` | `r64, r64` | 92 | 17 | `and rax, rbx` | coreutils/base64.asm:951 | `48 21 d8` | - |  |
| `and` | `r8, imm8` | 9 | 3 | `and cl, 1` | coreasm/x86_64/format.asm:179 | `80 e1 01` | - |  |
| `and` | `r8, r8` | 4 | 1 | `and al, bl` | coreasm/x86_64/float.asm:116 | `20 d8` | - |  |
| `and` | `rax, imm32` | 66 | 33 | `and rax, 0xF000` | coreasm/x86_64/resource_buffer.asm:569 | `48 25 00 f0 00 00` | - | accumulator short form |
| `btr` | `r64, imm8` | 2 | 1 | `btr rax, 63` | coreasm/x86_64/format.asm:1249 | `48 0f ba f0 3f` | - |  |
| `call` | `label` | 5482 | 44 | `call _flush_readahead_fd` | coreasm/x86_64/resource_fd.asm:176 | `e8 fb ef 0f 00` | - |  |
| `clc` |  | 17 | 17 | `clc` | coreasm/x86_64/list.asm:628 | `f8` | - |  |
| `cld` |  | 33 | 33 | `cld` | coreasm/x86_64/resource_buffer.asm:1131 | `fc` | - |  |
| `cmovge` | `r64, r64` | 24 | 8 | `cmovge r12, rbx` | coreasm/x86_64/map.asm:220 | `4c 0f 4d e3` | - |  |
| `cmovz` | `r64, r64` | 6 | 3 | `cmovz rax, rcx` | coreutils/cat.asm:355 | `48 0f 44 c1` | - |  |
| `cmp` | `[reg+reg*scale], r64` | 17 | 17 | `cmp [rax + rcx*8], rdi` | coreasm/x86_64/list.asm:615 | `48 39 3c c8` | - |  |
| `cmp` | `al, imm8` | 122 | 29 | `cmp al, 't'` | coreasm/x86_64/string.asm:277 | `3c 74` | - | accumulator short form |
| `cmp` | `byte [reg+disp8], imm8` | 25 | 25 | `cmp byte [rbx + 4], 0` | coreasm/x86_64/string.asm:272 | `80 7b 04 00` | - |  |
| `cmp` | `byte [reg+reg*scale+disp8], imm8` | 33 | 33 | `cmp byte [r12 + 24 + r13], '-'` | coreasm/x86_64/resource_buffer.asm:1083 | `43 80 7c 2c 18 2d` | - |  |
| `cmp` | `byte [reg+reg*scale], imm8` | 107 | 37 | `cmp byte [r13 + rcx], 0` | coreasm/x86_64/resource_buffer.asm:1029 | `41 80 7c 0d 00 00` | - |  |
| `cmp` | `byte [reg], imm8` | 26 | 12 | `cmp byte [r15], '0'` | coreasm/x86_64/float.asm:363 | `41 80 3f 30` | - |  |
| `cmp` | `byte [rel label], imm8` | 96 | 33 | `cmp byte [rel cleanup_done], 0` | coreasm/x86_64/resource_fd.asm:289 | `80 3d f9 ef 0f 00 00` | `80 3d [00 00 00 00] 00` |  |
| `cmp` | `qword [reg+disp32], imm8` | 27 | 4 | `cmp qword [rbp-144], 0` | coreutils/cut.asm:229 | `48 83 bd 70 ff ff ff 00` | - |  |
| `cmp` | `qword [reg+disp8], imm8` | 179 | 39 | `cmp qword [r13 + 8], 0` | coreasm/x86_64/resource_buffer.asm:551 | `49 83 7d 08 00` | - |  |
| `cmp` | `qword [reg], imm8` | 8 | 8 | `cmp qword [rdi], 0` | coreasm/x86_64/map.asm:361 | `48 83 3f 00` | - |  |
| `cmp` | `qword [rel label], imm8` | 160 | 35 | `cmp qword [rel _parsed_valid], 0` | coreasm/x86_64/args.asm:140 | `48 83 3d f8 ef 0f 00 00` | `48 83 3d [00 00 00 00] 00` |  |
| `cmp` | `r32, imm8` | 296 | 8 | `cmp r11d, 4` | coreutils/cut.asm:1561 | `41 83 fb 04` | - |  |
| `cmp` | `r64, [reg+disp32]` | 8 | 6 | `cmp rax, [rbp-136]` | coreutils/cat.asm:477 | `48 3b 85 78 ff ff ff` | - |  |
| `cmp` | `r64, [reg+disp8]` | 120 | 30 | `cmp rax, [rbp-72]` | coreutils/base64.asm:155 | `48 3b 45 b8` | - |  |
| `cmp` | `r64, [reg]` | 220 | 34 | `cmp rax, [r13 + 0]` | coreasm/x86_64/resource_buffer.asm:580 | `49 3b 45 00` | - |  |
| `cmp` | `r64, [rel label]` | 96 | 46 | `cmp rax, [rel _max_call_depth]` | coreasm/x86_64/core.asm:50 | `48 3b 05 f9 ef 0f 00` | `48 3b 05 [00 00 00 00]` |  |
| `cmp` | `r64, imm32` | 61 | 38 | `cmp r10, 0x8000` | coreasm/x86_64/resource_buffer.asm:719 | `49 81 fa 00 80 00 00` | - |  |
| `cmp` | `r64, imm8` | 2077 | 43 | `cmp rcx, 64` | coreasm/x86_64/resource_fd.asm:77 | `48 83 f9 40` | - |  |
| `cmp` | `r64, qword [rel label+disp]` | 1 | 1 | `cmp rax, qword [rel gvar_2+8]` | examples/delivery.asm:372 | `48 3b 05 01 f0 0f 00` | `48 3b 05 [08 00 00 00]` |  |
| `cmp` | `r64, qword [rel label]` | 1 | 1 | `cmp rax, qword [rel gvar_2]` | examples/delivery.asm:369 | `48 3b 05 f9 ef 0f 00` | `48 3b 05 [00 00 00 00]` |  |
| `cmp` | `r64, r64` | 2060 | 44 | `cmp rax, rdi` | coreasm/x86_64/resource_fd.asm:149 | `48 39 f8` | - |  |
| `cmp` | `r8, imm8` | 617 | 42 | `cmp dl, 9` | coreasm/x86_64/resource_buffer.asm:1272 | `80 fa 09` | - |  |
| `cmp` | `r8, r8` | 71 | 29 | `cmp al, bl` | coreasm/x86_64/string.asm:103 | `38 d8` | - |  |
| `cmp` | `rax, imm32` | 485 | 38 | `cmp rax, -4096` | coreasm/x86_64/resource_buffer.asm:102 | `48 3d 00 f0 ff ff` | - | accumulator short form |
| `cqo` |  | 21 | 9 | `cqo` | coreasm/x86_64/int.asm:49 | `48 99` | - |  |
| `cvtsi2sd` | `xmm, r64` | 52 | 10 | `cvtsi2sd xmm1, r12` | coreasm/x86_64/float.asm:319 | `f2 49 0f 2a cc` | - |  |
| `cvttsd2si` | `r64, xmm` | 123 | 10 | `cvttsd2si r12, xmm0` | coreasm/x86_64/float.asm:275 | `f2 4c 0f 2c e0` | - |  |
| `dec` | `qword [reg+disp8]` | 7 | 4 | `dec qword [rbp-40]` | coreutils/wc.asm:1253 | `48 ff 4d d8` | - |  |
| `dec` | `qword [rel label]` | 129 | 46 | `dec qword [rel _call_depth]` | coreasm/x86_64/core.asm:66 | `48 ff 0d f9 ef 0f 00` | `48 ff 0d [00 00 00 00]` |  |
| `dec` | `r64` | 1186 | 46 | `dec rdi` | coreasm/x86_64/io.asm:142 | `48 ff cf` | - |  |
| `div` | `r64` | 205 | 45 | `div rbx` | coreasm/x86_64/io.asm:153 | `48 f7 f3` | - |  |
| `divsd` | `xmm, xmm` | 3 | 2 | `divsd xmm0, xmm1` | coreasm/x86_64/float.asm:46 | `f2 0f 5e c1` | - |  |
| `fdiv` | `qword [reg+disp32]` | 10 | 10 | `fdiv qword [rsi + 22*8]` | coreasm/x86_64/float.asm:484 | `dc b6 b0 00 00 00` | - |  |
| `fdiv` | `qword [reg+reg*scale]` | 10 | 10 | `fdiv qword [rsi + rcx*8]` | coreasm/x86_64/float.asm:488 | `dc 34 ce` | - |  |
| `fild` | `qword [reg]` | 10 | 10 | `fild qword [rsp]` | coreasm/x86_64/float.asm:463 | `df 2c 24` | - |  |
| `fldcw` | `[reg+disp8]` | 20 | 10 | `fldcw [rsp + 12]` | coreasm/x86_64/float.asm:460 | `d9 6c 24 0c` | - |  |
| `fmul` | `qword [reg+disp32]` | 10 | 10 | `fmul qword [rsi + 22*8]` | coreasm/x86_64/float.asm:472 | `dc 8e b0 00 00 00` | - |  |
| `fmul` | `qword [reg+reg*scale]` | 10 | 10 | `fmul qword [rsi + rcx*8]` | coreasm/x86_64/float.asm:476 | `dc 0c ce` | - |  |
| `fnstcw` | `[reg+disp8]` | 10 | 10 | `fnstcw [rsp + 8]` | coreasm/x86_64/float.asm:447 | `d9 7c 24 08` | - |  |
| `fstp` | `qword [reg]` | 10 | 10 | `fstp qword [rsp]` | coreasm/x86_64/float.asm:491 | `dd 1c 24` | - |  |
| `idiv` | `r64` | 21 | 9 | `idiv rbx` | coreasm/x86_64/int.asm:50 | `48 f7 fb` | - |  |
| `imul` | `r64, [reg+disp8]` | 51 | 17 | `imul rbx, [r12 + 16]` | coreasm/x86_64/list.asm:82 | `49 0f af 5c 24 10` | - |  |
| `imul` | `r64, imm32` | 20 | 12 | `imul rax, 8192` | coreasm/x86_64/resource_readahead.asm:123 | `48 69 c0 00 20 00 00` | - |  |
| `imul` | `r64, imm8` | 144 | 8 | `imul rcx, 24` | coreasm/x86_64/map.asm:233 | `48 6b c9 18` | - |  |
| `imul` | `r64, r64` | 323 | 22 | `imul rax, rbx` | coreasm/x86_64/int.asm:16 | `48 0f af c3` | - |  |
| `imul` | `r64, r64, imm8` | 20 | 10 | `imul rax, rax, 10` | coreasm/x86_64/float.asm:582 | `48 6b c0 0a` | - |  |
| `inc` | `qword [reg+disp32]` | 10 | 8 | `inc qword [rbp-136]` | coreutils/base64.asm:512 | `48 ff 85 78 ff ff ff` | - |  |
| `inc` | `qword [reg+disp8]` | 263 | 32 | `inc qword [rbp-80]` | coreutils/base64.asm:168 | `48 ff 45 b0` | - |  |
| `inc` | `qword [rel label]` | 82 | 38 | `inc qword [rel fd_count]` | coreasm/x86_64/resource_fd.asm:89 | `48 ff 05 f9 ef 0f 00` | `48 ff 05 [00 00 00 00]` |  |
| `inc` | `r64` | 1832 | 46 | `inc rax` | coreasm/x86_64/core.asm:48 | `48 ff c0` | - |  |
| `inc` | `r8` | 1 | 1 | `inc al` | coreasm/x86_64/format.asm:1440 | `fe c0` | - |  |
| `ja` | `label` | 422 | 41 | `ja .failed` | coreasm/x86_64/resource_buffer.asm:103 | `0f 87 fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 77 00; vas always encodes rel32 |
| `jae` | `label` | 146 | 39 | `jae .rnt_digits_read` | coreasm/x86_64/int.asm:232 | `0f 83 fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 73 00; vas always encodes rel32 |
| `jb` | `label` | 226 | 39 | `jb .exact_fill_overflow` | coreasm/x86_64/resource_buffer.asm:727 | `0f 82 fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 72 00; vas always encodes rel32 |
| `jbe` | `label` | 477 | 42 | `jbe .presize_restore` | coreasm/x86_64/resource_buffer.asm:581 | `0f 86 fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 76 00; vas always encodes rel32 |
| `je` | `label` | 2113 | 44 | `je .found_fd` | coreasm/x86_64/resource_fd.asm:186 | `0f 84 fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 74 00; vas always encodes rel32 |
| `jg` | `label` | 144 | 46 | `jg .stack_overflow` | coreasm/x86_64/core.asm:51 | `0f 8f fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 7f 00; vas always encodes rel32 |
| `jge` | `label` | 764 | 41 | `jge .table_full` | coreasm/x86_64/resource_fd.asm:78 | `0f 8d fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 7d 00; vas always encodes rel32 |
| `jl` | `label` | 449 | 39 | `jl .next` | coreasm/x86_64/resource_fd.asm:220 | `0f 8c fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 7c 00; vas always encodes rel32 |
| `jle` | `label` | 1023 | 36 | `jle .mmap_alloc` | coreasm/x86_64/resource_buffer.asm:372 | `0f 8e fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 7e 00; vas always encodes rel32 |
| `jmp` | `label` | 5511 | 46 | `jmp .count_loop` | coreasm/x86_64/io.asm:90 | `e9 fb ef 0f 00` | - | rel8: nasm encodes a target in reach as eb 00; vas always encodes rel32 |
| `jnc` | `label` | 25 | 17 | `jnc .free_list_new_visit` | coreasm/x86_64/list.asm:681 | `0f 83 fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 73 00; vas always encodes rel32 |
| `jne` | `label` | 1240 | 43 | `jne .flush_next` | coreasm/x86_64/resource_fd.asm:150 | `0f 85 fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 75 00; vas always encodes rel32 |
| `jns` | `label` | 190 | 45 | `jns .positive` | coreasm/x86_64/io.asm:132 | `0f 89 fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 79 00; vas always encodes rel32 |
| `jnz` | `label` | 1253 | 46 | `jnz .convert_loop` | coreasm/x86_64/io.asm:141 | `0f 85 fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 75 00; vas always encodes rel32 |
| `jo` | `label` | 8 | 6 | `jo ..@289.div_fail` | coreasm/x86_64/int.asm:34 | `0f 80 fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 70 00; vas always encodes rel32 |
| `js` | `label` | 305 | 38 | `js .error` | coreasm/x86_64/file.asm:588 | `0f 88 fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 78 00; vas always encodes rel32 |
| `jz` | `label` | 2376 | 46 | `jz .do_print` | coreasm/x86_64/io.asm:88 | `0f 84 fa ef 0f 00` | - | rel8: nasm encodes a target in reach as 74 00; vas always encodes rel32 |
| `lea` | `r64, [reg+disp32]` | 12 | 4 | `lea rax, [rbp-136]` | coreutils/wc.asm:560 | `48 8d 85 78 ff ff ff` | - |  |
| `lea` | `r64, [reg+disp8]` | 1509 | 40 | `lea rdi, [r12 - 8]` | coreasm/x86_64/resource_buffer.asm:378 | `49 8d 7c 24 f8` | - |  |
| `lea` | `r64, [reg+reg*scale+disp8]` | 332 | 38 | `lea rsi, [r12 + 24 + r13 - 1]` | coreasm/x86_64/resource_buffer.asm:1126 | `4b 8d 74 2c 17` | - |  |
| `lea` | `r64, [reg+reg*scale]` | 183 | 34 | `lea rax, [rbx + rcx*8]` | coreasm/x86_64/resource_buffer.asm:225 | `48 8d 04 cb` | - |  |
| `lea` | `r64, [reg]` | 33 | 33 | `lea rsi, [rbp]` | coreasm/x86_64/resource_buffer.asm:1376 | `48 8d 75 00` | - |  |
| `lea` | `r64, [rel label+disp]` | 124 | 45 | `lea rdi, [rel int_buffer + 20]` | coreasm/x86_64/io.asm:137 | `48 8d 3d 0d f0 0f 00` | `48 8d 3d [14 00 00 00]` |  |
| `lea` | `r64, [rel label]` | 3461 | 46 | `lea rsi, [rel _stack_overflow_msg]` | coreasm/x86_64/core.asm:57 | `48 8d 35 f9 ef 0f 00` | `48 8d 35 [00 00 00 00]` |  |
| `leave` |  | 709 | 46 | `leave` | coreasm/x86_64/io.asm:99 | `c9` | - |  |
| `mov` | `[reg+disp32], r64` | 230 | 13 | `mov [rbp-144], rax` | coreutils/base64.asm:450 | `48 89 85 70 ff ff ff` | - |  |
| `mov` | `[reg+disp8], r16` | 10 | 10 | `mov [rsp + 12], bx` | coreasm/x86_64/float.asm:459 | `66 89 5c 24 0c` | - |  |
| `mov` | `[reg+disp8], r64` | 2688 | 43 | `mov [rdi + -8], rax` | coreasm/x86_64/resource_buffer.asm:226 | `48 89 47 f8` | - |  |
| `mov` | `[reg+disp8], r8` | 25 | 5 | `mov [rbp-104], r11b` | examples/map.asm:440 | `44 88 5d 98` | - |  |
| `mov` | `[reg+reg*scale+disp8], r64` | 19 | 17 | `mov [rax + rcx*8 + 8], rdx` | coreasm/x86_64/list.asm:929 | `48 89 54 c8 08` | - |  |
| `mov` | `[reg+reg*scale], r32` | 33 | 33 | `mov [rdx + r12*4], eax` | coreasm/x86_64/resource_fd.asm:104 | `42 89 04 a2` | - |  |
| `mov` | `[reg+reg*scale], r64` | 150 | 38 | `mov [rbx + rcx*8], rdi` | coreasm/x86_64/resource_fd.asm:88 | `48 89 3c cb` | - |  |
| `mov` | `[reg+reg*scale], r8` | 95 | 30 | `mov [rbx + rcx], al` | coreasm/x86_64/string.asm:176 | `88 04 0b` | - |  |
| `mov` | `[reg], r64` | 673 | 40 | `mov [rax + 0], r12` | coreasm/x86_64/resource_buffer.asm:172 | `4c 89 20` | - |  |
| `mov` | `[reg], r8` | 282 | 45 | `mov [rdi], dl` | coreasm/x86_64/io.asm:157 | `88 17` | - |  |
| `mov` | `[rel label], r64` | 931 | 46 | `mov [rel _call_depth], rax` | coreasm/x86_64/core.asm:49 | `48 89 05 f9 ef 0f 00` | `48 89 05 [00 00 00 00]` |  |
| `mov` | `byte [reg+disp32], imm8` | 8 | 1 | `mov byte [rbx + 128], 1` | coreasm/x86_64/list.asm:297 | `c6 83 80 00 00 00 01` | - |  |
| `mov` | `byte [reg+disp8], imm8` | 332 | 39 | `mov byte [rdi + 24], 0` | coreasm/x86_64/resource_buffer.asm:1178 | `c6 47 18 00` | - |  |
| `mov` | `byte [reg+reg*scale+disp8], imm8` | 33 | 33 | `mov byte [r12 + 24 + r9], 0` | coreasm/x86_64/resource_buffer.asm:1144 | `43 c6 44 0c 18 00` | - |  |
| `mov` | `byte [reg+reg*scale], imm8` | 69 | 36 | `mov byte [rbx + rcx], 0` | coreasm/x86_64/resource_fd.asm:152 | `c6 04 0b 00` | - |  |
| `mov` | `byte [reg], imm8` | 617 | 45 | `mov byte [rdi], 0` | coreasm/x86_64/io.asm:138 | `c6 07 00` | - |  |
| `mov` | `byte [rel label+disp], imm8` | 15 | 3 | `mov byte [rel _format_buffer + 40], '0'` | coreasm/x86_64/format.asm:874 | `c6 05 21 f0 0f 00 30` | `c6 05 [28 00 00 00] 30` |  |
| `mov` | `byte [rel label], imm8` | 89 | 33 | `mov byte [rel cleanup_done], 1` | coreasm/x86_64/resource_fd.asm:291 | `c6 05 f9 ef 0f 00 01` | `c6 05 [00 00 00 00] 01` |  |
| `mov` | `dword [reg+reg*scale], imm8` | 33 | 33 | `mov dword [rdx + r12*4], 0` | coreasm/x86_64/resource_fd.asm:113 | `42 c7 04 a2 00 00 00 00` | - |  |
| `mov` | `qword [reg+disp32], imm8` | 62 | 10 | `mov qword [rbp-136], 0` | coreutils/base64.asm:443 | `48 c7 85 78 ff ff ff 00 00 00 00` | - |  |
| `mov` | `qword [reg+disp8], imm8` | 893 | 39 | `mov qword [rax + 8], 0` | coreasm/x86_64/resource_buffer.asm:108 | `48 c7 40 08 00 00 00 00` | - |  |
| `mov` | `qword [reg+disp8], r64` | 38 | 18 | `mov qword [rdi + 8], rcx` | coreasm/x86_64/list.asm:520 | `48 89 4f 08` | - |  |
| `mov` | `qword [reg+reg*scale+disp8], imm8` | 17 | 17 | `mov qword [rax + r13*8 + 8], 0` | coreasm/x86_64/list.asm:934 | `4a c7 44 e8 08 00 00 00 00` | - |  |
| `mov` | `qword [reg+reg*scale], imm8` | 245 | 33 | `mov qword [rdx + r12*8], 0` | coreasm/x86_64/resource_fd.asm:115 | `4a c7 04 e2 00 00 00 00` | - |  |
| `mov` | `qword [reg], imm32` | 33 | 33 | `mov qword [rax + 0], 4096` | coreasm/x86_64/resource_buffer.asm:107 | `48 c7 00 00 10 00 00` | - |  |
| `mov` | `qword [reg], imm8` | 112 | 38 | `mov qword [rax], 0` | coreasm/x86_64/resource_buffer.asm:245 | `48 c7 00 00 00 00 00` | - |  |
| `mov` | `qword [reg], r64` | 28 | 20 | `mov qword [rdi + 0], r13` | coreasm/x86_64/list.asm:518 | `4c 89 2f` | - |  |
| `mov` | `qword [rel label+disp], r64` | 4 | 1 | `mov qword [rel gvar_3+8], rax` | examples/delivery.asm:191 | `48 89 05 01 f0 0f 00` | `48 89 05 [08 00 00 00]` |  |
| `mov` | `qword [rel label], imm8` | 2274 | 42 | `mov qword [rel fd_count], 0` | coreasm/x86_64/resource_fd.asm:234 | `48 c7 05 f5 ef 0f 00 00 00 00 00` | `48 c7 05 [00 00 00 00] 00 00 00 00` |  |
| `mov` | `qword [rel label], r64` | 1 | 1 | `mov qword [rel gvar_3], rax` | examples/delivery.asm:189 | `48 89 05 f9 ef 0f 00` | `48 89 05 [00 00 00 00]` |  |
| `mov` | `r16, [reg+disp8]` | 10 | 10 | `mov bx, [rsp + 8]` | coreasm/x86_64/float.asm:448 | `66 8b 5c 24 08` | - |  |
| `mov` | `r32, [reg+disp8]` | 33 | 33 | `mov eax, [rsp + 24]` | coreasm/x86_64/resource_fd.asm:103 | `8b 44 24 18` | - |  |
| `mov` | `r32, [reg+reg*scale]` | 66 | 33 | `mov eax, [rdx + rcx*4]` | coreasm/x86_64/resource_buffer.asm:622 | `8b 04 8a` | - |  |
| `mov` | `r32, [rel label]` | 5 | 4 | `mov ecx, [rel _reaped_status]` | coreasm/x86_64/proc.asm:284 | `8b 0d fa ef 0f 00` | `8b 0d [00 00 00 00]` |  |
| `mov` | `r32, imm8` | 539 | 10 | `mov edx, 0` | coreutils/cut.asm:1428 | `ba 00 00 00 00` | - |  |
| `mov` | `r32, r32` | 2 | 2 | `mov edx, r11d` | examples/walker.asm:267 | `44 89 da` | - |  |
| `mov` | `r64, [reg+disp32]` | 291 | 12 | `mov rax, [rbp-136]` | coreutils/base64.asm:445 | `48 8b 85 78 ff ff ff` | - |  |
| `mov` | `r64, [reg+disp8]` | 5542 | 43 | `mov rax, [rax + 48]` | coreasm/x86_64/file.asm:592 | `48 8b 40 30` | - |  |
| `mov` | `r64, [reg+reg*scale+disp8]` | 33 | 17 | `mov rdi, [r12 + rax + 24]` | coreasm/x86_64/list.asm:708 | `49 8b 7c 04 18` | - |  |
| `mov` | `r64, [reg+reg*scale]` | 425 | 38 | `mov rax, [rbx + rcx*8]` | coreasm/x86_64/resource_fd.asm:80 | `48 8b 04 cb` | - |  |
| `mov` | `r64, [reg]` | 1519 | 40 | `mov rsi, [rdi + 0]` | coreasm/x86_64/resource_buffer.asm:273 | `48 8b 37` | - |  |
| `mov` | `r64, [rel label]` | 1165 | 46 | `mov rax, [rel _call_depth]` | coreasm/x86_64/core.asm:47 | `48 8b 05 f9 ef 0f 00` | `48 8b 05 [00 00 00 00]` |  |
| `mov` | `r64, imm(label)` | 23 | 3 | `mov r13, str_4` | coreasm/x86_64/file.asm:270 | `49 bd 00 00 50 00 00 00 00 00` | `49 bd [00 00 00 00 00 00 00 00]` |  |
| `mov` | `r64, imm32` | 538 | 36 | `mov rsi, 4096 + 24 + 1 + 8` | coreasm/x86_64/resource_buffer.asm:90 | `be 21 10 00 00` | - | nasm encodes this 64-bit mov as a 32-bit mov (no REX.W), which zero-extends |
| `mov` | `r64, imm32u` | 11 | 2 | `mov rdi, 0xFEE1DEAD` | coreasm/x86_64/proc.asm:179 | `bf ad de e1 fe` | - | nasm encodes this 64-bit mov as a 32-bit mov (no REX.W), which zero-extends |
| `mov` | `r64, imm64` | 136 | 39 | `mov rax, 1 << 46` | coreasm/x86_64/resource_buffer.asm:1095 | `48 b8 00 00 00 00 00 40 00 00` | - |  |
| `mov` | `r64, imm8` | 10954 | 46 | `mov rax, 1` | coreasm/x86_64/core.asm:55 | `b8 01 00 00 00` | - | nasm encodes this 64-bit mov as a 32-bit mov (no REX.W), which zero-extends |
| `mov` | `r64, qword [reg+disp32]` | 7 | 1 | `mov rax, qword [rbp-208]` | vox-libs/date.asm:14319 | `48 8b 85 30 ff ff ff` | - |  |
| `mov` | `r64, qword [reg+disp8]` | 6 | 2 | `mov rax, qword [rbp-104]` | vox-libs/date.asm:8092 | `48 8b 45 98` | - |  |
| `mov` | `r64, qword [rel label+disp]` | 8 | 1 | `mov rdi, qword [rel gvar_2+8]` | examples/delivery.asm:182 | `48 8b 3d 01 f0 0f 00` | `48 8b 3d [08 00 00 00]` |  |
| `mov` | `r64, qword [rel label]` | 4 | 1 | `mov rdi, qword [rel gvar_2]` | examples/delivery.asm:178 | `48 8b 3d f9 ef 0f 00` | `48 8b 3d [00 00 00 00]` |  |
| `mov` | `r64, r64` | 10812 | 46 | `mov rbp, rsp` | coreasm/x86_64/io.asm:79 | `48 89 e5` | - |  |
| `mov` | `r8, [reg+disp8]` | 125 | 37 | `mov dl, [rbx + 1]` | coreasm/x86_64/int.asm:125 | `8a 53 01` | - |  |
| `mov` | `r8, [reg+reg*scale]` | 252 | 45 | `mov al, [rsi + rcx]` | coreasm/x86_64/io.asm:86 | `8a 04 0e` | - |  |
| `mov` | `r8, [reg]` | 329 | 40 | `mov dl, [rbx + 0]` | coreasm/x86_64/int.asm:125 | `8a 13` | - |  |
| `mov` | `r8, imm8` | 725 | 34 | `mov r8b, ' '` | coreasm/x86_64/resource_buffer.asm:1075 | `41 b0 20` | - |  |
| `mov` | `r8, r8` | 30 | 6 | `mov cl, bl` | coreutils/base64.asm:841 | `88 d9` | - |  |
| `movq` | `r64, xmm` | 98 | 10 | `movq rdi, xmm0` | coreasm/x86_64/float.asm:247 | `66 48 0f 7e c7` | - |  |
| `movq` | `xmm, [reg]` | 6 | 6 | `movq xmm0, [r14]` | coreasm/x86_64/list.asm:1049 | `f3 41 0f 7e 06` | - |  |
| `movq` | `xmm, r64` | 187 | 10 | `movq xmm1, rax` | coreasm/x86_64/float.asm:228 | `66 48 0f 6e c8` | - |  |
| `movsd` | `[reg+disp8], xmm` | 20 | 10 | `movsd [rbp-8], xmm0` | coreasm/x86_64/float.asm:210 | `f2 0f 11 45 f8` | - |  |
| `movsd` | `xmm, [reg+disp8]` | 40 | 10 | `movsd xmm0, [rbp-8]` | coreasm/x86_64/float.asm:226 | `f2 0f 10 45 f8` | - |  |
| `movsd` | `xmm, [reg]` | 10 | 10 | `movsd xmm0, [rsp]` | coreasm/x86_64/float.asm:493 | `f2 0f 10 04 24` | - |  |
| `movsd` | `xmm, [rel label]` | 54 | 10 | `movsd xmm1, [rel _float_int64_boundary]` | coreasm/x86_64/float.asm:243 | `f2 0f 10 0d f8 ef 0f 00` | `f2 0f 10 0d [00 00 00 00]` |  |
| `movsd` | `xmm, xmm` | 20 | 10 | `movsd xmm0, xmm1` | coreasm/x86_64/float.asm:395 | `f2 0f 10 c1` | - |  |
| `movzx` | `r32, byte [reg+disp8]` | 31 | 8 | `movzx r15d, byte [rax + 16]` | coreasm/x86_64/map.asm:567 | `44 0f b6 78 10` | - |  |
| `movzx` | `r32, byte [reg+reg*scale]` | 54 | 33 | `movzx eax, byte [rbx + rcx]` | coreasm/x86_64/resource_fd.asm:144 | `0f b6 04 0b` | - |  |
| `movzx` | `r32, byte [reg]` | 34 | 17 | `movzx r15d, byte [rbx]` | coreasm/x86_64/list.asm:698 | `44 0f b6 3b` | - |  |
| `movzx` | `r32, byte [rel label]` | 14 | 7 | `movzx ebx, byte [rel line_read_fallback_tmp]` | coreasm/x86_64/resource_readahead.asm:271 | `0f b6 1d f9 ef 0f 00` | `0f b6 1d [00 00 00 00]` |  |
| `movzx` | `r32, r8` | 36 | 34 | `movzx eax, r8b` | coreasm/x86_64/resource_buffer.asm:1141 | `41 0f b6 c0` | - |  |
| `movzx` | `r32, word [reg+disp8]` | 20 | 20 | `movzx eax, word [rax + 24]` | coreasm/x86_64/file.asm:667 | `0f b7 40 18` | - |  |
| `movzx` | `r64, byte [reg+disp8]` | 53 | 9 | `movzx r11, byte [rsi + 16]` | coreasm/x86_64/map.asm:510 | `4c 0f b6 5e 10` | - |  |
| `movzx` | `r64, byte [reg+reg*scale+disp8]` | 22 | 9 | `movzx rdx, byte [rsi + rdx + 16]` | coreasm/x86_64/map.asm:839 | `48 0f b6 54 16 10` | - |  |
| `movzx` | `r64, byte [reg+reg*scale]` | 3 | 1 | `movzx rax, byte [rsi + rdi]` | coreasm/x86_64/format.asm:1355 | `48 0f b6 04 3e` | - |  |
| `movzx` | `r64, byte [reg]` | 41 | 22 | `movzx rax, byte [rax]` | coreutils/cat.asm:356 | `48 0f b6 00` | - |  |
| `movzx` | `r64, r8` | 222 | 34 | `movzx rcx, dl` | coreasm/x86_64/int.asm:219 | `48 0f b6 ca` | - |  |
| `mul` | `r64` | 29 | 26 | `mul r8` | coreasm/x86_64/int.asm:233 | `49 f7 e0` | - |  |
| `mulsd` | `xmm, xmm` | 26 | 10 | `mulsd xmm0, xmm1` | coreasm/x86_64/float.asm:325 | `f2 0f 59 c1` | - |  |
| `neg` | `r64` | 332 | 46 | `neg rax` | coreasm/x86_64/io.asm:133 | `48 f7 d8` | - |  |
| `nop` |  | 20 | 10 | `nop` | coreasm/x86_64/float.asm:17 | `90` | - |  |
| `or` | `al, imm8` | 100 | 25 | `or al, 0x20` | coreasm/x86_64/string.asm:276 | `0c 20` | - | accumulator short form |
| `or` | `r16, imm16` | 20 | 10 | `or bx, 0x0200` | coreasm/x86_64/float.asm:454 | `66 81 cb 00 02` | - |  |
| `or` | `r64, r64` | 117 | 26 | `or r12, rdx` | coreasm/x86_64/int.asm:234 | `49 09 d4` | - |  |
| `or` | `r8, imm8` | 50 | 25 | `or dl, 0x20` | coreasm/x86_64/int.asm:184 | `80 ca 20` | - |  |
| `pop` | `r64` | 16697 | 46 | `pop rbx` | coreasm/x86_64/io.asm:98 | `5b` | - |  |
| `push` | `imm8` | 2 | 1 | `push 10` | coreasm/x86_64/file.asm:334 | `6a 0a` | - |  |
| `push` | `r64` | 16250 | 46 | `push rbp` | coreasm/x86_64/io.asm:78 | `55` | - |  |
| `rep movsb` |  | 463 | 38 | `rep movsb` | coreasm/x86_64/resource_buffer.asm:439 | `f3 a4` | - |  |
| `rep stosb` |  | 36 | 34 | `rep stosb` | coreasm/x86_64/resource_buffer.asm:1142 | `f3 aa` | - |  |
| `ret` |  | 3276 | 46 | `ret` | coreasm/x86_64/core.asm:52 | `c3` | - |  |
| `roundsd` | `xmm, xmm, imm8` | 20 | 10 | `roundsd xmm0, xmm0, 0` | coreasm/x86_64/float.asm:328 | `66 0f 3a 0b c0 00` | - |  |
| `seta` | `r8` | 1 | 1 | `seta al` | coreasm/x86_64/float.asm:114 | `0f 97 c0` | - |  |
| `setb` | `r8` | 2 | 1 | `setb al` | coreasm/x86_64/float.asm:96 | `0f 92 c0` | - |  |
| `sete` | `r8` | 66 | 35 | `sete bl` | coreasm/x86_64/resource_buffer.asm:819 | `0f 94 c3` | - |  |
| `setg` | `r8` | 4 | 3 | `setg al` | coreasm/x86_64/int.asm:89 | `0f 9f c0` | - |  |
| `setge` | `r8` | 5 | 2 | `setge al` | coreasm/x86_64/int.asm:95 | `0f 9d c0` | - |  |
| `setl` | `r8` | 1 | 1 | `setl al` | coreasm/x86_64/int.asm:77 | `0f 9c c0` | - |  |
| `setle` | `r8` | 7 | 4 | `setle al` | coreasm/x86_64/int.asm:83 | `0f 9e c0` | - |  |
| `setne` | `r8` | 64 | 4 | `setne al` | coreasm/x86_64/int.asm:71 | `0f 95 c0` | - |  |
| `setnp` | `r8` | 4 | 1 | `setnp bl` | coreasm/x86_64/float.asm:115 | `0f 9b c3` | - |  |
| `setnz` | `r8` | 2 | 1 | `setnz al` | examples/args_and_env.asm:595 | `0f 95 c0` | - |  |
| `setz` | `r8` | 8 | 8 | `setz al` | coreutils/base64.asm:382 | `0f 94 c0` | - |  |
| `shl` | `r64, 1` | 121 | 38 | `shl rax, 1` | coreasm/x86_64/resource_buffer.asm:498 | `48 d1 e0` | - | shift-by-one form (D0/D1) |
| `shl` | `r64, cl` | 7 | 3 | `shl rax, cl` | coreutils/base64.asm:842 | `48 d3 e0` | - |  |
| `shl` | `r64, imm8` | 281 | 21 | `shl rax, 52` | coreasm/x86_64/float.asm:894 | `48 c1 e0 34` | - |  |
| `shr` | `r64, 1` | 48 | 35 | `shr rax, 1` | coreasm/x86_64/resource_buffer.asm:1310 | `48 d1 e8` | - | shift-by-one form (D0/D1) |
| `shr` | `r64, cl` | 20 | 5 | `shr rax, cl` | coreutils/base64.asm:949 | `48 d3 e8` | - |  |
| `shr` | `r64, imm8` | 130 | 35 | `shr rax, 4` | coreasm/x86_64/resource_buffer.asm:1290 | `48 c1 e8 04` | - |  |
| `stc` |  | 34 | 17 | `stc` | coreasm/x86_64/list.asm:620 | `f9` | - |  |
| `std` |  | 33 | 33 | `std` | coreasm/x86_64/resource_buffer.asm:1129 | `fd` | - |  |
| `sub` | `r64, [reg+disp8]` | 161 | 34 | `sub rax, [r13 + 8]` | coreasm/x86_64/resource_buffer.asm:638 | `49 2b 45 08` | - |  |
| `sub` | `r64, imm32` | 126 | 35 | `sub rsp, 144` | coreasm/x86_64/resource_fd.asm:95 | `48 81 ec 90 00 00 00` | - |  |
| `sub` | `r64, imm8` | 637 | 46 | `sub rsp, 32` | coreasm/x86_64/io.asm:125 | `48 83 ec 20` | - |  |
| `sub` | `r64, r64` | 453 | 35 | `sub rdx, r14` | coreasm/x86_64/resource_buffer.asm:851 | `4c 29 f2` | - |  |
| `subsd` | `xmm, xmm` | 43 | 10 | `subsd xmm0, xmm1` | coreasm/x86_64/float.asm:320 | `f2 0f 5c c1` | - |  |
| `syscall` |  | 2875 | 46 | `syscall` | coreasm/x86_64/core.asm:59 | `0f 05` | - |  |
| `test` | `qword [reg+disp8], imm8` | 297 | 33 | `test qword [rdi + 16], 2` | coreasm/x86_64/resource_buffer.asm:262 | `48 f7 47 10 02 00 00 00` | - |  |
| `test` | `r32, r32` | 40 | 33 | `test eax, eax` | coreasm/x86_64/resource_fd.asm:145 | `85 c0` | - |  |
| `test` | `r64, imm8` | 180 | 33 | `test r15, 1` | coreasm/x86_64/resource_buffer.asm:549 | `49 f7 c7 01 00 00 00` | - |  |
| `test` | `r64, r64` | 3450 | 46 | `test rax, rax` | coreasm/x86_64/io.asm:131 | `48 85 c0` | - |  |
| `test` | `r8, r8` | 192 | 46 | `test al, al` | coreasm/x86_64/io.asm:87 | `84 c0` | - |  |
| `ucomisd` | `xmm, xmm` | 44 | 10 | `ucomisd xmm0, xmm1` | coreasm/x86_64/float.asm:214 | `66 0f 2e c1` | - |  |
| `xchg` | `r64, r64` | 25 | 25 | `xchg rsi, rdx` | coreasm/x86_64/int.asm:347 | `48 87 f2` | - |  |
| `xor` | `r32, r32` | 586 | 39 | `xor ebx, ebx` | coreasm/x86_64/resource_buffer.asm:539 | `31 db` | - |  |
| `xor` | `r64, r64` | 2410 | 46 | `xor rcx, rcx` | coreasm/x86_64/io.asm:83 | `48 31 c9` | - |  |
| `xorpd` | `xmm, xmm` | 70 | 10 | `xorpd xmm1, xmm1` | coreasm/x86_64/float.asm:213 | `66 0f 57 c9` | - |  |

## Directives

Counted in the preprocessed corpus, where nasm has already rewritten `section`, `global` and
`extern` as their bracketed primitive forms and `align` as `times ... nop`.

| Directive | Count | Files | Example | Source |
|---|---:|---:|---|---|
| `db` | 1988 | 46 | `_stack_overflow_msg: db "Error: stack overflow (recursion depth exceeded)", 10, 0` | coreasm/x86_64/core.asm:39 |
| `default rel` | 5 | 5 | `[default rel]` | examples/mathkit_lib.asm:4 |
| `dq` | 252 | 46 | `_max_call_depth: dq 10000` | coreasm/x86_64/core.asm:32 |
| `equ` | 1783 | 46 | `_stack_overflow_msg_len: equ $ - _stack_overflow_msg - 1` | coreasm/x86_64/core.asm:40 |
| `extern` | 2 | 1 | `[extern mathkit_1_0_add_two_numbers]` | examples/mathkit_consumer.asm:7 |
| `global` | 1758 | 46 | `[global _file_size]` | coreasm/x86_64/file.asm:578 |
| `resb` | 229 | 35 | `stat_buf: resb 144` | coreasm/x86_64/file.asm:571 |
| `resd` | 33 | 33 | `fd_mode_table: resd 64` | coreasm/x86_64/resource_fd.asm:45 |
| `resq` | 1018 | 46 | `_last_error: resq 1` | coreasm/x86_64/core.asm:10 |
| `sectalign` | 20 | 10 | `[sectalign 8]` | coreasm/x86_64/float.asm:17 |
| `section .bss` | 261 | 46 | `[section .bss]` | coreasm/x86_64/core.asm:6 |
| `section .data` | 232 | 46 | `[section .data]` | coreasm/x86_64/core.asm:31 |
| `section .fini_array progbits alloc write` | 3 | 3 | `[section .fini_array progbits alloc write]` | vox-libs/date.asm:818 |
| `section .note.GNU-stack noalloc noexec nowrite progbits` | 46 | 46 | `[section .note.GNU-stack noalloc noexec nowrite progbits]` | coreutils/base64.asm:15 |
| `section .rodata` | 33 | 33 | `[section .rodata]` | coreasm/x86_64/resource_fd.asm:274 |
| `section .text` | 468 | 46 | `[section .text]` | coreasm/x86_64/core.asm:42 |
| `times` | 68 | 45 | `int_buffer: times 21 db 0` | coreasm/x86_64/io.asm:10 |

## Encoding cases

The encoding details the brief names as traps, with how often the corpus meets each one. Every case
here needs a focused encoder test.

| Case | Count | Example | Source |
|---|---:|---|---|
| RIP-relative memory [rel label] | 8722 | `mov rax, [rel _call_depth]` | coreasm/x86_64/core.asm:47 |
| a 16-bit operand (0x66 prefix) | 50 | `mov bx, [rsp + 8]` | coreasm/x86_64/float.asm:448 |
| a 32-bit displacement | 675 | `mov qword [rbp-136], 0` | coreutils/base64.asm:443 |
| a full 64-bit immediate | 136 | `mov rax, 1 << 46` | coreasm/x86_64/resource_buffer.asm:1095 |
| a jump or call to a label (rel32 in vas) | 22154 | `jg .stack_overflow` | coreasm/x86_64/core.asm:51 |
| a register r8 to r15 (REX.R, REX.X or REX.B) | 27992 | `mov r8, 0` | coreasm/x86_64/io.asm:129 |
| a rep prefix | 499 | `rep movsb` | coreasm/x86_64/resource_buffer.asm:439 |
| an 8-bit displacement | 13133 | `mov rax, [rax + 48]` | coreasm/x86_64/file.asm:592 |
| an imm8 sign-extended into a wider operation | 5841 | `sub rsp, 32` | coreasm/x86_64/io.asm:125 |
| memory [rbp] or [r13] with no displacement (needs disp8 0) | 405 | `mov qword [r13 + rcx*8], 0` | coreasm/x86_64/resource_fd.asm:154 |
| memory based on rsp or r12 (needs a SIB byte) | 2564 | `mov eax, [rsp + 24]` | coreasm/x86_64/resource_fd.asm:103 |
| memory with an index register (SIB byte) | 2242 | `mov al, [rsi + rcx]` | coreasm/x86_64/io.asm:86 |
