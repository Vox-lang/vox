# vas: the front end

vas is the Vox assembler: it reads the NASM-dialect assembly the Vox compiler
writes and will turn it into machine code for the voxelf linker, so that
building a Vox program needs neither nasm nor ld. It is written in Vox, as a
library, in `vas.vox`.

This directory holds its front end. The front end reads a source file and
everything it includes, runs the preprocessor, follows the sections, and
parses every statement into a record for the encoder, which comes next. It
accepts exactly the NASM constructs found in the compiler's output and in
coreasm, and refuses everything else by name, with the file and the line.

## What the front end does

1. Reads the whole file into a buffer and cuts it into lines, each without
   its comment (a semicolon outside quotes starts one). Every line keeps its
   file and line number, for the diagnostics.
2. Runs the preprocessor over the lines. `%include` reads another file.
   `%define` and `%undef` keep single-line macros, which are expanded
   wherever their names appear and rescanned for macros of their own. `%if`,
   `%ifdef`, `%ifndef`, `%else` and `%endif` choose which lines are kept.
   `%macro` keeps a multi-line macro's body, which is expanded where the
   macro is called, with its parameters put in and its `%%labels` renamed
   `..@<number>.label`, one number to each expansion, as NASM names them.
   `%rep` repeats lines and `%rotate` turns a macro's arguments. Macro
   expansion, the rescanning of single-line macros and `%include` each
   nest no deeper than `'deepest nesting'` in `vas.vox`: 16 levels.
3. Follows the `section`, `global`, `default rel` and `align` directives,
   and records whether the stack is to be executable.
4. Classifies every statement as a label, a constant, a directive or an
   instruction, and parses it into a record: the mnemonic and its operands,
   each a register, a memory reference taken apart into base, index, scale
   and displacement, or an expression. A local label, one that begins with a
   dot, belongs to the last label that does not.
5. Works out every expression that holds only numbers and constants already
   known, `equ` constants among them. An expression that depends on a label
   or on `$` is left for the encoder, which knows the addresses.

## What it accepts

The list is the corpus's: the constructs `tests/toolchain/SHAPES.md` finds in
the compiler's output and coreasm, and nothing else.

| Kind | Accepted |
|---|---|
| Preprocessor | `%include "file"`; `%define NAME body` and `%define NAME(a,b) body`; `%undef NAME`; `%if EXPRESSION` and `%if EXPRESSION > EXPRESSION`; `%ifdef NAME`; `%ifndef NAME`; `%else`; `%endif`; `%macro NAME N` and `%macro NAME N-*`; `%endmacro`; `%1` and on, `%0`, `%%label`; `%rotate N`; `%rep N` and `%endrep` |
| Sections | `section .text`, `.data`, `.bss`, `.rodata`; `section .note.GNU-stack noalloc noexec nowrite progbits`, which marks the stack as not executable |
| Directives | `global`; `default rel`; `align N`, a power of two; `db`, `dq`; `resb`, `resd`, `resq`; `name: equ EXPRESSION`; `times N` before a data directive or an instruction |
| Labels | `name:`; `.local:`, scoped to the label before it |
| Instructions | `adc add addsd and andpd btr call clc cld cmovg cmovge cmovl cmovz cmp cqo cvtsi2sd cvttsd2si dec div divsd fdiv fild fldcw fmul fnstcw fstp idiv imul inc ja jae jb jbe je jg jge jl jle jmp jnc jne jns jnz jo js jz lea leave mov movq movsd movzx mul mulsd neg nop not or pop push ret roundsd sar seta setae setb setbe sete setg setge setl setle setne setnp setnz setp setz shl shr stc std sub subsd syscall test ucomisd xchg xor xorpd`, and `rep movsb`, `rep stosb` |
| Registers | the general registers in their 64, 32, 16 and 8-bit forms (`rax` to `r15`, `eax` to `r15d`, `ax` to `r15w`, `al`, `cl`, `dl`, `bl`, `spl`, `bpl`, `sil`, `dil`, `r8b` to `r15b`), and `xmm0` to `xmm15` |
| Operands | a register; a size word, `byte`, `word`, `dword` or `qword`, before a memory reference or an immediate; memory as `[base]`, `[base + displacement]`, `[base + index * scale + displacement]` with its terms in any order, `[rel label]` and `[rel label + displacement]`, through 64-bit registers; an expression, as an immediate or a jump's or a call's target |
| Expressions | decimal, `0x` hexadecimal and `0o` octal numbers; characters and strings in single or double quotes; floating-point numbers, as whole items of `dq`; names; `$`; the operators `+`, `-`, `*`, `/`, `%`, `<<`, `&`, `|` and the unary `-`, `+` and `~`, with NASM's precedence; parentheses |

Mnemonics, registers, size words and directives are taken in lower case, as
the compiler and coreasm write them. `/` and `%` are worked out on values
that are not negative, where NASM's unsigned division agrees with a signed
one.

## What it refuses

Everything else is refused, naming the construct, with the file and the
line, and the call that met it answers a count of errors instead of writing
its output. Among what NASM has and the corpus does not use:

- `extern` and `section .fini_array`, which only a shared build writes:
  shared builds still use nasm, and vas stops reading a source at the
  first of them it meets;
- `incbin`, `struc`, `istruc`, `bits`, `org`, `absolute`, `common`,
  `segment` and NASM's other directives;
- `dw`, `dd`, `resw` and the wider data and reservation directives;
- `%assign`, `%xdefine`, `%idefine`, `%elif`, `%push`, `%pop` and every
  other preprocessor directive; token pasting with `%+`, context-local
  names, braced parameters and backquoted strings;
- `default abs`, `abs`, segment overrides and 32-bit addressing;
- the size words beyond the four, and the jump qualifiers `short`, `near`,
  `far` and `strict`;
- `ah`, `bh`, `ch`, `dh`, and the segment, x87, MMX and AVX registers;
- the operators `^`, `>>`, `//`, `%%` and `!`, and every comparison but `>`
  in `%if`;
- `0b` binary numbers, NASM's suffix forms such as `10h`, `$$`, and names
  written after a `$`;
- the prefixes other than `rep`, and `rep` before anything but `movsb` and
  `stosb`;
- a macro parameter count other than `N` and `N-*`.

`tests/toolchain/vas/refusals/` holds a test for each kind of refusal, with
the exact message it gives.

## The interface

The public entries take and return only paths, numbers and texts, so a host
that is not Vox can call them through `libvas.so`:

| Function | Symbol | What it does |
|---|---|---|
| `'expand file' of <source> and <coreasm directory> and <output path>` | `vas_0_1_expand_file` | Preprocesses the source and writes the expansion, one statement per line, to the output path. Answers the number of errors: 0 when the expansion was written. |
| `'expand file with definitions' of <source> and <coreasm directory> and <output path> and <definitions>` | `vas_0_1_expand_file_with_definitions` | The same, with single-line macros defined before the source is read, as nasm's `-D` defines them: words separated by spaces, each `NAME` or `NAME=VALUE`. |
| `'assembler diagnostics' of <output path>` | `vas_0_1_assembler_diagnostics` | The messages of the last failing call that wrote to that output path, one per line, each `<file>:<line>: <message>`. |

A shared library keeps nothing between calls, since only functions may stand
at its top level, so a failing call writes its messages to
`<output path>.diagnostics`, and `'assembler diagnostics'` reads them back
from there. A failing call never writes the output, and a call that succeeds
removes a diagnostics file an earlier call left.

`%include` looks for a file beside the file that includes it, then in the
directory that holds the coreasm directory (the compiler names its includes
`coreasm/<arch>/<file>.asm`), then in the coreasm directory itself.

A Vox program can skip the files and call the front end directly:

    'read the source' with <source> and <coreasm directory> and <definitions>
        and <what vas knows> and <statements list> and <diagnostics buffer>

It fills the statements list with one record per statement, in order, puts
the messages in the diagnostics buffer, leaves in the map `'what vas knows'`
what the front end learnt (the globals, the constants it worked out, whether the stack
is to be executable), and answers the number of errors. Each record is a map;
the comment above `'record the statement'` in `vas.vox` lists its fields for
every kind of statement.

## Building and using it

Build the shared library, then either `see` its interface or pull the source
into a program:

    vox tools/vas/vas.vox --shared -o libvas.so
    see vas version "0.1" from "./libvas.lib".
    see "../../tools/vas/vas.vox".

The build writes `libvas.lib` beside `libvas.so`. A Vox library exports every
function it defines, so the `.so` and the table of contents in the `.lib`
list all of the front end's functions, its helpers and the zero-argument
functions that name its numbers among them. Only the entries above are its
interface; the others may change with the encoder.

`readelf -r libvas.so` shows one relocation, an `R_X86_64_RELATIVE` in
`.fini_array`. The compiler gives a library that entry when its functions
use the runtime's resources, a buffer among them: it points at the runtime's
cleanup, which releases them when the library is unloaded, and the loader
adds the load address to it. A library that uses none, such as the `mathkit`
example in the Vox manual, has neither the entry nor the relocation. The
library is position-independent either way.

A program that pulls the source in shares one name space with it, so its
global variables need names the library's functions do not use for a
variable of another type; the two programs in `tests/toolchain/vas/` show
the way.

## The checks

All three build their own driver program from `tests/toolchain/vas/`. They
run in the Vox repository, with its assembly corpus present: the expansion
and structure checks read the corpus in `tests/corpus`, and the structure
check also reads `tests/toolchain/shapes.py`, none of which this directory
carries. A path that is not there stops a check with a sentence naming the
variable that sets it.

    bash tests/toolchain/vas/expand_check.sh
    bash tests/toolchain/vas/refusal_check.sh
    bash tests/toolchain/vas/structure_check.sh

- `expand_check.sh` expands every corpus file with vas and with `nasm -E`,
  with the include path and the definitions the corpus harness uses (`PIC`
  for a library), and compares the two after `normalise.py`, which both go
  through: it drops comments, blank lines and nasm's `%line` markers, writes
  nasm's bracketed directives and its expansion of `align` plainly, puts each
  label on a line of its own, takes out the spacing outside quotes, writes
  hexadecimal digits in lower case, and numbers the `..@` labels of macro
  expansions in the order they appear. Every corpus file must match, except
  the ones listed in `refused_corpus_files.tsv`, which use `extern` or
  `section .fini_array` and must be refused instead, with the message listed
  beside each. That file is the one list of them, which the structure check
  reads too.
- `refusal_check.sh` runs every file in `refusals/`, each using one refused
  construct, and requires a non-zero result, no output, and exactly the
  messages in the `.expected` file beside it.
- `structure_check.sh` compares the operands the front end parses with the
  ones `tests/toolchain/shapes.py` reads from `nasm -E`, instruction by
  instruction: the mnemonic, each register, each memory reference's size,
  base, index, scale, relativity and displacement, and each immediate's size
  and value. Where vas leaves a value to the encoder, because it depends on
  a label, shapes.py may know it; those are counted and reported. The
  refused files are left out.

Each ends with one summary line and exits non-zero on any failure. Before
it, the expansion check prints a `refused as expected:` line for each
refused file, and a check that fails lists what failed. They read `VOX`
(the compiler, default `vox`), `VOX_CORE_PATH` (the coreasm directory,
default the repository's `coreasm`), `VAS_CORPUS` (the corpus, default the
repository's `tests/corpus`) and, for the structure check, `VAS_SHAPES`
(default the repository's `tests/toolchain/shapes.py`). Each builds its
driver, and runs nasm, in a scratch directory of its own, since nasm and the
compiler both search the current directory first.

## Cost

Every text, buffer, list and map a Vox program makes is kept until the
program ends, and the runtime gives each one at least a page of memory of
its own, 4 KB however little it holds. A map lookup by a key put together as
text makes such a text, and a list or a map put into another, or read back
out of one, is a copy of it with everything inside it.

The front end is written to make as few as it can. It reads each line a byte
at a time through two buffers made once for the whole file, and a token of
one byte, or a word that stands alone, is handed on as it is rather than
copied. It looks a token up as a single-line macro only when a macro has been
given that name, and asks `'what vas knows'` one question per word. When only
the expansion is wanted, as for `'expand file'`, it keeps each statement's
text rather than its whole record.

Even so, expanding the largest program in the corpus, `coreutils/cut.asm`,
takes about 750 MB at its peak, and most take between 130 and 550 MB. A
shared build's source is refused where its `.fini_array` section or its
first `extern` is reached, and nothing after that is read, so the largest
library in the corpus, `vox-libs/date.asm`, takes about 580 MB before it is
refused, where reading it to the end took about 2.5 GB.
