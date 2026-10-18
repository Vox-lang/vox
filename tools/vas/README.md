# vas: the Vox assembler

vas reads the NASM-dialect assembly the Vox compiler writes and turns it into
a static x86-64 executable, through the voxelf ELF writer, so that building a
Vox program needs neither nasm nor ld. It is written in Vox, as a library,
`Library 'vas' version "0.1".`, with a command in front of it.

    vas program.asm -o program
    chmod 755 program

It accepts exactly the NASM constructs found in the compiler's output and in
coreasm, and refuses everything else by name, with the file and the line.
Every jump and call is encoded rel32, where nasm picks rel8 for a target in
reach, so vas's code is longer than nasm's by those bytes; everything else it
lays down byte for byte as nasm does (see The checks).

| File | What it is |
| --- | --- |
| `vas.vox` | the library: the front end, and the `see` lines that bring in the rest |
| `encoder.vox` | the encoder: the bytes of one instruction, from a table of the shapes |
| `assembler.vox` | the two passes, the placing of the sections, and the entries that write an executable |
| `vas-command.vox` | the `vas` command; it `see`s the library as source, so it is a flat static binary with nothing to load |
| `build.sh` | builds `vas`, and `libvas.so` with its `libvas.lib`, and checks that the shared build exports the entries under vas's name |

## What it does

The front end reads the source and parses every statement into a record.
Pass one measures every statement and gives each label its offset in its
section. voxelf places the sections, which makes every label an address.
Pass two lays down every statement's bytes at its address, and voxelf writes
the executable.

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
   or on `$` is left for the passes, which know the addresses.

## What the passes do

1. Pass one walks the records in order. An instruction takes the bytes the
   encoder measures for it; a data directive its unit for each item, a
   string its own bytes padded to a whole unit; a reservation its count of
   units; an `align` the padding it needs where it stands, filled with `nop`
   as NASM fills it, and its section's alignment rises to its boundary. A
   `times` prefix multiplies the statement. Each label takes the offset its
   section has reached.
2. A value that waits on a label is worked out as soon as the label has its
   place. It is either a number no layout changes, such as the length of a
   string, `$ - str_0 - 1`, which the encoder may give a short form, or an
   address, which it takes at full width, as NASM does. vas tells the two
   apart by working the expression out twice, with each section moved by a
   different large amount the second time: a number comes out the same both
   times. An `equ` must be a number.
3. A statement measured before every label it waits on had its place is
   measured again once every label has one, and again after any size
   changes, until the sizes settle, as NASM settles them. The corpus settles
   in one round.
4. voxelf's `'place the sections'` places every section that holds anything,
   at the alignment NASM gives it in an object (16 for code, 4 for data,
   raised by `align`), and each label becomes an address.
5. Pass two lays down every statement's bytes at its address, and checks
   that each comes out the size pass one measured: anything else is an
   internal error, named with its line.
6. voxelf's `'write the executable and count the errors'` takes the section
   images, joined into one image buffer, the address each was assembled for,
   which voxelf checks against its own placing, and the address of `_start`,
   and writes the executable. Nothing is written when there was any error.

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

The passes refuse, with the file and the line:

- a name nothing defines;
- an `equ` whose value is an address rather than a number;
- a `times` count or a reservation count not known before anything is
  assembled;
- data or an instruction in `.bss`, and anything in `.note.GNU-stack`;
- a floating-point number anywhere but `dq`;
- an instruction whose operands no row of the encoder's table takes;
- a source with no `_start` label, or with no `.note.GNU-stack` section to
  say that the stack is not executable: the executable's stack never is.

`tests/toolchain/vas/refusals/` holds a test for each kind of refusal the
front end makes, and `tests/toolchain/vas/assembly/refusals/` one for each
the passes make, with the exact message it gives.

## The interface

The public entries take and return only paths, numbers and texts, so a host
that is not Vox can call them through `libvas.so`, by the symbols a shared
build exports, which are these:

| Function | Symbol | What it does |
|---|---|---|
| `'assemble the file' of <source> and <coreasm directory> and <output path>` | `vas_0_1_assemble_the_file` | Assembles the source into a static executable at the output path, with mode 0644: the caller makes it executable. Answers the diagnostics, one per line, each `<file>:<line>: <message>`, or the empty text when the executable was written. |
| `'assemble file counting errors' of <source> and <coreasm directory> and <output path>` | `vas_0_1_assemble_file_counting_errors` | The same, answering the number of errors instead, and keeping the diagnostics of a failing call for `'assembler diagnostics'`. |
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

A Vox program can call the whole assembly in process, with a buffer of its
own for the diagnostics; it answers the number of errors:

    'assemble the source' with <source> and <coreasm directory> and <output path>
        and <diagnostics buffer>

or skip the files and call the front end directly:

    'read the source' with <source> and <coreasm directory> and <definitions>
        and <what vas knows> and <statements list> and <diagnostics buffer>

It fills the statements list with one record per statement, in order, puts
the messages in the diagnostics buffer, leaves in the map `'what vas knows'`
what the front end learnt (the globals, the constants it worked out, whether the stack
is to be executable), and answers the number of errors. Each record is a map;
the comment above `'record the statement'` in `vas.vox` lists its fields for
every kind of statement.

## Building and using it

`tools/vas/build.sh [DIR]` builds the `vas` command, and the shared library,
into `$VAS_BUILD` or `${TMPDIR:-/tmp}/vas-build`, compiling in that directory
rather than in the source tree. By hand, build the shared library and `see`
its interface, or pull the source into a program:

    vox tools/vas/vas.vox --shared -o libvas.so
    see vas version "0.1" from "./libvas.lib".
    see "../../tools/vas/vas.vox".

`vas.vox` sees `encoder.vox`, `assembler.vox` and `../voxelf/voxelf-body.vox`,
so those three come with it, and a program that sees it is a flat static
binary, as the command is. It sees voxelf by its body, which has no Library
line, because a seen file is read where the `see` stands and a Library line
puts every function after it into that library: seeing `voxelf.vox` would
put vas's own functions into library voxelf. Seen by its body, voxelf's
functions belong to vas, so a shared build of vas exports them too, as
`vas_0_1_...` beside vas's own: `vas_0_1_place_the_sections`, for one.
`build.sh` checks that `libvas.so` exports the entries above under vas's
name, and that `libvas.lib` names library vas, so a change that moved them
into another library fails there.

The build writes `libvas.lib` beside `libvas.so`. A Vox library exports every
function it defines, so the `.so` and the table of contents in the `.lib`
list every function of the front end, the encoder, the passes and voxelf,
helpers and the zero-argument functions that name numbers among them. Only
the entries above are vas's interface; the others may change.

The `vas` command takes the source, `-o` for the output,
and `-c` for the coreasm directory, which defaults to the one `VOX_CORE_PATH`
names and then to `/usr/share/vox/coreasm`. It writes the diagnostics to
standard error and exits with the number of errors, or 255 when there are
more. Vox opens a file for writing with mode 0644 and has no statement that
changes a file's mode, so the caller makes the executable executable, as with
`vox-elf`.

A program that pulls the source in shares one name space with it, so its
global variables need names the library's functions do not use for a
variable of another type; the programs in `tests/toolchain/vas/` show the
way.

## The checks

Each builds its own driver program from `tests/toolchain/vas/`, or the `vas`
command with `build.sh`. They run in the Vox repository, with its assembly
corpus present: the expansion, structure and program checks read the corpus
in `tests/corpus`, and the structure check also reads
`tests/toolchain/shapes.py`, none of which this directory carries. A path
that is not there stops a check with a sentence naming the variable that
sets it.

    bash tests/toolchain/vas/expand_check.sh
    bash tests/toolchain/vas/refusal_check.sh
    bash tests/toolchain/vas/structure_check.sh
    bash tests/toolchain/vas/encoder/encoder_check.sh
    bash tests/toolchain/vas/assembly_check.sh
    bash tests/toolchain/vas/program_check.sh

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
- `encoder/encoder_check.sh` encodes each mechanic, and the example of every
  row of `tests/toolchain/shapes.tsv`, and compares the bytes with nasm's.
- `assembly_check.sh` runs every file in `assembly/refusals/`, each a
  program the passes must refuse, as `refusal_check.sh` runs the front
  end's; and assembles `assembly/features.asm`, which uses `default rel`, an
  `equ` used before it is defined, `$`, `times`, `align` in data,
  floating-point `dq` items and all four sections. Its bytes must be nasm's
  when nasm has every jump written near and ld links it at the addresses vas
  chose, and it must run as nasm and ld's executable runs.
- `program_check.sh` assembles every program in the corpus with the `vas`
  command, links nothing else, and compares the executable's `.text` and
  `.data` with those of the executable nasm and ld make of it, by
  `tests/toolchain/run.sh`'s recipe. Equal, the program is identical.
  Otherwise its bytes must be nasm's when nasm has every jump written near,
  linked at vas's addresses, which shows the difference is jump widths and
  nothing else, and the two executables must run alike, with the arguments
  and input `tests/toolchain/voxelf/check.sh` gives each program: then it
  runs the same. A program that needs root, does not finish, or prints
  something different every run, is listed as not run, with the reason.
  Every run of `vas` and of a program is held to `VAS_MEMORY_CAP` (4G) with
  systemd-run where there is a user session, and to a time limit. The check
  prints each run's time and peak memory.

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

Even so, on the machine these checks were written on, with Vox v0.4.16,
expanding the largest program in the corpus, `coreutils/cut.asm`, peaked at
about 750 MB (766 MB when measured again on 17 October 2026), and most
peaked between 130 and 550 MB. A shared build's source is refused where its
`.fini_array` section or its first `extern` is reached, and nothing after
that is read, so the largest library in the corpus, `vox-libs/date.asm`,
peaked at about 580 MB before it was refused, where reading it to the end
took about 2.5 GB.

The passes read each record out of the statements list once each, which
copies it, and keep everything else about a statement as five numbers in one
list. An instruction's operands are copied again only when it has a value to
work out, and the statements pass one measures again are only those whose
size could still change. Measured on 17 October 2026, with Vox v0.4.16 and
the corpus in `tests/corpus`, on the machine these checks were written on,
assembling `coreutils/cut.asm` whole peaked at about 2.1 GB and took under
3 seconds, and the other corpus programs peaked between 50 MB and 1.5 GB.
`program_check.sh` prints the figures for the machine it runs on.
