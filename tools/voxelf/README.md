# voxelf and vox-elf

voxelf is the ELF writer of the Vox toolchain, written in Vox. It takes the
assembled bytes of a program's sections and writes a flat, static,
position-dependent x86-64 executable: no interpreter, no dynamic section, no
relocations, the same shape `ld` gives a Vox program today. It is the piece
that lets a Vox build stop calling `ld`.

It comes as a library, `Library 'voxelf' version "0.1".`, and a command,
`vox-elf`, which is the library behind a command line.

| File | What it is |
| --- | --- |
| `voxelf.vox` | the library: its Library line, and the body seen under it |
| `voxelf-body.vox` | the library's functions: layout, the ELF writer, the manifest reader. It has no Library line, so another library, such as vas, can see it and take the functions in under its own name |
| `vox-elf.vox` | the command; it `see`s the library as source, so it is a flat static binary with nothing to load |
| `nasm-image.sh` | assembles a compiler `.asm` with `nasm -f bin` into an image and a manifest, using `vox-elf --layout` for the addresses |
| `build.sh` | builds `libvoxelf.so` with its `.lib`, and the static `vox-elf` |
| `compiler.sh` | picks the compiler `build.sh` and the tests use, and refuses one that lacks the fixes voxelf needs |
| `fixes-it-needs.vox` | the program `compiler.sh` asks the compiler with |

## The compiler it needs

voxelf needs three fixes that are on Vox main and in no release up to
0.4.16, each an entry of [docs/bugs/unreleased.md](../../docs/bugs/unreleased.md):
#128, naming copies; #156, a map read out of a list parameter into a local
and appended; and #160, the period after an `Otherwise`. Build it with Vox
main at or after commit 1aee89e, or with the first release after 0.4.16, which
carries them. Built with 0.4.16 it does not work: placement gives the wrong
addresses, and the manifest reader reads each line once for every byte of
it, as the start of the line up to that byte.

`build.sh` takes the compiler `VOX` names, else this tree's own
`target/release/vox` when it has been built, with the tree's `coreasm` unless
`VOX_CORE_PATH` says otherwise, else the `vox` on `PATH`. It checks that
compiler before it builds anything. A compiler built from main before the
fixes says it is 0.4.16, as the release does, so the check does not read the
version: it compiles and runs `fixes-it-needs.vox`, which prints one line for
each fix, and when the answer is not the one a compiler with all three gives,
it refuses the compiler with a sentence naming the fixes and what to build
with, and builds nothing. `tests/toolchain/voxelf/test.sh` makes the same check
first and runs every test with that compiler.

A git worktree of this repository has no `target/release/vox` of its own until
it is built there, so in a worktree set `VOX` to a compiler built from main, or
put one first on `PATH`; otherwise the check finds the release or no compiler
and refuses.

## How a program gets linked today

```sh
vox program.vox --emit-asm -o program.asm
tools/voxelf/nasm-image.sh program.asm program     # writes program.image and program.manifest
vox-elf program.manifest -o program
chmod 755 program
```

`nasm-image.sh` assembles the program once to measure its sections, asks
`vox-elf --layout` where they go, and assembles it again with every section
pinned to its file position and address (nasm's bin format takes both). If the
second assembly measures differently, it lays the sections out again, until
two rounds agree. The addresses are voxelf's, not nasm's: the same layout an
assembler written in Vox will ask for through `'place the sections'` before it
encodes a single instruction. A third argument names the entry symbol, and a
fourth the load base: `nasm-image.sh program.asm program _start 0x10000000`.

The pinned assemblies turn nasm's `sectalign` off, so an `align` or `alignb`
directive inside a section, `alignb` in `.bss` included, pads to its place but
does not try to change the alignment of a section whose address is already
pinned; the alignment each section is laid out by is the one the first,
unpinned assembly measured.

Vox opens a file for writing with mode 0644 and has no statement that changes
a file's mode, so the executable comes out without its execute bits, and the
`chmod` is the caller's.

`vox-elf` exits with the number of errors, one line of diagnostics on standard
error for each, or with 255 when there are more than 255.

## The input: a raw image and a manifest

The image is a file of section bytes, as `nasm -f bin` writes it. The manifest
is a text file that says what is in the image, one statement per line, words
separated by spaces, tabs or carriage returns, so Windows line endings read
the same. A blank line, and a line whose first word starts with `#`, say
nothing.

```
# hello.asm, assembled by nasm -f bin for vox-elf
image hello.image
base 0x400000
section .text text size 303 alignment 16 address 0x4000f0 offset 0
section .data data size 102 alignment 4 address 0x401000 offset 3856
section .bss bss size 32 alignment 4 address 0x401068
symbol _start 0x4001df
```

| Statement | Meaning |
| --- | --- |
| `image PATH` | the image, read from the manifest's own directory unless PATH starts at `/`, and refused when a part of PATH is `..`, which would climb out of that directory. Exactly one. |
| `base ADDRESS` | where the file starts in memory; 0x400000 when it is not given. At most one. Must start a page, must lie in one of the two halves of the address space, with the program's memory, and in the lower half must not be below 0x10000 (see below). |
| `section NAME KIND` and pairs | one section, described once. KIND is `text` (code), `rodata` (read-only data), `data` (initialised data) or `bss` (zero-filled data, no bytes in the file). The pairs, each said at most once: `size` in bytes (required), `alignment` (a power of two, at most 4096; 1 when not given), `address` it was assembled for (required to link; see below), `offset` where its bytes start in the image, counting from 0. `file-offset` is what `--layout` writes; it must be a number, and is otherwise ignored on the way in. |
| `symbol NAME ADDRESS` | a symbol's address, given once; the entry point is looked up here by name. |
| `machine x86-64`, `class 64`, `type executable` | optional, and refused when they say anything else. |

Numbers are whole numbers, in decimal, or in hexadecimal after `0x` or `0X`;
`12.9` is not a number. An address is read as any 64 bits, written with up to
sixteen hexadecimal digits. A program is placed in either half of the x86-64
address space, where an address is canonical, as `ld` places it: every
segment, from its address up to its address plus its size in memory, lies
wholly in the lower half, from 0 up to 0x800000000000, or wholly in the upper
half, from 0xffff800000000000 up to 2^64, where a kernel such as Linux is
linked at 0xffffffff80000000. No segment crosses the addresses between the
halves, which are not canonical, so nothing can be mapped there, and none
runs past 2^64 and wraps round to 0; a segment may end exactly at
0x800000000000 or at 2^64. A load base in the lower half must also not be
below 0x10000; the upper half has no such floor. A size, an alignment or an
offset is below 2^63, and a decimal number of any kind is too.

Every section must say the `address` it was assembled for. The image's code
and data point at the addresses they were assembled for, and voxelf applies no
relocations, so a section placed anywhere else would point at the wrong places;
voxelf refuses a section whose address differs from the one it lays out, and
one that does not say. The `--layout` request is the one manifest that has no
addresses, since asking for them is what it is for.

A manifest is read up to 16 MiB and an image up to 256 MiB; a larger file, or
one that never ends, such as `/dev/zero`, is refused rather than read.

`vox-elf --layout` reads a manifest that has only names, kinds, sizes and
alignments, and a `base` line when it wants one, and writes it back with a
`base` line and every section's `address` and `file-offset`.

## Layout

voxelf lays a program out as `ld` lays out a static executable. The file
starts with the ELF header and the program headers, inside the text segment,
and every section starts at the next multiple of its own alignment.

- The code follows the headers.
- The segment after the code starts on the next page boundary of the file,
  and the next one in memory, so the pages of the file that hold code hold
  nothing else, and no data is ever mapped executable.
- Read-only data, when there is any, gets that segment. The writable segment
  then starts as `ld`'s `DATA_SEGMENT_ALIGN` starts it. By default it follows
  the read-only data in the file with no padding but its own alignment, and
  starts in memory on the first page after the read-only data ends, at the
  same place in that page as in its page of the file. But when the segment
  would then start part way into one page and end part way into another, and
  the two parts would fit in one page together, it starts on a fresh page,
  in memory and in the file: that takes one page less of memory, for at most
  a page of padding in the file. The end measured is the end of the
  zero-filled data padded to 8 bytes, where `ld`'s script ends the data
  segment. With no read-only data, the writable segment starts the page after
  the code instead.
- Zero-filled data follows the initialised data in memory, in the same
  segment, which makes its memory size larger than its file size. The
  segment's memory ends on a multiple of 8, as `ld`'s script pads `.bss`.
- A segment that holds only zero-filled data has no bytes in the file, and its
  file offset is its address's place in its page, or 4096 when that place is
  0, which is the offset `ld` gives it.

So every segment's file offset and address agree modulo 4096, as the loader
requires, and no two segments share a page of memory, so each keeps its own
permissions. For each program in the test corpus and each hand-written layout
in `tests/toolchain/voxelf/layouts.sh`, the ELF header (but for the three
fields that find the section headers), every program header, and every byte
every loadable segment maps are the same as `ld`'s, byte for byte, and for the
corpus the file is no longer than `ld`'s once its symbols are stripped.

| Segment | Flags | Holds |
| --- | --- | --- |
| `PT_LOAD` | R+X | the headers and every `text` section |
| `PT_LOAD` | R | every `rodata` section, when there are any |
| `PT_LOAD` | R+W | every `data` section, then every `bss` section |
| `PT_GNU_STACK` | R+W | nothing: it says the stack is not executable |

voxelf always writes `PT_GNU_STACK`, read and write but never execute. It is
what `ld` writes for an object that carries a `.note.GNU-stack` section, as
every program the Vox compiler writes does, and it states in the file that the
stack is not executable, rather than leaving that to whatever the kernel
defaults to for a program without the header: older kernels, and other
architectures, map such a program's stack executable. No Vox program runs code
on its stack, and an executable stack is a place an attacker's bytes could run.
The image says nothing about its stack, so voxelf does not read the choice from
it: given assembly that lacks the note, `ld` (2.46) writes no `PT_GNU_STACK` at
all, and voxelf still writes one.

After the section bytes come a `.shstrtab` and a section header table, so
`readelf -S` and `objdump -d` read the result. The output has no symbol table.

## The library

`vox tools/voxelf/voxelf.vox --shared -o libvoxelf.so` writes `libvoxelf.so`
and `libvoxelf.lib` beside it; `see "./voxelf.vox".` takes the same code in
as source, which is how `vox-elf` gets it. `tools/voxelf/build.sh [DIR]` does
both, into `$VOXELF_BUILD` or `${TMPDIR:-/tmp}/voxelf-build`, compiling in that
directory rather than in the source tree.

Another library that needs voxelf sees `voxelf-body.vox`, not `voxelf.vox`.
A seen file is read where the `see` stands, and a Library line puts every
function after it into that library, so seeing `voxelf.vox` would move the
seeing library's own functions into voxelf. Seen by its body, voxelf's
functions are taken in under the other library's name instead: in vas's
shared build they are exported as `vas_0_1_...`.

Nothing in the library prints or exits. A function that fails answers how
many errors there were and puts one line of diagnostics in the caller's hands
for each error; for a Vox caller it also raises the error flag.

**For a host that is not Vox**, numbers and paths only:

| Function | Symbol | Does |
| --- | --- | --- |
| `'link and keep the diagnostics' of MANIFEST and OUTPUT and ENTRY` | `voxelf_0_1_link_and_keep_the_diagnostics` | writes the executable; answers 0 or the number of errors |
| `'lay out and keep the diagnostics' of MANIFEST and OUTPUT` | `voxelf_0_1_lay_out_and_keep_the_diagnostics` | writes the placed manifest; answers the same |
| `'linker diagnostics' of OUTPUT` | `voxelf_0_1_linker_diagnostics` | what went wrong in the last call that wrote to OUTPUT, one error to a line; reading removes it |

A shared library may declare nothing at its top level but functions, so it
has no storage that lasts from one call to the next. The diagnostics of a
failed call are therefore kept in a file beside the output,
`OUTPUT.diagnostics`, which `'linker diagnostics'` reads and removes, and
which is why it takes the output path.

**For a Vox caller**, the same work in process, with the diagnostics appended
to a buffer the caller owns:

- `'link and count the errors' with MANIFEST and OUTPUT and ENTRY and DIAGNOSTICS`
- `'lay out and count the errors' with MANIFEST and OUTPUT and DIAGNOSTICS`
- `'place the sections' with SECTIONS and BASE and DIAGNOSTICS`: SECTIONS is a
  list of maps with `"name"`, `"kind"`, `"size"` and `"alignment"`; the answer
  is a new list, in layout order, each map with `"address"` and `"file offset"`
  added.
- `'write the executable and count the errors' with SECTIONS and IMAGE and ENTRY ADDRESS and BASE and OUTPUT and DIAGNOSTICS`:
  SECTIONS as above, each also holding `"image offset"` and `"assembled
  address"`, the address it was assembled for, which must be the one
  `'place the sections'` gives it; IMAGE is a buffer. Answers 0 or the number
  of errors, and writes nothing unless there were none.

Vox has no way to keep a library's helpers private, so every function in
`voxelf-body.vox` is exported; only the ones above are its interface.

## What it does not do yet

These are open gaps, not choices: each is work voxelf has still to do. voxelf
refuses each by name, says that it does not do it yet, and writes no output.

Every gap but the last needs voxelf to take object files as its input, and
each of them is planned in [ROADMAP.md](../../ROADMAP.md), Milestone 8,
Shared-library output:

- **Reading ELF objects and applying relocations**: voxelf does not read
  relocatable objects or apply relocations yet, so every address in the image
  must already be final. A `relocation` line, or any ELF file handed over as
  the input, is refused.
- **Several images**: voxelf links one image so far; a second `image` line is
  refused.
- **Sections other than `.text`, `.rodata`, `.data` and `.bss`**: `ld` places
  any other section, such as a `.mydata`, by its flags, and `nasm -f bin` keeps
  no flags, so `nasm-image.sh` cannot tell what such a section holds, and
  refuses it. This needs the ELF object.
- **Shared libraries and position-independent executables**: voxelf does not
  write them yet, only static executables. `type shared` in a manifest, or an
  ELF shared object or position-independent executable handed over as the
  input, is refused.
- **Dynamic executables**: voxelf does not link dynamically yet, so an
  `interpreter` or `needed` line is refused, and a program that calls a shared
  library, such as `examples/mathkit_consumer.vox`, is not linked.

The last is not part of Shared-library output:

- **Other machines and 32-bit ELF**: voxelf writes only x86-64, 64-bit
  executables so far. `machine` other than `x86-64`, `class 32`, or an ELF file
  that is 32-bit or for another machine, is refused. Other machines come with
  [ROADMAP.md](../../ROADMAP.md), Milestone 6, Multi-Architecture, and
  Milestone 8, More architectures; no milestone plans 32-bit ELF.

## What it takes as ld does

Two things voxelf takes without question, as `ld` does:

- **An entry point anywhere in the code**: the entry symbol must lie inside a
  text section, but nothing checks that it is the start of an instruction,
  since the image holds bytes, not instructions. `ld` does not check it
  either.
- **An image path from the root**: a path starting at `/` is read as it is
  written, wherever it points, as `ld` reads any path it is given. A manifest
  is not a security boundary. Only a path read from the manifest's own
  directory is held inside it.

## What it refuses

These are mistakes in the input. Each refusal names its reason, and none
writes an output.

- A section that does not say the address it was assembled for, or that was
  assembled for an address other than the one layout gives it.
- A section whose bytes run past the end of the image. The bounds are
  compared without adding the offset to the size, so an offset near 2^63
  cannot wrap round and pass.
- A section larger than one half of the x86-64 address space (2^47 bytes), or
  sections that need more than that together.
- A load base between the two halves of the address space, from
  0x800000000000 up to 0xffff800000000000, where no address is canonical, and
  sections whose memory would run from a load base in the lower half past
  0x800000000000, into those addresses: nothing can be mapped there, so the
  program could not be loaded, though `ld` writes such a file all the same.
  And sections whose memory would run from a load base in the upper half
  past 2^64, where it would wrap round to 0, which `ld` refuses too. Vox holds an address of the upper half as the
  number below zero with the same 64 bits, and every size voxelf adds up is
  below 2^47, so every sum it works out, of offsets or of addresses, stays
  between -2^47 and 2^48, and none can wrap round to a small number and pass
  a check.
- A load base that does not start a page, or one in the lower half below
  0x10000. Linux maps nothing there unless its `vm.mmap_min_addr` setting is
  lowered, so the program could not be started; `ld` writes such a file all
  the same.
- An image path read from the manifest's directory that climbs out of it, by
  a part that is `..`.
- A section, a symbol, a load base or a pair of a section line given twice,
  rather than one silently taking the other's place.
- A number with a fraction, with more than 64 bits, or 2^63 or more where a
  size, an alignment or an offset is wanted; a negative number.
- A manifest larger than 16 MiB or an image larger than 256 MiB.
- An entry point outside the code, a missing entry symbol, a kind it does not
  know, an alignment that is not a power of two or is larger than a page, a
  manifest with no text section, and any line it does not understand.

## Tests

From the root of the Vox tree, with `nasm` on `PATH`, a compiler with the
fixes voxelf needs (see [The compiler it needs](#the-compiler-it-needs)), and
a checkout of each of the two projects whose programs join the corpus, Vox OS
and vox-coreutils:

```sh
VOXOS_SRC=/path/to/voxos COREUTILS_SRC=/path/to/vox-coreutils bash tests/toolchain/voxelf/test.sh
```

Both variables are required: `test.sh` stops before building anything, with
a sentence naming the variable, when either is not set, so every run compares
the whole corpus. A CI job supplies both checkouts, read only, and both
variables, as well as `vox`, `nasm`, `ld`, `readelf`, `objdump` and `strace`
on `PATH`.

It checks the compiler as `build.sh` does, and stops with the reason when the
compiler lacks a fix; then it builds the library and `vox-elf`, and runs each
test in turn, with that compiler first on `PATH`:

- `headers.vox`: the ELF header and two program headers compared byte for
  byte with bytes written out by hand from `ld`'s output for
  `examples/hello.vox` and `examples/pi.vox`, and the layout of both programs'
  sections, which must give `ld`'s addresses and file offsets, down to pi's
  writable segment, whose program header is built again from the layout and
  compared with `ld`'s bytes; then the layouts where `ld` makes a choice: a
  segment of zero-filled data alone, data aligned to a page after read-only
  data, code on the last page below 0x7ffffffff000, code at a kernel's base,
  0xffffffff80000000, and code that ends exactly at 2^64; and the layouts
  that would not lie wholly in one half of the address space, which must be
  refused: load bases between the halves, memory that runs from the lower
  half into the addresses between them, and memory that runs past 2^64.
- `refusals.sh`: every refusal above, with its exit status, its words and the
  absence of an output, and that `ld` refuses code that runs one byte past
  2^64 too; the exit status of a run with more errors than a status can
  hold; the edges it takes, among them a manifest with Windows line endings,
  and four programs linked and compared with `ld`'s build byte for byte,
  since none can run here: code on the last page but one of the lower half,
  code that ends exactly at 0x800000000000, a program with a section of every
  kind at a kernel's base, 0xffffffff80000000, and code that ends exactly at
  2^64; one program linked from hand-written bytes and run; and the same link
  through `libvoxelf.so` from `path_surface.vox`, which `see`s
  `libvoxelf.lib`.
- `layouts.sh`: hand-written programs linked both ways and compared byte for
  byte with `same-bytes.sh`: a grid of 280 shapes of read-only data,
  initialised data and zero-filled data, sized and aligned on either side of
  each choice `ld` makes, then programs written for one edge each, from code
  aligned to a page to a gigabyte of zero-filled data, and a section by a name
  voxelf does not take yet, which must be refused with the reason.
- `no-fallback.sh`: `check.sh` on three copies of `examples/hello.vox`, one
  in each place it takes programs from, with an `ld` first on `PATH` that
  refuses to link the reference for one of them. The run must fail, naming
  that program and what `ld` said, and must still link and compare the other
  two.
- `check.sh`: the differential test. Every `examples/*.vox`, every Vox OS
  system program and every vox-coreutils tool is linked twice: by `nasm -f
  elf64` and `ld`, with the arguments the compiler gives `ld`, and by
  `nasm-image.sh` and `vox-elf`. A program that sees a library's `.lib` has
  that library built beside it first, from the source in its directory that
  declares it, and `ld` is given the library, its directory and the dynamic
  loader, as the compiler gives them. The reference is `ld`'s output and
  nothing else: when `nasm` or `ld` refuses to build it, the program fails
  the check, with what it said. The two executables must be the same, byte for byte, in everything the loader
  reads: the ELF header but for the three fields that find the section
  headers, every program header, and every byte of every loadable segment.
  A program with read-only data must also come out of `vox-elf` no larger
  than the `ld` build with its symbols stripped. Then both are run once each,
  with the same arguments and input, and must give the same standard output,
  standard error, exit status and files left behind; a run that does not
  finish within the time limit is a failure. A program that cannot run here,
  because it needs root or prints the time, is still compared byte for byte,
  and is listed as not run, with the reason.

  What voxelf supports is measured, not listed: a program whose `ld` build has
  a `PT_INTERP` or `PT_DYNAMIC` program header needs dynamic linking, which
  voxelf does not do yet (Milestone 8, above), and is reported as not
  supported yet when
  voxelf refuses it, as `examples/mathkit_consumer` is today. When voxelf
  links such a program, it is compared like any other and must pass, so
  dynamic programs join the comparison by themselves once voxelf links them.
  A program left out for any other reason, a missing checkout or a program
  that does not compile, fails the check with the reason. The check passes
  when every static program passes, nothing is left out, and the count of
  ld pass-throughs is 0; its last line gives those totals, as in `same bytes
  41 of 41 static; 1 not supported (dynamic, M8); 0 ld pass-throughs`, and
  counts the programs that are compared byte for byte but not run.

`same-bytes.sh REFERENCE CANDIDATE` is the byte comparison `refusals.sh`,
`layouts.sh` and `check.sh` use.

Nothing on voxelf's side calls `ld` today: neither `vox-elf` nor
`nasm-image.sh` starts it. The tests check that rather than take it on
trust. In `refusals.sh`, `layouts.sh` and `check.sh`, `vox-elf` and `nasm-image.sh` run under
`strace -f -e trace=execve` (`ld-trace.sh`), which sees every program they
start, wherever it lives, and every summary line gives the count of ld
pass-throughs: the programs started whose name is `ld` or starts with `ld.`,
which must be 0. A stand-in for `ld` first on `PATH` also fails any call
found there. `refusals.sh` first checks that the trace counts a call of `ld`
by its absolute path. The summaries give, beside that count, the links `ld`
made for the test itself, as the reference to compare with.
