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
encodes a single instruction.

Vox opens a file for writing with mode 0644 and has no statement that changes
a file's mode, so the executable comes out without its execute bits, and the
`chmod` is the caller's.

`vox-elf` exits with the number of errors, one line of diagnostics on standard
error for each, or with 255 when there are more than 255.

## The input: a raw image and a manifest

The image is a file of section bytes, as `nasm -f bin` writes it. The manifest
is a text file that says what is in the image, one statement per line, words
separated by spaces. A blank line, and a line whose first word starts with
`#`, say nothing.

```
# hello.asm, assembled by nasm -f bin for vox-elf
image hello.image
base 0x400000
section .text text size 303 alignment 16 address 0x4000f0 offset 0
section .data data size 102 alignment 16 address 0x401000 offset 3856
section .bss bss size 32 alignment 16 address 0x401070
symbol _start 0x4001df
```

| Statement | Meaning |
| --- | --- |
| `image PATH` | the image, read from the manifest's own directory unless PATH starts at `/`. Exactly one. |
| `base ADDRESS` | where the file starts in memory; 0x400000 when it is not given. Must start a page. |
| `section NAME KIND` and pairs | one section. KIND is `text` (code), `rodata` (read-only data), `data` (initialised data) or `bss` (zero-filled data, no bytes in the file). The pairs: `size` in bytes (required), `alignment` (a power of two, at most 4096; 1 when not given), `address` it was assembled for, `offset` where its bytes start in the image, counting from 0. `file-offset` is what `--layout` writes, and is ignored on the way in. |
| `symbol NAME ADDRESS` | a symbol's address; the entry point is looked up here by name. |
| `machine x86-64`, `class 64`, `type executable` | optional, and refused when they say anything else. |

Numbers are decimal, or hexadecimal after `0x`.

`vox-elf --layout` reads a manifest that has only names, kinds, sizes and
alignments, and writes it back with a `base` line and every section's
`address` and `file-offset`.

## Layout

The file starts with the ELF header and the program headers, inside the text
segment, and the code follows at the next multiple of its alignment: the way
`ld` lays out a static executable. Read-only data, when there is any, gets a
segment of its own on the next page; initialised data starts the next page
after that, with the zero-filled data after it in memory, in the same
segment, its memory size larger than its file size. Every segment starts on a
page boundary in the file and in memory, so file offsets and addresses agree
modulo 4096 as the loader requires.

| Segment | Flags | Holds |
| --- | --- | --- |
| `PT_LOAD` | R+X | the headers and every `text` section |
| `PT_LOAD` | R | every `rodata` section, when there are any |
| `PT_LOAD` | R+W | every `data` section, then every `bss` section |
| `PT_GNU_STACK` | R+W | nothing: the stack is not executable, as `.note.GNU-stack` asks |

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
  SECTIONS as above, each also holding `"image offset"`, and, when it was
  assembled for a particular address, `"assembled address"`; IMAGE is a
  buffer. Answers 0 or the number of errors, and writes nothing unless there
  were none.

Vox has no way to keep a library's helpers private, so every function in
`voxelf-body.vox` is exported; only the ones above are its interface.

## What it refuses

Each refusal names its reason, and none writes an output.

- **Shared objects**: `type shared` in a manifest, or an ELF shared object (or
  position-independent executable) handed over as the input.
- **Relocations**: a `relocation` line, or a relocatable ELF object. voxelf
  applies none, so every address in the image must already be final.
- **Dynamic linking**: an `interpreter` or `needed` line.
- **Several objects**: a second `image` line.
- **Anything but x86-64**: `machine` other than `x86-64`, `class 32`, or an
  ELF file that is 32-bit or for another machine.

It also refuses, by name, a section assembled for an address other than the
one layout gives it, a section whose bytes run past the end of the image, an
entry point outside the code, a missing entry symbol, a kind it does not
know, an alignment that is not a power of two or is larger than a page, a
manifest with no text section, and any line it does not understand.

## Tests

From the root of the Vox tree, with `vox` and `nasm` on `PATH`:

```sh
bash tests/toolchain/voxelf/test.sh
```

It builds the library and `vox-elf`, then runs each test in turn:

- `headers.vox`: the ELF header and two program headers compared byte for
  byte with bytes written out by hand from `ld`'s output for
  `examples/hello.vox` and `examples/pi.vox`, and the layout of both programs'
  sections, which matches `ld`'s addresses for the first.
- `refusals.sh`: every refusal above, with its exit status, its words and the
  absence of an output; the exit status of a run with more errors than a
  status can hold; one program linked from hand-written bytes and run; and
  the same link through `libvoxelf.so` from `path_surface.vox`, which `see`s
  `libvoxelf.lib`.
- `check.sh`: the differential test. Every `examples/*.vox` that compiles on
  its own, and any further programs `check.sh` is pointed at (its header
  names the variables), is linked twice: by `nasm -f elf64` and `ld` as the
  compiler does it, and by `nasm-image.sh` and `vox-elf`. Both executables
  must show the same flags and alignment for every segment in `readelf -l`,
  and must give the same standard output, standard error, exit status and
  files left behind when run with the same arguments and input. A program
  that needs root is linked and its segments compared, but it is not run;
  one that does not compile on its own is left out. Each is listed as
  skipped, with the reason.

A difference only counts if it holds: a run that differs is repeated three
times for each executable, and if the `ld` build disagrees with itself, or
the vox-elf build matches it even once, the program is reported as varying
instead, and skipped.
