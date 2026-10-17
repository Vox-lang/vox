# The assembly corpus

Every `.asm` file here is the assembly the compiler emits for a real Vox
program, kept in the repository so the assembler (vas) and the ELF writer
(vox-elf) can be tested without the compiler. The sources are:

- `examples/`: every program in this repository's `examples/`;
- `voxos/`: the voxos programs in its `system/`;
- `coreutils/`: the vox-coreutils tools, one `<tool>/<tool>.vox` each;
- `vox-libs/`: the vox-libs libraries, one `<library>/<library>.vox` each,
  compiled with `--shared`.

`MANIFEST` lists each file, whether it is a program or a library, its source
path relative to its own repository, the corpus library a program links
against, and the compiler version that wrote the whole corpus. It also lists
every source that did not compile, with the compiler's message.

## Regenerating

The corpus is only true for the compiler that wrote it. Regenerate it after
any change to code generation, and in particular after the 0.5.0
copy-on-naming change lands:

    bash tests/toolchain/corpus.sh

The script's header names the environment variables that point it at the
voxos, vox-coreutils and vox-libs checkouts and at the compiler and coreasm
to use. After regenerating, run `python3 tests/toolchain/shapes.py` so the
instruction shapes in `tests/toolchain/` match the new corpus.

## Using it

The files `%include "coreasm/x86_64/<file>.asm"`, so nasm needs the
directory above `coreasm` on its include path. nasm looks in the current
directory before the include path, so a `coreasm/` there wins; from the
root of this repository both are the same one:

    nasm -f elf64 -I"$PWD/" -o hello.o tests/corpus/examples/hello.asm
    ld -o hello hello.o

A library is assembled with `-DPIC` and linked with `ld -shared`, as the
compiler does for `--shared`. `tests/toolchain/run.sh` assembles and links
the whole corpus this way.
