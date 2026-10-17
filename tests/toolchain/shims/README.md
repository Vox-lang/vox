# Toolchain shims: the compiler's own tests, linked by vox-elf

The Vox compiler assembles a program with `nasm` and links it with `ld`, both
found on `PATH`. The two scripts here stand in for them, so the whole test
suite can be run with a program's link done by vox-elf
(`tools/voxelf/`) instead of `ld`, and the results compared with a run that
uses the real tools.

| File | What it is |
| --- | --- |
| `nasm` | runs the real nasm exactly as asked, and records the source of each ELF object in `OBJECT.source` beside it |
| `ld` | links a static program of one object with `nasm-image.sh` and vox-elf, from the source `nasm` recorded; passes every other link to the real ld |
| `compare.sh` | runs the compiler's test runner with the real tools, then with the stand-ins, and compares the two |

## The stand-ins

Each is called by name, exactly as the compiler calls the real tool, so it
must be executable and first on `PATH`. `compare.sh` copies both into its
report directory and makes the copies executable, so it works whatever mode
the files here have.

`ld` passes a link to the real ld, unchanged, when it is a shared library
(`-shared`), when it needs the dynamic loader (`-dynamic-linker`, `-rpath`,
any `-l`), when it has more than one object, when its object was not
assembled by the `nasm` stand-in, or when it carries an option the
stand-in does not read. Otherwise it assembles the recorded source with
`tools/voxelf/nasm-image.sh` and writes the output with `vox-elf`, then makes
it executable, since vox-elf writes it with mode 0644. A link vox-elf
refuses is a failed link, as it would be with ld: there is no quiet fallback.

Every decision either stand-in makes is one line in the file `SHIM_LOG`
names: assembled and recorded, passed through and why, linked with vox-elf,
or failed and why.

| Variable | Default | Meaning |
| --- | --- | --- |
| `REAL_NASM` | `/usr/bin/nasm` | the real nasm |
| `REAL_LD` | `/usr/bin/ld` | the real ld |
| `VOXELF_SRC` | `tools/voxelf` in this tree | where `nasm-image.sh` and `build.sh` are |
| `VOXELF_BUILD` | `${TMPDIR:-/tmp}/voxelf-build` | the directory holding `vox-elf`; built there if missing, with this directory taken off `PATH` |
| `SHIM_LOG` | `${TMPDIR:-/tmp}/vox-toolchain-shims.log` | the decision log, appended to |
| `SHIM_ASSEMBLER` | `nasm` | `vas` asks for the Vox assembler; it is not written yet, so the `nasm` stand-in refuses it with a message |

## Running the comparison

From any directory outside a Vox tree, with `vox` and `nasm` on `PATH`:

```sh
VOX_CORE_PATH=/usr/share/vox/coreasm bash tests/toolchain/shims/compare.sh [REPORT_DIR]
```

It runs the tree's `test.sh` twice, each time in a fresh scratch copy of the
tree: first with the real nasm and ld, then with the stand-ins first on
`PATH`. The copy of `test.sh` is changed in four lines, each matched exactly,
and the comparison stops if one is not found: it uses the compiler on `PATH`
(`$VOX`, default `vox`) instead of building one, it skips `cargo test`, it
keeps the caller's `VOX_CORE_PATH`, and it records the sha256 of every
program it builds before running it. The copy's `coreasm` is a link to
`VOX_CORE_PATH`, so only one runtime is in play. Tests run one at a time,
because many of them use fixed paths under `/tmp`.

`REPORT_DIR/summary.txt` gives:

- each run's pass, fail and skip counts;
- the tests that pass in both, and those that fail in both, which are the
  baseline's failures and say nothing about vox-elf;
- every regression, a test that passes with ld and fails with vox-elf, with
  the runner's diff and standard error for it; the exit status is 1 when
  there is one;
- how many links vox-elf did, how many were passed through, and every link
  vox-elf failed;
- how many programs hash the same both ways. vox-elf lays a file out its own
  way and writes no symbol table, so a different hash is expected and is not
  a failure; the test results are what count.

The full output of each run is in `baseline.log` and `shimmed.log`, and the
decision logs in `baseline.shim.log` and `shimmed.shim.log`.
