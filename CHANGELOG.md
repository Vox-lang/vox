# Changelog

All notable changes to Vox are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-08-03

A Vox program can now call a Vox library. Build a library with `--shared`,
then consume it from another Vox program with
`see "<lib>" version "<ver>" from "<path>.lib".`. The "Shared libraries"
section of `LANGUAGE.md` is the full guide.

> **Breaking.** This release breaks three things a non-Vox consumer, a
> `--shared` build, or a stale `see` can depend on. Each is detailed under
> `### Removed` and `### Changed` below; the summary:
>
> 1. **Every exported library symbol is renamed** to `<lib>_<version>_<func>`
>    (e.g. `add_two_numbers` → `mathkit_1_0_add_two_numbers`), with no
>    unmangled alias. Any C/Rust/assembly consumer must update its `extern`
>    declarations and relink.
> 2. **`--shared` now requires a `Library` declaration.** Add
>    `Library "name" version "x.y".` at the top of the library source.
> 3. **Three `see` forms that silently linked nothing are now compile
>    errors.** Switch to `see "<lib>" version "<ver>" from "<path>.lib".`.

### Removed

- **Three `see` forms that silently linked nothing are now compile errors.**
  `see "./path.so".`, `see "lib" version "1.0" from "./path.so".`, and
  `see "./path.so" for "lib" version "1.0".` previously compiled while linking
  nothing — every call into the library was simply missing, with no warning.
  They now error and name the canonical form
  `see "<lib>" version "<ver>" from "<path>.lib".` (the `see ... for ...` form
  has its own diagnostic). A previously *silent* failure is now loud — that is
  the point of the change, not a regression. If a build breaks here, build the
  library with `--shared` (which writes the `.lib` beside the `.so`) and point
  `see` at the `.lib`.

### Changed

- **Every exported library symbol is renamed.** Labels are now
  `<library>_<version>_<function>` — for example `add_two_numbers` becomes
  `mathkit_1_0_add_two_numbers`, and `greet` becomes `mathkit_1_0_greet`.
  There is deliberately **no unmangled alias**: an alias would let two versions
  of one library collide in the same `.so`, which is exactly what the scheme
  exists to prevent.

  If you call a Vox library from C, Rust, or assembly, update your `extern`
  declarations and relink:

  ```nasm
  ; before
  extern add_two_numbers
  extern greet
  ; after
  extern mathkit_1_0_add_two_numbers
  extern mathkit_1_0_greet
  ```

  Find the new names for any library you have with:

  ```bash
  $ nm -D --defined-only libmathkit.so
  00000000000005c4 T mathkit_1_0_add_two_numbers
  00000000000005f9 T mathkit_1_0_greet
  ```

- **`--shared` now requires a `Library` declaration.** A `--shared` build
  with no `Library` line has no identity to mangle with and no `.lib` to emit,
  and now errors:

  ```
  error: A shared library must declare its identity with a `Library`
  declaration giving its name and version — without one there is no mangling
  and no `.lib`. Add `Library "name" version "x.y".` before the function
  definitions and rebuild with --shared.
  ```

  Add `Library "name" version "x.y".` at the top of the library source.

### Added

- **Consuming a library from Vox.** `see "<lib>" version "<ver>" from
  "<path>.lib".` resolves the `.lib`, selects the block matching name *and*
  version, verifies every promised symbol against the `.so`'s dynamic symbol
  table (a stale `.lib` is a compile error, not a runtime crash), registers
  the signatures so calls type-check, and links the `.so` with an `-rpath`.

  ```vox
  see "mathkit" version "1.0" from "./libmathkit.lib".

  a number called "sum" is "add two numbers" of 3 and 4.
  Print the sum.
  ```

- **The `.lib` interface file.** A `--shared` build writes `<output>.lib`
  beside the `.so` — the library's name and version, the `Location` of its
  `.so`, and a table of contents of every exported function's signature. It is
  the only place Vox types live; a `.so` carries mangled names but no types.

  ```
  Library "mathkit" version "1.0".
  Location "./libmathkit.so".

  Table of Contents:
      To "add two numbers" with a number called "a" and a number called "b", returning a number.
      To "greet".
  ```

- **Several libraries — and several versions of one library — in one `.so`.**
  `vox a.vox b.vox --shared -o lib.so` links multiple libraries in a single
  link step (you cannot append to a linked `.so`). Two versions of the same
  library coexist with distinct mangled symbols, so a consumer can keep
  calling `mathkit_1_0_add_two_numbers` after `mathkit_2_0_add_two_numbers`
  ships beside it, with no recompile. Duplicate `<library, version>` pairs
  across inputs are rejected; multi-input is `--shared` only.

- **Consumption diagnostics.** Each failure mode is its own error naming the
  file and what was expected: a missing `.lib`; no such library in it (with the
  libraries it does declare); a version mismatch (listing the versions
  offered); a missing `.so` at `Location`; a stale `.lib` promising a symbol
  the `.so` does not export (naming the mangled symbol); and an arity or type
  mismatch at the call site (naming the library and version).

## [0.1.24] - 2026-08-03

Compiler fixes. No breaking changes.

### Fixed

- **`append each x from <list> to <dest>`** no longer has its destination
  eaten by range parsing. A list source `[1, 2, 3]` now appends `[1, 2, 3]`,
  while the range form `append each n from 1 to 5 to rl` still appends
  `[1, 2, 3, 4, 5]`.
- **`append <expression> to <list>`** now parses its value with full
  arithmetic. Appending a computed value in a loop works — `append i multiply i
  to squares` across `i` from 1 to 5 now yields `[1, 4, 9, 16, 25]`.
- **A timer's `start time` and `end time`** now parse through the reserved
  `time` keyword, so `Print the "job timer"'s start time.` and `... end time.`
  work as documented and return unix timestamps.

### Changed

- **`VOX_CORE_PATH` is the documented environment variable** and
  **`~/.config/vox/config` the documented config path.** The older
  `EC_CORE_PATH` and `~/.config/ec/config` still work as deprecated aliases:
  the `vox` name wins when both are set, and a one-line deprecation note is
  printed (on stderr, at the start of the build) when only the old name is
  found. Existing shell profiles and CI that set the old name keep working;
  migrate when convenient. Note that the note on stderr can surface in builds
  that capture stderr and expect it empty.