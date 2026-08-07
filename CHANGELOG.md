# Changelog

All notable changes to Vox are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-08-07

`"..."` is now always a string literal — never an identifier. Names are bare
words (`total`), or `'single quoted'` when they contain spaces
(`'total items'`). This closes the single overload that has caused this
project's worst defects: `a number called "x" is "get five".` used to
silently parse a function call as a string and print a stray pointer instead
of calling anything. The "Names and strings" section of `LANGUAGE.md` is the
full guide.

> **Breaking.** Every existing `.vox` program that names anything the old way
> (`a number called "x" is 5.`, `To "greet".`, `print "greet" of 3.`,
> `Library "lib" version "1.0".`) now fails to compile, with a diagnostic
> telling you the correct replacement. There is no compatibility window.
>
> | Before | After |
> |---|---|
> | `a number called "x" is 5.` | `a number called x is 5.` |
> | `a number called "total items" is 5.` | `a number called 'total items' is 5.` |
> | `To "greet" with a number called "n".` | `To greet with a number called n.` |
> | `print "greet" of 3.` | `print greet of 3.` |
> | `Library "mathkit" version "1.0".` | `Library mathkit version "1.0".` |
>
> **Unchanged, still double-quoted** — these were never names: map keys
> (`person's "name"`), file/library paths (`see "./utils.vox"`,
> `from "./lib.lib"`), flag aliases (`"-v"`), and version strings
> (`version "1.0"`).
>
> A mechanical migration tool ships in this repo at
> `tools/migrate-identifiers`; it rewrote this project's own 250+ file test
> corpus and is a reasonable starting point for a large program, though its
> output should be reviewed.

### Fixed

- **A function call could silently misparse as a string literal**, printing a
  raw pointer instead of calling anything — `a number called x is "get
  five".` compiled and ran, printing something like `4198480`. The old
  grammar (`name ::= string | identifier`) made this possible in any position
  a name was expected; it no longer exists.
- **The same defect shape, independently, in `element N of`.** `element 1 of
  "no such thing".` compiled and printed `0` — a string naming nothing was
  silently treated as an out-of-bounds access rather than rejected. Bare
  string literals are now rejected in this position with a clear diagnostic.
- **A value-typed parameter's runtime type tag could leak across function
  definitions.** If two functions in the same file reused a parameter name
  (e.g. both taking a parameter called `x`), a later string literal that
  happened to equal that name could be misread as a stale value tag instead
  of literal data. `variable_types`/`mixed_tag_slots` are now scoped per
  function, matching how ordinary variables already were.
- **A `.lib`'s declared return type was silently dropped to void** for any
  function whose `Return` was not its first statement — the common case for
  any function with real logic before returning. The library's own interface
  file described a function as returning nothing when it returned a value.
- **`to`/`of`/`with` as universal call connectors collided with grammar that
  already used those words** — `Set x to 1.` followed later by `x` used as a
  range bound, `append ... to`, and `element N of`/`byte N of` with a
  variable index could all misparse as function calls, consuming a token that
  belonged to the enclosing statement.

### Added

- **`docs/check-samples.sh`** — extracts every runnable code sample from
  `LANGUAGE.md`, compiles it against the built compiler, and reports honest
  pass/fail/skip counts with an internal consistency check (`checked +
  skipped` must equal the real number of samples). Every sample in the
  language reference is now verified to actually compile, not merely
  asserted to.
- **A C-interoperability test** confirming a Vox `--shared` library is
  genuinely callable from C: a built `.so` has zero `NEEDED` entries
  (freestanding), exports the documented mangled symbol names, and a C driver
  linked against it produces the exact expected output.
- **`tools/migrate-identifiers`** — the mechanical migration tool described
  above, with its own test suite (idempotent, byte-identical on
  already-canonical input, preserves the semantic meaning of blank lines
  between function definitions).

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
>    errors.** Switch to `see "<lib>" version "<ver>" from "<path>.lib"`.
>
> Upgrading from before 0.1.23? Two earlier breaking changes are documented
> under their own releases below: arithmetic on a text/buffer/list/file now
> errors with a cast suggestion (`0.1.21`), and `.en` source includes no
> longer inline — use `.vox` (`0.1.23`).

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

## [0.1.23] - 2026-07-31

Collections, maps, the `nothing` value, and the shared-library foundation.

> **Breaking.** `.vox` is now the sole source extension: a `see` of a `.en`
> source, which was the only include form that worked before, no longer
> inlines (silently — the call site errors "Unknown function"). Switch `.en`
> includes to `.vox`. The main input still accepts any extension. See
> `### Changed` below.

### Added

- **Whole-list printing.** `Print <list>` renders the list (`[1, 2, 3]`), and
  `{list}` format interpolation routes the same way. Previously printing a
  list showed only the first element.
- **Mixed-type lists with per-slot type tags.** A list may hold number, text,
  decimal, and boolean together; each element carries a one-byte runtime tag
  and reads back as its own type. A list the compiler can prove homogeneous
  keeps an untagged fast path; one it cannot prove widens to mixed by default
  ("static is a proof, mixed is the default"), so an opaque value — e.g. a
  function result with no declared return type — is never silently reinterpreted.
- **Nested lists.** A list element may be a list; printing is recursive and
  cycle-safe (capped at depth 64).
- **Type predicates.** `is a number/text/decimal/boolean/list/map` (and
  `is not a …`) read the runtime type tag and fold at compile time on a
  statically-typed value.
- **The `value` type.** A declared dynamic type that carries its runtime tag
  across a function call, so one function can accept "whatever this slot
  holds" and ask `is a …` inside. A `value` is rejected from arithmetic until
  its type is checked.
- **`nothing` (the absent value).** `null` and `nil` are accepted spellings.
  It sits in a list, map, or `value` slot, prints as `nothing`, and is tested
  with `is nothing`. It is not `0`: `0 is nothing` is false.
- **Maps.** Key/value collections — JSON objects. `{"key": value}` literals
  (empty `{}`), `map's "key"` read, `set map's "key" to value`, `length`/
  `empty`/`keys`/`values`, recursive printing. A missing key sets the error
  flag (it is an error, not `nothing`); keys are text only.
- **Shared-library foundation.** `--shared` builds a self-contained,
  position-independent `.so` a C or assembly caller can reach; only the
  library's own functions are exported (runtime symbols are kept out of the
  dynamic table), and an empty `--shared` export is rejected. (Consuming a
  library from Vox via `see` of a `.lib` arrives in 0.2.0.)

### Changed

- **`.vox` is the sole source extension.** `see` of a `.vox` source now
  inlines correctly — the include gate previously matched `.en`, so
  `see "./foo.vox".` was silently skipped and the call site errored "Unknown
  function". The `.en` form, which was the one that worked, no longer inlines;
  switch `.en` includes to `.vox`. The main input still accepts any extension.
- **`nothing` is refused in arithmetic.** A literal `nothing` in arithmetic
  is a compile error — "Cannot use nothing in arithmetic; check it with 'is
  nothing' first" — and a `nothing` that turns up at run time (read from a map
  or a mixed list) sets the error flag so `on error` catches it. `nothing` is
  new in 0.1.23, so this is a safe default, not a change to code that used to
  work: there was no `nothing` to put in arithmetic before.

### Fixed

- **Maps own their keys.** The map copies each key on insert rather than
  borrowing the caller's text. No current Vox program could break the old
  borrowing — keys are text literals and buffers are rejected as keys — but a
  dynamic key would have corrupted the entry; a forward correctness fix.

## [0.1.22] - 2026-07-31

A hardening release with one user-visible fix.

### Fixed

- **Function-parameter type labels no longer leak to the top level.** A
  parameter named like a top-level variable previously relabeled it: after
  `To "show" with a text called "x"`, top-level arithmetic on a number `x`
  was falsely rejected as text arithmetic. The parameter's type is now
  scoped to its function body.

## [0.1.21] - 2026-07-28

Heterogeneous lists, type-checked arithmetic, and buffer-safety fixes.

> **Breaking.** Arithmetic on a text, buffer, list, file, or timer now
> errors with a cast suggestion. Such code previously compiled to pointer or
> handle arithmetic and produced a wrong number at runtime. Add a cast where
> you meant a numeric conversion. See `### Changed` below.

### Added

- **Heterogeneous lists with per-slot type tags.** A list may hold mixed
  types (number, text, decimal, boolean); each element carries a runtime type
  tag and reads back as its own type. (Whole-list printing, the `value` type,
  type predicates, maps, and `nothing` follow in 0.1.23.)

### Changed

- **Arithmetic operands are type-checked.** Using a non-numeric value — a
  text, buffer, list, file, or timer — in arithmetic is now a compile error
  naming the value and suggesting a cast (`as a number` / `as a float`).
  Previously such code compiled to pointer or handle arithmetic and produced
  garbage at runtime. Add a cast where you meant a numeric conversion.

### Fixed

- **A genuine fixed-buffer overflow is an error**, not silent data loss.