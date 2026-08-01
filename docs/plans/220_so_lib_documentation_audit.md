# Plan 220 — audit: where the docs claim a `.so` can be used directly as a library

**This is an audit, not a fix.** Produce an inventory. Change no behaviour, correct
no wording. The target design is not settled yet, and edits made before it is
would have to be redone.

## Background — why direct `.so` linking cannot work

The original design linked a program straight to a `.so`. That was later found
to be unworkable, and `docs/SHARED_LIBRARIES_DESIGN.md` replaced it with a
`.lib` indirection. Documentation from before that change survives in several
places and still asserts the original, wrong model.

The reason it cannot work: **a `.so` is binary ELF.** The compiler can read
mangled symbol *names* out of `.dynsym`, but nothing about Vox types — how many
parameters a function takes, whether each is a number or a text, what it
returns. Without that it cannot check a call site, infer types, or produce a
useful diagnostic. `nm -D` on a Vox library today gives exactly
`add_two_numbers`, `greet`, `makebuf` and no more.

So a `.lib` is the typed interface — the `.h` equivalent:

```
Library "flags" version "0.1".
Location "/home/josj/scr/ec/libs/libflags.so".

Table of Contents:
    To "hasflag" with a text called "flag".
    To "isverbose".
```

The chain is **`.vox` → `see` a `.lib` → `Location` → `.so`**. A `.vox` file may
also `see` another `.vox`, which is a source include and already works.

## What counts as a finding

Flag a line **only** if it asserts or implies that a `.so` can serve as a
library interface — that a program can `see`/import/link one *as a library* and
call its functions. Examples of findings:

- `see "./path/to/lib.so".` presented as a working library import
- `see "libname" version "1.0" from "./path.so".` as the linking form
- prose stating a program links "directly to the `.so`"
- a parser comment, `--help` string, or error message offering a `.so` as the
  argument to `see`
- `docs/SHARED_LIBRARIES_DESIGN.md:71` — "parse `.so` files from top to bottom,
  treating each `Library "<name>" version "<ver>"` declaration as a separator".
  A `.so` is binary; this describes `.lib` parsing. Start here, it is confirmed.

**Do NOT flag** these — they are correct and must stay:

- `--link` / `--lib-path` against a `.so`. This works today and is verified.
- `vox lib.vox --shared -o lib.so` producing a `.so`. Correct.
- A `.so` carrying its own runtime, being loadable from C/Rust, `.fini_array`,
  the version script, `nm -D`/`readelf` checks. All correct.
- `Location "…/libflags.so"` inside a `.lib`. That is the intended chain.
- `see` of a **`.vox`** file. That is a source include and works.

When unsure, list it as **uncertain** with your reasoning rather than
guessing either way. A misclassification in either direction costs more than
an honest question.

## Where to look

`docs/` (including `docs/plans/`), `LANGUAGE.md`, `README.md`, `ROADMAP.md`,
`src/` (comments, `--help` text, diagnostics, parser doc-comments), `tests/`,
`examples/`. Search for `.so`, `see`, `See`, `Library`, `link`, and `.lib`.
Grep is a starting point, not the deliverable — read the surrounding context,
because the wrong assertions are often in prose that never names `.so` on the
same line.

## Deliverable

Append a `## Findings` section to **this file**. One entry per finding:

| field | content |
|---|---|
| location | `path:line` |
| quote | the asserting text, trimmed |
| why wrong | one sentence |
| suggested correction | what it should say, or "delete" — **do not apply it** |
| confidence | confirmed / uncertain |

Group by file, most-load-bearing file first — `LANGUAGE.md` is what users read,
so it outranks a plan document. Finish with a short count: findings per file,
and how many are uncertain.

Also note any place the docs are **silent** where they should not be — if
`LANGUAGE.md` documents `see` without mentioning `.lib` at all, that is a gap
worth recording even though no single line is wrong.

## Out of scope

No code changes. No wording changes. Do not implement plan 200 Phase 3, do not
create `.lib` parsing, do not touch the parser's accepted syntaxes. If you
notice a code defect while reading, record it at the end under
`## Incidental code observations` and keep going.

## Success criteria

- [ ] Every file in the search set has been read, not just grepped
- [ ] Each finding has a location, quote, reason, and confidence
- [ ] Correct `.so` usage (`--shared`, `--link`, `Location`) is not flagged
- [ ] Uncertain cases are marked uncertain rather than guessed
- [ ] `cargo build --release` 0 warnings; `cargo test --release` ≥ 116;
      `./test.sh` ≥ 196 passed, 0 failed, 6 skipped — unchanged, since this
      task changes no code

---

## Findings

Audit run 2026-08-01 on `so-lib-audit` at `570aefc`. Search set read end to
end, not just grepped: `LANGUAGE.md`, `README.md`, `ROADMAP.md`, every file in
`docs/` (including `docs/plans/`), every `.rs` in `src/`, `tests/`, `examples/`.
The classification boundary in the spec held — nothing was found that proves a
`.so` carries Vox type information, and `--link` is verified working (it links
an assembly driver against `libmath.so` and calls across the boundary in
`./test.sh`; the driver is hand-written assembly that declares its externs
itself, which is exactly why `--link` works for it while a compiler-driven
`see .so` cannot). Grouped by file, most load-bearing first.

### `LANGUAGE.md` — what users read

| field | content |
|---|---|
| location | `LANGUAGE.md:2797-2798` |
| quote | `see "./libraries/math.so".` / `see "math" version "1.0" from "./libraries/math.so".` (shown under "Use `see` to include other source files or libraries:") |
| why wrong | A `.so` is binary ELF with mangled symbol names but no Vox type information, so the compiler cannot treat a `see` of one as a library import; today `see` of a non-`.vox` path is kept as a marker and emitted as an assembly comment (`src/codegen/mod.rs:4164`), linking nothing. |
| suggested correction | Replace both lines with the intended chain — `see "./math.lib"` (a `.lib` carrying the typed table of contents and a `Location` pointing at the `.so`) — and keep `see "./utils.vox"` as the source-include form. Do not apply yet. |
| confidence | confirmed |

| field | content |
|---|---|
| location | `LANGUAGE.md:2803-2805` |
| quote | `- see "./path/to/lib.so". - Include compiled library` / `- see "libname" version "1.0" from "./path.so". - Include specific version` / `- see "./path.so" for "libname" version "1.0". - Alternative syntax` |
| why wrong | The "Syntax variations" list presents three `see`-of-a-`.so` forms as supported library imports; none of them links anything (see above). |
| suggested correction | Replace the three `.so` bullets with the `.lib` form(s); keep the `see "./path/to/file.vox".` bullet. Do not apply yet. |
| confidence | confirmed |

**Silence (no single line is wrong, but the section is).** The "Libraries and
Imports" section documents `see` with a `.vox` and a `.so` form but never shows
`see` of a `.lib` — the typed interface the design moved to. `.lib` is named
only once, buried in the "What is not yet supported" paragraph at
`LANGUAGE.md:2857` ("`.lib` metadata … arrive together in a later phase"),
which itself defers the whole feature. A user reading the `see` syntax list
gets the old direct-`.so` model and no pointer to the `.lib` chain that
replaced it. Worth recording even though no one line is false.

**Internal contradiction (already noted by plan 200 at
`docs/plans/200_shared_library_repair.md:558-561`).** The examples and syntax
list above (`:2797-2805`) present `see` of a `.so` as working, while
`LANGUAGE.md:2854-2859` says "linking a program against a `.so` through `see`
arrive together in a later phase; until then `--link` is the way to link an
executable against a built `.so`." The later paragraph is the correct,
current-state one; the `see .so` examples above are the stale remnant.

### `docs/SHARED_LIBRARIES_DESIGN.md` — the design authority

| field | content |
|---|---|
| location | `docs/SHARED_LIBRARIES_DESIGN.md:71` |
| quote | "The compiler must parse `.so` files from top to bottom, treating each `Library "<name>" version "<ver>"` declaration as a separator between library blocks. The parsing continues until EOF is reached." |
| why wrong | A `.so` is binary and contains no `Library "…"` text; this describes parsing a `.lib` (the typed table of contents), not a `.so`. |
| suggested correction | "The compiler must parse `.lib` files from top to bottom, treating each `Library "<name>" version "<ver>"` declaration as a separator…" Do not apply yet. |
| confidence | confirmed |

| field | content |
|---|---|
| location | `docs/SHARED_LIBRARIES_DESIGN.md:112` |
| quote | "- Handle multi-library parsing in `.so` files" (under "#### 1. Parser Modifications") |
| why wrong | Same error as `:71` — the parser cannot read `Library` declarations out of a binary `.so`; that is `.lib` parsing. |
| suggested correction | "Handle multi-library parsing in `.lib` files". Do not apply yet. |
| confidence | confirmed |

Note: this file is mostly *correct* on the new model — its "Library Linking"
section at `:48-51` already says `See "Path/to/library.lib" for "lib_name"
"version"`, and the `Location "…/libflags.so"` example at `:37` is the intended
chain. The two findings above are stale remnants of the pre-`.lib` design
surviving in the "Multi-Library .so" subsection. The multi-library `.so`
*structure* diagram at `:275-288` and the linker bullet at `:128` ("Handle
multiple library versions in single `.so` files") describe bundling several
libraries' mangled symbols into one `.so`, which is fine and is **not** flagged.

### `src/parser/mod.rs` — parser doc-comment and diagnostic

| field | content |
|---|---|
| location | `src/parser/mod.rs:3840-3844` |
| quote | `// Supported syntaxes:` followed by `// see "math" version "1.0" from "./path.so".`, `// see "./path.so" for "math" version "1.0".`, `// see "./path.so" for math version 1.0.` (in `parse_see`) |
| why wrong | A parser doc-comment listing `.so` as a "Supported" `see` argument; `see` of a `.so` is parsed but compiles to a comment (`src/codegen/mod.rs:4164`), so it is not a supported library-linking syntax. |
| suggested correction | Keep only `// see "./path/to/file.vox".` here and route the library forms through `.lib` when that lands. Do not apply yet. |
| confidence | confirmed |

| field | content |
|---|---|
| location | `src/parser/mod.rs:3874-3876` |
| quote | Error message: `Or: see "libname" version "1.0" from "./path.so".` (shown when `see` is missing its path/name) |
| why wrong | The diagnostic offers a `.so` as the `see` argument, steering users at the non-working direct-`.so` form. |
| suggested correction | Point the hint at `see "./path/to/file.lib"` (or, until `.lib` exists, at `--link`). Do not apply yet. |
| confidence | confirmed |

### `ROADMAP.md`

| field | content |
|---|---|
| location | `ROADMAP.md:132` |
| quote | "`--shared`, `--link`, and `see ... version ...` already exist in early form." |
| why wrong | `--shared` and `--link` work; `see ... version ...` only *parses* and then emits a comment — it does not link. Grouping it with the two working flags as "already exist in early form" overstates it. |
| suggested correction | "`--shared` and `--link` work today; `see ... version ...` is parsed but not yet wired (arrives with `.lib` in Milestone 3)." Do not apply yet. |
| confidence | uncertain — "in early form" could be read as "the parser exists", which is true; flagged because it is filed beside two mechanisms that actually link. |

### `docs/plans/200_shared_library_repair.md` — the active implementation plan

| field | content |
|---|---|
| location | `docs/plans/200_shared_library_repair.md:163` |
| quote | "**A `see` of a `.so` produces a standalone library.** The shared object is self-contained and usable from C, Rust, or any other host — not only from Vox — and cleans up its own resources on exit regardless of who loaded it." |
| why wrong | The "`see` of a `.so`" framing is the direct-`.so` model the `.lib` indirection was introduced to replace; a pure-Vox `see` caller is explicitly out of scope here (`:142`: "A pure-Vox caller via `see` (needs the `.lib`/extern wiring above)"). |
| suggested correction | Reframe as "A `--shared` build produces a standalone `.so`…" and leave the `see` caller to the `.lib`-based Phase 3 design. Do not apply yet. |
| confidence | uncertain — the *content* (a `.so` carrying its own runtime, loadable from C/Rust) is correct and in the do-not-flag list; only the "`see` of a `.so`" framing is stale. This is a live plan, not user-facing doc, so it is low-load-bearing. |

### Count

| file | findings | uncertain |
|---|---|---|
| `LANGUAGE.md` | 2 confirmed + 1 silence | 0 |
| `docs/SHARED_LIBRARIES_DESIGN.md` | 2 confirmed | 0 |
| `src/parser/mod.rs` | 2 confirmed | 0 |
| `ROADMAP.md` | 1 | 1 |
| `docs/plans/200_shared_library_repair.md` | 1 | 1 |
| **total** | **9 entries (7 confirmed, 2 uncertain) + 1 silence** | **2** |

The two or three most load-bearing:

1. **`LANGUAGE.md:2797-2798`** — the example a user copies. It says `see
   "./libraries/math.so"` includes a library. It does not.
2. **`LANGUAGE.md:2803-2805`** — the "Syntax variations" list a user references
   for the correct form; three of four bullets point at a `.so`.
3. **`docs/SHARED_LIBRARIES_DESIGN.md:71`** — the design authority literally
   specifying "parse `.so` files … treating each `Library` declaration as a
   separator," which is the `.lib`-parsing claim the spec pre-confirmed.

---

## State of play — 2026-08-01, for the design work that follows

Recorded here because the audit is the starting point for planning Phase 3, and
a reader arriving cold needs the current position, not just the defect list.

### Shared libraries today: producible, not consumable from Vox

**Works.** `vox lib.vox --shared -o lib.so` builds a real library using the full
core language — arithmetic, print, buffers, files, floats, lists, maps. Exports
exactly the library's own functions, named by `mangle_symbol` (`To "add two
numbers"` → `add_two_numbers`); zero absolute relocations; `.fini_array`
registered; every coreasm symbol kept out of `.dynsym` by the version script.
Callable from any SysV host, proven on every `./test.sh` run by an assembly
driver linked with `--link`. Top-level statements and empty libraries are
rejected with clear diagnostics.

**Does not work.** From Vox, a library cannot be used at all:

```
see "mathkit" version "1.0" from "./libmathkit.so".
Display {"add two numbers" of 40}.
    → error: Unknown function: add two numbers
```

The `see` line parses, emits an assembly comment, and links nothing — with no
diagnostic. `Library "name" version "ver"` is likewise recorded and ignored;
exports are not `mathkit_1_0_*`.

### The intended design (confirmed with the project owner, 2026-08-01)

The chain is **`.vox` → `see` a `.lib` → `Location` → `.so`**. The `.lib` is the
typed interface — the `.h` equivalent — carrying library name, version, a
`Location` pointing at the `.so`, and a `Table of Contents` of signatures.
Authority: [SHARED_LIBRARIES_DESIGN.md](../SHARED_LIBRARIES_DESIGN.md).

**Multiple libraries — and multiple versions of the same library — live in one
`.so`, kept apart by name mangling.** This is a deliberate feature for
backwards compatibility, not an incidental capability: it is what lets a
consumer keep calling `flags_0_1_hasflag` after `flags_1_0_hasflag` ships
alongside it. Mangling is therefore load-bearing for the library system, not
cosmetic. Rules in [SYMBOL_MANGLING.md](../SYMBOL_MANGLING.md); the same scheme
already mangles per-library runtime state so two versions in one `.so` do not
share `_last_error`.

Direct `see` of a `.so` was the original design and was abandoned: a `.so` is
binary ELF, so the compiler can read mangled names from `.dynsym` but nothing
about Vox types, and cannot check a call site. The findings above are the
surviving documentation of that abandoned model.

### Open work, roughly by value

1. **Plan 200 Phase 3** — `.lib` generation and parsing, `<lib>_<version>_`
   export mangling, version enforcement, `see` wiring. This is what makes
   everything already built reachable from Vox. ROADMAP Milestone 3.
2. **Make `see` of a `.so` an error** rather than a silent no-op. Small, and it
   removes the trap that makes the stale docs dangerous.
3. **Apply these findings** once the target design is settled.
4. **Growable resource tables** — `MAX_FDS`/`MAX_BUFFERS` are 64 and
   `_register_buffer` silently no-ops when full. Needs its own plan.
5. **Spans in the `Statement` AST** — `find_symbol_location` misplaces any
   diagnostic whose symbol is short or common, not just the `--shared` ones.
6. **`coreasm` version stamping** — a stale system install currently fails with
   an inscrutable relocation error. Affects every build path.

### Environment note

`/usr/local/share/vox/coreasm` predates the Phase 1 PIC rewrite (34 `[abs`
sites against 0 in the repo), so `--shared` fails outside a repo checkout until
`sudo make install` is run. Not a code defect; see plan 210.

---

### Incidental code observations (not defects, no action taken)

- `src/main.rs:155-185` / `src/codegen/mod.rs:4164-4173`: a `see` whose path
  does not end in `.vox` is silently kept as a marker and emitted as an
  assembly comment (`; See: ...`), with no "not yet supported" diagnostic.
  This is why the `LANGUAGE.md` examples mislead without any compile-time
  warning — the program compiles and the library call simply is not there.
  By design pending Phase 3; recorded because it is what makes the stale docs
  dangerous in practice rather than just cosmetically wrong.
- No code defect was noticed. The `see .so` no-op, the `--link`/`--shared`
  paths, the version script, `.fini_array`, and the PIC runtime all behave as
  the (correct) docs and plans describe.
