# Plan 230 — shared libraries Phase 3: `.lib` interfaces, mangling, `see` wiring

Completes plan 200. Phases 0–2 made a `.so` **producible**; this makes it
**consumable from Vox**, which is what the whole feature is for.

Two tracks run in parallel on separate branches and **do not share a file**:

| Track | Branch | Owns | Stages |
|---|---|---|---|
| **A — code** | `p230-libs` | `src/`, `tests/`, `test.sh` | A1 → A5 |
| **B — docs** | `p230-docs` | `*.md`, `docs/`, `examples/` | B1 → B2 |

If a track needs to touch the other's files, stop and say so — do not reach
across. Track B documents what this plan specifies; it does not wait for
Track A to build it.

---

## Design decisions (settled 2026-08-01 with the project owner — do not relitigate)

1. **Multi-input `--shared`.** `vox a.vox b.vox --shared -o lib.so` links
   several libraries into one `.so`. You cannot append to a linked `.so`, so
   the only coherent way to get two libraries into one file is one link step.
2. **One canonical `see`:** `see "<lib>" version "<ver>" from "<path>.lib".`
   Every other form is deleted. Today's parser accepts four; three of them
   encode the abandoned direct-`.so` model.
3. **The `.lib` is trusted for types, verified for existence.** Vox types are
   not recoverable from ELF, so the `.lib` is the only type source. But every
   mangled name it promises is checked against the `.so`'s `.dynsym` at
   compile time, which is the only staleness check available.
4. **Mangling is a deliberate break.** `add_two_numbers` becomes
   `mathkit_1_0_add_two_numbers`. There is no unmangled alias — an alias would
   defeat the version isolation that is the point.
5. **`Location` resolves relative to the `.lib` first,** then `--lib-path`,
   then error. Absolute paths in a `.lib` are honoured but never generated.

### Explicit non-goal: runtime state is *not* mangled

`SHARED_LIBRARIES_DESIGN.md` says `_last_error` and the resource tables get
per-version mangling. **Phase 3 does not do this, on purpose.** Multi-input
compiles to one assembly unit, so the runtime is emitted once and shared by
every library in that `.so` — which is correct and desirable: one resource
table, one `.fini_array`, one `_cleanup_all` that stays idempotent.
Duplicating the runtime per library would multiply size and give a `.so`
several competing cleanup paths. Cross-`.so` isolation already holds, because
each `.so` carries its own runtime and the version script hides it.

Track B updates the design doc to match. If you think this is wrong, argue it
before implementing anything else — it changes A1.

---

## The `.lib` format (normative — both tracks work from this)

```
Library "mathkit" version "1.0".
Location "./libmathkit.so".

Table of Contents:
    To "add two numbers" with a number called "n", returning a number.
    To "greet".
    To "makebuf", returning a number.
```

- **Lexed with the existing `Lexer`** so quoting and escaping rules cannot
  drift from Vox source, but **parsed by a dedicated parser** in
  `src/lib_file.rs` — not the full Vox parser. A `.lib` must be incapable of
  carrying executable statements; a dedicated ~150-line parser makes that
  structural rather than a post-hoc rejection, and gives precise errors.
- Parameter types and return types are drawn from the existing signature
  vocabulary: `number`, `text`, `boolean`, `file`, `value`. Anything else is
  an error naming the unsupported type.
- `, returning a <type>` is new and exists only in `.lib` files. Vox source
  declares return types in the body (`Return a number, x.`), which a
  bodiless declaration has no room for.
- **Several `Library` blocks may appear in one `.lib`**, each with its own
  `Location`. Parsing runs to EOF; a `Library` line starts a new block.

## Mangling (normative)

`mathkit` + `1.0` + `add two numbers` → `mathkit_1_0_add_two_numbers`.

> **Corrected 2026-08-01, after A1.** This section originally read "apply
> `mangle_symbol` to each of the three components and join with `_`". Taken
> literally that produces `mathkit__1_0_add_two_numbers` — a *double*
> underscore — because `mangle_symbol` prefixes a leading digit, turning `1.0`
> into `_1_0`. The example above was always the intended result; the rule
> stated beside it was wrong. A1 implemented the intended result and flagged
> the contradiction rather than emitting the double underscore.

The rule, precisely: there is **one** sanitizer, `sanitize_symbol`, mapping
every character outside `[A-Za-z0-9_]` to `_`. `mangle_symbol` is that plus a
leading-digit prefix. The library mangling applies:

- **full `mangle_symbol` to the library component** — it starts the symbol, so
  a leading digit there would make the whole result an invalid C identifier;
- **`sanitize_symbol` alone to the version and function components** — they are
  interior, joined by `_`, so a leading digit is harmless and the prefix would
  only insert a spurious second underscore.

Do not write a second sanitizer.

---

# Track A — code (`p230-libs`)

## Stage A1 — mangle exported symbols by library and version

The label itself must change, not just the export list. Two libraries in one
`.so` both defining `greet` would otherwise emit the same NASM label twice.

- `Statement::LibraryDecl` sets the codegen's current library identity;
  `FunctionDef` and every call site resolve through it while
  `shared_lib_mode` is on.
- `--shared` **without** a `Library` declaration becomes an error: a library
  with no identity has no mangling and no `.lib`. Diagnose it plainly.
- Non-shared builds are completely unaffected — same labels as today.
- Update `tests/runtime/shared_lib_driver.asm` externs and the exact export
  set in `test.sh` to the mangled names.

**Acceptance**
- `nm -D --defined-only libmath.so` is exactly
  `{mathkit_1_0_add_two_numbers, mathkit_1_0_greet, mathkit_1_0_makebuf}`.
- Two source files each defining `greet`, in one `.so`, assemble and both are
  independently callable.
- A `--shared` build with no `Library` line errors with a message naming the
  missing declaration.
- Every existing non-shared test is byte-identical in output.

**Success**: `cargo build --release` 0 warnings · `cargo test --release` ≥ 116
· `./test.sh` ≥ 196 passed, 0 failed, **exactly 6 skipped**.

## Stage A2 — multi-input `--shared`

`vox a.vox b.vox --shared -o lib.so`. Sources are parsed independently, then
concatenated into one compilation unit, so the runtime is included once.

### Carried forward from A1 — the symbol tables are keyed by authored name

A1 mangled the *labels* and proved they are distinct. It could not demonstrate
two libraries each defining `greet` in one `.so`, and found why: the
per-compilation symbol tables (`function_return_types`, `function_param_types`,
and any other map keyed on the authored name) are keyed by the name the author
wrote, not by the label. Two `greet`s therefore collide in those maps even
though their emitted labels differ.

**This is A2's to solve, and it is the core of the stage** — not a detail.
Distinct labels are necessary but not sufficient; until the tables are scoped
by `<library, version>`, the second library's signature silently overwrites
the first's, and calls resolve against the wrong return and parameter types
with no diagnostic. That is a wrong-code bug, not a compile error, so nothing
will catch it for you.

Scope those tables by `<library, version>` and keep resolution within the
current library. A call from library A to library B in the same `.so` is out
of scope for this stage; if a name is not found in the current library, that
is the existing unknown-function error.

- Reject duplicate `<lib,version>` pairs across inputs with both filenames.
- Multi-input is `--shared` only; reject it for executable builds, where the
  semantics would be ambiguous.
- The version script must list every library's exports.

**Acceptance**
- Two libraries in one `.so`; `nm -D` shows both mangled sets and nothing else.
- Two *versions* of one library in one `.so` coexist and are separately
  callable — this is the backwards-compatibility case the design exists for.
- Duplicate `<lib,version>` errors and names both files.
- `readelf -r` still shows zero absolute relocations.

## Stage A3 — emit the `.lib`

A `--shared` build writes `<output-stem>.lib` beside the `.so`, one `Library`
block per input, `Location` **relative to the `.lib`**, and a `Table of
Contents` of every exported signature.

- Never overwrite a pre-existing file that this build did not produce without
  saying so — plan 210's P1 was exactly this class of bug.
- The `.lib` must be re-readable by Stage A4's parser. Round-trip is the test.

**Acceptance**
- Emitted `.lib` parses cleanly and its ToC matches `nm -D` one-for-one.
- Two inputs produce two `Library` blocks in one `.lib`.
- Signatures carry parameter names, parameter types, and return types.

## Stage A4 — parse `.lib` and wire `see`

The consumer side. `see "mathkit" version "1.0" from "./mathkit.lib".`

1. Resolve the `.lib` (relative to the source, then `--lib-path`).
2. Parse it; select the block matching name **and** version.
3. Resolve `Location` relative to the `.lib`, then `--lib-path`.
4. **Verify against `.dynsym`**: every mangled ToC name must exist in the
   `.so`. Write a minimal ELF64 `.dynsym` reader in Rust — do not shell out to
   `nm`, and do not add a crate. The compiler already requires `nasm` and `ld`;
   it should not grow a third external dependency for something this small.
5. Register the signatures so calls type-check like any other function.
6. Emit `extern <mangled>` and call it; add the `.so` and its `-rpath` to the
   link line.

Diagnostics are the deliverable as much as the linking is. Each of these gets
its own message naming the file and what was expected:
missing `.lib`; no such library in it; **version mismatch, listing the
versions the `.lib` does offer**; missing `.so` at `Location`; symbol absent
from `.dynsym` (name the symbol — this is the stale-`.lib` case); arity or
type mismatch at the call site.

### Name resolution (added 2026-08-01 — the spec was silent and cannot be)

`see` puts foreign names into a scope that until now held only the program's
own definitions, so two collisions become possible for the first time: a local
definition versus an import, and an import versus another import — including
two *versions* of one library, which is the expected steady state here, not an
edge case.

**Local definitions win**, with a **warning** naming the library shadowed. The
alternative is that adding an unrelated `see` silently redirects an existing
call to someone else's code — behaviour changing with no diagnostic and no
edit to the call site. Shadowing is legitimate (it is how you locally override
a library function), so it is not an error; it must simply never be silent.

**Ambiguity between two imports is a compile error**, naming the call, both
libraries and both versions. Do not pick one. Resolving by `see` order makes a
call's meaning depend on the order of unrelated lines at the top of the file;
resolving by highest version silently changes behaviour on upgrade, which is
the exact outcome multi-version support exists to prevent.

**No qualification syntax in A4.** `{"greet" from "mathkit"}` is probably right
eventually, but it is new user-facing surface needing its own design, and the
error above tells the user what is wrong meanwhile. If you find a case where
that error leaves a user genuinely stuck with no way forward, report it —
do not invent the syntax.

**Acceptance**
- A pure-Vox program calls a pure-Vox library through `see` and prints the
  right answer. **This is the goal of plans 200 and 230 — until it passes,
  nothing else in either plan has delivered its purpose.**
- Wrong version, absent library, missing `.so`, and a hand-edited stale ToC
  entry each produce their own diagnostic. All four are tested.
- Calling with the wrong argument count or type is a compile error.
- The two-version `.so` from A2 is consumed at each version from two programs.
- A program defining `greet` and importing a library exporting `greet`
  compiles, calls its **own** `greet`, and warns naming the shadowed library.
- A program importing two libraries that both export `greet` fails to compile,
  and the error names the call, both library names and both versions.
- A program importing `flags 0.1` and `flags 1.0` and calling a function
  present in only one of them resolves correctly and does not warn.

## Stage A5 — retire the abandoned syntax

- `see` of a `.so` is an error directing the user to the `.lib`. It is
  currently a silent no-op that compiles a program with the call missing —
  the trap that makes the stale docs dangerous.
- Delete the three non-canonical `see` forms from `parse_see`
  (`src/parser/mod.rs:3839`). Removed syntax gets a diagnostic showing the
  canonical form, not a parse error.
- `see` of a `.vox` source keeps working unchanged.

**Acceptance**: each retired form produces a message showing the canonical
syntax; `.vox` includes unaffected; a `.so` `see` never compiles silently.

---

# Track B — documentation (`p230-docs`)

The audit is done and lives in `docs/plans/220_so_lib_documentation_audit.md`
under `## Findings`. This applies it.

## Stage B1 — correct the stale direct-`.so` claims

Work the 220 findings in order. Every correction states the current model:
`.vox` → `see` a `.lib` → `Location` → `.so`.

- `docs/SHARED_LIBRARIES_DESIGN.md:71` claims the compiler parses `.so` files
  top-to-bottom looking for `Library` declarations. That describes `.lib`
  parsing; a `.so` is binary ELF.
- Also update that document's runtime-state mangling section per the explicit
  non-goal above, **with the reason**, so the next reader does not implement
  the abandoned version.
- `README.md` and `ROADMAP.md` per the findings.
- Do not delete history: where a doc records the abandoned design, mark it
  abandoned and say why. A reader who finds only silence will re-propose it.

**Acceptance**: every 220 finding is either corrected or has a written reason
it was left; no document still asserts a `.so` is directly importable; the
`.lib` chain appears in each place the old claim did.

## Stage B2 — document the library system properly

`LANGUAGE.md:2796-2805` lists four `see` forms, two of them the abandoned
model, and never mentions `.lib` at all.

- Rewrite that section around the canonical form. Delete the others.
- A new **Shared libraries** section: writing one (`Library`, `--shared`,
  multi-input), the `.lib` format with a full worked example, consuming one
  with `see`, and how versions coexist in one `.so`.
- Document the mangling scheme where a C or Rust caller will look for it —
  they need the mangled name to link against.
- A runnable `examples/` pair: a small library and a program that uses it,
  with the exact commands to build both.

**Acceptance**: a reader who has never seen the feature can write, build,
publish and consume a library from `LANGUAGE.md` alone. Every command shown
is one you have run. Every code sample compiles.

---

## Constraints (both tracks)

- **No libc, ever.** `nasm` + `ld` + `cargo` only. No new crates.
- **Never weaken a test to make it pass.** A rising skip count is a failure —
  `./test.sh` must report **exactly 6** skipped. A skipped test still prints
  "ALL TESTS PASSED", which is how this hides.
- **Commits are GPG-signed by hardware key and a human must touch it.** If a
  commit hangs, that is the key waiting for a person: wait and say so. Never
  `--no-gpg-sign`, never `-c commit.gpgsign=false`.
- One commit per stage. Do not push, do not open a PR.
- **Report what you could not do.** Silently reducing scope is the one
  unrecoverable failure here — a gap you name costs a follow-up, a gap you
  hide ships.
- If this plan is wrong, say so and argue it rather than implementing
  something you believe is a mistake.

## Definition of done

- [ ] A Vox program calls a Vox library through `see` of a `.lib`
- [ ] Two versions of one library coexist in one `.so`, both callable
- [ ] Stale `.lib`, wrong version, missing `.so`, bad call — four diagnostics
- [ ] `see` of a `.so` errors; the three retired forms error with guidance
- [ ] No document claims a `.so` is directly importable
- [ ] `LANGUAGE.md` documents the whole chain with runnable examples
- [ ] 0 warnings · cargo ≥ 116 · `./test.sh` ≥ 196 passed, 0 failed, 6 skipped
- [ ] `readelf -r` zero absolute relocations on every `.so` built
