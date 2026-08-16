# Plan 303 — list element typing defects (BUGS_FOUND #17, #18)

Two open defects in how list elements acquire and carry their type, found
2026-08-16 and recorded in `docs/BUGS_FOUND.md` (#17, #18). Phase 1 is a
memory-safety bug and comes first; Phase 2 is a static-inference gap in the
`.lib` writer. Do them in order, with a commit per phase.

Baselines that must hold after every phase: `cargo build --release` clean,
`./test.sh` fully green (currently 307 passed / 0 failed / 6 skipped — the
skips are the root-requiring `manual_*` cases and are expected).

---

## Phase 1 — #17: appending a format string to a list stores a corrupt element

**Severity: high.** This violates the memory-safety story: user programs
segfault or print raw addresses with no unsafe construct in sight.

### Reproductions (all standalone executables, current `main`)

```vox
a list called out is [].
a text called x is "x".
append "fmt {x}" to out.
Print the out.
```
→ SIGSEGV (exit 139). `element 1 of out` read into a text and
`For each w from out, print "<{w}>".` segfault identically.

Variants, same 4-line shape, differing only in the appended expression:

| appended | `Print the out.` result |
|---|---|
| `"literal"` (no interpolation) | correct `["literal"]` |
| `"fmt {x}"`, `x` a text | SIGSEGV |
| `"n {k}"`, `k` a number | prints a raw pointer, e.g. `[139846434144280]` |
| `"{w}"`, `w` a buffer | prints a raw pointer |
| text local initialized from a format string, appended by name | SIGSEGV |
| text local initialized from a literal, appended by name | correct |

### Where to look

- `Statement::ListAppend` codegen: `src/codegen/mod.rs:5023` (plus the
  store-back sites near `:451` and `:2596`, and the tag-forwarding pattern
  referenced at `:7224`).
- `Expr::FormatString` (`src/parser/ast.rs:188`); its codegen arms at
  `src/codegen/mod.rs:1327`, `:6177`, `:8423`.
- The element-tagging tests in `src/codegen/mod.rs` around
  `append_fresh_mixed_element_keeps_tag`, `declared_text_function_append_tagged_string`,
  `declared_type_does_not_forge_a_string_tag` — the fix must be consistent
  with the design decisions those tests pin.

The working hypothesis from the reproduction matrix: a format string
evaluated as a list-append source yields something other than a durable
tagged string payload (a temporary, or a buffer struct pointer rather than
its data), and nothing in the append path materializes or tags it. A format
string can only ever produce text, so the append should store an owned,
text-tagged element — the same outcome as appending a call with a declared
`text` return, which works today.

### Acceptance

1. Every reproduction above prints the interpolated text correctly
   (`["fmt x"]`, `["n 7"]`, `["buf"]`, …) with exit 0, via whole-list print,
   `element N of`, and `for each`.
2. The homogeneous fast path is preserved: a list whose elements are all
   provably one scalar type must not start emitting per-element tag dispatch
   where it doesn't today (the existing codegen tests pin this).
3. Regression tests in the repo's established style
   (`tests/bugs_found_17_*.vox` + `.expected`, and/or unit tests beside the
   existing tagging tests) covering: direct format-string append with text,
   number, and buffer interpolants; the text-local-from-format-string
   variant; element access and for-each readback.
4. `docs/BUGS_FOUND.md` #17 status flipped to fixed, naming the tests, and a
   CHANGELOG `Unreleased`/`Fixed` entry describing the behaviour change.

---

## Phase 2 — #18: `.lib` element-type inference credits fewer shapes than the runtime tagger

**Severity: low.** No crash; the `.lib` table of contents under-reports.

### Reproduction

A `--shared` library where each exported function appends exactly one
element to a fresh list and returns it with a declared `Return a list, out.`:

| element appended | `.lib` records today | should record |
|---|---|---|
| `append "literal" to out` | `list of text` | `list of text` |
| text parameter appended by name | `list of text` | `list of text` |
| text local initialized from a literal, appended by name | `list` | `list of text` |
| call to a function with a declared `text` return | `list` | `list of text` |
| format-string appends (both shapes) | `list` | `list of text`, once Phase 1 makes the element sound |

### Where to look

`scan_list_element_type`, `note_element_type`, and `scalar_expr_type` in
`src/codegen/mod.rs` (~428–460), and the `list_element_types` map they feed.
The scan currently proves an element type only for direct literals and typed
parameters. A local variable's declared scalar type is authoritative for its
reads, and a call's declared return type likewise — both should count as
evidence, as should a format string (always text) once Phase 1 lands.

If widening any of these conflicts with the conservatism pinned by
`declared_type_does_not_forge_a_string_tag` (runtime tag forging is a
different, deliberate decision from static TOC evidence), keep the two
mechanisms separate and document the distinction in a comment rather than
weakening either.

### Acceptance

1. All five shapes above emit `list of text` in the `.lib` table of
   contents; a genuinely mixed or evidence-free list still emits plain
   `list` (the `plan_296_list_element_type_stays_unknown_on_disagreement_or_no_evidence`
   test must keep passing).
2. Consumer behaviour for the previously-under-reported shapes is unchanged
   or better (they already print correctly via runtime tags).
3. Unit tests beside the existing `plan_296_*` element-type tests covering
   the newly credited shapes.
4. `docs/BUGS_FOUND.md` #18 status flipped, CHANGELOG entry appended to the
   same `Fixed` section.

---

## Constraints and traps

- **No parser or language-surface changes.** This is codegen and the `.lib`
  writer only.
- **The `.lib` format itself does not change** — only what the existing
  `list of <type>` slot gets filled with.
- Semver: both are bug fixes — patch-level; do not bump the version, just
  extend `Unreleased` in the CHANGELOG.
- Compile throwaway test programs from `/tmp`, never from the repo root —
  `vox --run` leaves the binary in the CWD. Stage commits with named paths
  only; never `git add -A`.
- A `--shared` build refuses to overwrite an existing `.lib`; `rm` it before
  rebuilding in any script or test.
- Judge crashes by exit code (139 = SIGSEGV, 124 = hang): a segfaulting
  program can look like empty-but-clean output.
- If any finding in this plan looks wrong once you're in the code, document
  why in the phase's commit message or a note here rather than implementing
  around it.

## Phase 1 finding: the plan's own repro exercises a second, unrelated bug

The Phase 1 reproduction (`a text called x is "x". append "fmt {x}" to out.`)
does SIGSEGV as documented, but not solely from bug #17. Its variable is
named `x` and initialized to the literal `"x"` — the same text as its own
name. `Statement::VarDecl` registers a declared variable's type (and BSS
mirror) before generating its initializer expression, and `Expr::StringLit`
codegen resolves a quoted name against known variables to decide
"literal vs. reference". So the initializer reads `x`'s own not-yet-written
slot instead of the literal `"x"`, leaving `x` null; confirmed standalone
with no list or format string involved (`a text called x is "x". Print x.`
segfaults on its own). This is a separate, previously-undocumented defect,
out of scope for this plan (not `Statement::ListAppend`/`Expr::FormatString`
codegen, and no parser/language-surface change would fix it). Documented in
`docs/BUGS_FOUND.md` under #17 rather than filed as its own numbered entry.

Bug #17's actual, in-scope defect — confirmed by disassembly — was purely in
the element's *type tag*, not its payload: `generate_expr` already built a
sound, durable string pointer for every format string; `emit_time_expr_tag`
and `prescan_expr_tag` just had no arm for `Expr::FormatString` and fell
through to their integer default. Once the reproduction matrix is re-run
with non-colliding names, all four interpolation shapes (literal, text,
number, buffer) showed the *same* symptom — a raw pointer printed where text
belonged — not the differentiated SIGSEGV/pointer split the original matrix
recorded (that split was an artifact of the `x`/`"x"` collision hitting only
the `x`-interpolating rows). Fixed by adding an explicit
`Expr::FormatString => TAG_STRING`/`VarType::String` arm to both functions.
