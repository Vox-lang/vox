# User-Defined Things Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement plan 310 — user-defined composite types (`A thing
called point has ...`) with value semantics, unlimited nesting, manifest
function members, and the possessive call forms.

**Architecture:** A `ThingDef` registry built during parsing (definitions
must precede use), carried on the `Program` to the analyzer and codegen.
Things are flat inline memory — every field offset is a compile-time
constant, composed through nesting. No runtime component of any kind.
Each task lands one language capability end to end (parse → analyze →
codegen → tests) so the suite stays green at every commit.

**Tech Stack:** Rust (the vox compiler), NASM x86_64 output, `./test.sh`
integration harness, `cargo test` unit suites, vox-vscode TextMate
grammar.

**Spec:** `docs/plans/310_user_defined_structures.md` (APPROVED in full).
The spec is the authority on semantics; this plan sequences the work.
The showcase file mirrors it with runnable-shaped examples.

## Global Constraints

- **All new Vox must read aloud as English** — see `docs/STYLE.md`
  (branch `docs/style-guide`, commit `6e513b8`), models
  `examples/cat.vox`, `pi.vox`, `controller.vox`. Names must be the
  thing's true name: `pi` and `x`-as-a-coordinate are correct because
  they ARE the names; `i`, `tmp`, `tns`, `buf`, `st`, `p`, `r66`,
  `SafetyGate2` are placeholders, abbreviations, and mangles, banned at
  any length. Use quoted multi-word names freely. This applies to every
  test fixture, example, and library file in this plan, and name review
  is part of each task's acceptance gate.

- **Branch:** work on `feature/user-defined-things`, branched from
  `docs/structures-design` (so the spec travels with the code). Never
  commit to main. Signed commits (config set; if pinentry blocks, retry
  once, then stop and report — never disable signing).
- **`VOX_CORE_PATH` must point at the repo's `coreasm`** for every
  manual vox invocation; `test.sh:76` already sets it. An installed
  `/usr/share/vox/coreasm` silently shadows the repo copy otherwise
  (see `docs/INSTALL.md`).
- **Gate:** `cargo build --release` with zero warnings, `./test.sh`
  fully green, `cargo test` green, `vox-vscode` drift check green —
  before every commit.
- **Definitions precede use.** A thing must be defined earlier in the
  program (or in a `see`n file already parsed) than any use of its name.
- **One identifier space:** type names, variable names, function names
  never collide; second definition errors at its own line, pointing at
  the first.
- **`thing` and `do` are keywords only inside their own constructs**
  (the `send` lookahead treatment, `src/parser/statements.rs:16-27` is
  the model); everywhere else they are ordinary identifiers.
- **No runtime machinery.** Every offset, size, copy, comparison, and
  print sequence is emitted inline at compile time.
- **Test numbering:** integration tests start at `tests/330_*`; if the
  in-flight `fix/reserved-word-loop-variable-diagnostic` branch claims
  328/329, that is fine — start at 330 regardless. Never-compiling
  shapes go in `src/compile_fail_tests.rs` following its existing
  pattern.
- Any pre-existing compiler bug uncovered while testing is a dogfood
  finding: report it to the master, do not fix it in this branch.

## File Structure

- `src/parser/ast.rs` — `ThingDef`, `FieldDef`, new `Statement` /
  `Expr` variants; `Program.things: Vec<ThingDef>`.
- `src/parser/things.rs` (new) — definition parsing, manifest entries,
  wrong-shape diagnostics. Keeps `declarations.rs` focused.
- `src/parser/declarations.rs` — extend `try_parse_type_noun` with
  registry lookup so `a point called origin` parses.
- `src/parser/expressions.rs` — field-chain possessive resolution, type
  possessive (`a point's F`), member-call parsing.
- `src/parser/statements.rs` — `To do` dispatch lookahead; `Set` on
  field chains.
- `src/analyzer/things.rs` (new) — registry validation: cycles, sizes,
  offsets, manifest both-way checks, member Return-type rule, collision
  space.
- `src/codegen/things.rs` (new) — layout, field address computation,
  copy emission, print emission, equality emission.
- `src/codegen/vars.rs` — sized `resb` allocation for thing globals;
  stack allocation for locals.
- `LANGUAGE.md`, `CHANGELOG.md`, `vox-vscode/` — final tasks.

---

### Task 1: ThingDef registry and definition parsing

**Files:**
- Create: `src/parser/things.rs`
- Modify: `src/parser/ast.rs` (add types below), `src/parser/mod.rs`
  (module + registry field), `src/parser/statements.rs` (dispatch)
- Test: `tests/330_thing_definition.vox` + `.expected`,
  `src/compile_fail_tests.rs`

**Interfaces:**
- Produces (later tasks depend on these exact shapes):

```rust
// ast.rs
#[derive(Debug, Clone)]
pub struct ThingDef {
    pub name: String,
    pub fields: Vec<FieldDef>,          // data fields only, in order
    pub members: Vec<String>,           // manifest function names
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub field_type: Type,               // scalar Type or Type::Thing(name)
    pub default: Option<Expr>,          // literal default, if given
}

// Type gets one new variant:
Type::Thing(String)
```

- `Parser` gains `things: HashMap<String, ThingDef>` (populated during
  parse; definitions precede use makes single-pass work), and `Program`
  gains `pub things: Vec<ThingDef>`.

- [ ] **Step 1: Write the failing integration test**

`tests/330_thing_definition.vox`:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

A thing called 'bounding box' has
  a number called width is 1,
  a number called height is 1.

a 'bounding box' called viewport.
Print viewport's width.

Print "defined".

a number called thing is 42.
Print thing.
```

`tests/330_thing_definition.expected`:

```
1
defined
42
```

(The quoted multi-word name exercises `parse_name()` in both the
definition and the declaration position — if declaration-position
support must wait for Task 2, move those two lines into
`tests/331_thing_declare_access.vox` and note it in the commit.)

(The tail proves `thing` stays an ordinary identifier outside the
construct.)

- [ ] **Step 2: Run to verify it fails**

Run: `./test.sh tests/330_thing_definition.vox`
Expected: COMPILE FAIL (parser rejects `A thing called ... has`).

- [ ] **Step 3: Implement definition parsing**

In `parse_typed_var_decl` (`src/parser/declarations.rs:430`), before
`try_parse_type_noun`: if the current token is the identifier `thing`
(case-insensitive) AND the sentence shape ahead is `called <name> has`,
delegate to `parse_thing_definition()` in the new `src/parser/things.rs`.
Use one-token-ahead checks in the style of `signal_keyword_follows`
(`src/parser/statements.rs:16`). The definition parser:

- reads the name (bare or quoted, `parse_name()`), rejects duplicates in
  the one identifier space (error names the first definition's line);
- expects `has`, then a comma-separated list of entries, each either
  `a/an <type-noun-or-thing-name> called <name> [is <literal>]` (field)
  or `a function called <name>` (manifest entry);
- ends at the construct's normal termination (period rules);
- registers the `ThingDef` in `self.things` and emits
  `Statement::ThingDecl(ThingDef)` into the program.

Wrong-shape diagnostics (spec §10), each a targeted error naming the
canonical form (model: the retired-`see` diagnostics):
- `Create a thing called X.` → "a thing is defined, not created: write
  `A thing called X has <fields>.`"
- `A thing called X is ...` → "`is` declares a variable; a thing
  definition uses `has`."
- `A thing called X has.` with zero fields → "a thing needs at least
  one field."

- [ ] **Step 4: Add the compile-fail cases**

In `src/compile_fail_tests.rs`, following its existing pattern, add
cases asserting each diagnostic above fires with its message, plus:
duplicate thing name; `a point called point.` (one identifier space —
if declarations are Task 2 territory, mark this one `#[ignore]` with a
comment and enable it in Task 2).

- [ ] **Step 5: Run tests**

Run: `./test.sh tests/330_thing_definition.vox && cargo test compile_fail`
Expected: PASS.

- [ ] **Step 6: Full gate, then commit**

```bash
cargo build --release 2>&1 | grep -c warning   # expect 0
./test.sh && cargo test
git add -A && git commit -m "feat(things): thing definitions parsed into a registry with targeted wrong-shape diagnostics"
```

---

### Task 2: Declarations, storage, and field access (with nesting)

**Files:**
- Modify: `src/parser/declarations.rs` (registry lookup in
  `try_parse_type_noun` path), `src/parser/expressions.rs` (field-chain
  possessive), `src/parser/statements.rs` (`Set` on chains),
  `src/analyzer/things.rs` (create: sizes, offsets, cycle check),
  `src/codegen/things.rs` (create: layout + address computation),
  `src/codegen/vars.rs` (sized `resb`)
- Test: `tests/331_thing_declare_access.vox`,
  `tests/332_thing_nesting.vox`, `src/compile_fail_tests.rs`

**Interfaces:**
- Consumes: `ThingDef`, `Type::Thing` (Task 1).
- Produces:
  - analyzer: `fn thing_size(&self, name: &str) -> u64` (bytes;
    scalars 8, nested things their own size) and
    `fn field_offset(&self, thing: &str, path: &[String]) -> u64` —
    both pure compile-time lookups used by codegen.
  - Cycle detection: DFS over field types; a cycle is a compile error at
    the definition that closes it, message naming the chain
    ("ouroboros contains ouroboros").
  - Expr variant `Expr::ThingField { base: String, path: Vec<String> }`
    for reads; `Statement::SetThingField { base, path, value }` for
    writes. Globals allocate `resb <size>` via the existing
    sorted-label machinery in `collect_global_var_labels`
    (`src/codegen/vars.rs`); locals extend `stack_offset` by the size.

- [ ] **Step 1: Write the failing tests**

`tests/331_thing_declare_access.vox`:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

a point called origin.
Set origin's x to 3.
Set origin's y to 4.
Print origin's x.
origin's y is origin's y add 1.
increment origin's x.
Print origin's y.
Print "origin sits at {origin's x}, {origin's y}".
If origin's x is greater than 3 then,
    Print "x grew".

Create a point called elsewhere.
Print elsewhere's x.
```

`.expected`:

```
3
5
origin sits at 4, 5
x grew
0
```

`tests/332_thing_nesting.vox`:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

A thing called segment has
  a point called start,
  a point called end.

A thing called route has
  a segment called leg,
  a number called id.

a route called 'route 66'.
Set 'route 66''s leg's start's x to 3.
Print 'route 66''s leg's start's x.
increment 'route 66''s leg's end's y.
Print 'route 66''s leg's end's y.
```

`.expected`:

```
3
1
```

- [ ] **Step 2: Run to verify both fail**

Run: `./test.sh tests/331_thing_declare_access.vox tests/332_thing_nesting.vox`
Expected: COMPILE FAIL (`point` unknown in declaration position).

- [ ] **Step 3: Implement**

Parser: where `try_parse_type_noun` returns `None`, check
`self.things.contains_key(word)` → `Type::Thing(name)`; declaration then
proceeds exactly as builtins do (including the `Create a X called Y`
form, which reuses this same path). Field defaults come from the
`ThingDef` (recursively for nested things; unset fields zero).
Possessive chains parse where `ObjectProperty` resolution
(`src/parser/expressions.rs:830` area) fails but the base is a
`Type::Thing` variable: consume `'s <field>` repeatedly while the
current type is a thing and the name matches a field.

Analyzer: build sizes/offsets; run the cycle DFS; unknown field in a
chain errors naming the thing and listing its fields.

Codegen: `resb thing_size` for globals; stack for locals; loads/stores
at `base_address + field_offset` — mimic how buffer field access emits
addresses. Format strings and comparisons need no new work once
`Expr::ThingField` evaluates to a value in rax (scalar fields only in
chains' final position; a chain ending on a nested thing is only legal
under Task 3's copy or Task 6's print).

- [ ] **Step 4: Compile-fail cases**

Enable/add: `a point called point.` (one space); `Set origin's z to 1.`
(unknown field, message lists x, y); the `ouroboros` cycle:

```
A thing called ouroboros has
  an ouroboros called tail.
```

- [ ] **Step 5: Run tests, full gate, commit**

```bash
./test.sh && cargo test && cargo build --release 2>&1 | grep -c warning
git add -A && git commit -m "feat(things): declarations, sized storage, chained field access, cycle detection"
```

---

### Task 3: Value semantics — copy on assign, pass, and return

**Files:**
- Modify: `src/parser/declarations.rs` (initializer form),
  `src/parser/statements.rs` (`Set <var> to <thing-expr>`),
  `src/analyzer/things.rs`, `src/codegen/things.rs` (copy emission)
- Test: `tests/333_thing_copy.vox`, `tests/334_thing_params.vox`

**Interfaces:**
- Consumes: sizes/offsets (Task 2).
- Produces: `emit_thing_copy(dst_addr, src_addr, size)` — inline
  `rep movsb` (or unrolled moves for small sizes); used by assignment,
  parameter passing, and returns. Functions with `Type::Thing` params
  receive a copy in their frame; `Return a point, out.` copies into a
  caller-provided slot.

- [ ] **Step 1: Write the failing tests**

`tests/333_thing_copy.vox`:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

a point called origin.
Set origin's x to 5.
a point called moved is origin.
Set moved's x to 9.
Print origin's x.
Print moved's x.
```

`.expected`: `5` then `9`.

`tests/334_thing_params.vox`:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

To nudged with a point called start.
  Set start's x to start's x add 1.
  Return a point, start.

a point called before.
The after is nudged of before.
Print before's x.
Print after's x.
```

`.expected`: `0` then `1`.

(Note `The after is ...` — declaration by inference rides along here
because return-type tracking already exists for builtins; if it demands
separate wiring, split it into its own commit within this task.)

- [ ] **Step 2: Run to verify both fail** (`./test.sh tests/333... tests/334...`)

- [ ] **Step 3: Implement copy emission and the three call paths**

Follow how buffers/values pass today to find the parameter-frame
conventions; a thing parameter reserves `thing_size` in the callee frame
and copies on entry. Same-type check on assignment: `a point called moved is
q.` where `q` is a vector3 errors naming both types.

- [ ] **Step 4: Compile-fail case** — cross-type assignment.

- [ ] **Step 5: Gate and commit**

```bash
./test.sh && cargo test
git add -A && git commit -m "feat(things): value semantics - copy on assign, pass, and return; The-inference for thing returns"
```

---

### Task 4: Instance possessive sugar

**Files:**
- Modify: `src/parser/expressions.rs` (possessive call resolution:
  field first, then function-with-matching-first-param),
  `src/analyzer/things.rs` (member-space collisions)
- Test: `tests/335_instance_sugar.vox`, `src/compile_fail_tests.rs`

**Interfaces:**
- Consumes: `Expr::ThingField` resolution order (Task 2).
- Produces: possessive resolution rule — on `X's name`: if `name` is a
  field of X's type → field access; else if a function exists whose
  first parameter is X's type → rewrite to a call with X as first
  argument, remaining args after any call preposition (`of/on/with/to`).
  Collision space per spec §4: fields + declared members + global
  functions with matching first param; duplicates error at the second
  definition site.

- [ ] **Step 1: Write the failing test**

`tests/335_instance_sugar.vox`:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

To magnitude with a point called corner.
  a number called 'x squared' is corner's x multiply corner's x.
  a number called 'y squared' is corner's y multiply corner's y.
  Return a number, 'x squared' add 'y squared'.

To 'scaled by' with a point called corner and a number called factor.
  a point called out.
  Set out's x to corner's x multiply factor.
  Set out's y to corner's y multiply factor.
  Return a point, out.

a point called origin.
Set origin's x to 3.
Set origin's y to 4.
Print magnitude of origin.
Print origin's magnitude.
The bigger is origin's 'scaled by' on 3.
Print bigger's x.

a point called 'the point in question'.
Set 'the point in question''s x to 7.
Print 'the point in question''s magnitude.
```

`.expected`: `25`, `25`, `9`, `49`.

- [ ] **Step 2: Run to verify it fails**

- [ ] **Step 3: Implement** the resolution order above as a compile-time
rewrite (no new codegen — the rewritten AST is an ordinary call).

- [ ] **Step 4: Compile-fail case** — `To x with a point called corner.` when
point has a field `x` (collision at the function's line, pointing at the
field).

- [ ] **Step 5: Gate and commit**

```bash
./test.sh && cargo test
git add -A && git commit -m "feat(things): instance possessive sugar with member-space collision checks"
```

---

### Task 5: Manifest members — `To do the point's`, type possessive calls

**Files:**
- Modify: `src/parser/things.rs` (`To do` dispatch + definition form),
  `src/parser/statements.rs` (lookahead: `do` + `the <thing>'s`),
  `src/parser/expressions.rs` (type possessive call `a <thing>'s F`),
  `src/analyzer/things.rs` (both-way manifest checks, member Return
  rule)
- Test: `tests/336_manifest_members.vox`, `src/compile_fail_tests.rs`

**Interfaces:**
- Consumes: manifest names in `ThingDef.members` (Task 1).
- Produces: member functions compiled under mangled internal names
  (follow the existing mangling in `src/codegen/mangling.rs`) so
  `point`'s and `vector3`'s `'from polar'` coexist. Call forms: type
  possessive (`a point's F with args`) for all members; instance
  possessive additionally when the member's first param is the owner.

- [ ] **Step 1: Write the failing test**

`tests/336_manifest_members.vox`:

```
A thing called point has
  a function called 'from polar',
  a function called reflected,
  a number called x is 0,
  a number called y is 0.

To do the point's 'from polar', with a float called r and a float called theta.
  a point called out.
  Set out's x to 1.
  Return a point, out.

To do the point's reflected, with a point called corner.
  a point called out.
  Set out's x to 0 minus corner's x.
  Set out's y to 0 minus corner's y.
  Return a point, out.

A thing called vector3 has
  a function called 'from polar',
  a number called x,
  a number called y,
  a number called z.

To do the vector3's 'from polar', with a float called r and a float called theta.
  a vector3 called out.
  Set out's z to 7.
  Return a vector3, out.

The unit is a point's 'from polar' with 1.0 and 0.0.
Print unit's x.
The mirrored is unit's reflected.
Print mirrored's x.
The mirrored2 is a point's reflected of unit.
Print mirrored2's x.
The v is a vector3's 'from polar' with 2.0 and 1.0.
Print v's z.
```

`.expected`: `1`, `-1`, `-1`, `7`.

- [ ] **Step 2: Run to verify it fails**

- [ ] **Step 3: Implement.** `To do` lookahead mirrors
`signal_keyword_follows`; `do` stays an ordinary identifier elsewhere
(regression case: a user function named `do`, called bare — add to the
integration test if it fits, else compile-fail file). The comma before
the parameter list follows the `Return a number,` payload-comma
precedent. Type possessive in expressions: `a <thing-name>'s <fn>` —
distinguish from declarations by the `'s` vs `called` token, one token
of lookahead.

- [ ] **Step 4: Compile-fail cases** (spec §10):
- `To do the point's sparkle, ...` with no manifest entry → "point does
  not declare sparkle — add `a function called sparkle` to the type".
- A manifest entry nothing defines → error at the type: "point declares
  'never written' but nothing defines it".
- **Member Return rule:** `To do the point's broken, ...` whose body
  ends `Return a vector3, out.` → error naming the `To do` line and the
  `Return` line: every declared member must return its owner.
- Duplicate definition of the same member.

- [ ] **Step 5: Gate and commit**

```bash
./test.sh && cargo test
git add -A && git commit -m "feat(things): manifest members, To-do definitions, type-possessive calls, both-way manifest checks"
```

---

### Task 6: Printing and equality (recursive)

**Files:**
- Modify: `src/codegen/things.rs`, `src/codegen/print.rs` (dispatch),
  `src/analyzer/expressions.rs` (equality typing)
- Test: `tests/337_thing_print_eq.vox`

**Interfaces:**
- Consumes: field metadata + offsets (Task 2).
- Produces: `Print <thing>` emits `{x: 5, y: 0}` — fields in definition
  order, recursing into nested things, skipping function members;
  format-string `{p}` reuses the same emission. `a is b` on same-type
  things expands to per-field comparisons (recursive); cross-type
  comparison and ordering comparisons are compile errors.

- [ ] **Step 1: Write the failing test**

`tests/337_thing_print_eq.vox`:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

A thing called segment has
  a point called start,
  a point called end.

a point called origin.
Set origin's x to 5.
Print a.

a segment called s.
Set s's end's y to 2.
Print s.

a point called c.
Set c's x to 5.
If a is c then,
    Print "equal".
Set c's y to 9.
If a is c then,
    Print "SHOULD NOT PRINT".
Print "done".
```

`.expected`:

```
{x: 5, y: 0}
{start: {x: 0, y: 0}, end: {x: 0, y: 2}}
equal
done
```

- [ ] **Step 2: Run to verify it fails**

- [ ] **Step 3: Implement** print emission (mimic how maps print
`{"k": v}`; things use unquoted field names) and equality expansion.

- [ ] **Step 4: Compile-fail cases** — `a is v` cross-type;
`a is greater than c` ordering on things.

- [ ] **Step 5: Gate and commit**

```bash
./test.sh && cargo test
git add -A && git commit -m "feat(things): recursive map-style printing and field-wise equality"
```

---

### Task 7: Cross-file things and the diagnostics sweep

**Files:**
- Modify: `src/parser/things.rs` (see-included definitions land in the
  same registry — likely free, verify), diagnostics polish across
  parser/analyzer
- Test: `tests/338_thing_see.vox` + `tests/fixtures/geometry.vox`,
  `src/compile_fail_tests.rs`

- [ ] **Step 1: Write the failing test**

`tests/fixtures/geometry.vox`:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.
```

`tests/338_thing_see.vox`:

```
see "./fixtures/geometry.vox".

a point called origin.
Set origin's x to 11.
Print origin's x.
```

`.expected`: `11`. (Confirm `test.sh`'s working directory lets the
relative `see` resolve; adjust the fixture path to match how existing
`see` tests do it — check for one first with `grep -l '^see' tests/`.)

- [ ] **Step 2: Run, verify state** — this may already pass once parsing
is registry-based; if so record that in the commit message rather than
forcing a failure.

- [ ] **Step 3: Diagnostics sweep** — verify every spec-§10 diagnostic
exists with its message; extend the unknown-type error to suggest
near-miss user thing names (reuse the existing near-miss machinery if
the repo has one — search for "did you mean"; if none exists, a
prefix/edit-distance suggestion over registry keys, ≤2 edits).

- [ ] **Step 4: Gate and commit**

```bash
./test.sh && cargo test
git add -A && git commit -m "feat(things): cross-file definitions via see; diagnostics sweep with near-miss suggestions"
```

---

### Task 8: LANGUAGE.md chapter, CHANGELOG, vox-vscode

**Files:**
- Modify: `LANGUAGE.md` (new "Things" chapter + Types table row + TOC),
  `CHANGELOG.md` (unreleased entry), `vox-vscode` grammar + aliases
- Test: the vox-vscode drift check; `docs/check-samples.sh` if it
  validates LANGUAGE.md examples (check its header)

- [ ] **Step 1: Write the LANGUAGE.md chapter.** Cover, with runnable
examples mirroring the tests: definition + defaults; manifest members
and the **article rule** ("a/an" pairs with types and values coming into
being, "the" with known identifiers); declarations (all forms);
field access incl. chains; nesting + the cycle error; value copy
semantics; the three call forms; the member-must-return-owner rule;
printing; equality; the one identifier space; every §10 diagnostic with
its message. Restate the sentence-consumption interaction for multi-line
definitions. Update the Types table and type-predicate section note
(user things are not in the runtime tag system in v1).

- [ ] **Step 2: vox-vscode.** Add `thing`/`To do` keywords AND the
positional type highlighting: in `a/an <word> called`, `a <word>'s`, and
`To do the <word>'s`, scope `<word>` as a type (`storage.type` or the
grammar's existing type scope) so user things highlight like builtins.
Run the drift check; keep it green.

- [ ] **Step 3: CHANGELOG entry** under the unreleased heading,
following its established voice.

- [ ] **Step 4: Full gate one last time, commit**

```bash
./test.sh && cargo test && (cd vox-vscode && <drift check command from its package.json>)
git add -A && git commit -m "docs(things): LANGUAGE.md chapter, changelog, vscode grammar with positional type highlighting"
```

---

## Execution notes for the master

- Worker assignment per the delegation policy: Tasks 1, 2, and 5 are the
  subtle parser/analyzer work (sentence-shape lookaheads, possessive
  chain resolution, manifest checking) — Opus 5 agent-workers. Tasks 3,
  4, 6 are pattern-following codegen — Ollama vox-workers with Opus
  escalation if frame conventions bite. Tasks 7–8 — Ollama vox-workers.
- Review gate between every task; a task is accepted only with the full
  gate green and the diff read.
- Red-team pass after Task 6: attack copy semantics (aliasing via
  chains), the cycle detector (long cycles, self-via-two-hops), and the
  one-identifier-space rule, with runnable reproductions.
