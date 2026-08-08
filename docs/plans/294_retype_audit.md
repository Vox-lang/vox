# Plan 294 — retype audit, and implementation checklist for type immutability

**Status:** audit only. **No `src/` changes.** A separate worker owns `src/`
and is implementing the type-immutability rule; another is fixing Bug B.

**Tree:** branch `retype-audit`, base `409bd2c`.

This document has two jobs:

1. **Findings** — every place the compiler's tracked type disagrees with the
   variable's actual runtime type. 18 findings, each with a runnable
   reproduction under `tests/retype_audit_pocs/`.
2. **Implementation checklist** — every site where a variable can be bound,
   assigned, or have its type inferred, for the team enforcing the new rule
   that **a variable's type is fixed at its declaration**.

## Baseline

Recorded before any work. All three match the expected numbers.

| check | result |
|---|---|
| `cargo build --release` | clean, **0 warnings** |
| `cargo test --release` | **189 passed / 0 failed** (174 + 7 + 4 + 3 + 1) |
| `./test.sh` | **219 passed / 0 failed / 6 skipped** (total 225) |
| `git status` | clean |

---

## Headline — the rule closes 9 of 18 findings; 9 survive it

This is the part worth reading first. Under the new rule (type fixed at
declaration; a type-changing assignment becomes a compile error pointing at an
explicit cast; `Type::Value`/`VarType::Mixed` remains the sanctioned dynamic
type), the findings split cleanly:

**Closed by the rule (9)** — findings 1, 6, 7, 8, 9, 10, 11, 13, 16.

All the flow-insensitivity findings are in this group, and they are closed
*elegantly*: if no assignment may change a variable's type, then the tracked
type never changes after declaration, so it cannot drift out of agreement with
runtime regardless of which branch executed. **Flow-insensitivity stops
mattering because there is nothing left for it to get wrong.** That is the
single strongest technical argument for the rule.

**Survives the rule (9)** — findings 2, 3, 4, 5, 12, 14, 15, 17, 18.

These survive because **the rule constrains assignment, and these are not
assignments.** They are: other statements that rebind a name (loop variables,
`open ... called`, `Allocate`), operations that ignore the type rather than
change it (`Increment`/`Decrement`), reads whose type cannot be inferred (map
values), scope machinery that never restores an outer type (nested
shadowing), and the genuinely dynamic case (heterogeneous list iteration).

Two structural reasons underlie the whole "survives" column, and both need a
deliberate decision:

- **A binding is not the same thing as an assignment.** Six statement forms
  put a new runtime value into an existing name without going through
  `Statement::Assignment`. If enforcement is added only to the assignment
  path, all of them still produce the same segfaults they do today.
- **Some types genuinely cannot be fixed.** Map value types are *never*
  inferred anywhere in the compiler (`Type::Map(Box::new(Type::Unknown))` at
  `src/analyzer/mod.rs:1315`, `1547`, `1761`, `1768`), and a heterogeneous
  list's elements differ per iteration. For these, "fixed type" is the wrong
  answer and the `value`/Mixed mechanism is the right one.

There is also a trap in the *closed* column: findings 1, 13 and 16 are closed
**only if enforcement is placed on the `VarDecl { var_type: None }`
re-declaration path**, which is precisely the path that currently forgets to
update the type at all. Enforcing on `Statement::Assignment` alone leaves
`Set`/`Store`/`Assign`/`Create` still segfaulting.

---

## Findings

Severity is by runtime consequence. PoC directory numbering matches this
order. Every `poc.sh` **exits 0 if and only if the bug is present**, so it
flips to non-zero once fixed. Run them all:

```bash
cd tests/retype_audit_pocs
for d in [0-9]*/; do ./"$d"/poc.sh >/dev/null 2>&1 && echo "BUG PRESENT $d" || echo "fixed/absent $d"; done
```

Both directions of that contract were verified, not assumed: a
`poc_expect_segv` script run against a healthy program exits 1
(`NOT REPRODUCED: exit=0 output=[abc]`), and a `poc_expect_not` script run
against correct output exits 1. Exit 3 is reserved for "could not run the
experiment" so infrastructure failure never reads as "bug present".

| # | sev | construct | consequence | under the new rule |
|---|---|---|---|---|
| 1 | **crit** | `Set X to <number>` where `X` is text | SIGSEGV | **closed** *if enforced on the `VarDecl{None}` path* |
| 2 | **crit** | for-range loop variable reusing a text name | SIGSEGV | **SURVIVES** — a binding, not an assignment |
| 3 | **crit** | `open a file ... called X` over a text name | SIGSEGV | **SURVIVES** — a binding, not an assignment |
| 4 | **crit** | text variable assigned a numeric map value | SIGSEGV | **SURVIVES** — map value types are never inferred |
| 5 | **crit** | `Increment` on a text variable | pointer walk → SIGSEGV | **SURVIVES** — no type change, an invalid operation |
| 6 | **crit** | assignment in an untaken `If` branch | SIGSEGV (Bug A) | **closed** |
| 7 | **crit** | assignment in an untaken `Otherwise` branch | SIGSEGV | **closed** |
| 8 | **crit** | assignment in a `While` body that never runs | SIGSEGV | **closed** |
| 9 | **crit** | assignment in a `Repeat 0 times` body | SIGSEGV | **closed** |
| 10 | **crit** | assignment in a for-range body over an empty range | SIGSEGV | **closed** |
| 11 | **crit** | assignment in an `on error` handler that never fires | SIGSEGV | **closed** |
| 12 | **crit** | *declaration* in an untaken branch | SIGSEGV | **SURVIVES** — needs real nested-scope shadowing |
| 13 | **high** | `Set X to <text>` where `X` is a number (Bug B) | pointer as integer | **closed** *same caveat as 1* |
| 14 | **high** | number variable assigned a text map value | pointer as integer | **SURVIVES** — map value types are never inferred |
| 15 | **high** | `Decrement` on a text variable | out-of-bounds read | **SURVIVES** — no type change, an invalid operation |
| 16 | **med** | arithmetic after `Set` retypes a text variable | spurious compile error | **closed** by redefinition |
| 17 | **low** | `Allocate N for X` over a text name | stale text tracking | **SURVIVES** — a binding, not an assignment |
| 18 | **high** | arithmetic on a for-each variable over a *heterogeneous* list | pointer as integer | **SURVIVES** — this is the Mixed case |

### 1 — critical — `Set X to <number>` on a text variable

```vox
a text called s is "hello".
Set s to 5.
Print "{s}".
```

Observed **SIGSEGV, exit 139**; expected `5`.

This is Bug B's root cause in the memory-unsafe direction, and it is why Bug B
should not be filed as merely "silently wrong output".
`Set`/`Store`/`Assign`/`Create` do **not** parse to `Statement::Assignment`.
They route through `Token::Set => self.parse_var_decl()`
(`src/parser/mod.rs:944`; `Create` at `:972`) and exit at
`src/parser/mod.rs:1453` as `Statement::VarDecl { var_type: None }` — a
*re-declaration* carrying no declared type.

Both consumers then skip their type update, because both guard on the declared
type being present:

- analyzer `src/analyzer/mod.rs:1987` — `if let Some(vt) = var_type`, so with
  `None` neither the insert at 1994/2002 nor the remove at 2004 runs.
- codegen `src/codegen/mod.rs:2696` — `if let Some(ref t) = var_type`, so the
  insert at 2711 does not run. The value-driven fallbacks at 2718-2786 do not
  cover a bare literal: a `StringLit` only inherits a type when it names an
  existing variable (2776).

The runtime store happens regardless, so the slot holds an integer while
`variable_types[s]` still says `String`. `resolve_format_variable`
(`src/codegen/mod.rs:664-725`, reading `variable_types` at 703/706) emits a
string-pointer dereference against the raw integer `5`.

All four spellings confirmed: `Set`, `Store`, `Assign` (all lex to `Token::Set`
at `src/lexer/mod.rs:773`) and `Create`. **Verify any fix against all four.**

> **Under the new rule:** closed — the assignment changes the type, so it
> becomes a compile error. **But only if the check is placed on the
> `VarDecl { var_type: None }` path.** This path is invisible to any
> enforcement written against `Statement::Assignment`, and it is the one that
> currently segfaults.

### 2 — critical — for-range loop variable reusing a text name

```vox
a text called i is "hello".
For each i from 1 to 3,
  Print "in {i}".
```

Observed: prints `in ` then **SIGSEGV**; expected `in 1 / in 2 / in 3`.

**The two maps disagree with each other.** The analyzer *does* retype the loop
variable to `Integer` (`src/analyzer/mod.rs:2151`), but codegen's
`Statement::ForRange` arm (`src/codegen/mod.rs:3032-3069`) **never writes
`variable_types` at all** — it allocates the slot and emits the counter, and
that is it. Its siblings do: the for-each-over-arguments path inserts `String`
(`:3410`) and the for-each-over-list path inserts the element type (`:3520`).

Because the analyzer is correct here, nothing can be flagged at compile time —
the defect is entirely inside codegen.

> **Under the new rule:** **survives.** Binding a loop variable is not an
> assignment, so no assignment check sees it. Enforcement must either reject
> reusing a text name as a numeric loop variable, or give the loop variable
> its own scoped binding that shadows the outer name (and restores it on
> exit). Either way codegen's `ForRange` arm has to start recording a type,
> which it does not do today at all.

### 3 — critical — `open a file ... called X` over a text name

```vox
a text called src is "hello".
open a file for reading called src at "/etc/hostname".
Print "[{src}]".
```

Observed: prints `[` then **SIGSEGV**.

`FileOpen` stores a file descriptor into the named slot. Neither side clears
the stale text label: the analyzer (`src/analyzer/mod.rs:2563-2569`) inserts
into `variables` and `file_variables` but never touches `scalar_types`, and
codegen's arm (`src/codegen/mod.rs:3974+`) contains no `variable_types` write
at all (verified by grep over its range). `variable_types[src]` stays `String`
and the fd is dereferenced as a `char*`.

> **Under the new rule:** **survives**, for the same reason as finding 2 —
> `open ... called X` is a binding site, not an assignment. It must either
> reject rebinding a name already declared as text, or be treated as a
> declaration of a `file`-typed variable.

### 4 — critical — text variable assigned a numeric map value

```vox
a map called m is {"k": 42}.
a text called s is "hello".
s is m's "k".
Print "[{s}]".
```

Observed: prints `[` then **SIGSEGV**; expected `[42]`.

The analyzer takes the `None` arm and *removes* the label
(`src/analyzer/mod.rs:2084-2086`) — correct and conservative. Codegen's
`Assignment` arm only overwrites `variable_types` when `infer_expr_type`
returns `Some` (`src/codegen/mod.rs:2922`); a map access infers to
`Unknown`, and `VarType::Unknown` is an explicit no-op at
`src/codegen/mod.rs:2931`. The stale `String` survives.

> **Under the new rule:** **survives.** The rule says a type-changing
> assignment is an error — but the compiler cannot tell that this assignment
> changes the type, because **no map is ever given a value type**:
> `Type::Map(Box::new(Type::Unknown))` is constructed at
> `src/analyzer/mod.rs:1315`, `1547`, `1761` and `1768`, and nothing ever
> refines it. See "where a fixed type is the wrong answer" below.

### 5 — critical — `Increment` on a text variable

```vox
a text called s is "hi".
Repeat 200000 times,
  Increment s.

Print "[{s}]".
```

Observed: **SIGSEGV.**

`Increment` emits an integer `inc` against a slot holding a string pointer,
with no check that the tracked type is numeric. The pointer is walked forward
one byte at a time with no relationship to the string's bounds; enough
iterations leave the mapping. A single `Increment s.` on `"hello"` prints
`ello` — the same defect, one byte in, which is how to recognise it in the
wild.

> **Under the new rule:** **survives, and is not addressed by it at all.**
> Tracking here is *correct* — `s` really is text and stays text. The rule
> governs what may change a type; this is an operation that ignores the type.
> `Increment`/`Decrement` need their own numeric-target check. The machinery
> exists and produces good messages already (finding 16 shows arithmetic
> rejecting a text operand), so this is cheap and independent of the rework.

### 6-11 — critical — flow-insensitive tracking across every non-linear path

Six findings, one root cause, differing only in the construct that creates the
unexecuted path. Finding 6 is Bug A, analysed in
`docs/plans/293_flow_insensitive_type_confusion_followup.md` and not repeated
here. The point of 7-11 is **blast radius**: it is not an `If` bug.

| # | construct | repro shape |
|---|---|---|
| 6 | `If` branch not taken | `If g is equal to 1,` with `g` = 0 |
| 7 | `Otherwise` branch not taken | `If g is equal to 1,` with `g` = 1 |
| 8 | `While` body never entered | `While g is equal to 1,` with `g` = 0 |
| 9 | `Repeat 0 times` | count is 0 |
| 10 | for-range over an empty range | `For each k from 1 to 0,` |
| 11 | `on error` handler, no error | the `open` succeeds |

All six go through the analyzer's `Assignment` arm
(`src/analyzer/mod.rs:2080-2087`) and codegen's
(`src/codegen/mod.rs:2922-2933`). The mechanism: `scalar_types` and
`variable_types` are flat `HashMap`s with no branch discipline.
`Statement::If` in the analyzer (`src/analyzer/mod.rs:2091-2136`) *does*
carefully snapshot, branch and merge — but only `AnalysisEnv`, which tracks
**variable availability**, not types. Types ride straight through the merge
untouched. `While`, `ForRange`, `ForEach` and `Repeat` (2138-2183) do not even
snapshot.

> **Under the new rule:** **all six closed.** No assignment may change a
> type, so the tracked type never diverges from the declared one and
> flow-sensitivity becomes unnecessary for *this* purpose. Note it is still
> needed for variable *availability*, which the existing `AnalysisEnv` merge
> already handles correctly.

### 12 — critical — a declaration in an untaken branch

```vox
a number called n is 5.
If 1 is equal to 2,
  a text called n is "abc".

Print "outer [{n}]".
```

Observed: prints `outer [` then **SIGSEGV**; expected `outer [5]`.

A **distinct code path** from findings 6-11: this goes through the `VarDecl`
arms (`src/analyzer/mod.rs:2002`, `src/codegen/mod.rs:2711`), not the
assignment arms.

The related *taken*-branch case shows why this is really a scoping problem:
with `1 is equal to 1`, the inner declaration overwrites the outer `n`
entirely and `Print` after the block yields `abc`. There is no separate slot
and no restore on scope exit.

> **Under the new rule:** **survives.** Everything depends on a decision the
> rule does not make: is an inner `a text called n` a *re-declaration* of the
> outer `n` (→ compile error, since the type differs) or a *shadowing*
> declaration of a new variable (→ legal, but it needs its own slot and the
> outer type must be restored at scope exit)? Today it is neither — it reuses
> the outer slot and permanently changes the outer type. Whichever answer is
> chosen must be implemented; the rule alone does not pick one.

### 13 — high — `Set X to <text>` on a number variable (Bug B)

```vox
a number called n is 5.
Set n to "abc".
Print "{n}".
```

Observed `4198480`; expected `abc` (the plain form `n is "abc".` prints
`abc`). Same root cause as finding 1, benign direction. **A separate worker
owns this fix; this track does not touch it.**

> **Under the new rule:** closed, with finding 1's caveat. Note the rule
> *changes the expected output*: `n is "abc".` on a number stops being legal
> Vox and becomes a compile error too. The premise "reassigning a number to
> text is legal Vox" — true today, and the reason Bug B is a bug rather than
> invalid code — is exactly what the rule repeals.

### 14 — high — number variable assigned a text map value

```vox
a map called m is {"k": "abc"}.
a number called n is 5.
n is m's "k".
Print "{n}".
```

Observed `4198548` (the string's address); expected `abc`. Finding 4's benign
direction, same lines.

> **Under the new rule:** **survives** — identical reasoning to finding 4.

### 15 — high — `Decrement` on a text variable

```vox
a text called s is "hello".
Decrement s.
Print "[{s}]".
```

Observed `[]`; expected `[hello]` or a diagnostic. The pointer is moved to
*before* the start of the string literal and the formatter reads from there.
Here the preceding byte happened to be `0`; what it lands on is a property of
`.rodata` layout, not of the program. Rated high rather than critical only
because a single decrement rarely leaves the page — finding 5 is the same
defect made to crash.

> **Under the new rule:** **survives** — see finding 5.

### 16 — medium — spurious compile error after a `Set` retype

```vox
a text called s is "hello".
Set s to 7.
a number called z is 0.
z is s add 1.
Print "{z}".
```

Observed a **compile error**: `Cannot use text s in arithmetic; cast it first
with 'as a number' or 'as a float'.` At runtime `s` holds `7`, so the
arithmetic is valid; the analyzer rejects it because `scalar_types[s]` is
still `String`.

> **Under the new rule:** **closed by redefinition.** The program becomes
> invalid at line 2 rather than line 4, and the diagnostic moves to the real
> mistake. Worth noting the error message quoted above is already the shape
> the new rule wants — it names the variable and points at the cast syntax.

### 17 — low — `Allocate N for X` over a text name

```vox
a text called p is "hello".
Allocate 100 for p.
Print "{p}".
```

Observed: prints nothing; expected the pointer as a number. The analyzer
correctly drops the label (`src/analyzer/mod.rs:2214`, with a comment saying
why), but codegen's `Allocate` arm never updates `variable_types`, so it stays
`String` and the formatter reads the fresh allocation as a C string.

**Why currently unobservable:** freshly-mapped pages are zero-filled, so the
read terminates on the first byte. It is one allocator change away from
becoming a wild read — if `Allocate` ever serves recycled memory (a free list,
an arena, a bump allocator over reused pages), this same program reads
uninitialised heap until it finds a zero byte.

> **Under the new rule:** **survives** — a binding, not an assignment, exactly
> like findings 2 and 3.

### 18 — high — arithmetic on a for-each variable over a heterogeneous list

```vox
a list called data is [42, "hello"].
For each item in data,
  a number called z is item add 1,
  Print "z={z}".
```

Observed:

```
z=43
z=4198529
```

Expected: either `43` and a meaningful second value, or a diagnostic. The
first iteration is correct arithmetic; the second uses the *address* of
`"hello"` as an integer operand.

**Printing the same variable is correct** — `Print "{item}"` over
`[42, "hello", 3.14]` yields `42 / hello / 3.14`, because the print path
dispatches on the element's runtime tag held in `mixed_tag_slots`. Arithmetic
does not consult that tag at all. That asymmetry is what makes this easy to
miss.

The analyzer *deliberately* clears the loop variable's label
(`src/analyzer/mod.rs:2167`), with a comment explaining the intent: a stale
label from a previous use of the name must not falsely reject arithmetic. That
is right for a homogeneous list and unsound for a heterogeneous one.

> **Under the new rule:** **survives, and it is the case where a fixed type is
> the wrong answer.** See the section below.

---

## Implementation checklist — every site that binds, assigns, or infers a type

This is the exhaustive enumeration for the team enforcing the rule. Ticks are
what the code does **today**.

### A. Statement-level binding sites

| # | site | source | analyzer | codegen | notes for enforcement |
|---|---|---|---|---|---|
| A1 | `VarDecl` with a declared type | `analyzer:1987-2009`, `codegen:2696-2716` | ✅ sets | ✅ sets | the canonical declaration; the rule's anchor point |
| A2 | **`VarDecl` with `var_type: None`** (`Set`/`Store`/`Assign`/`Create`) | `parser:944`, `:972`, `:1453` | ❌ none | ❌ none | **findings 1, 13, 16.** Highest-priority site |
| A3 | `Assignment` (`X is v`, `the X is v`) | `analyzer:2047-2089`, `codegen:2912-2933` | ✅ sets/clears | ✅ sets, no-ops on `Unknown` | the obvious site; the one everyone will patch |
| A4 | `FlagSchemaDecl` | `analyzer:2012-2041`, `codegen:2879-2905` | ✅ checks default | ✅ sets from `FlagValueType` | already type-checks its default |
| A5 | **`ParseFlags`** | `codegen:2907-2910` | ❌ no-op | ❌ **no-op placeholder** | flags are **never parsed at runtime**; becomes a binding site when implemented |
| A6 | `ForRange` loop variable | `analyzer:2151`, `codegen:3032-3069` | ✅ `Integer` | ❌ **nothing** | **finding 2** |
| A7 | `ForEach` loop variable | `analyzer:2167`, `codegen:3520` / `:3410` | ⚠️ clears | ✅ elem type / `String` | **finding 18**; see Mixed discussion |
| A8 | `Repeat` counter | `codegen:3078` | n/a | n/a | counter is internal `_repeat_counter`, **not user-bindable** — no burden |
| A9 | Function parameters | `analyzer:2330`, `codegen:3261` | ✅ + save/restore `2299`/`2349` | ✅ + save/restore `3219`/`3379` | **verified correct**, no leak across functions |
| A10 | `Allocate` | `analyzer:2214`, codegen arm | ✅ clears | ❌ **nothing** | **finding 17** |
| A11 | `Free` | analyzer/codegen | ❌ leaves type | ❌ leaves type | name keeps its type after the memory is gone |
| A12 | `BufferDecl` | `codegen:3587` | ✅ `buffer_variables` | ✅ `Buffer` | |
| A13 | `FileOpen` | `analyzer:2563-2569`, `codegen:3974+` | ⚠️ `file_variables` only | ❌ **nothing** | **finding 3** |
| A14 | `FileRead` / `FileReadLine` | analyzer/codegen | ✅ requires buffer | ✅ | writes *through* a buffer |
| A15 | `TimerDecl` | `codegen:4689` | ✅ | ✅ `Integer` | the `// Track as integer for now` comment is **benign** |
| A16 | `GetTime` | `analyzer:2802`, `codegen:4732` | ✅ `Integer` | ✅ `Integer` | correct on both sides |
| A17 | `ByteSet` / `ElementSet` / `MapSet` / `ListAppend` / `BufferCopy` / `BufferClear` / `BufferResize` | various | write *through* | write *through* | `MapSet`/`ListAppend` store back a **reallocated pointer** (`ast.rs:416-429`) — the slot is rewritten even though the type does not change |
| A18 | `Return` / declared return type | `parser:4282-4318` | ✅ | ✅ `function_return_types` | a top-level `Return` **ends the function body** (`parser:4318-4327`) — intended |

### B. Expression-level type-inference sites

Everything that answers "what type is this value" — `arithmetic_operand_type`
and `infer_simple_expr_type` (analyzer), `infer_expr_type` (codegen).

| site | today | notes |
|---|---|---|
| **`MapAccess`** | ❌ always `Unknown` | `Type::Map(Box::new(Type::Unknown))` at `analyzer:1315`, `1547`, `1761`, `1768`. **Findings 4, 14.** No map anywhere is given a value type |
| `ElementAccess` / `ListAccess` | ✅ via `list_element_types`, `Mixed` when heterogeneous | |
| `ByteAccess` | ✅ integer | verified |
| `FunctionCall` | ✅ via `function_return_types` | verified: `n is mk.` retypes correctly |
| `Argument*` (`ArgumentAt/Name/First/Second/Last`) | ✅ `String` at `codegen:2760-2766` | in the **`VarDecl`** path |
| `ArgumentAll` / `ArgumentRaw` | ✅ `List` of `String` at `codegen:2755-2757` | |
| `EnvironmentVariable*` | ✅ `String` at `codegen:2760-2766` | same arm as `Argument*` |
| `Cast` / `TreatingAs` | ✅ | **the escape hatch the whole rule depends on** — `'42' as a number` |
| `FormatString` | ✅ `String`; buffer destination required (`analyzer:2056`) | |
| `BinaryOp` / `UnaryOp` / `Range` / `ListLit` / `MapLit` | ✅ | |
| `LastError`, `CurrentTime`, `Fork`, `ReapChild`, `FileAvailable`, `DurationCast`, `NothingLit`, `PropertyAccess`, `PropertyCheck`, `TypeCheck` | mixed | statically typed; no retype surface found |

### C. Cross-module and scope machinery

| site | source | notes |
|---|---|---|
| **`.lib` imported signatures** | `src/lib_file.rs:194-201`, `:252` | parses declared parameter and return types (`Integer/String/Boolean/File/Value/Buffer/List/Map`) and feeds both `analyzer.imports` and `codegen.imports`. **The importing program trusts the `.lib`'s declared types with no verification against the `.so`** — a binding site across a module boundary |
| `collect_definite_decls` | `ast.rs:642-681` | shared analyzer/codegen view of which main-line declarations act as globals. Carries `DefiniteDeclKind` (Plain/Buffer/List/Map/File) — a *kind*, **not a scalar type**, so the global-mirror path has no opinion on number-vs-text |
| global bss mirrors | `emit_mirror_stack_var_to_global_if_needed` | globals get a mirror slot; type comes from `variable_types` |
| `If` branch merge | `analyzer:2091-2136` | merges **availability only**; types are not part of `AnalysisEnv` — the root of findings 6-11 |
| function scope save/restore | `analyzer:2299`/`2349`, `codegen:3219`/`3379` | ✅ correct |
| **nested block shadowing** | — | ❌ no separate slot, outer clobbered, no restore — **finding 12** |
| loop variable after loop exit | — | persists with the last iteration's value and type |

### D. The runtime-tag (dynamic) machinery

| component | source |
|---|---|
| `mixed_lists` — pre-scan set of heterogeneous lists | `codegen:20` |
| `list_element_types` → `VarType::Mixed` | `codegen:15` |
| `mixed_tag_slots` — shadow slot holding the runtime tag | `codegen:31` |
| `value_typed_names` — declared `value`; bare arithmetic rejected | `analyzer:1969-1974` |
| `unprovable_scalars` | `codegen:27` |
| `Type::Value` / `VarType::Mixed` | `ast.rs`, `codegen` |

### E. Sites the brief did not list — what I found beyond it

The steer asked specifically for anything not on its list. These are the ones:

1. **`ParseFlags` is an unimplemented no-op** (A5). Flag values are never
   parsed at runtime, so `FlagSchemaDecl`'s declared type is currently never
   challenged by a real value. When runtime parsing lands it becomes a binding
   site that converts text argv into typed values — a natural home for the
   same class of bug.
2. **`Free` does not clear tracking** (A11). The name keeps its type after the
   memory is gone. Independently, `Allocate` + `Free` + use segfaults today
   (use-after-free, noted under "adjacent" below).
3. **Map value types are structurally unknowable** (B). Not merely un-inferred
   in one path — `Type::Map` is *only ever* constructed with
   `Box::new(Type::Unknown)`, at all four sites. Even a homogeneous map
   literal like `{"k": 42}` yields no value type.
4. **`Repeat` counters are not user-bindable** (A8) — one *fewer* site than
   the steer expected; the counter is an internal `_repeat_counter` slot.
5. **Tuples, multiple return values and destructuring do not exist yet.**
   `Type` has no tuple variant, `Expr` has none, and
   `grep -rn "Tuple\|destructur" src/` returns nothing. Plans 110/120/130
   specify them but have not landed. **The rule should be settled before they
   do**, because destructuring binds several names at once and is a binding
   site by construction.
6. **`.lib` signatures are trusted, unverified** (C). Nothing checks the
   declared types in a `.lib` against the actual `.so`.
7. **`collect_definite_decls` carries kind, not type** (C).
8. **Loop variables outlive their loop** (C), keeping the last iteration's
   value — so their type after the loop is a real question, not a hypothetical.

---

## Enforcing the rule per site — and where a fixed type is the *wrong* answer

### What enforcement requires, by group

**The binding sites (A2, A6, A10, A13 — findings 1, 2, 3, 17).** These are the
"survives" column and the real work. Each stores a new runtime value into an
existing name without going through `Statement::Assignment`. Enforcement must
decide, per site, between *reject* (the name is already declared with a
different type) and *rebind* (this is a new declaration that shadows). Because
this is a class of **omission**, patching the four known sites will not stop
the fifth appearing: the durable shape is a single choke point — one
`bind(name, type, span)` helper that every arm must call, so forgetting is a
visible absence rather than a silent default. That helper is also the natural
place to raise the new diagnostic.

**The assignment site (A3) plus the `VarDecl{None}` path (A2).** The cleanest
shape is for the parser to emit `Statement::Assignment` when the name is
already declared and no type is written, so there is one path to keep correct
instead of two. Adding a parallel check to the `VarDecl` arms leaves
`VarDecl{None}` as a live trap for the next statement form that reuses it.

**Operations that ignore the type (findings 5, 15).** Independent of the rule
and cheap: `Increment`/`Decrement` should reject a non-numeric target, reusing
the existing arithmetic diagnostic. This can land first and is a strict
improvement regardless of what happens to the rest.

**Scope (finding 12).** Decide whether an inner declaration shadows or is an
error. If it shadows, it needs its own slot and a restore at scope exit; the
function-scope save/restore at `analyzer:2299`/`2349` and
`codegen:3219`/`3379` is the working model to copy.

**Flow-sensitivity (findings 6-11).** Becomes unnecessary for type tracking
once the rule holds, and that is a large simplification: it removes the need
for the per-branch snapshot/merge that plan 293 recommends. Keep the existing
`AnalysisEnv` merge for variable *availability*, which is a separate concern
and already correct.

### Where a fixed type is genuinely the wrong answer

**1. For-each over a heterogeneous list — the case to get right (finding 18).**

The loop variable genuinely holds a different type each iteration. No fixed
type is correct: pinning it to the first element's type is wrong for every
other element, and pinning it to text/number rejects valid programs. This is
precisely what `Type::Value`/`VarType::Mixed` exists for, and **the compiler
already computes the discriminator it needs** — the `mixed_lists` pre-scan
proves whether a list is heterogeneous before codegen runs.

The correct design falls out of that:

- **Homogeneous list** → the element type is known, the loop variable takes it
  as a normal fixed type. This is already what `codegen:3520` does.
- **Heterogeneous list** → the loop variable is `value`/Mixed. Printing
  already dispatches on the runtime tag and is correct today. What is missing
  is that **arithmetic and other type-specific operations must require a check
  or a cast**, exactly as a declared `a value called x` already does.

The mechanism is already built and working. Verified:

```vox
a value called v is 5.
a number called z is v add 1.
```

gives `Cannot use a value v in arithmetic; check its type with 'is a number'/'is a text' first.`

So the fix for finding 18 is not new machinery — it is to route
heterogeneous-list loop variables into `value_typed_names`
(`analyzer:1969-1974`) instead of merely *clearing* their label at
`analyzer:2167`. Clearing says "I don't know, allow anything"; the rule needs
"I don't know, so demand a check". **That one-word difference in intent is the
whole finding.**

**2. Map reads (findings 4, 14).** Because map value types are never inferred,
every map read is dynamically typed in practice. Two coherent options:

- *Infer value types for homogeneous map literals* (`{"k": 42}` → map of
  number), which makes the rule enforceable and closes findings 4 and 14 by
  making the mismatch visible; or
- *Treat every map read as `value`*, requiring a check or cast at the use
  site — sound, consistent with option 1's fallback for heterogeneous maps,
  but more verbose for the common homogeneous case.

Doing neither leaves findings 4 and 14 alive **and silent**, which is the
worst outcome: the rule would appear to close them while the segfault remains.
I recommend inferring for homogeneous literals and falling back to `value`,
which mirrors how lists are already handled and reuses the same pre-scan idea.

**3. Externally-sourced values.** `Argument*`, `EnvironmentVariable*` and
`LastError` have known static types (`String`/`Integer`), so a fixed type is
correct. `ParseFlags` (A5), when implemented, converts text argv into the
flag's declared type — a cast, not a retype, so it fits the rule cleanly.

**4. `.lib` imports.** Declared types cross the module boundary unverified. A
fixed-type rule is only as strong as the weakest declaration it trusts; worth
deciding whether a mismatch between `.lib` and `.so` should be detectable.

---

## Migration cost

**One site in one file.** The rule is cheap to adopt.

```bash
python3 migration_scan.py tests examples     # script in the audit scratch dir
```

The scan classifies literal right-hand sides only: it walks each `.vox` file,
records `a <type> called <name>` declarations, then flags any
`X is <literal>` / `the X is <literal>` / `Set|Store|Assign|Create X to
<literal>` whose literal kind differs from the declared type. Buffers, lists,
maps and `value` are exempt.

```
files scanned : 354      (324 under tests/, 30 under examples/)
files affected: 1        (excluding this audit's own PoC files)
retype sites  : 1
```

The single hit is `tests/149_cast_in_arithmetic.vox:25`:

```vox
a text called dyn is "hi".
dyn is 5.
a number called dynr is dyn add 1.
```

Note this test **deliberately asserts that implicit retyping works** — its
`.expected` ends in `6`, which is `dyn add 1` after the retype. So migration
here is not "add a cast": it is amending a test that encodes the old
semantics. That is the only such test in the corpus.

**Confidence and limits.** The heuristic under-counts by construction: a
retype whose right-hand side is a function result, a map read or an element
read is invisible to it, and those are exactly findings 4/14/18. It is a lower
bound, not a proof. Three things suggest the true number is still small: the
corpus contains 368 typed declarations and 274 `Set`/`Store`/`Assign`
statements, of which **164 are `set byte …`** (`ByteSet`, not a variable
binding) and a further handful are `set element`/`set …'s` (`ElementSet`,
`MapSet`); and the only two files matching `set X to "…"` are
`tests/066_format_buffer_set_append_copy.vox` and
`tests/067_format_buffer_fixed_overflow.vox`, where the targets are **buffers**
(format-string writes, already special-cased at `analyzer:2074` and
`codegen:2919`/`2935`) and therefore exempt.

**Order of magnitude: single digits.** The rule does not need adjusting on
migration-cost grounds.

---

## Null results — constructs checked and found correct

Each was run the same way: write the program to `p.vox` in a temp directory
(never the repo — a compiled Vox program is dropped in the CWD), then

```bash
cd "$(mktemp -d)" && vox p.vox -o p.bin && ./p.bin; echo "exit=$?"
```

| construct | program | observed | verdict |
|---|---|---|---|
| plain assignment `X is <text>` over a number | `a number called n is 5.` / `n is "abc".` | `abc` | correct today — **the rule repeals this** |
| plain assignment `X is <number>` over text | `a text called s is "hello".` / `s is 5.` | `5` | correct today — likewise |
| `the X is <value>` | `the n is "abc".` | `abc` | correct — parses to `Statement::Assignment` (`parser:1808`) |
| assignment from a function return value | `To mk. Return a text, "abc".` / `n is mk.` | `abc` | correct |
| assignment from a list element | `a list called L is ["abc","def"].` / `n is element 1 of L.` | `abc` | correct — elements are runtime-tagged |
| assignment from a buffer byte | `s is byte 1 of b.` over a text `s` | `0` | correct — retypes to integer |
| `Set element N of L to <text>` on a numeric list | `Set element 1 of L to "abc".` | `["abc", 2, 3]` | correct — `ElementSet` writes a tagged element |
| **print** of a for-each variable over a heterogeneous list | `[42, "hello", 3.14]` | `42 / hello / 3.14` | correct — dispatches on the runtime tag (contrast finding 18) |
| `Get current time into X` over a text name | over `a text called t` | `1786204206` | correct — both maps retype (`analyzer:2802`, `codegen:4732`) |
| `Create a timer called X` over a text name | over `a text called clock` | `0` | correct — `codegen:4689` retypes to integer |
| function parameter typing does not leak out | `To f with a number called v.` + a global text `v` | `3` then `hello` | correct — save/restore both sides |
| same parameter name, two functions, different types | `To f with a number called p.` + `To g with a text called p.` | `f 7` / `g hi` | correct — no cross-function leak |
| `a value called v` rejects bare arithmetic | `a number called z is v add 1.` | compile error naming the check | correct — **the mechanism finding 18 should reuse** |
| dead code after a top-level `Return` | `To f.` / `Return a number, 1.` / `n is "abc".` | `abc` | **correct, and intended** — see below |

### Two things that look like bugs and are not

**A top-level `Return` ends the function body.** `To f. Return a number, 1.
n is "abc".` prints `abc` at top level even though `f` is never called. I
initially recorded this as a finding; it is not one.
`src/parser/mod.rs:4318-4327` documents the behaviour explicitly, so
`n is "abc".` is a genuine top-level statement. Confirmed directly: a
`Print "SIDE EFFECT".` before the `Return` never runs, while a
`Print "LEAKED".` after it prints in top-level order. Consequently the brief's
"early `Return`" item has no separate failure mode — a return inside a
conditional reduces to the `If` case.

**A block body is one statement unless clauses are comma-separated.**
`For each item in data,` followed by two period-terminated `Print` lines runs
only the first inside the loop; the second executes once afterwards with the
loop variable's final value. This is the comma/period clause structure, not a
bug — but it invalidates any test written with multi-statement
period-separated bodies. It cost me two spurious results before I caught it
(finding 18 is the corrected version), and it is worth knowing before writing
regression tests for the fix. Every PoC in this audit uses a single-statement
body or explicit comma clauses.

---

## Suspected, not reproduced

- **Short-circuit evaluation.** Listed in the brief as a direction-1 path. No
  repro is constructible because assignment is not an expression in Vox —
  there is no way to place a store inside the right-hand operand of `and`/`or`.
- **`MapSet` / `BufferCopy` retyping their target.** These write *through* a
  variable; I found no way to make the container's own tracked type change.
  `ElementSet` is confirmed correct. I did not find a defect, and I also
  cannot prove absence — see "not audited".

## Adjacent — real and reproducible, but not retype bugs

- **A declaration inside a nested block clobbers the outer variable.** The
  *taken*-branch form of finding 12. Tracked type and runtime value stay
  consistent, so it is not memory-unsafe — it is the shadowing decision the
  rule must make anyway.
- **Use-after-free.** `Allocate 32 for s.` / `Free s.` / `Print "[{s}]".`
  segfaults. Independent of type tracking; correct types would still
  dereference freed memory.

## Root-cause grouping

**Group A — flow-insensitive type tracking.** Findings 6-11. One defect, six
surfaces. **Fully closed by the rule.**

**Group B — re-declaration forms never retype.** Findings 1, 13, 16.
`Set`/`Store`/`Assign`/`Create` produce `VarDecl { var_type: None }`; both
consumers guard on `Some`. One missing update, three consequences: a segfault,
wrong output, and a spurious compile error. **Closed by the rule only if
enforced on that path.**

**Group C — statements that rebind a name without retyping it.** Findings 2, 3,
17 (and finding 12's slot reuse). Each is a separate statement arm.
**Survives the rule.** The group the brief predicted would be largest, and the
one where undiscovered instances are most likely.

**Group D — untyped expression results leave stale tracking.** Findings 4, 14.
`VarType::Unknown` is a deliberate no-op at `codegen:2931` while the analyzer
correctly clears. **Survives the rule** until map value types are inferred.

**Group E — operations that ignore the tracked type.** Findings 5, 15, 18.
Not tracking bugs at all: tracking is correct and the code generator does not
consult it. **Survives the rule**, and is independent of it.

Groups C, D and E are genuinely independent of each other and of the rule.
Group A is one bug; group B is one bug with three faces.

## Cross-cutting recommendation

Findings 2 and 17 are codegen-only, and finding 2 is a case where the analyzer
is *right* and codegen is wrong — so no diagnostic is possible even in
principle. Two hand-maintained copies of the same information in two files
guarantee a recurring supply of this bug class. The strategic fix is for the
analyzer to publish a resolved per-variable type that codegen **reads** rather
than recomputes. That is larger than any single fix here and should be a
deliberate decision, but every group except E gets cheaper once it is done —
and the type-immutability rule makes it markedly easier, because a type that
never changes after declaration is far simpler to publish than one that varies
per program point.

## What I could not audit, and why

- **`.lib` type agreement across a module boundary.** `src/lib_file.rs` has a
  real type surface (`:194-201`, `:252`) but no `scalar_types`/`variable_types`
  involvement — both maps are referenced only in `src/analyzer/mod.rs` and
  `src/codegen/mod.rs`, zero references elsewhere in `src/`. I did **not** test
  whether a `.lib` can declare a type that disagrees with its `.so`; that needs
  a two-crate fixture. Genuine gap.
- **`MapSet` and `BufferCopy` as retype vectors.** Probed, nothing found, but I
  could not construct a case that changes the container's tracked type, so I
  cannot distinguish "correct" from "wrong shape tried".
- **Cross-function global retyping.** Parameters are properly scoped
  (verified), but I did not get a reproduction for a function that assigns to a
  *global* of a different type and is then called conditionally. The
  save/restore at `analyzer:2299`/`2349` suggests the tracking write would be
  discarded while the runtime write persists — a direction-2 bug — but I will
  not report it as a finding without a repro.
- **Non-x86_64 targets.** Everything here is x86_64; `coreasm/` was not
  exercised. A target with a different string representation could change the
  observed symptom, though not the tracking defect.
- **Migration count is a lower bound**, per the limits stated in that section.

## Notes on the brief

The brief was accurate everywhere I checked it; the `scalar_types` and
`variable_types` write-site line numbers were all correct. Three refinements:

1. `src/codegen/mod.rs:4689` (`// Track as integer for now`) was flagged as a
   likely home for a wrong assumption. It is `TimerDecl`, and it is
   **correct** — verified. The suspicious comment is benign.
2. **Bug B deserves higher than "high".** The same missing update with the
   operands swapped (finding 1) is a segfault, not wrong output.
3. The brief's premise that "reassigning a number to text is legal Vox" is
   true today and is what makes Bug B a bug rather than invalid code — and it
   is exactly what the new rule repeals. Under the rule, Bug B's repro program
   becomes a compile error and the finding is closed by redefinition rather
   than by fixing the tracking.
