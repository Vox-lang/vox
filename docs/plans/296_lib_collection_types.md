# Plan 296 — full type-vocabulary parity for parameters and return types,
# on ordinary Vox functions and across the `.lib` boundary

**Status:** specced 2026-08-08, rescoped 2026-08-09 (two owner steering
messages, both folded in below). Baseline measurements below are against
`23bc193` (v0.3.3).

## Rescope history

The plan started narrow: allow `list`/`buffer` as `.lib` return types, and
stop erasing a list's element type at the `.lib` boundary. Two owner
messages widened it during implementation:

1. **"every type Vox can express must work as a `.lib` PARAMETER and RETURN
   TYPE. Not a curated subset."** The `.lib` return-type limit (five types)
   is a bug to delete, not a design to preserve. `float` is missing from the
   `.lib` vocabulary entirely, in both positions — a second hole in the same
   wall.
2. **"this must work for ORDINARY FUNCTIONS too... ordinary functions are
   the ROOT of the problem."** The `.lib` vocabulary mirrors a restriction
   that already exists in Vox source's own `Return a <type>,` syntax.
   Fixing `lib_file.rs` alone would be pointless — a library author cannot
   write `Return a list, ...` in Vox source in the first place, so there is
   nothing for a widened `.lib` to describe.

So the work has two surfaces, not one, and both need the same vocabulary in
both positions.

## The target vocabulary

From `src/parser/ast.rs`, `Type` has 13 variants: `Integer, Float, String,
Boolean, List, Map, Buffer, File, Time, Timer, Value, Void, Unknown`.

11 of these are expressible and get full parameter/return parity:
**number, float, text, boolean, list, map, buffer, file, time, timer,
value.**

Two need a judgment call, not blind inclusion:

- **`Void`** already means "returns nothing," spelled by *omitting* the
  `Return`/`, returning` clause entirely. This stays as-is — there is no
  `returning a void` or `Return a void,`. Adding a spelling for "nothing"
  would give two ways to say the same thing (omit the clause, or say
  `void`), which is exactly the kind of surface-area growth this plan is
  supposed to be closing off, not opening. Not adding it.
- **`Unknown`** is an internal placeholder — the parser's fallback for an
  untyped `with n` parameter, and the `.lib` emitter's fallback noun when a
  parameter has no declared type (`param_type_noun`'s "render `Unknown` as
  `number`" comment). It has no surface spelling anywhere in Vox source and
  none is being added: "unknown" is not a type an author declares, it is
  what's left when they declare nothing.

## Baseline measurements (verify-before-build, both true on `23bc193`)

**A. Vox source `Return a <type>,` accepts 5 of 11, and inconsistently —
two divergent parsers.** `To 'give it'. Return a <type>, 1.` (Return as the
function's only/first statement) goes through the *inline* path in
`parse_function_def` (`src/parser/mod.rs` ~4295-4309):
accepts number, text, boolean, file, value; rejects float, list, map,
buffer, time, timer with `Expected a statement, got <Type>`.

But when `Return` is **not** the function's first statement, a *different*
parser runs — `parse_return` (Gate B, ~2154-2189) — and it is stricter
still: it accepts only number, text, boolean (file and value fail there
too, with `Expected type after 'a' in return statement`). This divergence
between two parsers for the same syntax is itself a bug, and exactly the
kind of thing a shared vocabulary table (see "What to build") prevents from
recurring.

**B. The bare (undeclared-type) return already carries collections
correctly, structurally — but not their elements.**
```vox
To 'make it'.
  a list called out is ["a", "b"].
  Return out.

a list called got is 'make it'.
Print "len={got's length}".
For each t from got, print "tok=[{t}]".
```
Verified: `len=2` (structurally correct — the pointer and length cross
back), but `tok=[4198528]` / `tok=[4198530]` (raw pointers — the element
type does not cross). This is the SAME element-erasure bug the original
plan found at the `.lib` boundary, just one level upstream: it already
happens for an ordinary same-file function returning a list through an
undeclared `Return`. Confirms the fix target (typed declaration syntax) is
additive — codegen's calling convention for returning a list is already
correct; only the declared-type *acceptance* and the element-type
*propagation* are missing.

**C. Vox source function PARAMETER declarations (`with a <type> called
x`) are also missing float/time/timer** (`src/parser/mod.rs` ~4230-4247)
— confirmed by direct test: `To f with a float called x.` fails with
"Cannot use 'float' as a variable name," because the unmatched `Token::Float`
is never consumed and `parse_name()` then trips over it. `list`, `map`,
`buffer`, `file`, `value` already work as parameters (just untyped-element
for the collections); this only affects the three newcomers.

**D. `.lib` vocabulary today:** parameter position accepts number, text,
boolean, file, buffer, list, map, value (8; missing float, time, timer).
Return position accepts only number, text, boolean, file, value (5; missing
float, list, map, buffer, time, timer). Both gaps mirror A and C — the
`.lib` format was never ahead of what Vox source could already express, so
fixing it alone (the original narrow plan) would have described signatures
no library could implement.

## What to build

### 1. Vox source: one shared type-vocabulary table, used by all three
   parser sites that currently disagree

Add a single helper (`fn declaration_type_token(&self) -> Option<Type>` or
similar) in `src/parser/mod.rs` recognizing all 11 types, and make these
three sites call it instead of hand-rolling their own `match`:

- Function parameter type (`with a <type> called <name>`, ~4230-4247):
  add float, time, timer (list/map/buffer/file/value already present).
- `Return a <type>,` inline path (~4295-4309): add float, list, map,
  buffer, time, timer.
- `Return a <type>,` Gate-B path (`parse_return`, ~2154-2189): add file,
  value, float, list, map, buffer, time, timer.

One shared table is the actual fix for "never wants to hear about this
class of problem again" — baseline A exists *because* two call sites hand-
rolled the same vocabulary and drifted. A third divergent copy is not
an option.

`list`/`map` stay element-untyped at the Vox-source declaration syntax
level (`Type::List(Box::new(Type::Unknown))`) — Vox deliberately has no
generic/typed-collection declaration syntax; see "Element typing" below for
why that's the right boundary and how the `.lib` case differs.

### 2. `.lib`: the same 11-type vocabulary, in both positions

`src/lib_file.rs`, `take_type`: add float/time/timer (new to both
positions), and drop the `position == "parameter"` guard on buffer/list/map
so they're legal in return position too. One vocabulary list, one error
message, no more per-position allow-lists.

`src/codegen/mod.rs`: `param_type_noun`/`return_type_noun` collapse into one
`type_noun` used for both positions (mirroring the `.lib` parser now
accepting the same set both ways) — see "Element typing" for the one
exception (`list`'s optional `of <type>` suffix).

### 3. Element typing still crosses the `.lib` boundary (original plan,
   unchanged in scope: `list` only, not `map`)

Vox source has **no** typed-list declaration syntax anywhere (confirmed:
grepped every `Token::List` match in the parser — var decl, parameter,
`is a list` predicate — all three hard-code
`Type::List(Box::new(Type::Unknown))`). This is deliberate, not an
oversight: `docs/COLLECTIONS_ROADMAP.md` states the design principle
outright — "the author picks the data; the compiler picks the
representation" — element type is *inferred* from how a list is built
(first-append/literal), never *declared*. Confirmed live: a list built from
string literals prints correctly with zero type annotation anywhere in the
program.

The original plan's stop condition — "if Vox source has no typed-list
syntax at all... stop and tell me rather than inventing `.lib`-only syntax
that source cannot express" — is real and was hit. Resolution, restated
per the owner's follow-up ("element typing must cross the boundary too,
per the original plan"): the `.lib` does **not** gain author-facing generic
syntax. Instead:

- **Emit side (Stage A3):** when a `.lib`-exported function has a
  list-typed parameter or a list-typed return, statically scan that
  function's own body (parameter appends: `Append <expr> to <param>`;
  return-traced literals/appends: `Return <list-var>.`) using the same
  "first-append/literal decides, disagreement widens to untyped" rule the
  compiler already applies for local list printing. If every observed
  element is the same scalar type, the `.lib` records it; if the scan finds
  disagreement or nothing at all, it emits plain untyped `list`, exactly
  today's behavior. **The library author writes nothing new** — this is a
  compiler-computed fact serialized into a machine-oriented interface file,
  the same way a return type is already inferred from the body rather than
  hand-annotated in the `.so`.
- **`.lib` serialization spelling (read+write):** `a list of <type> called
  <name>` / `returning a list of <type>`, where `<type>` is any of the nine
  non-collection nouns (number, float, text, boolean, file, buffer, time,
  timer, value — no nested list-of-list/map, out of scope, no evidence
  requires it). Bare `list` keeps parsing exactly as today (backward
  compatible; untyped element). This spelling exists **only** in the `.lib`
  grammar — which is already its own bespoke DSL, not a Vox-source subset
  (`lib_file.rs`'s own module doc: "parsed by this dedicated parser, not
  the full Vox parser... deliberate"). It does not imply or require any new
  Vox author-facing syntax, so it does not contradict the "author doesn't
  declare, compiler infers" principle above — it just gives the compiler's
  own inference a place to write its answer down.
- **Consume side:** at a call site whose target's `.lib`-declared parameter
  is `list of <type>`, and the argument is a plain local variable, the
  codegen records that variable's element type the same way a local
  `Append <literal> to x` already does. Symmetrically, a `VarDecl` whose
  value is a call to a `.lib` function with a `list of <type>` return
  records the declared variable's element type. Both are additive lookups
  keyed off the already-`.dynsym`-verified import table; no new runtime
  representation, no ABI change — a list crossing the boundary is the exact
  same pointer it is today, just with the compiler now trusting a real
  element type for it instead of defaulting to "don't know."

`map`'s value type is **not** addressed here — the original plan never
scoped it, and the owner's follow-ups reaffirmed "everything else in the
plan stands" without mentioning it. `.lib` gains bare `map` in return
position (item 2), but its value type stays `Unknown`, same as today. Noted
below as a symmetric known gap, not fixed here.

## Newly discovered, explicitly out of scope

**The element-erasure bug is not `.lib`-specific — it also hits an
ordinary same-file out-parameter and an ordinary same-file undeclared list
return (baseline B above, and a same-file out-param case verified the same
way: `To 'fill' with a list called out. Append "hi" to out. ...` — the
caller's `for each` also prints raw pointers).** Root cause: the compiler's
existing flow-sensitive list pre-scan (`prescan_walk` /
`prescan_mixed_lists` in `codegen/mod.rs`) recurses into a function's body
but never seeds its environment with that function's own **parameters** —
so any list built through a parameter (appended-to as an out-param, or
returned after being appended-to) is invisible to the same inference that
already works for a list built and printed within one straight-line scope.
This plan does not fix it: the two steering messages scoped element-typing
fixes to "the boundary" (the `.lib` case) specifically, and a general fix
to the pre-scan's parameter-seeding is a larger, independent change with
its own blast radius across every function call in the language, not just
`.lib` calls. Flagged for a future plan.

**Declared `.lib` types remain trusted, not verified against the `.so`**
(plan 294 findings 19/20 — a `.lib` declaring a return type its
implementation doesn't provide crashes the consumer). This plan widens what
a `.lib` may declare in both positions, which widens that hole further
(more declarable types = more ways to lie). Not fixed here, per the
original plan's explicit instruction.

## Acceptance criteria

1. `Return a <type>, <expr>.` accepts all 11 types, identically via both
   the inline and Gate-B parser paths, for an ordinary (non-`.lib`) Vox
   function.
2. `with a <type> called <name>` accepts all 11 types as an ordinary
   function parameter.
3. A `.lib` can declare all 11 types in **both** parameter and return
   position; round-trips (emit a `.lib`, reparse it, type survives) for
   every one of the 11, in both positions.
4. The original verified repro prints `tok=[hello]` / `tok=[second]` (real
   values) for the **parameter** case, and the analogous **returned**-list
   case (a `.lib` function returning a list of text, consumed and
   `for each`-printed) does too.
5. `examples/mathkit_lib.vox` and the C-interop test still work — the ABI
   for existing scalar signatures must not shift.
6. Gate green: `cargo build --release` (0 warnings), `cargo test --release`,
   `./test.sh` (baseline 219 passed / 0 failed / 6 skipped — count will grow
   with the new matrix tests).
7. Plan 294 PoCs stay closed: `for d in tests/retype_audit_pocs/[0-9]*/; do
   bash "$d/poc.sh"; echo "$d -> $?"; done` — all non-zero.
8. Regression matrix tests exist on **both** surfaces (ordinary-function
   `Return`, and `.lib` parameter+return round trip) covering all 11 types,
   so a future narrowing on either surface fails a test instead of shipping
   silently.
9. `unsupported_return_type_is_named` (the test that pinned the old
   restriction) is rewritten to assert the "named unsupported type"
   diagnostic still fires for a genuinely-invalid type (not
   buffer/list/map/float/time/timer anymore — those are now valid) — the
   coverage for that diagnostic is not deleted, just re-pointed.

## Documentation — describe the END STATE, not the history

`docs/SHARED_LIBRARIES_DESIGN.md` and `LANGUAGE.md` both currently state a
single five-type vocabulary shared by parameters and returns. That was
already wrong (parameters additionally took buffer/list/map/value — 8, not
5) and becomes wrong in a new way once this lands (11 in both positions).
Rewrite both to state the finished rule plainly — the same 11-type set in
both positions, on both ordinary functions and `.lib` — with no "this used
to be narrower" framing. Also document: the `list of <type>` `.lib`
spelling and that it's compiler-inferred, never author-declared; that
`map`'s value type is not carried; and that `Void`/`Unknown` are
deliberately unspellable (see judgment calls above).

## Hard constraints

- **Never `git add -A`.** Compiled Vox programs land in the CWD. Named paths
  only; build test programs in a temp dir.
- **Never `--no-gpg-sign`.** Hardware key; a hanging commit is waiting for a
  human.
- **No `Co-Authored-By:` trailers.**
- **Do not spawn workers.** You are the worker.
- Commit incrementally so the owner can review as you go.

## Reporting

Report each unit of work: done / not done, with the reason. Say plainly if
this doc is wrong about the code — fixing the doc beats building on a false
premise. Report what could not be done rather than silently reducing scope.
