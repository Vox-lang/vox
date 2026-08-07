# Plan 280 S1 — Type audit

**Status:** audit complete 2026-08-07. Read-only measurement; no compiler,
test, or doc changes made. This is the deliverable for plan 280 stage S1
(`docs/plans/280_uniform_signature_types.md`).

## Method

Built `cargo build --release` (0 warnings), set `VOX_CORE_PATH` to this
worktree's `coreasm`, then for every cell wrote a minimal `.vox` (or, for
`.lib` cells, a hand-written `.lib` + a `see`-importing consumer) and
compiled it with the release binary. Every "pass" cell below was also run,
not just compiled, wherever a meaningful runtime check existed (arithmetic,
printing, or a real `.lib`/`.so` round trip) — compiling without error is
necessary but not sufficient evidence, and two of the "fixes" below would
have looked like passes from compile output alone.

Two traps, both hit and worked around:

1. **The declare-then-return trap** (flagged in the brief). Fixed by giving
   every type a real initialiser and testing parameter/return acceptance
   independently, per the brief's suggested syntax.
2. **A second, undocumented trap: `Return` has two independent gates**,
   found while measuring. See "Return position is two gates, not one"
   below — this affects how the "fn return" column must be read for
   `file` and `value`, and changes the fix required in S2.

For `.lib` cells: `.lib` parsing (`src/lib_file.rs`'s `take_type`) runs
before `.so`/`Location` resolution, so a hand-written `.lib` pointing at a
nonexistent `.so` still exercises the real type gate — the "does the .so
exist" error only appears for types that got past `take_type`, which is a
clean pass/fail signal. Where a type could plausibly be produced by a real
compiled library (all 8 that pass `fn param`, plus `value`/`file` return),
that was additionally verified with a genuine compiled `.so`: a probe
library exporting `buffer`/`list`/`map` params and `value`/`file`
param-and-return, consumed through `see`, run, and checked for correct
output (fd numbers, echoed values). All of it round-tripped correctly.

## The 11×4 table

| type | fn param | fn return | `.lib` param | `.lib` return |
|---|---|---|---|---|
| `number` | yes | yes | yes | yes |
| `text` | yes | yes | yes | yes |
| `boolean` | yes | yes | yes | yes |
| `list` | yes | no | yes | no |
| `map` | yes | no | yes | no |
| `buffer` | yes | no | yes | no |
| `value` | yes | no¹ | yes | yes |
| `file` | yes | no¹ | yes | yes |
| `float` | no | no | no | no |
| `time` | no | no | no | no |
| `timer` | no | no | no | no |

¹ `value` and `file` **do** pass `fn return` when `Return` is the literal
first statement of the function body (no local declarations, no prior
logic). They fail via a second, separate, narrower gate as soon as
`Return` follows any other statement — which is the realistic shape of
any function with actual logic. The table reports the realistic case, to
match how the original plan doc's matrix was produced. See the dedicated
section below; this is not `file`/`value`-specific.

Not part of the 4-position table but measured per the brief's explicit
ask: **`file` cannot be declared as a local variable at all** (`a file
called "v" is 1.` → `Cannot use 'file' as a variable name`). See the
`file` section below.

## Failing cells, by type

### `float`

- **fn param** — FAIL. `Missing parameter name\n  Syntax: a <type> called "<name>"\n  Example: a number called "x"`. Site: `src/parser/mod.rs:4077-4090` — the parameter-type match has no `Token::Float` arm, so it falls to `_ => Type::Unknown` (line 4089) **without consuming the token**; the still-current `Float` token then fails the parameter-name check at `src/parser/mod.rs:4098-4106`, producing a misleading "missing name" error for what is really a missing type.
- **fn return** — FAIL both gates. Immediate gate: `Expected a statement, got Float` at `src/parser/mod.rs:6013` (`parse_primary`'s catch-all — reached because the gate at `src/parser/mod.rs:4143-4145` omits `Float`, so the `a` article gets consumed at line 4139 but the `Float` token is left for `parse_condition` to choke on as an expression). Later-statement gate: `Expected type after 'a' in return statement` at `src/parser/mod.rs:2081` (`parse_return`'s gate at line 2068 only matches `Number`/`Text`/`Boolean`).
- **`.lib` param** — FAIL. `unsupported type Float in a parameter position — a .lib states types as one of: number, text, boolean, file, buffer, list, map, value`. Site: `src/lib_file.rs:169-206`, match at 170-179 has no `Token::Float` arm.
- **`.lib` return** — FAIL. Same site, "in a return position" variant.
- **Classification: parser gap, confirmed, not inferred.** `Type::Float` is a fully realized scalar elsewhere — `VarType::Float`/`TAG_FLOAT` exist and are used throughout `src/codegen/mod.rs` for arithmetic, printing, and local storage; a local (`a float called "v" is 1.5.`) compiles and runs correctly, printing `1.5`. There is no representation barrier; the type simply isn't listed in any of the four gates.
- **Recommendation:** add `Token::Float` to all four gates (the two in `src/parser/mod.rs` line ranges above, `parse_return`'s gate, and `take_type`) plus `Type::Float` arms in `src/codegen/mod.rs`'s `param_type_noun` (262-274) and `return_type_noun` (281-290), which the `.lib` emitter needs to actually produce `float` in a table-of-contents entry once the parser accepts it.

### `time`

- **fn param** — FAIL, identical mechanism and error text to `float` (`Missing parameter name`); `Token::Time` is likewise absent from `src/parser/mod.rs:4077-4090`.
- **fn return** — FAIL both gates, identical mechanism to `float` (`Expected a statement, got Time` / `Expected type after 'a' in return statement`); `Token::Time` absent from both `4143-4145` and `2068`.
- **`.lib` param** — FAIL. `unsupported type Time in a parameter position ...`. Same site as `float`.
- **`.lib` return** — FAIL. `unsupported type Time in a return position ...`.
- **Classification: parser gap.** Confirmed by reading the representation, not assumed: `Statement::GetTime` (`src/codegen/mod.rs:4645-4653`) stores "current time" as one plain 8-byte unix timestamp, tracked as `VarType::Integer`. Property access (`the now's hour`, `.minute`, etc., `src/codegen/mod.rs:6132-6155`) derives each component from that same raw integer via macros like `TIME_GET_HOUR rax` at access time — there is no richer stored struct, just an int. `time` is exactly as passable/returnable as `number`.
- **Recommendation:** same shape as `float` — add `Token::Time` to all four gates and both codegen noun tables.

### `timer`

- **fn param** — FAIL, same mechanism/error as `float`/`time` (`Missing parameter name`); `Token::Timer` absent from `src/parser/mod.rs:4077-4090`.
- **fn return** — FAIL both gates, same mechanism as `float`/`time`.
- **`.lib` param / return** — FAIL, same `take_type` mechanism.
- **Classification: representation gap — genuine, not a parser oversight.** `Statement::TimerDecl` (`src/codegen/mod.rs:4600-4611`) allocates a 48–56-byte **in-place stack structure** (`TIMER_INIT`, sized via `TIMER_SIZE`) and every timer operation — `TimerStart`/`TimerStop` (4613-4629), `.elapsed`/`.duration`/`.start time`/`.end time`/`.running` (6161-6190) — addresses it by taking **its stack address** (`lea rax, [rbp - offset]`) and mutating that memory in place. There is no single register-sized value that represents "a timer," unlike every other type this audit measured (all fit in one 8-byte word, or two for `value`'s tagged payload). Forcing `timer` through the existing by-value convention would either truncate the struct to 8 bytes silently, or — if a pointer were passed instead without saying so — hand back a dangling stack address the instant the declaring frame returns. That's the textbook unsound case the brief warned about.
- **Recommendation: do not add `Timer` to the four gates as a one-line fix.** This needs an explicit design decision first: either (a) support pass/return by an opaque handle (heap-allocate the timer struct, pass/return a pointer or table index), or (b) keep `timer` local-only, but turn that into an *explicit, reasoned, documented* restriction (a `.lib`/signature diagnostic that names the actual reason — "no value representation" — rather than the current generic "unsupported type" text that reads like an oversight). Given plan 280's target is "every type legal everywhere, or an explicit documented exception," (b) is the cheaper and, absent a concrete need for timers to cross a function boundary, the more honest outcome for S2 to ship, with (a) as a later, separate piece of work if a real use case shows up.

### `list`, `map`, `buffer`

- **fn param** — pass (all three), not repeated here.
- **fn return** — FAIL both gates, same two errors and same two sites as `float`/`time` (`Expected a statement, got List`/`Map`/`Buffer` immediately after signature; `Expected type after 'a' in return statement` when preceded by another statement). None of the three tokens appear in `src/parser/mod.rs:4143-4145` or `2068`.
- **`.lib` return** — FAIL. `unsupported type 'list'/'map'/'buffer' in a return position — a .lib states types as one of: number, text, boolean, file, value`. Site: `src/lib_file.rs:169-206` — these three are gated `position == "parameter"` at lines 176-178, exactly the drift the top-level plan doc names as the seed bug.
- **Classification: parser gap**, confirmed rather than assumed. `list`/`buffer` parameters occupy exactly one register-sized pointer word in the calling convention (`src/codegen/mod.rs:3163-3187`, the `word_count`/param-slot allocation for `FunctionDef` codegen) — the same mechanism a `string` parameter already uses, and `string` already returns fine. There's no structural reason a pointer that can be received can't also be handed back in `rax`.
- **Recommendation:** add `List`/`Map`/`Buffer` to the two `fn return` gates and drop the `position == "parameter"` condition in `take_type`'s `.lib` gate (`src/lib_file.rs:176-178`) — but only once `fn return` actually supports them, or `.lib` would claim a return shape the `.vox` grammar backing it can't produce. `src/codegen/mod.rs:281-290`'s `return_type_noun` doc-comment already anticipates this ("types the return-annotation parser never produces: `Float`, `Buffer`, `List`, `Map`, `Time`, `Timer`") — it just needs the three arms added once the parser catches up.

### `value`

- **fn param, `.lib` param, `.lib` return** — pass, verified with a real compiled `.so`: a probe library's `value identity` function (param and return both `value`) was called through `see`, and the round-tripped value printed correctly.
- **fn return — pass, but only via the "immediate" gate**, also verified with a real round trip (an `identity` function whose only statement is `Return a value, x.`, called and printed correctly). Fails via the later-statement gate with `Expected type after 'a' in return statement` (`src/parser/mod.rs:2081`) as soon as `Return` is preceded by any other statement in the same function body.
- **This corrects, rather than confirms, the brief's framing.** The brief characterizes this as "`value` accepted as `.lib` return but not fn return" — measurement shows `value` genuinely is accepted as a function return, just only in the narrow shape that happens to match how tiny library wrapper functions are usually written (see `tests/cinterop/mathkit.vox`'s `add two`: `Return` is the function's first and only statement). That's presumably *why* `.lib` files declaring `returning a value` already compile and run today — their generating source happens to fit the gate that works. The actual bug isn't a `value`-specific carve-out; it's that the later-statement return gate (`parse_return`, `src/parser/mod.rs:2055-2087`) has only ever supported `Number`/`Text`/`Boolean`, for every type, not just `value`. See "Return position is two gates, not one" below.
- **Classification: parser gap** (in the later-statement return gate specifically).
- **Recommendation:** extend `parse_return`'s type check at line 2068 to the full signature-type vocabulary (not just add `value` — this gate is what blocks `list`/`map`/`buffer`/`file`/`float`/`time` too, per the sections above).

### `file`

- **fn param, `.lib` param, `.lib` return** — pass, and independently re-verified beyond a bare compile: a real fd (opened by the caller) was passed through a `file identity` function (parameter and return both `file`) compiled into a real `.so`, consumed via `see`, and used again afterward — the same fd value survived the round trip.
- **fn return** — pass via the immediate gate only (same real-fd round trip as above, using `Return a file, x.` as the function's only statement); fails via the later-statement gate with the same generic `Expected type after 'a' in return statement`, for the same non-file-specific reason as `value`. Not a `file`-specific gap; see "Return position is two gates, not one."
- **Local declaration — FAIL, and this is the case the brief said to work out.** `a file called "v" is 1.` → `Cannot use 'file' as a variable name - it's a reserved keyword.` Site: `src/parser/mod.rs:1423-1621` (`parse_typed_var_decl`). Every other type in the grammar — `Number`/`Int`, `Float`, `Text`, `Boolean`, `value`, `List`, `Map`, `Buffer`, `Timer`, `Time` — has its own arm in this match. **`File` does not.** Mechanism, traced exactly: the unmatched `Token::File` falls to the catch-all `_ => None` (line 1621) without being consumed; the parser then looks for `Token::Called` (line 1625 — `expect()` just returns `false` on a mismatch, `src/parser/mod.rs:757-764`, no error, no advance); it then calls `check_not_keyword` on the still-current token (line 1629, defined at 698-710) — which is still `Token::File`, a genuine keyword token, so it reports "reserved keyword." **The error text is a red herring**: `file` isn't rejected because it's reserved, it's rejected because no arm was ever written to consume it as a type, so the parser stumbles into the variable-name check with the type token still sitting there.
- **Which behaviour is correct — work it out, per the brief.** `.lib`'s acceptance is correct; the local-declaration gap is the bug. `file` already round-trips as an ordinary 8-byte scalar (a fd) everywhere it's reachable — parameter, `.lib` parameter, `.lib` return, and function return via the immediate gate — with a real, verified round trip, not just a successful parse. There's no representation obstacle the way there is for `timer`. The fix is mechanical and has a direct precedent already in the same function: `Token::Time`'s arm at `src/parser/mod.rs:1585-1620` does exactly what `File` needs (`self.advance()`, build the `VarDecl` with `Some(Type::Time)`).
- **Classification: parser gap.**
- **Recommendation:** add a `Token::File` arm to `parse_typed_var_decl` (`src/parser/mod.rs:1423-1621`), modeled on the adjacent `Token::Time` arm, producing `Some(Type::File)` and falling through to the shared `called <name> [is <value>]` tail (lines 1624+) rather than `Time`'s bespoke inline block — `file` doesn't need `Time`'s special "is current time" parsing, just the type tag.

### `number`, `text`, `boolean`

Pass in all four positions and via both return gates; no failing cells, no
action needed. These are the baseline every other type is measured
against.

## Two findings beyond the four positions

The brief asked for four positions and named four interesting cases. Two
more things turned up while measuring that materially change what "fn
return" means and that S2 needs to know about, so they're recorded here
rather than glossed over.

### Return position is two gates, not one

`fn return`'s vocabulary depends on **where `Return` sits in the function
body**, not just on the type:

- **Gate A — `Return` is the literal first statement** of the function
  body (nothing precedes it, not even a local declaration). Handled
  inline in `parse_function_def`, `src/parser/mod.rs:4132-4162`; the type
  gate is at `4143-4145`/`4146-4157`. Accepts `number`, `text`,
  `boolean`, `file`, `value` (5 types). Anything else falls through to
  `parse_condition` → `parse_primary`'s catch-all at `src/parser/mod.rs:6013`,
  producing `Expected a statement, got <Token>`.
- **Gate B — `Return` follows any other statement** (a local
  declaration, an `if`, anything). Routed through the ordinary statement
  dispatcher to `parse_return`, `src/parser/mod.rs:2055-2087`; the type
  gate is at line `2068` and accepts **only** `number`, `text`, `boolean`
  (3 types) — `file` and `value` included. Everything else produces
  `Expected type after 'a' in return statement` at line `2081`,
  regardless of which type was actually written.

Verified directly: `Return a number, v.` after a preceding local
declaration compiles; the identical construction with `a value`/`a
file`/`a list`/`a timer` in place of `a number` all fail with the exact
same error text and line.

**A further consequence, also verified, not inferred:** only Gate A ever
writes to the `FunctionDef.return_type` field (`src/parser/mod.rs:4146-4153`).
Gate B parses and validates its own copy of the type annotation but
**never feeds it back into the function's declared return type**, which
stays `Type::Void` whenever `Return` isn't the first statement — even for
`number`. Confirmed by compiling a `.lib`-exporting function whose
`Return` follows one local declaration (`a number called "y" is x add x.`
then `Return a number, y.`): the emitted `.lib` table-of-contents entry
for that function has **no `, returning a number` clause at all**, i.e.
it's recorded as void. A consumer that calls it and uses the result in
arithmetic still happens to compile and run correctly in the case tested
(the value that lands in `rax` is right regardless of what the `.lib`
claims), so this isn't visibly breaking simple programs today — but the
`.lib` is describing the wrong signature for any function with real logic
before its return, which is the common case, not the exception. This is
a distinct, pre-existing defect from the type-vocabulary gaps plan 280 is
about — it affects `number`/`text`/`boolean` too, not just the types
missing from Gate B's list — but it directly undermines S2's goal: unifying
the *vocabulary* across four gates does nothing if the return type still
silently evaporates whenever a function has a body. **Recommend S2 treat
"Gate B doesn't set `return_type`" as an in-scope fix, not a follow-up** —
otherwise "every type legal in return position" will be true of the
grammar and false of what actually reaches the analyzer/codegen/`.lib`
emitter for any non-trivial function.

### Minor: `value`'s type-position match is case-sensitive where `.lib`'s isn't

Not a blocking finding, noted for S2's "one shared routine" pass: the
`value` keyword-as-type checks in `src/parser/mod.rs` (`parse_function_def`
param/return, `parse_typed_var_decl`) all compare with exact `n == "value"`,
while `src/lib_file.rs:175`'s equivalent check uses
`n.eq_ignore_ascii_case("value")`. `Value called "x"` and `value called
"x"` currently behave differently depending on which of the two parsers
sees them. Worth reconciling as part of building the one shared routine,
not worth a standalone fix.

## Summary

**20 of the 44 primary-table cells fail today**, plus the separate
`file`-as-local-variable gap (not one of the 44, but explicitly asked
for), plus the Gate-A/Gate-B split inside the `fn return` column itself.

By classification:

- **Parser gap — 16 cells, cheap, no design work needed:** `float` (4/4
  cells), `time` (4/4), `list`/`map`/`buffer` (`fn return` + `.lib
  return`, 2 cells each = 6), `value` (`fn return`, 1), `file` (`fn
  return`, 1). Plus, outside the 44-cell table: `file` as a local
  variable. All of these have a working, verified value representation
  already (confirmed by reading and running the codegen, not assumed) —
  the fix in every case is adding the missing token to a `match`, in one
  or more of five known sites: `src/parser/mod.rs:4077-4090` (fn param),
  `4143-4157` (fn return, gate A), `2055-2087`/`2068` (fn return, gate
  B — needs the whole vocabulary added, not per-type patches),
  `1423-1621` (local decl — `file` only), and `src/lib_file.rs:169-206`
  (`.lib`, both positions). Two codegen noun tables
  (`src/codegen/mod.rs:262-274`, `281-290`) need matching arms so `.lib`
  emission can actually produce the newly-legal return nouns.
- **Representation gap — 4 cells, needs a design decision, not a
  one-line fix:** `timer` in all four positions. It has no register-sized
  runtime value — it's a 48–56-byte in-place stack structure addressed by
  pointer for every operation. Passing/returning it by value the way
  every other type is handled would either truncate it or hand out a
  dangling stack address. Recommend deciding between an opaque-handle
  design (heap-allocate, pass/return a pointer) or making the current
  exclusion an explicit, reasoned diagnostic instead of the generic
  "unsupported type" text — the latter is the cheaper correct outcome
  absent a concrete need for timers to cross a function boundary.
- **Deliberate restriction with a real, already-good reason — 0 cells.**
  Nothing measured here should stay rejected for a reason that isn't
  simply "nobody's written the grammar arm yet" or (for `timer`) "no
  design decision has been made." There is no case in this audit where
  the current rejection is correct and should be preserved as-is.

**Types that are pure one-line-per-site fixes:** `float`, `time`,
`list`, `map`, `buffer` — plus `value` and `file`, whose only remaining
gaps (`fn return` gate B, and for `file`, local declaration) share the
exact same shape.

**Types that need a design decision before any code changes:** `timer`
— and only `timer`. Its exclusion is real and, right now, correct; it
should stop looking like an oversight (fix the diagnostic to name the
reason) whether or not the by-reference design work happens.

**Independent of type vocabulary, worth carrying into S2:** the
`fn return` position is gated twice, inconsistently, and the second gate
(`parse_return`) silently discards the function's declared return type
for every type whenever `Return` isn't the function's first statement.
Unifying the four *lists* without also unifying *these two gates into
one* — and making that one gate actually set `return_type` — would leave
plan 280's target unmet for any function with a real body.
