# Report: #104 — the byte-iteration sentence

Worktree `wt-fix-104`, branch `fix/bug-104-each-byte-from-buffer`, off
`main` at `4995394` (v0.4.14). The caret half of #104 shipped in 0.4.14
already; this pass builds the other half — the owner's ruling
(2026-08-29 07:02): `each byte from buffer` should take the same shape
as `each item from list`.

**Stopped STAGED**, gate green. `git add -A && git diff --cached >
~/scr/english/vox-notes/parked/fix-bug-104.patch` (635 lines).

## The grammar as built

- `each <name> from <buffer>` (the universal loop-expansion clause —
  `print each X from data`, `append each X from data to out`,
  `function of each X from data`, chained `each` grids, `arguments's
  all`-style clauses — everything `try_parse_each_from` serves) and
  `For each <name> from <buffer>,` both accept a buffer wherever they
  accepted a list. Each iteration binds the loop variable to one byte's
  value, a number 0–255, in order 1..size — the same value `byte N of
  <buffer>` yields. Fixed and dynamic buffers, buffer parameters inside
  functions, and a `Free`d buffer (reads as size 0 → zero iterations, no
  error) all take this path.
- `byte` is now legal as the loop-variable name in that one position.
  `byte` stays reserved everywhere else (`byte N of <buffer>`, `Set
  byte N of <buffer> to ...`) — this is narrower than the documented
  "contextual keyword" family (`start`/`send`/`capacity`/…), which are
  free identifiers everywhere outside their one fixed position; `byte`
  is free only as the `each ... from` loop variable and, by
  consequence, as a bare reference to that bound variable inside the
  loop body. I did not add it to LANGUAGE.md's "Two classes of special
  word" contextual-keyword list for that reason — see Questions below.

## Files touched

**Parser**
- `src/parser/control_flow.rs` — `try_parse_each_from` and `parse_for`
  each gained a `Token::Byte => { self.advance(); "byte".to_string() }`
  arm, mirroring the existing `Token::Number => "number"` arm right
  above it.
- `src/parser/expressions.rs` — `parse_primary`'s `Token::Byte` arm now
  tries the `byte N of <buffer>` reading first (index expression, then
  `of`); on failure to find either, it rewinds and reads `byte` as a
  plain `Expr::Identifier("byte")` instead of hard-erroring. This is
  what makes `Set total to total add byte.` work inside a byte-iteration
  loop body — a bare `byte` there is not the start of a byte-access
  expression.

**Analyzer**
- `src/analyzer/scope.rs` — `non_collection_kind` no longer classifies a
  buffer identifier as a refused kind (the `is_buffer_variable(name) =>
  Some("buffer")` arm now returns `None`). The refusal hint for every
  other rejected kind (map still excepted, it has its own hint) now
  reads "`each ... from` walks a list, a range, a buffer's bytes, or
  `arguments's all`". Doc comments on `non_collection_kind` and
  `check_loop_collection` updated to describe buffer as a legal walk,
  not a refused one.
- `src/analyzer/statements.rs` — `Statement::ForEach`'s analysis arm
  detects a buffer collection (`Expr::Identifier` name in
  `buffer_variables`) and types the loop variable `Type::Integer`
  (matching `Expr::ByteAccess`'s own type), skipping the
  mixed-list/element-type machinery that only makes sense for a list.

**Codegen**
- `src/codegen/statements.rs` — `Statement::ForEach` gained a buffer
  branch (checked via `is_buffer_expr`, ahead of the list-header logic)
  that walks index 1..=`BUFFER_LENGTH`, reading each byte through
  `BUFFER_DATA_ADDR` — the exact macros (`core.asm`) `byte N of
  <buffer>` (`Expr::ByteAccess`, `src/codegen/expr.rs`) and `Set byte N
  of <buffer> to ...` (`Statement::ByteSet`) already use. No coreasm
  changes were needed; `_buffer_length`/the data-offset macro already
  expressed exactly "length, then byte i".

**Docs**
- `LANGUAGE.md` — the Loop Expansion "Supported collections" list gains
  a "A buffer's bytes" bullet; the Buffer Byte Access subsection gains
  an "Iterating bytes" paragraph + two-line example (`a buffer called
  data is "AB". For each byte from data, print byte.`) — this exact
  example is pinned verbatim as test 594.
- `docs/BUGS_FOUND.md` #104 — status line now state-first ("Fixed in
  v0.4.15 — …"), history paragraphs kept; a new "Fix — the
  byte-iteration sentence (v0.4.15)" paragraph appended after the
  existing caret-fix paragraph, describing what actually landed.
- `CHANGELOG.md` — new `## [Unreleased]` section above `## [0.4.14]`
  with the `### Added` entry the brief specified.

## Tests

Numbered from 587 (`tests/NNN_slug.vox` + `.expected`, all green):
- 587 fixed buffer, 588 dynamic buffer, 589 empty buffer (zero
  iterations, line after runs), 590 `For each byte from …,` summing,
  591 a `Free`d buffer (zero iterations), 592 a buffer parameter inside
  a function, 593 a non-`byte` variable name (`octet`), 594 the
  manual's own "Iterating bytes" example verbatim.
- 595 (new, not in the original numbered list — see "Not asked for"
  below): `append each part from sink to out.` now legitimately
  appends byte values into a list.

`compile_fail`:
- 275 (`_foreach_over_buffer_anchors_at_use_site` →
  `_foreach_over_number_anchors_at_use_site`): a buffer is now legal, so
  the caret-misanchor regression was moved onto a `number` collection,
  same three-line shape, same line:col (9:23) by coincidence (the
  `Print each octet from <name>.` prefix is unchanged length).
- 276 (map): untouched, still green — map stays refused, same hint text.
- 280 (new): `print each byte from <map>` is still refused with the same
  message/hint as 276 — pins that the `byte` contextual-keyword parsing
  doesn't accidentally widen which *collections* are legal, only which
  *loop-variable spellings* are.

**Gate:**
```
cargo test --release       330 passed; 0 failed (unit + compile_fail corpus)
VOX_CORE_PATH=$PWD/coreasm ./test.sh
  Passed:  644
  Failed:  0
  Skipped: 6   (pre-existing: manual mount/reboot/pivot cases, no .expected)
  Total:   650
  ALL TESTS PASSED
```

## Something the brief didn't anticipate

`tests/compile_fail/097_foreach_over_buffer.vox` (a legacy-named,
pre-`_anchors_at_use_site` compile_fail case, not mentioned in the
brief) pinned exactly the old bug #49 behaviour: `append each part from
sink to out.` used to be refused outright because a buffer walked as a
list misread its own header. That refusal is now wrong — the sentence
is legal and correct (`out` ends up `[97, 98, 99]` for `sink is "abc"`,
not the old silently-misread header). I removed that compile_fail case
(`git rm`, both `.vox` and `.err`) and replaced it with a passing
regression, test 595, whose comment records the history (#49 → #104)
so the removal isn't silent. I searched the rest of `tests/compile_fail`
for any other case assuming buffer-loop refusal (grep for `each` +
buffer-shaped names) and found none.

## Anything I could not do

Nothing in the brief's "What to build" was skipped. The one deliberate
scope call is the contextual-keyword documentation question below.

## Questions for the master

1. **Should `byte` be listed in LANGUAGE.md's "Two classes of special
   word" → Contextual Keywords prose** (the `start`/`send`/`capacity`/…
   family, ~line 5171)? I left it out: those words are free identifiers
   *everywhere* outside their one fixed grammatical position (`a number
   called capacity is 1.` compiles); `byte` is not — it's free only as
   the `each ... from` loop-variable spelling (and, as a consequence,
   as a bare reference to that bound variable inside the loop body).
   `a number called byte is 1.` and `Set byte to 5.` still hard-error,
   same as before this fix. Documenting it in that list without a
   caveat would overclaim; adding a caveat felt like it was drifting
   past the brief's explicit scope ("byte is a legal loop-variable name
   **in that position**"). Said so here rather than deciding it myself.
2. Bullet 6 said "compile_fail from 280" — I read that as "the next
   available compile_fail number is 280, use it if a new case is
   warranted" rather than "add a redundant map-refusal test", since 276
   already pins the map case. I used 280 for the `byte`-as-loop-var
   interaction with a map instead (see Tests above), which felt like
   the genuinely new thing worth pinning. Flagging the reading in case
   a different test was intended there.
3. Discovered and fixed the stale `097_foreach_over_buffer.vox`
   compile_fail case (see above) — not in the brief's list, but its
   premise (buffer-as-collection is always wrong) directly contradicted
   the feature being built, so leaving it in place would have made the
   gate red. Flagging the removal explicitly since it's a deletion, not
   an edit.

## Review round 1

Master accepted the work (probes on the built binary all passed: manual
example, expansion form, arithmetic on `byte`, `byte N of` inside the
loop, text still refused, nested byte/octet loops, `byte` still
reserved as a plain name outside the loop-var position, freed buffer
zero iterations). One addendum requested: bug #49's Fix paragraph
(`docs/BUGS_FOUND.md`, still described the buffer walk as refused)
now ends with "Superseded in v0.4.15 by #104: a buffer is now a legal
`each ... from` collection walked byte by byte; `compile_fail/097`
became run test 595." #49's Status line is unchanged (still **fixed**).
Re-staged and re-parked to the same patch path.

DONE — stopped staged, patch parked.
