# Plan 295 — statement-grouping defects: statements silently leave the block they were written in

**Status:** specced 2026-08-08. Three defects, all reproduced by the plan
author against `23bc193` (v0.3.3) and, where noted, against `v0.3.2`.

## The shared symptom

A statement written inside a block — a loop body, a function body, an `if`
body — is silently parsed as belonging to an **outer** block, or dropped
entirely. Nothing is reported at compile time. The program builds cleanly and
does the wrong thing.

This is the same family the plan 294 audit flagged as residual and the plan
282 red team catalogued as "loop body ejects a statement" / "nested if steals
outer actions". It was never root-caused. These three repros are the smallest
cases found so far, and finding 1 is a **regression introduced in 0.3.3**.

The unifying question the parser answers wrongly: **where does a block end?**
The disambiguation rule is stated in prose as *"is the following text
independently valid as its own top-level sentence?"* — the implementation
substitutes a one-token lookahead on `Comma`, which is not equivalent.

---

## Finding 1 — CRITICAL, and a 0.3.3 regression: `but if` on `append`
## silently discards the rest of the program

```vox
a buffer called line is 64 bytes in size.
a number called v is 1.
print "BEFORE".
Append "." to line, but if v is equal to 1 append "#" to line.
print "AFTER".
print "SECOND AFTER".
```

**Actual output:** `BEFORE`, and nothing else. Both trailing `print`s are
discarded, and `line` is never appended to either.

**Expected:** `BEFORE`, then the append happens, then `AFTER`, then
`SECOND AFTER`.

**This is a regression.** On `v0.3.2` the same program is a clean compile
error — `error: Expected a statement, got Comma`. Plan 291 (which generalised
`but if` beyond bare `print`) landed after the v0.3.2 tag, so 0.3.3 turned a
loud rejection into silent code loss. That direction is the worst possible
one and is why this finding is first.

`print` + `but if` works correctly, so the defect is specific to the
generalised (non-`print`) path:

```vox
a number called v is 1.
print "plain", but if v is equal to 1 print "override".   (correct: prints "override")
```

**Severity:** critical. Silent loss of arbitrary amounts of code.

---

## Finding 2 — a function body's trailing statement escapes to top level

```vox
To 'do thing' with a number called n.
    if n is 1 then,
        print "inner".
        Return.
    print "ESCAPED".

print "MAIN".
```

**Actual output:** `ESCAPED`, then `MAIN` — even though `'do thing'` is
**never called**. The statement after the `Return.`-terminated `if` is parsed
as top-level code rather than as part of the function body.

**Expected:** `MAIN` only.

Both of these are required to trigger it; removing either gives correct
behaviour:

- the `if` body must end with `Return.`
- at least one statement must follow the `if` inside the function

**Pre-existing:** `v0.3.2` behaves identically. Not a regression.

**Where this bit in practice:** `voxos`'s `sh.vox` defines
`To 'change directory' …` in exactly this shape, so every run of the shell
printed `cd: too many arguments` at startup, from a function that was never
invoked.

**Severity:** critical. Code moves silently between scopes.

---

## Finding 3 — one extra statement ejects the loop tail and kills an `if`

```vox
a number called k is 0.
a number called p is 0.
While k is less than 2,
    increment k,
    if p is 9 then, print "never".
    print "EXTRA k={k}".
    if p is 0 and k is 1 then,
        print "BRANCH k={k}".
    print "TAIL k={k}".
```

**Actual output:** `EXTRA k=1`, `EXTRA k=2`, `TAIL k=2`

**Expected:** `EXTRA k=1`, `BRANCH k=1`, `TAIL k=1`, `EXTRA k=2`, `TAIL k=2`

Two things go wrong at once: the second `if`'s body never executes at all, and
`TAIL` is ejected from the loop body so it runs **once, after** the loop
instead of once per iteration.

Delete the single line `print "EXTRA k={k}".` and the same program behaves
correctly (`BRANCH k=1`, `TAIL k=1`, `TAIL k=2`). So whether a statement
belongs to the loop depends on how many statements precede it — the parser's
notion of the body boundary is not stable under insertion.

**Pre-existing:** `v0.3.2` behaves identically. Not a regression.

**Where this bit in practice:** it is what still blocks `voxos`'s `sh.vox`
from executing commands after its paragraph breaks were removed.

**Severity:** critical. Silent wrong control flow.

---

## Findings 2 and 3 reclassified: malformed source, not compiler defects

**Status:** investigated 2026-08-09. Neither finding is a parser bug. This
section replaces the "root-cause findings 2 and 3" instruction below with
what the investigation actually found — the plan's own premise about "the
rule" was wrong, and per this plan's own instruction ("if you find the rule
as specified is itself wrong or ambiguous, say so and argue it"), here is
that argument.

**The rule this plan opens with — "is the following text independently
valid as its own top-level sentence?" — is not the language's rule.** It is
the exact speculative-comma-lookahead heuristic that
`docs/plans/282_while_ignores_paragraph_break.md` built, red-teamed, and
explicitly discarded (see that plan's "History" section) after finding six
independent correctness bugs and an O(N²) parse-time/stack-overflow DoS in
it. That plan replaced it with a different, already-implemented,
already-documented rule (`LANGUAGE.md`, "The termination rule"):

1. A period closes the most recently opened clause — the innermost one
   currently open (`if`, `on error`, `for`, `while`, `repeat`, a function
   body), and only that one.
2. A blank line (paragraph break) force-closes every open clause at once,
   including an enclosing function definition.

Applying rule 1 by hand to both repros — and then confirming empirically by
compiling and running the traced result — reproduces **exactly the current
compiler output**, not this plan's `EXPECTED.md`:

- **Finding 2:** `print "inner".`'s period closes the `if` (rule 1) — the
  `if`'s body is exactly the one action it was given, no more. `Return.` is
  therefore not nested inside the `if`; it is the function body's own next
  direct statement, and a `Return` parsed as a function's own direct body
  statement ends the body early (a deliberate, separate convenience at
  `src/parser/mod.rs:4319-4337`, unrelated to rule 1/2, so a function ending
  in `Return.` doesn't need a trailing blank line to avoid swallowing
  following top-level code). `Return.` was never actually the function's
  last statement here, so `print "ESCAPED".` is left over as a top-level
  statement — which is exactly what runs.
- **Finding 3:** `increment k,` explicitly continues the `while`'s
  sentence; `if p is 9 then, print "never".` is a nested clause whose own
  period closes only it, and the `while` — still open — keeps going without
  needing a comma (the same fallthrough plan 282 confirmed correct). But
  `print "EXTRA k={k}".` is a bare action: nothing is nested open when its
  period is reached, so per rule 1 that period closes the innermost open
  clause, which at that point is the `while` itself. Everything after is
  therefore top-level, run once after the loop finishes — which is exactly
  what runs.

**Both repros are missing a comma at the exact point the author needed to
keep a clause open — not encountering a parser bug.** Rewriting each with
that one comma reproduces the author's evident intent using the existing
rule, with no parser change (verified: see
`tests/p295_statement_grouping_scope.rs`,
`finding2_conforming_rewrite_achieves_the_intended_semantics` and
`finding3_conforming_rewrite_achieves_the_intended_semantics`).

This is structurally identical to plan 282's own "Reclassified: bugs
originally reported as 2 and 3 are malformed source" section — the same
shape of author confusion, the same production file affected
(`voxos`'s `sh.vox`, outside this repo, cited by both plan 282 and this
plan), and the same owner ruling applies: **there is no compiler bug here,
and per plan 282's own hard-won lesson, attempting to make the parser
"smarter" about this ambiguity — rather than diagnosing it — is exactly how
new, worse bugs get introduced** (the six correctness bugs and the DoS in
plan 282's withdrawn first attempt).

That said, this is now the **third** time this exact shape has produced a
bug report against real code. That is real signal that the ergonomics here
are a genuine, recurring foot-gun, even though the rule itself is correct
and sufficient. The recommended follow-up — **not implemented by this
plan** — is a compile-time diagnostic: warn when a self-terminating nested
clause (`if`/`on error`) is immediately followed, with no comma and no
blank line, by more code at the same apparent body level inside an open
`while`/`for`/`repeat`/function, since that shape is exactly where a period
silently closes more than the author's indentation suggests. That is new
work, not a fix to this plan's findings, and deserves its own plan given
how easily a heuristic here goes wrong (see plan 282's History again).

No fix is made to `parse_while`, `parse_block`, or `parse_function_def` for
findings 2 or 3. `tests/p295_statement_grouping_scope.rs` locks in the
current (correct) behavior for both repros as written, plus a conforming
rewrite of each, so a future well-intentioned "fix" here doesn't
reintroduce plan 282's discarded heuristic.

---

## What to do

Findings 2 and 3 turned out not to share a root cause with each other in
the way originally assumed — see "Findings 2 and 3 reclassified" above,
which supersedes this section's original instruction to root-cause them as
one parser fix. Finding 1 is unrelated to that reclassification and is a
real, narrow compiler bug (a 0.3.3 regression).

Order of work:

1. **Finding 1 first**, because it is the regression and the fix may be
   narrow: the generalised `but if` path should either consume its
   continuation correctly or refuse to parse, never accept-and-discard. If a
   full fix is large, making it a compile error again — restoring 0.3.2
   behaviour — is an acceptable interim, but say so explicitly rather than
   leaving silent loss in place.
2. **Findings 2 and 3**: reclassified as malformed source, not compiler
   defects — see above. No fix applies; regression tests lock in current
   behavior instead.

Each fix needs a regression test that fails without it. Given how this family
behaves, also add tests asserting the *neighbouring* shapes still work — the
characteristic failure here is fixing one side and silently breaking another.

## Verification

- `cargo build --release` — 0 warnings
- `cargo test --release`
- `./test.sh` — baseline **219 passed / 0 failed / 6 skipped**, and it
  includes a compile check over every file in `examples/`
- Finding 1's program produces its **Expected** output; findings 2 and 3's
  programs produce the (revised) output in `tests/p295_repros/EXPECTED.md`,
  which now documents the current compiler's actual, correct-per-rule-1
  output for each, plus a conforming rewrite achieving the original intent —
  see "Findings 2 and 3 reclassified" above
- Re-run the plan 294 PoCs under `tests/retype_audit_pocs/` — all 18 must
  still be closed (non-zero exit)

## Out of scope

- The type-immutability work from plan 294 — settled, do not revisit
- `.lib` signature verification (plan 294 findings 19/20)
- Casting a dynamically-tagged `value` (plan 294 finding 21)
