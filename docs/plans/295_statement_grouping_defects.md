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

## What to do

Findings 2 and 3 are very likely one root cause; finding 1 may be a third
site with the same shape. **Root-cause them before patching any individual
symptom.** A fix that special-cases these three programs and leaves the
boundary rule inconsistent is not what this plan is asking for — the plan 282
red team demonstrated that patching one side of this rule reliably breaks
another.

Order of work:

1. **Finding 1 first**, because it is the regression and the fix may be
   narrow: the generalised `but if` path should either consume its
   continuation correctly or refuse to parse, never accept-and-discard. If a
   full fix is large, making it a compile error again — restoring 0.3.2
   behaviour — is an acceptable interim, but say so explicitly rather than
   leaving silent loss in place.
2. **Findings 2 and 3 together**, as one root cause if the evidence supports
   it.

Each fix needs a regression test that fails without it. Given how this family
behaves, also add tests asserting the *neighbouring* shapes still work — the
characteristic failure here is fixing one side and silently breaking another.

## Verification

- `cargo build --release` — 0 warnings
- `cargo test --release`
- `./test.sh` — baseline **219 passed / 0 failed / 6 skipped**, and it
  includes a compile check over every file in `examples/`
- The three programs above produce their **Expected** output
- Re-run the plan 294 PoCs under `tests/retype_audit_pocs/` — all 18 must
  still be closed (non-zero exit)

## Out of scope

- The type-immutability work from plan 294 — settled, do not revisit
- `.lib` signature verification (plan 294 findings 19/20)
- Casting a dynamically-tagged `value` (plan 294 finding 21)
