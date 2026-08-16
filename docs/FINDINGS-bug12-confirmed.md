# BUGS_FOUND #12 — CONFIRMED, with a minimal repro

> **SUPERSEDED.** The conclusion below — that this is a defect needing a
> parser change — is **wrong**. Periods stack: one period closes one open
> clause, so N periods close N levels, and that is how an author chooses
> which `if` an `Otherwise` continues. The compiler was correct throughout;
> what was missing was documentation. See LANGUAGE.md, *Closing more than one
> level*, and the #12 entry in `BUGS_FOUND.md`. The reproductions in this
> document are accurate and still worth reading; every conclusion drawn from
> them is not. Retained as a record of the mistake.

**Status:** confirmed 2026-08-15 against `main` at v0.3.6 (post-merge of
PR #143, i.e. with the #14 chain-termination fix already in). **Not fixed.**
Not a regression from the 0.3.6 work — the original reporter hit it on 0.3.5.

This supersedes the earlier "could not reproduce" assessment. That assessment
was wrong, and the reason is recorded at the bottom so the same mistake is not
repeated.

---

## The repro

```vox
a number called guard is 0.
a number called escaped is 34.
While guard is less than 3,
  if escaped is equal to 92 then,
    If escaped is equal to 34 then, print "quote".
    But if escaped is equal to 117 then, print "unicode".
  Otherwise,
    print "plain".
  increment guard.

Print "loop finished".
```

**Hangs forever, printing nothing at all** — not even `plain`, which is the
branch that should be taken (`escaped` is 34, not 92). No error, no warning,
no output. `timeout` kills it at exit 124.

### The reporter's own workaround works

Give the *inner* chain its own `Otherwise` and it behaves correctly:

```vox
    If escaped is equal to 34 then, print "quote".
    But if escaped is equal to 117 then, print "unicode".
    Otherwise, print "other escape".      (<- added)
```
→ `plain` / `plain` / `plain` / `loop finished`, exit 0.

## What is actually happening

The hang is a *consequence*, not the defect. Narrowing:

| shape | result |
|---|---|
| nested `If` as last action inside an `if … then,` branch, then more statements | **everything after is swallowed**, including code *after* the enclosing loop |
| same, with no outer `Otherwise` | same |
| flat `if`, no nesting | correct |

Minimal demonstration — no `While` involved is needed to see the swallowing,
but with a loop it becomes an infinite one:

```vox
a number called g is 0.
a number called e is 34.
While g is less than 2,
  if e is equal to 92 then,
    If e is equal to 34 then, print "q".
  Otherwise,
    print "plain".
  increment g.

Print "done".
```
→ **no output at all.** `Print "done"` — which is after the loop entirely — is
absorbed too.

So: **a nested construct as the last action of an outer `if … then,` branch
leaves that outer branch open, and it goes on consuming every following
statement**, through the end of the loop body and past the loop itself. When
one of the swallowed statements is the loop's own increment, the loop never
terminates.

## Why this is not simply "as documented"

LANGUAGE.md's termination rule 1 says a period closes only the innermost open
clause, so the inner `If`'s period closing only the inner `If` is *correct*.
Rule 2 says a blank line force-closes everything — but that would also close
the enclosing `While`, so it cannot be used to close just the outer branch.

That leaves a genuine expressiveness gap: **there is currently no way to write
"an if-chain nested inside an if branch, followed by more statements in the
same loop body."** The reporter's workaround (give the inner chain an
`Otherwise`) works, but that is a coincidence of how the chain terminates, not
a documented construct — and nothing tells an author they need it.

This is the same *family* as BUGS_FOUND #14 (a `but if` chain closed by a
nested clause's period, fixed in 0.3.6) but for the **statement** form of
`If`/`But if`/`Otherwise`, not the suffix form.

## Why it matters

- **Silent infinite loop.** No error, no warning, no partial output. The
  program simply never returns.
- **Silent no-op** in the non-loop case: code after the construct is absorbed
  and never runs, exit 0.
- It is reachable from ordinary control flow, and the swallowing reaches
  *past* the enclosing loop, so the blast radius is not local.

## Open design question — needs the language owner

This is not obviously a pure bug fix, because the current behaviour follows
rule 1 exactly. Roughly the options:

1. **Make a nested construct's terminator close the outer branch too** when
   the outer branch is itself an `if … then,` body. Changes rule 1's scope;
   needs care not to break the many places nesting currently works.
2. **Introduce an explicit closing form** for a branch, so an author can end
   the outer branch without a blank line closing the enclosing loop.
3. **Diagnose it.** Leave parsing as-is but detect the shape — an outer branch
   still open when the enclosing loop's body ends — and refuse, or warn,
   naming the fix. Cheapest, and consistent with the "function still open at
   end of file" warning added in 0.3.6.

Option 3 is the smallest change that removes the silent failure, and could
ship in a patch. Options 1 and 2 are language changes and belong with the
0.4.0 breaking batch alongside plan 297.

## Why the earlier assessment was wrong

The report describes **two** shapes. I built and tested **Shape B** (an outer
`If` whose last action is a `While`, followed by another `If`), found it
behaved correctly, and concluded the whole item was unreproducible. I never
constructed **Shape A** — the `While` body whose nested if-chain lacks an
`Otherwise` — which is the one that reproduces.

Lesson: when a report describes multiple shapes, each one needs its own repro
before any of them is dismissed. A single failed reproduction does not clear
the report.

Related: the same investigation earlier confirmed BUGS_FOUND #11 only *after*
#14 turned out to be its cause — a second case where an item first judged
unreproducible was real.
