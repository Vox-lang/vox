# Plan 297 — a comma separates a `but if` condition from its action

**Status:** specced 2026-08-14, owner-requested. Targets **v0.4.0** — this is
a breaking syntax change, and the project's versioning policy takes a minor
bump for breaking changes while pre-1.0. Baseline is v0.3.6, which shipped
the generalization in [plan 291](291_but_if_conditional_sugar_generalization.md).

## The problem

`but if` is the only conditional in the language with no marked boundary
between its condition and its action:

```
but if n modulo 2 is equal to 0 print "even"
```

Everywhere else, Vox marks that boundary explicitly. The statement form uses
`then,`:

```
If n modulo 2 is equal to 0 then, print "even".
But if n modulo 3 is equal to 0 then, print "fizz".
Otherwise, print "odd".
```

So a reader parsing `but if <cond> <action>` has to infer where the condition
stops by knowing which words can continue an expression — the one place in the
language that asks them to do that.

**This got worse in v0.3.6.** Plan 291 generalized the branch so *any*
statement can be the action. Previously the action was almost always `print`
(or `append`), which made the boundary easy to spot. Now it can be:

```
but if f is equal to "sysfs" Mount "sysfs" at "/sys" with type "sysfs"
but if x is equal to 2 Set total to 99
but if x is equal to 2 bump
but if d is equal to "proc" 'mount proc'
```

The more shapes the action can take, the more work the reader does, and the
less the eye can rely on a familiar keyword marking the transition.

## What is *not* wrong

The parser is not currently ambiguous, and this plan is not a bug fix.
Attempts to make it mis-parse the boundary — including a bare single-word
function call as the action (`but if x is equal to 2 bump.`), which is the
sharpest case, since a bare identifier is also a valid expression operand —
resolve correctly, because statement-introducing keywords are disjoint from
expression continuations. This is an ergonomics and consistency change, and
the plan should not claim otherwise in its commit message or CHANGELOG entry.

## The change

Require a comma between the condition and the action:

```
print each number from 1 to 15,
    but if the number modulo 15 is equal to 0, print "fizzbuzz",
    but if the number modulo 3 is equal to 0, print "fizz".
```

### Why a comma, and not `then,`

`then` is precisely what distinguishes the **statement** form from the
**suffix** form:

| Form | Shape |
|------|-------|
| statement | `If <cond> then, <action>. But if <cond> then, <action>.` |
| suffix | `<base action>, but if <cond> <action>.` |

Reusing `then,` in the suffix form would make the two indistinguishable to
both reader and parser. A bare comma is distinct, and it already reads as
"clause boundary" everywhere else in Vox.

### Disambiguation the implementation must handle

Comma is already doing three jobs in this construct. After the change the
parser must distinguish, at a comma:

1. **condition → action** (new): comma followed by a statement.
2. **chain continuation**: comma followed by `but` / `otherwise`.
3. **action-list continuation inside a branch**: comma followed by another
   action belonging to the same branch (e.g. an `On error` handler's actions).

(2) is already distinguished by lookahead for `but`/`otherwise`. (1) and (3)
are distinguished by position — (1) can occur only once per branch, directly
after the condition, before any action has been parsed. State that invariant
explicitly in the implementation rather than relying on it emergently.

## Migration

Breaking changes get a window rather than a flag day:

1. **v0.3.x (optional):** accept the comma where it is currently absent, so
   both spellings parse identically. Document the comma form as canonical in
   LANGUAGE.md and use it in every example. No existing program breaks.
2. **v0.4.0 (required):** omitting the comma becomes a compile error. The
   diagnostic must name the fix directly — point at the token where the action
   begins and say a comma is required between a `but if` condition and its
   action, in the style of the existing reserved-word and unmatched-brace
   diagnostics (a caret at the offending position plus a one-line remedy).

Step 1 can land in a patch release; only step 2 forces the minor bump.

## Scope

In scope: the `but if` / `otherwise` **suffix** form, in both the plain and
loop-expansion shapes.

Out of scope: the `If ... then, ... But if ... then, ... Otherwise, ...`
statement form, which already has its separator and must be left alone —
including verifying it still parses correctly afterwards, since the two forms
share `parse_conditional_*` machinery.

## Acceptance

- Both spellings parse identically in step 1; the comma-less spelling errors
  with the diagnostic above in step 2.
- Every `but if` example in LANGUAGE.md and every `tests/butif_*` fixture uses
  the comma form.
- The statement form is unaffected — `If num is equal to 1 then, print "one".
  But if num is equal to 2 then, print "two". Otherwise, print "other".` still
  behaves correctly.
- `./test.sh` and `cargo test --release` fully green.

## Dependencies

- [291](291_but_if_conditional_sugar_generalization.md) — the generalization
  that makes this worth doing.
- `docs/BUGS_FOUND.md` #14 (chain termination by a nested clause's period)
  should be resolved first. It touches the same chain-continuation logic, and
  landing both at once would make either one harder to review in isolation.
