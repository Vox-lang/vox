# 316 — String literals in function-body conditions

**Status:** staged 2026-08-18. Not started. Independent of plan 315 and
may land before, after, or between its classes — but not in the same
worker session.

**The defect:** BUGS_FOUND.md #21. Inside a function body, a string
literal on either side of an `If`/`While` comparison is resolved as a
variable name:

```vox
To g with a text called w.
  If w is not "banana" then,
      Return a number, 1.
  Return a number, 0.

Print g of "hang".
```

fails with `Unknown variable: banana`. The identical comparison works at
top level, works in `Return a boolean, w is "banana".`, and works once
the literal is bound to a local. All four comparison spellings fail the
same way; number literals are unaffected.

**Authority:** LANGUAGE.md, "Names and identifiers", rule 1: `"..."` is
never an identifier, in any position. The current behaviour violates the
language's own rule; this is a compiler fix, not a design change.

## Scope

- Find where function-body condition parsing (or the analyzer pass over
  it) diverges from the top-level path in its treatment of string
  literals. The divergence itself is the interesting part: whatever
  causes it may affect other expression positions inside function bodies,
  so **map the divergence before fixing it** and report anything else it
  mis-handles.
- Fix so that a string literal in any condition position is a literal.
- Do not change anything else about condition parsing.

## Tests

The repo has **zero coverage** of this shape (verified by grep — that is
how it survived to 0.4.2). Add `tests/bugs_found_21_literal_condition.vox`
following the `bugs_found_NN` convention:

- text parameter compared to a literal with all four spellings, inside a
  function, both `If` and `While`
- the same at top level (guarding the path that already works)
- a number literal in a function-body condition (already works; pins it)
- interpolated comparison after binding (the workaround, still legal)

## Gates

`cargo test`, `./test.sh`; baselines cargo ≥ 312, integration ≥ 355 plus
new, skips ≤ 6, zero warnings. Master commits; worker stops before
committing.
