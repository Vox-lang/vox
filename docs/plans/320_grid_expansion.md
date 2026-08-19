# 320 — N-ary loop expansion: chained `each` clauses are a grid

**Status:** approved by TheJostler (2026-08-19); built on
`feature/grid-expansion`. A fix to a gap in a documented promise, parsed
and desugared in the parser — the analyzer and codegen need no changes,
because the desugaring reuses the existing nested `For each` machinery.

## Versioning

This ships as a **patch** release, not a minor one. LANGUAGE.md already
promises that `each...from` is a *universal* loop expansion that "works
with any action" — the spec committed to universality before this work.
Rejecting multiple `each` clauses in one sentence, or an expansion mixed
with a fixed argument, was therefore a **gap in a documented promise**, not
a missing feature: the language said it could do something the parser then
refused to do. Closing that gap is a fix. The CHANGELOG records it under
**Fixed**, worded as loop expansion now honouring its documented
universality — not under Added.

## The feature in one sentence

A call's argument list may contain **any number of `each <name> from
<collection>` clauses**, and the action executes once per element of the
**Cartesian product**, exactly as if the clauses were nested `For each`
loops written left-to-right, outermost first.

```vox
'pair' of each x from [1, 2] and each y from [10, 20].
```

runs `'pair'` four times — `(1,10), (1,20), (2,10), (2,20)` — row-major,
identical to:

```vox
For each x from [1, 2],
    For each y from [10, 20],
        'pair' of x and y.
```

## Motivation

Consistency with nested `For each`. Until now a loop expansion consumed
the *entire* argument tail: an expansion plus any second clause — another
`each`, or a plain fixed argument, in either order — was a parse error
("Expected a statement, got `And`"). The only way to iterate two
collections into one call was to write the nested loops by hand, or to
funnel one collection through a mutable global the inner loop read. The
grid spelling removes that restriction: the sentence says what the nested
loops say, with no workaround.

## The rules, all of them

1. **Grammar.** `args ::= arg_clause ("and" arg_clause)*` where
   `arg_clause ::= loop_expansion | expr`. The formal grammar in
   LANGUAGE.md is updated to match.
2. **Semantics = desugaring.** N expansion clauses desugar to N nested
   loops, left-to-right = outermost-to-innermost. Fixed (non-`each`)
   argument clauses ride along and are **evaluated per call** — the
   natural consequence of the desugaring, since each call sits inside
   every loop.
3. **Unlimited clause count.** Two, three, five — no cap. The
   implementation is genuinely N-ary (a loop over clauses), not a
   hardcoded two-clause special case.
4. **Arity is checked.** The number of argument clauses must equal the
   callee's parameter count, same as today. A one-parameter action with
   two `each` clauses is a compile error with a clear diagnostic (e.g.
   `` `print` takes one value but this sentence supplies 2 `each`
   clauses. ``). This is deliberate: it is what stops `print each x from
   A and each y from B` from being misread as concatenation.
5. **Empty collection anywhere → zero calls.** Consistent with the
   documented `print each n from [].` behaviour.
6. **An inner collection may use an outer clause's variable.**
   `'pair' of each x from [1,2,3] and each y from 1 to x.` is legal and
   gives triangle iteration — it falls straight out of the desugaring
   (the inner loop's collection is inside the outer loop's body).
7. **Duplicate loop variables in one sentence are a compile error**
   (`each x from A and each x from B`), with a diagnostic naming the
   variable.
8. **`but if` clauses** attach to the innermost iteration and their
   conditions can reference **all** loop variables (every loop is
   outside the conditional).
9. **`treating X as Y`** stays per-clause, attached to its own expansion
   (the grammar already scopes it that way).
10. **After the loop**, every loop variable retains its last-iteration
    value — the documented single-variable shadowing rule, applied to
    each variable independently. (For a range clause, "last-iteration
    value" means what it means for a handwritten `For each ... from 1
    to N`: the counter that ended the loop.)
11. **Zip is explicitly out of scope.** Do not build it; the parse is
    structured so a trailing marker word could later select it. The
    design note records `respectively` as the likely future marker.
12. **Specialized action forms** (`append each ... to dest`,
    `open ... at each ...`, `Print each ...`) keep working exactly as
    today with one clause. Whether they accept multiple `each` clauses
    is governed by rule 4 (arity): if the action has only one value
    slot, multiple clauses are the arity error. No new multi-slot
    behaviour is invented for them.

## The rejected alternative: zip by default

The obvious competing semantics for `each x from A and each y from B` is
**zip** — iterate the two collections in lockstep, pairing the first with
the first, the second with the second. It was rejected for two reasons.

1. **Comprehension precedent.** Every list-comprehension syntax in common
   use (Haskell, Python, Rust) reads two generators joined by `and`/`,`
   as a Cartesian product, never a zip. A reader who has seen any of
   those reads `each x from A and each y from B` as "for every x, for
   every y" — the product. Zip-by-default would surprise that reader.
2. **English.** "Each x from A and each y from B" reads as "every x and
   every y" — all pairs. English's own zip marker is **respectively**:
   "x from A and y from B, respectively" pairs them in lockstep. The
   word is unused, so it is left as the natural future marker for a zip
   mode if one is ever wanted.

## Compatibility

A **pure extension.** Every program that compiles today keeps its
meaning: today's spellings of the new form are all parse errors (an
expansion followed by `and` was rejected at the `and`), so nothing that
compiled before changes meaning. The single-clause form desugars to
exactly the loop it desugared to before; only the parser path that
collects clauses was generalized.

## Where it lives in the compiler

Parser-only. `parse_arg_clauses` collects the `and`-separated clause
list (each clause an expansion or a fixed expression); `finish_grid`
wraps the call in one nested loop per expansion clause, leftmost
outermost, with the `, but if ...` / body / period tail attached to the
innermost iteration. The analyzer already scopes nested `For each`/`For`
variables (an inner collection may reference an outer variable), and the
codegen already lowers nested loops — so neither needed a change. The
one-value-slot actions (`print`, `append`, `open`) reject a second
`each` clause with the rule-4 arity diagnostic.