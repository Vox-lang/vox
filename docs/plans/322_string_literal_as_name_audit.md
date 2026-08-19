# Plan 322 — audit: a string literal is never a name

**Status:** approved by TheJostler, 2026-08-19 (night).
**Origin:** three of the four bugs found on 2026-08-19 — #27, #29, #30 —
are the same mistake wearing different clothes: **the compiler treating
one syntactic thing as another.** #29 and #30 specifically are a string
literal's *content* being resolved as a variable name, which
LANGUAGE.md's grammar forbids in as many words:

```
string ::= '"' ... '"'            ; a string literal is data, never a name
```

Bug **#19** (fixed in v0.4.4) was the first of this family and its fix
removed the pattern from five codegen sites. #29 and #30 are two more
that were missed. This plan is the deliberate search for the rest,
before they are found one segfault at a time.

## Why an audit and not just two fixes

#29 and #30 are already fixed (their own PRs). This plan is not those
fixes — it is the recognition that they are **instances of a family**,
and that fixing instances as they surface is slower and less safe than
closing the family.

Two facts make the family bigger than it looks:

1. **The obvious search under-counts.** The pattern
   `Expr::StringLit(name) | Expr::Identifier(name)` appears at **12
   sites** (6 in `src/codegen/tags.rs` alone). But #30 does **not** match
   that shape — it is a bare `Expr::StringLit(s)` whose `s` is then used
   as a lookup key. So a grep for the pattern misses real cases.
2. **Not every site is a bug.** Some positions legitimately accept
   either a bare word or a quoted one — map keys are the obvious
   candidate — and there treating them alike is correct. Each site needs
   judging, not blanket removal.

Therefore: **search by behaviour, not by pattern.**

## The task

- [ ] **Enumerate every site** where a string literal's content is used
      as a name. Start from the grep for
      `Expr::StringLit(name) | Expr::Identifier(name)` (12 sites), then
      widen to any place a `StringLit`'s inner string is passed to
      `variable_types.get`, `variables.get`, `get_var`,
      `global_var_label`, `unprovable_scalars.contains`, the symbol
      table, or any name-resolution helper — including bare
      `Expr::StringLit(s)` arms like #30's.
- [ ] **For each site, decide and record:** is treating a quoted string
      as a name *correct here* (a position that genuinely accepts either
      form), or is it a defect? Write the verdict next to the site or in
      this plan — the record is the deliverable as much as the fix.
- [ ] **Remove it where it is a defect.** The shape of the fix is #29's:
      give `Expr::StringLit` its own arm that treats the literal as data,
      before any name lookup, leaving `Expr::Identifier` untouched.
- [ ] **A behavioural test matrix**, driven by observation not by code
      structure: for each construct that takes a value (list element,
      map value, buffer initialiser, function argument, print, `Set`,
      `treating`, interpolation, return), a program where a string
      literal collides with a variable of each type
      (number/float/text/list/map/buffer), asserting the literal is used
      as data. The 2026-08-19 audit's blast-radius table is the seed:
      list-element and buffer-initialiser were the two live ones; the
      rest were correct and must stay correct.

## The trap, recorded because it caught the master once

A `text`-typed collision produces the **right answer even before a fix**,
because the wrong tag and the right tag are the same value. Any site
validated only against a `text` collision looks correct and proves
nothing. Every test must include a `list` or `number` collision.

## Out of scope

- Bug #27 (`Repeat` termination) is the same *category* — "one
  syntactic thing read as another" — but a different mechanism (a period
  not closing a clause), already fixed, and not part of the literal
  family. Mentioned only to note the pattern; not audited here.

## Reference

Full evening audit, including the blast-radius table and the 12-site
list: `~/scr/english/vox-notes/2026-08-19-evening-bug-audit.md`,
sections J, K, L.
