# Plan 304 — a string literal's content must never resolve as a variable (BUGS_FOUND #19)

BUGS_FOUND #19 documents the crash form of this defect; this plan is the fix,
plus a second, worse manifestation found while scoping it.

## The two manifestations

**Crash (documented in #19):** a variable initialized to a literal equal to
its own name reads its own unwritten slot:

```vox
a text called x is "x".
Print x.
```
→ SIGSEGV (exit 139).

**Silent wrong data (new, worse):** a literal equal to *any other* in-scope
variable's name reads that variable instead of the literal:

```vox
a text called greeting is "hello".
a text called b is "greeting".
Print b.
```
→ prints `hello`. No crash, no diagnostic — `b` holds the wrong text. Any
program is affected the moment a string literal's content coincides with any
in-scope variable name, which is a normal thing for real programs to do
(`"count"`, `"line"`, `"name"`, …).

## The rule being enforced

LANGUAGE.md, *Naming Rules*: "A name is an identifier, never a string
literal … `\"...\"` is never an identifier, in any position." The v0.3.0
split implemented this at the parser level precisely because the pre-0.3.0
literal-or-identifier overload caused silent wrong answers. The codegen
still carries that overload: `Expr::StringLit` arms resolve the literal's
*content* against known variable names before falling back to emitting the
literal bytes. The fix is to make codegen agree with the grammar: **a
double-quoted string literal is data in every position, at codegen time
too.**

## Where the overload lives

All in `src/codegen/mod.rs`:

- `emit_load_named_var_into_rax` (`:1117`) — the resolver itself. Called
  from `Expr::StringLit` arms near `:6481` and `:6907`. NOTE: the adjacent
  calls near `:6558` and `:6915` take an *identifier's* name, and the map
  paths at `:5162`/`:8578` pass a map variable's name — those are legitimate
  identifier resolution and must not change.
- `quoted_name_var_type` (`:1562`) — consulted on StringLit content by the
  type predicates at `:2228`, `:2258`, `:2363` (is-float / is-buffer
  decisions can currently flip because a literal matches a variable's name)
  and by the type-inference arm at `:8877`
  (`Expr::StringLit(s) => self.quoted_name_var_type(s).or(Some(VarType::String))`,
  which should become unconditionally `Some(VarType::String)`).

Step one of the work is mapping which parser paths construct
`Expr::StringLit` nodes that reach these arms. If any in-tree code path
*deliberately* routes a variable name through a StringLit node and relies on
codegen resolving it, that path is itself a violation of the v0.3.0 rule —
surface it and argue it in the report rather than silently preserving or
silently breaking it. An existing test failing after the removal is exactly
such a reliance: name it, don't adapt it quietly.

## Acceptance

1. Both repros above behave correctly: `Print x.` prints `x` (exit 0);
   `Print b.` prints `greeting`.
2. A string literal matching a `float`/`buffer` variable's name no longer
   flips the `:2228`/`:2258`/`:2363` predicates.
3. Identifier-based resolution (bare and single-quoted names, map lookups)
   is unchanged.
4. Full gate green: `cargo build --release && ./test.sh` (baseline 319
   passed / 0 failed / 6 skipped `manual_*`).
5. Regression tests in repo style (`tests/bugs_found_19_*.vox` +
   `.expected`) covering: self-name initializer, other-variable-name literal
   (both the initializer and a `Print "greeting".` statement position), and
   a predicate case.
6. `docs/BUGS_FOUND.md` #19 status flipped (mention the silent-wrong-data
   variant), CHANGELOG `Unreleased`/`Fixed` entry.

## Constraints

- No parser or language-surface changes; the grammar already states the rule.
- Named paths only in commits; never `--no-gpg-sign`; compile throwaway
  programs from /tmp.
- Semver: bug fix, patch-level; extend `Unreleased` only.
