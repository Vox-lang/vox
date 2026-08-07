# Plan 281 — connector suppression leaks into `{...}` groups

**Status:** specced 2026-08-10. Root cause found and confirmed live; not yet
fixed.

## Problem

`byte {<function call>} of <buffer>` rejects any function call inside the
braces — not even a single-argument one:

```
byte {ci of 1 and 2} of b     -> error: Expected a statement, got And
byte {id of 3} of b           -> error: Expected a statement, got CloseBrace
```

Same for `element N of list`:

```
print element {idfn of 2} of lst.   -> error: Expected a statement, got CloseBrace
```

Both confirmed live against `main`. Found while porting `examples/life.vox`
(Conway's Game of Life), which needed a computed buffer index and had to work
around it by precomputing into a local variable first — a real program cannot
write the natural, direct form.

## Root cause — confirmed by reading the code, not inferred

Plan 270's connector-precedence fix (`af8c425`, "Fix 'to'/'of' connector root
cause...") introduced `parse_primary_reserving(to: bool, of: bool)`
(`src/parser/mod.rs:841-854`):

```rust
fn parse_primary_reserving(&mut self, to: bool, of: bool) -> Result<Expr, Box<CompileError>> {
    let saved_to = self.suppress_to_connector;
    let saved_of = self.suppress_of_connector;
    if to { self.suppress_to_connector = true; }
    if of { self.suppress_of_connector = true; }
    let result = self.parse_primary();
    self.suppress_to_connector = saved_to;
    self.suppress_of_connector = saved_of;
    result
}
```

`byte`'s index (`src/parser/mod.rs:1263` for `Set byte N of buffer to
value`, and `5145` for the `byte N of buffer` expression) and `element`'s
index (`1286` and `5162`) both call this with `of=true` — correctly reserving
`of` so the enclosing `byte X of buffer`/`element X of list` doesn't have its
own `of` eaten by an identifier immediately followed by `of` (the original
bug this mechanism fixed). This part works and must not regress.

**The bug:** `suppress_of_connector` (and `suppress_to_connector`) are flat
booleans on the parser, not scoped to the call that set them. `parse_primary`'s
`Token::OpenBrace` handler (`src/parser/mod.rs:5091-5138`) parses the braced
content with a plain `self.parse_expression()` call — it does not save, clear,
and restore the suppress flags around that nested parse. So a flag set to
protect the *outer* `byte X of buffer` construct stays active while parsing
*inside* an explicitly-delimited `{...}` group, incorrectly blocking a nested,
self-contained function call from using its own `of`/`to` — even though the
closing `}` already unambiguously ends the group and there is no real
ambiguity left to protect against.

This affects the same handler regardless of which of its two sub-cases fires
(plain grouping `{expr}`, or a map literal `{"k": v, ...}` — both reach
`parse_expression()` before branching on whether a colon follows), so a map
literal value nested inside a suppressed context has the identical exposure,
though this hasn't been observed in practice yet.

**Nine call sites total currently use `parse_primary_reserving`**
(`grep -n parse_primary_reserving src/parser/mod.rs`): the four `byte`/
`element` sites above (`of=true`), plus five `to=true` sites (range bounds
and the `For each ... from X to Y` family, lines 1912, 2569, 2587, 2602,
5651). Fixing the mechanism itself — rather than patching each site — fixes
all nine at once and prevents a tenth site from reintroducing the same bug
later.

## Target

A function call (or any expression) inside an explicit `{...}` group parses
normally, using its own connector words, **regardless of what the enclosing
context has reserved** — because the `{` and `}` already fully delimit where
the group starts and ends; there is nothing left for the outer reservation to
protect once inside it.

## Fix

In `parse_primary`'s `Token::OpenBrace` arm, save the current
`suppress_to_connector`/`suppress_of_connector`, clear both to `false` before
calling `parse_expression()` for the group's content (both the grouping path
and the map-literal key/value path), and restore the saved values immediately
after — the same save/set/restore shape `parse_primary_reserving` itself
already uses, just applied at the point where a nested group begins rather
than only at the top-level reserving call.

## Required verification

1. The two repros above (`byte`, `element`) now compile and produce correct
   values — not just "no parse error." Assert the actual runtime output, not
   only compile success.
2. `examples/life.vox`'s 21 precomputed-variable workarounds are no longer
   *necessary* — as a proof, revert one or two of them back to the direct
   `byte {'cell index' of r and c} of grid` form in a **throwaway test**, not
   in the shipped example (the shipped file should stay as-is; this is purely
   to confirm the fix). Do not change the shipped example file in this task.
3. **Regression coverage for what the original fix protected:** the exact
   cases from plan 270 S1 round 2 must still work — `Set start to 1.` followed
   by a range using `start`/`end` as bounds, `append ... to`, and a bare
   identifier immediately followed by `of`/`to` (no braces) still correctly
   reserves the enclosing connector. The bug being fixed here is specifically
   about *braced* sub-expressions; anything *not* in braces must behave
   exactly as it did after `af8c425`.
4. A map-literal value nested inside a suppressed context (construct a test
   case exercising this even though it hasn't been observed as a live bug) —
   confirm it also now works correctly.
5. `cargo test` fully green. `./test.sh` — 209 passed / 0 failed / 6 skipped
   on a **force-clean rebuild** (`cargo clean -p vox` first; this environment
   has shown fast/stale-looking rebuilds after a merge — verify behaviorally,
   not by trusting build time).
6. 0 build warnings.

## Hard constraints

- **No new crates, no libc.**
- **Never weaken a test to make it pass.**
- **Do not touch `examples/life.vox`.** It already works correctly with its
  workaround; this plan is about the compiler, not that file.
- If the fix turns out to be more tangled than described here — e.g. the
  nine call sites don't share the fix as cleanly as expected — stop and say
  so precisely rather than force a partial fix. This project has been right
  to trust that judgement call before.
