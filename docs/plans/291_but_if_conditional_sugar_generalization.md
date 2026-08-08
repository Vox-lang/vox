# Plan 291 — generalize `but if` conditional sugar beyond bare `print`

**Status:** specced 2026-08-07. Root cause found and confirmed live against a
fresh `main` build (`b143840`); not yet fixed.

## Problem

Two related, confirmed-live failures, both the same underlying construct:

**Finding 5 — `append` rejects `but if`:**

```vox
a buffer called line is 256 bytes in size.
a number called v is 1.
Append ".", but if v is equal to 1 append "#".
```

```
error: Expected 'to' after value in append statement
```

The parser tries to parse `but if v is equal to 1 append "#".` as more of
the *first* append statement's own value/destination grammar — it has no
concept of `but if` at all in that code path.

**Finding 6 — conditional `print` rejects `without newline` on the
branches:**

```vox
a number called v is 1.
Print "." without newline, but if v is equal to 1 print "#" without newline.
```

```
error: Expected a statement, got Without
```

Here `but if` **is** recognized (this is the working, existing case for
bare `print`) — but the conditional-branch grammar it invokes only knows how
to parse `print <value>`, not `print <value> without newline`. The trailing
`without newline` on the branch is left unconsumed, so it gets picked up as
the start of the *next* statement and fails there.

Both confirmed live against `main`, independently re-verified by the root
master against a fresh build before this track was spun up.

## Root cause — confirmed by reading the code, not inferred

**There are exactly two call sites of the conditional-sugar builder today**
(`grep -n parse_conditional_print src/parser/mod.rs`), both hardcoded to
`print`:

1. **Standalone**, `src/parser/mod.rs:1161-1184`, inside `parse_print`. After
   parsing the print value and its own `without newline`, it looks for
   `, but if` / `but if` and, if found, calls
   `self.parse_conditional_print(value)` (line 1176) — passing only the bare
   `Expr` value, **not** the `without_newline` flag it just parsed, and not
   anything that could identify a different base statement kind.

2. **Loop-expansion**, `src/parser/mod.rs:2626-2683`
   (`wrap_in_loop_expansion`, used by `print each X from Y, but if ...`). Its
   `but if` handling (2634-2649) explicitly requires the base statement to be
   `Statement::Print` and errors `"'but if' conditional branching only works
   with print statements"` (line 2645) if it isn't — this is the literal
   sentence stating today's scope limit. This call site is **out of scope**
   for this plan (see Non-goals) but must not regress.

**The builder itself**, `parse_conditional_print` (`src/parser/mod.rs:1187-1253`):

- Takes only a `default_value: Expr`, discarding any modifier (like
  `without_newline`) the caller already parsed for the base statement.
- Each branch body is parsed by a fixed sequence:
  `self.expect(&Token::Print); ...; let val = self.parse_primary()?;` — the
  `Token::Print` keyword is hardcoded (line 1195 for the first branch, 1224
  and 1231 for continuations), and there is **no** parsing of `without
  newline` after `val` in any branch — that grammar element simply does not
  exist in this function. This is the direct cause of Finding 6.
- The chain is built by wrapping the branches in nested `Statement::If`,
  with the innermost `else` being a hardcoded
  `Statement::Print { value: default_value, without_newline: false }`
  (line 1241) — again dropping whatever `without_newline` the caller had.

**`append`'s parser has no hook for this at all.** `parse_append`
(`src/parser/mod.rs:3716-3818`) builds `Statement::ListAppend { list, value }`
and returns it directly (line 3817) — there is no check for a trailing
`but if`/`, but if` anywhere in it, so a `but if` after an append statement
is never recognized as sugar; it falls through to being parsed as more of
the append statement's own grammar, which is what produces Finding 5's
"Expected 'to'" error (the parser is still inside `parse_append`, trying to
find a `to` for the whole `,  but if v is equal to 1 append "#"` blob).

## Target

One shared mechanism recognizes `but if` after **either** `print ...
[without newline]` or `append ... to <target>`, and builds the same nested
`Statement::If` chain for both — rather than two independent, statement-
specific implementations. Each conditional branch parses using its base
statement's own value grammar (including, for `print`, its own independent
`without newline`).

```vox
Append ".", but if v is equal to 1 append "#".
```
→ appends `"#"` if `v == 1`, else `"."`, into the *same* target buffer named
in the base statement (append branches do not re-specify a target — there
is no `to <list>` in the branch grammar; the destination is fixed by the
statement the sugar is attached to).

```vox
Print "." without newline, but if v is equal to 1 print "#" without newline.
```
→ prints `#` (no trailing newline) if `v == 1`, else prints `.` (no trailing
newline).

## Non-goals — explicitly out of scope

- **`append each X from Y, but if ... append ...` (loop-expansion + append).**
  Not one of the three confirmed findings. `wrap_in_loop_expansion`'s
  existing `Statement::Print`-only check (line 2645) may stay exactly as is.
  If your refactor happens to make extending it trivial, that's a bonus, not
  a requirement — do not spend effort chasing it, and do not let pursuing it
  put the three required repros at risk.
- **A conditional `append` branch specifying its own `to <target>`,
  different from the base statement's target.** Not in any of the three
  repros. Every example in this plan reuses the base statement's target for
  every branch; that is the only grammar you need to implement.
- **A type-predicate suffix (`is a number`) on a conditional append
  branch.** `parse_append` supports this on its own top-level value
  (`src/parser/mod.rs:3769-3792`); the conditional-branch grammar does not
  need to.

## Fix — shape, not literal code

This is a sketch to guide the implementation, not something to copy-paste
verbatim — verify it actually compiles and adjust as the borrow checker and
real token stream require.

1. **Replace the inline `but if` detection duplicated across call sites**
   with one shared "detect and dispatch" helper that takes the fully-built
   base statement:

   ```rust
   fn maybe_parse_conditional_suffix(&mut self, base: Statement) -> Result<Statement, Box<CompileError>> {
       let start_pos = self.pos;
       if matches!(self.current(), Token::But | Token::Comma) {
           self.advance();
           self.skip_noise();
           if *self.current() == Token::But {
               self.advance();
               self.skip_noise();
           }
           if *self.current() == Token::If {
               return self.parse_conditional_suffix(base);
           }
           self.pos = start_pos;
       }
       Ok(base)
   }
   ```

   This is the existing block at `src/parser/mod.rs:1165-1182`, generalized
   to take/return a full `Statement` instead of being specific to the print
   value. `parse_print` calls this at its tail instead of its current inline
   block. `parse_append` gains a call to this at its tail (this is the actual
   Finding 5 fix — today it has no call at all).

2. **Generalize the chain-builder** (rename `parse_conditional_print` →
   e.g. `parse_conditional_suffix`, taking `base: Statement`) to dispatch
   each branch's grammar off `base`'s shape instead of hardcoding `print`:

   ```rust
   fn parse_conditional_suffix(&mut self, base: Statement) -> Result<Statement, Box<CompileError>> {
       self.advance(); // consume 'if'
       self.skip_noise();
       let mut conditions = Vec::new();

       let cond = self.parse_condition()?;
       self.skip_noise();
       conditions.push((cond, self.parse_conditional_branch(&base)?));

       self.skip_noise();
       loop {
           if !matches!(self.current(), Token::But | Token::Comma | Token::And) {
               break;
           }
           let started_with_comma = *self.current() == Token::Comma;
           self.advance();
           self.skip_noise();
           if started_with_comma && *self.current() == Token::But {
               self.advance();
               self.skip_noise();
           }
           if *self.current() == Token::If {
               self.advance();
               self.skip_noise();
               let cond = self.parse_condition()?;
               self.skip_noise();
               conditions.push((cond, self.parse_conditional_branch(&base)?));
           } else if *self.current() == Token::Else || *self.current() == Token::Otherwise {
               self.advance();
               self.skip_noise();
               conditions.push((Expr::BoolLit(true), self.parse_conditional_branch(&base)?));
               break;
           } else {
               break;
           }
       }

       let mut result = base;
       for (cond, val) in conditions.into_iter().rev() {
           result = Statement::If {
               condition: cond,
               then_block: vec![val],
               else_if_blocks: vec![],
               else_block: Some(vec![result]),
           };
       }
       Ok(result)
   }
   ```

   Note `conditions` now holds `(Expr, Statement)` pairs (a full branch
   statement), not `(Expr, Expr)` — the old code built
   `Statement::Print { value: val, without_newline: false }` itself, inline,
   for every branch (line 1246); that construction moves into
   `parse_conditional_branch` below, where it can differ per statement kind
   and actually parse `without newline`.

3. **New helper, one branch's grammar, dispatched by the base statement's
   kind:**

   ```rust
   fn parse_conditional_branch(&mut self, base: &Statement) -> Result<Statement, Box<CompileError>> {
       match base {
           Statement::Print { .. } => {
               if !self.expect(&Token::Print) {
                   return Err(self.err("Expected 'print' in 'but if' branch"));
               }
               self.skip_noise();
               let val = self.parse_primary()?;
               self.skip_noise();
               let without_newline = if *self.current() == Token::Without {
                   self.advance();
                   self.skip_noise();
                   if *self.current() == Token::Newline
                       || matches!(self.current(), Token::Identifier(s) if s.to_lowercase() == "newline")
                   {
                       self.advance();
                       true
                   } else {
                       false
                   }
               } else {
                   false
               };
               Ok(Statement::Print { value: val, without_newline })
           }
           Statement::ListAppend { list, .. } => {
               if !self.expect(&Token::Append) {
                   return Err(self.err("Expected 'append' in 'but if' branch"));
               }
               self.skip_noise();
               let mut val = self.parse_append_value_primary()?;
               val = self.parse_append_value_ops(val, 0)?;
               Ok(Statement::ListAppend { list: list.clone(), value: val })
           }
           _ => unreachable!("conditional sugar is only built for Print/ListAppend bases"),
       }
   }
   ```

   `parse_append_value_primary`/`parse_append_value_ops` are the existing
   functions `parse_append` itself already uses for its own top-level value
   (`src/parser/mod.rs:3599-3714`) — reuse them rather than writing new
   value-parsing logic; this is exactly why they're already factored out of
   `parse_append` as standalone functions.

   The original code used the loose `self.expect(&Token::Print);` without
   checking the return (a pre-existing pattern at old lines 1195/1224/1231
   that silently no-ops on a mismatch, since `expect` returns `bool` and the
   call site ignores it). Above, this plan tightens that to a real parse
   error on mismatch — a mismatched keyword is a genuinely bad program, and
   producing a clear error beats letting the append/print value parser choke
   confusingly on the wrong following tokens. This is a small, deliberate
   improvement bundled with the generalization; call it out in your PR
   description as such.

4. **Wire up the two remaining call sites:**
   - `parse_print` (`src/parser/mod.rs:1161-1184`): replace the inline
     detection block with
     `return self.maybe_parse_conditional_suffix(Statement::Print { value, without_newline });`
     at the tail (after the base statement's own `without_newline` has
     already been parsed, same as today).
   - `parse_append` (`src/parser/mod.rs:3716-3818`): before the final
     `Ok(Statement::ListAppend { list, value })` (line 3817), call
     `return self.maybe_parse_conditional_suffix(Statement::ListAppend { list, value });`
     instead of returning directly.
   - `wrap_in_loop_expansion` (`src/parser/mod.rs:2626-2683`): keep its
     existing `Statement::Print`-only branch (2634-2649) functionally
     unchanged — it should still call into the (renamed) chain-builder the
     same way it does today, just under the new name/signature
     (`self.parse_conditional_suffix(Statement::Print { value: default_value, without_newline: false })`).
     Do not widen this call site to accept `ListAppend` — see Non-goals.

## Required verification

1. Both repros above now produce **correct runtime output**, not just "no
   parse error":
   - Finding 5: assert the buffer's actual content after the conditional
     append (`#` when `v == 1`, `.` otherwise — test both branches of the
     condition, not just the one in the repro).
   - Finding 6: assert the actual printed output has no newline after either
     branch's value (capture stdout, check it does not end in `\n` where it
     shouldn't, and that the correct value printed).
2. Regression coverage — all of these must be unaffected:
   - `print X, but if Y print Z.` with **no** `without newline` anywhere —
     today's working case, must produce identical output to before.
   - `print each N from A to B, but if ... print ...` — the loop-expansion
     `but if` form (see `tests/018_fizzbuzz.vox`, `tests/021_ranges.vox`,
     `tests/043_loop_expansion.vox`) — must still pass unchanged; these are
     part of the existing suite so `./test.sh` covers them, but look at the
     diffed output yourself too, don't just trust green.
   - `print X without newline.` with **no** `but if` — must still work
     (this exercises the ordinary `without newline` path, untouched by this
     plan, but confirm it wasn't accidentally broken by the refactor).
   - `Append "literal" to buf.` with **no** `but if` — must still work
     (ordinary append, untouched by this plan).
   - A multi-branch `append ... but if ... but if ... otherwise append ...`
     chain (3+ conditions) — the loop in `parse_conditional_suffix` handles
     `Token::And` as well as `Token::But`/`Token::Comma` continuations;
     confirm at least one multi-branch case for `append`, mirroring the
     existing multi-branch print test (`018_fizzbuzz.vox` has three).
3. `cargo test` fully green.
4. `./test.sh` — baseline on a fresh `main` (`b143840`) checkout, force-clean
   build (`rm -f target/release/vox` before building — this environment has
   shown builds reporting success in ~0.03s without recompiling), is:
   **211 passed / 0 failed / 6 skipped, 217 total.** Hold this or better, 0
   failed, verified behaviorally (run the actual repros against your built
   binary), not by trusting build timing.
5. 0 build warnings.
6. New test files: use numbers **220 and up** (worker 1, working finding 4
   in a sibling worktree, uses 217-219; check
   `ls tests/*.vox | grep -oE '[0-9]+' | sort -n | tail -1` before picking a
   number in case this range has since been taken by something else landing
   on `main`).

## Hard constraints

- No new crates, no libc.
- Never weaken a test to make it pass.
- Do not extend `wrap_in_loop_expansion`'s `but if` support to `append` —
  out of scope, see Non-goals.
- Commits are GPG-signed with a hardware key. If signing hangs, stop and say
  so — never `--no-gpg-sign`.
- If the fix turns out more tangled than this plan describes — e.g. the two
  statement kinds don't actually share as much grammar as assumed, or the
  borrow-checker forces a meaningfully different shape than the sketch above
  — stop and say so precisely, including what you found, rather than forcing
  a partial fix or silently diverging from the design without flagging it.
