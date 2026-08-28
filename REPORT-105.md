# Fix report — register #105: a call missing its preposition reports arity, not the missing preposition

Branch `fix/bug-105-missing-preposition`, off `origin/main` = Vox 0.4.13 (4c85e03).

## Step 0 — verify first

Repro (`docs/BUGS_FOUND.md` #105):

```vox
To 'write a blank pair to' with a buffer called output.
  set byte {output's size add 1} of output to ' '.

Create a buffer called staged.
'write a blank pair to' staged.
```

**Before** ("before" compiler, `~/scr/english/vox/target/release/vox`, main's
code, verbatim):

```
error: Function 'write a blank pair to' expects 1 argument but was called with 0.
  --> ...repro105.vox:1:5
  1 | To 'write a blank pair to' with a buffer called output.
    |     ^--- here

error: Unknown function: staged
  --> ...repro105.vox:4:24
  4 | Create a buffer called staged.
    |                        ^--- here
```

(Note: the second error's caret lands on `staged` inside the `Create`
statement on line 4, not line 5 — the analyzer reports a name-resolution
error against the declaration site of the unresolved reference, not the use
site on line 5. This is a caret-placement detail of the pre-existing
"Unknown function" error, not part of what this fix changes.)

Rebuilt this tree unbuilt-yet (same commit as "before", so same binary):
identical output, confirmed byte-for-byte matching the two errors above.

**What must not change** — recorded on the pre-fix baseline, reconfirmed
unchanged after the fix (see "After" section):

| Case | Behavior |
|---|---|
| `'f' of x.` (single arg, `of`) | compiles, exit 0 |
| `'f' with x and y.` (two args, `with`) | compiles, exit 0 |
| Zero-arg call followed by a period (`'greet'.`) | compiles, exit 0 |
| Call followed by `..` (double period) | unaffected: `Expected a statement, got Period` at the second `.` |
| Call at the end of a comma-chained clause (`While x is less than 1, increment x, 'greet'.`) | compiles, exit 0 |

## Root cause

`parse_identifier_statement` (`src/parser/statements.rs`) parses a call
statement in three shapes: assignment (`name is value`), a call with a
connector (`Of`/`To`/`With`/`On` followed by an argument list), or —
falling through both — an unconditional **zero-argument call**. A call
written with no preposition before its argument falls into the third shape:
the parser accepts `'write a blank pair to'` as a complete zero-arg call and
leaves `staged` sitting in the token stream. Back in `parse_statement_list`,
the loop expects a period next, doesn't find one (`self.expect(&Token::Period)`
silently fails and consumes nothing), and loops around to parse a *new*
top-level statement starting at `staged` — which becomes its own zero-arg
call, immediately failing name resolution as "Unknown function: staged".
Two statements, two errors, neither naming the actual cause (the missing
preposition).

## The fix

`src/parser/statements.rs`, `parse_identifier_statement`: before falling
through to the zero-argument-call return, check whether the next token
(after the callee, in the same sentence) is a bare or quoted identifier
(both lex as `Token::Identifier` — a single-quoted multi-word name is one
token with spaces in it, same as a bare word). If so, this is the
dropped-preposition shape, not a genuine zero-arg call: return one parse
error naming the missing preposition, anchored at that identifier (the use
site), and do not return a `FunctionCall` statement at all — so the
identifier is never left for the statement-list loop to reparse as anything
else, and the second, unrelated error can't happen.

Message: `'staged' follows the call with no preposition — arguments are
introduced with 'of', 'to', 'with', or 'on'.` (preposition order matches
LANGUAGE.md:866/876, the existing "Function Calls" rule text.)

Diff: `src/parser/statements.rs`, +19/-0, one `if let` block inserted before
the existing "Zero-argument call" comment. Arity checking itself
(`validate_function_call_args`, `src/analyzer/expressions.rs:81`) is
untouched — a genuine zero-argument call never reaches it any differently
than before.

## After

```
error: 'staged' follows the call with no preposition — arguments are introduced with 'of', 'to', 'with', or 'on'.
  --> ...repro105.vox:5:25
  5 | 'write a blank pair to' staged.
    |                         ^--- here
```

One error, anchored at `staged` on line 5 (the use site, as the brief
specifies) — the "Unknown function" error is gone because `staged` is never
parsed as its own statement.

**Preserved-behavior recheck, after the fix** (same five cases as Step 0,
rerun against the fixed binary): all five identical to baseline — `'f' of
x.` and `'f' with x and y.` still compile; a bare zero-arg call still
compiles; the double-period case still fails at the second period with the
same message; the comma-chained-clause case still compiles.

## Tests

Two new `compile_fail` cases (271–272; 270 was the highest existing number):

- **`271_call_missing_preposition_bare_call.vox`** — the register's own
  repro (single would-be argument). `.err` pins the new message.
- **`272_call_missing_preposition_two_args.vox`** — second shape: an
  `of`-style call (two declared parameters) also missing its preposition,
  called as `'combine' x and y.`. Before the fix this didn't reproduce the
  *same* two-error shape as the register's repro — `x` becomes its own
  zero-arg call, then the loop chokes on the stray `and`, so it failed with
  a single, different, unhelpful error (`Expected a statement, got And`,
  pointing at `and`, not at the real cause). After the fix it gets the same
  one-error treatment, naming the missing preposition at `x`, the first
  bare token after the callee.

**Fail-before/pass-after**, both binaries against both new `.vox` files:

`271_call_missing_preposition_bare_call.vox`:
- Before (`~/scr/english/vox` binary): the two errors quoted in Step 0 (arity
  0, then "Unknown function: staged").
- After (this tree): `'staged' follows the call with no preposition —
  arguments are introduced with 'of', 'to', 'with', or 'on'.` at 5:25.

`272_call_missing_preposition_two_args.vox`:
- Before: `error: Expected a statement, got And` at 6:13 (pointing at `and`,
  not the callee or the dropped preposition).
- After: `'x' follows the call with no preposition — arguments are
  introduced with 'of', 'to', 'with', or 'on'.` at 6:11 (pointing at `x`,
  the first token after the callee).

**`./test.sh`** (this worktree, release build): `Passed: 611, Failed: 0,
Skipped: 6, Total: 617` — `ALL TESTS PASSED`. The 6 skips are pre-existing
manual-only fixtures (`manual_mknod_device`, `manual_mount_bind_and_move`,
`manual_mount_tmpfs`, `manual_pivot_root`, `manual_reboot`,
`manual_unmount` — no `.expected` file by design), unrelated to this
change.

**`cargo test --release`**: every suite green, including
`compile_fail_tests::tests::compile_fail_corpus_reports_errors ... ok`
covering **318** cases (the pre-existing 316 plus the two new ones).

## Docs

- `LANGUAGE.md`: one line added to the "Function Calls" **Rules** list
  (~line 877), current-state only: "Writing an argument right after the
  function name with none of these words is an error naming the missing
  preposition, not a call with that argument dropped."
- `docs/BUGS_FOUND.md` #105: status line rewritten state-first
  (`**Status:** fixed in v0.4.14. Regression tests: ...`); a **Fix.**
  paragraph appended in the entry's own voice, naming the file, the
  mechanism, and why the "Unknown function" error disappears. The rest of
  the entry (repro, observed output, root cause, fix direction) is
  untouched as the record.
- `CHANGELOG.md`: new `## [Unreleased]` section created above `## [0.4.13]`
  (none existed) with one `### Fixed` bullet ending `(#105)`.

## Status

Working tree: all changes `git add -A`'d and staged. Nothing committed —
per the brief, this worktree stops staged for the master to review and
Josj to sign. Staged diff parked at
`/home/josj/scr/english/vox-notes/parked/fix-bug-105.patch`.
