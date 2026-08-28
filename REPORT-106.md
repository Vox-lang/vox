# Report — fix register entry #106 (`print`'s aliases reserved unevenly)

Branch `fix/bug-106-print-aliases`, off `origin/main` = Vox 0.4.13 (4c85e03).
Worker did not commit or push; diff is staged and parked for master review.

## The decision (master + Josj, not re-opened)

Every reserved-word table now agrees with the **live lexer**:

- `show`, `display`, and `prints` fold to `print` in the lexer's word fold
  (`src/lexer/scan.rs`'s `read_word`) and stay reserved.
- `say` and `output` are never folded by the lexer and are **not**
  reserved — they stay ordinary variable names.
- No shipped program's behaviour changes. `output` is a variable name in
  six files (found the sixth per the brief's "find it": the five named in
  the brief plus `tools/migrate-identifiers/tests/all_positions.vox`,
  which uses `output` on its own line `Write "Hello World" to output.`).

## Step 0 — verify first (before vs. after)

Ran all four probes on the **before** binary
(`/home/josj/scr/english/vox/target/release/vox`,
`VOX_CORE_PATH=/home/josj/scr/english/vox/coreasm`) and on **this
worktree's** built binary after the fix. Identical both sides:

```
a number called show    is 1.   -> rejected: "Cannot use 'show' as a variable
                                    name - it's a reserved keyword.
                                    'show' is an alternate spelling of the
                                    reserved keyword 'print'."
a number called display is 1.   -> rejected, same shape, names 'display'.
a number called say     is 1.   -> compiles (exit 0).
a number called output  is 1.   -> compiles (exit 0).
a number called prints  is 1.   -> rejected, same shape, names 'prints'
                                    (checked in addition to the brief's
                                    four probes: `prints` is also a live
                                    print alias, on both binaries, before
                                    my fix touched anything - this
                                    rejection path never went through
                                    `string_is_keyword` in the first
                                    place, only `Token::as_keyword()`).
```

All six `output`-as-a-name files re-run on the fixed binary: the five
`.vox` sources compile cleanly (exit 0). The sixth,
`tools/migrate-identifiers/tests/all_positions.vox`, fails to parse on
**both** the before and the after binary with the identical error
(`Expected a statement, got File` at its `#`-comment first line) — it is a
fixture for the separate `migrate-identifiers` codemod tool, written in a
syntax the main compiler was never able to parse directly; pre-existing,
unrelated to this fix, confirmed identical before/after.

## The fix

**One source of truth.** A new `pub const RESERVED_ALIASES: &[(&str,
&str)]` in `src/lexer/tokens.rs` (222 rows: one row per reserved spelling,
including a keyword's own canonical spelling, mapping to its canonical
name) is now what `Token::string_is_keyword` reads from — the hand-written
match statement is gone, replaced by a lookup into the const. The live
lexer's fold in `src/lexer/scan.rs`'s `read_word` was **not** touched
(per the brief: "you are not adding or removing any alias the lexer
honours today") — it remains the ground truth the const is checked
against, by a new `cargo test`
(`codegen::tests::string_is_keyword_matches_the_live_lexer`) that
tokenizes every spelling in the const and asserts the live lexer's fold
agrees with both the const and `string_is_keyword`.

**Docs.** LANGUAGE.md's Reserved Aliases table (`### Reserved Aliases`,
was 3 rows: `ms`, `message`, `string`) is now 85 rows — every alias in
the const whose spelling differs from its own canonical, one row per
alias, generated from the const by inspection and locked in place by a
second new `cargo test`
(`codegen::tests::reserved_aliases_doc_matches_the_const`), which parses
the markdown table out of `LANGUAGE.md` and asserts it is exactly the set
of (alias, canonical) pairs the const carries — fails the build the
moment either side drifts. The "Context" column was dropped (nothing in
the const carries per-row prose, and inventing 85 near-identical "context"
strings by hand is exactly the kind of hand-maintained data that drifts);
a two-column table plus one clarifying sentence about `say`/`output`
replaces it.

**Unit test.** A third new test,
`codegen::tests::print_aliases_reserved_evenly`, is the bug's own
regression pin: asserts `string_is_keyword` claims `show`/`display`/
`prints` and not `say`/`output`, then drives the real parser (with
`.with_source`, needed for `current_lexeme()` to recover the typed
spelling) to confirm `show`/`display` are rejected with the "alternate
spelling of the reserved keyword 'print'" diagnostic and `say`/`output`
parse cleanly as variable names.

## Every other table disagreement found and how each was resolved

Auditing `string_is_keyword`'s old hand-written match against the live
lexer's fold (by tokenizing every candidate spelling and comparing
`Token::as_keyword()` to the table's claim) turned up 41 disagreements
beyond `print`'s own four-word split — the same bug, throughout the
table:

**Over-claimed — dropped (not live aliases, the table wrongly reserved them):**
`say`, `output` (bug #106 itself), `let`, `put`, `declare`, `over`,
`increase`, `decrease`, `execute` (no `Token::Execute` variant exists at
all — the entire row was spurious dead weight), `respond`, `reply`,
`end`, `halt`, `abort`, `using`, `given`, `taking`, `higher`, `above`,
`lower`, `below`, and the four unreachable symbol spellings `==`, `!`,
`&&`, `||` (`scan.rs` has no character-level handling for `=`, `!`, `&`,
or `|` at all — confirmed by grep — so none of the four can ever be
produced by the lexer, and no identifier lexeme can spell one anyway, so
these rows could never have fired on real input).

**Omitted — added (live aliases the table never claimed):** `prints` (→
`print`, the other half of #106), `store` (→ `set`), `returns` (→
`return`), `append`/`push` (→ `append`, a whole missing keyword), `copy`
(a whole missing keyword), `map`/`dictionary` (→ `map`, a whole missing
keyword), `keys`, `values`, `element`, `without` (four more missing
keywords), and the six `bit-and`/`bit-or`/`bit-xor`/`bit-not`/
`bit-shift-left`/`bit-shift-right` forms (missing entirely).

**Wrong canonical — moved to the right row:**
- `make` was claimed as a `set` alias; the lexer folds it to `create`
  (`scan.rs`: `"create" | "make" | "define" => Token::Create`). Moved.
- `times` was claimed as a `multiply` alias; the lexer treats it as its
  own keyword, `Token::Times` (the `Repeat N times.` loop word), never as
  a multiply synonym. Given its own row (`("times", "times")`).
- `equals`/`equal` were claimed as `is` aliases; the lexer folds both to
  their own keyword, `Token::Equals` (canonical name `"equals"`), never
  to `Token::Is`. Moved to their own row.

**Verified correct as-is (no change):** every remaining row already
agreed with the live lexer, including several multi-alias rows that
looked suspicious on first read but checked out: `to`/`up` (both fold to
`Token::To`), `in`/`inside`/`within`, `on`/`at`, `free`/`release`/
`deallocate`, and the contextual words (`flags`, `it`, `all`, `size`,
`length`, `capacity`, `first`, `last`, `version`, `count`, `raw`,
`start`/`begin`/`stop`/`finish`, `second`) that `scan.rs` deliberately
folds to `Token::Identifier` and `string_is_keyword` already, correctly,
never claimed.

**Noted but out of scope — not fixed:** `Token::Equal` (singular, distinct
from `Token::Equals`) is never produced by the lexer at all — no word or
symbol folds to it — yet `src/parser/expressions.rs:246` does
`self.expect(&Token::Equal)`, an `expect` call against a token the lexer
can never hand it. This looks like dead/unreachable parser code, but it
is a different bug shape (an unreachable expectation, not a keyword-table
disagreement) and outside bug #106's scope; flagging for the register
rather than touching parser logic in this branch.

## Tests

- `tests/compile_fail/277_show_reserved_print_alias.vox` + `.err`:
  `a number called show is 1.` rejected, `.err` matches "reserved keyword"
  and "'show' is an alternate spelling of the reserved keyword 'print'."
- `tests/compile_fail/278_display_reserved_print_alias.vox` + `.err`:
  same shape for `display`.
- `tests/577_say_and_output_are_variable_names.vox` +
  `.expected` (**renumbered from 566 mid-flight** — 566–576 collided with
  the #108 fixer's claim, made after this brief was written; renumbered
  per master's steer, `git status` confirms no leftover `566_*` files):
  declares `say` and `output` as text variables and prints both;
  `.expected` is `hello`/`world`.
- `src/codegen/tests.rs`, beside the existing `string_is_keyword` tests:
  `string_is_keyword_matches_the_live_lexer`,
  `print_aliases_reserved_evenly`, `reserved_aliases_doc_matches_the_const`.

**Counts** (`./test.sh`, which runs `cargo test` as one of its steps, both
re-run once after the 566→577 renumber):

```
./test.sh:  Passed 612 / Failed 0 / Skipped 6 / Total 618
            (baseline 617 + 1 new run test = 618 - matches)
cargo test: 379 passed, 0 failed, across every test binary
            (includes all three new codegen::tests:: cases, ok)
```

No `FAIL` or `test result: FAILED` anywhere in either log.

## Files changed (staged, not committed)

```
 CHANGELOG.md          |   5 +
 LANGUAGE.md           | 100 ++++++++++++++--
 docs/BUGS_FOUND.md    |  52 ++++++--
 src/codegen/tests.rs  | 155 ++++++++++++++++++++++++
 src/lexer/mod.rs      |   4 +
 src/lexer/tokens.rs   | 330 +++++++++++++++++++++++++++++----------------------
 tests/577_say_and_output_are_variable_names.{vox,expected}       (new)
 tests/compile_fail/277_show_reserved_print_alias.{vox,err}       (new)
 tests/compile_fail/278_display_reserved_print_alias.{vox,err}    (new)
```

`git diff --cached` parked at
`/home/josj/scr/english/vox-notes/parked/fix-bug-106.patch`; this report
copied to `/home/josj/scr/english/vox-notes/REPORT-106.md`.

FIX 106 DONE
