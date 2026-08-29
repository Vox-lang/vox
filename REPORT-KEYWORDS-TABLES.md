# Report: every reserved word appears in the Keywords chapter

Worktree `wt-docs-keywords`, branch `docs/keywords-tables-complete`, off
`main` at 4995394 (v0.4.14). Brief:
`/home/josj/.local/state/agent-worker/wt-docs-keywords-wt-docs-keywords/prompt.md`.

## What changed

- `LANGUAGE.md` (+90 lines, all inside the `## Keywords` chapter):
  - **Statement Starters**: 14 new rows — the brief's five (`Read`,
    `Write`, `Open`, `Close`, `Wait`) plus nine more the drift-guard test
    (below) also caught: `Sleep`, `Get`, `Clear`, `Copy`, `Resize`,
    `Seek`, `Repeat`, `See`, `Library`.
  - **Connectors**: 8 new rows — the brief's two (`each`, `without`) plus
    `between`, `in`, `into`, `as`, `treating`, `times`.
  - **Types** (new table, 13 rows): `number`, `int`, `float`, `text`,
    `boolean`, `true`/`false`, `list`, `map`, `buffer`, `file`, `time`,
    `timer`, `nothing`.
  - **Operators** (new table, 5 rows covering 24 words): arithmetic
    (`add`/`subtract`/`multiply`/`divide`/`modulo`), comparison
    (`is`/`are`/`equals`/`greater`/`less`/`than`), `not`, property-check
    predicates (`even`/`odd`/`positive`/`negative`/`zero`/`empty`), and
    the six `bit-*` bitwise operators.
  - **Reserved Nouns and Properties** (new table, the brief's ask): the
    seven (`input`/`standard`, `byte`, `elapsed`, `error`, `arguments`,
    `environment`) plus `argument` (singular) and `variable`, which
    belong to the same noun-phrase family (`the argument count`, `the
    environment variable ...`), plus `exists` and `auto`/`enable`/
    `disable` (see "Judgment calls" below).
  - **File, Buffer, List, and Time Properties** (new table, 9 rows
    covering 28 words): the File Properties septet (`descriptor`,
    `modified`, `accessed`, `permissions`, `readable`, `writable`,
    `full`), the three open modes (`reading`/`writing`/`appending`), map
    `keys`/`values`, number `absolute`/`sign`, `element`, `bytes`, and the
    Time and Timers cluster (`current`, `hour`, `minute`, `day`, `month`,
    `year`, `unix`, `duration`, `running`, `millisecond`(s), `seconds`).
  - No prose changed outside these table insertions. "Two classes of
    special word" (the reserved-class prose) was left as written — it
    already says the reserved class is "statement starters, operators
    (`times`, `add`), type names, connectors", and that is now literally
    true of the tables above it, so nothing there needed correcting.

- `src/codegen/tests.rs`: one new test,
  `every_reserved_word_appears_in_a_keywords_chapter_table`, beside
  `reserved_aliases_doc_matches_the_const` (see "Test placement"
  below for why it's here and not in `tokens.rs`).

- `docs/BUGS_FOUND.md`: appended a "Second half (v0.4.15)" paragraph to
  #106. Status line left as `fixed in v0.4.14` — it names what #106 was
  about (print's uneven aliases) and doesn't overclaim about this
  adjacent gap, so it didn't need touching per the brief's "state-first"
  rule.

- `CHANGELOG.md`: added `## [Unreleased]` above `## [0.4.14]` with one
  `### Fixed` bullet.

## The test's scan rules

Scoped exactly as the brief specified: from `## Keywords` to the next
`\n## ` heading (i.e. it never reaches into `## Examples` or, on the
other side, `## Operators`/`## Types`, which precede the chapter).
Within that span it finds every table whose header row's **first** cell
is literally `Keyword` or `Alias`, and collects every backtick-quoted
span in the first column of that table's data rows (splitting a
multi-word span like `` `Send signal` `` into separate words — harmless,
since neither word collides with a real reserved spelling there).

The "reserved word" set is every `(spelling, _)` in `RESERVED_ALIASES` —
i.e. every string `Token::string_is_keyword` answers for, canonical
self-mapped rows included. Contextual words (`start`/`begin`/`stop`/
`finish`, `send`, `capacity`, `waiting`, `available`, `name`, `count`,
`raw`, `all`, `first`, `last`, `second`, `size`/`length`, `version`, the
Things words) never enter this set in the first place — they have no row
in `RESERVED_ALIASES` at all (see that const's own doc comment), so the
brief's "decide deliberately how to treat them" question turned out to be
moot: there was nothing to exclude. I recorded why in the test's comment
rather than adding dead exclusion code.

**Verified failing on the unmodified table first**, per the gate: with
`LANGUAGE.md` reverted to `HEAD` (Rust unchanged), the test failed
listing exactly 101 missing words - the transcript is below. After the
doc changes above, it passes with zero missing.

```
thread 'codegen::tests::every_reserved_word_appears_in_a_keywords_chapter_table' panicked at src/codegen/tests.rs:1784:9:
these reserved words appear in no `| Keyword |` / `| Alias |` table in LANGUAGE.md's Keywords chapter: ["absolute", "accessed", "add", "appending", "are", "argument", "arguments", "as", "auto", "between", "bit-and", "bit-not", "bit-or", "bit-shift-left", "bit-shift-right", "bit-xor", "boolean", "buffer", "byte", "bytes", "clear", "close", "copy", "current", "day", "descriptor", "disable", "divide", "duration", "each", "elapsed", "element", "empty", "enable", "environment", "equals", "error", "even", "exists", "false", "file", "float", "full", "get", "greater", "hour", "in", "input", "int", "into", "is", "keys", "less", "library", "list", "map", "millisecond", "milliseconds", "minute", "modified", "modulo", "month", "multiply", "negative", "not", "nothing", "number", "odd", "open", "permissions", "positive", "read", "readable", "reading", "repeat", "resize", "running", "seconds", "see", "seek", "sign", "sleep", "standard", "subtract", "text", "than", "time", "timer", "times", "treating", "true", "unix", "values", "variable", "wait", "without", "writable", "write", "writing", "year", "zero"]
```

## Scope: 14 words became 101 - why, and a flag for the master

The brief's gap (five starters + nine nouns, from vox-fuzz's ledger
Discrepancy 4) is real, but Discrepancy 4 was never an exhaustive scan of
the chapter - it's a hand-picked list of egregious misses ("`input` and
`error` are ordinary enough words that a program will hit them"). Once I
had the test running the actual scan, it failed on **101** reserved
spellings, not 14: every type name, every arithmetic/comparison/bitwise
operator, and most of the File I/O / Time and Timers / Object Properties
nouns had *never* had a table row in this chapter, in any version I could
find. `## Types` and `## Operators` are full chapters elsewhere in
`LANGUAGE.md` with their own tables - but this chapter's own tables never
referenced them, despite its prose claiming "operators" and "type names"
as two of the four reserved classes.

The brief anticipated *some* overrun ("if the lexer reserves words the
ledger's list missed, they go in too - the test below decides, not the
list above") and forbade weakening the assertion to fit. Given that, and
that nobody's at the desk to ask mid-flight, I completed all 101 rather
than stopping at 14 or narrowing the test's scope to make it pass
early - a partially-enumerated "look up what you may not name" chapter is
exactly the trap BUGS_FOUND #106 already named. But this is a 7x scope
increase over the brief's explicit list, so: **if this was supposed to
stay small, say so and I'll cut it back to just the 14 plus a scan that
also credits the `## Types`/`## Operators` chapters** (a few lines of
comment-and-`find` in the test instead of five chapter-local tables). I
judged the self-contained version better because every other row in this
chapter already points elsewhere for detail rather than requiring the
reader to leave the chapter to find out a word is reserved at all - but
it's a real design choice, not a forced one.

## Judgment calls worth a second look

- **`int`/`integer` as a synonym for `number`.** `src/lexer/scan.rs:440`
  folds both to `Token::Int`, and `Token::Int` is accepted everywhere
  `Token::Number` is for declaring an `Integer` type
  (`src/parser/declarations.rs:559,954,977`, `src/parser/expressions.rs:403`).
  This was undocumented *anywhere* in `LANGUAGE.md` before this branch -
  not a ledger/GitHub-tracked gap, just something the exhaustive scan
  turned up. I added one Types-table row for it. Worth a "should `## Types`
  itself mention this?" follow-up, since right now the only place it's
  named is the Keywords chapter's index.
- **`auto`/`enable`/`disable` are reserved for a feature that doesn't
  exist.** `src/parser/control_flow.rs:1189-1211` — all three always
  return `Err("'... error catching' is not yet implemented. Use 'on
  error <action>.' instead.")`. They're live parser paths (not dead
  code), genuinely reserved, and genuinely not implemented. Per the rules
  ("a reserved word being wrong is a candidate, not a fix I make"), I
  documented them as-is with the parser's own wording rather than
  guessing at a shipped grammar for them.
- **`exists` has no file-level use.** The chapter's own File Operations
  section says plainly "There is no `exists` property" for files (the
  file-existence check is `is available`). The only living grammar for
  `exists` is `the environment variable "<NAME>" exists`
  (`src/parser/expressions.rs:1228` on). I documented it against that
  usage only, not against files.
- **Rows group related keywords** (e.g. `` `descriptor`, `modified`,
  `accessed`, `permissions`, `readable`, `writable`, `full` `` in one
  row) rather than "one keyword per row" everywhere, following the
  chapter's own existing convention (`` `Create`, `Change`,
  `Remove`/`Delete` `` is already one row). The brief said "one row each"
  for its 6-item Reserved Nouns table; I kept that literally for those
  six, but grouped the ~85 additional words to keep the new tables
  readable. If the master wants strictly one-keyword-per-row throughout,
  it's a mechanical split - the test doesn't care either way, since it
  reads every backtick span in a cell regardless of how many share a row.
- **Anchors** (`(#file-properties)`, `(#buffer-byte-access)`, etc.) were
  built by hand following the same lowercase-hyphen, punctuation-stripped
  rule already used elsewhere in the doc (verified against
  `#nothing-the-absent-value`, `#releasing-a-buffer`, and
  `#directories-mounting-and-process-control`, all pre-existing working
  links), but not run through a markdown renderer. Worth a spot-check;
  none of them affect the test or the compiler.

## Test placement

The brief said "in `src/lexer/tokens.rs`", but `reserved_aliases_doc_matches_the_const`
and `string_is_keyword_matches_the_live_lexer` - the pair it names as
"the pattern to copy" - both actually live in `src/codegen/tests.rs`
(`tokens.rs`'s doc comment names them by their real path,
`codegen::tests::...`). I put the new test beside them there rather than
in `tokens.rs`, matching where the pattern actually is.

## Gate

- `cargo build --release`: clean.
- `cargo test --release`: **all green** (15/15 test-result summaries
  `ok`, 0 failed), new test included and shown failing-then-passing
  above.
- `VOX_CORE_PATH=$PWD/coreasm ./test.sh`: **635 passed, 0 failed, 6
  skipped** (the 6 skips are pre-existing `manual_*` device/mount/reboot
  tests with no `.expected` file - unrelated to this change).

## Questions for the master

1. Is the 14→101 scope increase (see above) the right call, or should
   this be cut back to a narrower test that also credits `## Types`/
   `## Operators` as valid sources, leaving those two words-classes
   undocumented in the Keywords chapter itself?
2. Should `## Types` gain its own mention of `int`/`integer` as a
   `number` synonym, or is the Keywords-chapter pointer enough?
3. Are `auto`/`enable`/`disable` (the unimplemented "auto error
   catching" stubs) worth a line in `docs/BUGS_FOUND.md` as a known
   reserved-but-unimplemented surface, or is documenting them in the
   Keywords chapter (as done here) sufficient?

## Review round 1

Master accepted the 101-word scope and the drift-guard test as-is.
One correction applied: the Connectors row for `into` claimed a third
site, `Set byte N of <buffer> to <value>.`, that actually uses `to` -
the parser has exactly two `Token::Into` sites. Row is now "Destination
of `Read from <file> into <buffer>.` and `Get current time into
<name>.`". Re-verified `cargo test --release --bin vox
every_reserved_word_appears_in_a_keywords_chapter_table`: still passing
(the corrected row still carries the lone `` `into` `` backtick span in
its first column, so the drift-guard set is unaffected). The `int` row
and the other judgment calls above stand unchanged; whether `int` should
be accepted as a `number` synonym at all is a design question for the
owner, not something this branch touches.

## Review round 2 (Q11)

Owner ruling: `int`/`integer` KEEP, `auto`/`enable`/`disable` (and their
`automatic`/`enabled`/`disabled` spellings) DROP. Two of the "Judgment
calls" I flagged in round 1 are now resolved by the owner rather than
left open, so this round is a real lexer/parser change (not docs-only),
authorized by this specific ruling.

**`int`/`integer` (kept):** added one present-tense sentence to `## Types`
beside the type table - "`int` and `integer` are accepted spellings of
`number`." The Keywords-chapter Types-table row was already correct and
needed no change.

**`auto`/`enable`/`disable` (unreserved):** all six spellings
(`auto`/`automatic`, `enable`/`enabled`, `disable`/`disabled`) removed
from the live lexer:
- `src/lexer/scan.rs`: deleted the three fold arms.
- `src/lexer/tokens.rs`: deleted the `Auto`/`Enable`/`Disable` `Token`
  variants, their three `RESERVED_ALIASES` rows, and their three
  `as_keyword` arms.
- `src/parser/statements.rs`: deleted the three dispatch arms
  (`Token::Auto => self.parse_auto_error()`, etc.).
- `src/parser/control_flow.rs`: deleted `parse_auto_error`/
  `parse_enable`/`parse_disable` in full - each was a stub that always
  returned "not yet implemented", so removing them drops no working
  behavior, only the reservation and the permanent error.
- `LANGUAGE.md`: removed the `` `auto`, `enable`, `disable` `` row from
  Reserved Nouns and Properties, and the three now-dead rows
  (`automatic`→`auto`, `disabled`→`disable`, `enabled`→`enable`) from
  Reserved Aliases. **This second removal wasn't in the steer's line
  numbers but was required**: `reserved_aliases_doc_matches_the_const`
  failed immediately without it (those three pairs were "extra in
  LANGUAGE.md (not live aliases)" once the const rows were gone) - caught
  by the gate, not missed.
- `src/errors.rs:341`'s `ENGLISH_KEYWORDS` list (a separate, looser
  "did you mean" vocabulary for typo suggestions, unrelated to actual
  reservation) still contains `"auto"`, `"enable"`, `"disable"`. Left
  alone: it's not in the steer's scope, it isn't what makes a word
  reserved (`RESERVED_ALIASES` is), and the list already carries several
  other non-reserved words (`call`, `until`, `every`, `loop`, `through`,
  `by`, `output`, `stderr`, `catching`, `define`, `function`, `end`,
  `returning`, `taking`) - a pre-existing looseness, not something this
  ruling introduced. Flagging it rather than touching it.
- No existing test pinned these words as reserved: `grep` across
  `tests/` found only prose mentions inside `(...)` comments ("auto-run",
  "auto-grow", "disabled the shared _print_depth budget") in
  `118_buffer_set_dynamic_growth.vox`, `119_buffer_resize_preserves_dynamic.vox`,
  `205_map_inside_list.vox`, and the `manual_*` device tests - none of
  them compile `auto`/`enable`/`disable` as a keyword, so nothing needed
  retiring.
- Added `tests/610_auto_enable_disable_are_variable_names.vox` +
  `.expected`: declares a `number` named after each of the six spellings,
  prints all six (1 through 6). Verified directly against
  `target/release/vox` before the full gate run.

Gate re-run in full after this round:
- `cargo test --release`: **all green** (15/15 `ok`, 0 failed) - this
  included one real catch, described above
  (`reserved_aliases_doc_matches_the_const` failing until the Reserved
  Aliases table rows were also removed).
- `VOX_CORE_PATH=$PWD/coreasm ./test.sh`: **636 passed, 0 failed, 6
  skipped** (same pre-existing `manual_*` skips; the new 610 test is
  among the 636 passes).

Register: no entry added, per the steer (a ruling, not a defect).

DONE — stopped staged, patch parked
