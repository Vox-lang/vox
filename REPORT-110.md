# REPORT-110 — quoted one-word name in a `{...}` format slot

Worktree: `~/scr/english/worktrees/wt-fix-110`, branch
`fix/bug-110-quoted-name-in-format-slot`, off `main` at 4995394 (v0.4.14).

## Mechanism

`parse_format_string` (`src/parser/expressions.rs`) splits a `{...}` slot's
content on the first unquoted `:` and hands the name/expression half to
`try_parse_expression`, which decided whether to run it through the real
lexer+parser or use it verbatim as a `FormatPart::Variable` name:

```rust
if !content.contains(' ') || content.chars().all(|c| c.is_alphanumeric() || c == '_') {
    return None;
}
```

The second clause is dead code — any string containing a space already
fails `.all(is_alphanumeric)`, so the guard's only real test was "does this
content contain a space". `'tally's size` and `'the toolbox'` both contain
a space, so they fell through to the lexer, which correctly recognises the
leading `'` and produces the right token stream (this is exactly why the
brief's two "already works" examples both happen to be the shapes with a
space in them). A bare quoted one-word token, `'tally'`, has no space
anywhere in it, so the guard returned `None` *before the lexer ever saw
it*. The caller's fallback then built `FormatPart::Variable { name:
"'tally'", .. }` — the placeholder's raw text, quote characters included,
used directly as the variable name. Every downstream lookup
(`is_variable_available` in the analyzer, `resolve_format_variable` in
codegen — documented there as "THE single name-resolution path shared by
every format-string sink") keys off that exact string, and no variable is
ever registered under a name containing literal `'` characters — hence
`Unknown variable: 'tally'`, quotes baked into the message because they
were baked into the (wrong) name that was looked up.

This is a lexer/parser split issue, not a character-literal issue: the
general-purpose lexer (`src/lexer/scan.rs`) already correctly distinguishes
`'x'` (`is_char_literal`, exactly one character) from `'tally'`
(`is_single_quoted_identifier`, two or more) wherever it runs. The bug was
that the slot's fast-path guard skipped the lexer entirely for any
space-free content, so it never got a chance to make that distinction for
a lone quoted token.

## Disambiguation: is a one-letter quoted name (`'x'`) ever legal?

The brief guessed a slot-only default ("inside a slot, a quoted token is
always a name, never a character") for this case. I did not take that
default — I checked the spec and the shipped binary instead, per the
brief's own "narrowest correct rule rather than guessing" instruction.

- LANGUAGE.md:691 (rule 3, Naming Rules): "Exactly one character between
  single quotes remains a **character literal** (`'A'`): that is why
  single-character quoted identifiers do not exist. Write `x`, not `'x'`."
- LANGUAGE.md:670–671: "Three forms, no overlap, **no context-sensitivity**."
- Confirmed directly against the shipped 0.4.14 binary before writing any
  code: `a number called 'x' is 5.` is already a compile error ("Expected a
  name, got IntegerLiteral(120)"), and bare `Print 'x'.` already prints
  `120`.

So a one-letter quoted name is not legal anywhere in the language today,
slots included, and the brief's tentative default would have been wrong —
it would have made `{'x'}` behave differently from every other position
`'x'` can appear in. The fix instead defers entirely to the lexer's
existing, already-correct distinction, so `{'x'}` now renders `120`,
identical to `Print 'x'.` outside any slot, and `Set byte N of <buffer> to
'A'` (the manual's own character-literal position) is untouched — it was
never routed through this code path at all. Test 629 pins both the
byte-write and the slot character-literal reading in one program.

## Fix

`src/parser/expressions.rs`, `try_parse_expression`: narrowed the guard so
it only bypasses the lexer for a genuinely bare word (no quotes, no
spaces); anything else — a lone single-quoted token included — now falls
through to the existing lex-and-parse path, unchanged, which already
handled the multi-word and possessive-property shapes correctly:

```rust
if !content.contains(' ') && !content.contains('\'') {
    return None;
}
```

No new codegen or analyzer path was added. A lone quoted identifier now
resolves via `Expr::Identifier` → `FormatPart::Expression`, the exact same
path `'the toolbox'` already used successfully before this fix (proof this
routing is safe: it was already shipping and tested for the multi-word
case). One visible side effect: an *unknown* quoted name's error message
now reads `Unknown variable: tally` (no quotes) instead of `Unknown
variable: 'tally'` (quotes baked into the wrong literal name it used to
look up) — cosmetic only, and it now matches exactly what a genuinely bare
`{tally}` unknown-variable error already looked like.

## Files touched

- `src/parser/expressions.rs` — the fix (`try_parse_expression` guard).
- `LANGUAGE.md` — reworded the two Functions-chapter sentences the brief
  named (~751, ~753) from "bare … or single-quoted multi-word" to "a bare
  word, or any name in single quotes (a single word may be quoted too)".
  **Beyond brief scope:** I found and fixed a third, near-identical
  sentence in the same chapter's Calls section (line ~875, "Function name
  is a bare single word … or a single-quoted multi-word name") that makes
  the same now-wrong claim about call-site function names. I fixed it the
  same way for internal consistency, since leaving it would have
  contradicted the two sentences right above it in the same chapter after
  this same ruling. I did **not** touch a fourth, similarly-worded sentence
  at LANGUAGE.md:973 ("A thing name may be a bare word … or a quoted
  multi-word name") — different chapter, different declaration kind, not
  named in the brief — see Questions below.
- `docs/BUGS_FOUND.md` — new entry #110.
- `CHANGELOG.md` — new `## [Unreleased]` section (none existed above
  `## [0.4.14]`) with a `### Fixed` bullet.
- `tests/620`–`629` (`.vox` + `.expected`, 10 pairs) — see below.

## Tests (620–629)

All ten new pairs, plus a temporary before/after check (see Verification):

- 620 number, 621 text, 622 boolean, 623 float, 624 buffer, 625 list,
  626 map — each declares `a <type> called '<name>' is …` and interpolates
  `{'<name>'}` in a `Print`, alongside the bare `{<name>}` form to prove
  parity.
- 627 — a quoted one-word name *with* a possessive property in the same
  slot (`{'nums's length}`), a different type (list) from the manual's own
  buffer example, to pin that the already-working space-containing path
  still works post-fix.
- 628 — a quoted one-word name inside a `Write "{...}" to <file>` format
  string, proving the fix covers every format-string sink, not just
  `Print` (`resolve_format_variable` is the shared path; this exercises it
  from the other caller).
- 629 — the disambiguation pin: `Set byte 1 of buf to 'J'` (character
  literal in byte-write position, untouched) and `Print "{'A'}"` (character
  literal in slot position, now correctly `65`, matching bare `Print
  'A'.`) in the same program.

No `compile_fail` test was added: the fix introduces no new refusal, only
widens which content previously-broken content now compiles successfully.

## Verification

- `cargo test --release`: all suites green (unit + integration, including
  the `compile_fail` corpus).
- `VOX_CORE_PATH=$PWD/coreasm ./test.sh`: **645 passed, 0 failed, 6
  skipped** (baseline before this branch's tests: 635 passed — exactly the
  10 new tests, no regressions).
- Before writing the fix, stashed the diff and reran the 620–629 repros
  against the un-fixed binary: all nine bug-repro tests (620–626, 628, 629)
  failed with `Unknown variable: '<name>'` exactly as the brief's repro
  showed; 627 (the already-working possessive-property case) compiled and
  passed unchanged, confirming it as a regression guard rather than a new
  repro. Restored the fix from the stash (`git stash apply` + verified
  `git diff --stat`, then dropped the entry after re-confirming its tag)
  and rebuilt before finalizing.

## Review round 1

Master accepted the fix as-is (mechanism, the one-clause change, the
char-literal reading kept per LANGUAGE.md:691, tests 620–629) — master's
own probes passed on this branch's binary. One consistency edit requested:
the ruling covers every name, so the Things-chapter sentence at
LANGUAGE.md:973 gets the same rewording as the three Functions-chapter
sentences, resolving question 1 below. Applied:

```
A thing name may be a bare word (`point`) or a quoted multi-word name
(`'bounding box'`), the same forms any identifier takes:
```
→
```
A thing name may be a bare word, or any name in single quotes (a single
word may be quoted too) (`point`, `'bounding box'`), the same forms any
identifier takes:
```

Verified this is a doc-only correction, not a missing feature: a one-word
quoted thing name already worked on the unmodified binary before this
change —

```vox
A thing called 'gadget' has
  a number called weight is 1.

a 'gadget' called g.
Set g's weight to 5.
Print g's weight.
```

→ prints `5`. No code change was needed for this edit. Re-ran the full
gate after the edit (doc-only, but re-parked and re-verified per the
steer): `cargo test --release` green, `VOX_CORE_PATH=$PWD/coreasm
./test.sh` still 645 passed / 0 failed / 6 skipped.

## What I could NOT do

Nothing I attempted was blocked.

## Questions for the master

1. ~~LANGUAGE.md:973~~ — resolved in review round 1 above; reworded.
2. I fixed a third occurrence of the two named sentences (LANGUAGE.md:875,
   Calls section) that wasn't in the brief's line count, since it was a
   near-verbatim duplicate of ~751 in the same chapter and leaving it
   would have made the chapter self-contradictory. Flagging in case that
   line was deliberately left out for a reason I'm not seeing.

DONE — stopped staged, patch parked
