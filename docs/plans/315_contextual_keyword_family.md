# 315 — The contextual keyword family

**Status:** rulings made by TheJostler (2026-08-18); staged, not started.
Ships as its own release (0.4.3) with its own red-team pass, the way
things did. Not part of 0.4.2.

**Reference implementation:** commit `9f31e67` (the `count` fix, PR #153)
is the recipe every word here follows: delete the word's token, lex it as
an ordinary identifier, and have the parser claim it **by lexeme, in
position** at each site that consumed the token.

## The rule being applied

LANGUAGE.md's "Two classes of special word" section (added in 0.4.2)
states the test: **if every position where a word means something is
grammatically identifiable, it is contextual; only a word that would be
ambiguous in ordinary positions is reserved.** This plan moves every word
that passes the test into the contextual class, so the language applies
its own rule consistently instead of word by word as someone happens to
trip on one.

The pattern already ships four times over: `start`/`begin`/`stop`/
`finish` (timers), `send` (signals), `waiting` (`without waiting`),
`available` (`is available`), `name` (property, matched by lexeme in the
parser today), and `count` (0.4.2).

## Ruling 1 — Class A: possessive/phrase-position words. APPROVED.

All were probed against the 0.4.2 compiler on 2026-08-18; parser site
counts from `grep -rn "Token::<T>" src/parser/ src/analyzer/`.

| Word | Claimed positions | Sites | Notes |
|---|---|---|---|
| `capacity` | `x's capacity` | 2 | cleanest; do it first |
| `raw` | `arguments's raw` | 2 | |
| `all` | `x's all` (incl. loop sources) | 4 | |
| `first` | `x's first`, argument/env property | 7 | |
| `last` | `x's last`, argument/env property | 7 | |
| `second` | `arguments's second` AND the duration unit (`Wait 1 second.`) | 10 | two claimed positions, both grammatically fixed. The absurdity motivating it: `third` is already an ordinary identifier, so today `second` and `third` sit on opposite sides of the law |
| `size` | `x's size`, the `N bytes in size` phrase | 6 | both positions are fixed phrases |
| `length` | `x's length` | 0 (lexer maps it to `Token::Size`) | it is a Reserved Alias of `size`; the lexer mapping moves to identifier and the possessive dispatch accepts the lexeme `length` as `size`'s synonym. Update the Reserved Aliases table — `length` leaves it |
| `version` | `Library X version "…"`, `see X version "…"` | header sentences | lowest value, but passes the test |

## Ruling 2 — Class B: predicate words, with **predicate-wins**. APPROVED.

`empty`, `even`, `odd`, `positive`, `negative`, `zero`.

Two claimed positions each: after `is` / `is not` (`If x is empty then`)
and as possessive properties (`letters's empty`).

**The predicate-wins rule (TheJostler's ruling):** in predicate position
the predicate reading wins, exactly as `available` already behaves —
`src/parser/expressions.rs:150` matches it as
`Token::Identifier(ref id) if id.eq_ignore_ascii_case("available")`, the
in-tree model for this class. Consequence, which must be documented and
tested: a variable named `empty` cannot be compared with bare
`x is empty` (that stays the emptiness predicate); the comparison is
written explicitly as `x is equal to empty`. Same for all six words.

## Ruling 3 — Class C: DEFERRED. Do not touch.

- `flag`, `message`, `string` — type-position words; freeing them opens
  "are type names reserved?", which touches `number`/`text` and is a
  separate design conversation.
- `ms` — duration-unit alias; passes the test but marginal value.
- `arg`/`args`/`ver` and the other aliases — the live question is whether
  those aliases should exist at all, not whether to free them.

If any Class C word turns out to block Class A/B work, stop and report
rather than widening scope.

## Ruling 4 — Class D: stays reserved. Do not touch.

`times` (multiplication), `bigger`, `up`, statement starters, connectors,
type names, and everything structural. These fail the test: they would be
ambiguous in ordinary expression positions.

## Documentation corrections (part of this work)

1. **LANGUAGE.md:3929 claims `end` is reserved ("`end` belongs to the
   `exit` family of keywords and remains reserved"). It is not** — the
   0.4.2 compiler accepts `a number called end is 1.` Reconcile:
   determine whether `end` was ever enforced, and either fix the sentence
   or (if the compiler is wrong) raise it as its own finding. Do not
   silently re-reserve a word that programs may already use.
2. The diagnostic `Expected arguments property (count, first, last,
   empty, all, raw)` omits `name` and `second`, both real properties.
   Fix the list (and its environment twin if it has the same gap).
3. The Reserved Aliases table: `length` leaves it (Ruling 1). Check
   `ms`/`message`/`string` rows still read correctly — they stay.
4. The "Two classes of special word" section lists the contextual family;
   extend it with the words shipped here.
5. The reserved-word Tip (`'{}_value' or 'my_{}'`) violates
   docs/STYLE.md's naming rules. Since far fewer words will now hit it,
   rewrite the Tip to suggest the thing's true name or the quoted form,
   not a prefix/suffix mangle.

## Tests

Per word, follow `tests/count_variable.vox`'s shape: declaration, `Set`,
a `While` condition, a function parameter, the possessive form, and — for
words with a second claimed position — that position exercised in the
same program (`second` as a duration unit; `size` in `bytes in size`;
`version` in a `see`/`Library` header via the shared-library tests).

Class B words additionally require the predicate-wins semantics pinned:

```
a number called empty is 3.
Print empty.
a list called letters is [].
Print "predicate: {letters's empty}".
If empty is equal to 3 then,
    Print "explicit comparison reaches the variable".
```

plus a test proving `x is empty` still means the predicate when a
variable named `empty` exists.

Gates: `cargo test` and `./test.sh`, baselines cargo ≥ 312,
integration ≥ 356, skips ≤ 6, zero build warnings.

## Process

- One worker, one class per session (A then B), reviewed at the boundary.
- Red-team pass after both land, before release — attack the ambiguity:
  programs that use a freed word as a variable AND its claimed position
  in the same sentence, chained possessives, format-string interpolation
  of freed-word variables, `Set second to 1. Wait second seconds.` and
  the nastiest compositions it can construct.
- Commits signed by the master; workers stop before committing.
- Release as 0.4.3: "every property word now sits in the right class."
