# User Story
> As an author, I want to ask what type a list element actually holds so that I can branch on it and work with heterogeneous data safely.

---

## Feature/Problem Description

**Summary:**
Add runtime type predicates — `If item is a number, ...`, `is a text`,
`is a decimal`, `is a boolean` — that compile to a comparison against
the element's per-slot type tag.

**Context:**
Stage 1a made mixed lists *store and print* correctly, but an author
still cannot branch on an element's type, so mixed lists are readable
but not yet programmable. Predicates are the author-facing payoff of the
tag machinery, and they are the prerequisite idiom for writing a JSON
consumer in Vox (stage 1e). They also read as natural Vox sentences,
which fits the language's surface grammar without inventing new syntax
shapes.

**Current Behavior (if bug):**
No way to inspect an element's type. Arithmetic on a mixed element
dispatches statically, so `item add 1` where `item` holds a text does
pointer arithmetic silently.

**Expected Behavior:**
```
a list called "m" is [1, "two", 3.5, yes].
For each item in m,
  If item is a text, print "text: {item}",
  otherwise if item is a decimal, print "decimal: {item}",
  otherwise print "number: {item}".
```

---

## Scope
- [x] Backend (lexer/parser/analyzer/codegen)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- Type *conversion* sentences (`treat item as a number`) — separate feature.
- Predicates on values crossing function boundaries (stage 1d).
- Guarding arithmetic automatically; this stage gives authors the tool to
  guard it themselves. Automatic guarding is a later decision.

---

## Technical Approach

**Proposed Solution:**
Parse `<expr> is a <type-noun>` as a new boolean-valued expression
(working name `Expr::TypeCheck { value, type_noun }`), reusing the
existing `is` comparison entry point in the parser and disambiguating on
the `a`/`an` article plus a known type noun. Vox already has
`Expr::PropertyCheck`, which is the closest existing precedent and where
the parsing hook likely belongs.

Codegen evaluates the operand; if it is a mixed element the runtime tag
is already available (in `r11` for a fresh element read, or in the
variable's shadow tag slot from `mixed_tag_slots`), so the predicate is
a `cmp` plus `sete`. If the operand is *statically* typed, the predicate
folds to a compile-time constant 1 or 0 — which is correct, costs
nothing, and means the sentence is legal on any value, not just mixed
ones.

Type nouns map to tags: `number` → 0, `text` → 1, `decimal` → 2,
`boolean` → 3. Reserve `list` → 4, `map` → 5, `nothing`/`null` → 6 for
later stages (parse them now, or leave until 1e — implementer's choice,
but do not reuse the numbers).

**Files/Components Affected:**
- `src/lexer/mod.rs` — type-noun keywords if not already tokenized
- `src/parser/mod.rs`, `src/parser/ast.rs` — new expression variant
- `src/analyzer/mod.rs` — validate the type noun; reject unknown nouns
  with a helpful error listing the valid ones
- `src/codegen/mod.rs` — tag comparison; constant folding for static
  operands; reuse `mixed_tag_slots` / `r11` conventions
- `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`
- `tests/`

**Dependencies:**
Stage 1a (merged). Benefits from 1b but does not require it.

---

## Success Criteria
- [ ] Feature works as described in expected behavior
- [ ] All tests pass
- [ ] Predicates on statically-typed values fold at compile time
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria
1. **Given** a mixed list element holding a text, **when** the author
   writes `If item is a text`, **then** the branch is taken.
2. **Given** the same element, **when** the author writes
   `If item is a number`, **then** the branch is not taken.
3. **Given** a statically-typed integer variable, **when** the author
   writes `If x is a number`, **then** the condition folds to true at
   compile time and emits no runtime comparison.
4. **Given** an unknown type noun (`If item is a widget`), **when**
   compiled, **then** a clear error names the valid type nouns.
5. **Given** a mixed list iterated with predicates, **when** run, **then**
   every element is classified correctly, including after the list has
   grown past a reallocation.
6. **Given** the existing suite, **when** it runs, **then** all tests pass.

---

## Tasks
- [x] Decide and document the exact sentence forms accepted (including
      negation: `is not a text`)
- [x] Add the AST variant and parse rule
- [x] Analyzer validation with a helpful error message
- [x] Codegen: runtime tag compare for mixed operands
- [x] Codegen: constant folding for statically-typed operands
- [x] Add tests: each type noun; negation; folding; post-realloc elements;
      predicate inside a nested `If`/`otherwise` chain
- [x] Update `LANGUAGE.md` (new subsection under Lists and Collections)
      and mark 1c done in `docs/COLLECTIONS_ROADMAP.md`
- [x] Run `./test.sh` and `cargo test --release`

---

## Notes
- Naming: Vox already uses `text`, `number`, `decimal`, `boolean` in
  declarations, so reusing those nouns keeps one vocabulary. Avoid
  introducing `string`/`float`/`int` at the surface.
- Boolean elements share the integer representation but have a distinct
  tag (3), so `is a boolean` and `is a number` must be distinguishable —
  do not collapse them in codegen even though both print as numbers.
- Consider a companion sentence in a later stage for safe extraction
  (e.g. `treat item as a number` returning a checked value); note it in
  the roadmap rather than building it here.
- **Scope added during implementation:** a predicate result is a boolean
  value, so `append <value> is a <noun> to <list>` (and `is not a`) is now
  accepted by `parse_append` (via a shared `parse_type_noun_after_article`
  helper) and tagged `TAG_BOOLEAN` at the store. This made the
  `TypeCheck` arms of `prescan_expr_tag` / `emit_time_expr_tag` and the
  append element-type classifier reachable (otherwise dead code) and fixed a
  latent asymmetry: `UnaryOp { Not, .. }` is now tagged `TAG_BOOLEAN` in
  both passes (a negation is always boolean), so `[not x]` and appended
  negated predicates classify and tag consistently. Covered by integration
  test `162_predicate_tagged_boolean` and the
  `type_predicate_result_appends_tagged_boolean` unit test.
