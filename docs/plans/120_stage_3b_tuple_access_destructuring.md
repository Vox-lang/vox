# User Story
> As an author, I want to unpack a tuple into named variables in one sentence so that my code reads naturally instead of repeating positional accesses.

---

## Feature/Problem Description

**Summary:**
Add destructuring: a sentence form that binds each position of a tuple to
a named variable in one statement.

**Context:**
Stage 3a gives construction and positional access. Positional access
alone (`point's first`, `point's second`) is serviceable but wordy, and
it reads poorly once the positions have meaning. Destructuring is what
makes tuples pleasant, and it is a prerequisite for the `(value, error)`
idiom that stage 3c enables.

**Current Behavior (if bug):**
```
a number called "x" is point's first.
a number called "y" is point's second.
```
Two statements, with the member types restated by the author even though
the compiler already knows them.

**Expected Behavior:**
```
take x and y from point.
print x.
print y.
```
The bound variables receive their types from the tuple's per-position
types automatically; no type annotation is needed or accepted.

---

## Scope
- [x] Backend (parser, analyzer, codegen)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- Partial or wildcard destructuring (skipping positions) unless it falls
  out for free; if deferred, produce a clear error.
- Nested destructuring of tuples within tuples.
- Multiple return values (stage 3c), which builds on this.

---

## Technical Approach

**Proposed Solution:**
Parse a destructuring statement binding N names to a tuple of arity N,
with an arity mismatch as a compile error naming both counts. Each bound
name is registered in the symbol table with the corresponding position's
static type, then allocated a stack slot and initialized by copying from
the tuple's slot — a plain move per position, since everything is static.

Because tuples are immutable, the bound variables are copies and are
themselves ordinary mutable variables. State this in the documentation:
authors will reasonably wonder whether reassigning `x` affects `point`.

**Files/Components Affected:**
- `src/parser/mod.rs`, `src/parser/ast.rs` — destructuring statement
- `src/analyzer/mod.rs` — arity check, name binding, type propagation,
  duplicate-name and shadowing rules
- `src/codegen/mod.rs` — slot allocation and per-position moves
- `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`
- `tests/`

**Dependencies:**
Stage 3a.

---

## Success Criteria
- [ ] Feature works as described in expected behavior
- [ ] All tests pass
- [ ] Bound variables receive correct static types with no annotation
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria
1. **Given** a pair of a number and a text, **when** destructured,
   **then** each bound variable has the correct type and prints correctly.
2. **Given** a destructuring with the wrong number of names, **when**
   compiled, **then** an error names both the expected and given counts.
3. **Given** a bound variable that is later reassigned, **when** the
   original tuple is read, **then** the tuple is unchanged (copy
   semantics).
4. **Given** a destructuring inside a function body, **when** the
   function runs, **then** the bindings are scoped to that frame.
5. **Given** a destructuring that reuses an existing variable name,
   **when** compiled, **then** the behavior matches Vox's existing
   shadowing rules (and a test pins whichever rule is chosen).
6. **Given** the existing suite, **when** it runs, **then** all tests pass.

---

## Tasks
- [ ] Choose the sentence form (`take x and y from point.` is a
      candidate; check it against the existing grammar for conflicts)
- [ ] Parser support
- [ ] Analyzer: arity check, type propagation, shadowing decision
- [ ] Codegen: slot allocation and moves
- [ ] Tests: types, arity error, copy semantics, function scoping,
      shadowing
- [ ] Update `LANGUAGE.md` and `docs/COLLECTIONS_ROADMAP.md`
- [ ] Run `./test.sh` and `cargo test --release`

---

## Notes
- The chosen wording should not collide with the existing `from` usages
  in the grammar (ranges, file reads). Check the parser before settling.
- Copy semantics are the only sensible choice given tuples are immutable
  and stack-allocated, but they must be documented explicitly — this is
  the first place in Vox where one statement creates several bindings.
