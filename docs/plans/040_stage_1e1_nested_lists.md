# User Story
> As an author, I want lists to contain other lists so that I can represent tree-shaped data such as JSON arrays.

---

## Feature/Problem Description

**Summary:**
Activate reserved tag 4 (`list`) so a list slot may hold a pointer to a
child list, with correct printing, iteration, and element access at every
level.

**Context:**
Tag 4 was reserved in stage 1a precisely so nesting would not require a
layout change. Nesting is the first of the three JSON prerequisites
(nesting, maps, null) identified in `docs/COLLECTIONS_ROADMAP.md`.

**Current Behavior (if bug):**
A list literal containing a list literal is either rejected or stores the
child pointer with an integer tag, so it prints as a raw address.

**Expected Behavior:**
```
a list called "nested" is [1, [2, 3], "four"].
print nested.
(prints: [1, [2, 3], "four"])
print element 2 of nested.
(prints: [2, 3])
```
Iterating the outer list yields the child list as a value whose type
predicate `is a list` is true, and which can itself be iterated.

---

## Scope
- [x] Backend (parser, codegen, coreasm runtime)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- Maps and null (stage 1e-2).
- The JSON/YAML parser itself (stage 1e-3).
- Deep copy / structural equality of nested lists.
- Freeing nested structures; Vox's list memory is already leak-bounded
  and reclaimed at process exit, and this stage does not change that.

---

## Technical Approach

**Proposed Solution:**
Parser: allow a list literal as an element of a list literal (likely
already parses; verify). Codegen: when a list-literal element is itself
a list, the child is generated first, its pointer stored in the slot, and
the slot tagged 4.

Runtime: make `_list_print` (from plan 000) recursive — on tag 4, call
itself with the child pointer. Add a depth guard to avoid unbounded
recursion on a cyclic structure (a list appended to itself), failing
safely via the existing `_last_error` mechanism rather than a stack
overflow.

Reads: `element N of`, `first`/`last`, and iteration must propagate tag 4
the same way they propagate tags 0–3 today, so a nested list bound to a
loop variable is usable as a list (i.e. `variable_types` gets `List` and
the shadow tag records 4).

**Files/Components Affected:**
- `src/parser/mod.rs` — nested list literals (verify/extend)
- `src/codegen/mod.rs` — nested literal emission; propagating tag 4 into
  loop variables and element reads; `is a list` predicate wiring
- `coreasm/x86_64/list.asm` — recursive printing with a depth guard
- `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`
- `tests/`

**Dependencies:**
Plan 000 (whole-list printing) should land first — nested printing is a
recursive extension of it. Stage 1c gives `is a list`. Stage 1d is needed
before a *recursive Vox function* can walk nested lists, but not for this
stage's own acceptance criteria.

---

## Success Criteria
- [ ] Feature works as described in expected behavior
- [ ] All tests pass
- [ ] Cyclic structures fail safely rather than crashing
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria
1. **Given** `[1, [2, 3], "four"]`, **when** printed, **then** the nested
   list renders inline as `[1, [2, 3], "four"]`.
2. **Given** the same list, **when** element 2 is read into a variable,
   **then** that variable is usable as a list (length, iteration,
   element access).
3. **Given** a three-level nesting, **when** printed, **then** all levels
   render correctly.
4. **Given** a nested list appended to a list after a reallocation,
   **when** read back, **then** its tag is still 4.
5. **Given** a list that (directly or indirectly) contains itself,
   **when** printed, **then** the program stops at a documented depth
   limit and sets the error flag instead of overflowing the stack.
6. **Given** the existing suite, **when** it runs, **then** all tests pass.

---

## Tasks
- [ ] Verify/extend parsing of nested list literals
- [ ] Codegen: emit child list, store pointer, write tag 4
- [ ] Propagate tag 4 through element reads, `first`/`last`, iteration
- [ ] Make `_list_print` recursive with a depth guard and error flag
- [ ] Wire the `is a list` predicate (stage 1c) to tag 4
- [ ] Tests: literal nesting, deep nesting, nested-after-append, element
      extraction and re-iteration, cycle safety
- [ ] Update `LANGUAGE.md` and `docs/COLLECTIONS_ROADMAP.md`
- [ ] Run `./test.sh` and `cargo test --release`

---

## Notes
- Pick and document the depth limit (suggestion: 64) — deep enough for
  real JSON, shallow enough to stay well inside the stack.
- A nested child list is heap-allocated exactly like a top-level one, so
  the existing realloc/aliasing semantics apply unchanged: a child that
  grows may move, and the parent slot must be updated. Appending to a
  nested list *through* the parent is the sharp edge here — either
  support it explicitly and update the parent slot, or reject it with a
  clear error this stage and revisit in 1e-3.
