# User Story
> As an author, I want a fixed-shape record of a few values so that I can group related data without inventing a list or a set of parallel variables.

---

## Feature/Problem Description

**Summary:**
Introduce tuples: fixed-arity, heterogeneous, immutable records whose
per-position types are known statically.

**Context:**
`docs/COLLECTIONS_ROADMAP.md` is explicit that what makes a tuple a tuple
is fixed arity and immutability — not the ability to hold different types
per slot, which Vox lists already do. Tuples are the record type; they
are not the ML structure (that is the matrix, Track 2) and not the
dynamic data structure (that is the mixed list, Track 1).

**Current Behavior (if bug):**
No way to group a small fixed set of values. Authors must use parallel
variables, or a list — which is growable and mutable, so it models the
wrong thing and pays for a heap allocation and a header it does not need.

**Expected Behavior:**
```
a pair called "point" is (3, 4).
a pair called "entry" is ("Ada", 36).
print point's first.
print entry's second.
```
Tuples are immutable: attempting to assign to a position is a compile
error. Arity and per-position types are fixed at declaration.

---

## Scope
- [x] Backend (lexer, parser, analyzer, codegen)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- Destructuring syntax (stage 3b).
- Multiple return values (stage 3c).
- Arity above a small documented maximum; start with pairs and triples.
- Nesting tuples inside lists or maps — decide whether to allow it, and
  if deferred, produce a clear error rather than silent misbehavior.

---

## Technical Approach

**Proposed Solution:**
Because arity and per-position types are fully static, a tuple needs no
runtime header and no heap allocation: it can occupy N consecutive stack
slots, with the compiler's symbol table recording the type of each
position. This is the cheapest possible representation and is the direct
consequence of the type being static — worth stating in the code comments
because it is the key design difference from lists.

The analyzer records a tuple type as an ordered vector of member types.
Position access (`point's first`, `point's second`) resolves statically
to a slot and a type, so downstream code (printing, arithmetic) uses the
existing static paths with no dispatch at all.

Immutability is enforced in the analyzer: any assignment targeting a
tuple position is rejected with a message explaining that tuples are
fixed and suggesting a list if the author wants to modify elements.

**Files/Components Affected:**
- `src/lexer/mod.rs` — `pair`, `triple`, and parenthesized literals
- `src/parser/mod.rs`, `src/parser/ast.rs` — tuple type, literal, access
- `src/analyzer/mod.rs` — tuple types, immutability enforcement
- `src/codegen/mod.rs` — stack slot allocation, positional access
- `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`
- `tests/`

**Dependencies:**
None on Tracks 1 or 2. Stage 2d wants tuples for argmax, so scheduling
this before 2d is preferable.

---

## Success Criteria
- [ ] Feature works as described in expected behavior
- [ ] All tests pass
- [ ] No heap allocation for tuples (verify in emitted assembly)
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria
1. **Given** `a pair called "point" is (3, 4).`, **when** each position
   is printed, **then** 3 and 4 are printed.
2. **Given** a pair of mixed member types `("Ada", 36)`, **when** each
   position is printed, **then** each prints according to its static
   type, with no runtime dispatch in the emitted assembly.
3. **Given** an attempt to assign to a tuple position, **when** compiled,
   **then** a clear error explains that tuples are immutable.
4. **Given** access to a position beyond the tuple's arity, **when**
   compiled, **then** a compile-time error is reported (not a runtime
   bounds check — the arity is static).
5. **Given** a tuple declared inside a function, **when** the function
   runs, **then** its slots are correctly scoped to the frame.
6. **Given** the existing suite, **when** it runs, **then** all tests pass.

---

## Tasks
- [ ] Finalize surface syntax: `pair`/`triple` versus a general `tuple`,
      and the literal form
- [ ] Lexer and parser support for tuple literals and declarations
- [ ] Analyzer: tuple types, arity checks, immutability enforcement
- [ ] Codegen: stack slot allocation and positional access
- [ ] Tests: construction, access, mixed member types, immutability
      error, out-of-arity error, function scoping
- [ ] Update `LANGUAGE.md` and `docs/COLLECTIONS_ROADMAP.md`
- [ ] Run `./test.sh` and `cargo test --release`

---

## Notes
- Naming matters for the language's voice: `a pair called "p"` reads far
  better than `a tuple called "p"`. Consider `pair` and `triple` as the
  spelled forms with a general form only if a real need appears.
- `first` and `second` already exist as list properties; reusing them for
  tuples is consistent, but check the parser and analyzer for any
  assumption that those properties imply a list.
- Watch the interaction with parenthesized expressions in the grammar:
  `(3)` must remain an arithmetic grouping, not a one-element tuple.
