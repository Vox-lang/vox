# User Story
> As an author, I want to pass heterogeneous values into and out of functions so that I can write reusable code (like a JSON walker) that handles data of any shape.

---

## Feature/Problem Description

**Summary:**
Introduce a declared dynamic type (working name `value`) usable as a
function parameter type and return type, whose runtime type tag travels
alongside the payload through the calling convention.

**Context:**
This is the largest sub-project of Track 1 and the last structural
prerequisite for writing a JSON parser *in Vox* rather than in the
compiler. Today, parameters are statically typed, so a mixed list
element loses its tag the moment it is passed to a function. Recorded in
`docs/COLLECTIONS_ROADMAP.md` as stage 1d.

**Current Behavior (if bug):**
```
to describe (item as a text) ...
```
There is no parameter type that accepts "whatever this slot holds". A
mixed element passed as `a number` is reinterpreted; passed as `a text`
it is dereferenced as a pointer.

**Expected Behavior:**
```
to describe (item as a value) returning text,
  If item is a text, return "a text",
  otherwise if item is a decimal, return "a decimal",
  otherwise return "a number".

a list called "m" is [1, "two", 3.5].
For each item in m, print describe(item).
```
Values of type `value` retain their tag across the call, work with the
stage 1c predicates inside the callee, and can be appended back into
lists with the correct tag preserved.

---

## Scope
- [x] Backend (parser, analyzer, codegen, calling convention)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- Nested containers as `value` payloads (stage 1e adds tags 4/5/6; this
  stage must not *preclude* them but need not carry them).
- Arithmetic on `value` operands without an explicit predicate guard.
- Shared-library ABI stability guarantees for `value` parameters.

---

## Technical Approach

**Proposed Solution:**
Represent a dynamic value as a (payload, tag) pair. Three candidate
transports, to be chosen with measurements and written up in the commit
message:

1. **Paired registers** — payload in the normal argument register, tag in
   a parallel register. Fastest; complicates the register allocator and
   the stack-spill path for functions with many arguments.
2. **Packed word** — tag in the high bits of the payload word. No ABI
   change at all, but pointers must be maskable and it forecloses future
   tag growth; likely too clever.
3. **Stack-passed tag** — payload in register, tag in a fixed stack slot
   of the frame. Simplest and most uniform; slowest.

Recommendation: (1) for parameters and returns, falling back to (3) when
arguments spill to the stack, and document the rule in one place.

The analyzer needs a `value` type in the type table that unifies with
everything at the call boundary but is *not* implicitly usable as a
number or text inside the callee — extraction must go through a stage 1c
predicate (or a later conversion sentence). This is what keeps the
"dynamic at the data boundary, static in the core" principle intact.

**Files/Components Affected:**
- `src/parser/ast.rs`, `src/parser/mod.rs` — `value` as a `Type`
- `src/analyzer/mod.rs` — unification rules, error messages for misuse
- `src/codegen/mod.rs` — `emit_function_call`, parameter binding,
  `Statement::Return`, `mixed_tag_slots` for parameters, plus the
  existing `r11` element-read convention
- `coreasm/x86_64/` — only if a helper is needed for spill handling
- `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`
- `tests/`

**Dependencies:**
Stage 1a (merged); stage 1c strongly recommended first (predicates are
how a callee inspects a `value`); stage 1b recommended.

---

## Success Criteria
- [ ] Feature works as described in expected behavior
- [ ] All tests pass
- [ ] Calling convention documented in `docs/` (a short ABI note)
- [ ] Recursion with `value` parameters works (prerequisite for JSON)
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria
1. **Given** a mixed list, **when** each element is passed to a function
   taking `a value`, **then** predicates inside the callee classify each
   element correctly.
2. **Given** a function returning `a value`, **when** its result is
   appended to a list, **then** the appended slot carries the correct tag.
3. **Given** a function with enough arguments to spill to the stack,
   **when** a `value` is among them, **then** its tag arrives intact.
4. **Given** a recursive function taking `a value`, **when** called to a
   depth of at least 100, **then** tags remain correct at every level.
5. **Given** an author using a `value` as a number without a predicate
   guard, **when** compiled, **then** a clear analyzer error explains
   that the type must be checked first.
6. **Given** existing functions with statically-typed parameters, **when**
   the suite runs, **then** their emitted code and behavior are unchanged.

---

## Tasks
- [ ] Choose the transport (measure options 1 and 3); write a short ABI
      note in `docs/`
- [ ] Add `value` to the type grammar and analyzer type table
- [ ] Analyzer: unification at call sites; rejection of unguarded use
- [ ] Codegen: argument passing, parameter binding to a shadow tag slot
- [ ] Codegen: `return` of a `value`; call-site capture of the returned tag
- [ ] Ensure stage 1c predicates work on `value` parameters
- [ ] Ensure appending a `value` to a list forwards its runtime tag
- [ ] Tests: pass-through, return, spill, recursion, misuse error
- [ ] Update `LANGUAGE.md` and `docs/COLLECTIONS_ROADMAP.md`
- [ ] Run `./test.sh` and `cargo test --release`

---

## Notes
- Register discipline is the main hazard: user functions preserve only
  `rbp`, and syscalls clobber `rcx`/`r11`. The existing code already
  documents this in `emit_syscall_args`; the chosen tag register must be
  saved across anything that can clobber it, or spilled to the frame.
- Keep the name decision open until implementation: `value` reads well in
  `(item as a value)` but conflicts with prose uses of the word; `anything`
  is an alternative that is unambiguous and arguably more Vox-like.
- This stage should include at least one end-to-end example program in
  `examples/` — a small recursive walker over a mixed list — since it is
  the first point where mixed data becomes genuinely programmable.
