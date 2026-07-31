# User Story
> As an author, I want a function to return several values at once so that I can express results with context — such as a value together with whether it succeeded.

---

## Feature/Problem Description

**Summary:**
Allow functions to declare and return a tuple, and allow the caller to
destructure the result in one statement — enabling the `(value, error)`
idiom.

**Context:**
Final stage of Track 3. Vox has an error-flag mechanism (`_last_error`,
surfaced as `On error ...`), which works but is implicit and easy to
ignore. Returning an explicit success indicator alongside a value gives
authors a second, more legible option and composes better inside
expressions. Stage 2d also wants this for argmax.

**Current Behavior (if bug):**
Functions return a single value. Communicating "the result, and whether
it worked" requires either the error flag or an out-parameter pattern
that Vox does not have.

**Expected Behavior:**
```
to divide (a as a number, b as a number) returning a pair,
  If b is 0, return (0, no),
  return (a divided by b, yes).

take result and ok from divide(10, 2).
If ok, print result, otherwise print "cannot divide by zero".
```

---

## Scope
- [x] Backend (parser, analyzer, codegen, calling convention)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- Replacing or deprecating the existing `On error` mechanism; both
  coexist, and the documentation should say when each is appropriate.
- Returning tuples of arity beyond the documented maximum.
- Named (as opposed to positional) return members.

---

## Technical Approach

**Proposed Solution:**
Extend function return types to include tuple types. For small arities,
return members in registers (`rax`, `rdx`, and further callee-saved
registers as needed) following the same discipline the existing calling
convention uses; for larger arities, return via a caller-provided stack
area. Document the rule in the same ABI note stage 1d creates, so there
is one place describing how non-scalar values move across calls.

Callers may either destructure directly (`take a and b from f(...)`,
reusing stage 3b) or bind the whole tuple to a variable first. Both
should work; the destructuring form is the ergonomic goal.

**Files/Components Affected:**
- `src/parser/mod.rs`, `src/parser/ast.rs` — tuple return types, tuple
  return statements
- `src/analyzer/mod.rs` — return-type checking against declared arity
  and member types
- `src/codegen/mod.rs` — `emit_function_call` result handling,
  `Statement::Return` for tuples
- `docs/` — extend the ABI note
- `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`
- `tests/`

**Dependencies:**
Stages 3a and 3b. Coordinate with stage 1d if both are in flight, since
both touch the calling convention.

---

## Success Criteria
- [ ] Feature works as described in expected behavior
- [ ] All tests pass
- [ ] Calling convention documented alongside the 1d ABI note
- [ ] Recursion returning tuples works correctly
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria
1. **Given** a function returning a pair, **when** called and
   destructured, **then** both members arrive with correct values and
   types.
2. **Given** a function whose returned tuple does not match its declared
   type, **when** compiled, **then** a clear error is reported.
3. **Given** a function returning a pair, **when** its result is bound to
   a single tuple variable, **then** positional access works.
4. **Given** a recursive function returning a pair, **when** called to a
   depth of at least 100, **then** all results are correct.
5. **Given** a `(value, error)`-style function called in both the success
   and failure paths, **when** run, **then** each path behaves correctly.
6. **Given** the existing suite, **when** it runs, **then** all tests
   pass and existing single-value functions are unchanged.

---

## Tasks
- [ ] Extend the return-type grammar to accept tuple types
- [ ] Analyzer: declared-versus-actual return checking
- [ ] Codegen: multi-register return; stack-area fallback for larger arity
- [ ] Caller-side capture, both destructured and whole-tuple
- [ ] Extend the ABI note in `docs/`
- [ ] Tests: pair return, type mismatch error, recursion, both idiom
      paths, existing single-value functions unchanged
- [ ] Add a worked `(value, error)` example to `examples/`
- [ ] Update `LANGUAGE.md` and `docs/COLLECTIONS_ROADMAP.md`
- [ ] Run `./test.sh` and `cargo test --release`

---

## Notes
- Register pressure is the hazard: user functions preserve only `rbp`, so
  a multi-register return must be captured by the caller immediately,
  exactly as the mixed-element tag convention requires for `r11`. Write
  the rule down once and reference it from both places.
- Once this lands, revisit the documentation for `On error` and explain
  the trade-off between the two error styles so authors are not left
  guessing which to reach for.
