# User Story
> As an author, I want to add, scale, transpose, and multiply matrices so that I can express numeric computation directly in Vox.

---

## Feature/Problem Description

**Summary:**
Implement matrix arithmetic — elementwise add and subtract, scalar
multiply, transpose, and matrix multiplication — with shape errors caught
at compile time wherever dimensions are statically known.

**Context:**
Stage 2a gives the type; this stage makes it useful. Compile-time shape
checking is the headline ergonomic win over numpy-style libraries, where
shape mismatches are a runtime rite of passage. It is available to Vox
because matrix shapes are frequently literal at the declaration site.

**Current Behavior (if bug):**
No arithmetic; matrices are inert storage after 2a.

**Expected Behavior:**
```
a matrix called "a" is 2 by 3.
a matrix called "b" is 3 by 4.
a matrix called "c" is a times b.        (2 by 4)
a matrix called "t" is a transposed.     (3 by 2)
a matrix called "s" is a scaled by 2.0.
a matrix called "d" is a plus a.
```
And, at compile time:
```
a matrix called "bad" is a times a.
(error: cannot multiply a 2 by 3 matrix by a 2 by 3 matrix;
 the first matrix's columns (3) must equal the second's rows (2))
```

---

## Scope
- [x] Backend (parser, analyzer, codegen, coreasm runtime)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- SIMD, tiling, and any performance work (stage 2c) — correctness first,
  with a clear scalar reference implementation to validate against.
- Matrix inversion, determinants, decompositions.
- Broadcasting. Shapes must match exactly; mismatches are errors.

---

## Technical Approach

**Proposed Solution:**
Each operation gets a `coreasm` routine taking source pointers and
producing a freshly allocated result:

- elementwise add/subtract: single loop over `rows * cols`
- scalar multiply: single loop
- transpose: `out[j][i] = in[i][j]`; naive first, blocked later in 2c
- matmul: classic i-k-j triple loop (k in the middle gives sequential
  access to both operands' rows, which matters even before SIMD)

Shape checking happens twice. In the analyzer, when both operands'
shapes are statically known, mismatches are compile errors with a message
that names both shapes and states the rule. When a shape is only known at
runtime, the routine checks and sets `_last_error`, returning a zero-shape
matrix.

Write the scalar implementations as the reference; stage 2c must produce
identical results, so keep them available for differential testing.

**Files/Components Affected:**
- `src/parser/mod.rs`, `src/parser/ast.rs` — operation sentence forms
- `src/analyzer/mod.rs` — static shape propagation and error messages
- `src/codegen/mod.rs` — operation dispatch, result allocation
- `coreasm/x86_64/matrix.asm` — the arithmetic routines
- `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`
- `tests/`

**Dependencies:**
Stage 2a.

---

## Success Criteria
- [ ] Feature works as described in expected behavior
- [ ] All tests pass
- [ ] Static shape mismatches are compile errors with actionable messages
- [ ] Runtime shape mismatches set the error flag and do not corrupt memory
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria
1. **Given** two 2 by 3 matrices, **when** added, **then** every element
   is the sum of the corresponding inputs and the result is 2 by 3.
2. **Given** a 2 by 3 and a 3 by 4 matrix, **when** multiplied, **then**
   the result is 2 by 4 and matches a hand-computed reference.
3. **Given** a 2 by 3 matrix, **when** transposed, **then** the result is
   3 by 2 with elements correctly swapped.
4. **Given** statically mismatched shapes, **when** compiled, **then**
   compilation fails with a message naming both shapes.
5. **Given** an identity matrix, **when** multiplied by any matrix of
   compatible shape, **then** the result equals the original matrix.
6. **Given** a matrix multiplied by its transpose, **when** computed,
   **then** the result is symmetric.
7. **Given** the existing suite, **when** it runs, **then** all tests pass.

---

## Tasks
- [ ] Finalize the sentence forms (`plus`, `minus`, `times`,
      `scaled by`, `transposed`)
- [ ] Analyzer: static shape propagation through expressions
- [ ] Analyzer: compile-time mismatch errors with both shapes named
- [ ] `coreasm`: add, subtract, scalar multiply, transpose, matmul
- [ ] Runtime shape checks and `_last_error` handling
- [ ] Tests: each operation, identity property, symmetry property,
      static mismatch error, runtime mismatch error
- [ ] Add a worked example to `examples/`
- [ ] Update `LANGUAGE.md` and `docs/COLLECTIONS_ROADMAP.md`
- [ ] Run `./test.sh` and `cargo test --release`

---

## Notes
- Floating-point comparison in tests must use a tolerance, not equality;
  pick and document an epsilon, and put the helper somewhere reusable.
- Result matrices are freshly allocated, so a chained expression
  (`a times b plus c`) allocates intermediates. That is acceptable now;
  note it as a future optimization (fusing, or an "into" destination form)
  rather than complicating this stage.
- The error message wording is a real deliverable here, not a detail — the
  compile-time shape error is the feature's main selling point.
