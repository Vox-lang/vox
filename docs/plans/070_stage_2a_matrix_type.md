# User Story
> As an author, I want a matrix type with a fixed shape so that I can represent numeric data for computation and inference.

---

## Feature/Problem Description

**Summary:**
Introduce a matrix (2-D tensor) type: a contiguous block of float64
values with shape metadata in a header. This is the foundation of
Track 2 and is entirely independent of Track 1.

**Context:**
`docs/COLLECTIONS_ROADMAP.md` explains why ML data wants a *tensor* and
not a tuple: homogeneous elements packed contiguously give fixed-stride
inner loops, cache-friendly traversal, and eventual SIMD. A matrix built
from tagged or heterogeneous slots would be the worst possible layout for
inference, which is why this is a separate type from the list.

**Current Behavior (if bug):**
No matrix type. Numeric grids must be faked with lists of lists, which
pointer-chase, cannot vectorize, and carry per-slot tags they do not need.

**Expected Behavior:**
```
a matrix called "m" is 3 by 4.
set element 2, 3 of m to 1.5.
print element 2, 3 of m.
print m's rows.
print m's columns.
print m.

a matrix called "id" is identity 3.
a matrix called "z" is zeros 2 by 5.
a matrix called "lit" is [[1.0, 2.0], [3.0, 4.0]].
```

---

## Scope
- [x] Backend (lexer, parser, analyzer, codegen, coreasm runtime)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- Arithmetic operations (stage 2b).
- SIMD and tiling (stage 2c).
- Tensors of rank other than 2; the layout should not preclude them, but
  this stage ships matrices only.
- Integer or mixed-precision matrices; float64 only for now.

---

## Technical Approach

**Proposed Solution:**
Layout, a deliberate sibling of the list header:

```
[rows:8][cols:8][data: rows x cols x 8]   ; packed float64, row-major
```

No tag region: every element is a float64 by construction, which is the
entire point of the type.

Allocation via `mmap` following the existing list pattern, including the
`cmp rax, -4096` failure check. Element access is
`data[(r-1) * cols + (c-1)]` with 1-indexed sentences matching list
conventions, and bounds checks on both dimensions using the existing
`_last_error` mechanism.

Printing renders rows on separate lines with aligned columns; reuse the
float formatting already available via `PRINT_FLOAT` and the precision
formatter.

**Files/Components Affected:**
- `src/lexer/mod.rs` — `matrix`, `by`, `identity`, `zeros` keywords
- `src/parser/mod.rs`, `src/parser/ast.rs` — declaration, literal,
  two-index element access, properties
- `src/analyzer/mod.rs` — matrix type, shape validation
- `src/codegen/mod.rs` — allocation, element get/set, properties, print
- `coreasm/x86_64/matrix.asm` (new) — allocation helper, printing
- `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`
- `tests/`

**Dependencies:**
Existing float support (`coreasm/x86_64/float.asm`) and the `mmap`
allocation pattern from `list.asm`. No dependency on Track 1.

---

## Success Criteria
- [ ] Feature works as described in expected behavior
- [ ] All tests pass
- [ ] All element access is bounds-checked on both dimensions
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria
1. **Given** `a matrix called "m" is 3 by 4.`, **when** `m's rows` and
   `m's columns` are printed, **then** they are 3 and 4.
2. **Given** a freshly declared matrix, **when** any element is read,
   **then** it is 0.0 (mmap zero-fill gives this for free — assert it).
3. **Given** a set followed by a get at the same position, **when** run,
   **then** the value round-trips exactly.
4. **Given** an out-of-range row or column (0, negative, or past the
   dimension), **when** accessed, **then** the error flag is set and no
   memory outside the allocation is touched.
5. **Given** a matrix literal `[[1.0, 2.0], [3.0, 4.0]]`, **when**
   declared, **then** its shape is 2 by 2 and its elements are in
   row-major order.
6. **Given** a ragged literal (rows of differing length), **when**
   compiled, **then** a clear error is reported at compile time.
7. **Given** the existing suite, **when** it runs, **then** all tests pass.

---

## Tasks
- [ ] Finalize the surface syntax for declaration, literals, and access
- [ ] Add lexer keywords and parser rules
- [ ] Analyzer: matrix type, ragged-literal rejection, shape tracking
- [ ] `coreasm/x86_64/matrix.asm`: allocation and printing
- [ ] Codegen: declaration, `zeros`, `identity`, literals, get/set,
      `rows`/`columns` properties
- [ ] Bounds checks on both dimensions via `_last_error`
- [ ] Tests: shape, zero-init, round-trip, bounds, literals, ragged error
- [ ] Update `LANGUAGE.md` and `docs/COLLECTIONS_ROADMAP.md`
- [ ] Run `./test.sh` and `cargo test --release`

---

## Notes
- Keep the header shape open to a future rank-N tensor (e.g. by treating
  `[rows][cols]` as the rank-2 case of a shape vector) but do not build
  rank-N now. Note the intended extension in a comment.
- 1-indexing is the Vox convention for lists and should hold for matrices
  too, even though it costs a decrement per access — consistency with the
  language's "natural language" surface matters more than that.
- Consider whether `element 2, 3 of m` or `m's element 2, 3` reads better
  before committing; changing it later is a breaking change.
