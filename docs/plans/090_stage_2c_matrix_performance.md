# User Story
> As an author, I want matrix operations to run fast so that inference workloads are practical in Vox.

---

## Feature/Problem Description

**Summary:**
Optimize the stage 2b matrix routines using SSE2 vectorization and cache
blocking, without changing any observable result.

**Context:**
SSE2 is part of the x86_64 baseline, so it can be used unconditionally
with no runtime feature detection — a good fit for a compiler that emits
plain NASM and avoids hidden runtime machinery. The contiguous,
homogeneous float64 layout chosen in 2a exists precisely to make this
stage possible.

**Current Behavior (if bug):**
Scalar loops from stage 2b: correct, straightforward, and slow. Matmul in
particular leaves most of the machine idle.

**Expected Behavior:**
Identical numerical results (bit-for-bit where the operation order is
unchanged; within a documented tolerance where it is not), with a
substantial measured speedup on medium and large matrices.

---

## Scope
- [x] Backend (coreasm runtime; codegen only for dispatch)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- AVX/AVX-512, which would require runtime detection and a dispatch
  mechanism; note as a future stage.
- Multithreading. Vox has no threading model yet.
- Changing the matrix layout or any surface syntax.

---

## Technical Approach

**Proposed Solution:**
Three independent optimizations, each landing separately so a regression
can be bisected:

1. **SSE2 elementwise** — `addpd` / `subpd` / `mulpd` process two
   float64s per instruction. Handle the odd trailing element with a
   scalar epilogue. Applies to add, subtract, and scalar multiply.
2. **Blocked matmul** — tile the i/j/k loops so working sets fit in L1.
   Combine with SSE2 on the innermost loop.
3. **Blocked transpose** — a cache-friendly tiled swap instead of the
   naive strided walk. Alternatively, evaluate stride metadata in the
   header for a zero-copy transpose; that is a layout change, so decide
   deliberately and document the trade-off (zero-copy is free but makes
   every consumer stride-aware).

Alignment: `mmap` returns page-aligned memory, so the data region's
alignment is known — use aligned loads where the offset permits and
document the rule.

Keep the scalar implementations in the tree for differential testing.

**Files/Components Affected:**
- `coreasm/x86_64/matrix.asm` — vectorized and blocked routines
- `src/codegen/mod.rs` — dispatch only, if a size threshold is used
- `docs/` — a short performance note recording the measurements
- `tests/` — differential and stress tests

**Dependencies:**
Stage 2b complete, with its scalar routines retained as the reference.

---

## Success Criteria
- [ ] Results match the scalar reference within the documented tolerance
- [ ] All tests pass
- [ ] Measured speedup recorded in `docs/` for representative sizes
- [ ] No correctness regression on non-multiple-of-2 dimensions
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria
1. **Given** matrices with odd dimensions (e.g. 7 by 5), **when** any
   vectorized operation runs, **then** the trailing scalar elements are
   handled correctly.
2. **Given** any operation, **when** run through both the scalar and
   optimized paths, **then** results agree within tolerance.
3. **Given** a 512 by 512 matmul, **when** benchmarked, **then** the
   optimized path is measurably faster than the scalar path, with the
   figure recorded.
4. **Given** a 1 by 1 matrix, **when** operated on, **then** the result
   is correct (degenerate-size guard).
5. **Given** the existing suite, **when** it runs, **then** all tests pass.

---

## Tasks
- [ ] Establish a benchmark harness and record scalar baselines
- [ ] SSE2 elementwise add/subtract/scalar-multiply with scalar epilogue
- [ ] Blocked matmul; tune the tile size against the baseline
- [ ] Blocked or zero-copy transpose (decide and document)
- [ ] Differential tests: optimized vs scalar across many shapes
- [ ] Degenerate and odd-size tests
- [ ] Write the performance note in `docs/`
- [ ] Update `docs/COLLECTIONS_ROADMAP.md`
- [ ] Run `./test.sh` and `cargo test --release`

---

## Notes
- Do not sacrifice the readability of generated assembly casually: one of
  Vox's selling points is that the output is inspectable. Comment the
  vectorized routines heavily, explaining the loop structure and the
  epilogue.
- Reassociation changes floating-point results. If a blocked matmul
  changes the accumulation order, say so explicitly in the docs and pick
  the test tolerance accordingly — silently different numbers would be
  exactly the kind of surprise this project avoids elsewhere.
