# User Story
> As an author, I want dot products, argmax, activation functions, and weight loading so that I can run a trained model's inference in Vox.

---

## Feature/Problem Description

**Summary:**
Add the small set of operations that turn matrix arithmetic into a usable
inference toolkit: dot product, argmax/argmin, common activation
functions, and loading weight blobs from files.

**Context:**
The goal of Track 2 is a Vox program that runs inference for a trained
model with no runtime, no libc, and a tiny binary — a compelling
demonstration of the language's premise. Stages 2a–2c provide the
arithmetic; this stage provides the remaining primitives.

**Current Behavior (if bug):**
Matrix arithmetic exists but there is no way to load learned parameters
or apply nonlinearities, so no model can actually be run.

**Expected Behavior:**
```
a matrix called "w" is weights from "model.bin" shaped 784 by 128.
a matrix called "h" is (input times w) with relu applied.
a matrix called "logits" is h times w2.
a pair called "best" is logits' argmax.
print "class {best's first} at {best's second}".
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
- Training, autograd, or any gradient computation. Inference only.
- Model format parsing (ONNX, safetensors). This stage loads raw float64
  blobs with an author-declared shape.
- Convolution and other layer types beyond dense; note as future work.

---

## Technical Approach

**Proposed Solution:**
- **Dot product**: a reduction over two equal-length vectors (1 by N or
  N by 1 matrices), returning a decimal. Vectorizable with the same SSE2
  approach as 2c.
- **argmax / argmin**: return an `(index, value)` tuple — the deliberate
  crossover point with Track 3, and the main reason tuples are scheduled
  before this stage.
- **Activations**: relu, sigmoid, tanh, softmax as elementwise (or
  row-wise, for softmax) transforms producing a new matrix. Sigmoid and
  tanh need `exp`; check what `coreasm/x86_64/float.asm` already provides
  and extend it if necessary — this may be the largest piece of work here.
- **Weight loading**: read a raw float64 blob via the existing file and
  buffer machinery into a matrix of an author-declared shape, validating
  that the file's byte length matches `rows * cols * 8` exactly.

**Files/Components Affected:**
- `src/parser/mod.rs`, `src/parser/ast.rs` — sentence forms
- `src/analyzer/mod.rs` — shape rules for reductions and activations
- `src/codegen/mod.rs` — dispatch
- `coreasm/x86_64/matrix.asm`, `coreasm/x86_64/float.asm` — reductions,
  activations, and any needed `exp` implementation
- `examples/` — an end-to-end inference example
- `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`
- `tests/`

**Dependencies:**
Stages 2a and 2b; 2c recommended. Track 3 stage 3a/3b for the tuple
returned by argmax (or return two values another way if tuples slip).

---

## Success Criteria
- [ ] Feature works as described in expected behavior
- [ ] All tests pass
- [ ] An end-to-end inference example runs and produces correct output
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria
1. **Given** two vectors, **when** the dot product is computed, **then**
   it matches a hand-computed reference within tolerance.
2. **Given** a matrix with a unique maximum, **when** argmax is taken,
   **then** the returned index and value identify it.
3. **Given** relu applied to a matrix with negative and positive values,
   **when** computed, **then** negatives become 0.0 and positives are
   unchanged.
4. **Given** softmax applied to a row, **when** computed, **then** the
   row sums to 1.0 within tolerance and is numerically stable for large
   inputs (max-subtraction trick applied).
5. **Given** a weight file whose length does not match the declared
   shape, **when** loaded, **then** a clear error is reported.
6. **Given** a small trained model and a known input, **when** inference
   runs, **then** the predicted class matches the reference
   implementation.
7. **Given** the existing suite, **when** it runs, **then** all tests pass.

---

## Tasks
- [ ] Audit `float.asm` for `exp`; implement or extend as needed
- [ ] Dot product with a vectorized reduction
- [ ] argmax/argmin returning a tuple
- [ ] relu, sigmoid, tanh, softmax (numerically stable)
- [ ] Weight-blob loading with strict length validation
- [ ] Tests for each operation, including stability and error cases
- [ ] End-to-end inference example in `examples/` with a reference output
- [ ] Update `LANGUAGE.md` and `docs/COLLECTIONS_ROADMAP.md`
- [ ] Run `./test.sh` and `cargo test --release`

---

## Notes
- Numerical stability is the classic trap: implement softmax as
  `exp(x - max(x)) / sum(exp(x - max(x)))` and test it with inputs large
  enough to overflow the naive form.
- Endianness and float format for weight blobs must be documented. Little
  endian IEEE 754 float64 matches the target and most exporters, but say
  so explicitly and validate what can be validated.
- The end-to-end example is the deliverable that makes Track 2 worth
  doing — budget real time for it, including a script that produces the
  weight blob from a reference model.
