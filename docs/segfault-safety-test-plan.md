# User Story

> As a Vox language user, I want unsafe or invalid Vox programs to fail at compile time so that generated binaries never segfault at runtime.

---

## Feature/Problem Description

**Summary:**
Build a comprehensive negative-test suite for Vox that intentionally exercises unsafe patterns and malformed programs, with success defined as deterministic compiler/analyzer errors (not runtime crashes).

**Context:**
Recent scheduler work exposed parser/control-flow edge cases and type-safety holes that can lead to invalid IR/codegen paths. Vox is intended to be memory-safe at the language level, so the compiler must reject any program shape that could produce unsafe runtime behavior.

**Current Behavior (if bug):**
- Some invalid constructs are currently accepted or fail late.
- Coverage of “must-fail” programs is incomplete and not organized by safety category.
- Regressions can slip in when parser/analyzer/codegen assumptions diverge.

**Expected Behavior:**
- Invalid Vox programs consistently fail compilation with actionable diagnostics.
- No malformed user program should produce a runtime segfault.
- Negative tests run in CI and block regressions.

---

## Scope

- [x] Backend
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- Rewriting the full compiler architecture
- New language features unrelated to safety hardening
- Optimizer performance work not tied to crash prevention

---

## Technical Approach

**Proposed Solution:**
1. Add a dedicated negative-test harness for compile-fail cases.
2. Organize invalid programs by safety class:
   - Parser structure violations
   - Type-system mismatches
   - Symbol/scope invalid references
   - Buffer/file operation misuse
   - Control-flow malformed constructs
   - Numeric edge cases (index/size/overflow-sensitive)
   - Runtime-safety contract mismatches (LANGUAGE.md promises vs emitted code behavior)
3. For each case, assert:
   - compiler exits non-zero
   - error message includes stable classifier text
   - no panic/segfault occurs
4. Add targeted analyzer/codegen guards where failures are currently late.
5. Add regression tests for historically risky patterns from scheduler debugging:
   - while/for body termination edge cases with nested blocks
   - boolean condition forms inside loop bodies
   - invalid variable/file references crossing nested block boundaries
6. Add fuzz/property-based test phase for parser+analyzer input mutation (bounded corpus).
7. Gate merges on compile-fail suite + sanitizer-enabled debug runs.
8. Add a “safety contract matrix” from `LANGUAGE.md` and enforce each contract with at least one failing negative test and one non-crashing runtime assertion where applicable.

**New high-risk targets identified from `LANGUAGE.md`:**
- 1-indexed byte/list access semantics (`byte N`, `element N`) and <1 index handling.
- Fixed-buffer truncation and resize edge paths (`resize`, shrink-to-zero, huge size requests).
- `Seek ... to byte/line` invalid target handling (0, negative, non-file handles).
- Overloaded `append`/`copy` semantics (buffer-vs-list destination confusion).
- Error-flag propagation paths (`On error`) after failed byte/list/file operations.
- Timer/time property misuse on wrong value kinds.
- Contract check: docs claim out-of-bounds byte access is trapped; enforce analyzer/codegen/runtime agreement.

**Files/Components Affected:**
- `src/parser/mod.rs`
- `src/analyzer/mod.rs`
- `src/codegen/mod.rs`
- `src/errors.rs`
- `tests/` (new compile-fail corpus and harness)
- CI config (`.github/workflows/*` or project CI equivalent)
- `LANGUAGE.md` (document safety guarantees + compile-fail behavior)

**Dependencies:**
- Existing Vox test runner
- Rust test framework (`cargo test`)
- Optional: sanitizers (`ASAN/UBSAN`) in debug CI lane
- Optional: lightweight fuzzing (`cargo-fuzz` or mutation-based runner)

---

## Success Criteria

- [ ] Feature works as described in expected behavior
- [ ] All tests pass
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria

1. **Given** an invalid Vox program that violates parser structure rules, **when** it is compiled, **then** the compiler returns a structured error and does not crash.
2. **Given** a program with type-unsafe buffer/file operations, **when** it is compiled, **then** the analyzer/codegen rejects it before binary generation.
3. **Given** known regression cases from prior scheduler-related failures, **when** test suite runs, **then** all cases fail compilation with expected diagnostics.
4. **Given** the negative corpus in CI, **when** a change introduces an unsafe compile path, **then** CI fails and blocks merge.

---

## Tasks

- [ ] Define compile-fail test directory layout (e.g., `tests/compile_fail/`)
- [ ] Implement compile-fail harness with expected error snapshot matching
- [ ] Add initial 50+ invalid programs across safety categories
- [ ] Add explicit regressions for loop-body termination and nested-scope cases
- [ ] Add type/symbol misuse regressions for buffer/file operations
- [ ] Add numeric edge-case regressions (sizes/indices/seek positions)
- [ ] Add panic-to-error conversions where needed in parser/analyzer/codegen
- [ ] Integrate suite into CI required checks
- [ ] Document safety model and failure guarantees in `LANGUAGE.md`

---

## Notes

- “Success” for these tests is compilation failure with a clear `CompileError`.
- Prefer specific error classes/messages over generic parse failures to aid users.
- Track every discovered crash as a new regression test first, then fix.
- Add a triage label/workflow for `compiler-crash` and link each fix to a test case.
