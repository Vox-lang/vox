# Design: splitting the compiler's monolithic phase modules

**Status:** design approved, execution deferred until after the 0.3.7 release.
**Scope:** internal source-tree reorganisation only. No language, compiler
behaviour, or public-interface change.

## Problem

Four `mod.rs` files carry almost the entire compiler, and three of them have
grown past the point where a human — or a model — can hold them in context:

| File | Lines | Shape |
|---|---:|---|
| `src/codegen/mod.rs` | 11,061 | one `impl CodeGenerator`, 169 methods (~8,000 lines), + ~1,000 lines of free fns/types, + ~2,000 lines of tests |
| `src/parser/mod.rs` | 7,200 | one `impl Parser`, 177 methods, with `#[cfg(test)]` modules interleaved before and after |
| `src/analyzer/mod.rs` | 4,032 | one `impl Analyzer`, 91 methods, + two test modules |
| `src/lexer/mod.rs` | 1,093 | one `impl Lexer` + keyword tables |

This is a barrier to entry for new contributors and a drag on every change:
navigation, review, and reliable editing all degrade with file size. The
`parser/ast.rs` split (already a separate 729-line submodule) shows the team
knows the submodule pattern; it simply hasn't been applied to the big `impl`
blocks.

## Goal

Replace each monolith with a directory of focused, single-responsibility files
of roughly 500–1,500 lines, `mod.rs` reduced to a thin hub. Applied uniformly
to all four compilation phases. **Zero behaviour change** — this is pure code
motion.

## Non-goals

- No logic changes, method renames, or signature changes.
- No trait/sub-struct decomposition of the phase types (that would move state
  ownership and alter interfaces — a separate, riskier effort; see
  "Alternatives").
- No "while I'm here" cleanups. Any genuine improvement spotted during the move
  is filed as a separate follow-up, never bundled in.
- No change to the public API of any module, or to `ast.rs` (already split).

## Approach: topical `impl`-split with a thin `mod.rs` hub

Each phase directory keeps `mod.rs` holding only the struct definition, shared
consts/enums, free helper functions that don't fit a topic, `mod`
declarations, and the few genuinely cross-cutting primitives (`new`,
label/variable allocation, `emit`/`emit_indent`). The giant `impl` block is
carved into topical submodules, each carrying its own `impl <PhaseType> { … }`.

This is safe because of two Rust facts:

1. **Multiple `impl` blocks** for one type may live in separate files.
2. **A child module can access the private fields** of a struct its ancestor
   defines. So `codegen/expr.rs` writing `impl CodeGenerator { … }` reaches
   every private field of `CodeGenerator` declared in `codegen/mod.rs`, with no
   visibility change to the struct.

The public API of each module is therefore unchanged, method bodies are
unchanged, and the compiler's output is unchanged.

### Assignment principle

Every method moves **whole** to the module owning its responsibility; no method
is split across files. Where a method genuinely spans two concerns, it goes
with its primary caller. The spec fixes the *target module set* and this
assignment rule; the exact home of each of ~440 methods is settled in the
implementation plan, not pre-locked here (locking it early just creates churn).

## The safety gate — how "without breaking any feature" is guaranteed

Because the approach is pure code motion, the compiler's output must not
change. That turns the correctness question into a mechanical, deterministic
check rather than a matter of trust.

**Verified:** `vox --emit-asm` is byte-deterministic across runs (confirmed on
`fizzbuzz.vox` and `life.vox` — two separate emissions are byte-identical).

**Baseline (captured once, before any change):**
- `--emit-asm` output for every program under `examples/`, plus a generated
  matrix of programs covering each language construct, saved to a baseline
  directory.
- The `./test.sh` green count (currently 323 passed / 0 failed / 6 skipped
  `manual_*`).

**Gate, applied after *every* extraction step — all three must hold:**
1. `cargo build --release` clean.
2. `./test.sh` fully green, same counts as baseline.
3. **Emitted assembly byte-identical to the baseline** across the whole corpus.

A green suite alone can miss a regression; byte-identical assembly cannot. Any
asm diff is a mechanical proof the move changed behaviour, and the step is
rejected until the diff is gone.

## Migration method — scripts, not retyping

**The code is moved by script, never re-typed by the model.** Each method (or
free-function, or test) is relocated by lifting its exact byte range:

```bash
# extract a method block into the new module file, wrapped in an impl
sed -n 'START,ENDp' src/codegen/mod.rs >> src/codegen/expr.rs
# delete the same range from the original
sed -i 'START,ENDd' src/codegen/mod.rs
```

This is mandatory, for three reasons:

- **Correctness.** Byte-preserving moves make the asm-identical gate pass by
  construction — the bytes literally did not change, only their file. Hand-
  retyping ~440 method bodies would introduce subtle transcription errors that
  the gate would then have to catch one by one.
- **Cost.** Re-emitting 22,000 lines of code through a model is enormously
  expensive and slow. Scripted extraction costs almost nothing.
- **Reviewability.** A scripted move produces a diff that is pure relocation,
  trivial to review as "same bytes, new home."

The model's job is orchestration: choose the ranges, wrap each new file in its
`impl <PhaseType>` and `use super::*;` preamble, add the `mod` declaration, and
fix only the `use`/visibility fallout the compiler reports (adding imports,
bumping a helper from private to `pub(crate)` where a sibling module now needs
it). It never rewrites a method body. If a step needs a logic change to
compile, that is a signal the move was mis-scoped — stop and re-scope, don't
edit the logic.

## Target structure

`mod.rs` in each becomes the thin hub described under "Approach". Module sets:

**codegen/** (~12 files) — `mangling`, `lib_output`, `vars`, `expr`,
`statements`, `print`, `buffers`, `format`, `collections`, `tags`, `functions`,
`flags`, `syscalls`, and `tests/` mirroring the topics.

**parser/** (~8 files) — cursor helpers stay in `mod.rs`; then `declarations`,
`expressions`, `statements`, `control_flow`, `functions`, `collections`, `io`,
and `tests/`. `ast.rs` is untouched.

**analyzer/** (~5 files) — `scope`, `statements`, `expressions`, `types`, and
`tests/`.

**lexer/** (~3 files) — `tokens` (the `Token` enum + keyword tables),
`scan` (the lexing loop), and `tests/`.

Secondary candidates, same principle applied only if they cross ~800 lines at
execution time: `src/main.rs` (1,070), `src/lib_file.rs` (985).

## Execution sequence

One connected series of extractions on a single branch, phase by phase.

**Phase order: lexer → analyzer → parser → codegen** (ascending complexity).
The smaller impls shake out the extraction scripts and the gate tooling before
the 8,000-line `codegen` impl, where a mis-scope is most expensive.

**Within a phase**, extract leaf/independent groups first (free functions, then
self-contained families like `buffers`/`format`/`flags`), leaving the most
cross-cutting groups (`expr`, `statements`) until the surrounding context is
already thinned.

**Per extraction step:** script the byte-move → add `mod` decl → `cargo build`,
fixing only `use`/visibility → run the full gate → **one commit per
extraction**. One extraction per commit keeps history reviewable and
bisectable, so a rare gate failure is localised to a single move.

## Execution model

Delegated to a worker under master review (the established pattern for this
repo). The asm-identical gate is ideal for delegated work because it is
self-verifying: the master re-runs the gate and reads each relocation diff,
rather than trusting a report. The baseline-capture script and the gate script
are written and committed first, before any extraction, so both sides run the
identical check.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| A move silently changes behaviour | Asm-identical gate after every step; byte-preserving scripts make this pass by construction |
| `use`/visibility churn cascades | Expected and allowed — it is the *only* permitted edit beyond relocation; a needed logic change means re-scope, not edit |
| Conflict with in-flight work | Execute only on a clean `main` after 0.3.7 merges; a 22k-line move cannot coexist with unmerged branches |
| A step is too large to review | One extraction per commit; leaf-first ordering keeps early steps small |
| Test modules tangled with prod code | Tests move to a `tests/` subdir per phase as their own extraction steps, same gate |

## Alternatives considered

- **Extract only free functions and tests, leave the giant `impl`.** Far less
  work but doesn't touch the actual monolith. Rejected — misses the goal.
- **Decompose each phase type into sub-structs / traits** (e.g. a
  `StringCodegen` owning its own state). A genuine architecture change that
  moves state ownership and alters interfaces — not pure code motion, real
  behaviour-change risk, much larger effort. Rejected for this work; it is the
  honest path *if* deeper decoupling is wanted later, as a separate project on
  top of this one.

## Sequencing

Execute on a clean `main` immediately after the 0.3.7 branches merge and
release. This design doc is written now so it is ready to hand to the
implementation-planning step at that point.
