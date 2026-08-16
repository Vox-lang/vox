# Compiler module split — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to work this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Break the four monolithic compiler-phase `mod.rs` files into focused topical submodules, as pure behaviour-preserving code motion.

**Architecture:** Each phase keeps its struct definition, shared consts/enums, free helpers, and `mod` declarations in a thin `mod.rs`; method groups move into topical child modules, each carrying its own `impl <PhaseType>`. Rust allows multiple `impl` blocks per type across files, and a child module can read its parent's private struct fields — so no struct/API visibility changes and no method bodies change. Correctness is a mechanical gate: `--emit-asm` output byte-identical to a pre-captured baseline, plus a green suite, after every extraction.

**Tech Stack:** Rust, `cargo`, `sed`/`awk` for byte-preserving moves, the repo's `./test.sh`, and `vox --emit-asm`.

**Spec:** `docs/MODULE_SPLIT_DESIGN.md`

## Global Constraints

- **Pure code motion only.** No logic change, no method rename, no signature change, no reordering beyond grouping. If a move needs a logic edit to compile, the move is mis-scoped — re-scope, do not edit logic. (verbatim intent from spec)
- **Move by script, never re-type.** Relocate exact byte ranges with `sed`; the model never re-emits a method body. (spec: "Migration method")
- **The only permitted edits beyond relocation** are `use`/visibility fixes the compiler reports: adding `use super::*;`/specific imports, and bumping a helper from private to `pub(crate)` when a sibling module now calls it.
- **The gate after every extraction — all three must hold:** `cargo build --release` clean; `./test.sh` fully green with the baseline counts (323 passed / 0 failed / 6 skipped `manual_*`); **emitted assembly byte-identical to the baseline** across the corpus.
- **One extraction per commit.** Reviewable, bisectable history.
- **Order:** phases smallest-first (lexer → analyzer → parser → codegen); within a phase, leaf/independent groups first (free fns, then self-contained families), cross-cutting groups (`expr`, `statements`) last.
- No change to `parser/ast.rs` (already split) or to any module's public API.

## Target file structure

From the spec. `mod.rs` in each phase becomes the thin hub (struct, consts/enums, `mod` decls, cross-cutting primitives such as `new`, label/var allocation, `emit`/`emit_indent`).

- **codegen/** → `mangling`, `lib_output`, `vars`, `expr`, `statements`, `print`, `buffers`, `format`, `collections`, `tags`, `functions`, `flags`, `syscalls`, `tests/`.
- **parser/** → cursor helpers stay in `mod.rs`; `declarations`, `expressions`, `statements`, `control_flow`, `functions`, `collections`, `io`, `tests/`. `ast.rs` untouched.
- **analyzer/** → `scope`, `statements`, `expressions`, `types`, `tests/`.
- **lexer/** → `tokens`, `scan`, `tests/`.

---

### Task 1: Safety tooling — baseline and gate scripts

Foundation for every later task. Committed first so worker and reviewer run the identical check.

**Files:**
- Create: `tools/module-split/capture-baseline.sh`
- Create: `tools/module-split/gate.sh`

**Interfaces:**
- Produces: `capture-baseline.sh` writes `target/module-split-baseline/asm/<name>.asm` for every corpus program and `target/module-split-baseline/test-summary.txt`. `gate.sh` re-emits the corpus, diffs against that baseline, runs `./test.sh`, and exits non-zero on any build failure, asm diff, or test-count mismatch.

- [ ] **Step 1: Write `tools/module-split/capture-baseline.sh`**

```bash
#!/bin/bash
# Snapshot the compiler's output BEFORE the refactor. The corpus is every
# examples/*.vox plus every tests/*.vox. Emission is byte-deterministic
# (verified), so this baseline is the ground truth the gate compares against.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
cargo build --release >/dev/null 2>&1 || { echo "baseline: build failed"; exit 1; }
VOX="$ROOT/target/release/vox"
OUT="$ROOT/target/module-split-baseline"
rm -rf "$OUT"; mkdir -p "$OUT/asm"
emit() { # <label> <vox-file>
  local label="$1" src="$2" d
  d="$(mktemp -d)"; cp "$src" "$d/p.vox"
  ( cd "$d" && "$VOX" p.vox --emit-asm -o p >/dev/null 2>&1 )
  [ -f "$d/p.asm" ] && cp "$d/p.asm" "$OUT/asm/$label.asm"
  rm -rf "$d"
}
for f in examples/*.vox tests/*.vox; do
  [ -e "$f" ] || continue
  emit "$(echo "$f" | tr '/' '_')" "$f"
done
./test.sh 2>&1 | grep -E 'Passed:|Failed:|Skipped:|Total:' > "$OUT/test-summary.txt"
echo "baseline captured: $(ls "$OUT/asm" | wc -l) asm snapshots"
cat "$OUT/test-summary.txt"
```

- [ ] **Step 2: Write `tools/module-split/gate.sh`**

```bash
#!/bin/bash
# The per-extraction gate. Exit 0 iff: build clean, asm byte-identical to
# baseline for every corpus program, and test summary matches baseline.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
OUT="$ROOT/target/module-split-baseline"
[ -d "$OUT/asm" ] || { echo "gate: no baseline — run capture-baseline.sh first"; exit 1; }
if ! cargo build --release 2>&1 | tail -1 | grep -q Finished; then
  echo "gate: BUILD FAILED"; exit 1; fi
VOX="$ROOT/target/release/vox"
fail=0
for f in examples/*.vox tests/*.vox; do
  [ -e "$f" ] || continue
  label="$(echo "$f" | tr '/' '_')"; base="$OUT/asm/$label.asm"
  [ -f "$base" ] || continue
  d="$(mktemp -d)"; cp "$f" "$d/p.vox"
  ( cd "$d" && "$VOX" p.vox --emit-asm -o p >/dev/null 2>&1 )
  if ! diff -q "$base" "$d/p.asm" >/dev/null 2>&1; then
    echo "gate: ASM DIFF in $f"; fail=1; fi
  rm -rf "$d"
done
now="$(./test.sh 2>&1 | grep -E 'Passed:|Failed:|Skipped:|Total:')"
if [ "$now" != "$(cat "$OUT/test-summary.txt")" ]; then
  echo "gate: TEST SUMMARY CHANGED"; echo "was:"; cat "$OUT/test-summary.txt"; echo "now: $now"; fail=1; fi
[ "$fail" -eq 0 ] && echo "gate: PASS (asm identical, suite matches baseline)" || echo "gate: FAIL"
exit $fail
```

- [ ] **Step 3: Make executable and commit**

```bash
chmod +x tools/module-split/capture-baseline.sh tools/module-split/gate.sh
git add tools/module-split/
git commit -m "chore(module-split): baseline + asm-identical gate scripts"
```

---

### Task 2: Capture the baseline

**Files:** none tracked (writes under `target/`, gitignored).

- [ ] **Step 1: Run the capture on the pre-refactor tree**

Run: `tools/module-split/capture-baseline.sh`
Expected: prints the snapshot count and the test summary (323 passed / 0 failed / 6 skipped).

- [ ] **Step 2: Confirm the gate is green against an unchanged tree**

Run: `tools/module-split/gate.sh`
Expected: `gate: PASS`. (Sanity check that the gate agrees with itself before anything moves.)

No commit — the baseline is a build artifact.

---

### Extraction procedure (the repeatable unit — every Task 3+ is one application)

Each extraction moves one topical group out of a phase's `mod.rs` into a new sibling module. The steps are identical every time; only the module name, its member methods, and the phase file differ. **Do not re-type any method body** — move byte ranges.

- [ ] **A. Identify the byte ranges.** In the phase `mod.rs`, list the line ranges of the methods (and any free fns) belonging to this module by the spec's responsibility rule. Grep the method signatures to get exact start lines; each method ends at its closing `}` at the method's indentation.

  **Start each range at the item's FIRST attached line, not the `fn` line** —
  walk upward from `fn` and include every immediately preceding `///` doc
  comment, `//` comment block, and `#[attribute]` line, stopping at the first
  blank line or the previous item's closing brace. Learned in the analyzer
  phase: ranges begun at the `fn` line stranded every moved method's doc
  comment in `mod.rs`, which the asm gate cannot catch (comments don't affect
  codegen) and which only surfaced as a compile error once an extraction left
  an `impl` block containing nothing but orphaned comments. Repairing it
  afterwards costs a git-history trace per comment; taking the range from the
  doc comment costs nothing.

- [ ] **B. Create the new module file** with the preamble, then append the moved ranges:

```bash
# example: extracting codegen/format.rs
printf 'use super::*;\n\nimpl CodeGenerator {\n' > src/codegen/format.rs
# for each method range START,END (repeat, in source order):
sed -n 'START,ENDp' src/codegen/mod.rs >> src/codegen/format.rs
printf '}\n' >> src/codegen/format.rs
# then delete the moved ranges from mod.rs, HIGHEST line range FIRST so
# earlier deletions don't shift later line numbers:
sed -i 'START,ENDd' src/codegen/mod.rs
```
(Free functions move the same way but sit outside the `impl` block — put them above the `impl CodeGenerator {` line in the new file, or in `mod.rs`'s free-fn area if shared.)

- [ ] **C. Declare the module** — add `mod <name>;` (or `pub(crate) mod <name>;` if anything in it must be reachable as `crate::codegen::<name>::…`, which for `impl` methods it need not) to the phase `mod.rs` alongside the other `mod` decls.

- [ ] **D. Build and fix only `use`/visibility.**

Run: `cargo build --release`
Fix ONLY: missing imports (broaden `use super::*;` is usually enough; add specific `use` for items outside the phase module), and any helper the new module calls that was private — bump it to `pub(crate)`. If a fix requires touching a method body's logic, STOP: the range was mis-scoped (a method was split, or a helper landed in the wrong module). Revert and re-draw the ranges.

- [ ] **E. Run the gate.**

Run: `tools/module-split/gate.sh`
Expected: `gate: PASS`. An asm diff means a byte was altered in the move (a stray edit, a merged/broken range) — find and undo it; the move must be byte-exact.

- [ ] **F. Commit this one extraction.**

```bash
git add src/<phase>/mod.rs src/<phase>/<name>.rs
git commit -m "refactor(<phase>): extract <name> module (pure code motion)"
```

---

### Tasks 3–N: the extractions, in order

Apply the Extraction Procedure once per row, top to bottom. Each row is one task and one commit. Member hints are seeds, not exhaustive — assign every method by the responsibility rule; the gate catches a wrong home.

**Phase 1 — lexer** (`src/lexer/mod.rs`, ~1,091 lines)
1. `tokens` — the `Token` enum, `string_is_keyword`/`as_keyword`, keyword tables.
2. `scan` — the character-scanning loop, `read_word`, number/string/char lexing.
3. `tests/` — move the `#[cfg(test)]` module(s) into `src/lexer/tests/` (or `tests.rs`), declared `#[cfg(test)] mod tests;`.

**Phase 2 — analyzer** (`src/analyzer/mod.rs`, ~4,032 lines)
1. `tests/` — the two `#[cfg(test)]` modules first (they're self-contained and de-risk the phase).
2. `scope` — `AnalysisEnv`, variable/guard environment, availability checks.
3. `expressions` — expression analysis.
4. `statements` — statement analysis.
5. `types` — type-checking rules and helpers.

**Phase 3 — parser** (`src/parser/mod.rs`, ~7,224 lines; cursor helpers `current`/`peek`/`advance`/`skip_noise` stay in `mod.rs`)
1. `tests/` — consolidate the interleaved `#[cfg(test)]` modules into `src/parser/tests/`.
2. `declarations` — variable/type declaration parsing.
3. `io` — file open/read/seek, flag-schema parsing.
4. `collections` — list/map/buffer literal and operation parsing.
5. `functions` — function def/call, connectors.
6. `control_flow` — if/but-if/otherwise, while/for/repeat, on-error.
7. `expressions` — expression/operator parsing.
8. `statements` — the top-level statement dispatch and remaining statement parsers.

**Phase 4 — codegen** (`src/codegen/mod.rs`, ~11,061 lines; keep `new`, label/var allocation, `emit`/`emit_indent` in `mod.rs`)
1. `tests/` — the `#[cfg(test)] mod tests` (~2,000 lines) into `src/codegen/tests/`.
2. `mangling` — `mangle_symbol`, `sanitize_symbol`, `make_function_label`, `format_lib_name` (free fns).
3. `lib_output` — `LibFunction`/`LibBlock`, `render_lib_file`, element-type inference free fns.
4. `flags` — `collect_flag_schemas`, `emit_flag_parse_routine`, `argument_view_uses_parsed`.
5. `syscalls` — `emit_syscall_args`, `is_fd_path_expr`.
6. `buffers` — the buffer clear/append/copy `emit_*` family.
7. `format` — `resolve_format_variable`, `emit_format_parts_*`, `parse_format_spec`, `emit_formatted_value`.
8. `vars` — `alloc_var`/`get_var`, global var labels, mirror-to-global, `add_string`/`add_float`.
9. `functions` — calls, labels, shared-lib mode, imports, library identity.
10. `tags` — `prescan_*`, `*_tag`, `runtime_tag_source`, value retype (runtime type-tag machinery).
11. `collections` — list/map runtime, mixed-list scanning, mixed-print dispatch.
12. `print` — `generate_print`.
13. `expr` — `generate_expr`, `infer_expr_type`, `is_*_expr`, equality/arithmetic helpers.
14. `statements` — `generate`, `generate_statement`, `generate_condition`.

---

### Task Final-1: Thin-hub check

- [ ] **Step 1:** Confirm each phase `mod.rs` now holds only the struct, consts/enums, cross-cutting primitives, free helpers that are genuinely shared, and `mod` declarations. Line counts should be a small fraction of the originals.

Run: `wc -l src/codegen/mod.rs src/parser/mod.rs src/analyzer/mod.rs src/lexer/mod.rs`
Expected: each far below its original; the total across each phase dir roughly equals the original (motion, not deletion).

- [ ] **Step 2:** Full gate one final time.

Run: `tools/module-split/gate.sh && ./test.sh`
Expected: `gate: PASS` and all tests green.

---

### Task Final-2: Documentation

**Files:**
- Modify: `CHANGELOG.md` (the `[0.3.7]` section)
- Modify: `docs/MODULE_SPLIT_DESIGN.md` (sequencing note)

- [ ] **Step 1:** In `CHANGELOG.md`, replace the `[0.3.7]` Documentation bullet that says the module split is "Design only; no code moved in this release" with a `### Changed` (internal) entry describing the completed split: the four phase modules broken into topical submodules, pure code motion verified byte-identical, no behaviour change.

- [ ] **Step 2:** In `docs/MODULE_SPLIT_DESIGN.md`, update the Status line and Sequencing section from "execution deferred until after 0.3.7" to "executed in 0.3.7".

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md docs/MODULE_SPLIT_DESIGN.md
git commit -m "docs: record the module split as completed in 0.3.7"
```

## Self-review

- **Spec coverage:** approach (topical impl-split) → Tasks 3–N; safety gate (asm-identical + green suite) → Tasks 1–2 and every extraction's step E; script-based motion → Extraction Procedure step B; target structure → File structure + task rows; ordering (phases smallest-first, leaf-first) → Global Constraints + row order; all four phases → Phases 1–4; docs update → Task Final-2. Covered.
- **Placeholder scan:** the scripts are complete and runnable; the per-extraction steps are a concrete parameterized procedure (module name + ranges + gate), not "implement later". Member lists are explicitly seeds with the responsibility rule as the assignment authority and the gate as the check — deliberate, not vague.
- **Type consistency:** no new types or signatures are introduced (pure motion); the only names are existing methods, moved whole.
