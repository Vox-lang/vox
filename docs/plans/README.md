# Implementation Plans

One plan per stage, following the project plan template. The design
rationale behind all of these lives in
[`docs/COLLECTIONS_ROADMAP.md`](../COLLECTIONS_ROADMAP.md) — read that
first for the *why*; these files cover the *what* and *how*.

Numbering is for ordering and stable reference only; it is not a strict
execution order. Tracks 1, 2, and 3 are independent of one another and
may proceed in parallel. Dependencies within a track are stated in each
plan's **Dependencies** section.

| Plan | Stage | Track | Depends on |
|------|-------|-------|-----------|
| [000](000_list_whole_printing.md) | Whole-list printing fix | Standalone | 1a (done) |
| [010](010_stage_1b_inference_soundness_flip.md) | 1b — inference soundness flip | 1: Lists | 1a (done) |
| [020](020_stage_1c_type_predicates.md) | 1c — runtime type predicates | 1: Lists | 1a (done) |
| [030](030_stage_1d_dynamic_value_type.md) | 1d — dynamic `value` type across functions | 1: Lists | 1c recommended |
| [040](040_stage_1e1_nested_lists.md) | 1e-1 — nested lists | 1: Lists | 000, 1c |
| [050](050_stage_1e2_maps_and_null.md) | 1e-2 — maps and `nothing` | 1: Lists | 1e-1 |
| [060](060_stage_1e3_json_yaml.md) | 1e-3 — JSON/YAML | 1: Lists | 1d, 1e-2 |
| [070](070_stage_2a_matrix_type.md) | 2a — matrix type and layout | 2: Numerics | none |
| [080](080_stage_2b_matrix_arithmetic.md) | 2b — matrix arithmetic | 2: Numerics | 2a |
| [090](090_stage_2c_matrix_performance.md) | 2c — SIMD and blocking | 2: Numerics | 2b |
| [100](100_stage_2d_ml_conveniences.md) | 2d — ML conveniences | 2: Numerics | 2b, 3a/3b |
| [110](110_stage_3a_tuple_type.md) | 3a — tuple type | 3: Records | none |
| [120](120_stage_3b_tuple_access_destructuring.md) | 3b — destructuring | 3: Records | 3a |
| [130](130_stage_3c_multiple_return_values.md) | 3c — multiple return values | 3: Records | 3a, 3b |
| [200](200_shared_library_repair.md) | Shared-library repair (`--shared` phases 0–2) | 4: Shared libraries | none |

Stage 1a (per-slot runtime type tags for heterogeneous lists) is already
implemented — see commit `6d60ea5`.

## Suggested order

1. **000** and **010** first: both are small, both close correctness gaps
   left open by 1a, and neither blocks anything else.
2. **020** next: it unlocks the rest of Track 1 and is the first
   author-visible payoff of the tag machinery.
3. Then either continue Track 1 toward JSON (**030** → **040** → **050**
   → **060**), or start Track 2 (**070** → **080**) — they do not
   interfere. Track 3 (**110** → **120**) is small and worth slotting in
   before **100**, which wants tuples for argmax.

## Cross-cutting notes for implementers

- **Do not regress the fast path.** Homogeneous lists must keep emitting
  the same assembly they do today. Where a plan touches shared codegen,
  verify with `--emit-asm` before and after.
- **Two ABI decisions are coming** (1d's dynamic values, 3c's multiple
  returns). Whoever gets there first should write the ABI note in
  `docs/`; the second should extend that same file rather than starting
  another.
- **Register discipline** is the recurring hazard across several stages:
  user functions preserve only `rbp`, and syscalls clobber `rcx`/`r11`.
  The existing comment on `emit_syscall_args` in `src/codegen/mod.rs`
  explains the rule.
- **Every stage ships tests and docs.** `./test.sh` for end-to-end tests
  (144 currently, 138 passing and 6 skipped) and `cargo test --release`
  for compiler unit tests (71 passing).
