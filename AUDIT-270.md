# Stale-syntax audit for identifier syntax change

This document lists every occurrence of the old identifier syntax (double-quoted identifiers) in the repository that is not in `docs/plans/**` (which is project history).

## UNOWNED (not covered by other workers)

These files are in the UNOWNED bucket - they should be addressed:

### scripts
- `test.sh:109` — `Print "Child exited with " then status.`
  - Comment describing shell output - ambiguous context
  - Likely intentional documentation

## compiler
- `src/parser/mod.rs:99` — `raise SystemExit("check-grammar: could not isolate body of " + name)`
  - Error message text containing variable name - intentional
- `src/codegen/mod.rs:313` — `out.push_str(" with ");`
  - Code generation - intentional formatting

## docs
- `docs/SYSCALLS_BRAINSTORM.md:56` — `| `chmod` | 90 | Change permissions | `Set permissions of "script.sh" to executable.` |`
  - Documentation example - intentional
- `docs/SYSCALLS_BRAINSTORM.md:57` — `| `chown` | 92 | Change ownership | `Set owner of "file.txt" to "user".` |`
  - Documentation example - intentional
- `docs/SYSCALLS_BRAINSTORM.md:109` — `Print "Child exited with " then status.`
  - Shell script documentation - intentional
- `docs/FUTURE_FEATURES.md:272` — `If any name in names is equal to "Alice" then,`
  - Example code - ambiguous, likely intentional
- `docs/FUTURE_FEATURES.md:308` — `If all name in names is not equal to "" then,`
  - Example code - ambiguous, likely intentional
- `docs/FUTURE_FEATURES.md:349` — `If none name in names is equal to "" then,`
  - Example code - ambiguous, likely intentional
- `docs/STRUCTS_AND_OBJECTS.md:75` — `Set spot's name to "Spot".`
  - Example code showing field name assignment - intentional
- `docs/STRUCTS_AND_OBJECTS.md:2` — `> document itself defers the feature to "a future major version," and the`
  - Commentary in changelog/explanation - looks intentional

## vscode
- `vox-vscode/check-grammar.sh:99` — `raise SystemExit("check-grammar: could not isolate body of " + name)`
  - Error message - intentional

## codemod
- (None found)

## corpus
- `tests/106_function_local_buffer_decl.vox:19` — `a number called "n" is "measure" of "sda2".`
  - Function call with string literal argument - appears to be intentional string value, not identifier
- `tests/128_boolean_as_text.vox:1` — `(Regression test: boolean "as text" was broken, returning raw numeric value instead of "true"/"false".)`
  - Test comment describing behavior - looks intentional
- `tests/166_value_recursion.vox:13` — `print "walk" of "two" and 100.`
  - Using a text literal, not an identifier - looks intentional
- `tests/202_value_local.vox:9` — `a value called "first_slot" is "echo" of "hello".`
  - Using text literals, not identifiers - looks intentional
- `tests/203_value_param_word_boundary.vox:27` — `"vfirst" of "aa" and 1 and 2.`
  - Using text literals as arguments - looks intentional
- `tests/203_value_param_word_boundary.vox:29` — `"twovals" of "x" and 5 and "y".`
  - Using text literals as arguments - looks intentional
- `tests/208_source_include.vox:12` — `print "greet" of "world".`
  - Function call with text literal - looks intentional
- `tests/lib/cli.vox:18` — `If "hasflag" of "-v" then, return a number, 1.`
  - Using a literal string "-v", not an identifier - looks intentional
- `tests/lib/cli.vox:19` — `If "hasflag" of "--verbose" then, return a number, 1.`
  - Using a literal string "--verbose", not an identifier - looks intentional
- `tests/lib/cli.vox:24` — `If "hasflag" of "-h" then, return a number, 1.`
  - Using a literal string "-h", not an identifier - looks intentional
- `tests/lib/cli.vox:25` — `If "hasflag" of "--help" then, return a number, 1.`
  - Using a literal string "--help", not an identifier - looks intentional

### examples
- `examples/time.vox:13` — `Stop the "job timer".`
  - Timer reference - intentional (found earlier)

## history
The following files are in `docs/plans/**` and are expected to contain old syntax:
- `docs/plans/000_list_whole_printing.md`
- `docs/plans/010_stage_1b_inference_soundness_flip.md`
- `docs/plans/020_stage_1c_type_predicates.md`
- `docs/plans/030_stage_1d_dynamic_value_type.md`
- `docs/plans/040_stage_1e1_nested_lists.md`
- `docs/plans/050_stage_1e2_maps_and_null.md`
- `docs/plans/060_stage_1e3_json_yaml.md`
- `docs/plans/070_stage_2a_matrix_type.md`

And:
- `CHANGELOG.md`
- `LANGUAGE.md`

These are all project history/documentation and should not be modified.

## Summary

### UNOWNED bucket
- `test.sh:109` — Print "Child exited with " then status. (likely intentional doc)

### compiler bucket
- `src/parser/mod.rs:99` — error message
- `src/codegen/mod.rs:313` — codegen string formatting

### docs bucket
- `docs/SYSCALLS_BRAINSTORM.md:56` — example
- `docs/SYSCALLS_BRAINSTORM.md:57` — example
- `docs/SYSCALLS_BRAINSTORM.md:109` — shell script doc
- `docs/FUTURE_FEATURES.md:272` — example
- `docs/FUTURE_FEATURES.md:308` — example
- `docs/FUTURE_FEATURES.md:349` — example
- `docs/STRUCTS_AND_OBJECTS.md:75` — example
- `docs/STRUCTS_AND_OBJECTS.md:2` — comment about feature
- `CHANGELOG.md` (multiple lines) — history
- `LANGUAGE.md` (multiple lines) — history

### vscode bucket
- `vox-vscode/check-grammar.sh:99` — error message

### codemod bucket
- None

### corpus bucket
- `tests/106_function_local_buffer_decl.vox:19` — function call with text literal
- `tests/128_boolean_as_text.vox:1` — test comment
- `tests/166_value_recursion.vox:13` — function call with text literal
- `tests/202_value_local.vox:9` — function call with text literal
- `tests/203_value_param_word_boundary.vox:27` — function call with text literals
- `tests/203_value_param_word_boundary.vox:29` — function call with text literals
- `tests/208_source_include.vox:12` — function call with text literal
- `tests/153_timer_start_end_time.vox:30` — Stop the "job timer"
- `tests/lib/cli.vox:18` — If "hasflag" of "-v"
- `tests/lib/cli.vox:19` — If "hasflag" of "--verbose"
- `tests/lib/cli.vox:24` — If "hasflag" of "-h"
- `tests/lib/cli.vox:25` — If "hasflag" of "--help"

### examples bucket
- `examples/time.vox:13` — Stop the "job timer"

### history bucket (excluded from changes)
- `docs/plans/000_list_whole_printing.md`
- `docs/plans/010_stage_1b_inference_soundness_flip.md`
- `docs/plans/020_stage_1c_type_predicates.md`
- `docs/plans/030_stage_1d_dynamic_value_type.md`
- `docs/plans/040_stage_1e1_nested_lists.md`
- `docs/plans/050_stage_1e2_maps_and_null.md`
- `docs/plans/060_stage_1e3_json_yaml.md`
- `docs/plans/070_stage_2a_matrix_type.md`
- `CHANGELOG.md`
- `LANGUAGE.md`

## Totals

| Bucket | Files | Matches |
|--------|-------|---------|
| UNOWNED | 1 | 1 |
| compiler | 2 | 2 |
| docs | 8 | ~30+ |
| vscode | 1 | 1 |
| codemod | 0 | 0 |
| corpus | 12 | 12 |
| examples | 1 | 1 |
| history | - | excluded |
| **Total** | 25 | 57+ |