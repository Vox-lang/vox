# Buffer-Targeted Format Strings (Build Into Buffer)

## User Story
As a Vox user, I want to use format strings to build text into an existing buffer so that I can reuse buffers in hot loops without allocating or leaking memory, and so that formatted content can be written/appended without going through `Print`.

## Current State
- Vox supports format strings in `Print`, e.g. `Print "Hello {name}".`
- The parser already builds `Expr::FormatString { parts }` for string literals containing `{...}`.
- Codegen only supports `Expr::FormatString` inside `generate_print()`.
- In expression context (`generate_expr()`), `Expr::FormatString` currently produces no value (it is effectively unsupported).
- Because of the above, format strings cannot be used meaningfully in `Set ... to ...` or `... is ...` assignments.

## Proposed Behavior
Support using format strings to *build bytes into a destination buffer* (null-terminated) in assignment contexts:

- Buffer assignment:
  - `Set out to "Hello {name}".`
  - `A buffer called "out" is "Hello {name}".`
  - `The buffer out is "Hello {name}".`
  - `append "Hello {name}" to out.`
  - `copy "Hello {name}" to out.`
  - `clear out.`

Semantics for buffer assignment using a format string:
- Clears destination buffer length to 0 (preserving capacity)
- Appends each format part to the buffer
- Ensures null-termination
- Uses existing error flag behavior when appending/converting overflows a fixed-size buffer

Non-goals (for now):
- Producing an owned heap-allocated `text` value from a format string
- Adding new garbage collection or string freeing semantics

## Affected Code
| File | Lines | Description |
|------|-------|-------------|
| `src/parser/ast.rs` | (existing) | `Expr::FormatString` already exists |
| `src/parser/mod.rs` | (existing) | Parsing already produces `Expr::FormatString` |
| `src/analyzer/mod.rs` | (TBD) | Validate format-string-to-buffer assignments are valid (destination is a buffer; referenced vars exist) |
| `src/codegen/mod.rs` | (TBD) | Emit buffer-building logic for buffer assignments when RHS is `Expr::FormatString` |
| `coreasm/x86_64/resource.asm` | (TBD) | Add runtime helpers for appending literals and formatted values into buffers |
| `coreasm/x86_64/format.asm` | (TBD) | Reuse/port formatting routines to write into buffers instead of stdout |
| `LANGUAGE.md` | (TBD) | Document buffer-targeted format strings in Set/is statements |
| `tests/` | (TBD) | Add tests for buffer assignment with format strings (dynamic + fixed) |

## Scope of Changes
- [ ] Analyzer: when assigning to a buffer, allow `Expr::FormatString` and validate referenced identifiers
- [ ] Codegen: implement `Expr::FormatString` in buffer assignment contexts
- [ ] Runtime: implement buffer-append helpers for:
  - [ ] literals
  - [ ] variable string/buffer parts
  - [ ] integer formatting with width/zero-pad/base options
  - [ ] float precision formatting (if supported in print formatting)
- [ ] Documentation updates in `LANGUAGE.md`
- [ ] Tests covering:
  - [ ] dynamic buffer assignment from format string
  - [ ] fixed buffer overflow/truncation sets error
  - [ ] expression parts inside `{...}`

## Success Criteria
- [ ] `Set <buffer> to "...{...}...".` builds formatted output into the buffer
- [ ] `A buffer called "x" is "...{...}...".` builds formatted output into the buffer
- [ ] No heap allocation is required beyond what buffers already do (dynamic growth is allowed)
- [ ] Fixed-size buffer behavior matches existing rules (truncate + set error)
- [ ] All existing tests pass
- [ ] New tests added and passing

## Acceptance Criteria
- [ ] Given a dynamic buffer `out`, when `Set out to "A={a}".` executes, then `out` contains the expected bytes and is null-terminated
- [ ] Given a fixed buffer too small for the formatted output, when setting it from a format string, then it truncates and sets the error flag
- [ ] Given a format string with an expression part `{x + 1}`, when assigned into a buffer, then it formats the computed value
- [ ] All existing tests pass
- [ ] New tests added for changed functionality
