# Plan 290 — `Append` rejects a `text` variable as a source

**Status:** specced 2026-08-07. Root cause found and confirmed live against a
fresh `main` build (`b143840`); not yet fixed.

## Problem

```vox
a buffer called line is 256 bytes in size.
a text called ch is ".".
Append ch to line.
```

```
error: Buffer append requires a buffer source: ch
```

`Append "literal" to line.` (a string literal) and `Append other_buf to
line.` (a buffer variable) both work today. A `text`-typed variable holding
a string — `ch` above — is rejected, even though it is exactly the same
underlying runtime value (a pointer to a NUL-terminated C-string) a string
literal already is.

Found while porting a Game of Life demo written in Vox, independently
reproduced by the root master against a genuinely fresh build before this
track was spun up.

## Root cause — confirmed by reading the code, not inferred

**The check.** `src/analyzer/mod.rs:2433-2469`, `Statement::ListAppend`
analysis, buffer-target branch:

```rust
if self.is_buffer_variable(list) {
    match value {
        Expr::Identifier(source) => {
            if !self.is_variable_available(source) {
                self.push_error(format!("Unknown buffer: {}", source), Some(source));
            } else if !self.is_buffer_variable(source) {
                self.push_error(
                    format!("Buffer append requires a buffer source: {}", source),
                    Some(source),
                );
            }
        }
        Expr::StringLit(_) | Expr::FormatString { .. } => {
            // Allowed: append text/format output into destination buffer.
        }
        _ => {
            self.push_error(
                "Buffer append requires a buffer source or format/literal text".to_string(),
                Some(list),
            );
        }
    }
}
```

The `Expr::Identifier(source)` arm only accepts `source` when
`is_buffer_variable(source)` is true. There is no sibling check for "is
`source` a `text`-typed scalar variable" — that category is accepted for a
*literal* (`StringLit`/`FormatString`, the arm below it) but never for a
*variable* holding the same kind of value. This is the entire bug: one
`Expr` variant (`Identifier`) is checked too narrowly; the others are fine.

**Codegen and runtime already support this — confirmed, not assumed.**
`src/codegen/mod.rs:3798-3817` (the `ListAppend` codegen for a buffer
target) first tries `emit_copy_expr_into_buffer_slot` (`codegen/mod.rs:822-918`).
That function's `Expr::Identifier(name)` arm (896-915) only special-cases a
*buffer*-typed identifier (it calls `_buffer_copy`/`_buffer_append` with the
source buffer's raw pointer) and returns `false` for anything else,
including a text variable. When it returns `false`, codegen falls through
to the generic path already used for every other "unknown at compile time,
resolve by runtime type tag" value:

```rust
self.generate_expr(value);
let fmt_spec = self.parse_format_spec(None);
// dst_local / dst_global branch:
self.emit_append_runtime_value_to_buffer_slot(offset, self.infer_expr_type(value), fmt_spec);
// or, for a global buffer:
self.emit_append_runtime_value_to_buffer_ptr(self.infer_expr_type(value), fmt_spec);
```

- `infer_expr_type(Expr::Identifier(name))` (`codegen/mod.rs:7356-7360`)
  resolves through `self.variable_types`, which already carries `VarType::String`
  for a `text`-declared variable.
- `emit_append_runtime_value_to_buffer_ptr` (`codegen/mod.rs:626-642`) already
  has a `Some(VarType::String) => call _buffer_append_cstr` arm.
- `_buffer_append_cstr` (`coreasm/x86_64/resource.asm:1362-1387`) computes the
  C-string's length by scanning for the NUL terminator, then calls
  `_buffer_append_bytes` (`coreasm/x86_64/resource.asm:1272-1357`) — the same
  bounds-checked routine every other buffer append already goes through. For a
  **fixed-size** buffer it clamps to remaining capacity and sets
  `_last_error` (lines 1313-1335) instead of overflowing; it does not special-
  case *how* the bytes arrived, only how many there are and how much room is
  left.

This exact runtime path (`_buffer_append_cstr` from a `VarType::String`
identifier) is already exercised today by `{ch}`-style format-string
interpolation into a buffer (`FormatPart::Variable` → `resolve_format_variable`
→ `emit_append_runtime_value_to_buffer_slot`, `codegen/mod.rs:727-759`). It is
not new code and not a new code path — the analyzer is the only thing
standing between `Append ch to line.` and a working, already-bounds-checked
runtime call.

**Conclusion: this is an analyzer-only fix.** No codegen or runtime change is
required or in scope. If, while implementing, you find codegen does *not*
actually reach `_buffer_append_cstr` for some sub-case (e.g. a local vs.
global buffer, or an uninitialized `scalar_types` entry), stop and say so
precisely — that would mean this root cause is wrong, not that you should
patch around it in codegen.

## Target

`Append ch to line.` where `ch` is a `text` variable compiles, and at
runtime appends `ch`'s current string content onto `line`, honoring the
same fixed-buffer bounds check that literal-text append already has
(`tests/143_fixed_buffer_overflow_still_errors.vox` is the existing
reference case for that behavior — do not weaken it).

## Fix

In `src/analyzer/mod.rs`, in the `Expr::Identifier(source)` arm of the
`ListAppend` buffer-target check (~line 2439-2447), accept `source` when it
is **either** a buffer variable (existing) **or** a text-typed scalar
variable. Use the existing `named_value_type` helper
(`src/analyzer/mod.rs:1516-1532`) to test the latter —
**do not use `infer_simple_expr_type`** (the other, similarly-named helper
at line 1724): that one does *not* consult `scalar_types` for a bare
`Identifier` (it only recognizes buffer/list/map/flag categories there,
see lines 1737-1749) and would return `None` for a `text` variable, silently
failing to fix anything. `named_value_type` is the one that already falls
through to `self.scalar_types.get(name)` (line 1530) and is what a `text`
declaration populates (`src/analyzer/mod.rs:1971-1979`) — it is also the
helper already reused for this exact "is this name currently holding text"
question elsewhere in the file (lines 1554, 1564).

Sketch (adapt exact syntax as needed, this is not meant to be copy-pasted
verbatim):

```rust
Expr::Identifier(source) => {
    if !self.is_variable_available(source) {
        self.push_error(format!("Unknown buffer: {}", source), Some(source));
    } else if !self.is_buffer_variable(source)
        && self.named_value_type(source) != Some(Type::String)
    {
        self.push_error(
            format!("Buffer append requires a buffer or text source: {}", source),
            Some(source),
        );
    }
}
```

(The error message wording is not load-bearing — adjust it if you think a
clearer one fits, just keep it accurate: it's no longer "must be a buffer.")

## Required verification

1. The repro above now produces **correct runtime output**, not just "no
   parse error." Assert the actual buffer contents after the append (e.g.
   print the buffer and check the printed text), not just that compilation
   succeeds.
2. Regression coverage, all must still pass unchanged:
   - `Append "literal" to buf.` (StringLit source — unaffected).
   - `Append other_buf to buf.` where `other_buf` is a `buffer` (Identifier +
     `is_buffer_variable` — the case that already worked, must keep working).
   - `Append n to buf.` where `n` is a `number` — must **still be rejected**.
     This finding is specifically about `text` sources; a number identifier
     is exactly the "or format/literal text" boundary the analyzer is meant
     to hold, and this fix must not widen it further than text. Assert the
     specific error still fires.
   - `tests/143_fixed_buffer_overflow_still_errors.vox` and
     `tests/067_format_buffer_fixed_overflow.vox` (or run the full suite —
     see below) still pass: the fixed-buffer bounds check must still fire
     for a text-variable source too large for the destination (this is also
     exactly what the red team will be probing — see the red team brief for
     this track; make sure your own test coverage independently proves it
     before red team even starts, since a real bounds-check regression here
     would be a memory-safety bug, not a cosmetic one).
3. `cargo test` fully green.
4. `./test.sh` — baseline on a fresh `main` (`b143840`) checkout, force-clean
   build (`rm -f target/release/vox` before building — this environment has
   shown builds reporting success in ~0.03s without recompiling), is:
   **211 passed / 0 failed / 6 skipped, 217 total.** Hold this or better, 0
   failed, verified behaviorally (run the actual repro against your built
   binary), not by trusting build timing.
5. 0 build warnings.
6. New test files: use numbers **217-219** (the range reserved for this
   track's worker 1; worker 2, working findings 5+6 in a sibling worktree,
   uses 220+ — check `ls tests/*.vox | grep -oE '[0-9]+' | sort -n | tail -1`
   before picking a number in case this range has since been taken by
   something else landing on `main`).

## Hard constraints

- No new crates, no libc.
- Never weaken a test to make it pass.
- Do not touch codegen or the runtime (`coreasm/`) unless verification in
  step 2 above actually proves the root-cause analysis wrong — if that
  happens, stop and describe exactly what you found rather than patching
  around it.
- Commits are GPG-signed with a hardware key. If signing hangs, stop and say
  so — never `--no-gpg-sign`.
