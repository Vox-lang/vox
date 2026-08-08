# Plan 292 — `Append <text var> to <global buffer>` corrupts data (register clobber)

**Status:** specced 2026-08-08. Found by the red team spawned on plan
290/291's track; self-diagnosed independently by the worker that implemented
plan 290 while investigating a third regression test; confirmed live by the
sub-master against the merged `p2-append-butif` tip (`5a52cdb`) with a fresh,
independently-verified rebuild.

## Problem

Plan 290 widened `Append <var> to <buffer>.` to accept a `text`-typed
variable as the source (previously only a literal or another buffer
variable). For a buffer declared at module/top level and mutated from
**inside a function** — a supported, tested pattern
(`tests/123_global_buffer_in_function.vox`) — the append silently writes the
**wrong bytes** instead of erroring or crashing:

```vox
a buffer called g is 64 bytes in size.
a text called payload is "PAYLOAD".

To mutate.
  Append payload to g.

mutate.
Print g.
```

Expected: `PAYLOAD`. Actual: `@` (one byte of buffer-internal header data,
misread as if it were the intended string). Confirmed live against
`5a52cdb`.

The same statement with a **literal** source instead of a `text` variable —
`Append "PAYLOAD" to g.` inside the same `mutate` function — prints
`PAYLOAD` correctly. This is not a general "buffer + function" bug; it is
specific to the newly-accepted `text`-variable source, and specific to a
**global** (cross-function) buffer destination — the exact combination plan
290 introduced.

## Root cause — confirmed by reading the code, not inferred

`src/codegen/mod.rs`, `Statement::ListAppend` codegen for a buffer target
(~line 3798-3817):

```rust
if !self.emit_copy_expr_into_buffer_slot(value, false, dst_local, dst_global.as_deref()) {
    self.generate_expr(value);                    // rax = source value/pointer
    let fmt_spec = self.parse_format_spec(None);
    if let Some(offset) = dst_local {
        self.emit_append_runtime_value_to_buffer_slot(offset, self.infer_expr_type(value), fmt_spec);
    } else if let Some(ref label) = dst_global {
        self.emit_load_named_var_addr(list);       // clobbers rax!
        self.emit_indent("mov rdi, rax");
        self.emit_append_runtime_value_to_buffer_ptr(self.infer_expr_type(value), fmt_spec);
        self.emit_indent(&format!("mov [rel {}], rax", label));
    }
}
```

`self.generate_expr(value)` leaves the source value (for a `text` variable,
a pointer to its C-string) in `rax`. For the `dst_global` branch,
`self.emit_load_named_var_addr(list)` (`src/codegen/mod.rs:577-587`) is then
called — and it **unconditionally writes into `rax`**:

```rust
fn emit_load_named_var_addr(&mut self, name: &str) -> bool {
    if let Some(offset) = self.get_var(name) {
        self.emit_indent(&format!("mov rax, [rbp-{}]  ; local {}", offset, name));
        true
    } else if let Some(label) = self.global_var_label(name).cloned() {
        self.emit_indent(&format!("mov rax, [rel {}]  ; global mirror {}", label, name));
        true
    } else {
        false
    }
}
```

This overwrites the source value that was sitting in `rax` **before** it's
consumed. `mov rdi, rax` then puts the *destination* buffer's address into
`rdi` (correct) — but `emit_append_runtime_value_to_buffer_ptr`
(`src/codegen/mod.rs:626-642`) subsequently does `mov rsi, rax` expecting
`rax` to still hold the *source* value; instead it now holds the same
destination address that's already in `rdi`. The runtime call
(`_buffer_append_cstr` for a `VarType::String` source) ends up reading from
the destination buffer's own header/data as if it were the source string,
appending a fragment of the buffer's own internal bytes onto itself.

**Why this is new, not a latent pre-existing bug:** before plan 290, the
analyzer rejected every `Expr::Identifier` append source unless it was
itself a buffer variable. A buffer-variable source is handled entirely by
`emit_copy_expr_into_buffer_slot`'s own `Identifier` arm (`src/codegen/mod.rs:896-915`),
which returns `true` and never falls through to the vulnerable generic path
at all. `StringLit`/`FormatString` sources are likewise fully handled by
`emit_copy_expr_into_buffer_slot`'s own arms. So **no previously-valid
program could ever reach this `dst_global` fallback branch** for a buffer
target — it was dead code. Plan 290's widening is what first makes a
`text`-variable `Identifier` fall through to it (since
`emit_copy_expr_into_buffer_slot`'s `Identifier` arm only special-cases a
*buffer*-typed name, returning `false` for a text-typed one). The `dst_local`
sibling branch has no equivalent bug — `emit_append_runtime_value_to_buffer_slot`
loads the destination via `mov rdi, [rbp-offset]`, a direct memory read that
never touches `rax`, so the source value survives untouched. This is purely
a `dst_global` (buffer declared outside the current function, mutated via
its "global mirror") issue.

**Independently confirmed** (not just read): the sub-master built
`5a52cdb` from a verified-clean rebuild and ran both the repro above (prints
`@`, wrong) and the literal-source control case in the same
function-mutates-global-buffer shape (prints `PAYLOAD`, correct) — isolating
the bug to exactly the text-variable-source × global-buffer-destination
combination.

## Target

`Append <text variable> to <buffer>.` produces the same correct result
regardless of whether the destination buffer is local to the current
function or declared outside it and mutated through its global mirror —
matching how the literal-source and buffer-variable-source cases already
behave identically in both contexts today.

## Fix

In the `dst_global` arm of the `ListAppend` buffer-target codegen
(`src/codegen/mod.rs`, ~line 3808-3812), preserve the source value across
the destination-address load. Sketch (adapt to actually compile and match
this file's existing push/pop idiom, e.g. the buffer-value handling a few
lines above at 3868-3887 which already does `push rbx; push r12; ...; pop
r12; pop rbx` around a runtime call that would otherwise clobber a live
value):

```rust
} else if let Some(ref label) = dst_global {
    self.emit_indent("push rax  ; save source value across destination address load");
    self.emit_load_named_var_addr(list);
    self.emit_indent("mov rdi, rax");
    self.emit_indent("pop rax  ; restore source value");
    self.emit_append_runtime_value_to_buffer_ptr(self.infer_expr_type(value), fmt_spec);
    self.emit_indent(&format!("mov [rel {}], rax", label));
}
```

Verify this doesn't disturb stack alignment expectations elsewhere in the
function (NASM/x86-64 codegen in this project pushes/pops liberally
elsewhere in the same function for the same reason — follow the existing
convention, don't invent a new one).

**Scope discipline:** fix only this one `dst_global` `ListAppend` fallback
path. Do not go hunting for the same clobber pattern in other statement
kinds (`MapSet`, `ElementSet`, etc.) — if you notice the same shape
elsewhere while you're in the file, note it in your report as a possible
follow-up, but do not fix or test it here; that would be scope creep beyond
what this plan (and the original findings 4/5/6 track) covers.

## Required verification

1. The repro above now prints `PAYLOAD`, not `@` — assert the actual
   printed buffer content, not just successful compilation.
2. Regression coverage:
   - The literal-source control case (`Append "PAYLOAD" to g.` inside the
     same `mutate`-function shape) — must still print `PAYLOAD` correctly
     (already works; must not regress).
   - `tests/123_global_buffer_in_function.vox` (byte-set into a global
     buffer from a function) — must still pass unchanged.
   - `tests/217_append_text_variable_source.vox` and
     `tests/218_append_text_variable_fixed_overflow.vox` (plan 290's own
     tests, all **local**-buffer cases) — must still pass unchanged; this
     fix must not touch the `dst_local` path at all.
   - A **local**-buffer text-variable append still works (should be
     unaffected, but worth a direct assertion since it's the sibling code
     path to the one you're touching).
3. `cargo test` fully green.
4. `./test.sh` — hold the current baseline (**217 passed / 0 failed / 6
   skipped, 223 total**, as of `5a52cdb`) or better, 0 failed, on a
   force-clean rebuild (`rm -f target/release/vox` before building — and if
   the build ever reports success in well under a second right after
   touching a `.rs` file, that's the known stale-hardlink trap in this
   environment; force a `cargo clean -p vox` and rebuild from scratch to be
   sure, don't trust a suspiciously fast "Finished").
5. 0 build warnings.
6. New test file(s): use number **224** onward
   (`ls tests/*.vox | grep -oE '[0-9]+' | sort -n | tail -1` to confirm
   nothing has since claimed it).

## Hard constraints

- No new crates, no libc.
- Never weaken a test to make it pass.
- Touch only the one `dst_global` fallback branch described above. Do not
  refactor `emit_load_named_var_addr` itself (it's used correctly by many
  other call sites that don't have a live value in `rax` at the time they
  call it) — the bug is in how this one call site uses it, not in the
  helper itself.
- Commits are GPG-signed with a hardware key. If signing hangs, stop and say
  so — never `--no-gpg-sign`.
