# Internal ABI for the `value` type (Collections stage 1d)

> **Status:** Built — internal x86_64 calling-convention note for the dynamic
> `value` type (Collections stage 1d, marked done in COLLECTIONS_ROADMAP.md).
> The ABI is live in codegen (`emit_load_value_tag`, `mixed_tag_slots`); this
> note records the contract future work must preserve or extend.
> _(assessed 2026-08, vox v0.1.23)_

This is the internal (x86_64) calling-convention note for Vox's dynamic
`value` type — the declared type that carries a runtime type tag alongside
its payload across function boundaries. It is compiler-internal: Vox authors
never see these rules, only the `with a value called x` /
`Return a value, <expr>` surface syntax documented in `LANGUAGE.md`. The
note exists so future work (stage 1e nested-list tags, a clobbering helper,
shared-library ABI) knows the contract it must preserve or extend.

## What `value` is

A `value` is the existing dynamic-tag carrier — `VarType::Mixed` plus the
per-variable `mixed_tag_slots` shadow-slot machinery from stages 1a/1c —
reused, not reinvented. The new work in 1d is purely the **ABI**: getting
the tag through the call in both directions. Inside a callee, a `value`
parameter or local is just a `Mixed` scalar with a shadow tag slot, so the
stage-1c predicates, printing, appending, forwarding, and recursion all work
on it unchanged.

Tag values are the list element tags (`LIST_TAG_*` in `coreasm/x86_64/list.asm`,
mirrored as `MAP_TAG_*` in `map.asm` and `TAG_*` in the codegen):

| tag | meaning     | source spelling                  |
|-----|-------------|----------------------------------|
| 0   | integer     | `42`                             |
| 1   | string      | `"text"`                         |
| 2   | float       | `3.5` (a decimal)                |
| 3   | boolean     | `true` / `false`                 |
| 4   | list        | `[1, 2, 3]`                      |
| 5   | map         | `{"k": v}`                       |
| 6   | nothing     | `nothing` / `null` / `nil`       |

Tag 6 (nothing, stage 1e3) carries payload 0. It is *not* a `VarType` or
declared `Type` — `NothingLit` threads through the tag oracles
(`prescan_expr_tag` / `emit_time_expr_tag` return `Some(6)`) only, so the
five tag-forward sites (list literal, `append`, `element set`, `map set`,
map literal pair) write 6 directly and a `value` return carrying nothing
loads tag 6 into `r11` via the `Some(t)` arm of `emit_load_value_tag`.
`is nothing` / `is not nothing` is the **equality** route (like `is true`
/ `is false`), not a type predicate: it compares the operand's runtime tag
against 6, and must precede the numeric payload compare so that `0 is
nothing` is false (a nothing payload is 0).

## Inbound — a `value` parameter

The argument stream is **word-indexed**. Each scalar parameter occupies one
argument word; each `value` parameter occupies **two consecutive words** —
payload first, then tag. Caller and callee both derive each parameter's word
count from the same `Vec<Type>` (caller: `function_param_types[f]`; callee:
the `FunctionDef` `params`), so they agree on every word's position.

- The first 6 words fill the SysV registers `rdi, rsi, rdx, rcx, r8, r9`
  (word 0 → `rdi`, word 1 → `rsi`, … word 5 → `r9`).
- Words 6 and above are pushed right-to-left onto the stack, so word 6
  lands at `[rbp+16]` (after the alignment pad, see below), word 7 at
  `[rbp+24]`, … word *w* at `[rbp+16+pad+(w-6)*8]`.

Because a `value` parameter is two words, its payload and tag can straddle
the register/stack boundary (e.g. 5 scalar params + 1 `value` = 7 words:
payload in `r9` (word 5), tag at `[rbp+16]` (word 6)). Word indexing handles
this naturally — there is no special straddle case.

**Caller** (`emit_function_call`): for each parameter right-to-left,
`generate_expr(arg)` → `rax` (payload); if the parameter is `value`,
`emit_load_value_tag(arg)` → `r11` (tag), then `push r11` (tag word) and
`push rax` (payload word, pushed last → on top → lower word index); else
`push rax`. Then pop the first `min(6, total_words)` words into the
registers, align the stack, `call`, and clean up.

**Callee**: pass 1 allocates a payload slot plus a `{name}_mixtag` shadow
slot for each `value` parameter and records the var as `Mixed` in
`mixed_tag_slots`. Pass 2 walks the parameters tracking a running `word_index`,
reading each word by index (register word or `[rbp+16+pad+(w-6)*8]`); for a
`value` parameter it stores the payload word to the payload slot and the tag
word (as a byte) to the `{name}_mixtag` slot.

**Stack alignment:** the prologue saves the `min(6, total_words)` *register*
words around `_check_call_depth` (which touches only `rax`), then when
`stack_words = total_words - 6` is odd, an 8-byte pad is inserted
(`sub rsp, 8`) so the stack is 16-byte aligned at the `call`. The pad sits
at `[rbp+16]`, pushing the first stack word to `[rbp+16+8]`. **Callee stack
reads must add this pad offset**: `pad = if stack_words is even { 0 } else { 8 }`,
and a stack word *w* is read from `[rbp+16+pad+(w-6)*8]`. (This pad-offset
rule is what makes the 7-argument `value`-spill case in test 165 work; before
1d no test had 7+ arguments, so the missing offset was a latent bug.)

## Outbound — a `value` return

The payload is returned in `rax` as usual. The tag is returned in **`r11`**,
loaded by the callee just before the epilogue via `emit_load_value_tag(v)`,
and read by the caller immediately after `call`.

This needs **no spill** because nothing between the tag load and the caller's
read clobbers `r11`:

- `FUNC_EPILOGUE` is `leave; ret` (`coreasm/x86_64/funcs.asm`) — neither
  touches `r11`.
- `_dec_call_depth` is `dec qword [rel _call_depth]; ret`
  (`coreasm/x86_64/core.asm`) — touches only memory and `rip`; not `r11`.
- The `call` instruction itself clobbers only `rax`, `rcx`, `r11` for
  *leaf* syscalls, but a user-function `call`/`ret` pair does not.

So the return path is:

```asm
    generate_expr(v)            ; rax = payload
    emit_load_value_tag(v)      ; r11 = tag
    push rax                    ; (existing)
    call _dec_call_depth        ; does NOT clobber r11
    pop rax                     ; (existing)
    FUNC_EPILOGUE               ; leave; ret — does NOT clobber r11
```

and the caller's `generate_expr(FunctionCall)` for a value-returning function
naturally leaves `r11 = tag`, which `emit_load_value_tag`'s no-op case relies
on.

## `emit_load_value_tag` — the single source of truth

```
fn emit_load_value_tag(&mut self, expr: &Expr) {
    match self.emit_time_expr_tag(expr) {
        Some(t) => "mov r11, {t}"                // static tag (literals, typed vars, scalar calls)
        None => match self.mixed_element_tag_slot(expr) {
            Some(off) => "movzx r11, byte [rbp-{off}]"  // shadow slot (value params/locals, for-each vars)
            None => {}                            // r11 already holds the tag
                                                  //   (fresh mixed element read, or value-returning call)
        }
    }
}
```

It is used by the inbound argument push, the outbound return, and the append
tag-forwarding fix. **Hazard for future work:** if a helper that *can* clobber
`r11` is ever inserted between an `emit_load_value_tag` call and its consumer,
`r11` must be spilled to a shadow slot first. Today no such helper exists on
any of these paths.

## Criterion 6 — no regression for statically-typed code

When every parameter is scalar, `total_words == params.len()` and each
param's word count is 1, so the word-indexed caller and callee emit
byte-identical code to the pre-1d path (same pushes, same register/stack
split, same pad rule — the pad condition changed from `stack_arg_count` to
`stack_words`, equal for all-scalar calls). The full existing test suite
remains green, and a 7-scalar-argument call (which exercises the stack
spill) emits no `value` artifacts and pads correctly.