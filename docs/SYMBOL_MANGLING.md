# Vox Standard: Symbol Mangling

> **Status:** Active project standard. The `<library>_<version>_<name>`
> function-label rule is the adopted standard and is emitted by the compiler
> (`nm -D` shows e.g. `mathkit_1_0_add_two_numbers`); per-version runtime-state
> mangling is an explicit non-goal, superseded by plan 230. _(assessed 2026-08,
> vox v0.1.24)_

Vox emits a flat assembly symbol namespace. Compiler-generated names, runtime
internals, author-written function names, and — once shared libraries land —
several library versions inside one process all land in it together. Nothing
separates them by construction, so collisions are silent until the assembler
or linker happens to notice.

This document is the project standard for keeping them apart. It applies
anywhere two independently-authored names can reach the same symbol table.

---

## The namespaces

| Namespace | Form | Example | Who owns it |
|---|---|---|---|
| Runtime internals | `_` prefix | `_map_insert`, `_last_error` | coreasm |
| Author functions (executable) | name with spaces → `_` | `greet_user` | the Vox author |
| Library exports | `<lib>_<version>_<name>` | `flags_0_1_hasflag` | a shared library |
| Library runtime state *(superseded — see note below)* | `<lib>_<version>_<name>` | `flags_0_1_last_error` | a shared library |

> **The "Library runtime state" row is superseded — see plan 230.** Phase 3
> deliberately does *not* mangle runtime state. The row is left here as the
> record of the earlier design; the sections below that argue and implement
> per-version runtime mangling ("Why runtime state is mangled too" and
> "Implementation: rename at include time, not in coreasm") are likewise
> superseded. **Function-label mangling** (the "Library exports" row and
> the `<library>_<version>_<name>` rule for exported functions) stands
> unchanged and remains the project standard. See plan 230, "Explicit
> non-goal: runtime state is not mangled", for the reason: multi-input
> `--shared` compiles to one assembly unit, so the runtime is emitted once
> and shared by every library in that `.so` — one resource table, one
> `.fini_array`, one idempotent `_cleanup_all` — and cross-`.so` isolation
> already holds because each `.so` carries its own runtime and the version
> script hides it.

**A leading underscore is reserved for the runtime.** This mirrors C, where
leading-underscore identifiers belong to the implementation. Author function
names must not start with one; the compiler rejects them rather than letting
the collision reach NASM. Before this rule, `To "_str_eq" ...` produced:

```
error: label `_str_eq' inconsistently redefined
```

— an assembler diagnostic about a symbol the author never wrote.

---

## Mangling rule for libraries

```
<library>_<version>_<name>
```

Every component is **sanitized to a valid C identifier**: each character
outside `[A-Za-z0-9_]` becomes `_`, and a leading digit is prefixed with `_`.

Sanitization is not cosmetic. A standalone `.so` must be callable from C or
Rust, and `flags_0.1_hasflag` — the form used in
[SHARED_LIBRARIES_DESIGN.md](SHARED_LIBRARIES_DESIGN.md) — **is not a valid C
identifier**. NASM accepts the dot, so the mistake assembles cleanly and only
surfaces when a C consumer cannot name the function. Version `0.1` therefore
mangles to `0_1`.

Apply the same rule to exported functions and runtime state alike, so there is
one function to reason about rather than two conventions.

---

## Why runtime state is mangled too

> **Superseded by plan 230's "Explicit non-goal: runtime state is not
> mangled".** The argument below was the case for per-version runtime
> mangling; Phase 3 rejects it for the reason given there. Kept as history.

A shared object's symbols are already module-local unless declared `global`, so
two separate `.so` files already have independent `_last_error`. Mangling earns
its keep in the case ELF scoping cannot reach:

> "A single `.so` file can contain multiple libraries and different versions."
> — [SHARED_LIBRARIES_DESIGN.md](SHARED_LIBRARIES_DESIGN.md)

Two versions inside **one** module share one symbol table, so without mangling
`flags 0.1` and `flags 1.0` share one `_last_error`, one `_call_depth`, one set
of fd and buffer tables. Mangling is what makes the documented multi-version
feature safe, and it gives each version the exact runtime it was compiled
against even if the runtime's table layout changes between releases.

---

## Implementation: rename at include time, not in coreasm

> **Superseded — do not implement.** This `%define` prologue is the mechanism
> for per-version runtime-state mangling, which plan 230's explicit non-goal
> reverses. The "no edit to any `coreasm/` file" constraint it illustrates is
> still good guidance for any future coreasm rewrite; the runtime-state
> *mangling* itself is not built. Kept as history.

Codegen emits a `%define` block ahead of the includes. NASM's preprocessor
rewrites the definition *and* every use:

```nasm
%define _last_error  _flags_0_1_last_error
%define _call_depth  _flags_0_1_call_depth
%define _print_depth _flags_0_1_print_depth
%include "coreasm/x86_64/core.asm"
```

`_last_error: resq 1` in `core.asm` becomes `_flags_0_1_last_error: resq 1`, and
`mov qword [rel _last_error], 1` in `resource.asm` follows it, with **no edit to
any coreasm file**.

That constraint is deliberate and should be preserved. `coreasm/` is rewritten
per architecture (ROADMAP M6: AArch64, RISC-V, Win64), so a mangling scheme
that required threading a prefix through every state reference would be
implemented four times and got wrong at least once. Keeping the mechanism in
the emitted prologue means a port inherits it for free.

---

## What mangling does not solve

> **The per-version `_last_error`/counter discussion below is superseded by
> plan 230's non-goal** — runtime state is shared, not mangled. The broader
> point that error propagation across a `.so` boundary is an ABI convention
> rather than shared state still applies. Kept as history.

Isolating a library's `_last_error` means a Vox program's `on error` no longer
sees it — the caller reads its own flag. That bridge is an **ABI convention,
not shared state**: the library exposes its error value, and codegen emits a
fetch-and-merge after each library call.

A C consumer needs that accessor regardless, so the convention is required by
the standalone-library goal rather than added by mangling. Mangling in fact
makes it cheaper: the symbol to read is derived deterministically from the
library and version at the call site, with no registry or runtime lookup.

The same applies to `_call_depth` and `_print_depth`. Per-version counters are
forced by the decision to make libraries standalone — a C host has no counter to
share — and they fail permissive (recursion and cycle budgets multiply by the
number of modules) rather than unsafe. Document the limit; do not paper over it.

---

## Checklist for new collision surfaces

When adding anything that introduces independently-authored names into the
symbol table, decide up front:

1. Which namespace above does it belong to?
2. Can an author choose a name that lands in it? If so, reject at analyze time
   with a Vox diagnostic — never let the assembler or linker report it.
3. Does it need to be reachable from C? If so, sanitize to a C identifier.
4. Can it be done with a `%define` prologue instead of editing `coreasm/`?
