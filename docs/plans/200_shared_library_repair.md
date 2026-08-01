# User Stories

> **US-1 (library author):** As a library author, I want
> `vox mylib.vox --shared -o libmylib.so` to produce a loadable `.so`,
> so that I can build reusable Vox libraries at all. (Today every
> `--shared` build fails inside NASM.)

> **US-2 (library author):** As a library author, I want library
> functions to be able to use the core language — arithmetic, printing,
> buffers, lists, floats — so that a library is written in real Vox, not
> a runtime-free subset.

> **US-3 (maintainer):** As a maintainer, I want `./test.sh` to build a
> shared library and call across its boundary on every run, so that
> `--shared` can never silently rot again. (It rotted precisely because
> no test anywhere exercises it.)

> **US-4 (application author, follow-on):** As an application author, I
> want `see "math" version "1.0" from "./libmath.so"` to link my program
> against the library and fail clearly on a version mismatch, per
> [SHARED_LIBRARIES_DESIGN.md](../SHARED_LIBRARIES_DESIGN.md).

US-1..3 are **bug fixing** — restoring behavior the CLI already
advertises (`--shared`, `--link` are documented in `--help`). US-4 is
**feature building** (Milestone 3 in ROADMAP.md) and is scoped here only
as a follow-on outline so the repair work doesn't paint it into a corner.

---

## Feature/Problem Description

**Summary:**
`--shared` is completely broken, in two independent ways, and the
front-end syntax that was built for it (`Library ... version ...`,
`see ...`) is parsed but wired to nothing.

**Current Behavior:**

1. **No runtime is emitted.** `src/codegen/mod.rs:2043` skips every
   `%include "coreasm/..."` line in shared mode, on the comment
   "Shared libraries don't include coreasm - they're pure function
   exports". The premise is false: function bodies are emitted using
   coreasm *macros* unconditionally, so the generated asm contains
   `FUNC_PROLOGUE 16`, `INT_MUL`, `PRINT_INT` with no definitions.
   Reproducer (fails in NASM with `instruction expected, found
   'FUNC_PROLOGUE 16'`):

   ```
   To "double" with a number called "n". Return a number, n multiply 2.
   ```
   ```
   $ vox lib.vox --shared -o libtest.so
   lib.asm:15: error: instruction expected, found `FUNC_PROLOGUE 16'
   ```

2. **The runtime is not position-independent.** With the includes
   restored by hand, NASM passes but `ld -shared` refuses. Re-verified
   2026-08-01 against a hand-built probe (`core` + `io` + `resource` +
   `int` + `string`): `readelf -r` reports **exactly 34** relocations,
   every one `R_X86_64_32S` against `.bss`, every one from
   `coreasm/x86_64/resource.asm`. Each is the indexed-table
   pattern `[abs table + reg*scale]` against the seven resource tables:
   `fd_table`, `buf_table`, `ra_used`, `ra_fd`, `ra_pos`, `ra_filled`,
   `ra_data`. x86-64 RIP-relative addressing cannot take an index
   register, which is why these sites were given `abs` when the NASM
   `DEFAULT ABS` warnings were silenced (commit `4fb5694`) — correct
   for a static executable, impossible in a `.so`.

3. **`LibraryDecl` and `See` compile to comments.** The parser fully
   supports all four `see` syntaxes plus `Library "x" version "y"`
   (`src/parser/mod.rs:3810`, `:3839`), but the analyzer treats both as
   no-ops (`src/analyzer/mod.rs:2293`, `:2297`) and codegen emits them
   as assembly comments (`src/codegen/mod.rs:4119`, `:4125`). Name
   mangling, `.lib` metadata, and version enforcement from the design
   doc are entirely unbuilt. Note that `LibraryDecl`'s name and version
   are consumed inline in the statement walk and never stored on the
   generator — anything that needs them in the file header must capture
   them first.

4. **Latent, discovered while investigating:** the executable `--link`
   path (`src/main.rs:443`) passes `-L`/`-l` to `ld` but never sets
   `-dynamic-linker` or an rpath, so an executable actually linked
   against a `.so` would have no `PT_INTERP` and fail at exec. Cannot
   bite anyone today because no `.so` can be produced; must be fixed by
   the phase that first links one.

5. **The whole runtime is `global`, so it would be exported.**
   Discovered 2026-08-01 while validating this plan. **54 coreasm
   symbols** carry an explicit `global` declaration — 29 in
   `resource.asm`, 12 in `args.asm`, 9 across `string.asm`/`int.asm`/
   `float.asm`, plus `funcs.asm`'s macro-generated one. Every one lands
   in `.dynsym`. The runtime-light probe (which links today with only
   the Phase-0 include fix) exports:

   ```
   $ nm -D --defined-only probe.so
   _mem_eq  _parse_i64  _parse_i64_bounded  _parse_int_radix
   _parse_int_radix_bounded  _strdup_bounded  _str_eq  _str_len
   _text_to_boolean  vox_add
   ```

   Nine runtime symbols for one exported function. This is a namespace
   leak, not merely untidy output: a host that `dlopen`s with
   `RTLD_GLOBAL`, or two Vox `.so`s loaded together, collide on generic
   names like `_str_len`. Phase 0 must close it — see the visibility
   task there. (Measured, so the plan does not overstate it: intra-
   library calls bound *directly* in the probe — zero `JUMP_SLOT`
   relocations — so internal calls are not themselves interposable.
   The defect is the exported namespace, not the internal call path.)

**Expected Behavior (after Phases 0–2):**

```
$ vox libmath.vox --shared -o libmath.so
Created shared library: libmath.so
$ nm -D --defined-only libmath.so
0000000000001000 T double
```

and `./test.sh` contains a test that builds a `.so`, verifies its
exports, and calls a Vox library function from a driver program.

**Why now:** the runtime-PIC work (Phase 1) is the better fix for the
addressing tension that `4fb5694` resolved with `abs` — the
`lea`+index form is correct in *both* static executables and shared
objects, retiring that trade-off permanently.

---

## Scope

- [x] Backend (codegen + coreasm runtime + driver/`main.rs`)
- [ ] Frontend (parser — already done, no changes needed)
- [x] Tests (`test.sh` + `tests/shared/`)
- [x] Documentation (LANGUAGE.md `--shared` status, ROADMAP.md refresh)

**Out of Scope (deferred to Phase 3 / Milestone 3):**
- Name mangling (`<lib>_<version>_<func>`), `.lib` metadata files,
  version-mismatch diagnostics, multi-library `.so` parsing — i.e. all
  of [SHARED_LIBRARIES_DESIGN.md](../SHARED_LIBRARIES_DESIGN.md).
- Cross-library resource cleanup / error-flag propagation ABI.
- A pure-Vox caller via `see` (needs the `.lib`/extern wiring above);
  Phase 2's cross-boundary test uses an assembly driver instead.

---

## Technical Approach

> **2026-08-01: architecture decided — see below.** The phases were written
> before runtime placement was settled and are annotated accordingly.

### Decided architecture

**A `see` of a `.vox` file is a source include.** The referenced file's
statements are spliced in where the `see` appears, before compilation —
no runtime involvement at all. This already works (`process_includes` in
`src/main.rs`, recursive, with cycle protection via the `included` set); it
**Done 2026-08-01** — the gate tested for `.en` while the tree uses `.vox`,
so every include silently failed to inline; `.vox` is now the sole source
extension and `tests/208_source_include.vox` covers it, including the
transitive case.

**A `see` of a `.so` produces a standalone library.** The shared object is
self-contained and usable from C, Rust, or any other host — not only from
Vox — and cleans up its own resources on exit regardless of who loaded it.
It therefore contains its own copy of coreasm.

**Per-library-version state, via symbol mangling.** Each library version's
runtime state is mangled `<lib>_<version>_<name>`, so two versions inside
one `.so` do not share `_last_error`, `_call_depth`, `_print_depth`, or the
resource tables. Codegen emits a `%define` block ahead of the includes and
NASM's preprocessor rewrites both definitions and uses, so **no coreasm file
changes** — which matters because M6 ports coreasm three more times. The
rules, including C-identifier sanitization (`0.1` → `0_1`, since a C caller
cannot name `flags_0.1_hasflag`), are the project standard in
[docs/SYMBOL_MANGLING.md](../SYMBOL_MANGLING.md).

> **Sequencing (decided 2026-08-01): mangling lands in Phase 3, not Phase 0.**
> The architecture above is unchanged — only *when* it is built moves. Its
> precondition is two library versions inside one `.so`, which requires the
> `.lib` metadata and multi-library parsing that are already Out of Scope
> until Phase 3. Phases 0–2 compile exactly one library per `.so`, where
> there is no second version to collide with, and the symbol-visibility fix
> in Phase 0 solves the cross-`.so` collision problem *more* completely by
> removing runtime symbols from `.dynsym` altogether rather than making them
> uniquely named but still exported. Building the `%define` prologue early
> would also mean answering two questions Phase 0 has no basis to answer:
> where the name and version come from when a file has no `Library`
> declaration, and which of the runtime's symbols are in the mangled set.
> Phase 3 has a real answer to both. `mangle_symbol` and
> [SYMBOL_MANGLING.md](../SYMBOL_MANGLING.md) stay exactly as they are and
> continue to govern function labels today.

**Cleanup runs on two paths, because the hosts differ.** A C or Rust host
gets it free: libc registers `_dl_fini` via `atexit`, so `ld.so` runs the
library's `.fini_array`. A Vox host does not — Vox exits through a raw
`sys_exit`, which never reaches `_dl_fini` — so codegen also emits explicit
cleanup calls for each linked library before its own exit, which it can do
because `see`/`--link` gives it the set at compile time. `_cleanup_all` must
be idempotent so the two paths cannot double-close a descriptor.

**Error propagation is an ABI convention, not shared state.** A Vox
program's `on error` reads its own `_last_error`; the library writes
`<lib>_<ver>_last_error`. Codegen emits a fetch-and-merge after each library
call. A C consumer needs that accessor regardless, so this is required by
the standalone goal rather than added by mangling. `_call_depth` and
`_print_depth` stay per-version and fail permissive (budgets multiply by
module count); document the limit rather than hide it.

**Consequence for the phases below:** because the `.so` contains coreasm,
Phase 1's PIC work is **required**, not optional — `resource.asm`'s 34
absolute `[abs table + reg*8]` relocations cannot be relocated in a shared
object. Phase 0 stands as written for the include block, with the
symbol-visibility work added.

### Phase 0 — emit the runtime in shared mode (US-1)

In the final-assembly step of `src/codegen/mod.rs` (the
`if self.shared_lib_mode` branch at `:2043`), emit the **same
conditional include block** the executable path uses (core + the
`uses_*`-gated modules), keeping `default rel` and keeping the existing
no-`_start` text section (`:2113`, which emits `global` for each entry
of `exported_functions`, populated at `:2678`). `args.asm` must be
excluded: it reads the Linux loader's stack layout, which never exists
in a library.

**Restrict the exported symbol set (see Current Behavior 5).** Including
coreasm puts all 54 of its `global` symbols into `.dynsym`. Do *not* fix
this by editing `global` declarations in coreasm — that is 54 edits
repeated for every architecture M6 adds. Pass an anonymous linker version
script instead: `src/main.rs` writes a temp `.map` naming only the
program's exported functions, and adds `--version-script=<map>` to the
`-shared` `ld` invocation at `:418`. Verified end-to-end on the probe:

```
$ printf '{ global: vox_add; local: *; };\n' > vox.map
$ ld -shared --version-script=vox.map -o probe.so probe.o
$ nm -D --defined-only probe.so
00000000000005c4 T vox_add
```

Use the **anonymous** form (no version tag). A named script such as
`VOX_1 { ... }` also works but stamps exports as `vox_add@@VOX_1`, which
complicates the `nm` assertion in Phase 2 for no benefit. The temp file
should sit beside the `.o` and be cleaned up with it.

Top-level executable statements in a `--shared` compile are currently
generated into the discarded main body — i.e. silently dropped. Add an
analyzer diagnostic (error, not warning) for top-level statements other
than declarations/`Library`/`see` when compiling `--shared`, so authors
aren't surprised.

Note this phase alone makes **runtime-light libraries** (no
buffers/files/floats ⇒ no `resource.asm`) build and link end-to-end;
Phase 1 removes the remaining blocker for the rest.

### Phase 1 (REQUIRED — see decided architecture) — make the runtime position-independent (US-2)

Rewrite the 34 `[abs table + reg*scale]` sites in
`coreasm/x86_64/resource.asm` to:

```nasm
lea r11, [rel fd_table]
mov rax, [r11 + rcx*8]
```

choosing a scratch register per routine. Hazards, per the existing
register-discipline notes in `docs/plans/README.md`: syscalls clobber
`rcx`/`r11`, so any site where the `lea` result must survive a
`syscall` needs a callee-saved register (push/pop `rbx`) or a re-`lea`
after the syscall. Where several table accesses share a routine, hoist
one `lea` per table to the top of the routine rather than repeating it.

Then remove `-DPIC` special-casing questions entirely: after this
phase the *same* coreasm assembles warning-free and relocation-clean
for both executables and shared objects. Verify mechanically:

```
readelf -r <obj> | grep -c R_X86_64_32   # must be 0 for the .so path
```

and confirm zero NASM warnings remain across all test/example
programs (the bar set by `4fb5694`).

### Phase 2 — cross-boundary test in the harness (US-3)

- `tests/shared/libmath.vox` — a small library: one pure-arithmetic
  function, one that prints (exercises `io`/`format` includes), one
  that uses a buffer (exercises the Phase-1 `resource.asm` work).
- New `test.sh` section:
  1. build the `.so`; assert exit 0;
  2. `nm -D --defined-only` lists the three exports **and nothing else**
     — this is the assertion that holds Phase 0's version script honest,
     so write it as an exact set comparison, not a `grep` for presence.
     Export names at this phase are the plain function labels produced
     by `mangle_symbol` (`add`, not `libmath_1_0_add`): `<lib>_<version>_`
     prefixing arrives with Phase 3, and this assertion changes then;
  3. `readelf -d` shows a valid dynamic section;
  4. link a driver against it and call across the boundary, asserting
     both the return value and that the library's error accessor
     reports cleanly.
- **Write the driver in assembly, not C.** `tests/runtime/*.asm` already
  does exactly this for `map_key_ownership`: `nasm` + `ld`, both already
  required to build Vox, so the test always runs. An earlier draft of this
  plan proposed a `dlopen` driver in C guarded by `command -v cc` — that
  adds a toolchain the project deliberately does not need, and worse, it
  *skips silently* when the compiler is absent, so CI would report green
  with the boundary untested.
- Fix the latent executable-link gap while here: add
  `-dynamic-linker /lib64/ld-linux-x86-64.so.2` (and `-rpath`)
  to the executable `ld` invocation **only when** `link_libs` is
  non-empty (`src/main.rs:443`), so plain static builds are untouched.

### Phase 3 (follow-on outline only — US-4, Milestone 3)

Not planned in detail here; when picked up, it should get its own plan
document. The seam left by Phases 0–2: `Statement::See` in the
analyzer becomes the point that (a) reads a `.lib` file, (b) registers
external function signatures into `self.functions` so the
"Unknown function" check (`src/analyzer/mod.rs:1789`, and the second
site at `:2539`) passes, and
(c) codegen emits `extern <symbol>` + the `--link` flags instead of a
comment. Mangling and `.lib` generation live in the `--shared` compile;
version enforcement lives in the `see` resolution. Design authority:
[SHARED_LIBRARIES_DESIGN.md](../SHARED_LIBRARIES_DESIGN.md).

### Housekeeping — done 2026-08-01

The ROADMAP items this plan bundled are complete: the `_list_append`
realloc segfault is marked fixed (verified at 10 000 appends), the
documented-vs-actual buffer semantics are reconciled in README's memory
model, and the version header is current. The M0 regression *tests* for
growth across the realloc boundary remain open.

---

## Files/Components Affected

| File | Change | Phase |
|------|--------|-------|
| `src/codegen/mod.rs:2043` | emit conditional coreasm includes in shared mode (minus `args.asm`) | 0 |
| `src/main.rs:418` | write an anonymous version script; pass `--version-script` to the `-shared` `ld` | 0 |
| `src/analyzer/mod.rs:2293` | error on top-level executable statements under `--shared` | 0 |
| `src/main.rs` | thread a `--shared` flag into the analyzer for that diagnostic | 0 |
| `coreasm/x86_64/resource.asm` | 34 sites: `[abs T + r*s]` → `lea`+index, PIC-safe | 1 |
| `src/codegen/mod.rs` | `.fini_array` entry for the library's `_cleanup_all`; make it idempotent | 1 |
| `src/codegen/mod.rs` | emit explicit cleanup calls per linked library before `sys_exit` (a Vox host never reaches `_dl_fini`) | 1 |
| `src/codegen/mod.rs` | fetch-and-merge the library's error value after each library call | 1 |
| `src/main.rs:443` | `-dynamic-linker`/`-rpath` on executable links when `link_libs` non-empty | 2 |
| `test.sh` | shared-library section (build, exact export set, dynamic section, asm driver) | 2 |
| `tests/shared/libmath.vox`, `tests/runtime/*.asm` | new | 2 |
| `LANGUAGE.md` | document what `--shared` supports and rejects | 0–2 |
| `docs/plans/README.md` | register this plan | 0 |
| `src/codegen/mod.rs` | capture `LibraryDecl` name/version onto the generator; emit the mangling `%define` prologue | 3 |

Already in place: `mangle_symbol` in `src/codegen/mod.rs` with its
collision guard in the analyzer, and the standard it implements in
[SYMBOL_MANGLING.md](../SYMBOL_MANGLING.md). Versions fold `.` → `_`
without a guard because their alphabet (`[0-9.]`) cannot produce a
collision; author-chosen components fold and are checked.

Unchanged by design: `src/parser/mod.rs` (`see`/`Library` parsing is
complete at `:3810`/`:3839`), `src/codegen/mod.rs:4119`/`:4125`
(`LibraryDecl`/`See` stay comments until Phase 3).

> Line numbers in this document were re-verified against `bb7584d` on
> 2026-08-01. They drift; treat them as a starting point and confirm by
> the surrounding code, not the number.

---

## Success Criteria

- [ ] `vox <lib>.vox --shared -o lib<x>.so` exits 0 for a library using
      arithmetic, print, and buffers — no NASM errors, no `ld`
      relocation errors.
- [ ] `readelf -r` on the shared object path shows **zero**
      `R_X86_64_32`/`R_X86_64_32S` relocations (34 today, all from
      `resource.asm`).
- [ ] `nm -D --defined-only` on that `.so` lists **only** the library's
      own exports — zero of the 54 coreasm `global` symbols reach
      `.dynsym`.
- [ ] All test and example programs still compile with **zero** NASM
      warnings (223 programs as of 2026-08-01; no regression of `4fb5694`).
- [ ] `./test.sh` and `cargo test --release` stay green (192 integration
      / 115 cargo as of 2026-08-01) plus the new shared-library tests.
- [ ] Hosted runtime behavior is byte-for-byte equivalent in observable
      output — `test.sh` is the arbiter.
- [ ] A C or Rust program can load the `.so`, call an exported function
      by the name `nm -D` reports for it, and see its resources cleaned
      up at exit.

---

## Acceptance Criteria

1. **Given** a `.vox` file containing only function definitions,
   **when** compiled with `--shared`, **then** a `.so` is produced and
   `nm -D --defined-only` lists exactly the defined functions and
   nothing else — none of coreasm's 54 `global` runtime symbols appear.
   Assert as a set equality; a presence-only `grep` passes while the
   leak is wide open.
2. **Given** a library function that prints and one that uses a buffer,
   **when** compiled with `--shared`, **then** the build succeeds
   (runtime included, PIC-clean) and the printing function works when
   invoked from the driver.
3. **Given** a `.vox` file with top-level executable statements,
   **when** compiled with `--shared`, **then** the compiler rejects it
   with a clear diagnostic naming the offending statement — not a
   silent drop.
4. **Given** the assembly driver, **when** it calls the arithmetic
   export with known operands, **then** the returned value is correct
   (proves calling convention survives the boundary).
5. **Given** a machine with only `nasm` and `ld` — the toolchain Vox
   already requires — **when** `./test.sh` runs, **then** the driver
   sub-test **executes and passes**. It must never report "skipped":
   the driver is assembly precisely so that no host-toolchain check can
   gate it, and a sub-test that skips silently would let CI go green
   with the boundary untested.
6. **Given** the full existing suite (`./test.sh`, `cargo test
   --release`, warning-free NASM check), **when** run after each phase,
   **then** all pass unchanged.

---

## Tasks

**Phase 0**
- [ ] Emit conditional coreasm includes in `shared_lib_mode` (exclude
      `args.asm`); keep `default rel`
- [ ] Write an anonymous version script and pass `--version-script` to the
      `-shared` `ld`, so none of coreasm's 54 `global` symbols reach
      `.dynsym`; clean the temp `.map` up with the `.o`
- [x] Inline `see` of a `.vox` file — done 2026-08-01, with
      `tests/208_source_include.vox`
- [ ] Analyzer: reject top-level executable statements under `--shared`
- [ ] Compile-fail test for the new diagnostic (`tests/compile_fail/`)
- [ ] LANGUAGE.md `--shared` section; register plan in `docs/plans/README.md`

**Phase 1**
- [ ] Rewrite the 34 `resource.asm` sites (`fd_table`, `buf_table`,
      `ra_*`) to `lea [rel]`+index; audit scratch registers around
      syscalls
- [ ] `.fini_array` entry for `_cleanup_all`, made idempotent
- [ ] Explicit per-library cleanup calls before `sys_exit` for a Vox host
- [ ] Error fetch-and-merge after each library call, so `on error` works
      across the boundary
- [ ] While rewriting those 34 sites, consider making the tables growable.
      `MAX_FDS` and `MAX_BUFFERS` are 64 and `alloc_table` is 256, fixed in
      `.bss`, and `_register_buffer` silently no-ops when full. Growing them
      means heap-allocating and loading a base pointer at each access - the
      *same* 34 sites this phase already touches, so doing it separately
      means editing them twice.
- [ ] `readelf -r` zero-abs-reloc check; full `test.sh` + NASM
      warning sweep

**Phase 2**
- [ ] `tests/shared/libmath.vox` (arith + print + buffer functions)
- [ ] `test.sh` shared section: build, **exact export-set** assert via
      `nm -D` (set equality, not `grep` presence), `readelf -d` assert,
      and an **assembly** driver under `tests/runtime/` (never C — it
      would add a toolchain the project avoids and would skip silently
      when absent)
- [ ] `-dynamic-linker`/`-rpath` on executable `ld` when `link_libs`
      non-empty
- [ ] Regression tests ROADMAP M0 asks for: list growth across realloc
      boundary (9 / 100 / 100 000 appends)

---

## Notes

- The Phase-1 rewrite deliberately supersedes the `abs` choice made in
  `4fb5694`: `lea [rel]`+index is the one form valid in both link
  models. After it lands, `[abs ...]` should not appear anywhere in
  `coreasm/` — worth a grep in the test harness or CI.
- Each `.so` carrying its own runtime is now the **decided design**, not a
  limitation: it is what lets the library be loaded by a C or Rust host and
  keep the exact runtime it was compiled against. The version script keeps
  that private runtime out of the dynamic namespace; mangling (Phase 3)
  makes it safe even for two versions inside one `.so`. The two are
  complementary — visibility controls what escapes the `.so`, mangling
  controls what collides *within* one.
- The version-script approach was chosen over adding `hidden` visibility
  qualifiers to coreasm's `global` declarations for the same reason the
  `%define` mangling was: it is zero coreasm edits, and coreasm gets
  ported three more times in M6. Prefer link-time solutions to source
  edits anywhere this trade-off recurs.
- The cost is that per-version counters fail *permissive*.
  `_check_call_depth`'s 10 000 limit and `_print_depth`'s 64-deep cycle
  budget apply per module, so recursion or a cyclic structure crossing the
  boundary can reach N × the limit. This is forced by the decision — a C
  host has no counter to share — so document the behaviour rather than
  hide it, and consider making the limits configurable.
- The assembly driver proves exactly one thing: the
  SysV boundary. It should be deleted, not extended, when Phase 3
  delivers a pure-Vox `see` caller.
