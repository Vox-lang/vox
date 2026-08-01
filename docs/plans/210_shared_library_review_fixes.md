# Plan 210 — shared-library review fixes

Findings from a full read of the Phases 0–2 implementation (plan 200,
commits `238f5df`..`a310237`, merged as PR #101). The feature works and its
suite is green; these are defects and gaps the suite does not catch.

Each finding below was reproduced before being written down. Reproduce it
yourself before fixing it, and confirm your fix turns that reproduction
around — a fix you cannot demonstrate is a fix you cannot trust.

---

## P1 — `--shared` destroys a user's pre-existing `.map` file

**Severity: data loss.** This is the only finding that damages something the
user owns.

`src/main.rs:428` writes the linker version script to `<base_name>.map`,
derived from the *source* filename, in the user's working directory. If a
file of that name already exists it is overwritten, and `:509` then deletes
it. Reproduced:

```
$ printf 'MY IMPORTANT LINKER SCRIPT\n' > victim.map
$ vox victim.vox --shared -o victim.so
$ ls victim.map
ls: cannot access 'victim.map': No such file or directory
```

A `.map` next to a source file is entirely plausible — linker scripts and
source maps both use that extension.

**Fix.** The version script is a pure implementation detail with no value to
the user, so it should never touch their directory. Write it to a uniquely
named temp file (`std::env::temp_dir()` plus the process id, or an existing
temp-file helper) and delete that. Keep the existing property that it is
removed on both the success and failure paths.

Note `.asm` and `.o` use the same `base_name` pattern, but those are the
compiler's own declared outputs and predate this work — leave them alone.

**Test.** A cargo test that creates `<name>.map`, compiles `<name>.vox
--shared`, and asserts the file still exists with its original contents.

---

## P2 — the shared test corpus never exercises `mangle_symbol`

`tests/shared/libmath.vox` exports `add_two`, `greet`, `makebuf` — all three
already valid C identifiers, so `mangle_symbol` is an identity function on
them. The `test.sh` export-set assertion is exact and good, but it cannot
catch a mangling regression, and mangling is what produces every export name.

The feature itself is fine — verified separately:

```
To "add two numbers" with a number called "n".
  Return n add 2.
```
```
$ nm -D --defined-only mangle_lib.so
00000000000003d5 T add_two_numbers
```

**Fix.** Rename at least one export in `tests/shared/libmath.vox` to a
natural multi-word Vox name so the label is *produced* by mangling rather
than coinciding with it — e.g. `To "add two"` exporting `add_two`. Update the
expected set in `test.sh` and the `extern` in the driver to match. Prefer
renaming an existing function to adding a fourth; the corpus should stay
small.

This also makes the corpus read like Vox. `To "makebuf"` is C-style naming in
an English-like language.

---

## P3 — the two new diagnostics have no source location

Every other compiler error carries file, line, column and a source excerpt.
The two `--shared` diagnostics do not, because both call `push_error(..., None)`
(`src/analyzer/mod.rs`). Side by side:

```
error: Top-level print statement is not allowed in a shared library: ...
```
```
error: Unknown variable: nosuchvar
  --> err.vox:1:16
   |
 1 | To "g". Return nosuchvar.
```

**Fix.** Pass the offending statement's span so both diagnostics point at the
line. If `Statement` does not currently carry a usable span for this, say so
in your report rather than inventing one — that would be a real finding about
the AST and worth its own work.

Keep the existing "stop at the first offender" behaviour; that is deliberate
and correctly avoids a cascade.

---

## P4 — `.fini_array` / `_cleanup_all` is registered but never exercised

Phase 1 registers `_cleanup_all` in `.fini_array` so a libc host cleans up on
unload. Nothing in the suite reaches it: `tests/runtime/shared_lib_driver.asm`
exits through a raw `sys_exit`, which never reaches `_dl_fini`, which is what
would run `.fini_array`. So the code is untested by construction, and the
suite would stay green if it were deleted.

**Do not fix by adding a C host** — the project deliberately depends only on
`nasm`, `ld` and `cargo`, and a `command -v cc` guard would skip silently.

**Fix.** Record the gap honestly rather than paper over it: a short note in
plan 200's status section stating that the `.fini_array` path is unverified,
what would verify it (a libc host, checked manually and recorded), and why
the suite cannot. Plan 200 already carries an unticked success criterion for
the C/Rust host — make these two consistent so a reader is not left thinking
one covers the other.

---

## P5 — a driver failure cannot be diagnosed

All three assertions in `shared_lib_driver.asm` jump to a single `.fail` that
exits 1. When CI reports `shared/libmath (driver exited 1)`, nothing indicates
whether arithmetic, the buffer, or the boundary itself broke.

**Fix.** Give each assertion a distinct non-zero exit code (e.g. 2 = add_two,
3 = makebuf) and have `test.sh` map the code back to a named check in its
failure message. Keep it terse — this is coreasm-adjacent test code and gets
read more than it gets run.

---

## P6 — the dynamic loader path is hard-coded for x86-64

`src/main.rs` emits `-dynamic-linker /lib64/ld-linux-x86-64.so.2`
unconditionally, while codegen already carries `self.target_arch` and M6 adds
three more architectures.

**Fix.** This does not need solving now and should not be over-built. Add a
comment at the site naming it as an x86-64 assumption that M6 must revisit, so
the next person porting finds it by reading rather than by debugging. If a
target-arch value is already threaded to that point, deriving the path from it
is fine; do not plumb one through just for this.

---

## P7 — the `.map` path is computed in two places

`src/main.rs:428` builds `map_path`, and `:509` independently recomputes
`format!("{}.map", base_name)` to delete it. Change one and the other leaks a
file. P1's fix should collapse this to a single value; if it does not, hoist
it so the path exists once.

---

## Out of scope

Do not start plan 200 Phase 3, do not touch the `LANGUAGE.md` `see "./lib.so"`
contradiction (it resolves in Phase 3), and do not begin growable resource
tables. Those are all separately tracked.

## Success criteria

- [ ] P1 reproduction fails to reproduce; a cargo test guards it
- [ ] At least one export in the shared corpus is produced by mangling
- [ ] Both `--shared` diagnostics carry file/line/column, or the report
      explains precisely why they cannot
- [ ] Plan 200's `.fini_array` and C/Rust-host gaps read consistently
- [ ] Driver failures name the failing check
- [ ] `cargo build --release` 0 warnings; `cargo test --release` ≥ 115;
      `./test.sh` ≥ 196 passed, 0 failed, **skips still 6**
- [ ] On a built `.so`: `readelf -r` 0 absolute relocations, `nm -D` exactly
      the corpus exports
