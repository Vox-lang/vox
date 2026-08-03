# Plan 260 — bug hunt on the 0.2.0 shared-library surface

A pre-release bug hunt (branch `p230-bughunt`, commit `1f34331`) whose job was
to make the green suite not green. The suite proves the feature works when used
correctly; this aimed at the gaps it cannot reach — malformed input, hostile
input, the second build, the docs-vs-reality drift. The best finding is the one
the suite could not see.

Reproduce each entry yourself before acting on it. Every reproduction below was
run against the shipped binary in a temp directory (never in the repo). Severity
tags: **crash / wrong output / bad diagnostic / cosmetic**.

The three findings marked **fixed** are small, unambiguous, and touched only
diagnostics or the test harness — never parser structure, codegen, or the ABI.
A regression test was added for each compiler fix; the baseline
(`cargo build` 0 warnings, `cargo test` 149, `./test.sh` 208 / 0 / 6 exactly)
holds after them. The five findings marked **reported** are left for the
release decision — they touch parser/codegen/ABI territory or are the known
design boundary, and a clever fix hours from a release is a worse risk than a
known bug.

---

## F1. Mangling collision across libraries/versions falls through to a raw NASM error  — bad diagnostic  (reported)

The library mangling `mangle_library_symbol(lib, version, func)` applies the
per-character `sanitize_symbol` to each component (every char outside
`[A-Za-z0-9_]` → `_`), so two **different** library names can fold to the same
symbol. The duplicate-identity check in `main.rs` compares the **raw** strings
(`a-b` ≠ `a_b`), and the analyzer's `mangled_functions` collision check
(`analyzer/mod.rs` ~2206) stores the **function name** keyed by the mangled
label — so it only flags two *different function names* that collide
(intra-library: `b.c` vs `b_c`). When the **same** function name appears under
two library/version strings that sanitise identically, the keys collide but
`prev == name`, so it is not flagged. The build falls through to NASM.

This is the theoretical hole plan 230's mangling section asked about. **It is
reachable.**

**Reproduction (library names collide):**
```bash
cd "$(mktemp -d)"
cat > dash.vox <<'EOF'
Library "a-b" version "1.0".

To "greet" with a number called "n".
  Return a number, n add 1.
EOF
cat > under.vox <<'EOF'
Library "a_b" version "1.0".

To "greet" with a number called "n".
  Return a number, n add 2.
EOF
vox dash.vox under.vox --shared -o lib.so
# dash.asm:36: error: label `a_b_1_0_greet' inconsistently redefined
# dash.asm:18: info: label `a_b_1_0_greet' originally defined here
# NASM assembly failed
```

**Reproduction (versions collide — same library name, `1.0` vs `1_0`):**
```bash
cd "$(mktemp -d)"
cat > v1.vox <<'EOF'
Library "x" version "1.0".
To "f" with a number called "n". Return a number, n add 1.
EOF
cat > v2.vox <<'EOF'
Library "x" version "1_0".
To "f" with a number called "n". Return a number, n add 2.
EOF
vox v1.vox v2.vox --shared -o lib.so
# v1.asm:36: error: label `x_1_0_f' inconsistently redefined
```

**Expected:** a vox diagnostic naming the two libraries/versions and the
colliding symbol, pointing the author at the sanitisation clash — the same
shape as the intra-library check that already exists.

**What happened:** a raw NASM assembler diagnostic that names an internal
`dash.asm` temp file the user never wrote, with no hint that the cause is a
name-collision-after-sanitisation. **Severity: bad diagnostic.** Not silent
wrong code — NASM catches the duplicate label and fails the build — but the
failure is inscrutable and leaks an internal filename.

The intra-library case (`b.c` and `b_c` in one `Library`) is already caught
with a clean diagnostic ("Functions 'b.c' and 'b_c' both become the assembly
symbol '...'; rename one so they stay distinct."), so the analyzer already
holds the pieces; the cross-library branch is the gap.

**Not fixed** — touches the analyzer's collision check / codegen keying. Report
only.

---

## F2. A failed build leaks the `<stem>.asm` file into the working directory  — cosmetic  (reported)

`main.rs` writes `<base_name>.asm` (the assembly it is about to assemble) to
the cwd before invoking nasm. On nasm failure it does `eprintln!("NASM
assembly failed"); exit(1)` with no `remove_file(&asm_path)`; the asm-file
cleanup lives after the successful link. So any nasm failure leaves
`<stem>.asm` behind in the user's directory — a temp artifact they never asked
to see. This is the same hazard class as plan 210 P1/P7 (the `.map` file),
which was fixed by moving the map to a temp path; the `.asm` path is the
unfixed sibling. The `.map` cleanup was also deliberately moved *before* the
success check so a failed link would not leave it behind; the `.asm` cleanup
was not given the same treatment.

**Reproduction:** any nasm failure, e.g. the F1 collision above:
```bash
cd "$(mktemp -d)"
# ...dash.vox, under.vox as in F1...
vox dash.vox under.vox --shared -o lib.so   # fails at nasm
ls dash.asm   # exists — left behind
```
The ld-failure exit path has the same shape (it exits without removing the asm
if `keep_asm` is false; the asm removal at line ~894 only runs on the success
path).

**Expected:** no stray `dash.asm` after a failed build. **What happened:**
`dash.asm` remains. **Severity: cosmetic.**

**Not fixed** — the cleanup belongs on every exit path (nasm-fail, ld-fail, and
the two `exit(1)` branches between them), and threading that needs care not to
delete a file the user asked to `--keep-asm`. Report only.

---

## F3. The elf "checking the library binary" error renders the `.so` path as `././...`  — cosmetic  (fixed)

The missing-`.so` diagnostic and the stale-symbol diagnostic both pass the
`.so` path through `normalise_display`, which strips the no-op `.` components
`Path::join` layers on. The elf-read error path does not — it hands `so_path`
straight to `elf::defined_dynamic_symbols`, which formats `path.display()`
itself — so the same file reads as `bad.so` in one error and `././bad.so` in
another. The test suite (`run_see_diagnostics_test`) explicitly asserts the
missing-`.so` error does **not** contain `././`, but only because it checks
that one path; the elf path was never normalised.

**Reproduction:**
```bash
cd "$(mktemp -d)"
cat > good.lib <<'EOF'
Library "x" version "1.0".
Location "./bad.so".

Table of Contents:
    To "f".
EOF
echo "not elf" > bad.so
cat > prog.vox <<'EOF'
see "x" version "1.0" from "./good.lib".
A number called "r" is "f" of 1.
Print the r.
EOF
vox prog.vox -o prog
# Error: checking the library binary: '././bad.so': not an ELF file (bad magic)
#                                  ^^^^ double ././ — the missing-so error shows 'bad.so'
```

**Expected:** `'bad.so'` (matching the missing-`.so` diagnostic).
**What happened:** `'././bad.so'`. **Severity: cosmetic.**

**Fixed** in `lib_file.rs`: the elf reader is now passed
`normalise_display(&so_path)`, which strips only `.` components (a no-op for
`fs::read`, so the same file is still read). Regression test:
`lib_file::tests::elf_error_path_is_normalised_no_double_dot_slash`.

---

## F4. A canonical-form `see` with a non-`.lib` path silently compiles  — bad diagnostic  (fixed)

The parser rejects a `.so` path (`see "x" version "1.0" from "./x.so".` → "see
of a .so is not supported"), `process_includes` inlines `.vox` paths, and
`resolve_program_imports` handles paths ending in `.lib`. Anything else falls
through **all** of them: the `.lib` filter (`path.ends_with(".lib")`) skips it
via `_ => continue`, so the import is silently dropped. A program that `see`s
a library through a typo'd or extensionless path compiles and runs with the
import missing — exactly the silent-compile trap stage A5 closed for the
direct-`.so` form, but the catch-all was not actually a catch-all.

The realistic typo is a missing/extra extension:

**Reproductions (all used to compile silently, exit 0):**
```bash
cd "$(mktemp -d)"
echo hello > notalib

# (a) extensionless path
cat > prog.vox <<'EOF'
see "mathkit" version "1.0" from "./notalib".
Print "compiled".
EOF
vox prog.vox -o prog && ./prog            # -> compiled  (import dropped, no error)

# (b) a .lib with an extra suffix (e.g. editor backup)
cat > prog.vox <<'EOF'
see "mathkit" version "1.0" from "./libmathkit.lib.txt".
Print "compiled".
EOF
vox prog.vox -o prog && ./prog            # -> compiled  (import dropped, no error)

# (c) canonical shape but the `from` path forgotten entirely
cat > prog.vox <<'EOF'
see "mathkit" version "1.0".
Print "compiled".
EOF
vox prog.vox -o prog && ./prog            # -> compiled  (import dropped, no error)
```

**Expected:** an error naming the path and the canonical form — the user wrote
the library-import shape (name + version), so a non-`.lib` path is unambiguously
a malformed import.
**What happened:** silent compile, exit 0, the library simply absent.
**Severity: bad diagnostic.** (If the program then *calls* an imported function
it gets "Unknown function", which is at least non-silent; the silent case is a
`see` that is never followed by a call, e.g. an import left in place after its
calls were removed.)

**Fixed** in `lib_file.rs` `resolve_program_imports`: a `see` carrying a
library name **and** version (the canonical shape) whose path does not end in
`.lib` now errors with the canonical form. A `.so` is still rejected at parse
time and a `.vox` is still inlined, so a `see` reaching this point with
name+version and a non-`.lib` path is unambiguously malformed. A bare
`see "<path>"` with no name/version and a non-`.lib` path is still skipped
(that path is ambiguous between a failed include and a non-import; see F5).
Regression tests: `canonical_see_with_non_lib_path_is_an_error`,
`bare_see_with_non_lib_path_is_skipped_not_errored`.

---

## F5. `test.sh` exports the deprecated `EC_CORE_PATH`, failing its own name-res test  — bad diagnostic  (fixed, pre-existing)

`test.sh` (line ~73) exports `EC_CORE_PATH="$SCRIPT_DIR/coreasm"` to point the
compiler at the in-repo coreasm. The compiler now reads `VOX_CORE_PATH` as the
documented name and treats `EC_CORE_PATH` as a deprecated fallback that prints
`note: EC_CORE_PATH is deprecated; set VOX_CORE_PATH instead` on **every** run.
The `run_see_name_resolution_test` "only-one" subcase captures the build's
combined output and asserts it is empty (the program should resolve without
warning) — so the deprecation note, printed by the very `vox` invocation the
test drives, makes it fail with "only-one emitted unexpected output: 'note:
EC_CORE_PATH is deprecated...'". The failure is deterministic; the `test.sh`
comment ("The compiler reads EC_CORE_PATH (not VOX_CORE_PATH)") is stale from
before the rename.

This is the same class as the install-guide-named-a-dead-binary finding from
plan 250: the harness and the compiler disagreed about an env-var name, and
nothing checked the harness against reality. The stated pre-hunt baseline
(208 / 0 / 6) did not hold on the shipped code — it was 207 / 1 / 6 — for this
reason.

**Reproduction:** `./test.sh` on the unpatched tree:
```
FAIL name-res (only-one emitted unexpected output: 'note: EC_CORE_PATH is deprecated...')
Passed:  207   Failed: 1   Skipped: 6
```

**Expected:** `./test.sh` → 208 / 0 / 6 exactly. **What happened:** 207 / 1 / 6.
**Severity: bad diagnostic** (a stray env var the harness itself sets breaks a
release-gating test).

**Fixed** in `test.sh`: export `VOX_CORE_PATH` (the documented name) instead.
No deprecation note is printed, the name-res "only-one" subcase sees empty
output, and the test passes. No test is weakened — the assertion (no warnings)
is unchanged; the root cause (the harness using the deprecated var) is removed.
After the fix: `./test.sh` → 208 / 0 / 6 exactly.

---

## Areas probed and found genuinely solid

These were attacked hard and produced clean diagnostics or correct output
every time. "I tried X and every one produced a clean result" is a real result
and these are it.

**The `.lib` parser** (`lib_file::parse_lib_text`), fed: an empty file; a
truncated mid-line file; a `Library` line with no `Location`; two `Location`
lines; a table of contents with no entries; a signature with an unknown return
type (`widget`); duplicate ToC entries; duplicate `<lib,version>` blocks in
one file; a binary file (a `.so`) renamed `.lib`; a UTF-8 BOM; CRLF line
endings; non-ASCII-shaped junk. Every one produced a clean, located parse error
("line N: ...") or a clean resolution error ("has no library named ...").
Empty/bad-but-parseable inputs never panicked. The one-entry-per-line / no-wrap
rule and the executable-statement structural rejection both fire as designed.

**The `.dynsym` reader** (`elf::defined_dynamic_symbols`), fed via a valid
`.lib` whose `Location` pointed at: a text file; an empty file; `/dev/null`; a
truncated ELF (header only); a 32-bit ELF header; a relocatable `.o` (not a
shared library); a directory; the `.lib` itself; `/etc/passwd` via an escaping
`Location`; a symlink loop. Every one produced a named error ("not an ELF64
file (N bytes...)", "bad magic", "not a 64-bit object", "has no section
headers", "has no .dynsym section (is this a shared library?)", "Is a
directory"). The field-offset readers are bounds-checked before every `.unwrap()`
(both the section-header and symbol-table reads guard `base + size ≤ len` with
`checked_add`); no panic path was found in the reader.

**`see` resolution.** Two `see` lines importing the same `<lib,version>` are
deduplicated (first wins). A `.lib` whose `Location` points at itself, an
escaping `Location`, a `Location` that is a directory, and a `.lib` that is a
symlink loop all produce clean errors. Version strings with spaces/dots are
accepted (they sanitise through the mangler like any component).

**Multi-input `--shared`.** The same file passed twice → "Duplicate library
identity" (clean). Twenty distinct files → builds, exactly 20 exports. A
nonexistent file alongside real ones → clean read error naming the missing
file. A mix of `.vox` and `.lib` as inputs → parse error naming the `.lib` and
line. A single input with two `Library` declarations → works, two distinct
mangled blocks in one `.so` (a feature, not a bug).

**Resource limits.** `MAX_FDS` and `MAX_BUFFERS` are 64; `_register_fd` /
`_register_buffer` silently no-op on the 65th (the table is full), exactly as
documented — the 65th buffer is still allocated and usable, the 65th file is
still opened and readable; both simply leak from tracking (the process reclaims
them on exit). `READAHEAD_SLOTS` is 8, not 64, and is the more likely limit to
hit — but `_read_line_into_buffer` falls back to byte-at-a-time reads when no
slot is free (`cmp rax, -1; je .line_loop_fallback`), so reading from 9
simultaneously-open files (each holding a read-ahead slot) still returns the
correct data, just slower. No crash, no wrong output, no OOB at either limit.

**Known, confirmed, not a new finding.** The `.lib` ToC drops the `returning`
clause for a function whose body is more than a single `Return` statement (the
`makebuf` case the `run_shared_library_test` comment already names as "a known
A3 gap"). A consumer who then uses that function's return value is told it
returns nothing — a wrong diagnostic, but documented and on the known list, so
not reported here. The ToC-count test (`run_lib_toc_count_test`) covers the
bodyless-function-drops-the-next-entry class and passes.