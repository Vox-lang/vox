# Plan 240 — claim audit (LANGUAGE.md, README.md, docs/INSTALL.md)

Two stages of the same method — run every code sample and shell command in
the target document against `target/release/vox` (v0.1.23) and record whether
it does what the surrounding prose says.

- **Stage B4** audited `LANGUAGE.md` (the language reference).
- **Stage B5** audited `README.md` and `docs/INSTALL.md` — the two documents a
  new user meets first.

## Stage B4 — LANGUAGE.md

Audited every Vox code sample and shell command in `LANGUAGE.md`. The shared-library section written in Stage B2
("Libraries and Imports", lines ~2789–3116) was skipped on instruction — its
`see`-of-a-`.lib` parts are unbuilt by design and its runnable parts were
verified in B2. Everything else in the file is covered.

Experiments ran in `/tmp/vox-b4`, not the repo, so no stray `.asm` or binaries
were left in the tree.

## Coverage

- **Samples / commands run:** approximately 75 distinct programs and shell
  commands (144 scratch `.vox` files, many isolating the same claim from
  different angles).
- **Passed (compile + run, output matches prose):** the large majority — every
  sample in Basics, Sentence Consumption, Ranges, Loop Expansion, `but if`,
  Functions, Literals, the full Type-Casting table, Radix conversions, Control
  Flow, most of Lists/Maps, Dynamic Values, Nothing, Format Strings (variable
  form), Escape Sequences, File I/O (buffers, byte access, resize, open, read,
  write, seek, close, `is available`, delete), Directories, Symlinks, Execute,
  fork, Time, Timers (duration/elapsed/running), Command-Line Arguments, Flag
  Parsing, Environment Variables, Bitwise Operators, the Examples block, and
  all four Compiler Usage shell commands.
- **Fragments (not executable, by design):** syntax skeletons with `<placeholders>`
  (function-definition template, `if <condition> then, …`, `while <condition>, …`,
  loop-expansion skeletons, `treating`/`open … at each …` fragments that depend
  on external state), the `Break.` / `Continue.` standalone lines, and the
  destructive-syscall blocks (Mount, mknod, pivot_root, Shutdown/Reboot/Halt)
  which were compile-verified with `--emit-asm` but not executed.
- **Untrue claims found:** 16 distinct findings below (some cover several
  line-locations each).

## Classification counts

- **doc wrong, compiler right** — 13 findings (fixed in this commit, noted below).
- **compiler wrong, doc right** — 4 findings (resolved by plan 250, commit
  `e137a63`; outcomes recorded per-finding below).
- **unclear** — 0.

---

## Findings — doc wrong, compiler right (fixed)

Each was fixed in `LANGUAGE.md` in this same commit.

### F-VAR-1 — line 270: `a boolean called "flag" is true.`
`flag` is a reserved keyword (`src/lexer/mod.rs:123`, used by declarative flag
parsing). Rejected: `Cannot use 'flag' as a variable name - it's a reserved
keyword.` **Fix:** renamed to `done`.

### F-VAR-2 — line 279: `Create a text called message to "Hello".`
`message` is a reserved keyword — a synonym for the `text` type
(`src/lexer/mod.rs:151`: `"text" | "string" | "message" => Some("text")`).
Rejected: `Cannot use 'message' as a variable name`. **Fix:** renamed to
`greeting`. (Side note, not a doc claim: when the reserved name is unquoted the
error misreports the keyword as `'text'` regardless of which synonym was used —
a cosmetic compiler bug in the error message.)

### F-CAST-1 — lines 585, 589–590: casting-examples block
Uses reserved keywords as variable names: `input` (line 585, `src/lexer/mod.rs:167`)
and `flag` (line 589). Block fails to compile. **Fix:** `input` → `userinput`,
`flag` → `done` (and `flag num` → `done num`, `the flag` → `the done`).

### F-CAST-2 — line 582 (minor): `a text called "age text" is the age as text.`
Declares OK, but the name contains the `text` type keyword, so it cannot be
referenced (`Print the age text.` → `Expected a statement, got Text`). The doc
never references it, so not a hard failure, but a reader who tries will be
confused. **Fix:** renamed to `agestr`.

### F-IN-1 — lines 596–608, 632: the `in` keyword
Documented as a general unit-conversion alternative to `as`:
`a number called "secs" is the ms in seconds.` (line 603). This does NOT compile:
`Expected a statement, got In`. `in <unit>` is only a timer `duration`/`elapsed`
cast (`t's duration in seconds`), codified by `tests/compile_fail/038_duration_cast_on_non_timer.vox`
(duration cast on a non-timer is an error). The timer form (lines 606–607)
works; the plain-number form does not. Line 632 ("`in` keyword is preferred for
unit/time conversions") reinforced the false claim. **Fix:** rewrote the section
to describe `in` as a timer duration/elapsed cast only, with the plain-number
alternative `the millis divide 1000`; fixed line 632. (Also line 602 `ms` is
reserved → removed.)

### F-PAD-1 — lines 612–619, 2359–2365: `as text padded to N`
This syntax does not exist anywhere in the compiler (no `padded` token in the
lexer; no handling in parser/analyzer/codegen). Fails: `Missing function name
after 'To'` (the `to` after `padded` is misparsed). Doc claims it prints `"09"`.
The real way to zero-pad is a format string. **Fix:** replaced
`the hour as text padded to 2` with `"{h:02}"` (format-string-as-value,
verified → `09`), and the time-formatting block (lines 2363–2365) with
`"{now's hour:02}"` etc. (verified → `15:19:29`).

### F-IF-1 — line 854: `if item is a list, print "L", otherwise print "s".`
The comma-then-bare-`otherwise` form is not supported: `Expected a statement,
got Otherwise`. The doc's own Control Flow section (line 646) specifies the
period-separated form `If <cond> then, <stmt>. Otherwise, <stmt>.`, which the
compiler accepts. Verified working: `if item is a list then, print "L". otherwise print "s".` → `s, L, s`. (Note: the `otherwise if` chain at line 960
*does* work in comma form — the parser accepts `otherwise if` but not bare
`otherwise` after a comma.) **Fix:** line 854 to the period-separated form.

### F-LISTPROP-1 — line 1200 (minor): `print items's empty. (prints false)`
Actually prints `0`. Booleans print as `1`/`0` (the doc's own rule, line 794).
**Fix:** parenthetical → `(prints 0)`.

### F-LIST-DECL — line 1752: `a list of strings called "names" contains "Alice", "Bob", "Charlie".`
This declaration syntax does not exist. Fails: `Cannot use 'of' as a variable
name`. **Fix:** replaced with the standard list-literal form
`a list called "names" is ["Alice", "Bob", "Charlie"].` (verified).

### F-LIST-SECOND — line 1779: `Print numbers's second. (prints 20)`
`second` is not a list property; it is the time `seconds` property. Fails:
`Property 'second' requires a time value (number)`. The list-properties table
(lines 1744–1748) correctly lists only length/size/empty/first/last. (Note:
`arguments's second` *is* a real arguments property and works — line 2388 is
correct.) **Fix:** removed the `second` line.

### F-HEX-1 — line 1709: `Print "First byte: 0x{b1:02X}".`
Double-prefixes: the `:X` specifier already emits the `0x` prefix (per the doc's
own table, line 1448 `{255:X}` → `0xFF`), so the literal `0x` is redundant.
Actual output: `First byte: 0x0xDE`. **Fix:** dropped the literal `0x` →
`Print "First byte: {b1:02X}".` (verified → `0xDE`).

### F-FMT-1 — lines 1447–1451: format-specifier table
The last five rows use bare numeric literals inside `{}`: `{255:x}`, `{255:X}`,
`{5:b}`, `{8:o}`, `{255:04x}`. These fail: `Unknown variable: 255` — `{}`
interpolates variables/expressions, not bare literals (the doc's own line 1431
says "Embed variables and expressions"). The first four rows use variables and
work. All specifiers produce the claimed output when given a variable. **Fix:**
changed the literal examples to a variable `n` and added a note that the value
must be a variable/expression, not a bare literal.

### Reserved-word-as-name (consolidated) — fixed
The doc repeatedly used reserved keywords as variable names. Each fails with
`Cannot use '<word>' as a variable name - it's a reserved keyword.` All renamed:
- line 716 `numbers` → `nums` (and line 717 `in numbers` → `in nums`)
- line 766 `numbers` → `nums`
- line 769 `empty` → `emptylist`
- line 889 `empty` → `emptymap`
- line 1216 `numbers` → `nums` (and lines 1218–1222, 1225 references)
- line 1243 `numbers` → `nums` (and lines 1244–1246 references)
- line 1560 `input` → `inputbuf`
- line 1766 `numbers` → `nums` (and lines 1768–1772 references)
- line 2011 `input` → `inputbuf`

### Grammar Summary — line 3202 (minor): `type ::= "number" | "text" | "boolean" | "list"`
Lists only 4 types; the Types table (lines 246–257) documents 10. **Fix:**
added `float`, `map`, `buffer`, `file`, `time`, `timer`, `value`.

### F-COMMENT-1 — lines 2007–2009, 2017–2018, 2040: `#` comments in Vox code
The Resource Safety section uses `#` comments (C/Python style) inside Vox code
blocks. Vox comments are `(...)`, not `#`; the blocks fail to compile
(`Expected a statement, got As` at the `#`). The rest of the document uses
`(...)` comments consistently. **Fix:** converted the six `#` comment lines to
`(...)` (and renamed the `input` buffer to `inputbuf` there — it was reserved
too).

---

## Findings — compiler wrong, doc right (resolved by plan 250)

Filed from the B4 audit for the code track. Three were genuine compiler defects
fixed by plan 250 (commit `e137a63`); the fourth (F-FORK-1) was not a real
defect and is recorded as such below. The samples were not modified — changing
them would have papered over a real defect, and once the compiler was fixed
they were correct as written. Each entry carries its outcome so the next reader
does not re-investigate settled ground.

### F-APP-1 — lines 1259, 1282: `append` rejects arithmetic expressions
`append` does not accept an arithmetic expression as the value, despite line
1259 listing "expressions" as supported. `append i multiply i to squares`
(line 1282) fails: `Expected 'to' after value in append statement`. The braced
form `append {i multiply i} to s` also fails: `Expected value to append`. Only
simple values (literals, variables) are accepted (`append i to s` works). The
documented behaviour (append an expression) is sensible; the compiler doesn't
do it. **Repro:**
```
a list called "s" is [].
a number called "i" is 2.
append i multiply i to s.
```

**Resolved (plan 250 D2, commit `e137a63`):** `append` now parses its value with
full arithmetic, including braced expressions — `append i multiply i to
squares` and `append {i multiply i} to s` both compile and run as documented.
Verified on this branch: the loop sample (line 1282) → `1 4 9 16 25`; the braced
form → `4`. Covered by `tests/047`. Sample unchanged.

### F-APP-2 — lines 1303, 1341: `append each x from <list> to <dest>`
Fails when the source is a list variable: `Expected 'to' after collection in
append` — the parser reads `from source to dest` as a *range* (`source to
dest`), consuming the `to <dest>` as the range end. The range-source form
`append each n from 1 to 5 to rl` (line 1336) works (→ `[1,2,3,4,5]`). So the
list-source append-each is broken by range ambiguity. **Repro:**
```
a list called "source" is [10, 20, 30].
a list called "dest" is [].
append each x from source to dest.
```

**Resolved (plan 250 D1, commit `e137a63`):** the list-source append-each no
longer has its destination eaten by range parsing. Verified on this branch:
list source `[1, 2, 3]` → `[1, 2, 3]` and `[10, 20, 30]` → `[10, 20, 30]`, while
the range form `1 to 5` still → `[1, 2, 3, 4, 5]`. Covered by `tests/046`.
Sample unchanged.

### F-FORK-1 — line 2173: `Set reaped to reap any child process.`
Fails when `reaped` is not already declared: `Unknown identifier 'reaped'` (did
you mean `read`?). `Set <newvar> to <expr>` *does* create new variables in
general — `Set newvar to 5.` and `Set pid to fork the process.` both work
without prior declaration (verified). So the compiler accepts `fork` but not
`reap` as the RHS of a Set-declaration. Pre-declaring (`a number called "reaped" is 0.` then `Set reaped to reap any child process.`) works. The doc's example
assumes Set creates the variable, which is correct for every other expression.
**Repro:** `Set reaped to reap any child process.` (alone).

**Resolved (plan 250 D4, commit `e137a63`): not a real defect.** Does not
reproduce — `Set reaped to reap any child process.` auto-declares at top level
exactly like every other RHS expression (the existing `tests/102_fork_reap`
already exercised the comma form). The "Unknown identifier 'reaped'" the audit
saw came from a different shape: a statement following the `Set` inside an
if-block separated by a *period*, which terminates the block and leaves the
next statement at top-level scope where the variable was never declared —
`Set reaped to 5.` fails identically, so it is not reap-specific. The fix is the
comma the block syntax requires, not a compiler change. Filed from the audit
without independent verification. Regression test `tests/211_set_reap_undeclared`
now guards the top-level auto-declare. Sample unchanged.

### F-TIMER-1 — lines 2316–2317, 2352, 2354: timer `start time` / `end time`
These properties do not parse: `Expected a statement, got Time` — `time` is a
reserved keyword (`src/lexer/mod.rs:220`) and is tokenized before the
multi-word property handler can match. The complete timer example (lines
2332–2355) therefore fails at `Print the "job timer"'s start time.` The source
*intends* to support them (`src/parser/mod.rs:5113`, `5156–5173`, `5700`
explicitly handle `"start time"`/`"end time"`), so the doc matches intent; a
tokenization bug breaks it. Workaround that works: `start`/`end` alone
(`Print t's start.` / `Print t's end.` → unix timestamp). `duration`,
`elapsed`, `running` all work. **Repro:**
```
a timer called "t".
Start t.
Stop t.
Print t's start time.
```

**Resolved (plan 250 D3, commit `e137a63`):** `start time` / `end time` now
parse through the reserved `time` keyword (the four property-access sites —
bare name, quoted name, and both `the ...` forms — now consume a `Time` token
directly after matching `start`/`end`; no lexer change). Verified on this
branch: the complete timer example (lines 2338–2361) runs and prints unix
timestamps for both `start time` and `end time`. Covered by `tests/153`.
Sample unchanged.

---

## Notes

- The destructive-syscall blocks (Mount/Unmount, `Create a device node`,
  `Pivot root`, `Shutdown`/`Reboot`/`Halt`) all compile cleanly (`--emit-asm`,
  rc=0) but were not executed, to avoid altering system state. Their runtime
  semantics (lowers to `mount(2)`, `mknod(2)`, `pivot_root(2)`, `reboot(2)`) are
  taken on trust plus the source. Directories, symlinks, `Execute`, and `fork`
  were run and behave as documented.
- `arguments's second` (line 2388) is correct and works — it is distinct from
  the non-existent list `second` property (F-LIST-SECOND).
- Every "compile error" claim in the Nothing and Dynamic Values sections
  (lines 1061, 1139) was verified: the compiler emits exactly the error text
  the doc shows.

---

## Stage B5 — README.md and docs/INSTALL.md

Same method applied to the two documents a new user meets first. README.md
holds 8 fenced blocks (16 fence markers); docs/INSTALL.md holds 9 (18 markers).
Every block was run or inspected. Experiments ran in `/tmp/vox-b5`; the repo
was not mutated outside `.md`/`docs/`.

### Inherited fix — LANGUAGE.md Mangling section

The B2 Mangling section said each component is sanitized and "a leading digit
is prefixed." Applied per component, the version `1.0` → `_1_0` (the sanitizer
yields `1_0`, which starts with a digit, so the prefix fires), and the join
gives `mathkit__1_0_add_two_numbers` — a double underscore, contradicting the
example `mathkit_1_0_add_two_numbers` on the same line. Inherited from plan 230,
which stated the rule wrongly; the code track hit the same contradiction
implementing Stage A1.

**Actual rule** (`src/codegen/mod.rs:124-137`, `mangle_symbol`, plus unit tests
at `:7151-7164`): one sanitizer maps every character outside `[A-Za-z0-9_]` to
`_`; the leading-digit prefix applies **only to the library component**, which
begins the symbol. Version and function components are interior and take the
sanitizer alone, so `1.0` → `1_0` (the `.` becomes a single `_`, no prefix).
**Fixed** the wording in `LANGUAGE.md` to state this, and to call out the
double-underscore trap explicitly.

**Could not verify the composed symbol empirically.** The steer asked for
`nm -D --defined-only` on a `probe`/`0.1` library to show `probe_0_1_inner`.
On this branch the `<lib>_<version>_<name>` composition is **not yet live**:
function labels are `mangle_symbol(name)` only (`src/codegen/mod.rs:2713`), and
`Statement::LibraryDecl` just emits a comment (`:4158`). Building
`Library "probe" version "0.1"` + `To "inner"` with `--shared` exports the bare
symbol `inner`, not `probe_0_1_inner` — consistent with `LANGUAGE.md` line 2900
("The mangled form … arrives with Stage A1"). So the `nm` check the steer
named cannot pass on this branch yet. The rule itself was verified from the
`mangle_symbol` implementation and unit tests, and by composing per the stated
rule. Reporting this rather than fabricating the verification.

### README.md — coverage

| # | Lines | Block | Result |
|---|-------|-------|--------|
| 1 | 125–140 | `text` — the `cat` example | **RUN_OK** — compiles and runs; `printf 'line one\nline two\n' \| vox cat.vox --run` prints `line one`/`line two`, rc=0 |
| 2 | 144–146 | `open ... at each X from Y` | fragment — illustrative snippet of the construct already exercised in block 1 |
| 3 | 156–164 | architecture diagram | illustration, not executable |
| 4 | 179–181 | `sudo apt install nasm rust make` | not executed (system mutation); inspected — **doc wrong**: Debian/Ubuntu has no `rust` package (it ships `cargo`/`rustc`); `apt install rust` fails. **Fixed** → `nasm cargo make` |
| 5 | 185–187 | `sudo yum install nasm rust make` | not executed; inspected — OK: `rust` is a real Fedora package (verified installed: `rust-1.97.1-1.fc44`), provides `cargo`. Left as-is |
| 6 | 193–195 | `cargo build --release` | **RUN_OK** — 0 warnings |
| 7 | 201–208 | `make build` / `sudo make install` / `sudo make uninstall` | not executed (mutates `/usr/local`); inspected — Makefile targets `build`/`install`/`uninstall` all exist; `install` puts the binary at `/usr/local/bin/vox` and coreasm at `/usr/local/share/vox/coreasm` (correct names). The `.7z` aside references a release artifact not in the repo (harmless advice) |
| 8 | 214–220 | `vox example.vox --run` / `vox example.vox` | **RUN_OK** — `--run` works; bare `vox ex.vox` produces executable `ex` (default output = source basename); `--help` lists `--run`/`--shared`/`--link`/`--lib-path`/`-o`/`--emit-asm`; `--version` → `vox v0.1.23` |

### docs/INSTALL.md — coverage

| # | Lines | Block | Result |
|---|-------|-------|--------|
| 1 | 12–15 | `sudo apt update` / `apt install -y nasm binutils` | not executed; inspected — **doc wrong**: Prerequisites list (lines 7–8) omitted Rust entirely, and the apt line omitted `cargo`, so `cargo build --release` (step 1) would fail for a user following the doc. **Fixed** — added `cargo` to Prerequisites and to the apt line |
| 2 | 23–25 | `cargo build --release` | **RUN_OK** |
| 3 | 29–31 | `sudo install -m 0755 target/release/ec /usr/local/bin/ec` | not executed; inspected — **doc wrong**: the binary is `target/release/vox` (Cargo.toml `name = "vox"`; Makefile `BIN := vox`); there is no `target/release/ec`. **Fixed** → `vox` |
| 4 | 39–43 | `sudo mkdir/rm/cp coreasm to /usr/local/share/ec/coreasm` | not executed; inspected — **doc wrong**: the compiler reads coreasm from `/usr/local/share/vox/coreasm` (`src/main.rs:51`), not `.../ec/...`. `coreasm/` exists in the repo with per-arch `.asm` (x86_64/aarch64/Win64). **Fixed** → `vox` |
| 5 | 47–49 | `vox /path/to/program.vox --run` | **RUN_OK** (uses the correct name `vox`; `--run` works) — note this line already said `vox` even before the fix, contradicting the `ec` install two blocks above |
| 6 | 68–71 | `export EC_CORE_PATH=/path/to/ec` | inspected — `EC_CORE_PATH` matches the compiler (`src/main.rs:30` reads exactly that var); illustrative path changed `ec`→`vox` |
| 7 | 81–84 | `text` config: `~/.config/ec/config`, `core_path=…` | inspected — **doc wrong**: the XDG config path is `~/.config/vox/config` (`src/main.rs:24,86`), not `~/.config/ec/config`. The key `core_path=` is correct (`src/main.rs:103`). **Fixed** → `vox` |
| 8 | 90–93 | `sudo rm -f /usr/local/bin/ec` / `rm -rf /usr/local/share/ec` | not executed; inspected — **doc wrong** (wrong name). **Fixed** → `vox` |
| 9 | 97–99 | `rm -rf ~/.config/ec` | not executed; inspected — **doc wrong** (wrong path). **Fixed** → `vox` |

The prose "How `ec` finds `coreasm`" resolution list (lines 51–62) had the
same `ec`→`vox` path errors in steps 2 and 3; **fixed**. Step 1 (`EC_CORE_PATH`)
left as-is — see the finding below.

### Stage B5 classification

- **doc wrong, fixed** — 3 findings (each spans several locations):
  - **R-APT** (README apt line): `rust` is not a Debian/Ubuntu package; changed
    to `cargo`. The yum line is correct (Fedora ships `rust`) and was left
    alone. *Caveat: this is a Fedora host with no `apt-cache`; the apt fix is
    reasoned from Debian/Ubuntu package naming (`cargo`/`rustc`, no `rust`).
    `cargo` is correct and sufficient regardless, so the fix is safe.*
  - **I-NAME** (docs/INSTALL.md, systematic): the entire document called the
    compiler `ec` — title, prose, `/usr/local/bin/ec`, `/usr/local/share/ec`,
    `/usr/share/ec/coreasm`, `/opt/ec/coreasm`, `~/.config/ec/config`, the
    uninstall paths, and the resolution-list paths (~20 occurrences). The
    actual binary is `vox` and the compiler reads coreasm from `…/vox/coreasm`.
    All changed to `vox`.
  - **I-PREREQ** (docs/INSTALL.md): Prerequisites omitted Rust, and the apt
    install line omitted `cargo`, so a user following the doc could not build.
    Added `cargo` to both.
- **compiler/source wrong, doc right — do not fix (1, observation):**
  - **ENV-EC** — the env var is `EC_CORE_PATH` (`src/main.rs:30`) while the
    binary and every path became `vox`. The doc documents `EC_CORE_PATH`
    correctly (it is what the compiler reads), so it was **not changed** —
    changing it to `VOX_CORE_PATH` would make the doc wrong. This is a
    source-side naming inconsistency left over from the `ec`→`vox` rename;
    flagging it for the code track to consider renaming the env var for
    consistency. Not a doc defect.
- **unclear — 0.** (ENV-EC is closest, but it is correctly classified as
  source-side: the doc matches behavior.)

### INSTALL steps not safely executed

Per the brief, nothing that writes outside the worktree or a temp dir was run.
Inspected-only (not executed), with what was checked:

- README block 4 (apt install) and block 5 (yum install) — package names
  verified against the host package set (Fedora: `rust`/`cargo`/`nasm` all
  installed; Debian/Ubuntu: reasoned, not run).
- README block 7 (`make install`/`make uninstall`) — Makefile inspected; all
  three targets exist and install to the correct `vox` paths.
- INSTALL blocks 1, 3, 4, 8, 9 (all `sudo`/`rm -rf` under `/usr/local` and
  `~/.config`) — inspected only: verified the real binary name (`vox`), the
  real coreasm search paths (`src/main.rs:51-53`), and that `coreasm/` exists.

### Version numbers

Neither document hardcodes a version; `vox --version` reports `v0.1.23`,
matching `Cargo.toml`. The README badges are dynamic. Nothing to flag, and the
upcoming `0.2.0` bump requires no change to either doc. (Flagging here per the
brief rather than guessing what a version field should say.)

### Most damaging finding to a new user

**I-NAME (docs/INSTALL.md `ec`→`vox`).** This is the first install path a new
user follows. As written, it told them to `sudo install … target/release/ec
/usr/local/bin/ec` (the source binary does not exist under that name) and to
place coreasm in `/usr/local/share/ec/coreasm` — but the compiler is `vox` and
looks for coreasm in `/usr/local/share/vox/coreasm`. A user following INSTALL.md
precisely would, after fixing the missing-`cargo` Prerequisites, find no
`target/release/ec` to install, and if they renamed it by hand, the compiler
still could not find coreasm. Compounding it, block 5 already invoked the
binary as `vox` two lines after installing it as `ec` — the doc contradicted
itself. A broken install on the very first try is the thing most likely to
make a newcomer conclude the project is abandoned and leave.