# REPORT-BATCH4 — #59, #60, #61, #62, #63, #64, #65 assembled onto main `23060d0`

One branch, `fix/bug-60-61-format-precision-and-pad`, `git log -1` =
**23060d0**, everything **staged, nothing committed**. Gate green.
`REPORT-60-61.md` deleted; its essentials are §3 and §4 below.

**Gate:** `VOX_CORE_PATH=$PWD/coreasm ./test.sh` →
**481 passed / 0 failed / 6 skipped, total 487.**
`cargo test` **284 passed** in the main binary (278 on main), the
compile_fail corpus **225 cases** (197 on main), `examples/` compile
check green.

Expected total, computed from each report's delta over main's 462:

| source | delta | why |
|---|---|---|
| main `23060d0` | 462 | REPORT-BATCH3's gate line |
| #59 | +7 | `tests/400`–`406` |
| #60 + #61 | +2 | `tests/410`, `411` |
| #62 + #63 | +3 | `tests/407`, `408`, plus one new shell test (`see/void-result`) |
| #64 | +5 | `tests/420`–`424` |
| #65 | +2 | `tests/395`, `396` |
| **expected** | **481** | **measured 481** ✓ |

The 28 new compile-fail cases add no count of their own: the corpus runs
inside one cargo test, which reports its case count separately (197 →
225, +28 ✓). The 6 skips are the pre-existing "no `.expected` file"
cases, unchanged.

---

## 0. Assembly record

### 0.1 The base step, done the way REPORT-BATCH3 §0.1 describes

This branch was cut from **9734e5d**; main is **23060d0**, one merge
ahead (batch 3: #38 #44 #45 #46 #51). `git reset --soft origin/main`
would therefore have staged the *reversion* of batch 3 — my index was a
snapshot of the older tree, and it touches four files batch 3 also
touches (`CHANGELOG.md`, `LANGUAGE.md`, `docs/BUGS_FOUND.md`,
`src/analyzer/expressions.rs`, `src/analyzer/mod.rs`,
`src/codegen/tests.rs`). Same trap, same route out as batch 3:

1. Captured my staged set as a patch, plus two independent backups — a
   `git stash create` commit object (`ab85b9d`, deliberately **not**
   pushed to the stash stack, so no other session's stash is disturbed)
   and a tarball of the worktree.
2. `git reset --hard origin/main` — branch tip and tree both at 23060d0,
   clean.
3. `git apply --3way` of the four other worktrees' staged diffs and then
   my own, in the briefed order: **#59, #65, #62, #64, #60**.

`git log -1` = 23060d0 and `git diff --cached --stat` = **110 files
changed, 4019 insertions(+), 659 deletions(-)** — 111 files with this
report.

Each worktree was read-only: `git -C <wt> diff --cached -- . ':(exclude)REPORT-*.md'`
and nothing else. No git state in any of them was touched.

### 0.2 Patch applies and conflicts

`CHANGELOG.md` was excluded from every apply (`--exclude=CHANGELOG.md`)
and composed once, by hand, in §0.4 — every worker appended its bullet
"after the last bullet present" on *its own* base, so the bullet list is
one guaranteed conflict per patch with one obvious resolution. Composing
it once, from main's list plus each worker's own added block, is the same
end state with none of the repeated conflict surgery.

| patch | source worktree HEAD | result |
|---|---|---|
| #59 | 9734e5d | clean |
| #65 | 9734e5d | 1 conflict — `src/codegen/statements.rs` |
| #62 + #63 | 9734e5d | 3 conflicts — `docs/BUGS_FOUND.md`, `src/analyzer/mod.rs`, `src/analyzer/statements.rs` |
| #64 | 23060d0 | clean (its `docs/BUGS_FOUND.md` hunk applied by hand, see below) |
| #60 + #61 (mine) | 9734e5d | 1 conflict — `src/codegen/tests.rs` |

A note on method: once a file is left unmerged, a later `git apply
--3way` refuses to touch it ("does not exist in index"), and silently
skips that file's hunks. My first pass hit exactly that and dropped
#64's and #60's `docs/BUGS_FOUND.md` hunks without failing. I reset and
redid the whole sequence **resolving after every patch**, which is the
only order that cannot lose a hunk.

**How each conflict was composed — no side dropped:**

- **`src/codegen/statements.rs` (#51 in main vs #65).** Both edit the
  same `VarDecl` `else` branch. #51 splits it on `is_text_target` (a text
  slot takes a *copy* of a buffer source); #65 converts an integer
  initialiser for a float slot. A text target can never be a float, so
  the two are disjoint: #51's split kept, #65's conversion placed inside
  the non-text arm, with a comment saying why they cannot overlap.
- **`src/analyzer/mod.rs` (#45 in main vs #62/#63)** — three hunks, all
  the same shape: #45 adds `mod untyped_returns;` /
  `untyped_result_functions`, #62 adds `mod void_results;` / `procedures`.
  Both kept, side by side.
- **`src/analyzer/statements.rs` (#45 in main vs #62/#63)** — the
  function-definition pre-scan records both facts now:
  `record_untyped_result_function(key.clone(), …)` **and**
  `record_procedure(key, …)`. The `.clone()` is mine: the first call
  takes `key` by value, so keeping both sides needs one clone. Two
  independent questions about one definition — #45 asks whether the
  result has a type to read, #63 whether there is a result at all.
- **`docs/BUGS_FOUND.md` (#62 vs #65)** — #62 replaces entry 62's "Not
  fixed" tail with its mechanism/fix and appends the new **### 63.**;
  #65 had already appended **### 65.** after the "(entries 63 and 64 are
  reserved)" placeholder. Composed to: #62's fixed tail, then 63, then
  (from #64's patch, applied by hand into the same region) 64, then 65 —
  numeric order, placeholder note gone because the entries it stood in
  for now exist.
- **`src/codegen/tests.rs` (#44 in main vs #60)** — both append a test
  block at the end of the file, so git split them across two conflict
  regions. Rebuilt deterministically instead: main's file (which already
  carries #44's tests) plus my six, appended once.

### 0.3 A real composition defect, found by the gate and fixed

**#62/#63's caret regressed under #46's region filter — the same class
batch 3 found for #45.** `162_procedure_result_in_a_format_hole` expects
the caret on the call inside `Print "shouted {shout of 3}".`, at column
17. On the combined tree it landed at column 8 — inside the *word*
`shouted` — and the corpus test failed.

Cause: #46 (batch 3, so absent from #62's base) taught
`find_pattern_location` to refuse a match sitting inside a text literal
unless the pattern *asks* for one (its prefix ends `{` or `"`). #62's
patterns are `'name'` and `name`; neither asks, so the filtered search
returned `None`, the code fell back to the unfiltered symbol scan, and
that scan's first hit for `shout` on the line is inside `shouted`.

Fix: `{name` now leads `void_results::use_site_location`'s pattern list —
the same shape `find_symbol_location` has always used. It cannot win for
an ordinary call (the code-only first pass cannot match a pattern that
exists only inside a literal), and in the text-allowing second pass it is
the only pattern that can reach into the hole. Caret back on the call;
corpus green. **This is the only behavioural change I made to any
worker's fix.**

### 0.4 CHANGELOG

Main's `[Unreleased] → Fixed` list already stood in the briefed order for
its fourteen bullets (#49 #50 #52 #53 #54 #55 #56 #57 #58 #38 #44 #45 #46
#51). Each worker's own added block was extracted against **its own
base** (`git -C <wt> diff --cached HEAD -- CHANGELOG.md`), so nothing of
main's was carried in or out, and the blocks were appended in ascending
bug order: **#59, #60, #61, #62, #63, #64, #65**. Each bullet's text is
its author's, verbatim, with one class of edit: test filenames that this
assembly renumbered (§0.6).

### 0.5 BUGS_FOUND

Entries 59, 60, 61 and 62 → **fixed** (each worker wrote its own status
line and fix section; none was rewritten here). 63, 64 and 65 are new and
fixed. Final order is numeric: … 59, 60, 61, 62, 63, 64, 65. The
placeholder "(Entries 63 and 64 are reserved for other findings in flight
and are deliberately absent here.)" is gone — both entries now exist.

Two brief items:

- **#51's foot-note** about `a text called n is 5.` ("it wants its own
  register entry") now ends: *"it got one, and its fix — see **### 65.**
  below."* One line, in place.
- **The #59 report's residuals** — a `value` as the `treating` match or
  replacement, and `append each … treating …` dropping the clause — are
  already recorded inside **### 59.** itself ("What this fix does not
  reach", "Found alongside, not fixed here"), which is where the brief
  wants them. There is no "candidate #66" note anywhere in REPORT-59 to
  relocate.

### 0.6 Numbering collisions and the renumber map

Four workers allocated from overlapping ranges. Nine compile-fail numbers
and two test numbers were duplicated. Each bug's block was kept
**contiguous**, and the blocks laid out in ascending order:

| bug | files | old | new |
|---|---|---|---|
| #65 | 13 compile_fail | 145–157 | **145–157** (unchanged) |
| #62/#63 | 11 compile_fail | 150–160 | **158–168** |
| #60/#61 | 2 compile_fail | 155–156 | **169–170** |
| #64 | 2 compile_fail | 160–161 | **171–172** |
| #62/#63 | 2 tests | 405, 406 | **407, 408** |
| #59 | 7 tests | 400–406 | unchanged |
| #60/#61 | 2 tests | 410, 411 | unchanged |
| #64 | 5 tests | 420–424 | unchanged |
| #65 | 2 tests | 395, 396 | unchanged |

Renames done with `git mv` through temporary names (the target numbers
were occupied by the very files being moved). Every reference chased:

- the 13 `.err` fixtures that quote their own `<case>.vox:line:col`
  (checked mechanically: every `.err` in 145–172 now names its own file);
- `docs/BUGS_FOUND.md` — 9 references in entries 61, 63 and 64;
- `CHANGELOG.md` — 7 references in the #60, #61, #62, #63 and #64
  bullets;
- this report.

Final corpus: **no duplicate numbers** among the new files;
compile_fail is contiguous 145–172. Five duplicate *test* numbers
survive — `067`, `320`, `340`, `355`, `356` — all of them pre-existing on
`origin/main` and none of them touched by this batch.

---

## 1. #59 — a `treating` clause over a mixed list keeps each element's tag

`Expr::TreatingAs` reported the *subject's* static type, and over a mixed
list the subject is the loop variable, which has none (`VarType::Mixed`).
Two things followed: the clause compared match and subject as raw
registers (so `treating "a" as "b"` never fired on a mixed list's `"a"`),
and the substituted element printed as a pointer. Codegen now carries the
element's runtime tag through the clause. Files: `src/codegen/expr.rs`,
`src/codegen/tags.rs`.

| test | on `origin/main` (per REPORT-59) | on this tree |
|---|---|---|
| `400_treating_a_mixed_list_keeps_each_tag` | FAIL — `4210906` / `4210912` / `4210924` | **PASS** |
| `401_treating_a_mixed_list_spares_floats_and_booleans` | FAIL — `4210888`, `4615063718147915776` (3.5's bits), … | **PASS** |
| `402_treating_a_mixed_list_holding_a_value_keeps_its_tag` | FAIL — `4198536` twice | **PASS** |
| `403_treating_inside_a_function_keeps_each_tag` | FAIL — `4198540` / `4198542` / `4198544` | **PASS** |
| `404_treating_a_map_s_values_keeps_each_tag` | FAIL — `4198559` twice | **PASS** |
| `405_treating_carries_the_tag_into_a_value_parameter` | FAIL — `4210914` / `4210920` | **PASS** |
| `406_treating_survives_an_is_a_guard_downstream` | FAIL — `number: 4210938` / … | **PASS** |
| `359_treating_matching_types_substitutes` (#55 control) | PASS | **PASS** |
| `360_treating_over_an_unprovable_list` (#55 control) | PASS | **PASS** |

Hand probe on the combined binary: `print each item from [1, "a"]
treating "a" as "X".` → `1`, `X`.

## 2. #60 — `{f:.N}` prints N correctly-rounded decimal places for any N

The old routine scaled the whole fraction by 10^N three ways and got it
wrong three ways from N=18: a `mulsd`-by-10 loop (accumulated error), an
`imul`-built 10^N carry threshold (wraps negative at N=19) and one
`cvttsd2si` (SSE "integer indefinite" from N=20 — the
`-9223372036854775808` spliced into the digits). The same `cvttsd2si`
took the *integer* part, so every magnitude at or beyond 2^63 printed
that sentinel too. Nothing is scaled now: the value is split as `m * 2^e`;
an integer part at or above 2^52 comes from the big-integer digit routine
the default float printer already uses (so `{f}` and `{f:.N}` agree on
every value), and the fraction's digits come from exact repeated halving
in decimal, rounded once, half-to-even. Files:
`coreasm/x86_64/format.asm`.

| line | on `origin/main` | on this tree (= glibc `printf`) |
|---|---|---|
| `{pi:.18}` | `3.141589999999999872` | **`3.141589999999999883`** |
| `{pi:.19}` | `4.-8584100000000001280` | **`3.1415899999999998826`** |
| `{pi:.20}` | `3.0-9223372036854775808` | **`3.14158999999999988262`** |
| `{pi:.30}` | `3.00000000000-9223372036854775808` | **`3.141589999999999882618340052431`** |
| `{pi:.50}` | `3.0000…000-9223372036854775808` | **all 50 places, exact** |
| 1e22 to 0 | `-9223372036854775808` | **`10000000000000000000000`** |
| 1e22 to 3 | `-9223372036854775808.-9223372036854775808` | **`10000000000000000000000.000`** |
| `0.1` to 55 / 60 | sentinel-spliced | **exact expansion, then zeros** |
| `9.9999` to 0 | `9` | **`10`** |
| `3.9` to 0 | `3` | **`4`** |
| `1.5` to 0 | `1` | **`2`** |
| `0.125` to 2 | `0.13` | **`0.12`** (exact tie → even) |
| 18 control lines (N=0,1,15–17; 0.0; 1e17; ties at 0/2; …) | correct | **unchanged** |

`tests/410_float_precision_any_places` **PASS**; `135_float_rounding_carry`
(#55-era control) **PASS**, byte-identical.

**Exactness re-verified on the combined binary**, not just on my own
branch: the 979-pair sweep against glibc `printf("%.*f")` was re-run
here — 690 ordinary pairs (23 mismatches, all of them the literal `-0.0`,
where Vox's own negation yields `+0.0` before the printer sees it, and
`{z}` agrees) and 289 extreme pairs **289/289 identical**, including the
smallest subnormal's 1074 places, the largest double, the
2^52/2^53/2^63 boundaries and N up to 1500.

## 3. #61 — a pad width is honoured at any size, and written a page at a time

The width was read with `parse::<i32>()` inside an `if let` with no else
arm, so one past `i32::MAX` the parse failed, the `Err` was dropped, and
the spec came out identical to a bare `{n}` — no padding, no diagnostic.
The width that did parse was then padded one `write(2)` per character.
Both halves fixed: one reader returns the spec *and* any count it cannot
honour (saturated, never absent), the analyzer turns that into a compile
error naming the limit, and `_fmt_emit_pad` writes the padding a
4096-byte page at a time through a short-write-safe writer. Files:
`src/codegen/format.rs`, `src/codegen/mod.rs`,
`src/analyzer/expressions.rs`, `coreasm/x86_64/format.asm`.

Re-measured on the combined binary (output to `/dev/null`, best of 2–5;
"before" is `origin/main`'s runtime assembled against the same compiler):

| width | before | on this tree |
|---|---|---|
| 1 000 | 0.0038 s | 0.0010 s (startup, not padding) |
| 1 000 000 | 2.579 s | **0.0017 s** |
| 100 000 000 | 283.5 s | **0.0750 s** |
| 2 147 483 647 (`i32::MAX`) | ~1.6 h at the measured rate | **1.330 s**, `wc -c` = 2 147 483 647 |
| **2 147 483 648 (2^31)** | **3 bytes, no padding, instantly** | **1.358 s**, `wc -c` = 2 147 483 648 |
| 99 999 999 999 999 999 999 | 3 bytes, no padding, instantly | **compile error** naming 9223372036854775807 |

`tests/411_pad_width_any_size` **PASS** (it also pins `{n:004x}`, which
printed `0255` before — the same reader cut `remaining` at a fixed
one-zero offset and lost the base specifier). Four codegen unit tests pin
the emitted width and precision either side of `i32::MAX` without writing
two billion spaces; all four green in the 284.
`tests/compile_fail/169`, `170` **refused**.

## 4. #62 — a `.lib` entry with no `, returning` clause cannot be read as a value

`ImportedFunction::return_type` was already `Type::Void` for a bare
entry; nothing consulted it. The call site checked arity and arguments
and never asked what the call answered with, so the result slot took
whatever `rax` held. Now refused at the use site, naming the function.
Files: `src/analyzer/void_results.rs` (new), `src/analyzer/expressions.rs`,
`src/analyzer/mod.rs`, `src/analyzer/statements.rs`, `test.sh`.

| case | on `origin/main` | on this tree |
|---|---|---|
| `a number called n is greet.` through a `.lib` | compiles, prints `hi from mathkit` then `1`, exit 0 | **compile error** |
| the same library, `greet.` as a statement + `'add two numbers' of 3 and 4` | `hi from mathkit`, `7` | **unchanged** |
| `see/void-result` shell test (asserts the `.lib` entry really is the bare `To greet.` first) | — (new) | **PASS** |

## 5. #63 — a procedure's non-existent result cannot be used as a value

The local half of the same defect: a `To` with no `Return` is
`Type::Void`, and a call in value position read the register the body
never set (`print ping.` printed `pong` then `1` — the `write` syscall's
return). One rule covers both halves. All eleven positions, re-run on the
combined binary:

| case (new number) | position | on `origin/main` | on this tree |
|---|---|---|---|
| 158 | declaration initializer | `pong` `1` | **REFUSED** |
| 159 | `print <call>` | `pong` `1` | **REFUSED** |
| 160 | list literal slot | `pong` `[1]` | **REFUSED** |
| 161 | map value | `pong` `{"first": 1}` | **REFUSED** |
| 162 | format hole (`of` form) | `shouted 3` `1` | **REFUSED** (caret fixed, §0.3) |
| 163 | `a value called …` | `pong` `1` | **REFUSED** |
| 164 | comparison operand | `pong` `took the branch` | **REFUSED** |
| 165 | argument to another call | `pong` `2` | **REFUSED** |
| 166 | `Set x to <call>` | `pong` `1` | **REFUSED** |
| 167 | `Append <call> to L` | `pong` `[1, 1]` | **REFUSED** |
| 168 | bare `Return.` only | `1` | **REFUSED** |

Controls `tests/407_procedure_called_as_a_statement` and
`408_declared_return_used_as_a_value` **PASS**. Hand probe: `To ping.
Print "pong".` + `ping.` → `pong`, still legal.

## 6. #64 — `the h's <property>` reads the property, like `h's <property>` always did

Two hand-written property lists in `parse_primary`: the bare arm knew
everything, the `the` arm knew the time/timer properties plus
`size`/`length`/`capacity`/`empty`/`full`. Both spellings now call one
`parse_possessive_tail`. File: `src/parser/expressions.rs` (a net
*reduction*: 524 changed lines, one list instead of two).

| test | on `origin/main` | on this tree |
|---|---|---|
| `420_the_possessive_reads_file_properties` | ✗ `Expected property name, got Descriptor` | **PASS** |
| `421_possessive_spellings_agree` | ✗ `…got Descriptor` | **PASS** |
| `422_the_possessive_in_every_position` | ✗ `…got Permissions` | **PASS** |
| `423_the_possessive_on_collections` | ✗ `…got StringLiteral("name")` | **PASS** |
| `424_the_possessive_on_numbers_and_timers` | ✗ `…got Identifier("start time")` | **PASS** |
| `compile_fail/171` (was 160) — `the h's exists` | ✗ generic message, not #38's | **REFUSED**, with #38's message |
| `compile_fail/172` (was 161) — unknown property | PASS (guard) | **REFUSED** (guard, both sides) |

Hand probe: `the items's length` and `items's length` both answer `3`;
`{the items's first} and {items's last}` → `1 and 3`.

## 7. #65 — a declaration whose initializer is the wrong type is a compile error

`a text called n is 5.` dereferenced the literal and segfaulted;
`a number called n is "get five".` printed the string's address. The
declaration path had no type check at all — the type lock only guards
writes to an *already-declared* name. `src/analyzer/types.rs` gains the
provable-type rule and three sites (declaration, argument, return);
`src/codegen/statements.rs` carries the designer's number/float ruling
(`a float called ratio is 3.` converts rather than being refused).

| case (unchanged numbers) | on `origin/main` | on this tree |
|---|---|---|
| 145 `a text called n is 5.` + `Print n.` | **exit 139** | **REFUSED** |
| 146 `a number called x is "get five".` | prints `4198488` | **REFUSED** |
| 147 `a boolean called ready is "x".` | prints `4198488` | **REFUSED** |
| 148 `a float called ratio is "abc".` | prints `0.0` | **REFUSED** |
| 149 `a list called items is 5.` | prints `[`, **exit 139** | **REFUSED** |
| 150 `a map called ages is "bo".` | prints `{}` | **REFUSED** |
| 151 `a text called label is true.` | **exit 139** | **REFUSED** |
| 152 `a number called count is <text var>` | prints `4198488` | **REFUSED** |
| 153 `Set a text called n to 5.` | **exit 139** | **REFUSED** |
| 154 `Create a number called n is "five".` | prints `4198488` | **REFUSED** |
| 155 `a text called got is five.` (number-returning call) | **exit 139** | **REFUSED** |
| 156 `greet with 5.` on a text parameter | **exit 139** | **REFUSED** |
| 157 `To 'label'. Return a text, 5.` | **exit 139** | **REFUSED** |
| `395_declaration_initialiser_types_that_agree` | byte-identical | **PASS** |
| `396_mistyped_initialisers_written_correctly` | byte-identical | **PASS** |

Hand probes on the combined binary: `a float called ratio is 3.` → `3.0`
(the ruling), `a number called n is 3.5.` → `3.5` (untouched), and
`a text called t is b.` on a buffer → `buf` (#51 still compiles, and this
is the interaction the `src/codegen/statements.rs` composition in §0.2
had to get right).

---

## 8. The final `[Unreleased] → Fixed` list, in order

Twenty-two bullets, each its author's text:

1. `For each` over a scalar, a map or a buffer is now a compile error — **#49**
2. A bare `otherwise` is accepted after any base action — **#50**
3. A text-valued special name built into a buffer no longer segfaults — **#52**
4. `Return a buffer, "<text>"` is a compile error instead of an empty buffer — **#53**
5. A collection element read into a variable of another type is a compile error — **#54**
6. A `treating` clause whose types do not match the collection is a compile error — **#55**
7. `all the numbers from/between …` no longer segfaults outside a loop — **#56**
8. `nothing` in a concretely-typed slot is now a compile error — **#57**
9. A buffer declared from a text-valued property keeps its type — **#58**
10. The documented file property `exists` is now a clear compile error — **#38**
11. A list or map interpolated into a format string renders everywhere — **#44**
12. A call with no declared return type is a compile error where nothing types it — **#45**
13. A diagnostic's caret no longer lands in a comment or a text literal — **#46**
14. A buffer put into a text no longer needs the cast — **#51**
15. A `treating` clause over a mixed list keeps each element's runtime tag — **#59**
16. `{f:.N}` prints N correctly-rounded decimal places for any N — **#60**
17. A pad width is honoured at any size it can be written — **#61**
18. A `.lib` entry with no `, returning` clause can no longer be read as a value — **#62**
19. A procedure's non-existent result can no longer be used as a value — **#63**
20. `the h's descriptor` reads the property, like `h's descriptor` always did — **#64**
21. A declaration whose initializer is the wrong type is a compile error — **#65**
22. `a float called ratio is 3.` holds 3.0 instead of 0.0 — **#65**

## 9. `git status --short`

111 paths staged (110 + this report), nothing unstaged, nothing untracked:

```
M  CHANGELOG.md
M  LANGUAGE.md
M  coreasm/x86_64/format.asm
M  docs/BUGS_FOUND.md
M  src/analyzer/expressions.rs
M  src/analyzer/mod.rs
M  src/analyzer/statements.rs
M  src/analyzer/types.rs
A  src/analyzer/void_results.rs
M  src/codegen/expr.rs
M  src/codegen/format.rs
M  src/codegen/mod.rs
M  src/codegen/statements.rs
M  src/codegen/tags.rs
M  src/codegen/tests.rs
M  src/parser/expressions.rs
M  test.sh
M  tests/p296_full_type_vocabulary.rs
A  REPORT-BATCH4.md
A  tests/395_… 396_… 400_…406_… 407_… 408_… 410_… 411_… 420_…424_…  (+ .expected)
A  tests/compile_fail/145_…172_…  (+ .err)
```

(the last two lines stand for the 91 individual test files, listed in
full by `git status --short`.)

Nothing committed. `REPORT-60-61.md` deleted; `REPORT-BATCH3.md` left
alone — it is part of main.

## 10. Residuals carried forward, not fixed here

Each is its author's, recorded in the register and repeated here so the
signer sees them in one place:

- **#59** — a `value` used as the `treating` match or replacement still
  prints an address (needs runtime tags on the match too), and
  `append each … treating …` drops the clause entirely, on homogeneous
  lists as well. Both inside **### 59.**
- **#60/#61** — `_buffer_append_formatted_int` still pads one byte at a
  time into a *buffer* (the value sink, not the print sink), and a
  precision on a non-float still reinterprets the value's bits (that is
  #36's remaining half). Both inside **### 61.** and **### 60.**
- **#62/#63** — a bare `Return <expr>.` with no declared type stays
  #45's business, untouched here.
- **#65** — the LANGUAGE.md:2024 example whose cast binds to the wrong
  operand is a one-line documentation defect, recorded and deliberately
  not changed.
- Five duplicate test numbers (`067`, `320`, `340`, `355`, `356`)
  pre-date this batch and are untouched.
