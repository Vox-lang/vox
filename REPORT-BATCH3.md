# REPORT-BATCH3 — #38, #44, #45, #46, #51 assembled onto main `9734e5d`

One branch, `fix/bug-45-undeclared-return-read`, `git log -1` = **9734e5d**,
everything **staged, nothing committed**. Gate green. `REPORT-45.md` deleted;
its essentials are §3 below.

---

## 0. Assembly record

### 0.1 The base step did not go the way the brief described — and why

The brief said to bring this branch onto main with `git reset --soft
origin/main`, as the #57 assembler did. That is wrong for this branch, and
the brief's own verification step is what catches it.

This branch was cut from **5dbbc75**; main is **9734e5d**, four commits
ahead (`#57`/`#58` and the register entries for `#59`–`#62`). `git reset
--soft` moves HEAD and leaves the index alone — and my index was a full
snapshot of the *old* tree. Diffed against the new HEAD it would have
staged the **deletion** of `tests/363`–`367` and `tests/compile_fail/119`–
`125` and the **reversion** of #57's and #58's source edits: ~60 files
staged instead of 31, with two accepted fixes quietly undone. (The #57
assembler's branch was cut from the commit immediately before its target,
where the reset is a no-op difference. Mine is not.)

What I did instead reaches the identical end state by the same route the
brief already uses for the other four:

1. Captured this branch's staged set as a patch, plus two independent
   backups: a `git stash create` commit object (`81248c0`, deliberately
   **not** pushed to the stash stack, so no other session's stash is
   touched) and a tarball of the worktree.
2. `git reset --hard origin/main` — branch tip and tree both at 9734e5d,
   clean.
3. `git apply --3way` of my own patch, then #44, #46, #38, #51 in the
   briefed order.

`git log -1` is 9734e5d and the #45 set came back as exactly **31 files**,
which is the check the brief asked for.

### 0.2 Patch applies and conflicts

| patch | source worktree HEAD | result |
|---|---|---|
| #45 (mine) | 5dbbc75 | 1 conflict — `CHANGELOG.md` |
| #44 | 5dbbc75 | 1 conflict — `CHANGELOG.md` |
| #46 | 2f80310 | 1 conflict — `CHANGELOG.md` |
| #38 | 9734e5d | clean |
| #51 | 9734e5d | clean |

Every conflict was the same shape and had the same resolution: each worker
appended its `Fixed` bullet "after the last bullet present" on *its* base,
so the bullet list is the conflicting region. **Ours-then-theirs, no side
dropped** — the accumulated bullets kept in place, the incoming bullet
appended — then the whole list reordered in §0.4. No source file, no test,
and no `docs/BUGS_FOUND.md` entry conflicted: the five touch mostly
disjoint files, and where they overlap they overlap in different sections.

Two overlaps the brief flagged, checked and clear:

- `src/analyzer/types.rs` — #51 only; #45 never touched it.
- `src/codegen/statements.rs` — #51 only, and #51 was written on top of
  #58, so its `VarDecl` guard composes with #58's rather than replacing it
  (`is_text_from_buffer` sits on the same `if`).

### 0.3 A real composition defect, found and fixed

**#45's caret regressed under #46's new region filter.** #46 taught
`find_pattern_location` to refuse a match sitting inside a text literal
unless the pattern *asks* for one (prefix ends `{` or `"`). That is right
for an unknown variable. But a call can legitimately sit inside a literal —
`print "got {'opaque label'}".` is an interpolated call — and the
quoted-name spelling puts a `'` between the `{` and the name, so no pattern
#45 can write satisfies #46's test. The filtered search returned `None`,
#45 fell back to the unfiltered `find_symbol_location`, and its first
textual hit for a function name is always the function's own `To` line:

```
before fix:  133_format_hole_undeclared_return.vox:1:5   ← the definition
after  fix:  133_format_hole_undeclared_return.vox:7:14  ← the interpolation
```

Reproduced with no comment in the file at all, so it is the literal, not
#46's comment handling.

Fixed **inside `src/analyzer/untyped_returns.rs`**, not by widening #46's
rule: `find_call_site_location` now falls through to a plain scan that
skips the definition line, which is the single thing the unfiltered
fallback got wrong here. #46's rule is untouched and its own four fixtures
plus its twenty-one corpus-wide caret corrections are unchanged (verified,
§4.4). `133`'s `.err` now pins `7:14` the way #46's fixtures pin theirs, so
the composition cannot drift back silently, and the #45 register entry
records why that one caret is pinned.

Checked and *not* a defect: #46 alone anchors `Print "{'my count'}"`
correctly for an unknown variable, because that path reaches the unfiltered
fallback and its first textual hit happens to be the right one. Only a
symbol that also appears earlier — which a *function* name always does —
exposes the gap.

### 0.4 CHANGELOG

One `## [Unreleased]` → `### Fixed`. Bullet text is each worker's own, verbatim;
only the order changed, plus the two fixture renames in §0.5.

Final order, verbatim from the file:

```
#49  For each over a scalar, a map or a buffer is now a compile error instead of a crash or garbage
#50  A bare otherwise is accepted after any base action, not just append
#52  A text-valued special name built into a buffer no longer segfaults
#53  Return a buffer, "<text>" is a compile error instead of an empty buffer or a segfault
#54  A collection element read into a variable of another type is a compile error, not a segfault
#55  A treating clause whose types do not match the collection is a compile error instead of a segfault
#56  all the numbers from/between … no longer segfaults outside a loop header, and both spellings now include their end bound
#38  The documented file property exists is now a clear compile error instead of a bare parser complaint
#44  A list or map interpolated into a format string renders everywhere, not just in Print
#45  A call with no declared return type is a compile error where nothing supplies one, instead of being read as a number
#46  A diagnostic's caret no longer lands in a comment, in a text literal, or in the middle of a longer word
#51  A buffer put into a text no longer needs the cast, and never yields the buffer's header
```

`#49 #50 #52 #53 #54 #55 #56 #57 #58` then `#38 #44 #45 #46 #51` ascending,
as briefed.

### 0.5 Renumber map

Two collisions, exactly the ones the brief predicted.

| bug | old | new |
|---|---|---|
| #38 | `tests/compile_fail/140_file_handle_exists_property.{vox,err}` | `141_file_handle_exists_property.{vox,err}` |
| #46 | `tests/compile_fail/135_caret_skips_a_comment_mention.{vox,err}` | `137_caret_skips_a_comment_mention.{vox,err}` |
| #46 | `tests/compile_fail/136_caret_skips_a_text_literal_mention.{vox,err}` | `138_caret_skips_a_text_literal_mention.{vox,err}` |
| #46 | `tests/compile_fail/137_caret_matches_a_whole_word_only.{vox,err}` | `139_caret_matches_a_whole_word_only.{vox,err}` |
| #46 | `tests/compile_fail/138_caret_skips_a_multi_line_comment_mention.{vox,err}` | `140_caret_skips_a_multi_line_comment_mention.{vox,err}` |
| #45 | `tests/372_undeclared_return_into_declared_variable.{vox,expected}` | `374_…` |
| #45 | `tests/373_undeclared_return_as_an_argument.{vox,expected}` | `375_…` |
| #45 | `tests/374_declared_return_reads_everywhere.{vox,expected}` | `376_…` |

`#38`'s 140 was moved **first**, to free the number `#46`'s last fixture
needed; `#46`'s four were then moved in descending order, and `#45`'s three
likewise, so no rename ever landed on an occupied name.

References updated with the renames — and each one checked, not assumed:

- **`#46`'s four `.err` files each pin `file:line:column`**, so all four
  carried their own old filename in the fixture. Rewritten; the pinned
  line:column are unchanged and still hold (§4.4).
- `docs/BUGS_FOUND.md` — `### 38.`'s regression list, `### 45.`'s control
  list, `### 46.`'s fixture list (which spells the names across line
  breaks).
- `CHANGELOG.md` — `#38`'s and `#46`'s bullets.
- Swept `tests/`, `src/`, `*.md` for any other reference to a moved
  number: none. The cross-references that exist (`tests/300_*`,
  `330`/`331`/`336`/`337`/`339`) are all to files nothing moved.

Final corpus: **no duplicate numbers**, compile_fail `100`–`125`, `130`–
`141`; runtime tests `…363`–`376`, `385`–`387`, `390`. Every `.vox` has its
`.err` (see §6 for the pre-existing `WARN`).

The brief asked for a sweep of `ls tests | sort` for any other clash. There
are five — `067`, `320`, `340`, `355`, `356` each name two different tests —
and all five are **pre-existing on `origin/main`**, untouched by this batch
and by any of the five branches. Recorded, not fixed: renaming shipped tests
is not this assembly's business, and the runner keys on the full filename
rather than the number, so nothing is shadowed.

### 0.6 BUGS_FOUND

`### 38.`, `### 44.`, `### 45.`, `### 46.`, `### 51.` all carry
`**Status:** **fixed**` — verified after the applies, not assumed. Entries
`### 57.`–`### 62.` untouched. The `### 51.` foot-note recording `a text
called n is 5.` (segfaults; #65, in flight) is present and untouched at
`docs/BUGS_FOUND.md:2804`. 62 entries total.

---

## 1. #38 — the documented file property `exists`

`Print h's exists.` on an open handle failed with `Expected property name,
got Exists`, which named the token but not the problem. The ruling taken
was **remove the row, document the idiom**: every property in the table
describes a handle that is already open, and a file that did not exist
could not have been opened, so `exists` on a handle is trivially true and
answers nothing. LANGUAGE.md's File Properties table drops the row and
gains the `On error` idiom with a worked example over both an existing and
a missing path; the parser names that idiom directly. A path-level `exists`
predicate is noted as a planned addition, not promised as syntax. The new
parser arm is unconditional — the parser tracks no per-variable type at
that site — which is safe because `exists` has no valid meaning after `'s`
for any object type.

**After, on the combined binary:**

| check | before (`origin/main`) | after |
|---|---|---|
| `Print h's exists.` diagnostic | `Expected property name, got Exists` | `a file handle has no \`exists\` property - a handle you hold is already open; …` at `141_file_handle_exists_property.vox:9:11` |
| `tests/390_file_exists_idiom` (both branches) | n/a (new) | **PASS** (exit 0) |

## 2. #44 — a list or map interpolated into a format string

`Print "{flat}"` gave `[1, 2, 3]`, but every other sink gave the heap
pointer as a decimal integer: `src/codegen/print.rs` special-cased
`VarType::List`/`Map` inside the Print emitter, while every other sink
funnels through `emit_append_runtime_value_to_buffer_ptr`, which had no
collection arm. The reading taken is **render everywhere**, on
LANGUAGE.md:3133-3136 and :3157-3163, neither of which carries a type
restriction; the `thing` precedent does not transfer, because a thing has
no runtime renderer at all while a list and a map each already have one
(`_list_print`, `_map_print`). The renderer was **redirected, not copied**.
The worker also found a sink the register did not know about: a *quoted*
name or a bare list literal in a hole (`{'the running total'}`, `{[1, 2]}`)
parses as `FormatPart::Expression`, whose Print arm had a `Map` case and
never a `List` one — so those spellings printed an address in Print
position, the one position the register reports as working.

**After, on the combined binary:**

| test | before (`origin/main`) | after |
|---|---|---|
| `368_collection_in_a_text_initializer` | 7 of 14 lines are addresses | **PASS** (exit 0) |
| `369_collection_in_the_buffer_sinks` | `copy: 140337510920192`, `set: …` | **PASS** (exit 0) |
| `370_collection_written_to_a_file` | the address is what lands in the file | **PASS** (exit 0) |
| `371_collection_as_a_function_argument` | `argument: 140059351597056` | **PASS** (exit 0) |
| `372_collection_in_a_treating_clause` | `140065996353536` | **PASS** (exit 0) |
| `373_quoted_list_name_in_a_format_string` | 6 of 8 lines are addresses, Print controls included | **PASS** (exit 0) |

## 3. #45 — a call with no declared return type

`To 'opaque label'. Return "hi".` then `print 'opaque label'.` printed
`4198488`, the rodata address of `"hi"`; through a declared `text` it
printed `hi`. `return_type` is `Type::Void` both for a procedure and for a
`Return` with no `a <type>,` prefix, so every consumer needing a type fell
back on "it is a number" — the integer formatter, or a `TAG_INTEGER` slot.
Nothing is dereferenced, so nothing crashes: it prints as a stable static
address, a wrong answer that looks like data, which is the shape
LANGUAGE.md:649-660 says the 0.3.0 split exists to kill.

Hand-running every position first changed the rule. **An argument is not an
untyped position** — the callee's parameter declares its own type — and
neither is a comparison against a typed operand. So the fix is *reject
where the position supplies no type*, not "reject every untyped call": one
new module (`src/analyzer/untyped_returns.rs`), one set filled in the
signature pre-pass, seven one-line hooks. A function with no
value-returning `Return` is excluded — it returns nothing, a different
question. LANGUAGE.md's Mixed-Type Lists section, which licensed the append
with a worked example and a "residual limitation" paragraph, is rewritten,
and a **Reading a result** subsection states the rule under Functions.

**After, on the combined binary:**

| position | before (`origin/main`) | after |
|---|---|---|
| `print 'opaque label'.` | `4198488` | rejected, caret `7:8` |
| `append … to items.` → `element 1` | `4210906` | rejected, caret `8:9` |
| `set labels's "first" to …` | `4210906` | rejected, caret `7:26` |
| `print "got {'opaque label'}".` | `got 4198488` | rejected, caret `7:14` |
| `a list called items is ['opaque label', …]` | `4210906` | rejected, caret `6:26` |
| `a value called label is …` | `4210906` | rejected, caret `8:26` |
| `set element 1 of items to …` | `4210906` | rejected, caret `7:28` |
| `374_undeclared_return_into_declared_variable` | `hi / got hi / hi / hi` (already right) | **PASS**, unchanged |
| `375_undeclared_return_as_an_argument` | `hi` (already right) | **PASS**, unchanged |
| `376_declared_return_reads_everywhere` | `hi ×6` (already right) | **PASS**, unchanged |

The three controls give identical output before and after — the point being
that the rejection narrows nothing that worked. `tests/155` and `156` and
the codegen test `unknowable_value_append_widens` were written on the now-
rejected construct; all three keep their property (an element the compiler
cannot type widens the list to mixed) using a `value`, which is opaque the
same way and carries the tag the function never did.

**Not closed:** a function with no `Return` at all (`print ping.` → `pong`
then `1`) — different shape, wants its own entry; and an undeclared return
crossing a `.lib` boundary, which records identically to a procedure.

## 4. #46 — the diagnostic caret

The caret was located by a plain text search over raw source for the
symbol's *name*, so the first textual occurrence won wherever it sat —
including inside a comment, inside a text literal, or in the middle of a
longer word. **No real spans were available**: `Expr::Identifier` is a bare
`String` and no expression node in the AST carries a position, so zero call
sites were converted and the fix is the fallback done properly. New
`src/lexer/regions.rs` classifies every byte `Code`/`Comment`/`Text` by
mirroring the lexer (nesting comments, escapes, character literals,
quoted identifiers), `SourceFile` computes it once, and
`find_pattern_location` scans twice — code-only, then allowing literals,
and only for a pattern that asks for one.

**After, on the combined binary** (`.err` pins the file:line:column, so
these are corpus-enforced):

| fixture (renumbered) | before | after |
|---|---|---|
| `137_caret_skips_a_comment_mention` | `1:11` — inside the comment | `3:8` ✓ |
| `138_caret_skips_a_text_literal_mention` | `2:8` — inside the literal | `3:8` ✓ |
| `139_caret_matches_a_whole_word_only` | `1:4` — the `n` of `print` | `2:13` ✓ |
| `140_caret_skips_a_multi_line_comment_mention` | `3:10` — inside it | `5:8` ✓ |

<a name="s4-4"></a>**§4.4 — the twenty-one corpus-wide corrections still hold** (spot-checked
against #46's own table, on the combined binary):

| pre-existing fixture | before | after |
|---|---|---|
| `003_copy_source_not_buffer` | `1:3` (the `n` in `number`) | `1:17` ✓ |
| `004_copy_destination_not_buffer` | `1:33` (the `n` in `in size`) | `2:17` ✓ |
| `025_read_target_not_buffer` | `1:4` (the `n` in `open`) | `2:17` ✓ |
| `041_increment_timer` | `1:3` (the `t` in `timer`) | `1:16` ✓ |
| `thing_interpolated_into_text` | `1:39` — **its own header comment** | `11:16` ✓ |

## 5. #51 — a buffer put into a text

`a text called t is b.` stored the buffer's struct pointer in the text
slot, so the first read walked the 24-byte `[capacity][length][flags]`
header as a C string. The register's mechanism was right and *narrower*
than the defect: **five** spellings put a buffer into a text slot, and the
compiler was doing neither thing consistently — three were silently wrong
and two were refused by the type lock. One copy, five callers:
`emit_buffer_to_text_copy` lifted out of the cast arm, called from the cast,
`VarDecl`, both assignment spellings, `Return`, and the argument path. Two
facts the register did not have: even an untouched buffer read its header
(a 32-byte buffer converted to a text printing a single space — 0x20 is
32), and the declaration form was a **use-after-free**, not just a wrong
character.

**After, on the combined binary:**

| test | before (`origin/main`) | after |
|---|---|---|
| `385_text_from_buffer_copies` | `@` / `A` / `[ ]` — wrong | **PASS** (exit 0) |
| `386_text_from_buffer_at_every_write_site` | two compile errors; its param/return halves gave `@` / `@` | **PASS** (exit 0) |
| `387_text_from_buffer_is_an_independent_copy` | **SEGFAULT, exit 139** | **PASS** (exit 0) |

---

## 6. Gate

```
VOX_CORE_PATH=$PWD/coreasm ./test.sh
  Passed: 462   Failed: 0   Skipped: 6   Total: 468   ALL TESTS PASSED   (exit 0)
  compile_fail corpus: 197 cases (checked by cargo test)
  examples/ compile check: PASS
```

The total is exactly the sum of the parts, computed before the run and
matched by it:

```
  449  main 9734e5d baseline   (#51's and #38's reports both state 449/0/6/455)
  +  1  #38   tests/390
  +  6  #44   tests/368-373
  +  3  #45   tests/374-376
  +  0  #46   compile-time only, no runtime test
  +  3  #51   tests/385-387
  ---
   462  ✓
```

`cargo test` green throughout: **278** in the main binary (263 on the #45
branch alone, + #46's 12 lexer tests and #44's 3 codegen tests) and 0 failed
across all twelve suites, `compile_fail_corpus_reports_errors` included.
Corpus 197 = main's 185 + 7 (#45) + 4 (#46) + 1 (#38).

The gate prints `WARN 197 .vox but 195 .err`. **Pre-existing, and not a
missing fixture:** the two extras are `tests/compile_fail/include/*.vox`,
helper files other cases `see` and which correctly have no `.err`. The
warning's `find` is recursive while the corpus walker is not. It fires on
main too. Both #38's and #44's workers noticed it independently and left it
alone; so have I.

## 7. `git status --short`

```
M  CHANGELOG.md
M  LANGUAGE.md
M  coreasm/x86_64/core.asm
M  coreasm/x86_64/float.asm
M  coreasm/x86_64/io.asm
M  coreasm/x86_64/list.asm
M  coreasm/x86_64/map.asm
M  coreasm/x86_64/resource.asm
M  docs/BUGS_FOUND.md
M  src/analyzer/expressions.rs
M  src/analyzer/mod.rs
M  src/analyzer/scope.rs
M  src/analyzer/statements.rs
M  src/analyzer/types.rs
A  src/analyzer/untyped_returns.rs
M  src/codegen/buffers.rs
M  src/codegen/expr.rs
M  src/codegen/functions.rs
M  src/codegen/print.rs
M  src/codegen/statements.rs
M  src/codegen/tests.rs
M  src/errors.rs
M  src/lexer/mod.rs
A  src/lexer/regions.rs
M  src/lexer/scan.rs
M  src/parser/expressions.rs
M  tests/155_unknowable_append_widens.vox
M  tests/156_alias_of_mixed_dispatches.vox
A  tests/368_collection_in_a_text_initializer.expected
A  tests/368_collection_in_a_text_initializer.vox
A  tests/369_collection_in_the_buffer_sinks.expected
A  tests/369_collection_in_the_buffer_sinks.vox
A  tests/370_collection_written_to_a_file.expected
A  tests/370_collection_written_to_a_file.vox
A  tests/371_collection_as_a_function_argument.expected
A  tests/371_collection_as_a_function_argument.vox
A  tests/372_collection_in_a_treating_clause.expected
A  tests/372_collection_in_a_treating_clause.vox
A  tests/373_quoted_list_name_in_a_format_string.expected
A  tests/373_quoted_list_name_in_a_format_string.vox
A  tests/374_undeclared_return_into_declared_variable.expected
A  tests/374_undeclared_return_into_declared_variable.vox
A  tests/375_undeclared_return_as_an_argument.expected
A  tests/375_undeclared_return_as_an_argument.vox
A  tests/376_declared_return_reads_everywhere.expected
A  tests/376_declared_return_reads_everywhere.vox
A  tests/385_text_from_buffer_copies.expected
A  tests/385_text_from_buffer_copies.vox
A  tests/386_text_from_buffer_at_every_write_site.expected
A  tests/386_text_from_buffer_at_every_write_site.vox
A  tests/387_text_from_buffer_is_an_independent_copy.expected
A  tests/387_text_from_buffer_is_an_independent_copy.vox
A  tests/390_file_exists_idiom.expected
A  tests/390_file_exists_idiom.vox
A  tests/compile_fail/130_print_undeclared_return.err
A  tests/compile_fail/130_print_undeclared_return.vox
A  tests/compile_fail/131_append_undeclared_return_to_list.err
A  tests/compile_fail/131_append_undeclared_return_to_list.vox
A  tests/compile_fail/132_map_value_undeclared_return.err
A  tests/compile_fail/132_map_value_undeclared_return.vox
A  tests/compile_fail/133_format_hole_undeclared_return.err
A  tests/compile_fail/133_format_hole_undeclared_return.vox
A  tests/compile_fail/134_list_literal_undeclared_return.err
A  tests/compile_fail/134_list_literal_undeclared_return.vox
A  tests/compile_fail/135_value_declaration_undeclared_return.err
A  tests/compile_fail/135_value_declaration_undeclared_return.vox
A  tests/compile_fail/136_set_element_undeclared_return.err
A  tests/compile_fail/136_set_element_undeclared_return.vox
A  tests/compile_fail/137_caret_skips_a_comment_mention.err
A  tests/compile_fail/137_caret_skips_a_comment_mention.vox
A  tests/compile_fail/138_caret_skips_a_text_literal_mention.err
A  tests/compile_fail/138_caret_skips_a_text_literal_mention.vox
A  tests/compile_fail/139_caret_matches_a_whole_word_only.err
A  tests/compile_fail/139_caret_matches_a_whole_word_only.vox
A  tests/compile_fail/140_caret_skips_a_multi_line_comment_mention.err
A  tests/compile_fail/140_caret_skips_a_multi_line_comment_mention.vox
A  tests/compile_fail/141_file_handle_exists_property.err
A  tests/compile_fail/141_file_handle_exists_property.vox
?? REPORT-BATCH3.md
```

Nothing committed. Branch `fix/bug-45-undeclared-return-read` at `9734e5d` + the staged batch.
