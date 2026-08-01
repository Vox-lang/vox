# Plan 240 — LANGUAGE.md claim audit (Stage B4)

Audited every Vox code sample and shell command in `LANGUAGE.md` by running it
against `target/release/vox` (v0.1.23) and recording whether it does what the
surrounding prose says. The shared-library section written in Stage B2
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
- **compiler wrong, doc right** — 4 findings (NOT fixed; reported for the code track).
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

## Findings — compiler wrong, doc right (NOT fixed)

Reported for the code track. Reproducible from each entry alone. Not modified —
changing these samples would paper over a real defect.

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

### F-FORK-1 — line 2173: `Set reaped to reap any child process.`
Fails when `reaped` is not already declared: `Unknown identifier 'reaped'` (did
you mean `read`?). `Set <newvar> to <expr>` *does* create new variables in
general — `Set newvar to 5.` and `Set pid to fork the process.` both work
without prior declaration (verified). So the compiler accepts `fork` but not
`reap` as the RHS of a Set-declaration. Pre-declaring (`a number called "reaped" is 0.` then `Set reaped to reap any child process.`) works. The doc's example
assumes Set creates the variable, which is correct for every other expression.
**Repro:** `Set reaped to reap any child process.` (alone).

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