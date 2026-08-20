# Changelog

All notable changes to Vox are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.4.8] - 2026-08-20

### Fixed

- **`Write` of a number, float, boolean, or `value` is a compile error,
  not a segfault** ([#40](docs/BUGS_FOUND.md)) — `Write n to out`
  compiled and then crashed the generated program (exit 139) for all
  three scalars, while text, buffers, and format strings wrote
  correctly: `Write` hands its operand to `FILE_WRITE_STR`, which reads
  it as a pointer to text, so a scalar's *value* was used as an address
  (n = 72 read address 72). LANGUAGE.md documents `Write` for text,
  buffers, and format strings, so the analyzer now refuses a bare scalar
  operand the way `append` refuses a number source, naming the operand,
  its type, and the spelling that works: `Write "{n}" to out.` A `value`
  operand is refused with it — it crashed the same way when it held a
  number or `nothing`, and the compiler cannot tell that from the
  text-holding case that worked — and its message names the fix verified
  for every case a value can hold: copy it into a typed variable and
  write that. Rendering a scalar directly remains an open design option;
  this pass fixes the diagnostic, not the language. Found by a human
  writing ordinary Vox while building vox-fuzz's stdin input
  generation.

- **`buffer as text` now copies the buffer instead of aliasing it**
  ([#41](docs/BUGS_FOUND.md)) — the cast returned a pointer into the
  buffer's data area, so a text made from a buffer was a window onto it,
  not a value. Clearing and refilling the buffer silently rewrote every
  text taken from it, with no diagnostic; and because resizing a buffer
  frees its old allocation, as the manual's Buffer Resizing section says
  it does, reading such a text after a resize was a use-after-free —
  both directions segfaulted from eight lines of ordinary code, in a
  language whose headline promise is memory safety. `as text` now copies
  the buffer's bytes into a fresh dynamic buffer, the same allocation
  format strings and the other text-producing casts use, so exit cleanup
  tracks it identically. Regression test
  `tests/buffer_as_text_copies.vox`; LANGUAGE.md's conversion table and
  Buffer Resizing notes now state that the text is an independent copy.
  Found while writing an ordinary Vox program that read lines from a
  file into a list.

- **A buffer's `type` property reports `Buffer (static)` however it was
  declared** ([#42](docs/BUGS_FOUND.md)) — `a buffer called b is 16
  bytes in size`, `is 16 bytes`, `Create a buffer called b with size 16`,
  and the bare dynamic `a buffer called b.` all printed `Text (dynamic)`
  from `b's type`, against LANGUAGE.md's explicit listing of `buffer`
  among the statically-typed kinds; only the string-initialised `is
  "seed"` form was right. Every sized and dynamic spelling routes through
  `BufferDecl`, which registered the variable's runtime kind but never
  its declared type, so the property's lookup missed and fell through to
  the runtime-tag dispatch, where a buffer pointer reads as a string tag.
  The declaration now registers the declared type; the same omission on
  `Get the current time into` is closed alongside it so a `time` reports
  `Time (static)`. Found by the vox-fuzz buffer claim ledger (discrepancy
  D2) and adjudicated by the language lawyer.

- **A conditional `value` return no longer segfaults the caller**
  ([#43](docs/BUGS_FOUND.md)) — a function whose only `Return` sat
  inside an `If`/`Otherwise` (`To label with a value called v. If v is a
  number, return a value, v. Otherwise, return a value, 99.`) crashed
  its caller with SIGSEGV, deterministically: the integer `99` was
  dereferenced as a `char*` inside `_print_cstr_impl`. The parser's Gate
  B fed a `Return`'s declared type into the function's signature only
  for **top-level** body statements, so a branch-nested `Return` left
  `return_type` at `Void`; codegen then skipped the `value` return's r11
  tag load, and the caller stored r11 into the variable's tag slot
  anyway — r11 still holding the callee's **parameter** tag (text) from
  the `is a number` predicate, which labelled an integer payload as
  text. Three changes: `emit_load_value_tag`'s no-tag arm now defaults
  to the integer tag unless `expr_leaves_tag_in_r11` confirms a tag was
  left there, which makes this class of mislabelling impossible
  whatever else is wrong; the parser now adopts a branch-nested
  `Return`'s declared type as the signature when the body declared no
  top-level one and every declaration agrees, which is the actual cause;
  and a function that falls off its end now returns its declared type's
  empty value (empty text, zero, or a `value` tagged as the number `0`)
  rather than whatever rax held, since a typed function could not
  previously reach that path at all. The same missing signature made the
  plain-type family silently wrong rather than unsafe — `Return a text`
  inside a branch printed the text's address as a number — and that is
  fixed by the same change. A function whose branches declare
  *different* types still has no signature to adopt and is unchanged
  (memory-safe, silently wrong); making that a compile error is a
  language decision, noted in the register. Regression test proven to
  segfault on the unfixed compiler and to pass after, with the
  single-expression `Return a value, <expr>.` form kept as the control.
  LANGUAGE.md's "One limitation to know" paragraph is rewritten: the
  factorial pattern now works for `value` returns. See
  [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) #43.

- **`Seek ... to line N` reaches line N** ([#47](docs/BUGS_FOUND.md)) — every
  target of 2 or more landed at the start of line 2, whatever N was, and a
  line past the end of the file never set the error flag. `_seek_fd_line`
  kept its line counter in `rcx` across the read syscall, and `syscall`
  clobbers rcx with the return address, so the counter became a code address
  on the very first byte read: the compare against the target failed
  immediately, the scan fell out at the first newline, and the past-EOF branch
  was unreachable. The counter now lives in `rbx`, which is callee-saved and
  already pushed. `Seek ... to byte N` was a bare `lseek` and was never
  affected; `_seek_fd_line` exists only in the x86_64 runtime. Found by the
  vox-fuzz files claim ledger (discrepancy D3) and adjudicated by the language
  lawyer.

- **A failed `Write` sets the error flag, and both read forms agree about a
  dead handle** ([#48](docs/BUGS_FOUND.md)) — a `Write` to a full device, to a
  handle opened for reading, to a closed handle or to a handle whose `open`
  failed all succeeded silently as far as Vox could tell, so a write that did
  not happen was indistinguishable from one that did; and `Read from` a
  failed-open handle reported a zero-byte read where `Read line from` the
  identical handle set the flag. The three write macros issued their `write(2)`
  and popped straight past rax without inspecting it, and `FileWrite` never
  touched `_last_error` at all. Writes now record their syscall's outcome —
  the errno for a failure, `EIO` for a short write, zero on success — and
  `Write`, `Write a newline` and `Read from` set the flag on a dead handle
  exactly as `Read line from` already did. Found by the vox-fuzz files claim
  ledger (discrepancies D4 and D5) and adjudicated by the language lawyer.

### Changed

- **LANGUAGE.md defines buffer bounds** — writes accept positions 1..capacity
  and extend `size` (zero-filling any gap); reads accept 1..size; position
  0 is out of bounds for both. The compiler has always behaved this way and
  the manual's own worked example relied on it, but the Bounds Checking
  paragraph never said so (buffer ledger discrepancy D3). The fixed-buffer
  feature list no longer says truncation is "silent": it sets the error
  flag, as the Reading section already stated.

- **LANGUAGE.md no longer says `Read` appends** — the Reading section's
  high-level bullet claimed `Read` "appends incoming data to the buffer", as
  the explicit contrast against `Read line`'s "replaces". The compiler
  deliberately replaces (`codegen/statements.rs`: "read replaces, not
  appends"), `tests/runtime/b340_pipe_exact_fit.asm` asserts it, and no other
  sentence in the manual depends on append. The bullet now says `Read`
  replaces the buffer's contents and continues from the file's current
  position — which is the real contrast with `Read line` (files ledger
  discrepancy D2). The Seeking, Writing and Error Handling sections now also
  state that a failed `Write`, and a read on a handle whose open failed, set
  the error flag and are catchable.

- **LANGUAGE.md collections section: five examples corrected, one
  annotated** — from the vox-fuzz collections-a claim ledger
  (discrepancies D1-D6), each adjudicated by the language lawyer and each
  recompiled against this tree. The mixed-list widening example's `append
  hello to items` is now `append "hello" to items`: a bare word is an
  identifier (LANGUAGE.md:645-668), so the example as printed did not
  compile (D1). The list-of-maps paragraph no longer claims a `For each`
  "types the loop variable as a map" — the loop variable is deliberately
  untyped and map access is a static check, so reading a key off it is a
  compile error; the section now shows the index-loop idiom that works
  (D2). The mixed-list guard idiom is replaced for the same reason: a
  predicate reads the runtime tag but does not narrow the static type, so
  the guarded element has to be extracted into a declared variable (D3),
  and the `item as a number` cast the same paragraph offered as the
  alternative is dropped, since casting a dynamically-tagged value is a
  known gap and is rejected (D4). The promise that an unprovable value in
  a list "is always read back as what it is rather than silently
  reinterpreted" is hedged to match the limitation paragraph twenty lines
  below it, which always conceded the conservative `number` tag guess
  (D5). And the cyclic-list example's `(prints: [[...]] then cyclic)` is
  marked as the abbreviation it is — 64 brackets each side of the `...`
  (D6). Filed unfixed alongside these: [#44](docs/BUGS_FOUND.md)
  (collections render as a raw address outside `Print`),
  [#45](docs/BUGS_FOUND.md) (D5's compiler half) and
  [#46](docs/BUGS_FOUND.md) (a diagnostic caret landing in a comment).

## [0.4.7] - 2026-08-20

### Fixed

- **A float at or beyond 2^63 no longer saturates when printed**
  ([#34](docs/BUGS_FOUND.md)) — `Print`, `"{x}"` interpolation, and
  `x as text` all printed `9223372036854775808.372036854775808` for
  *every* value at or past 2^63 (10000000000000000000.0 included),
  because the formatter's integer part went through `cvttsd2si`, which
  saturates to `i64::MIN`'s bit pattern past `i64::MAX` — the trailing
  digits were the fractional part of that same wrong, constant value,
  which is why they never changed. The stored double was always
  correct; only the print path was wrong. 2^63 is already far past
  2^52, the point beyond which a double's 52-bit mantissa has no room
  left for a fractional bit, so every affected value is an exact
  integer — `_print_float` and `_buffer_append_float` now detect the
  magnitude and, for that range only, extract the raw mantissa and
  exponent and produce the exact decimal digits by schoolbook
  binary-to-decimal (double the mantissa's decimal digit string once
  per bit of exponent past 52), which is exact because no floating
  point is involved past reading the bits. Values below 2^63 are
  untouched and still use the original, already-correct path.
  Deliberately **not** fixed in this pass: a nonzero float below the
  formatter's fixed 15-digit fractional precision still prints `0.0` —
  a lost-precision problem in a different part of the same routine, not
  a saturation, tracked as still-open in the register entry. Regression
  test proven to fail on the unfixed compiler on exactly the
  large-magnitude rows, with the sub-2^63, division-derived, and
  IEEE-754-rounding rows kept as controls that pass on both sides. See
  [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) #34.
- **`as a number` no longer wraps silently past i64's range**
  ([#35](docs/BUGS_FOUND.md)) — `"9223372036854775808" as a number` (one
  past `i64::MAX`) returned `-9223372036854775808` with the error flag
  never set, so `On error` could not catch it and the wrapped value was
  indistinguishable from a real one; applied to every base
  (`"ffffffffffffffffff" as a hex number` gave `-1`). Every digit in
  these inputs is valid for its base, so the documented "stops at the
  first invalid character" rule never engaged — the whole string parsed
  and the accumulator wrapped. `_parse_i64`, `_parse_int_radix`, and
  their length-bounded buffer variants in `coreasm/x86_64/int.asm` now
  accumulate the magnitude with an unsigned `mul` (which reports a
  truncated product instead of silently wrapping) and range-check the
  result against the sign at the end: a positive numeral must fit under
  `i64::MAX`, a negative one may reach `i64::MIN`'s magnitude (`2^63`) —
  the two are different bounds, so a naive "digits > i64::MAX" check
  would have wrongly flagged legitimate `i64::MIN` input, which is kept
  as a control. Either check failing sets the same error flag `On error`
  already reads for a wholly-invalid string. The returned value on
  overflow is not defined (0 or a wrapped magnitude); the flag is the
  fix. Regression test proven to fail on the unfixed compiler on exactly
  the three overflow cases, with `i64::MAX`, `i64::MIN`, a valid hex
  value, and the pre-existing `"abc" as a base5 number` raise kept as
  controls that pass unchanged on both sides. See
  [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) #35.

- **A width specifier no longer changes what a value is**
  ([#36](docs/BUGS_FOUND.md)) — `"{f:06}"` on a float printed its raw
  IEEE-754 bit pattern (`4615063718147915776` for 3.5), and on a `text`
  printed the string's **address** — silent wrong data and an
  information leak, proven by two same-content texts printing different
  numbers. The type-aware dispatch in `emit_formatted_value` was gated
  on there being *no* width, so writing one skipped the type check
  precisely when the compiler knew the type best. Non-integer types are
  now rendered by type whether or not a width is present. The width is
  not yet *applied* to floats/texts — coreasm has padding primitives
  only for integers and hex — so a width there is ignored rather than
  honoured, matching the runtime-tagged `value` path; that cosmetic
  residue is recorded in the register. Regression test proven to fail
  on the unfixed compiler on exactly the float/text/buffer rows, with
  integer and boolean width rows kept as controls that pass on both
  sides. See [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) #36.

- **A file's `readable` property now reflects its actual open mode**
  ([#37](docs/BUGS_FOUND.md)) — `readable` tested `fd >= 0`, which is
  true for any successfully opened handle, so a file opened `for
  writing` or `for appending` still reported `readable` as `1`. The
  obvious defensive idiom, `If f's readable then,` before a read, passed
  on a write-only handle and the read that followed failed at the OS
  level. `writable` already derived its answer correctly from the
  handle's recorded open mode; `readable` now shares that same source of
  truth instead of being a constant. Regression test opens one file for
  writing, appending, and reading in turn and checks `readable`,
  `writable`, and `permissions` in each mode; proven to fail on the
  unfixed compiler on exactly the writing/appending `readable` rows,
  with the `writable` rows and the constant `permissions` value kept as
  controls. See [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) #37.

- **A format string in a collection prints as text at every position, not
  just the second** ([#39](docs/BUGS_FOUND.md)) — `["{base}", "plain"]`
  printed two raw pointers (a heap address that moved under ASLR between
  runs, plus a stable rodata address) instead of `core`/`plain`; moving the
  format string to the second slot made both elements print correctly,
  which was the tell that this was a static element-type inference bug,
  not a runtime-tag bug — a named list under a plain `print each` already
  worked, but attaching a `treating` clause to that *same* list broke it
  again. `Expr::FormatString` had no arm in the three places that classify
  a list's element type from its literal shape — the `for each`/`print
  each` inline-literal inference, the named-list-declaration inference
  that feeds `treating`, and `element N of <literal>` — so each fell
  through to its generic default (`Unknown`, which for a literal is not
  the same safe fallback `Unknown` is for a named list, since a named
  list's `Unknown` widens to `Mixed` and dispatches on the still-correct
  runtime tag, while a literal's `Unknown` fed nothing and defaulted to
  `PRINT_INT`). Bug #17 fixed this same missing arm in the two functions
  that back append and general expression typing; these three siblings
  were never given it. Fixed by adding `Expr::FormatString => VarType::
  String`/`Some(VarType::String)` to all three. Regression test covers all
  nine control rows (first vs. second position in an inline literal, a
  named list with and without `treating`, `element N of`, a plain `For
  each`, escaped-braces-only, and a no-format-string `treating` list);
  proven to fail on the unfixed compiler on exactly the format-first
  inline-literal, `For each`-over-literal, and named-list-with-`treating`
  rows, with the rest passing on both sides as controls. See
  [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) #39.

## [0.4.6] - 2026-08-20

### Fixed

- **A period now closes a `Repeat` body** ([#27](docs/BUGS_FOUND.md)) — the
  construct that `Repeat N times, <actions>.` is a sentence-ending loop, the
  shape LANGUAGE.md documents for `While` and `For each`, never closed on a
  period. The continuation was silently absorbed into the loop and re-run
  once per iteration, with no error: `Repeat 2 times, print "r". Print
  "after".` printed `r after r after` (the absorbed statement run inside
  the loop) instead of `r r after`. A second symptom shared the same root:
  a comma did not separate actions in a `Repeat` body, so `Repeat 2 times,
  print "a", print "b".` was a parse error at the comma — `Repeat`'s body
  loop was missing the entire separator handling that `While`'s had. Both
  are the same gap: the spec already promised that a period closes the
  innermost open clause and that `Repeat` is one such clause, so this is a
  fix, not a feature. `parse_repeat` now shares one body loop with
  `parse_while` (factored into `parse_loop_body` so the two cannot drift
  apart again): comma continues, period closes, blank line closes, EOF
  closes. `Repeat` was also added to `parse_block`'s self-terminating
  construct list alongside `If`/`While`/`For`, so a `Repeat` that is not the
  last action in a branch no longer swallows the action that follows it.
  Regression tests cover the period-closes case, the comma-continues case,
  the blank-line-closes case (the one path that already worked, kept as a
  guard), stacked periods closing a `Repeat` nested in each of `For each`,
  `While`, and `If`, a `Repeat` inside a function followed by a statement,
  a nested `If` as the last action, and the self-termination parity case.
  Parser-only; analyzer and codegen already handled a closed `Repeat`
  correctly. See [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) #27.

- **A buffer declaration always allocates** ([#28](docs/BUGS_FOUND.md)) — a
  `buffer` declared inside an `If` body that never ran, then redeclared at
  top level, segfaulted. The second declaration emitted no allocation at
  all — only `_buffer_clear` and `_buffer_append_bytes` — because the name
  was already bound, so the only `_alloc_buffer` sat inside the branch that
  did not run and the slot still held null when the clear dereferenced it.
  It needed both halves: neither a conditional declaration alone nor a
  redeclaration alone reproduced it, and only `buffer` was affected —
  `number` and `text` in the same shape were fine, as was the sized buffer
  path, which already allocated on every declaration. Diagnosed from the
  emitted assembly rather than from the symptom: the register's original
  guess (stack garbage dereferenced by `Print`) was wrong, since the crash
  happens even when the buffer is never read. The string-initialised
  declaration now allocates unconditionally, as the sized path always did,
  while preserving sizedness — an earlier attempt that allocated a dynamic
  auto-growing buffer everywhere silently disabled fixed-size overflow
  detection language-wide, which the full suite caught and the bug's own
  matrix did not. Twelve regression tests; eight segfault on the unfixed
  compiler and the rest are controls that must pass on both sides.
  See [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) #28.

- **A string literal is data, never a name** ([#29](docs/BUGS_FOUND.md),
  [#30](docs/BUGS_FOUND.md)) — two live defects from one design
  inconsistency, both cases of a string literal being resolved as a
  variable name when a variable happened to share its text. In a list
  literal (#29) the literal took its slot type tag from the colliding
  variable: colliding with a list gave a tag that led to a wild
  dereference and a segfault, and colliding with a number tagged a string
  pointer as an integer, so it printed as `4198536` — silent wrong data,
  the worse half. Colliding with a `text` was correct only by coincidence,
  the wrong tag and the right tag being the same number. In a buffer
  initialiser (#30), `a buffer called hello is "SURPRISE".` followed by
  `a buffer called b is "hello".` printed `SURPRISE`: no crash, no
  diagnostic, just the wrong contents. Both belong to #19's family, marked
  fixed in v0.4.4 — that fix removed the pattern from five codegen sites
  and missed these two. LANGUAGE.md's grammar is unambiguous that a string
  literal is data, so this is a fix, not a change of meaning. The cure is
  narrow at each site: `tags.rs` gains an `Expr::StringLit` arm returning
  `TAG_STRING` ahead of any lookup, leaving `Expr::Identifier` alone, and
  `buffers.rs` loses its `variable_types` lookup entirely, the code
  beneath it already appending the literal's bytes correctly. Eight
  regression tests covering every row of the matrix, controls included.
  See [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) #29 and #30.

- **A `text` flag with no default reads as empty, not null**
  ([#31](docs/BUGS_FOUND.md)) — `a flag called name is "-n" or "--name",
  it is a text.` segfaulted the moment the flag was read and the user had
  not supplied it. A flag's slot was initialised to `0` whatever its
  declared type, which is right for a `number` or a `boolean` and is a
  null pointer for a `text`. A `text` flag with no explicit default now
  initialises to the empty string, so an unsupplied flag reads as `""` and
  can be tested with `is empty` the way the documented shape implies.
  See [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) #31.

- **A flag keeps its declared type inside a function body**
  ([#32](docs/BUGS_FOUND.md)) — a flag read inside a function was typed
  `boolean` whatever it had been declared as, so a `text` or `number` flag
  compared or interpolated inside a function produced wrong code. The
  analyzer held declared flags in a bare `HashSet<String>` — names, no
  types — and both type-query sites answered `Some(Type::Boolean)` for any
  name in the set. It misbehaved only inside a function body, because at
  top level the declaration's own type is still in scope and answers
  first, which is why the obvious one-line test passes and the defect
  could sit indefinitely. `flag_variables` is now a `HashMap<String,
  Type>`, populated from the declaration's `value_type`, and both query
  sites return the declared type. The regression test carries a top-level
  control alongside the function-body case to pin the diagnosis.
  See [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) #32.

- **`is empty` on a `text` tests the contents, not the pointer**
  ([#33](docs/BUGS_FOUND.md)) — `"" is empty` was always false, for
  every `text` in the language. The predicate special-cased buffers and
  lists (read the length field) and fell back to `test rax, rax` for
  everything else; a text's value is a pointer to its NUL-terminated
  bytes, which is never null, so the predicate compiled to "is this
  pointer null". Found while verifying the documentation line #31's fix
  earned — the claim that an unsupplied text flag can be tested with
  `is empty` was written, then proven false before it shipped. The spec
  already promised the predicate on a text (its own worked example uses
  `if 'output file' is empty then,`), so this is a fix, not a feature.
  A text now tests its first byte, null-safely, at both twin codegen
  sites (expression and branch forms); both sites also stop resolving a
  string literal through `variable_types` — the #19/#29 family pattern,
  removed. Not one test in the suite used `is empty` before this bug's
  regression pair. See [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) #33.

## [0.4.5] - 2026-08-19

### Fixed

- **Loop expansion now honours its documented universality.** LANGUAGE.md
  promises that `each...from` is a *universal* loop expansion that "works
  with any action," yet an argument list holding more than one `each <name>
  from <collection>` clause — or an expansion mixed with a fixed argument —
  was a parse error at the `and`. That rejection was a gap in a promise the
  spec had already made, so this is a fix, not a new feature. A call's
  argument list may now hold any number of `each <name> from <collection>`
  clauses joined by `and`, and the action runs once per element of the
  Cartesian product, row-major — the leftmost clause is the outermost loop,
  exactly as if the clauses were nested `For each` loops. `'pair' of each x
  from [1, 2] and each y from [10, 20]` calls `'pair'` four times:
  `(1,10), (1,20), (2,10), (2,20)`. There is no clause cap; a fixed
  (non-`each`) argument may sit in any position; an inner collection may use
  an outer clause's variable (triangle iteration). Arity is still checked —
  a one-value action with two `each` clauses is a compile error, not a
  concatenation (`` `print` takes one value but this sentence supplies 2
  `each` clauses. ``), which is what keeps `print each x from A and each y
  from B` from being misread. Duplicate loop variables in one sentence are a
  compile error naming the variable; an empty collection in any position
  yields zero calls; `but if` attaches to the innermost iteration and may
  reference every loop variable; each loop variable retains its
  last-iteration value after the loop. The semantics is the Cartesian
  product (matching comprehension syntax in Haskell, Python, and Rust), not
  zip — `respectively` is left as a possible future zip marker. A pure
  extension: today's spellings of the form were all parse errors.
  Parser-only; the analyzer and codegen already handled nested `For each`
  loops. See
  [docs/plans/320_grid_expansion.md](docs/plans/320_grid_expansion.md).

## [0.4.4] - 2026-08-18

### Fixed

- **The fuzzer's remaining findings, closed — the bug register is empty.**
  With 0.4.3's two segfaults, every bug vox-fuzz has reported is now
  fixed, and so is the sibling that fixing #24 uncovered.
  - **An integer literal too large for 64 bits compiled silently and
    evaluated to `0`** ([#22](docs/BUGS_FOUND.md)) — a wrong answer with
    no crash, which is the failure mode this manual says the language
    exists to prevent. It is now a compile-time error naming both the
    literal and the valid range. `9223372036854775807` still compiles.
  - **Printing a list of `arguments's all` leaked raw pointers**
    ([#23](docs/BUGS_FOUND.md)) while `element N of` read the same
    values back correctly — the payloads were sound, their type tags
    were not. Same family as #17/#18, fixed the same way.
  - **Out-of-range positional properties segfaulted**
    ([#26](docs/BUGS_FOUND.md)) — `arguments's first` with no arguments,
    `arguments's second` with fewer than two, `environment's first` and
    `last` on an empty environment, and a negative index. Each handed a
    reader a null pointer to dereference. They now set the error flag
    and yield empty text, catchable by `On error`, matching `last`,
    `name`, `all`, `raw`, and `count`, which were already correct — the
    right behaviour had been implemented next door the whole time.
  - **A string literal in a function-body `If`/`While` condition
    resolved as a variable name** ([#21](docs/BUGS_FOUND.md)) —
    `If w is not "banana"` failed with `Unknown variable: banana`. This
    one was a **regression**: an analyzer helper reintroduced the
    pre-0.3.0 quoted-token-as-identifier ambiguity that #19 removed from
    codegen, and it sat unreachable until an April cleanup widened a
    recursion guard and exposed it. The helper is deleted; a
    compile-fail test pins that genuine undeclared-identifier detection
    still works without it.

## [0.4.3] - 2026-08-18

### Fixed

- **Two segfaults, found by Vox's own fuzzer.** vox-fuzz — a fuzzer
  written in Vox — generated the programs that surfaced both, and both
  are now closed.
  - **A declaration on a conditional path read uninitialised storage**
    ([#25](docs/BUGS_FOUND.md)). A name declared inside an `On error`,
    `While`, `for each`, or `Repeat` body registered in the enclosing
    scope, but its initialising store sat behind the branch — so when
    the branch never ran, the name read a raw stack slot: a `number`
    leaked a neighbouring frame's values (one program printed `12345`
    from an unrelated function, exit 0, no warning), and a `text` was a
    wild pointer that segfaulted. The compiler now emits the type's
    default at frame setup for any such name, so a declared name always
    holds its initializer or its type's default, exactly as this manual
    has always promised. Programs where the branch *does* run are
    unaffected.
  - **Reading an unset environment variable segfaulted**
    ([#24](docs/BUGS_FOUND.md)), and `On error` could not catch it,
    because the fault preceded any error-flag write. A missing variable
    now sets the error flag and yields empty text, like every other
    fallible read.
- **Two diagnostics that pointed at the wrong thing.** The orphaned
  `Return` error now carries a source location and explains that a
  body-level `Return` closed the function early; the cross-condition
  `Unknown variable` caret now lands on the failing read rather than on
  the declaration it was complaining about, with a hint naming the
  branch rule.

### Fixed

- **Nine more reserved words are now legal identifiers** — `capacity`,
  `raw`, `all`, `first`, `last`, `second`, `size`, `length`, and
  `version`. Each was reserved as a keyword but is only special in one
  fixed grammatical position, the same contextual-keyword treatment that
  freed `count` in 0.4.2. The compiler now lexes all nine as identifiers
  and claims each by lexeme at the position where it means something,
  leaving it an ordinary variable name everywhere else:

  - `capacity` — after a possessive marker (`data's capacity`) and in the
    `with capacity N` / `of capacity N` buffer-declaration phrase.
  - `raw` — after a possessive marker (`the program's raw`).
  - `all` — after a possessive marker (`the numbers's all`) and in the
    `all the numbers from/between … to and …` range literal.
  - `first`, `last`, `second` — after a possessive marker
    (`arguments's first`, `the letters's last`, `arguments's second`);
    `second` also names the `Wait 1 second.` time unit, so
    `Set second to 1. Wait second seconds.` waits one second while `a
    number called second is 0.` compiles.
  - `size` and its synonym `length` — after a possessive marker
    (`the letters's size`, `the letters's length`); `size` also in the
    `with size N` / `N bytes in size` declaration phrases.
  - `version` — the `Library <name> version "…"` and `see <lib>
    version "…"` header sentences only.

  Each is a bare variable name everywhere except its one fixed
  grammatical position; `arguments's first` and `a number called first is
  0.` both work in the same program. The quoted forms (`'first'`,
  `'size'`, etc.), which always lexed identically to the bare forms, are
  unaffected. The reserved alias `length` (previously an alternate
  spelling of `size` in the alias table) is now a contextual keyword — a
  synonym of `size` in the possessive dispatch only — so
  `a number called length is 1.` compiles and `x's length` still means the
  same as `x's size`. See [plan 315](docs/plans/315_contextual_keyword_family.md).

## [0.4.2] - 2026-08-18

### Fixed

- **Bare `count` is now a legal identifier.** It was reserved as a keyword
  alongside `capacity`, `length`, `first`, and `last`, but the word is only
  special after a possessive marker (`arguments's count`,
  `environment's count`) or in the `the argument count` / `the environment
  variable count` phrases. A word that is special in one syntactic position
  is no longer banned from every other, so `count` is now an ordinary
  variable name — declarations, `Set`, loop variables, function parameters,
  arithmetic, conditions — while every possessive `'s count` use is
  unchanged. The compiler now lexes `count` as an identifier and claims it
  for the possessive property in the parser, the same contextual-keyword
  treatment `start`/`begin`/`stop` already get for timers. The quoted form
  `'count'` (which always lexed identically to the bare form) is unaffected.
- **`cargo install vox-lang` produced a compiler that could not compile
  anything.** Cargo copies only the binary into `~/.cargo/bin`, leaving the
  crate's `coreasm/` behind in the registry cache, so every step of the
  resolution order missed and the first compile died with `unable to open
  include file 'coreasm/x86_64/core.asm'`. The crate already ships all 21
  `.asm` files — they are inside the crates.io tarball and covered by its
  checksum — so the compiler now carries them in the binary (a `build.rs`
  walks `coreasm/` at build time, so a newly added file ships without any
  list to update) and writes them to `~/.cache/vox/<version>/coreasm` the
  first time it needs them. The tree is written to a temporary directory
  and renamed into place, so it is never observably half-written and two
  vox processes racing on first use is harmless. Nothing is downloaded, at
  build time or run time. The embedded copy is consulted **last**, after
  `VOX_CORE_PATH`, the XDG config, the system paths, the executable-relative
  search, and `./coreasm` — so an RPM install, a development tree, and
  `VOX_CORE_PATH` all behave exactly as before. See
  [plan 312](docs/plans/312_cargo_install_coreasm.md).

### Added

- **Installing vox on dnf suggests vox-libs.** The RPM carries
  `Suggests: vox-libs` — a weak dependency, so nothing is pulled in
  automatically and the compiler stays standalone, but the relationship is
  recorded where packaging tools can see it. README and INSTALL.md now
  document the libraries and where they install.

## [0.4.1] - 2026-08-18

### Changed

- **Examples for everything 0.4.0 shipped.** `examples/delivery.vox` (user-
  defined things end to end) and `examples/supervisor.vox` (fork, non-
  blocking reap, deadline, Send signal, inline status decode) are new;
  `examples/pi.vox` adopts `times`; README's feature list catches up.
- **The compiler ships no libraries.** `lib/process.vox` moved out to
  [Vox-lang/vox-libs](https://github.com/Vox-lang/vox-libs). The reaped-
  status tests decode inline, proving the feature is complete with
  nothing installed. The shared-library machinery tests are unchanged.

## [0.4.0] - 2026-08-18

**Vox has a type system.** This is the biggest release in the language's
history: as of today, a Vox program can define its own types — in plain
English, like everything else here.

```vox
A thing called point has
  a function called 'placed at',
  a number called x is 0,
  a number called y is 0.

To do the point's 'placed at', with a number called across and a number called climb.
  a point called spot.
  Set spot's x to across.
  Set spot's y to climb.
  Return a point, spot.

The corner is a point's 'placed at' with 3 and 4.
Print corner.
```

That prints `{x: 3, y: 4}` — and yes, this example compiles; every
example in this release does, checked against the compiler before
shipping.

Things nest to any depth, copy by value, print themselves, compare
field-by-field, carry their own function members, and work across files —
all resolved at compile time, with not one byte of runtime added. The
generated binaries are still just your code and syscalls.

And because a memory-safe language should have to prove it: this release
was **adversarially tested before it shipped**. A red team attacked the
type system with 38 runnable probes; it found two real holes, both were
fixed, and the exact programs that broke the compiler are now regression
tests that must fail to break it. The copy semantics survived everything
thrown at them.

Also in this release: Vox grows real process control — `Send signal`
performs `kill(2)`, `reap ... without waiting` polls without blocking,
and `the reaped status` finally tells you *how* a child died. Decoding it
lives in `lib/process.vox`, **a library written in Vox, naturally** —
not a standard library, and not something the compiler needs: `the
reaped status` hands you the raw word and any program may decode it
itself. Vox has no standard library on purpose, and the compiler runs
perfectly with none installed. A pure-Vox process supervisor
(fork, poll, timeout, kill, classify) now needs no shell and no
coreutils. Timers were caught reporting a 100 ms wait as a full second
and now measure honestly, which matters rather a lot for the benchmarking
tool this unblocks. And `Print 6 times 7.` finally does what the manual
always claimed.

The full ledger:

### Added

- **User-defined things — composite value types declared in the program.**
  A new `thing` construct lets a program declare its own composite types at
  the top level, alongside the builtins. `A thing called point has a number
  called x is 0, a number called y is 0.` declares a type `point` with two
  number fields, each defaulted by a literal of its own type; the definition
  fixes a layout for the whole program and emits no code. A thing may also
  carry function members — `a function called 'placed at'` in the body
  declares the type's callable surface (its manifest), defined separately
  with `To do the point's 'placed at', with ...`. Declarations bring a thing
  into being with `a point called origin.` or `Create a point called p.`;
  `the` reads a known one. Fields are reached by possessive chains
  (`commute's leg's start's x`), and things nest (a segment holds two
  points) under an acyclicity check: a thing may name only previously-
  defined types, so a cycle is unconstructible within a file and is proved
  out across `see`d files by the analyzer's registry DFS. Things are
  values — assignment, argument passing, and return copy the whole thing
  field by field, so mutating a copy never touches the original. A member
  is called three ways: the free call `'magnitude squared' of origin`, the
  instance possessive `origin's 'magnitude squared'` (sugar that fills the
  first parameter with the receiver), and the type possessive `a point's
  'placed at' with 3 and 4` (a maker — the article `a` because a new thing
  comes into being). A manifest member must return its own thing; its first
  parameter may be the thing (reachable by instance sugar) or not (a maker,
  reached by naming the type). Things print as `{x: 5, y: 0}` and compare
  for equality field by field. Type, variable, and function names share one
  global identifier space (first-come-first-served); each type owns a
  separate member space. Cross-file, `see "./geometry.vox".` makes another
  file's things usable — a `see` of an unreadable file is now an error (it
  was silently skipped without `-v`), and a duplicate type name across a
  `see` now errors at the second definition, naming the other file. In v1
  a field's type is `number`, `float`, `boolean`, `time`, or any previously-
  defined thing (`text`/`list`/`map`/`buffer` deferred); user things are not
  part of the runtime tag system, so there is no `is a point` predicate, and
  a `.lib` cannot yet take or return a thing across its boundary (the
  diagnostic names the fields to pass across instead). Every reserved
  wrong-shape use has a targeted message — a thing copied from or written
  as a bare value, returned as a value, interpolated into text, or put in
  order; a member returning another thing, or declared but never defined;
  a maker reached by a receiver; a members-only or field-less definition;
  a definition written with `is` instead of `has`, created as a variable,
  defined inside a block, or defined after a variable of the same name; a
  field default of the wrong type; an unknown field type. `thing`, `has`,
  and `do` are contextual keywords — claimed only inside the construct,
  ordinary identifiers elsewhere, so `a number called thing is 5.` compiles.
  See the new [Things](LANGUAGE.md#things) chapter in LANGUAGE.md. Strictly
  additive: no existing program changes meaning; the construct, its
  diagnostics, the cross-file and `.lib` refusals, and the `see` behaviour
  tightenings are all new surface. Tests: `tests/330_thing_definition.vox`
  through `tests/340_thing_see.vox` plus `tests/include/geometry.vox`, and
  the `tests/compile_fail/thing_*.err` corpus.

- **`Send signal <N> to process <pid>.` performs `kill(2)`.** A new statement
  that sends signal `<N-expr>` to the process with PID `<pid-expr>` (syscall
  62). `child` is accepted as an alias for `process`, mirroring
  `reap process/child`: `Send signal 9 to child pid.`. On success it clears
  the error flag; on failure (`ESRCH`, `EINVAL`, `EPERM`) it sets it, so
  `On error` catches the failure exactly like the other syscall statements.
  Signal 0 is the standard no-deliver existence check, useful for probing the
  error path safely. Strictly additive: no existing program changes meaning.

- **`times` is now a multiplication operator, an alias for `multiply`.**
  `Print 6 times 7.` and `Set n to n times 10.` compile and behave exactly
  like their `multiply` forms, including precedence — `Print 2 plus 3 times
  4.` evaluates to 14, multiplication still binding tighter than addition,
  identical to `2 plus 3 multiply 4.`. `times` was already a reserved
  keyword for the `Repeat <count> times,` loop, so no lexer change was
  needed; the `Repeat` count is read with `parse_primary`, which never
  reaches the multiplicative layer, so the loop construct is unaffected.
  Strictly widening: no previously-valid program changes meaning.

- **`reap ... without waiting` performs a non-blocking `wait4(2)` (WNOHANG),
  and `the reaped status` yields the raw wait-status word.** Any reap form
  (`reap any child process`, `reap process <pid>`, `reap child <pid>`) takes
  a `without waiting` suffix, which calls `wait4` with `WNOHANG` instead of
  blocking. The return value is the whole value of the form: the reaped
  child's PID if one finished; `0` if children exist but none has finished
  yet (this is **not** an error — it is how "still running" is told from
  "gone"); or a negative value with the error flag set on a genuine error
  such as `ECHILD` (no such child), catchable with `On error`. A reap that
  returns `0` reaps nothing and does not disturb `the reaped status`.
  `the reaped status` is a new expression yielding the raw `int status` the
  kernel wrote, undecoded, from the most recent *successful* reap; before
  any reap it is `-1` (a sentinel kept in `.data`, not `.bss`, so a
  `--shared` library does not read `0` and misreport "exited cleanly"). The
  compiler contains no knowledge of the wait-status encoding. `without` is
  already a reserved keyword (the `print ... without newline` token), so
  the suffix cannot be confused with a call argument, and `reaped` /
  `waiting` remain ordinary identifiers everywhere they are not these
  forms. Strictly additive: no existing program changes meaning.

- **`lib/process.vox`, a library for decoding a wait status.** Ships in
  the repo as ordinary Vox and decodes the raw wait-status word with four
  functions matching the `<sys/wait.h>` macros: `'exit code of'` (bits
  8–15), `'signal of'` (the low 7 bits), `crashed` (true if a signal
  killed it), and `'exited normally'` (true if no signal was involved).
  Pulled in with `see "./lib/process.vox".`. Decoding lives here rather
  than in the compiler so that user-defined things (plan 310) can later
  wrap a status in a `process` thing with no compiler change.

  **This is a convenience library, not a standard library, and the
  compiler does not depend on it.** `the reaped status` is complete on
  its own — it returns the raw word, and any program may decode it with
  `divide`, `modulo`, and `bit-and` without `see`ing anything. Vox
  deliberately has no standard library: the compiler must build and run
  with an empty `/usr/share/vox/lib/`, and a language that assumed a
  package were installed would have a circular dependency it could never
  pay off. That directory is a *convention for users* — a place to drop
  your own libraries and reach them by bare name — not a compiler
  requirement. (An earlier draft of these notes called this file "the
  first standard-library file". That was wrong on both counts and is
  corrected here.)

### Fixed

- **Timer `duration`/`elapsed` reported the wrong time in every unit.**
  `... in milliseconds` read whole seconds × 1000, so a 30 ms wait read 0
  and a 1.5-second wait read 1000. The bare `the timer's duration` /
  `... elapsed` forms and `... in seconds` subtracted the monotonic
  clock's *calendar second fields* (`end_sec − start_sec`) instead of the
  real elapsed time, so a 100 ms wait that straddled a second boundary
  read 1 — a tenfold error — and a 1500 ms wait read 1 or 2 depending on
  where it began. `Start` and `Stop` already captured the nanosecond
  halves into `TIMER_START_MONO_NSEC` / `TIMER_END_MONO_NSEC`; nothing
  ever read them. A new internal `TIMER_ELAPSED_NANOSECONDS` helper now
  subtracts the full timespec with borrow handling (the shape
  `TIME_ELAPSED_PRECISE` already used), handles both the stored-end path
  (timer stopped) and the still-running path (sampling `clock_gettime`
  into a stack timespec and reading `[rsp + 8]` for nanoseconds), and
  leaves a 128-bit nanosecond total in `rdx:rax`. `TIMER_DURATION_SECONDS`
  and `TIMER_DURATION_MILLISECONDS` share that helper and differ only in
  the divisor (`NANOSECONDS_PER_SECOND` vs `NANOSECONDS_PER_MILLISECOND`),
  so seconds is now true truncation of the real elapsed time and
  milliseconds is true milliseconds. The meaning of the seconds/bare
  forms is unchanged — still whole truncated seconds, never milliseconds
  — but their values are now correct and no longer depend on where the
  interval fell within a second. This unblocks the planned Vox
  benchmarking tool, which is useless when a sub-second run reads zero.
  Regression tests: `tests/350_timer_subsecond_milliseconds.vox`,
  `tests/351_timer_millisecond_boundary.vox`,
  `tests/352_timer_seconds_still_whole.vox`,
  `tests/353_timer_elapsed_while_running.vox`,
  `tests/354_timer_bare_duration_whole_seconds.vox`.

- **A reserved word used as a loop variable reported "Missing loop
  variable" instead of naming the reserved word.** `print each arg from
  argv.` failed with "Missing loop variable after 'each'" even though
  the variable was not missing — it was `arg`, which the lexer folds
  onto `Token::Argument` (an alias of the reserved keyword `argument`).
  Because the parser saw a keyword token where it expected an
  identifier, it reported the variable as absent and sent the reader
  hunting for a syntax error that did not exist. Both each-loop variable
  sites (`each <var> from ...` and `for each <var> from ...`) now
  delegate to the existing `check_not_keyword` diagnostic when the token
  in the variable slot is a keyword, so the message names the spelling
  the user actually typed and notes that `arg` is an alternate spelling
  of `argument`. A genuinely omitted variable is still reported as
  "Missing loop variable": the loop's own `from`/`between` delimiters
  are excluded from the keyword check, so `print each from argv.` keeps
  its existing message. Diagnostics only — the program is still
  rejected, just with an accurate reason. No words were un-reserved and
  no loop semantics changed. Regression tests:
  `tests/compile_fail/087_reserved_word_each_loop_variable.vox`,
  `tests/compile_fail/088_reserved_word_for_each_loop_variable.vox`,
  `tests/compile_fail/089_missing_loop_variable_keyword_delim.vox`, and
  `tests/322_each_loop_reserved_word_regression.vox` (the renamed form
  still compiles and iterates).

## [0.3.7] - 2026-08-16

### Changed

- **`begin`, `stop`, and `finish` are no longer reserved words.** They now
  behave exactly like `start` always did: the parser claims them for a timer
  statement only when a name operand follows (`Start the t.`, `stop t.`),
  and everywhere else they are ordinary identifiers — `a number called stop
  is 0.` now compiles instead of being rejected as a reserved keyword. The
  timer dispatch also gained that one-token lookahead for all four words, so
  a program can define and call its own zero-argument `start.`/`stop.`
  function; previously a bare `start.` was swallowed by the timer parser and
  died with "Expected timer name". Strictly widening: no previously-valid
  program changes meaning.

- **The compiler source is reorganised into focused modules.** Each
  compilation phase was a single very large `mod.rs` — codegen 11,061 lines,
  parser 7,224, analyzer 4,032, lexer 1,091 — which made the code hard to
  navigate, review, and contribute to. Every phase is now a directory of
  topical modules (for example `codegen/expr.rs`, `codegen/tags.rs`,
  `parser/control_flow.rs`, `analyzer/scope.rs`), with `mod.rs` reduced to
  the phase's type, shared constants, and module declarations: 494, 205, 200,
  and 52 lines respectively. This is **pure code motion — no behaviour
  change**. Every step was verified by compiling the whole example and test
  corpus and confirming the emitted assembly stayed byte-identical to the
  pre-refactor compiler's, alongside the full test suite. Nothing about the
  language, the CLI, or any public interface changes; the difference is
  purely that the source is now navigable.

### Fixed

- **Appending a format string to a list stored a corrupt element** (BUGS_FOUND
  #17). `append "fmt {x}" to out.` — and a `text` local initialized from a
  format string and appended by name — wrote the element's runtime type tag
  as plain integer instead of text, because neither the pre-scan nor the
  emit-time tag selector recognised `Expr::FormatString` as always producing
  text. Reading the corrupted element (whole-list print, `element N of`, or
  `for each`) then reinterpreted a valid string pointer as an integer:
  sometimes a raw pointer address printed in place of the text, sometimes a
  crash, depending on what surrounding code did with the misread value. Fixed
  by teaching both the pre-scan (`prescan_expr_tag`) and the emit-time
  fallback (`infer_expr_type`) that a format string is always `text`.
  Regression tests: `tests/bugs_found_17_format_append_text.vox`,
  `tests/bugs_found_17_format_append_number.vox`,
  `tests/bugs_found_17_format_append_buffer.vox`,
  `tests/bugs_found_17_format_append_named.vox`,
  `tests/bugs_found_17_element_access.vox`, `tests/bugs_found_17_for_each.vox`,
  plus three codegen unit tests pinning the tag write and the no-spurious-
  widening behaviour.

- **The `.lib` table of contents under-reported list element types for
  provably-`text` elements** (BUGS_FOUND #18). A `--shared` build's element-
  type scan credited only a direct literal or a parameter's declared type,
  so a `text` local's declared type, a called function's declared `text`
  return, and a format-string append (once #17 made the element itself
  sound) all shipped as plain `list` instead of `list of text`, even though
  the runtime tagger already agreed on `text` and consumers already printed
  correctly. The scan now credits all three. A genuinely mixed or
  evidence-free list is unaffected — still plain `list`. Regression tests:
  `plan_303_local_declared_type_credits_element_parameter`,
  `plan_303_call_declared_return_type_credits_element_parameter`,
  `plan_303_format_string_credits_element_parameter`,
  `plan_303_newly_credited_shapes_in_return_position`,
  `plan_303_function_call_return_type_scoped_per_library`,
  `plan_303_local_declared_type_conflict_stays_unknown`.

- **A string literal's content was silently resolved against known variable
  (or top-level constant) names at codegen time** (BUGS_FOUND #19). The
  crash form: `a text called x is "x".` reads `x`'s own not-yet-written slot
  instead of the literal (its declared type is registered before its
  initializer is generated), segfaulting on first use. The much wider,
  silent form: `a text called greeting is "hello". a text called b is
  "greeting". Print b.` printed `hello`, not `greeting` — any literal whose
  text coincides with any in-scope variable's name, in an initializer or a
  bare `Print "literal".`, silently took that variable's value instead, and
  a literal matching a `float`/`buffer` variable's name could flip an `is a`
  type predicate or an equality comparison's codegen strategy. Every
  `Expr::StringLit` codegen site now treats its payload as text
  unconditionally, with no variable-table or constant-table lookup on its
  content — matching LANGUAGE.md's post-0.3.0 rule that a double-quoted
  token is data everywhere, never a name. Identifier-based resolution (bare
  and single-quoted names, map lookups, `{name}` format-string
  interpolation) is unchanged. Regression tests:
  `tests/bugs_found_19_self_name_initializer.vox`,
  `tests/bugs_found_19_other_name_initializer.vox`,
  `tests/bugs_found_19_other_name_print_direct.vox`,
  `tests/bugs_found_19_predicate.vox`.

- **Comparing a `text`/`buffer`/string literal to a `number`, `float`,
  `boolean`, `list`, or `map` for equality dereferenced the non-stringy
  operand as a string pointer** (BUGS_FOUND #20). `If "abc" is equal to 3.5
  then, ...` segfaulted with no variable or name collision involved at all;
  `list`/`map` operands didn't crash but gave a wrong answer via a suspected
  out-of-bounds read. Pre-existing, but the #19 fix made it commonly
  reachable: a literal that happens to share a variable's name (e.g. `"pi"
  is equal to pi`) previously took a different, wrong-but-non-crashing path
  by accident, and now correctly reaches this one. Comparing a stringy
  operand against a *provably* non-stringy one now folds to a compile-time
  constant (`is equal to` → false, `is not equal to` → true) without
  evaluating either operand; `text`/`buffer` comparisons, and comparisons
  involving a dynamic `value` operand, are unaffected. Regression tests:
  `tests/bugs_found_20_no_collision.vox`, `tests/bugs_found_20_float_collision.vox`,
  `tests/bugs_found_20_number_boolean_list.vox`, `tests/bugs_found_20_not_equal.vox`,
  `tests/bugs_found_20_buffer_text_positive.vox`, `tests/bugs_found_20_return_position.vox`.

- **`End` is no longer documented as a timer-stop spelling.** It never
  worked: `end` lexes into the `exit` keyword family, so `End the t.` was a
  parse error despite LANGUAGE.md listing it beside `Stop`/`Finish`. The
  spelling list now matches the compiler.

### Documentation

- **Documented how to close more than one level of nesting.** A period closes
  one open clause and a blank line closes every open clause, but nothing
  described the space between them: periods stack, so N periods close N
  levels. This is also how an author chooses which `if` an `Otherwise` or
  `But if` continues — an else-chain continues the innermost `if` still open,
  so closing that `if` first hands the branch to the enclosing one, a
  one-character difference in the source. Undocumented, this was easy to get
  wrong in a way that produces no error: too few periods and following
  statements are absorbed into a clause the author believed was closed, and
  if one of them is a loop's increment the program hangs silently. LANGUAGE.md
  gains a *Closing more than one level* section with worked examples at one,
  two and three periods, the equivalent empty `Otherwise,.` form, and
  `tests/nested_clause_close_levels.vox` pins the behaviour. No compiler
  change: the parser was correct throughout.

- **A "Projects built with Vox" section in the README.** Lists actively
  developed FOSS projects written in Vox, with an invitation to add yours by
  emailing vox-lang@tegosec.com.

- **A design document and implementation plan for the module split**
  (`docs/MODULE_SPLIT_DESIGN.md`, `docs/plans/306_module_split.md`), recording
  the strategy and the procedure the refactor below followed.

## [0.3.6] - 2026-08-14

### Added

- **`but if` is now a general conditional branch.** Both the default action
  and each branch action may be any valid statement, in the plain form and in
  loop expansion — previously only `print` (and, outside loop expansion,
  `append`) could carry a `but if`, and anything else was rejected with
  "'but if' conditional branching only works with print statements". A branch
  body is parsed with the ordinary statement parser rather than a
  per-statement-kind grammar, so new statement kinds gain `but if` support
  automatically. The terse `append <value>` form, which inherits its target
  from the base statement, still works, and a branch naming a different list
  or buffer than the base is still a compile error.

- **In-place retyping for `value` variables.** The statement
  `<valuevar> is a <type>.` converts a `value` variable in place and updates
  its runtime tag. Supported targets are `number`, `float`/`decimal`, `text`,
  and `boolean`; the conversion follows the same rules as the static cast
  table. The same phrase in condition position (`If v is a number then, ...`)
  remains a type predicate. A failed runtime conversion sets `_last_error` and
  leaves the variable holding `0` so `On error` can catch it; retyping a
  statically-typed variable is a compile error with a remedy pointing at the
  explicit cast.

- **A warning when a function is still open at end of file.** A function body
  is closed by a blank line, so without one the rest of the file is read as
  part of the body and the program silently does nothing. The compiler now
  points at the function definition instead of compiling a do-nothing binary
  in silence. Suppressed for `Library` files and `--shared` builds, where a
  trailing function ending at EOF is correct by construction. This is a
  diagnostic only — the parsing behaviour is unchanged.

- **A `type` property on every variable.** `<var>'s type` returns a text
  description of the variable's declared type, e.g. `Number (static)` for a
  `number` or `Text (dynamic)` for a `value`. Statically-typed variables fold
  to a compile-time literal; `value` variables dispatch on the runtime tag
  already kept in their shadow slot or BSS mirror. Intended for debugging and
  logging — type tests still use the `is a <type>` predicate.

### Fixed

- **Seven compiler bugs found while building a JSON library**, all with
  regression tests:
  - A `float` interpolated into a `text`/`buffer` destination
    (`a text called t is "{y}".`) printed the raw IEEE-754 bit pattern
    instead of the number.
  - `buffer as text` returned the buffer's struct pointer rather than its
    character data, so the cast silently produced an empty string.
  - Extracting a `float` from a `value` by reassignment (`the y is v.` /
    `Set y to v.`) produced the raw bit pattern; only declaration with an
    initializer worked. A `value` source no longer overwrites the
    destination's declared type.
  - Extracting a `list` from a `value` produced a bogus pointer and a length
    of `-1`, while the same extraction into a `float` or `map` worked.
  - **Assignments to a top-level variable inside a function did not persist,
    and could read another function's local.** Top-level `number`, `float`,
    `text`, `boolean`, `buffer`, and `value` variables now live in one storage
    location shared by top-level code and every function, so a write inside a
    function is visible after it returns. Previously such a write allocated
    an uninitialised per-call stack slot, so a counter could read an
    unrelated function's local instead of its own value. For `value`
    specifically, its runtime type tag is stored alongside the payload in its
    own shared location too, kept paired with it on every read and write, so
    the value keeps behaving as the type it currently holds — not just an
    integer that happens to round-trip. Declaring a variable of the same name
    inside a function still shadows the global, and recursion still gets
    per-call locals.
  - A map key taken from `map's keys` never matched on lookup, always
    returning the not-found sentinel, even though the key printed correctly.
  - Chaining an index over a property read (`element 1 of m's values`)
    produced garbage; the same read split across two statements was correct.

- **A `but if` chain was closed by a period belonging to a nested clause, so
  every later branch was silently lost.** A period closes only the innermost
  open clause, but a `but if` branch consumed one that belonged to a clause
  *inside* it — most visibly an `On error` handler attached to a fallible
  action in the branch. A dispatch loop giving each branch its own failure
  handling ran only its first branch, with no error; the same structure
  without `On error` produced a misattributed `Unknown variable` error
  pointing at an unrelated, valid line. A branch body is now parsed as a
  block, like an `If` branch, so it can hold its own trailing clause, and a
  period followed by `but` continues the chain instead of ending it. A period
  that genuinely ends the chain still ends it.

- **Reassigning a `value` that held a `float` to an integer left the static
  type stale at `float`.** The runtime tag was written correctly, but declaring
  `a value called v is 3.5.` let the initializer's type-inference demote the
  `value` from its `Mixed` (runtime-tagged) type to a concrete `Float`, so
  every later read dispatched on the stale static type instead of the tag:
  `Print v` emitted `PRINT_FLOAT` and reinterpreted the integer `1` as the
  denormal `0.0`, and `If v is a number` folded statically to false. A declared
  `value` now keeps `Mixed` through its initializer — the same guard the
  bare-assignment arm already had — so reads dispatch on the runtime tag as
  intended. Covers all three assignment spellings (`Set v to`, `the v is`,
  `v is`) and a function reassigning a top-level `value` global.

- **A declared-but-uninitialized `text` variable held a null pointer, so
  printing, interpolating, or comparing it segfaulted the process on the
  first read** (`a text called ex.` / `Create a text called ex.`, then
  `Print ex.`). Every other default-initializing type had a real, safe
  default; `text` fell through to a generic zero-fill that later reads
  dereferenced. An uninitialized `text` now points at a real, shared empty
  string, so it reads, prints, and interpolates as `""` and can be
  reassigned normally afterward.

- **`Create a TYPE called NAME.` (and the bare `a TYPE called NAME.` form
  with no initializer) now default-initializes every declarable type
  uniformly**, routed through one shared type resolver instead of a
  hardcoded subset. Previously only `number`, `text`, `boolean`, and
  `buffer` default-initialized this way; `float`, `list`, `map`, `value`,
  and `timer` now do too. `file` and `time` still require an explicit
  initializer — a default value would be meaningless for either (no path
  to open, no timestamp to hold) — and are rejected at compile time with a
  message naming what to supply.
  - An uninitialized `value` now defaults to `nothing`, not the number `0`.
  - An empty `map` now prints `{}`, not `{`.

### Changed

- **A reserved-word error now names the word you wrote.** Declaring a
  variable called `length` reported that `'size'` was reserved, because the
  lexer canonicalises the alias before the check runs. It now reads
  "Cannot use 'length' as a variable name" and explains that `length` is an
  alternate spelling of `size`. `length`/`size` is also documented in the
  reserved-alias table.
- **An unmatched `{` in a string literal has a real diagnostic.** It
  previously failed with an empty-named `Unknown variable: `; it now names
  the unmatched brace and points at `{{` / `}}` as the literal-brace escape.
- **LANGUAGE.md's blank-line rule corrected.** It claimed a blank line after
  a function definition was "a style convention, not a requirement". A blank
  line is in fact the only thing that closes a function body.

## [0.3.5] - 2026-08-11

### Fixed

- **Nine compiler bugs found while building a JSON library**, all with
  regression tests:
  - `Print` on an inlined float-returning call no longer prints the raw
    bit-pattern.
  - `Return a boolean, A and B.` now parses and evaluates correctly even
    inside an `If` branch.
  - A nested, self-terminated `If ... .` no longer closes the outer statement
    early (both `If` branches and `While` bodies).
  - A function call in an arithmetic expression now binds tighter than the
    surrounding operator instead of absorbing it as an argument.
  - Same-named locals in different functions no longer corrupt each other's
    list/element-type inference.
  - Reading an element (or iterating with `For each`) from a bare `list`
    parameter now preserves the per-slot runtime type tag.
  - `{{` and `}}` in string literals now collapse to literal `{` and `}`.

## [0.3.4] - 2026-08-09

### Fixed

- **A `but if` branch on a non-`print` action (e.g. `append`) could silently
  discard the rest of the program.** The branch's grammar didn't consume a
  trailing `to <name>` clause, which desynced the parser into treating
  everything after it as the body of a bogus, never-called function. This
  was a regression: the previous release rejected the same source with a
  compile error instead of silently discarding it. It's a compile error
  again if the branch names the wrong target, and consumed correctly
  otherwise.

- **A function could only declare a handful of parameter and return types.**
  `number`, `float`, `text`, `boolean`, `list`, `map`, `buffer`, `file`,
  `time`, `timer`, and `value` now all work identically as a parameter type
  and a declared return type, for ordinary functions and for shared-library
  (`.lib`) functions alike. Previously only five of these were accepted as a
  return type at all, and `float`/`time`/`timer` weren't accepted anywhere.

- **A list returned or passed across a `.lib` boundary printed raw memory
  addresses instead of its actual contents.** The list's length and
  structure always crossed correctly; only its element type was lost. The
  compiler now infers a list's element type from the exporting function's
  own code and carries it across the boundary automatically, for every call
  shape - no new syntax required.

## [0.3.3] - 2026-08-08

### Fixed

- **Reassigning a variable to a value of a different type could silently
  produce a wrong number, or segfault** — the compiler's tracked type for a
  variable could disagree with what the variable actually held at runtime,
  and formatting/printing code trusted the tracked type. Depending on the
  direction of the mismatch this either printed a pointer address as if it
  were a number, or dereferenced a raw number as if it were a string
  pointer and crashed:

  ```
  a number called n is 5.
  n is "abc".
  Print "{n}".        -> printed a garbage number; could also segfault
                          depending on which way the mismatch ran
  ```

  A variable's type is now fixed at its declaration and never changes. A
  write that would change it — `n is "abc".`, `the n is "abc".`, or `Set n
  to "abc".`, and reusing an already-declared name as a loop variable, an
  `open ... called` target, or an `Allocate ... for` target — is now a
  compile error instead:

  ```
  n is "abc".   -> error: cannot assign text to 'n', which is a number
                    help: convert it explicitly:  n is "abc" as a number.
  ```

  **If a program you have relies on this**, convert the value explicitly
  with `as a number` / `as text` / `as a float` / `as a boolean` at the
  point of assignment — this syntax already existed and is unchanged. A
  variable declared `a value called x` is unaffected and keeps accepting
  any type, as documented.

  This also closes several related cases with the same root cause:
  incrementing or decrementing a text variable, a declaration inside an
  untaken `If`/`Otherwise`/`While`/`Repeat`/`for` branch or an `on error`
  handler that never fires, a nested declaration that reuses an outer
  variable's name with a different type, and reading a mismatched value out
  of a map whose value type is provable from its own literal.

## [0.3.2] - 2026-08-07

### Fixed

- **A function call inside an explicit `{...}` group failed to parse when the
  enclosing statement had reserved `of` or `to` for itself** — most visibly,
  `byte {<call>} of <buffer>` and `element {<call>} of <list>` rejected any
  function call in the braces, even a single-argument one, so a program had
  to precompute the index into a local variable first instead of writing it
  directly.

  ```
  byte {ci of 1 and 2} of b     -> error: Expected a statement, got And
  ```

  The connector-precedence fix in 0.3.0 reserved `of`/`to` for the duration
  of parsing an index or bound, so an identifier immediately followed by that
  word couldn't swallow the enclosing statement's own connector. But the
  reservation wasn't cleared when parsing entered an explicit `{...}` group —
  even though the closing brace already unambiguously ends the group, leaving
  nothing left to protect. It now correctly parses:

  ```
  byte {ci of 1 and 2} of b     -- compiles and evaluates correctly
  ```

## [0.3.1] - 2026-08-07

### Fixed

- **A `.lib`'s declared return type silently dropped to void** for any
  function whose `Return` was not its first statement — the common case for
  any function with real logic before returning. `Return`'s type is parsed by
  two different code paths depending on where it sits in the function body;
  only one of them fed the parsed type back into the function's declared
  return type. A library's own interface file could describe a function as
  returning nothing when it genuinely returned a value.

  ```
  To gb with a number called x.
    a number called y is x add x.
    Return a number, y.
  ```

  Before this fix, the emitted `.lib` read `To gb with a number called x.` —
  no `, returning a number` clause. It now correctly reads `To gb with a
  number called x, returning a number.`

## [0.3.0] - 2026-08-07

`"..."` is now always a string literal — never an identifier. Names are bare
words (`total`), or `'single quoted'` when they contain spaces
(`'total items'`). This closes the single overload that has caused this
project's worst defects: `a number called "x" is "get five".` used to
silently parse a function call as a string and print a stray pointer instead
of calling anything. The "Names and strings" section of `LANGUAGE.md` is the
full guide.

> **Breaking.** Every existing `.vox` program that names anything the old way
> (`a number called "x" is 5.`, `To "greet".`, `print "greet" of 3.`,
> `Library "lib" version "1.0".`) now fails to compile, with a diagnostic
> telling you the correct replacement. There is no compatibility window.
>
> | Before | After |
> |---|---|
> | `a number called "x" is 5.` | `a number called x is 5.` |
> | `a number called "total items" is 5.` | `a number called 'total items' is 5.` |
> | `To "greet" with a number called "n".` | `To greet with a number called n.` |
> | `print "greet" of 3.` | `print greet of 3.` |
> | `Library "mathkit" version "1.0".` | `Library mathkit version "1.0".` |
>
> **Unchanged, still double-quoted** — these were never names: map keys
> (`person's "name"`), file/library paths (`see "./utils.vox"`,
> `from "./lib.lib"`), flag aliases (`"-v"`), and version strings
> (`version "1.0"`).
>
> A mechanical migration tool ships in this repo at
> `tools/migrate-identifiers`; it rewrote this project's own 250+ file test
> corpus and is a reasonable starting point for a large program, though its
> output should be reviewed.

### Fixed

- **A function call could silently misparse as a string literal**, printing a
  raw pointer instead of calling anything — `a number called x is "get
  five".` compiled and ran, printing something like `4198480`. The old
  grammar (`name ::= string | identifier`) made this possible in any position
  a name was expected; it no longer exists.
- **The same defect shape, independently, in `element N of`.** `element 1 of
  "no such thing".` compiled and printed `0` — a string naming nothing was
  silently treated as an out-of-bounds access rather than rejected. Bare
  string literals are now rejected in this position with a clear diagnostic.
- **A value-typed parameter's runtime type tag could leak across function
  definitions.** If two functions in the same file reused a parameter name
  (e.g. both taking a parameter called `x`), a later string literal that
  happened to equal that name could be misread as a stale value tag instead
  of literal data. `variable_types`/`mixed_tag_slots` are now scoped per
  function, matching how ordinary variables already were.
- **A `.lib`'s declared return type was silently dropped to void** for any
  function whose `Return` was not its first statement — the common case for
  any function with real logic before returning. The library's own interface
  file described a function as returning nothing when it returned a value.
- **`to`/`of`/`with` as universal call connectors collided with grammar that
  already used those words** — `Set x to 1.` followed later by `x` used as a
  range bound, `append ... to`, and `element N of`/`byte N of` with a
  variable index could all misparse as function calls, consuming a token that
  belonged to the enclosing statement.

### Added

- **`docs/check-samples.sh`** — extracts every runnable code sample from
  `LANGUAGE.md`, compiles it against the built compiler, and reports honest
  pass/fail/skip counts with an internal consistency check (`checked +
  skipped` must equal the real number of samples). Every sample in the
  language reference is now verified to actually compile, not merely
  asserted to.
- **A C-interoperability test** confirming a Vox `--shared` library is
  genuinely callable from C: a built `.so` has zero `NEEDED` entries
  (freestanding), exports the documented mangled symbol names, and a C driver
  linked against it produces the exact expected output.
- **`tools/migrate-identifiers`** — the mechanical migration tool described
  above, with its own test suite (idempotent, byte-identical on
  already-canonical input, preserves the semantic meaning of blank lines
  between function definitions).

## [0.2.0] - 2026-08-03

A Vox program can now call a Vox library. Build a library with `--shared`,
then consume it from another Vox program with
`see "<lib>" version "<ver>" from "<path>.lib".`. The "Shared libraries"
section of `LANGUAGE.md` is the full guide.

> **Breaking.** This release breaks three things a non-Vox consumer, a
> `--shared` build, or a stale `see` can depend on. Each is detailed under
> `### Removed` and `### Changed` below; the summary:
>
> 1. **Every exported library symbol is renamed** to `<lib>_<version>_<func>`
>    (e.g. `add_two_numbers` → `mathkit_1_0_add_two_numbers`), with no
>    unmangled alias. Any C/Rust/assembly consumer must update its `extern`
>    declarations and relink.
> 2. **`--shared` now requires a `Library` declaration.** Add
>    `Library "name" version "x.y".` at the top of the library source.
> 3. **Three `see` forms that silently linked nothing are now compile
>    errors.** Switch to `see "<lib>" version "<ver>" from "<path>.lib"`.
>
> Upgrading from before 0.1.23? Two earlier breaking changes are documented
> under their own releases below: arithmetic on a text/buffer/list/file now
> errors with a cast suggestion (`0.1.21`), and `.en` source includes no
> longer inline — use `.vox` (`0.1.23`).

### Removed

- **Three `see` forms that silently linked nothing are now compile errors.**
  `see "./path.so".`, `see "lib" version "1.0" from "./path.so".`, and
  `see "./path.so" for "lib" version "1.0".` previously compiled while linking
  nothing — every call into the library was simply missing, with no warning.
  They now error and name the canonical form
  `see "<lib>" version "<ver>" from "<path>.lib".` (the `see ... for ...` form
  has its own diagnostic). A previously *silent* failure is now loud — that is
  the point of the change, not a regression. If a build breaks here, build the
  library with `--shared` (which writes the `.lib` beside the `.so`) and point
  `see` at the `.lib`.

### Changed

- **Every exported library symbol is renamed.** Labels are now
  `<library>_<version>_<function>` — for example `add_two_numbers` becomes
  `mathkit_1_0_add_two_numbers`, and `greet` becomes `mathkit_1_0_greet`.
  There is deliberately **no unmangled alias**: an alias would let two versions
  of one library collide in the same `.so`, which is exactly what the scheme
  exists to prevent.

  If you call a Vox library from C, Rust, or assembly, update your `extern`
  declarations and relink:

  ```nasm
  ; before
  extern add_two_numbers
  extern greet
  ; after
  extern mathkit_1_0_add_two_numbers
  extern mathkit_1_0_greet
  ```

  Find the new names for any library you have with:

  ```bash
  $ nm -D --defined-only libmathkit.so
  00000000000005c4 T mathkit_1_0_add_two_numbers
  00000000000005f9 T mathkit_1_0_greet
  ```

- **`--shared` now requires a `Library` declaration.** A `--shared` build
  with no `Library` line has no identity to mangle with and no `.lib` to emit,
  and now errors:

  ```
  error: A shared library must declare its identity with a `Library`
  declaration giving its name and version — without one there is no mangling
  and no `.lib`. Add `Library "name" version "x.y".` before the function
  definitions and rebuild with --shared.
  ```

  Add `Library "name" version "x.y".` at the top of the library source.

### Added

- **Consuming a library from Vox.** `see "<lib>" version "<ver>" from
  "<path>.lib".` resolves the `.lib`, selects the block matching name *and*
  version, verifies every promised symbol against the `.so`'s dynamic symbol
  table (a stale `.lib` is a compile error, not a runtime crash), registers
  the signatures so calls type-check, and links the `.so` with an `-rpath`.

  ```vox
  see "mathkit" version "1.0" from "./libmathkit.lib".

  a number called "sum" is "add two numbers" of 3 and 4.
  Print the sum.
  ```

- **The `.lib` interface file.** A `--shared` build writes `<output>.lib`
  beside the `.so` — the library's name and version, the `Location` of its
  `.so`, and a table of contents of every exported function's signature. It is
  the only place Vox types live; a `.so` carries mangled names but no types.

  ```
  Library "mathkit" version "1.0".
  Location "./libmathkit.so".

  Table of Contents:
      To "add two numbers" with a number called "a" and a number called "b", returning a number.
      To "greet".
  ```

- **Several libraries — and several versions of one library — in one `.so`.**
  `vox a.vox b.vox --shared -o lib.so` links multiple libraries in a single
  link step (you cannot append to a linked `.so`). Two versions of the same
  library coexist with distinct mangled symbols, so a consumer can keep
  calling `mathkit_1_0_add_two_numbers` after `mathkit_2_0_add_two_numbers`
  ships beside it, with no recompile. Duplicate `<library, version>` pairs
  across inputs are rejected; multi-input is `--shared` only.

- **Consumption diagnostics.** Each failure mode is its own error naming the
  file and what was expected: a missing `.lib`; no such library in it (with the
  libraries it does declare); a version mismatch (listing the versions
  offered); a missing `.so` at `Location`; a stale `.lib` promising a symbol
  the `.so` does not export (naming the mangled symbol); and an arity or type
  mismatch at the call site (naming the library and version).

## [0.1.24] - 2026-08-03

Compiler fixes. No breaking changes.

### Fixed

- **`append each x from <list> to <dest>`** no longer has its destination
  eaten by range parsing. A list source `[1, 2, 3]` now appends `[1, 2, 3]`,
  while the range form `append each n from 1 to 5 to rl` still appends
  `[1, 2, 3, 4, 5]`.
- **`append <expression> to <list>`** now parses its value with full
  arithmetic. Appending a computed value in a loop works — `append i multiply i
  to squares` across `i` from 1 to 5 now yields `[1, 4, 9, 16, 25]`.
- **A timer's `start time` and `end time`** now parse through the reserved
  `time` keyword, so `Print the "job timer"'s start time.` and `... end time.`
  work as documented and return unix timestamps.

### Changed

- **`VOX_CORE_PATH` is the documented environment variable** and
  **`~/.config/vox/config` the documented config path.** The older
  `EC_CORE_PATH` and `~/.config/ec/config` still work as deprecated aliases:
  the `vox` name wins when both are set, and a one-line deprecation note is
  printed (on stderr, at the start of the build) when only the old name is
  found. Existing shell profiles and CI that set the old name keep working;
  migrate when convenient. Note that the note on stderr can surface in builds
  that capture stderr and expect it empty.

## [0.1.23] - 2026-07-31

Collections, maps, the `nothing` value, and the shared-library foundation.

> **Breaking.** `.vox` is now the sole source extension: a `see` of a `.en`
> source, which was the only include form that worked before, no longer
> inlines (silently — the call site errors "Unknown function"). Switch `.en`
> includes to `.vox`. The main input still accepts any extension. See
> `### Changed` below.

### Added

- **Whole-list printing.** `Print <list>` renders the list (`[1, 2, 3]`), and
  `{list}` format interpolation routes the same way. Previously printing a
  list showed only the first element.
- **Mixed-type lists with per-slot type tags.** A list may hold number, text,
  decimal, and boolean together; each element carries a one-byte runtime tag
  and reads back as its own type. A list the compiler can prove homogeneous
  keeps an untagged fast path; one it cannot prove widens to mixed by default
  ("static is a proof, mixed is the default"), so an opaque value — e.g. a
  function result with no declared return type — is never silently reinterpreted.
- **Nested lists.** A list element may be a list; printing is recursive and
  cycle-safe (capped at depth 64).
- **Type predicates.** `is a number/text/decimal/boolean/list/map` (and
  `is not a …`) read the runtime type tag and fold at compile time on a
  statically-typed value.
- **The `value` type.** A declared dynamic type that carries its runtime tag
  across a function call, so one function can accept "whatever this slot
  holds" and ask `is a …` inside. A `value` is rejected from arithmetic until
  its type is checked.
- **`nothing` (the absent value).** `null` and `nil` are accepted spellings.
  It sits in a list, map, or `value` slot, prints as `nothing`, and is tested
  with `is nothing`. It is not `0`: `0 is nothing` is false.
- **Maps.** Key/value collections — JSON objects. `{"key": value}` literals
  (empty `{}`), `map's "key"` read, `set map's "key" to value`, `length`/
  `empty`/`keys`/`values`, recursive printing. A missing key sets the error
  flag (it is an error, not `nothing`); keys are text only.
- **Shared-library foundation.** `--shared` builds a self-contained,
  position-independent `.so` a C or assembly caller can reach; only the
  library's own functions are exported (runtime symbols are kept out of the
  dynamic table), and an empty `--shared` export is rejected. (Consuming a
  library from Vox via `see` of a `.lib` arrives in 0.2.0.)

### Changed

- **`.vox` is the sole source extension.** `see` of a `.vox` source now
  inlines correctly — the include gate previously matched `.en`, so
  `see "./foo.vox".` was silently skipped and the call site errored "Unknown
  function". The `.en` form, which was the one that worked, no longer inlines;
  switch `.en` includes to `.vox`. The main input still accepts any extension.
- **`nothing` is refused in arithmetic.** A literal `nothing` in arithmetic
  is a compile error — "Cannot use nothing in arithmetic; check it with 'is
  nothing' first" — and a `nothing` that turns up at run time (read from a map
  or a mixed list) sets the error flag so `on error` catches it. `nothing` is
  new in 0.1.23, so this is a safe default, not a change to code that used to
  work: there was no `nothing` to put in arithmetic before.

### Fixed

- **Maps own their keys.** The map copies each key on insert rather than
  borrowing the caller's text. No current Vox program could break the old
  borrowing — keys are text literals and buffers are rejected as keys — but a
  dynamic key would have corrupted the entry; a forward correctness fix.

## [0.1.22] - 2026-07-31

A hardening release with one user-visible fix.

### Fixed

- **Function-parameter type labels no longer leak to the top level.** A
  parameter named like a top-level variable previously relabeled it: after
  `To "show" with a text called "x"`, top-level arithmetic on a number `x`
  was falsely rejected as text arithmetic. The parameter's type is now
  scoped to its function body.

## [0.1.21] - 2026-07-28

Heterogeneous lists, type-checked arithmetic, and buffer-safety fixes.

> **Breaking.** Arithmetic on a text, buffer, list, file, or timer now
> errors with a cast suggestion. Such code previously compiled to pointer or
> handle arithmetic and produced a wrong number at runtime. Add a cast where
> you meant a numeric conversion. See `### Changed` below.

### Added

- **Heterogeneous lists with per-slot type tags.** A list may hold mixed
  types (number, text, decimal, boolean); each element carries a runtime type
  tag and reads back as its own type. (Whole-list printing, the `value` type,
  type predicates, maps, and `nothing` follow in 0.1.23.)

### Changed

- **Arithmetic operands are type-checked.** Using a non-numeric value — a
  text, buffer, list, file, or timer — in arithmetic is now a compile error
  naming the value and suggesting a cast (`as a number` / `as a float`).
  Previously such code compiled to pointer or handle arithmetic and produced
  garbage at runtime. Add a cast where you meant a numeric conversion.

### Fixed

- **A genuine fixed-buffer overflow is an error**, not silent data loss.