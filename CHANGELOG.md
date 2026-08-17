# Changelog

All notable changes to Vox are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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

- **`lib/process.vox`, the first standard-library file.** Ships in the
  repo as ordinary Vox and decodes the raw wait-status word with four
  functions matching the `<sys/wait.h>` macros: `'exit code of'` (bits
  8–15), `'signal of'` (the low 7 bits), `crashed` (true if a signal
  killed it), and `'exited normally'` (true if no signal was involved).
  Pulled in with `see "./lib/process.vox".`. Decoding lives here rather
  than in the compiler so that user-defined things (plan 310) can later
  wrap a status in a `process` thing with no compiler change.

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