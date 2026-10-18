# The Vox bug register

The register holds one entry per root cause: every defect in the compiler that is open today, and an index of every entry ever filed. A fixed entry keeps its number and moves, unchanged, to the archive of the release that fixed it, in [docs/bugs/](bugs/); a report that turned out not to be a compiler defect moves to [docs/bugs/not-bugs.md](bugs/not-bugs.md). The regression test each fix added, named in its entry, stays in the compiler's test suite.

**Open entries: 12.** Wrong output on valid input: 5. Accepted invalid input: 0. Spurious compile error: 5. Crash: 2. Assembler rejected output: 0. Hang: 0.

## How an entry enters the register

A report becomes an entry when it reproduces on current `main` and breaks a sentence of [LANGUAGE.md](../LANGUAGE.md), or finds a question the manual does not answer. A report can wait while the compiler moves on, so each entry is re-run against current `main` immediately before it is filed and records the commit it was verified at: the check that decides an entry is the one made at filing time. A report with the same root cause as an open entry adds a hit to that entry instead of opening a new one.

Each entry gives its **Reproducer** (the program, what it should do, what it does), its **Class**, the compiler **Phase** where that can be told, the **Claims** of the manual it exercises, its **Pile** (`manual says X, compiler does Y`, `manual is silent`, or `manual says X and X is wrong`), its **Hits**, a **Proposal** where the manual is silent, and its **State**.

## How the entries are ordered

By class, in this order: `wrong output on valid input`, `accepted invalid input`, `spurious compile error`, `crash`, `assembler rejected output`, `hang`. The first two come first because they mislead the reader without a word; the others announce themselves. Within a class, entries stand in number order.

## Open entries

### 164. A hole naming a parameter called 'the text' as `{the text}` prints a stray value

**Reproducer:**

```vox
To 'show' with a text called 'the text'.
  Print "hole: {the text}".

'show' of "hello".
```

- **Expected:** `hole: hello`, or a compile error if the hole cannot name this parameter.
- **Actual:**

```text
$ vox the_text_hole.vox -o the_text_hole && ./the_text_hole
hole: 6
```

The value printed is not the parameter's. The same hole with the parameter renamed (`'some words'` and `{some words}`) prints `hole: hello`, and so does `{'the text'}` with the single quotes written in the hole. Only a name that begins with `the` is affected.

**Class:** wrong output on valid input.

**Phase:** codegen.

**Claims:** LANGUAGE.md "Format Strings": "Embed variables and expressions directly in strings using curly braces `{}`", and a hole prints the value of the variable it names. LANGUAGE.md "Parameter and Local Types": "a typed parameter supports the same properties and operations as a top-level variable of that type". A multi-word name is written bare in a hole (`print "line {line number}",` in "Sentence Consumption").

**Pile:** manual says X, compiler does Y.

**Hits:** 1, first and last seen 2026-10-18.

**State:** open. Registered 2026-10-18. Verified on vox 0.4.16 and on main 88a2de2. Approved by TheJostler 2026-10-18. Root cause not yet investigated.

---

### 165. Appending an untyped call's result to a buffer writes an address

**Reproducer:**

```vox
To 'untyped' of a text called word. Return "{word}?".
a buffer called other is 64 bytes in size.
append 'untyped' of "x" to other.
Print "top: {other}".
```

- **Expected:** a compile error, as `append` of the same call to a list gives: the function has no declared return type, so its result has nothing to be read as.
- **Actual:**

```text
$ vox untyped_append.vox -o untyped_append && ./untyped_append
top: 139743229972512
```

The program compiles without a message and the buffer holds the digits of an address. The same function with `Return a text, "{word}?".` appends `x?`.

**Class:** wrong output on valid input.

**Phase:** analysis.

**Claims:** LANGUAGE.md "Reading a result": "A result with **no** declared return type has nothing to be read as, and the compiler will not guess: it is accepted only where the position itself supplies the type, and refused where nothing does." The positions that need the return type declared include `append`.

**Pile:** manual says X, compiler does Y.

**Hits:** 1, first and last seen 2026-10-18.

**State:** open. Registered 2026-10-18. Verified on vox 0.4.16 and on main 88a2de2. Approved by TheJostler 2026-10-18. Root cause not yet investigated.

---

### 166. A text from `arguments's all`, named in a local and appended to a list, is stored as an address

**Reproducer:**

```vox
a list called kept is [].
a list called given is arguments's all.
a text called word is element 1 of given.
append word to kept.
Print "word: {word}, kept: {kept}".
```

- **Expected:** with the argument `hello`, `word: hello, kept: ["hello"]`.
- **Actual:**

```text
$ vox arguments_kept.vox -o arguments_kept && ./arguments_kept hello
word: hello, kept: [140729249601978]
```

`word` prints correctly; the list holds the address of its characters. This is the family of #156 (an element named in a local, then appended) and of #23 (a list of `arguments's all` elements).

**Class:** wrong output on valid input.

**Phase:** codegen.

**Claims:** LANGUAGE.md "Mixed-Type Lists": "Appending, `set element`, `element N of`, `first`/`last`, iteration, and `{...}` format interpolation all respect each element's actual type."

**Pile:** manual says X, compiler does Y.

**Hits:** 1, first and last seen 2026-10-18.

**State:** open. Registered 2026-10-18. Verified on vox 0.4.16 and on main 88a2de2. Approved by TheJostler 2026-10-18. Root cause not yet investigated.

---

### 167. A loop variable over a returned list, cast as a number, gives the text's address

**Reproducer:**

```vox
To 'the rows'.
    a list called rows is [].
    a buffer called digits is "12".
    a text called row is digits as text.
    append row to rows.
    Return a list, rows.

a list called got is 'the rows'.
For each row in got,
    a number called parsed is row as a number,
    Print parsed.
```

- **Expected:** `12`.
- **Actual:**

```text
$ vox rows_as_number.vox -o rows_as_number && ./rows_as_number
140653719011360
```

**Class:** wrong output on valid input.

**Phase:** codegen.

**Claims:** LANGUAGE.md "Type Casting": a `text` cast `as a number` gives the number the text spells (`"123" as a number` is `123`). LANGUAGE.md "Mixed-Type Lists": every element "prints and reads back as what it is".

**Pile:** manual says X, compiler does Y.

**Hits:** 1, first and last seen 2026-10-18.

**State:** open. Registered 2026-10-18. Verified on vox 0.4.16 and on main 88a2de2. Approved by TheJostler 2026-10-18. Root cause not yet investigated.

---

### 168. A `Library` line arriving through `see` silently renames the library

**Reproducer:** two files. `outer.vox`:

```vox
Library 'outer' version "0.1".

see "./inner.vox".

To 'outer answer'.
  Return a number, 'inner answer' add 1.
```

and `inner.vox`, beside it:

```vox
Library 'inner' version "0.1".

To 'inner answer'.
  Return a number, 41.
```

- **Expected:** a compile error naming both `Library` lines, because one library cannot have two identities.
- **Actual:**

```text
$ vox outer.vox --shared -o libouter.so
$ nm -D --defined-only libouter.so
00000000000003b9 T inner_0_1_inner_answer
00000000000003d0 T inner_0_1_outer_answer
$ cat libouter.lib
Library inner version "0.1".
Location "./libouter.so".

Table of Contents:
    To 'inner answer', returning a number.
    To 'outer answer', returning a number.
```

The build succeeds without a message, and `outer.vox`'s own `Library 'outer'` line is lost: the library is exported as `inner`, under the name and version of the included file.

**Class:** wrong output on valid input.

**Phase:** analysis.

**Claims:** LANGUAGE.md "Mangling": every exported function is mangled to `<library>_<version>_<func>`. LANGUAGE.md "Writing a library": "**A library needs an identity.** The `Library` declaration gives the library the name and version that drive mangling and the `.lib`."

**Pile:** manual says X, compiler does Y.

**Hits:** 1, first and last seen 2026-10-18.

**State:** open. Registered 2026-10-18. Verified on vox 0.4.16 and on main 88a2de2. Approved by TheJostler 2026-10-18. Root cause not yet investigated.

---

### 169. A shared library cannot use another library's `.lib`

**Reproducer:** `inner.vox`, built first with `vox inner.vox --shared -o libinner.so` (which writes `libinner.lib` beside it):

```vox
Library 'inner' version "0.1".

To 'inner answer'.
  Return a number, 41.
```

and `outer.vox`, beside them:

```vox
Library 'outer' version "0.1".
see 'inner' version "0.1" from "libinner.lib".

To 'outer answer'.
  Return a number, 'inner answer' add 1.
```

- **Expected:** `libouter.so` builds and its `outer answer` calls the inner library.
- **Actual:**

```text
$ vox outer.vox --shared -o libouter.so
/usr/bin/ld.bfd: outer.o: warning: relocation against `inner_0_1_inner_answer' in read-only section `.text'
/usr/bin/ld.bfd: outer.o: relocation R_X86_64_PC32 against symbol `inner_0_1_inner_answer' can not be used when making a shared object; recompile with -fPIC
/usr/bin/ld.bfd: final link failed: bad value
Linking failed
```

A program that `see`s the same `.lib` links and runs.

**Class:** spurious compile error.

**Phase:** codegen.

**Claims:** LANGUAGE.md "Writing a library": "The runtime is position-independent, so a library may use the full core language (arithmetic, printing, buffers, files, floats, lists, maps), not a runtime-free subset." LANGUAGE.md "Consuming a library": "`see` of a `.lib` is the consumption path."

**Pile:** manual says X, compiler does Y.

**Hits:** 1, first and last seen 2026-10-18.

**State:** open. Registered 2026-10-18. Verified on vox 0.4.16 and on main 88a2de2. Approved by TheJostler 2026-10-18. Root cause not yet investigated.

---

### 170. Whether a local can shadow a global depends on where the function is

**Reproducer:**

```vox
a number called g is 1.

To 'shadow it'.
  a text called g is "five".
  Print "inside: {g}".

'shadow it'.
```

- **Expected:** `inside: five`. The local `g` is a text and shadows the global number.
- **Actual:**

```text
$ vox shadow_by_position.vox -o shadow_by_position
error: cannot bind 'g' to text in this declaration; 'g' is already declared as a number
  --> shadow_by_position.vox:4:17
    |
  4 |   a text called g is "five".
    |                 ^ this declares as text
```

With the function written above `a number called g is 1.` the same local is accepted and prints `inside: five`, and the global stays `1`. A local of the global's own type (`a number called g is 5.` inside the function) is accepted in both positions.

**Class:** spurious compile error.

**Phase:** analysis.

**Claims:** LANGUAGE.md "Function Scope": "Declaring a variable inside a function **shadows** a top-level variable of the same name (`a number called g is 5.` inside a function creates a local `g`); the global is left untouched." A function reads a global the same way "including inside a function written **above** the declaration".

**Pile:** manual says X, compiler does Y.

**Hits:** 1, first and last seen 2026-10-18.

**State:** open. Registered 2026-10-18. Verified on vox 0.4.16 and on main 88a2de2. Approved by TheJostler 2026-10-18. Root cause not yet investigated.

---

### 171. A text from `arguments's name` is refused as an append source

**Reproducer:**

```vox
a buffer called holder.
a text called 'the binary name' is arguments's name.
append 'the binary name' to holder.
Print holder.
```

- **Expected:** the program prints its own name.
- **Actual:**

```text
$ vox name_append.vox -o name_append
error: Buffer append requires a buffer source: the binary name
  --> name_append.vox:3:29
```

The text is declared on line 2 and is a text; every other text is accepted as an append source.

**Class:** spurious compile error.

**Phase:** analysis.

**Claims:** LANGUAGE.md "Buffer Append and Copy": "`append source to destination` adds source bytes to the end of destination." LANGUAGE.md "Arguments Properties": `arguments's name` is the program name (argv[0]), a text.

**Pile:** manual says X, compiler does Y.

**Hits:** 1, first and last seen 2026-10-18.

**State:** open. Registered 2026-10-18. Verified on vox 0.4.16 and on main 88a2de2. Approved by TheJostler 2026-10-18. Root cause not yet investigated.

---

### 172. A timer parameter cannot read `elapsed`

**Reproducer:**

```vox
To check with a timer called watch.
    Print the watch's elapsed in milliseconds.

a timer called clock.
Start the clock.
check of clock.
```

- **Expected:** the elapsed milliseconds print.
- **Actual:**

```text
$ vox timer_parameter.vox -o timer_parameter
error: Property 'elapsed' requires a timer: watch
  --> timer_parameter.vox:1:30
    |
  1 | To check with a timer called watch.
    |                              ^--- here
```

The message says `watch` is not a timer, and the caret is on its declaration as a timer.

**Class:** spurious compile error.

**Phase:** analysis.

**Claims:** LANGUAGE.md "Parameter and Local Types": "a typed parameter supports the same properties and operations as a top-level variable of that type", and `timer` is one of the 11 parameter types. LANGUAGE.md "Timer Properties": `elapsed` is a timer property.

**Pile:** manual says X, compiler does Y.

**Hits:** 1, first and last seen 2026-10-18.

**State:** open. Registered 2026-10-18. Verified on vox 0.4.16 and on main 88a2de2. Approved by TheJostler 2026-10-18. Root cause not yet investigated.

---

### 173. A lexer error inside a `see`-included file is reported at the including file's first line

**Reproducer:** `main.vox`:

```vox
(a comment line)
see "./inc/helper.vox".
greet.
```

and `inc/helper.vox`:

```vox
To greet.
    (says hello)
    Print "{".
```

- **Expected:** the error points at `inc/helper.vox:3`, where the unmatched `{` is.
- **Actual:**

```text
$ vox main.vox -o main
error: Unmatched `{` in a string literal. A single `{` begins a format interpolation, but no variable or expression followed it. To write a literal brace, double it: `{{` for `{` and `}}` for `}`.
  --> main.vox:1:1
    |
  1 | (a comment line)
    | ^--- here
```

The message gives neither the file nor the line of the string, and the caret is on the first line of the including file. The same family as #11 and #46, which misattributed error positions.

**Class:** spurious compile error.

**Phase:** parse.

**Claims:** LANGUAGE.md "The `see` Keyword" says an included file "is parsed as part of your program" and does not say where an error inside it is reported.

**Pile:** manual is silent.

**Hits:** 1, first and last seen 2026-10-18.

**Proposal:** an error found in an included file is reported at that file's path, line and column, with the line quoted from that file.

**State:** open. Registered 2026-10-18. Verified on vox 0.4.16 and on main 88a2de2. Approved by TheJostler 2026-10-18. Root cause not yet investigated.

---

### 163. Reading a global timer's `elapsed` inside a function stops the program

**Reproducer:**

```vox
a timer called clock.
To check.
    a number called waited is the clock's elapsed in milliseconds.
    Print "waited {waited}".

Start the clock.
Wait 50 milliseconds.
check.
check.
```

- **Expected:** `waited 50` (about), twice.
- **Actual:**

```text
$ vox timer_in_function.vox -o timer_in_function && ./timer_in_function
waited 0
Floating point exception
[exit 136]
```

The first call prints `waited 0` where about 50 is expected, and the second call stops the program on a floating point exception.

**Class:** crash.

**Phase:** runtime.

**Claims:** LANGUAGE.md "Function Scope": "Variables declared at top level are global and can be used inside functions". LANGUAGE.md "Timer Properties": `elapsed` is "Elapsed time while running". LANGUAGE.md "A supervisor loop, with no shelling out" reads `the clock's elapsed in milliseconds` while the timer runs. A program that vox accepts never stops on a signal.

**Pile:** manual says X, compiler does Y.

**Hits:** 1, first and last seen 2026-10-18.

**State:** open. Registered 2026-10-18. Verified on vox 0.4.16 and on main 88a2de2. Approved by TheJostler 2026-10-18. Root cause not yet investigated.

---

### 174. When memory runs out, a growing buffer stops the program with a segfault instead of a message

**Reproducer:**

```vox
a buffer called heap.
a number called rounds is 0.
While rounds is less than 200000,
    append "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" to heap,
    increment rounds.
On error Print "append refused, error flag set".
Print "size {heap's size}".
```

Run with the address space limited to 10 MB: `prlimit --as=10000000 -- ./out`.

- **Expected:** when the program cannot get the memory it asks for, it stops with a clear `out of memory` message on its standard error and a non-zero exit status.
- **Actual:**

```text
$ vox out_of_memory.vox -o out_of_memory
$ prlimit --as=10000000 -- ./out_of_memory
Segmentation fault
[exit 139]
```

**Class:** crash.

**Phase:** runtime.

**Claims:** LANGUAGE.md "Dynamic Buffers": "Buffers start with 4096 bytes of capacity (size 0) and grow automatically." LANGUAGE.md "Memory Safety Guarantees" lists "No buffer overflows" with "Buffers grow dynamically as needed". The manual does not say what happens when the system has no memory to give.

**Pile:** manual is silent.

**Hits:** 1, first and last seen 2026-10-18.

**Proposal:** TheJostler ruled the behaviour: when memory runs out, the program stops with a clear `out of memory` message on its standard error and a non-zero exit status, never a segfault. The manual states this once the compiler does it.

**State:** open. Registered 2026-10-18. Verified on vox 0.4.16 and on main 88a2de2. Approved by TheJostler 2026-10-18, who ruled the expected behaviour above. Root cause not yet investigated.

---

## Index of every entry

Every entry ever filed, by number. Number 113 was never used.

| # | Entry | Class | State | Full text |
|---|---|---|---|---|
| 1 | A float routed through `{}` interpolation into `text`/`buffer` prints the raw bit pattern | wrong output on valid input | fixed in 0.3.6 | [0.3.6](bugs/0.3.6.md#1-a-float-routed-through--interpolation-into-textbuffer-prints-the-raw-bit-pattern) |
| 2 | `value` → `float`: reassignment is broken, declare-with-initializer isn't | wrong output on valid input | fixed in 0.3.6 | [0.3.6](bugs/0.3.6.md#2-value--float-reassignment-is-broken-declare-with-initializer-isnt) |
| 3 | `but if` is restricted to `print` actions: silently, undocumented | spurious compile error | fixed in 0.3.6 | [0.3.6](bugs/0.3.6.md#3-but-if-is-restricted-to-print-actions--silently-undocumented) |
| 4 | A top-level `number` global doesn't retain mutations made inside a function | wrong output on valid input | fixed in 0.3.6 | [0.3.6](bugs/0.3.6.md#4-a-top-level-number-global-doesnt-retain-mutations-made-inside-a-function) |
| 5 | Omitting the blank line after a function definition is silently required, not "not a requirement" | wrong output on valid input | not a compiler defect: docs corrected in 0.3.6 | [not-bugs](bugs/not-bugs.md#5-omitting-the-blank-line-after-a-function-definition-is-silently-required-not-not-a-requirement) |
| 6 | A variable named `length` reading `.size`/`.length` fails, blaming `"size"` | spurious compile error | not a compiler defect: docs corrected in 0.3.6 | [not-bugs](bugs/not-bugs.md#6-a-variable-named-length-reading-sizelength-fails-blaming-size) |
| 7 | `map's "{loopvar}"` fails when the loop variable comes from `.keys` | wrong output on valid input | fixed in 0.3.6 | [0.3.6](bugs/0.3.6.md#7-maps-loopvar-fails-when-the-loop-variable-comes-from-keys) |
| 8 | Extracting a `list` from a `value` corrupts it; `float` and `map` extraction (the same way) don't | wrong output on valid input | fixed in 0.3.6 | [0.3.6](bugs/0.3.6.md#8-extracting-a-list-from-a-value-corrupts-it-float-and-map-extraction-the-same-way-dont) |
| 9 | `buffer as text` cast silently returns an empty string | wrong output on valid input | fixed in 0.3.6 | [0.3.6](bugs/0.3.6.md#9-buffer-as-text-cast-silently-returns-an-empty-string) |
| 10 | A bare `{` or `}` in a string literal throws a confusing, empty-named error | unclassified | not a compiler defect: docs corrected in 0.3.6 | [not-bugs](bugs/not-bugs.md#10-a-bare--or--in-a-string-literal-throws-a-confusing-empty-named-error) |
| 11 | That error's reported line can be badly misattributed | unclassified | fixed in 0.3.6 | [0.3.6](bugs/0.3.6.md#11-that-errors-reported-line-can-be-badly-misattributed) |
| 12 | A nested if/but-if chain with no trailing `Otherwise`, as the last action in an outer branch, silently breaks everything after it | wrong output on valid input | not a compiler defect: documentation gap, documented in 0.3.7 | [not-bugs](bugs/not-bugs.md#12-a-nested-ifbut-if-chain-with-no-trailing-otherwise-as-the-last-action-in-an-outer-branch-silently-breaks-everything-after-it) |
| 13 | Chaining `element N of X's property` in one expression corrupts the result: splitting it into two statements doesn't | wrong output on valid input | fixed in 0.3.6 | [0.3.6](bugs/0.3.6.md#13-chaining-element-n-of-xs-property-in-one-expression-corrupts-the-result--splitting-it-into-two-statements-doesnt) |
| 14 | A `but if` chain is closed by a period that belongs to a nested clause | wrong output on valid input | fixed in 0.3.6 | [0.3.6](bugs/0.3.6.md#14-a-but-if-chain-is-closed-by-a-period-that-belongs-to-a-nested-clause) |
| 15 | Reassigning a `value` that holds a `float` to an integer leaves the tag as `float` | wrong output on valid input | fixed in 0.3.6 | [0.3.6](bugs/0.3.6.md#15-reassigning-a-value-that-holds-a-float-to-an-integer-leaves-the-tag-as-float) |
| 16 | A declared-but-uninitialised `text` variable segfaults on first read | crash | fixed in 0.3.6 | [0.3.6](bugs/0.3.6.md#16-a-declared-but-uninitialised-text-variable-segfaults-on-first-read) |
| 17 | Appending a format string to a list stores a corrupt element: printing or reading it back segfaults or leaks a raw pointer | crash | fixed in 0.3.7 | [0.3.7](bugs/0.3.7.md#17-appending-a-format-string-to-a-list-stores-a-corrupt-element--printing-or-reading-it-back-segfaults-or-leaks-a-raw-pointer) |
| 18 | The `.lib` list-element-type inference credits fewer shapes than the runtime element tagger: provably-`text` elements ship as plain `list` | unclassified | fixed in 0.4.0 | [0.4.0](bugs/0.4.0.md#18-the-lib-list-element-type-inference-credits-fewer-shapes-than-the-runtime-element-tagger--provably-text-elements-ship-as-plain-list) |
| 19 | A string literal's content resolved against known variable names at codegen time: crash on self-name collision, silent wrong data on any other collision | wrong output on valid input | fixed in 0.3.7 | [0.3.7](bugs/0.3.7.md#19-a-string-literals-content-resolved-against-known-variable-names-at-codegen-time--crash-on-self-name-collision-silent-wrong-data-on-any-other-collision) |
| 20 | Equality dispatch treats a non-stringy operand as a string pointer and dereferences it | crash | fixed in 0.3.7 | [0.3.7](bugs/0.3.7.md#20-equality-dispatch-treats-a-non-stringy-operand-as-a-string-pointer-and-dereferences-it) |
| 21 | A string literal in an `If`/`While` condition inside a function body resolves as a variable name | wrong output on valid input | fixed in 0.4.4 | [0.4.4](bugs/0.4.4.md#21-a-string-literal-in-an-ifwhile-condition-inside-a-function-body-resolves-as-a-variable-name) |
| 22 | An integer literal too large for 64 bits compiles silently and evaluates to 0 | accepted invalid input | fixed in 0.4.4 | [0.4.4](bugs/0.4.4.md#22-an-integer-literal-too-large-for-64-bits-compiles-silently-and-evaluates-to-0) |
| 23 | Printing a list of `arguments's all` elements leaks raw pointers; element access is fine | wrong output on valid input | fixed in 0.4.4 | [0.4.4](bugs/0.4.4.md#23-printing-a-list-of-argumentss-all-elements-leaks-raw-pointers-element-access-is-fine) |
| 24 | Reading an unset environment variable by name segfaults: `On error` cannot catch it | crash | fixed in 0.4.3 | [0.4.3](bugs/0.4.3.md#24-reading-an-unset-environment-variable-by-name-segfaults--on-error-cannot-catch-it) |
| 25 | A declaration on a non-`If` conditional path stays in scope over storage nothing ever initialises: stack garbage for numbers, segfault for text | accepted invalid input | fixed in 0.4.3 | [0.4.3](bugs/0.4.3.md#25-a-declaration-on-a-non-if-conditional-path-stays-in-scope-over-storage-nothing-ever-initialises--stack-garbage-for-numbers-segfault-for-text) |
| 26 | Out-of-range `arguments`/`environment` positional properties segfault | crash | fixed in 0.4.4 | [0.4.4](bugs/0.4.4.md#26-out-of-range-argumentsenvironment-positional-properties-segfault) |
| 27 | A period never closes a `Repeat` body: following statements are silently absorbed into the loop | wrong output on valid input | fixed in 0.4.6 | [0.4.6](bugs/0.4.6.md#27-a-period-never-closes-a-repeat-body--following-statements-are-silently-absorbed-into-the-loop) |
| 28 | A `buffer` declared on an untaken `If` branch, then redeclared at top level, segfaults on first read | crash | fixed in 0.4.6 | [0.4.6](bugs/0.4.6.md#28-a-buffer-declared-on-an-untaken-if-branch-then-redeclared-at-top-level-segfaults-on-first-read) |
| 29 | A string literal inside a list literal is resolved as a variable name: silent wrong data, or a segfault | wrong output on valid input | fixed in 0.4.6 | [0.4.6](bugs/0.4.6.md#29-a-string-literal-inside-a-list-literal-is-resolved-as-a-variable-name--silent-wrong-data-or-a-segfault) |
| 30 | A buffer initialised from a string literal copies a same-named buffer instead: silently | wrong output on valid input | fixed in 0.4.6 | [0.4.6](bugs/0.4.6.md#30-a-buffer-initialised-from-a-string-literal-copies-a-same-named-buffer-instead--silently) |
| 31 | A `text` flag with no default segfaults when the flag is not supplied | crash | fixed in 0.4.6 | [0.4.6](bugs/0.4.6.md#31-a-text-flag-with-no-default-segfaults-when-the-flag-is-not-supplied) |
| 32 | A flag read inside a function body is typed `boolean`, whatever it was declared as | spurious compile error | fixed in 0.4.6 | [0.4.6](bugs/0.4.6.md#32-a-flag-read-inside-a-function-body-is-typed-boolean-whatever-it-was-declared-as) |
| 33 | `is empty` on a `text` is always false: it tests the pointer, not the contents | wrong output on valid input | fixed in 0.4.6 | [0.4.6](bugs/0.4.6.md#33-is-empty-on-a-text-is-always-false--it-tests-the-pointer-not-the-contents) |
| 34 | A float outside ±2^63 prints as `9223372036854775808.372036854775808`, and one below ~1e-8 prints as `0.0` | wrong output on valid input | fixed in 0.4.7 | [0.4.7](bugs/0.4.7.md#34-a-float-outside-263-prints-as-9223372036854775808372036854775808-and-one-below-1e-8-prints-as-00) |
| 35 | `as a number` wraps silently on overflow: a positive numeral parses to a negative number | wrong output on valid input | fixed in 0.4.7 | [0.4.7](bugs/0.4.7.md#35-as-a-number-wraps-silently-on-overflow--a-positive-numeral-parses-to-a-negative-number) |
| 36 | A width specifier in a format string reinterprets a float's bits, and leaks a text's address | wrong output on valid input | fixed in 0.4.7 | [0.4.7](bugs/0.4.7.md#36-a-width-specifier-in-a-format-string-reinterprets-a-floats-bits-and-leaks-a-texts-address) |
| 37 | A file's `readable` property is always true, whatever mode the file was opened in | wrong output on valid input | fixed in 0.4.7 | [0.4.7](bugs/0.4.7.md#37-a-files-readable-property-is-always-true-whatever-mode-the-file-was-opened-in) |
| 38 | The documented file property `exists` is a parse error | spurious compile error | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#38-the-documented-file-property-exists-is-a-parse-error) |
| 39 | A format string as the FIRST element of an inline collection makes every element print as a raw pointer | wrong output on valid input | fixed in 0.4.7 | [0.4.7](bugs/0.4.7.md#39-a-format-string-as-the-first-element-of-an-inline-collection-makes-every-element-print-as-a-raw-pointer) |
| 40 | `Write` of any scalar to a file segfaults: number, float, and boolean alike | crash | fixed in 0.4.8 | [0.4.8](bugs/0.4.8.md#40-write-of-any-scalar-to-a-file-segfaults--number-float-and-boolean-alike) |
| 41 | `buffer as text` aliases the buffer: resizing it leaves the text dangling, and reading it segfaults | crash | fixed in 0.4.8 | [0.4.8](bugs/0.4.8.md#41-buffer-as-text-aliases-the-buffer--resizing-it-leaves-the-text-dangling-and-reading-it-segfaults) |
| 42 | A buffer declared with a byte count reports `Text (dynamic)` from its `type` property | wrong output on valid input | fixed in 0.4.8 | [0.4.8](bugs/0.4.8.md#42-a-buffer-declared-with-a-byte-count-reports-text-dynamic-from-its-type-property) |
| 43 | A conditional `value` return leaves a stale tag, and the caller dereferences an integer as text: segfault | crash | fixed in 0.4.8 | [0.4.8](bugs/0.4.8.md#43-a-conditional-value-return-leaves-a-stale-tag-and-the-caller-dereferences-an-integer-as-text--segfault) |
| 44 | `{list}` / `{map}` in a format string renders correctly only in `Print` position: everywhere else it prints a raw heap address | wrong output on valid input | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#44-list--map-in-a-format-string-renders-correctly-only-in-print-position--everywhere-else-it-prints-a-raw-heap-address) |
| 45 | A function with no declared return type is read back as an integer wherever its result lands untyped | wrong output on valid input | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#45-a-function-with-no-declared-return-type-is-read-back-as-an-integer-wherever-its-result-lands-untyped) |
| 46 | The diagnostic caret can land inside a comment | unclassified | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#46-the-diagnostic-caret-can-land-inside-a-comment) |
| 47 | `Seek ... to line N` lands on line 2 for every N of 2 or more, and a line past EOF never sets the error flag | wrong output on valid input | fixed in 0.4.8 | [0.4.8](bugs/0.4.8.md#47-seek--to-line-n-lands-on-line-2-for-every-n-of-2-or-more-and-a-line-past-eof-never-sets-the-error-flag) |
| 48 | A failing `Write` never sets the error flag, and `Read from` a dead handle sets nothing while `Read line from` sets it | wrong output on valid input | fixed in 0.4.8 | [0.4.8](bugs/0.4.8.md#48-a-failing-write-never-sets-the-error-flag-and-read-from-a-dead-handle-sets-nothing-while-read-line-from-sets-it) |
| 49 | `For each` over a scalar segfaults; over a map or a buffer it silently iterates garbage | crash | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#49-for-each-over-a-scalar-segfaults-over-a-map-or-a-buffer-it-silently-iterates-garbage) |
| 50 | A bare `otherwise` is rejected after any base action except `append` | spurious compile error | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#50-a-bare-otherwise-is-rejected-after-any-base-action-except-append) |
| 51 | A text initialised from a buffer WITHOUT the cast (`a text called t is b.`) points at the buffer's header and prints its capacity byte | wrong output on valid input | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#51-a-text-initialised-from-a-buffer-without-the-cast-a-text-called-t-is-b-points-at-the-buffers-header-and-prints-its-capacity-byte) |
| 52 | Any text-valued special name built into a buffer segfaults: `copy "{arguments's first}" to built` | crash | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#52-any-text-valued-special-name-built-into-a-buffer-segfaults--copy-argumentss-first-to-built) |
| 53 | `Return a buffer, "<text literal>"` answers with an empty buffer: or segfaults, once the program holds a second string | wrong output on valid input | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#53-return-a-buffer-text-literal-answers-with-an-empty-buffer--or-segfaults-once-the-program-holds-a-second-string) |
| 54 | A list element read into a variable of another type segfaults: `a text called label is element 1 of counts.` | crash | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#54-a-list-element-read-into-a-variable-of-another-type-segfaults--a-text-called-label-is-element-1-of-counts) |
| 55 | A `treating` clause whose types do not match the collection segfaults: `print each item from ["a"] treating 98 as 31.` | crash | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#55-a-treating-clause-whose-types-do-not-match-the-collection-segfaults--print-each-item-from-a-treating-98-as-31) |
| 56 | `all the numbers from/between X and Y`: a range that segfaults in a loop header, segfaults as a value, and drops its end bound | crash | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#56-all-the-numbers-frombetween-x-and-y--a-range-that-segfaults-in-a-loop-header-segfaults-as-a-value-and-drops-its-end-bound) |
| 57 | A `text`, `list` or `map` initialised to `nothing` segfaults on the first read: `a text called t is nothing.` | crash | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#57-a-text-list-or-map-initialised-to-nothing-segfaults-on-the-first-read--a-text-called-t-is-nothing) |
| 58 | A buffer declared from a text-valued property (`environment's "HOME"`, `environment's first`, `arguments's first`) is silently re-typed as text: size `-1`, prints nothing, and on `Set` loses its bounds | wrong output on valid input | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#58-a-buffer-declared-from-a-text-valued-property-environments-home-environments-first-argumentss-first-is-silently-re-typed-as-text--size--1-prints-nothing-and-on-set-loses-its-bounds) |
| 59 | A `treating` clause on a mixed-list loop variable prints a pointer, matched or mismatched (wrong value; family of #44/#45) | wrong output on valid input | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#59-a-treating-clause-on-a-mixed-list-loop-variable-prints-a-pointer-matched-or-mismatched-wrong-value-family-of-4445) |
| 60 | `{f:.N}` for N ≥ 18 corrupts the decimals: culminating in a spliced `i64::MIN` sentinel from N=20 | wrong output on valid input | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#60-fn-for-n--18-corrupts-the-decimals--culminating-in-a-spliced-i64min-sentinel-from-n20) |
| 61 | A format pad width beyond `i32::MAX` is silently dropped: no padding, no diagnostic; a pad width below that renders correctly but at roughly one syscall per byte | wrong output on valid input | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#61-a-format-pad-width-beyond-i32max-is-silently-dropped--no-padding-no-diagnostic-a-pad-width-below-that-renders-correctly-but-at-roughly-one-syscall-per-byte) |
| 62 | A `.lib` entry with no `, returning` clause is not type-checked at the call site: its non-existent result is silently accepted into a typed variable | accepted invalid input | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#62-a-lib-entry-with-no--returning-clause-is-not-type-checked-at-the-call-site--its-non-existent-result-is-silently-accepted-into-a-typed-variable) |
| 63 | A procedure: a `To` with no `Return` at all, is silently accepted as a value: `print ping.` prints `pong`, then `1` | accepted invalid input | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#63-a-procedure--a-to-with-no-return-at-all--is-silently-accepted-as-a-value-print-ping-prints-pong-then-1) |
| 64 | The `the <name>'s <property>` spelling implements almost no properties: `the h's size` reads, `the h's descriptor` is a parse error | spurious compile error | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#64-the-the-names-property-spelling-implements-almost-no-properties--the-hs-size-reads-the-hs-descriptor-is-a-parse-error) |
| 65 | A declaration whose initializer is the WRONG type is accepted: `a text called n is 5.` segfaults on the first read, `a number called n is "get five".` prints the literal's address | accepted invalid input | fixed in 0.4.9 | [0.4.9](bugs/0.4.9.md#65-a-declaration-whose-initializer-is-the-wrong-type-is-accepted--a-text-called-n-is-5-segfaults-on-the-first-read-a-number-called-n-is-get-five-prints-the-literals-address) |
| 66 | A global declared below a function is read inside it as a raw machine word: every type but `number` | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#66-a-global-declared-below-a-function-is-read-inside-it-as-a-raw-machine-word--every-type-but-number) |
| 67 | A declared `float`, `map` or `buffer` return is printed by the integer formatter: the fix #45's diagnostic tells the author to apply | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#67-a-declared-float-map-or-buffer-return-is-printed-by-the-integer-formatter--the-fix-45s-diagnostic-tells-the-author-to-apply) |
| 68 | A mixed list's element in the *expression* form of a format hole prints as an integer: the same read printed as a statement is correct | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#68-a-mixed-lists-element-in-the-expression-form-of-a-format-hole-prints-as-an-integer--the-same-read-printed-as-a-statement-is-correct) |
| 69 | A `treating` clause whose match or replacement is a `value` keeps the static path: a pointer printed as a number, or a number read as a `char*` | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#69-a-treating-clause-whose-match-or-replacement-is-a-value-keeps-the-static-path--a-pointer-printed-as-a-number-or-a-number-read-as-a-char) |
| 70 | `append each … treating …` parses the clause and discards it: silently in the spelling that compiles, as a parse error in the grammar's own | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#70-append-each--treating--parses-the-clause-and-discards-it--silently-in-the-spelling-that-compiles-as-a-parse-error-in-the-grammars-own) |
| 71 | A format specifier other than a width still ignores the value's type: a precision on a number renders `0.00`, and `:x` / `:b` / `:o` on a text or buffer print its address | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#71-a-format-specifier-other-than-a-width-still-ignores-the-values-type--a-precision-on-a-number-renders-000-and-x--b--o-on-a-text-or-buffer-print-its-address) |
| 72 | An absent map key, or an out-of-range list index, is typed from the collection's VALUES: the manual's own `a number called x is m's "never_set".` is refused, and the `help:` line it offers segfaults | spurious compile error | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#72-an-absent-map-key-or-an-out-of-range-list-index-is-typed-from-the-collections-values--the-manuals-own-a-number-called-x-is-ms-never_set-is-refused-and-the-help-line-it-offers-segfaults) |
| 73 | A `To` definition swallowed into an open clause is accepted, and every call to it passes a `value` parameter's tag from an uninitialised register: an integer is then dereferenced as a text pointer | accepted invalid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#73-a-to-definition-swallowed-into-an-open-clause-is-accepted-and-every-call-to-it-passes-a-value-parameters-tag-from-an-uninitialised-register--an-integer-is-then-dereferenced-as-a-text-pointer) |
| 74 | A `'s length` / `'s size` / `'s capacity` / `'s empty` read is typeless to the type lock: `a text called t is xs's length.` compiles and segfaults | accepted invalid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#74-a-s-length--s-size--s-capacity--s-empty-read-is-typeless-to-the-type-lock--a-text-called-t-is-xss-length-compiles-and-segfaults) |
| 75 | A list or map grown through a function parameter silently stops at the literal's capacity: the realloc is never stored back, and every call past that leaks a whole collection | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#75-a-list-or-map-grown-through-a-function-parameter-silently-stops-at-the-literals-capacity--the-realloc-is-never-stored-back-and-every-call-past-that-leaks-a-whole-collection) |
| 76 | A `map` parameter is typed as nothing at all: `holder's length` emits `_file_size` and the program fails to ASSEMBLE, `Print holder` leaks a heap address, and `holder's length` reads `-1` where it links | assembler rejected output | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#76-a-map-parameter-is-typed-as-nothing-at-all--holders-length-emits-_file_size-and-the-program-fails-to-assemble-print-holder-leaks-a-heap-address-and-holders-length-reads--1-where-it-links) |
| 77 | The `append` value slot refuses a negative literal, `nothing`, every collection read and `times`: `append -5 to xs.` is "Expected value to append" | spurious compile error | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#77-the-append-value-slot-refuses-a-negative-literal-nothing-every-collection-read-and-times--append--5-to-xs-is-expected-value-to-append) |
| 78 | A buffer sized from a variable escapes the size bound: `-1 bytes` is accepted and reports `capacity -1`, and a size past what can be mapped segfaults | accepted invalid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#78-a-buffer-sized-from-a-variable-escapes-the-size-bound---1-bytes-is-accepted-and-reports-capacity--1-and-a-size-past-what-can-be-mapped-segfaults) |
| 79 | A top-level read before the variable's own declaration is accepted and prints the raw slot: no "used before its declaration" diagnostic exists | accepted invalid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#79-a-top-level-read-before-the-variables-own-declaration-is-accepted-and-prints-the-raw-slot--no-used-before-its-declaration-diagnostic-exists) |
| 80 | A `thing` instance declared below a function cannot be read inside it: `Expected property name, got Identifier("x")`, with the caret on the property name | spurious compile error | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#80-a-thing-instance-declared-below-a-function-cannot-be-read-inside-it--expected-property-name-got-identifierx-with-the-caret-on-the-property-name) |
| 81 | A dynamic map key inside a format hole: `"{m's \"{k}\"}"`, renders the value then two stray characters from the hole's own syntax | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#81-a-dynamic-map-key-inside-a-format-hole--ms-k--renders-the-value-then-two-stray-characters-from-the-holes-own-syntax) |
| 82 | The runtime text→float parser rounded once per fractional digit, so `"0.88" as a float` was not `0.88`: 53 of the 1000 two-decimal values disagreed with their own literal | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#82-the-runtime-textfloat-parser-rounded-once-per-fractional-digit-so-088-as-a-float-was-not-088--53-of-the-1000-two-decimal-values-disagreed-with-their-own-literal) |
| 83 | `not` binds to a primary, so `If not v1 is v2 then,` compiles as `(not v1) is v2` and the guard never fires: no spelling of `not <comparison>` exists | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#83-not-binds-to-a-primary-so-if-not-v1-is-v2-then-compiles-as-not-v1-is-v2-and-the-guard-never-fires--no-spelling-of-not-comparison-exists) |
| 84 | `isn't` and `aren't`: documented spellings of `not` at LANGUAGE.md:4662, can never be lexed: `read_word` stops at the apostrophe, so six keyword-table entries are dead code | spurious compile error | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#84-isnt-and-arent--documented-spellings-of-not-at-languagemd4662--can-never-be-lexed-read_word-stops-at-the-apostrophe-so-six-keyword-table-entries-are-dead-code) |
| 85 | A width and a precision written together silently drop both: `{f:8.2}` prints `2.5` while `{f:.2}` prints `2.50`; and the manual never said whether `N.M` composes | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#85-a-width-and-a-precision-written-together-silently-drop-both--f82-prints-25-while-f2-prints-250-and-the-manual-never-said-whether-nm-composes) |
| 86 | A float's precision is dropped by every sink but `Print`: `copy "{ratio:.2}" to b` and `write "{ratio:.2}"` give `2.5` where `Print` gives `2.50` | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#86-a-floats-precision-is-dropped-by-every-sink-but-print--copy-ratio2-to-b-and-write-ratio2-give-25-where-print-gives-250) |
| 87 | A buffer in a `value` carries its struct pointer, not its bytes: `a value called carried is made.` prints an empty line, or the capacity byte (`@` at 64 bytes) | wrong output on valid input | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#87-a-buffer-in-a-value-carries-its-struct-pointer-not-its-bytes--a-value-called-carried-is-made-prints-an-empty-line-or-the-capacity-byte--at-64-bytes) |
| 88 | `Print not <text \| list \| map>` segfaults: `infer_expr_type` and `is_float_expr` return a unary `not`'s OPERAND type, while `is_boolean_expr` twelve lines away and the declaration path both correctly call it a boolean | crash | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#88-print-not-text--list--map-segfaults--infer_expr_type-and-is_float_expr-return-a-unary-nots-operand-type-while-is_boolean_expr-twelve-lines-away-and-the-declaration-path-both-correctly-call-it-a-boolean) |
| 89 | The "Unknown variable" caret for a bare literal in a format hole lands on the first textual occurrence of that literal anywhere in the file - a legal `a float called f is 3.14.` is marked as the error | unclassified | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#89-the-unknown-variable-caret-for-a-bare-literal-in-a-format-hole-lands-on-the-first-textual-occurrence-of-that-literal-anywhere-in-the-file---a-legal-a-float-called-f-is-314-is-marked-as-the-error) |
| 90 | A `buffer` grown past its capacity through a parameter is a use-after-free: the caller's next read of its own buffer segfaults | crash | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#90-a-buffer-grown-past-its-capacity-through-a-parameter-is-a-use-after-free--the-callers-next-read-of-its-own-buffer-segfaults) |
| 91 | A non-provable absent-key or out-of-range read into a `text`, `list` or `map` slot hands the raw 0 to a pointer and segfaults | crash | fixed in 0.4.10 | [0.4.10](bugs/0.4.10.md#91-a-non-provable-absent-key-or-out-of-range-read-into-a-text-list-or-map-slot-hands-the-raw-0-to-a-pointer-and-segfaults) |
| 92 | `Set <global> to <value>.` at top level takes a `list`, `map` or `buffer` global out of scope, so every function reading it fails with `Unknown variable`: and the caret lands on the declaration | spurious compile error | fixed in 0.4.11 | [0.4.11](bugs/0.4.11.md#92-set-global-to-value-at-top-level-takes-a-list-map-or-buffer-global-out-of-scope-so-every-function-reading-it-fails-with-unknown-variable--and-the-caret-lands-on-the-declaration) |
| 93 | A user-facing diagnostic cites LANGUAGE.md by a stale line number, and the manual and a compiler warning both say a fresh dynamic buffer has zero capacity when the runtime gives it 4096 bytes | unclassified | fixed in 0.4.11 | [0.4.11](bugs/0.4.11.md#93-a-user-facing-diagnostic-cites-languagemd-by-a-stale-line-number-and-the-manual-and-a-compiler-warning-both-say-a-fresh-dynamic-buffer-has-zero-capacity-when-the-runtime-gives-it-4096-bytes) |
| 94 | `Set <reserved-type-noun> to <value>.` blames the following `to`, not the reserved word the author actually typed | unclassified | fixed in 0.4.11 | [0.4.11](bugs/0.4.11.md#94-set-reserved-type-noun-to-value-blames-the-following-to-not-the-reserved-word-the-author-actually-typed) |
| 95 | A name brought into being by an untyped `Set` escapes the type lock and carries no type at all, so a rewrite of another type prints an ADDRESS: and LANGUAGE.md never said `Set` declares | wrong output on valid input | fixed in 0.4.11 | [0.4.11](bugs/0.4.11.md#95-a-name-brought-into-being-by-an-untyped-set-escapes-the-type-lock-and-carries-no-type-at-all-so-a-rewrite-of-another-type-prints-an-address--and-languagemd-never-said-set-declares) |
| 96 | A `To` (function definition) inside a still-open `If`/loop/function body was parsed into that body instead of refused, silently moving every following statement's control flow | accepted invalid input | fixed in 0.4.11 | [0.4.11](bugs/0.4.11.md#96-a-to-function-definition-inside-a-still-open-ifloopfunction-body-was-parsed-into-that-body-instead-of-refused-silently-moving-every-following-statements-control-flow) |
| 97 | A text appended into a caller's list through a `list` parameter reads back as its address: the heterogeneous verdict stopped at the callee's own parameter | wrong output on valid input | fixed in 0.4.11 | [0.4.11](bugs/0.4.11.md#97-a-text-appended-into-a-callers-list-through-a-list-parameter-reads-back-as-its-address--the-heterogeneous-verdict-stopped-at-the-callees-own-parameter) |
| 98 | An unrecognised format specifier is silently discarded: `{n:q}`, `{n:#x}` and `{n:zzz}` render as a bare `{n}`, no warning, no error | accepted invalid input | fixed in 0.4.11 | [0.4.11](bugs/0.4.11.md#98-an-unrecognised-format-specifier-is-silently-discarded--nq-nx-and-nzzz-render-as-a-bare-n-no-warning-no-error) |
| 99 | A bare `.lib` name in `see` never finds an installed interface: `/usr/include/vox` is not in the search order, though every doc says installed interfaces live there | spurious compile error | fixed in 0.4.12 | [0.4.12](bugs/0.4.12.md#99-a-bare-lib-name-in-see-never-finds-an-installed-interface--usrincludevox-is-not-in-the-search-order-though-every-doc-says-installed-interfaces-live-there) |
| 100 | A zero-width format specifier: `{n:0}`, `{n:00000}`, regressed to an unknown-specifier error in 0.4.11, though a width of 0 is a legal no-op | spurious compile error | fixed in 0.4.12 | [0.4.12](bugs/0.4.12.md#100-a-zero-width-format-specifier--n0-n00000--regressed-to-an-unknown-specifier-error-in-0411-though-a-width-of-0-is-a-legal-no-op) |
| 101 | An over-precise float compares unequal to itself across the two parse routes: the literal route's rule was undocumented, and the headline oversold the text route | unclassified | not a compiler defect: documentation gap, documented in 0.4.13 | [not-bugs](bugs/not-bugs.md#101-an-over-precise-float-compares-unequal-to-itself-across-the-two-parse-routes--the-literal-routes-rule-was-undocumented-and-the-headline-oversold-the-text-route) |
| 102 | `Create a list called X.` (and `a list called X.` / the list default on a branch-declared name) emits a bare `HEAP_ALLOC` with `heap.asm` never included, so the program fails to assemble | assembler rejected output | fixed in 0.4.14 | [0.4.14](bugs/0.4.14.md#102-create-a-list-called-x-and-a-list-called-x--the-list-default-on-a-branch-declared-name-emits-a-bare-heap_alloc-with-heapasm-never-included-so-the-program-fails-to-assemble) |
| 103 | A thing with a disallowed field type gets two errors, the first garbled: and the field-type surface itself is narrower than it should be | unclassified | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#103-a-thing-with-a-disallowed-field-type-gets-two-errors-the-first-garbled--and-the-field-type-surface-itself-is-narrower-than-it-should-be) |
| 104 | `each ... from` over a non-list anchors the error at the variable's declaration, not the loop: and there is no byte-iteration sentence at all | unclassified | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#104-each--from-over-a-non-list-anchors-the-error-at-the-variables-declaration-not-the-loop--and-there-is-no-byte-iteration-sentence-at-all) |
| 105 | A call missing its `with` reports arity, not the missing preposition | unclassified | fixed in 0.4.14 | [0.4.14](bugs/0.4.14.md#105-a-call-missing-its-with-reports-arity-not-the-missing-preposition) |
| 106 | `print`'s aliases are enforced unevenly: `show`/`display` reserved, `say`/`output` not | unclassified | fixed in 0.4.14 | [0.4.14](bugs/0.4.14.md#106-prints-aliases-are-enforced-unevenly-showdisplay-reserved-sayoutput-not) |
| 107 | A buffer, list, or format-string text declared inside a function or loop body is allocated on every entry and released only at program exit | unclassified | not a compiler defect: a limitation by design | [not-bugs](bugs/not-bugs.md#107-a-buffer-list-or-format-string-text-declared-inside-a-function-or-loop-body-is-allocated-on-every-entry-and-released-only-at-program-exit) |
| 108 | `Set <text> to "<format string>"` allocates a fresh string on every evaluation and never frees the one it replaces: building a text up in a loop is quadratic | unclassified | fixed in 0.4.14 | [0.4.14](bugs/0.4.14.md#108-set-text-to-format-string-allocates-a-fresh-string-on-every-evaluation-and-never-frees-the-one-it-replaces--building-a-text-up-in-a-loop-is-quadratic) |
| 109 | `Free` on a list was a silent no-op for a global and a dangling-pointer segfault for a function-local: the buffer half of the released-buffer contract never reached lists | crash | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#109-free-on-a-list-was-a-silent-no-op-for-a-global-and-a-dangling-pointer-segfault-for-a-function-local--the-buffer-half-of-the-released-buffer-contract-never-reached-lists) |
| 110 | A single-quoted ONE-WORD name never resolved inside a `{...}` format-string slot: every type, quotes and all read back as the "variable" | wrong output on valid input | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#110-a-single-quoted-one-word-name-never-resolved-inside-a--format-string-slot--every-type-quotes-and-all-read-back-as-the-variable) |
| 111 | Nested collections were shared by pointer, not copied: a list or map placed inside another one aliased the SAME block, so mutating either side reached the other, and freeing the outer one dangled the original name | wrong output on valid input | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#111-nested-collections-were-shared-by-pointer-not-copied--a-list-or-map-placed-inside-another-one-aliased-the-same-block-so-mutating-either-side-reached-the-other-and-freeing-the-outer-one-dangled-the-original-name) |
| 112 | A typed function that falls off its end hands back the empty value of every declared type: before this fix that was true for four of eleven, and the rest crashed | wrong output on valid input | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#112-a-typed-function-that-falls-off-its-end-hands-back-the-empty-value-of-every-declared-type--before-this-fix-that-was-true-for-four-of-eleven-and-the-rest-crashed) |
| 114 | Reading a number-valued map key into a `text` variable compiles clean and segfaults on first string use; the type check that fires for a literal map is absent for a dynamically-built one | crash | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#114-reading-a-number-valued-map-key-into-a-text-variable-compiles-clean-and-segfaults-on-first-string-use-the-type-check-that-fires-for-a-literal-map-is-absent-for-a-dynamically-built-one) |
| 115 | A dynamically-typed value read into a statically-typed variable copies the bits with no runtime tag check, at every landing site except map access: a memory-safety class | wrong output on valid input | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#115-a-dynamically-typed-value-read-into-a-statically-typed-variable-copies-the-bits-with-no-runtime-tag-check-at-every-landing-site-except-map-access-a-memory-safety-class) |
| 116 | An untyped `Set` that retypes a name it created prints a raw address instead of the value | wrong output on valid input | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#116-an-untyped-set-that-retypes-a-name-it-created-prints-a-raw-address-instead-of-the-value) |
| 117 | A text appended into a caller's list through a parameter prints an address | wrong output on valid input | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#117-a-text-appended-into-a-callers-list-through-a-parameter-prints-an-address) |
| 118 | `Set <global> to ...` refuses a list/map/buffer global that a function reads, with the caret on the declaration | spurious compile error | fixed in 0.4.15, a duplicate of #92 | [0.4.15](bugs/0.4.15.md#118-set-global-to--refuses-a-listmapbuffer-global-that-a-function-reads-with-the-caret-on-the-declaration) |
| 119 | A file handle (or plain variable) declared inside a branch is treated as undeclared after the branch | spurious compile error | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#119-a-file-handle-or-plain-variable-declared-inside-a-branch-is-treated-as-undeclared-after-the-branch) |
| 120 | A possessive member call stops parsing at a line break before its preposition | spurious compile error | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#120-a-possessive-member-call-stops-parsing-at-a-line-break-before-its-preposition) |
| 121 | A removed directory still answers `available` | unclassified | not a compiler defect: did not reproduce | [not-bugs](bugs/not-bugs.md#121-a-removed-directory-still-answers-available) |
| 122 | A `To` inside an open `If`/loop body is swallowed into the body | accepted invalid input | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#122-a-to-inside-an-open-ifloop-body-is-swallowed-into-the-body) |
| 123 | Redeclaring a name as another kind reports "Unknown variable" at the read, not the conflict | unclassified | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#123-redeclaring-a-name-as-another-kind-reports-unknown-variable-at-the-read-not-the-conflict) |
| 124 | A user-facing error cites LANGUAGE.md by a now-stale line number | unclassified | fixed in 0.4.11, a duplicate of #93 | [0.4.11](bugs/0.4.11.md#124-a-user-facing-error-cites-languagemd-by-a-now-stale-line-number) |
| 125 | `Set message to "x".` blames `to` instead of the reserved word the author typed | unclassified | fixed in 0.4.11, a duplicate of #94 | [0.4.11](bugs/0.4.11.md#125-set-message-to-x-blames-to-instead-of-the-reserved-word-the-author-typed) |
| 126 | An unrecognised format specifier is silently discarded | accepted invalid input | fixed in 0.4.11, a duplicate of #98 | [0.4.11](bugs/0.4.11.md#126-an-unrecognised-format-specifier-is-silently-discarded) |
| 127 | A malformed precision `{n:.z}` is silently ignored | accepted invalid input | fixed in 0.4.15 | [0.4.15](bugs/0.4.15.md#127-a-malformed-precision-nz-is-silently-ignored) |
| 128 | `Free` through one name of an assigned list, then a read through the other name, segfaults | crash | fixed in the next release | [unreleased](bugs/unreleased.md#128-free-through-one-name-of-an-assigned-list-then-a-read-through-the-other-name-segfaults) |
| 129 | A number field used to initialise a text variable segfaults | accepted invalid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#129-a-number-field-used-to-initialise-a-text-variable-segfaults) |
| 130 | A text written into a number field is stored as its address | accepted invalid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#130-a-text-written-into-a-number-field-is-stored-as-its-address) |
| 131 | A zero-argument call written directly is not honoured in three positions | wrong output on valid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#131-a-zero-argument-call-written-directly-is-not-honoured-in-three-positions) |
| 132 | A `see` nested in an `If` body or a function body is silently dropped | accepted invalid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#132-a-see-nested-in-an-if-body-or-a-function-body-is-silently-dropped) |
| 133 | A device-node minor number is encoded in 8 bits | wrong output on valid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#133-a-device-node-minor-number-is-encoded-in-8-bits) |
| 134 | The `none` + `move`/`bind` mount pattern is recognised only for literals | wrong output on valid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#134-the-none--movebind-mount-pattern-is-recognised-only-for-literals) |
| 135 | A signal number or pid wider than 32 bits reaches kill(2) as a different value | wrong output on valid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#135-a-signal-number-or-pid-wider-than-32-bits-reaches-kill2-as-a-different-value) |
| 136 | An exit code above 255 exits with a different status | wrong output on valid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#136-an-exit-code-above-255-exits-with-a-different-status) |
| 137 | A time used to initialise a text variable segfaults | accepted invalid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#137-a-time-used-to-initialise-a-text-variable-segfaults) |
| 138 | A list parameter's `'s first` and `'s last` read text elements as numbers | wrong output on valid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#138-a-list-parameters-s-first-and-s-last-read-text-elements-as-numbers) |
| 139 | One list passed as two parameters splits when it grows | wrong output on valid input | fixed in the next release | [unreleased](bugs/unreleased.md#139-one-list-passed-as-two-parameters-splits-when-it-grows) |
| 140 | `Free` through one of two parameters naming one list, then a read through the other, segfaults | crash | fixed in the next release | [unreleased](bugs/unreleased.md#140-free-through-one-of-two-parameters-naming-one-list-then-a-read-through-the-other-segfaults) |
| 141 | A boolean field `as text` gives "1" | wrong output on valid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#141-a-boolean-field-as-text-gives-1) |
| 142 | `reap process <pid>` with 0 or a negative pid reaps another child | wrong output on valid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#142-reap-process-pid-with-0-or-a-negative-pid-reaps-another-child) |
| 143 | Two names of one collection can disagree: growth, `Free` and `Set` through one are not seen by the other | wrong output on valid input | fixed in the next release | [unreleased](bugs/unreleased.md#143-two-names-of-one-collection-can-disagree-growth-free-and-set-through-one-are-not-seen-by-the-other) |
| 144 | A call with arguments cannot be the source of `Write` or of `append` to a buffer, even braced | spurious compile error | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#144-a-call-with-arguments-cannot-be-the-source-of-write-or-of-append-to-a-buffer-even-braced) |
| 145 | A list declared with `The X is <list>.` refuses `'s length`, and the message names `size` | spurious compile error | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#145-a-list-declared-with-the-x-is-list-refuses-s-length-and-the-message-names-size) |
| 146 | A shared library asks for an executable stack, so a C host cannot `dlopen` it | unclassified | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#146-a-shared-library-asks-for-an-executable-stack-so-a-c-host-cannot-dlopen-it) |
| 147 | Arithmetic on a call that returns a text, a `value` or another type arithmetic refuses computes on raw bits | accepted invalid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#147-arithmetic-on-a-call-that-returns-a-text-a-value-or-another-type-arithmetic-refuses-computes-on-raw-bits) |
| 148 | A width in a format string is accepted and not applied on a `float` or a `text` | wrong output on valid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#148-a-width-in-a-format-string-is-accepted-and-not-applied-on-a-float-or-a-text) |
| 149 | Dividing the most negative number by -1 stops the program | crash | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#149-dividing-the-most-negative-number-by--1-stops-the-program) |
| 150 | An ordering comparison on a text, a list, a map or a buffer compares memory addresses | accepted invalid input | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#150-an-ordering-comparison-on-a-text-a-list-a-map-or-a-buffer-compares-memory-addresses) |
| 151 | Comparing a list element that holds a number with a text segfaults | crash | fixed in 0.4.16 | [0.4.16](bugs/0.4.16.md#151-comparing-a-list-element-that-holds-a-number-with-a-text-segfaults) |
| 152 | `Get current time into` a declared text, number or list turns it into a time | accepted invalid input | fixed in the next release | [unreleased](bugs/unreleased.md#152-get-current-time-into-a-declared-text-number-or-list-turns-it-into-a-time) |
| 153 | A comparison is refused as the value of a declaration or a `Set` | spurious compile error | fixed in the next release | [unreleased](bugs/unreleased.md#153-a-comparison-is-refused-as-the-value-of-a-declaration-or-a-set) |
| 154 | A format string reassigned to a text with `the <name> is` is refused | spurious compile error | fixed in the next release | [unreleased](bugs/unreleased.md#154-a-format-string-reassigned-to-a-text-with-the-name-is-is-refused) |
| 155 | A file opened in a branch under a top-level buffer's name segfaults | crash | fixed in the next release | [unreleased](bugs/unreleased.md#155-a-file-opened-in-a-branch-under-a-top-level-buffers-name-segfaults) |
| 156 | An element of a list parameter named in a local, then appended, prints an address | wrong output on valid input | fixed in the next release | [unreleased](bugs/unreleased.md#156-an-element-of-a-list-parameter-named-in-a-local-then-appended-prints-an-address) |
| 157 | Two `value`s holding equal texts compare not equal | wrong output on valid input | fixed in the next release | [unreleased](bugs/unreleased.md#157-two-values-holding-equal-texts-compare-not-equal) |
| 158 | A format string as the match of `treating` never fires over a text list | wrong output on valid input | fixed in the next release | [unreleased](bugs/unreleased.md#158-a-format-string-as-the-match-of-treating-never-fires-over-a-text-list) |
| 159 | A width with `.0` on a whole number is one character short | wrong output on valid input | fixed in the next release | [unreleased](bugs/unreleased.md#159-a-width-with-0-on-a-whole-number-is-one-character-short) |
| 160 | After an `Otherwise`, one closing period is lost | wrong output on valid input | fixed in the next release | [unreleased](bugs/unreleased.md#160-after-an-otherwise-one-closing-period-is-lost) |
| 161 | `{n:0.2}`, `{n:00.2}` and `{n:0.0}` are refused | spurious compile error | fixed in the next release | [unreleased](bugs/unreleased.md#161-n02-n002-and-n00-are-refused) |
| 162 | A list holding `nan` is equal to itself | wrong output on valid input | fixed in the next release | [unreleased](bugs/unreleased.md#162-a-list-holding-nan-is-equal-to-itself) |
| 163 | Reading a global timer's `elapsed` inside a function stops the program | crash | open | [open entries](#163-reading-a-global-timers-elapsed-inside-a-function-stops-the-program) |
| 164 | A hole naming a parameter called 'the text' as `{the text}` prints a stray value | wrong output on valid input | open | [open entries](#164-a-hole-naming-a-parameter-called-the-text-as-the-text-prints-a-stray-value) |
| 165 | Appending an untyped call's result to a buffer writes an address | wrong output on valid input | open | [open entries](#165-appending-an-untyped-calls-result-to-a-buffer-writes-an-address) |
| 166 | A text from `arguments's all`, named in a local and appended to a list, is stored as an address | wrong output on valid input | open | [open entries](#166-a-text-from-argumentss-all-named-in-a-local-and-appended-to-a-list-is-stored-as-an-address) |
| 167 | A loop variable over a returned list, cast as a number, gives the text's address | wrong output on valid input | open | [open entries](#167-a-loop-variable-over-a-returned-list-cast-as-a-number-gives-the-texts-address) |
| 168 | A `Library` line arriving through `see` silently renames the library | wrong output on valid input | open | [open entries](#168-a-library-line-arriving-through-see-silently-renames-the-library) |
| 169 | A shared library cannot use another library's `.lib` | spurious compile error | open | [open entries](#169-a-shared-library-cannot-use-another-librarys-lib) |
| 170 | Whether a local can shadow a global depends on where the function is | spurious compile error | open | [open entries](#170-whether-a-local-can-shadow-a-global-depends-on-where-the-function-is) |
| 171 | A text from `arguments's name` is refused as an append source | spurious compile error | open | [open entries](#171-a-text-from-argumentss-name-is-refused-as-an-append-source) |
| 172 | A timer parameter cannot read `elapsed` | spurious compile error | open | [open entries](#172-a-timer-parameter-cannot-read-elapsed) |
| 173 | A lexer error inside a `see`-included file is reported at the including file's first line | spurious compile error | open | [open entries](#173-a-lexer-error-inside-a-see-included-file-is-reported-at-the-including-files-first-line) |
| 174 | When memory runs out, a growing buffer stops the program with a segfault instead of a message | crash | open | [open entries](#174-when-memory-runs-out-a-growing-buffer-stops-the-program-with-a-segfault-instead-of-a-message) |
