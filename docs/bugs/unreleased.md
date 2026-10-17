# Fixed in the next release

Register entries fixed on main since 0.4.16, moved here unchanged from [the register](../BUGS_FOUND.md), which indexes every entry.

---

### 128. `Free` through one name of an assigned list, then a read through the other name, segfaults

**Status:** **fixed** (unreleased). Registered 2026-10-05. Verified on vox 0.4.15 (8c73f0d); confirmed by TheJostler 2026-10-05. Regression test: tests/867_freeing_a_list_leaves_its_named_copy.vox.

```vox
a list called xs is ["a"].
a list called ys is xs.
Free xs.
print ys's length.
```
```text
$ vox free_alias.vox -o free_alias && ./free_alias
Segmentation fault         (core dumped)
[exit 139]
```

**Observed:** the program dies on a signal at the read of `ys`.

**Expected:** `1`. Naming copies: `a list called ys is xs.` gives `ys` its own list, so `Free xs.` leaves `ys` holding `["a"]`. Sharing one list under two names is written `xs is also called ys.`, and then `Free xs.` empties it for both names. Never a signal.

**The manual:** LANGUAGE.md "Releasing a Buffer": "A list also accepts `Free`, with the same after-state a buffer gets: it becomes **empty** (length 0, `empty` is true, prints `[]`), and every later write - `append`, `Set element N of ...` - is refused with the error flag; a second `Free` is the same no-op-that-flags, not a second release. Free releases the list and every collection it holds: a nested list or map element is freed too, recursively, before the list itself is." The manual has no sentence on what `a list called ys is xs.` means; the rule below settles it for this entry.

**Root cause:** `a list called ys is xs.` stored `xs`'s block pointer in `ys`, so the two names held one block; `Free xs.` released it and pointed only `xs` at the empty released list, leaving `ys` on the released block.

**Fix direction:** TheJostler ruled on 2026-10-05 that a segmentation fault here is a bug. A name copies what it is given, so each name owns its list and `Free` on one name never leaves another holding a released block. Where two names are written as one list (`xs is also called ys.`), `Free xs.` empties the list for both. `Free` releases the children a list holds, tracked by the allocation tracker Vox already uses.

**Fix:** naming copies. A list or map given a name from another name (a declaration, `Set`, `is`, `the ... is`, `Return` of a parameter's or a top-level list, storing it in a `value`, passing it to a `value` parameter) is that name's own copy, all the way down. The program above now prints `1`: `Free xs.` empties `xs` and leaves `ys` holding `["a"]`. The other outcome this entry describes, two names for one list where `Free` empties both, belongs to `is also called`, which Vox does not have yet; until it does, two names share one list only as two parameters given the same list.

---

### 139. One list passed as two parameters splits when it grows

**Status:** **fixed** (unreleased). Registered 2026-10-05. Verified on vox main dfdfc7f; confirmed by TheJostler 2026-10-05. Regression tests: tests/812_one_list_passed_as_two_parameters_grows_as_one.vox, tests/813_one_map_passed_as_two_parameters_grows_as_one.vox.

```vox
To 'merge' of a list called first and a list called second.
    For each number from 1 to 20, append the number to first.
    Print "second sees: {second's length}".
    append "via second" to second.
    Print "first sees: {first's length}".

a list called xs is ["a"].
'merge' of xs and xs.
Print "xs length: {xs's length}".
Print "xs last: {xs's last}".
```
```text
$ vox merge_growth.vox -o merge_growth && ./merge_growth
second sees: 8
first sees: 21
xs length: 9
xs last: via second
[exit 0]
```

**Observed:** after 20 appends through `first`, `second` still sees 8 elements, and the append through `second` is lost to `first`. The caller's `xs` ends with 9 elements. Both parameters named the same list, and the list has split in two. A map passed twice behaves the same way.

**Expected:** `second sees: 21`, `first sees: 22`, `xs length: 22`, `xs last: via second`. Each parameter is the caller's list, so both are one list.

**The manual:** LANGUAGE.md "Functions" and "Function Calls" (list parameters): a list parameter names the caller's collection, and growth through it is the caller's growth.

**Root cause:** each name kept its own copy of the list's block pointer: a list parameter's slot held a copy of the caller's pointer, written back to the caller only by the growth that went through that one parameter, so a second parameter naming the same list kept the old block.

**Fix direction:** TheJostler confirmed on 2026-10-05 that this is a bug. Every name of a list (a variable, a parameter, and `is also called`) goes through the one slot that owns the list, so growth, `Free` and writes through any name are seen by all. This is the same change that settles #140 and #143.

**Fix:** a `list`, `map` or `buffer` parameter holds the address of the word that owns the collection, never a copy of the block. Every read through the parameter goes to that word at the point of use, and every growth, `Free` or `Set` through it writes the new block there before anything else runs, so both parameters, and the caller, see one list. The program above prints `second sees: 21`, `first sees: 22`, `xs length: 22`, `xs last: via second`.

---

### 140. `Free` through one of two parameters naming one list, then a read through the other, segfaults

**Status:** **fixed** (unreleased). Registered 2026-10-05. Verified on vox main dfdfc7f; confirmed by TheJostler 2026-10-05. Regression tests: tests/814_one_list_passed_as_two_parameters_freed_through_one.vox, tests/816_one_buffer_passed_as_two_parameters_freed_through_one.vox.

```vox
To 'merge' of a list called first and a list called second.
    Free first.
    Print "second sees: {second's length}".
    append "after" to second.
    Print "second now: {second}".

a list called xs is ["a", "b"].
'merge' of xs and xs.
Print "xs: {xs}".
```
```text
$ vox merge_free.vox -o merge_free && ./merge_free
second sees: Segmentation fault         (core dumped)
[exit 139]
```

**Observed:** the program dies on a signal at the read through `second`.

**Expected:** `second sees: 0`, then the append is refused with the error flag and `second now: []`, then `xs: []`. `Free first.` empties the one list both parameters name. Never a signal.

**The manual:** LANGUAGE.md "Releasing a Buffer": a freed list becomes empty, and every later write is refused with the error flag. Parameters name the caller's list.

**Root cause:** `Free first.` pointed `first`'s own slot, and the caller's, at the released list; `second` kept its copy of the block `Free` had just released.

**Fix direction:** TheJostler ruled on 2026-10-05 that a segmentation fault here is a bug. Naming copies, but a parameter still borrows the caller's list, so two parameters can name one list and this program remains reachable under the copy rule. The one-owning-slot representation described under #139 removes it: `Free` through either parameter empties the list for both.

**Fix:** the one-owning-place change described under #139. `Free first.` stores the released list in the word that owns the list, which both parameters read. The program above prints `second sees: 0`, refuses the append with the error flag, and prints `second now: []` and `xs: []`.

---

### 143. Two names of one collection can disagree: growth, `Free` and `Set` through one are not seen by the other

**Status:** **fixed** (unreleased). Registered 2026-10-05. Verified on vox main dfdfc7f; confirmed by TheJostler 2026-10-05. Regression tests: (a) tests/815_one_buffer_passed_as_two_parameters_grows_as_one.vox, (b) tests/816_one_buffer_passed_as_two_parameters_freed_through_one.vox, (c) tests/817_a_list_freed_by_its_global_name_while_a_parameter_names_it.vox, (e) tests/844_a_for_each_over_a_list_the_body_frees.vox, (f) tests/836_a_list_write_whose_value_grows_the_list.vox and tests/837_a_map_write_whose_value_grows_the_map.vox, (g) tests/818_set_on_a_list_parameter_replaces_the_callers_list.vox, (d) tests/878_a_value_parameter_holds_a_copy.vox.

Seven programs, one cause: each name of a collection keeps its own copy of the block pointer, so a change that moves or releases the block through one name leaves the others on the old block. Each was re-run on vox main dfdfc7f from a directory outside any repository. Each program below is shown with its own output.

**(a) One buffer passed as two parameters, grown through the first, read through the second.**
```vox
To 'merge' of a buffer called first and a buffer called second.
    For each number from 1 to 3000, append "abcdefgh" to first.
    Print "second sees: {second's size}".
    append "Z" to second.
    Print "first sees: {first's size}".

a buffer called hold is "a".
'merge' of hold and hold.
Print "hold size: {hold's size}".
```
```text
second sees: Segmentation fault         (core dumped)
[exit 139]
```
Expected: `second sees: 24001`, `first sees: 24002`, `hold size: 24002`.

**(b) `Free` through one of two buffer parameters naming one buffer, then a read through the other.**
```vox
To 'merge' of a buffer called first and a buffer called second.
    Free first.
    Print "second sees: {second's size}".
    append "after" to second.
    Print "second now: {second}".

a buffer called hold is "ab".
'merge' of hold and hold.
Print "hold: {hold}".
```
```text
second sees: Segmentation fault         (core dumped)
[exit 139]
```
Expected: `second sees: 0`, the append refused with the error flag, `second now: `, `hold: `.

**(c) `Free` by a list's global name inside a function, then a read of the list parameter that names it.**
```vox
a list called xs is ["a", "b"].
To 'look at' with a list called items.
    Free xs.
    Print "items: {items}".

'look at' of xs.
Print "xs: {xs}".
```
```text
items: [Segmentation fault         (core dumped)
[exit 139]
```
Expected: `items: []`, then `xs: []`.

**(d) The same with a `value` parameter.**
```vox
a list called xs is ["a", "b"].
To 'look at' with a value called v.
    Free xs.
    Print "v: {v}".

'look at' of xs.
Print "xs: {xs}".
```
```text
v: [Segmentation fault         (core dumped)
[exit 139]
```
Expected: `v: []`, then `xs: []`.

**(e) `Free` inside `For each` over the same list.**
```vox
a list called xs is ["a", "b", "c"].
For each item in xs, print item, Free xs.
Print "after: {xs's length}".
```
```text
a
Segmentation fault         (core dumped)
[exit 139]
```
Expected: `a`, then the loop ends because the list is empty, then `after: 0`.

**(f) A call that grows the list the statement writes into.**
```vox
To 'grow' with a list called items.
    For each number from 1 to 20, append the number to items.
    Return a number, 99.

a list called xs is [1, 2].
Set element 1 of xs to 'grow' of xs.
Print "first: {element 1 of xs}, length: {xs's length}".
a list called ys is [1, 2].
append 'grow' of ys to ys.
Print "last: {ys's last}, length: {ys's length}".
```
```text
first: 1, length: 22
last: 99, length: 9
[exit 0]
```
Expected: `first: 99, length: 22` and `last: 99, length: 23`. The first write is lost, and the second append lands on a stale copy of `ys`. A map does the same:
```vox
To 'grow map' with a map called shelf.
    For each number from 1 to 20, Set shelf's "{number}" to number.
    Return a number, 99.

a map called m is {"k": 1}.
Set m's "k" to 'grow map' of m.
a number called k is m's "k".
Print "k: {k}, length: {m's length}".
```
```text
k: 99, length: 8
```
Expected length: 21. Here the write is kept and the 20 new entries are lost.

**(g) `Set` on a list parameter does not reach the caller.**
```vox
To 'replace it' with a list called items.
    Set items to ["new"].
    Print "inside: {items}".

a list called xs is ["old"].
'replace it' of xs.
Print "xs: {xs}".
```
```text
inside: ["new"]
xs: ["old"]
[exit 0]
```
Expected: `xs: ["new"]`. The parameter is the caller's list.

**Observed:** four programs die on a signal, and three silently lose a write or a growth.

**The manual:** LANGUAGE.md "Functions" and "Function Calls": a buffer parameter and a list parameter each name the caller's collection, so a change through the parameter is a change to the caller's; and "Releasing a Buffer": a freed collection is empty and refuses writes. Never a signal.

**Root cause:** shared with #128, #139 and #140. Every name caches the block pointer of the collection, so growth or `Free` through one name leaves the others pointing at the old block. In (f) the statement also loaded the list or map before working out the value, so the call's growth went to a block the write no longer used.

**Fix direction:** TheJostler confirmed the whole family on 2026-10-05. Every name of a collection (variable, parameter, `value` parameter, loop source, and later `is also called`) goes through the one slot that owns it, so growth, `Free` and `Set` through any name are seen by every name. Which `For each` should see a write made during the loop is a separate question with its own ruling; this entry covers the crashes and the lost writes only.

**Fix:** (a), (b), (c) and (g): a `list`, `map` or `buffer` parameter holds the address of the word that owns the collection (see #139), so a parameter reads what the owner holds now, and `Set` on a parameter replaces the caller's list. (e): a `For each` over a named list reads the list again from its owner at every iteration and stops when the list is shorter than the index, so after `Free` it ends. (f): a statement works out its value (and an index or a key) first and loads the collection last. Programs (a), (b), (c), (e), (f) and (g) now print their Expected output. (d): a list passed to a `value` parameter is copied into it, as storing a list in a `value` is, so the function's `v` keeps `["a", "b"]` while `Free xs.` empties `xs`: the program prints `v: ["a", "b"]`, then `xs: []`. Its Expected above (`v: []`) reads the `value` parameter as sharing the caller's list; with naming copies it holds its own.

---

### 152. `Get current time into` a declared text, number or list turns it into a time

**Status:** **fixed** (unreleased). Registered 2026-10-16. Verified on vox 0.4.16; confirmed by TheJostler 2026-10-16. Regression tests: tests/compile_fail/the_current_time_cannot_go_into_text.vox and its siblings for a number, a float, a boolean, a list, a map, a buffer and a `value`, and tests/863_the_current_time_goes_into_a_time_or_a_new_name.vox.

```vox
a text called here is "hello".
Get current time into here.
Print "{here}".
Print "hour {here's hour}".
```
```text
$ vox clock_into_text.vox -o clock_into_text && ./clock_into_text
1792147030
hour 10
```

**Observed:** the statement compiles and quietly changes `here` from a text into a time: it prints the time in seconds, and `here's hour`, a property only a time has, is accepted. A declared `number` becomes a time the same way. A declared `list` also compiles, and a later `append "b" to xs.` then fails in the assembler (`symbol '_file_size' not defined`). A declared `buffer` fails in the assembler at the `Get` itself.

**Expected:** a declared variable keeps its type. `Get current time into` takes a `time` (or a name not yet declared); a text, number, list or buffer is refused at compile time with a message naming the variable and its type.

**The manual:** LANGUAGE.md "Type Immutability": "A variable's type is fixed at its declaration and never changes"; LANGUAGE.md "Getting Current Time": `Get current time into now.`.

**Root cause:** the statement made a new slot for its name and recorded the name as a time, whatever the name had been declared as. Every later use read that slot as a time, so a text or a number printed the seconds and took a time's properties, and a later list or buffer statement on the name was given a time to work on, which the assembler then could not build.

**Fix:** `Get current time into` takes a `time`, or a name not yet declared, which it declares as a time. Any other declared variable is refused at compile time, naming it and its type: `'here' is text, so it cannot take the current time: a variable's type is fixed at its declaration`, with the hint to get the time into a time or a new name. A name declared inside a function is judged the same way.

---

### 153. A comparison is refused as the value of a declaration or a `Set`

**Reproducer:**

```vox
a number called x is 3.
a number called y is 3.
a boolean called same is x is y.
Print "{same}".
```

- **Expected:** `same` is declared as `true` and the program prints `1`.
- **Actual:** the declaration stops at the first `is` after `x` and reads the second `is` as the start of a new statement:

```text
$ vox comparison_into_boolean.vox -o comparison_into_boolean
error: Expected a statement, got Is
  --> comparison_into_boolean.vox:3:28
```

`Set same to x is y.` is refused the same way. The same comparison is accepted as a `Return` value (`Return a boolean, x is y.` answers `1`) and as a condition.

**Class:** spurious compile error.

**Phase:** parse.

**Claims:** LANGUAGE.md "Grammar Summary": `var_decl ::= ("a" | "an") type "called" name "is" expr "."`, with `expr` reaching `comparison ::= additive (comp_op additive)?`. LANGUAGE.md "Definition" returns a comparison as a value: `Return a boolean, the divisor modulo the dividend is 0.` LANGUAGE.md "Type Predicates": "A predicate result is itself a boolean value, so you can store one".

**Pile:** manual says X, compiler does Y.

**Hits:** 1, first and last seen 2026-10-17.

**State:** fixed in the next release. Registered 2026-10-17. Verified on vox 0.4.16 and on main 9544ceb; confirmed by TheJostler 2026-10-17. Regression tests: tests/900_a_comparison_is_the_value_of_a_declaration.vox, tests/901_a_comparison_is_the_value_of_a_set.vox, tests/902_every_comparison_declares_and_sets_a_boolean_at_the_top_level.vox, tests/903_every_comparison_declares_and_sets_a_boolean_in_a_function.vox, tests/904_a_comparison_value_leaves_the_next_action_of_a_clause_alone.vox, tests/905_existing_declarations_and_assignments_read_as_before.vox, tests/compile_fail/900_a_number_cannot_be_declared_or_set_from_a_comparison.vox.

---

### 154. A format string reassigned to a text with `the <name> is` is refused

**Reproducer:**

```vox
a text called path is "a.txt".
a text called note is "".
the note is "processed {path}".
Print note.
```

- **Expected:** the program prints `processed a.txt`.
- **Actual:** the reassignment is refused, and the caret points at the declaration on line 2, not at the statement on line 3:

```text
$ vox format_into_text.vox -o format_into_text
error: Format-string assignment requires a buffer destination: note
  --> format_into_text.vox:2:15
```

A plain literal (`the note is "plain".`) is accepted, and so is `Set note to "processed {path}".`, which prints `processed a.txt`.

**Class:** spurious compile error.

**Phase:** analysis (the message comes from the analyzer's assignment check).

**Claims:** LANGUAGE.md "Grammar Summary": `assignment ::= "the" name "is" expr "."`. LANGUAGE.md "Format Strings as Values": a format string "works as a text initializer or assignment", and "A text variable reassigned from a format string releases the string it no longer holds".

**Pile:** manual says X, compiler does Y.

**Hits:** 1, first and last seen 2026-10-17.

**State:** fixed in the next release. Registered 2026-10-17. Verified on vox 0.4.16 and on main 9544ceb; confirmed by TheJostler 2026-10-17. Regression tests: tests/906_a_format_string_reassigns_a_text_with_the_is.vox, tests/907_format_strings_with_every_hole_reassign_with_the_is.vox, tests/compile_fail/901_a_format_string_cannot_be_written_into_a_number_with_the_is.vox.
