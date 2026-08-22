# Vox Language Specification

**Version 0.4.10**

This document defines the syntax and semantics of Vox (sentence based code).
It states the language as it is now. What changed in which release is in
[CHANGELOG.md](CHANGELOG.md), the defect register
[docs/BUGS_FOUND.md](docs/BUGS_FOUND.md), and [docs/HISTORY.md](docs/HISTORY.md).

---

## Table of Contents

1. [Basics](#basics)
2. [Types](#types)
3. [Variables](#variables)
4. [Names and strings](#names-and-strings)
5. [Functions](#functions)
6. [Things](#things)
7. [Expressions](#expressions)
8. [Control Flow](#control-flow)
9. [Lists and Collections](#lists-and-collections)
10. [Input/Output](#inputoutput)
11. [File I/O](#file-io)
12. [Directories, Mounting, and Process Control](#directories-mounting-and-process-control)
13. [Time and Timers](#time-and-timers)
14. [Command-Line Arguments](#command-line-arguments)
15. [Environment Variables](#environment-variables)
16. [Operators](#operators)
17. [Keywords](#keywords)
18. [Examples](#examples)
19. [Libraries and Imports](#libraries-and-imports)
20. [Compiler Usage](#compiler-usage)
21. [Grammar Summary](#grammar-summary)

---

## Basics

### Statements

Every statement ends with a **period** (`.`).

```
Print "Hello, World!".
```

### Case Sensitivity

Keywords are **case-insensitive**. These are equivalent:
- `Print`, `print`, `PRINT`
- `If`, `if`, `IF`

### Comments

Comments use **parentheses** `( )` — just like parenthetical remarks in natural language writing.

```
(This is a comment)
print "Hello".

print "World". (end of line comment)

a number (the counter) called x is 5.

(Multi-line comments
work naturally across
several lines)

(Nested (parentheses (are supported)) too)
```

Comments can appear:
- On their own line
- At the end of a statement
- In the middle of a statement (between tokens)
- Spanning multiple lines

### Paragraph Breaks (Blank Lines)

Blank lines (paragraph breaks) organize code into logical sections. They are optional and have no effect on program execution *between two fully-terminated top-level constructs* — for example, between two function definitions or between two complete statements at the top level.

Inside an open clause they are **not** cosmetic: a blank line force-closes every clause that is still open, including an enclosing function definition. Use a blank line to end a construct deliberately (after a `while`, `for each`, `repeat`, `on error`, or nested `if` body), not to add visual spacing in the middle of a body.

```
print "Section 1".

print "Section 2".
```

**Note:** A function definition is closed by a **blank line (paragraph break)** — this is *required*, not a style convention. A period closes only the innermost open clause (rule 1 below), so the period ending a body statement does **not** close the function. Without a blank line after the body, every statement following the signature is absorbed into the function body; since the function is typically not called from within itself, the program then silently does nothing (exit 0, no output). A following `To` or `Library` does begin a new top-level construct and so ends the body, but any other statement is absorbed. The compiler warns when a function definition is still open at end of file. See [The termination rule](#the-termination-rule) below.

### Sentence Consumption

Action-consuming constructs (loops, conditionals, error handlers) consume the **entire sentence** they appear in. Multiple actions within that sentence are separated by **commas**.

```
(Single action)
While x is less than 10, increment x.

(Multiple comma-separated actions in one sentence)
While x is less than 10, print x, increment x.

(For loops work the same way)
For each number from 1 to 10, print the number, print " ".

(Error handlers too)
On error print "Something went wrong", exit 1.

(If/else with multiple actions)
If x is greater than 10 then, print "big", set y to 1. Otherwise, print "small", set y to 0.
```

**Key Rules:**
- **Period** (`.`) ends the entire construct, including all its actions
- **Comma** (`,`) separates multiple actions within the same construct
- Only **function definitions** can span multiple sentences (using paragraph breaks)

**Sentence ownership (nested constructs):**
- A nested construct (especially `if ... then`) owns its **own trailing period**.
- Outer constructs (`while`, `for each`, `repeat`) do **not** steal that inner period.
- After an inner `if` ends, the outer sentence may continue with more actions.

```
While content is not empty,
    if number_lines then,
        print "{line}: " without newline.
    write content to output,
    read line from source into content.
```

In the example above, the period after the inner `if` closes only that `if`. The `while` body continues with `write` and `read`.

### The termination rule

Two rules govern where a construct's body ends, and together they explain everything above precisely:

1. **A period closes the most recently opened clause** — the innermost one currently open (`if`, `on error`, `for`, `while`, `repeat`), and only that one. This is why the nested `if` example above works: its period closes the `if`, not the `while`. One period closes one level; to close more than one, write more than one — see [Closing more than one level](#closing-more-than-one-level).
2. **A blank line (paragraph break) force-closes every open clause at once** — including an enclosing function definition. Think of nested HTML `<div>`s: a paragraph boundary closes all of them together, the same way you would never continue a single sentence across a paragraph break in English.

```
(A blank line closes everything still open, not just the nearest thing)
a number called retries is 0.
While retries is less than 3,
    if retries is equal to 1 then, print "retrying".
    the retries is retries add 1.

Print "done".
```

This prints `retrying` once (when `retries` is 1) then `done` once, after the loop runs its full three iterations — the blank line closes the `while` (rule 2) even though the `if`'s own period already closed the `if` (rule 1); there is nothing special about the `if` being the loop's last action, the blank line would close the loop the same way after any kind of action.

**This applies uniformly** — `while`, `for each`, `repeat`, and `on error` all terminate their body on a blank line, regardless of what the last body statement was (an ordinary statement, an `if`/`on error`, or another nested loop).

**Caution:** because rule 1 means a nested construct's own period doesn't close its parent, a blank line placed purely for visual readability *inside* a loop body — after a nested `if` or a nested loop, before more of the same loop's actions — will close that loop early, not just add whitespace:

```
(This blank line is NOT cosmetic - it ends the outer while)
a number called round is 0.
While round is less than 2,
    the round is round add 1,
    For each item in batch,
        print item.

    print "batch done".
```

This prints `1 2 1 2 batch done` — not `1 2 batch done 1 2 batch done` as the indentation suggests. `print "batch done".` runs once, after the loop, not once per batch, because the blank line closed the `while` right after the nested `for each` closed itself.

**This can hang your program with no error message, if the ejected statement happens to be the loop's own increment:**

```
(DON'T DO THIS - infinite loop, no diagnostic, the blank line ejects the increment)
a number called counter is 1.
While counter is less than or equal to 2,
    For each k from 1 to 2,
        print "inner {k}".

    increment counter.
Print "end".
```

`increment counter.` is ejected from the `while` body by the same blank line, so `counter` never changes and the loop never becomes false — it hangs forever, printing `inner 1` / `inner 2` on repeat, and `Print "end".` never runs. There is no error, no warning, and nothing in the output points at the blank line as the cause. If a loop that should terminate hangs instead, check for a blank line inside its body first.

A blank line placed **after a comma** (mid-sentence, more actions still to come) is the one exception — it is still just visual spacing there, since the sentence is explicitly still open:

```
(Safe: this blank line follows a comma, so it stays cosmetic)
While retries is less than 3,
    print "attempt {retries}",

    increment retries.
```

### Closing more than one level

Rule 1 closes exactly one level, and rule 2 closes all of them. When you are nested several levels deep and want to come back up **some** of the way, **periods stack: write one period per level you want to close.**

```
(Three nested ifs, so three periods to get all the way back out)
a number called n is 0.
If n is equal to 1 then,
    If n is equal to 1 then,
        If n is equal to 1 then, print "innermost"...
print "back at the top".
```

This prints `back at the top`. The three periods close the innermost `if`, then the middle one, then the outer one, so `print "back at the top".` runs at the top level. Written with one period or two, it would still be inside an `if` whose condition is false, and would print nothing at all — with no error.

Indentation is **not** what decides this. Vox ignores leading whitespace entirely, so a program can be minified without changing its meaning; the period count is the only thing that closes a clause.

#### This is how you choose which `if` an `Otherwise` belongs to

An `Otherwise` (or `But if`) continues the innermost `if` that is still open. Closing that `if` first is therefore how you hand the `Otherwise` to an enclosing one. These two programs differ by a **single character** and behave differently:

```
(ONE period: the Otherwise belongs to the INNER if)
a number called m is 5.
If m is equal to 1 then,
    If m is equal to 2 then,
        print "inner then".
    Otherwise,
        print "outer else".

Print "done".
```

prints only `done`. The `Otherwise` continued the inner `if`, so the whole construct sits inside `If m is equal to 1`, which is false — nothing in it runs.

```
(TWO periods: the inner if is closed, so the Otherwise belongs to the OUTER one)
a number called m is 5.
If m is equal to 1 then,
    If m is equal to 2 then,
        print "inner then"..
    Otherwise,
        print "outer else".

Print "done".
```

prints `outer else` then `done`, which is what the indentation in both versions suggests — but only the second one actually says it.

An empty `Otherwise,.` closes an inner chain the same way and is easier to read than a run of periods, since it names the thing being closed instead of asking you to count:

```
(Same result as two periods, spelled out instead of counted)
a number called m is 5.
If m is equal to 1 then,
    If m is equal to 2 then,
        print "inner then".
    Otherwise,.
    Otherwise,
        print "outer else".

Print "done".
```

This also prints `outer else` then `done`. The first `Otherwise,.` takes the inner `if`'s else branch and does nothing with it, which closes that chain; the second one is then free to continue the outer `if`.

**Get the count wrong and nothing tells you.** Too few periods and the following statements are absorbed into a clause you thought you had left; too many and they escape one you meant to stay in. Either way the program still compiles and still runs. If a branch never seems to execute, or a loop that should finish hangs instead, count the periods between it and the construct it belongs to — and remember the hanging case is the same one described above under rule 2: the absorbed statement is the loop's own increment.

### Ranges

Ranges define a sequence of numbers from a start to an end value. They are **not** allocated as lists - they compile directly to efficient loop constructs with a counter, bounds check, and increment.

```
(Basic range in for-each loop)
For each number from 1 to 10, print the number.

(Range with variable bounds)
Set start to 1.
Set end to 5.
For each number from start to end, print the number.

(Range in loop expansion - see below)
print each number from 1 to 10.
```

**Key points:**
- Ranges are **inclusive** - `1 to 5` includes 1, 2, 3, 4, and 5
- Ranges compile to efficient assembly loops, not list allocations
- The loop variable (`the number`) is available inside the loop body

### Loop Expansion

The `each...from` syntax is a **universal loop expansion** that works with any action. It transforms a single action into a loop that executes for each item in a collection or range.

```
(Print each item from a list)
print each number from [1, 2, 3].

(Print each number from a range)
print each number from 1 to 15.

(Call a user function for each item)
process of each item from mylist, print "done".

(Open a file for each argument)
a buffer called content.
open a file for reading called source at each filename from arguments's all,
  read from source into content,
  print the content,
  close source.
```

**Syntax:** `<action> each <variable> from <collection>, <additional actions>`

The action executes once per item in the collection or range, with the loop variable bound to each item. Additional comma-separated actions execute inside the loop after the main action.

**Works with:**
- `print each X from Y` - print each item
- `function of each X from Y` - call function for each item
- `open ... at each X from Y` - open file for each path
- Any action that takes an argument

**Supported collections:**
- **Ranges:** `1 to 10`, `start to end` - numeric sequences
- **Lists:** `[1, 2, 3]`, any list variable
- `arguments's all` - all command-line arguments (argv[1..])

#### Chained `each` clauses — a grid

More than one `each <variable> from <collection>` clause may appear in a single
sentence, joined by `and`. The action then runs once per element of the
**Cartesian product** of the collections, in **row-major order** — the
leftmost clause is the outermost loop, exactly as if the clauses were nested
`For each` loops written left to right:

```
'pair' of each x from [1, 2] and each y from [10, 20].
```

runs `'pair'` four times — `(1,10), (1,20), (2,10), (2,20)` — identical to:

```
For each x from [1, 2],
    For each y from [10, 20],
        'pair' of x and y.
```

There is **no limit** on the number of clauses. A fixed (non-`each`) argument
may sit among them in any position, and is evaluated once per call:

```
'pair' of 5 and each y from [10, 20].       (fixed first, then expansion)
'pair' of each x from [1, 2] and 99.        (expansion first, then fixed)
```

An inner collection may use a variable bound by an outer clause, giving
triangle iteration:

```
'pair' of each row from [1, 2, 3] and each col from 1 to row.
```

A range bound in an `each` clause takes a primary, not an expression —
`each col from row add 1 to 4` is a parse error. Brace an arithmetic bound:
`each col from {row add 1} to 4`.

See **Loop Expansion with Collections** below for the arity rule, the
empty-collection rule, duplicate loop variables, and after-loop values.

### Conditional Branching with `but if`

The `but if` clause is a generic conditional branch over a base action. It is available in both `for each` loops and loop expansion (`<action> each ... from ...`).

```
(FizzBuzz example - print number, but override with word if divisible)
print each number from 1 to 15,
    but if the number modulo 6 is equal to 0 print "fizzbuzz",
    but if the number modulo 2 is equal to 0 print "fizz",
    but if the number modulo 3 is equal to 0 print "buzz".

(Simple even/odd labeling)
print each number from 1 to 10,
    but if the number modulo 2 is equal to 0 print "even".

(Append to a list with a conditional override)
append each number from 1 to 5 to out,
    but if the number modulo 2 is equal to 0 append 0.

(With for-each loop)
For each number from 1 to 15,
  print the number,
    but if divisible of the number and 3 is true print "divisible by 3".
```

**Syntax:** `<base action>, but if <condition> <alternative action>, but if <condition> <alternative action>, ... [otherwise <default alternative action>].`

**How it works:**
1. The default action is the base statement.
2. Each `but if` clause is checked in order.
3. If a condition is true, that alternative action runs instead of the default.
4. If no conditions match, the default action runs.
5. An optional trailing `otherwise` clause provides a final alternative.

**Key points:**
- Conditions are checked in order - first match wins
- Multiple `but if` clauses can be chained
- The alternative action can be any valid Vox statement
- `otherwise` provides a catch-all alternative
- Works with both ranges and collections
- The loop variable (`the number`) is available in conditions
- In an `append` branch, the `to <list/buffer>` target may be omitted and is inherited from the base append statement; retargeting to a different list/buffer is not allowed

### Inline Substitution with `treating`

The `treating X as Y` clause performs inline value substitution - like bash's `${var//X/Y}` but readable.

```
(Replace '-' with "/dev/stdin" for each filename)
open a file for reading called source at each filename from arguments's all treating "-" as "/dev/stdin",
  read from source into content,
  write content to output,
  close source.

(Print with default value)
print each name from names treating "" as "Anonymous".

(Call function with substitution)
process of each filename from files treating "-" as "/dev/stdin".

(Append with substitution - the clause goes with the `each` clause, before
 the `to <destination>`)
append each name from names treating "" as "Anonymous" to cleaned.
```

**Syntax:** `... each <var> from <collection> treating <match> as <replacement>, ...`

If the loop variable equals `<match>`, it's replaced with `<replacement>` for that iteration.

Equality is by type as well as by value: a `<match>` whose type differs from
the element's never fires, and that element comes through unchanged — and
where the compiler can prove the mismatch, it says so at compile time
instead. Where the element, the `<match>` or the `<replacement>` is a
`value`, the runtime tag it carries is what the comparison reads, and a
substitution that fires hands the `<replacement>`'s own type out with it.

---

## Types

| Type | Keyword | Description |
|------|---------|-------------|
| Integer | `number` | Whole numbers |
| Float | `float` | Floating-point numbers (64-bit IEEE 754) |
| String | `text` | Text strings |
| Boolean | `boolean` | `true` or `false` |
| List | `list` | Collection of items |
| Map | `map` | Key/value collection (JSON object; text keys) |
| Buffer | `buffer` | Memory block for I/O (dynamic or fixed-size) |
| File | `file` | File descriptor handle (auto-cleaned) |
| Time | `time` | Date/time value (unix timestamp with components) |
| Timer | `timer` | Stopwatch for measuring durations |
| Thing | `thing` *(contextual)* | User-defined composite value type — see [Things](#things) |

---

## Variables

### Declaration with Type

Use `a` or `an` before the type to declare a new variable:

```
a number called x is 5.
a text called name is "Alice".
a boolean called done is true.
a list called nums is [1, 2, 3].
a map called person is {"name": "Alice", "age": 30}.
```

### Declaration with Set/Create

```
Set a number called counter to 1.
Create a text called greeting to "Hello".
```

### Two Canonical Forms

Every declarable type supports two equivalent forms, both routed through
the same type resolver:

- **`A TYPE called NAME is VALUE.`** — declares `NAME` and initializes it
  to `VALUE` immediately. `Set`/`Create` with `to <value>` (above) is the
  same form with a different lead-in word.
- **`Create a TYPE called NAME.`** — declares `NAME` with no initializer
  and gets that type's default (zero) value:

  ```
  Create a number called n.       (n is 0)
  Create a float called f.        (f is 0.0)
  Create a boolean called b.      (b is false / 0)
  Create a list called items.     (items is [])
  Create a map called m.          (m is {})
  Create a buffer called buf.     (buf is empty, 0 bytes, dynamic capacity)
  Create a value called v.        (v is nothing)
  Create a timer called t.        (t is ready to Start)
  ```

  | Type | Default on bare `Create` |
  |------|---------------------------|
  | `number` | `0` |
  | `float` | `0.0` |
  | `text` | empty string |
  | `boolean` | `false` (`0`) |
  | `list` | `[]` |
  | `map` | `{}` |
  | `buffer` | empty (0 bytes) |
  | `value` | `nothing` |
  | `timer` | ready to `Start` |
  | `file` | **not supported** — see below |
  | `time` | **not supported** — see below |

  **`file` and `time` require an initializer.** A default file or time
  value would be meaningless (no path to open, no timestamp to hold), so
  `Create a file called N.` and `Create a time called N.` are both
  rejected at compile time with a message naming what to supply:

  ```
  Create a file called src.
  (compile error: A file variable must be initialized with a path
     Example: a file called source is "input.txt".)

  Create a time called clk.
  (compile error: A time variable must be initialized
     Example: a time called now is current time.)
  ```

  Give them a value with the first canonical form instead: `a file called
  source is "input.txt".` / `a time called now is current time.`

### Declaration Order

Top-level statements run in the order they are written, so a variable must be
declared **above** the code that reads it. Reading a top-level variable before
its own declaration is a compile-time error:

```
Print label.                     (compile error: 'label' is used before it is declared)
a text called label is "hello".
```

A function body is the exception, and for the same reason: a function runs
when it is **called**, not where it is written, so a body may name a global
declared further down the file — see [Function Scope](#function-scope).

### Assignment (Existing Variable)

Use `the` to reference an existing variable:

```
the x is 10.
the counter is the counter add 1.
```

### Type Immutability

**A variable's type is fixed at its declaration and never changes** —
`value` is the one deliberate exception, covered below. Every form that
writes to an already-declared name — `x is <value>.`, `the x is <value>.`,
and `Set x to <value>.` — is checked the same way: if the new value's type
doesn't match the type `x` was declared with, that's a compile error, not a
silent retype.

```vox fragment
a number called n is 5.
n is "abc".              (compile error: cannot assign text to 'n', which is a number)
n is "42" as a number.   (OK: n is now 42)
```

The error names the variable, its declared type and where it was declared,
the type of the value that doesn't match, and the exact cast that would fix
it:

```text
error: cannot assign text to 'n', which is a number
  --> prog.vox:2:1
   |
 2 | n is "abc".
   | ^ this assigns text
   |
  note: 'n' was declared as a number at prog.vox:1:17
  help: convert it explicitly:  n is "abc" as a number.
```

Convert explicitly with [Type Casting](#type-casting) (`as a number` / `as
text` / ...) — the same mechanism used everywhere else in the language, not
new syntax for this rule.

This isn't limited to reassignment. Any construct that binds a name to a new
runtime value is checked the same way: reusing an already-declared name as a
`For each`/for-range loop variable, as the target of `open ... called`, or
as the target of `Allocate ... for` all reject a type that conflicts with
the name's existing declaration. So does a nested declaration that reuses an
outer name with a different type (Vox has no block-level scoping today, so
there is no separate slot for the inner declaration to occupy):

```vox fragment
a number called n is 5.
If 1 is equal to 2,
  a text called n is "abc".   (compile error: cannot bind 'n' to text in this
                                 declaration; 'n' is already declared as a number)
```

**Two exemptions, both deliberate:**

- **Buffers.** Writing into a buffer (`b is 42.`, `Set b to "text".`) copies
  the value's text representation into the buffer's content — a format
  operation, not a type change — so a buffer accepts any value type on every
  write.
- **`value`.** A variable declared `a value called x` is the language's
  sanctioned dynamic type and keeps accepting any type across reassignment,
  exactly as documented in [Dynamic Values (`value`)](#dynamic-values-value)
  below — that section's behavior is unchanged by this rule, not an
  exception carved out of it. This also covers the in-place retype
  statement `<valuevar> is a <type>.` (e.g. `numstr is a number.`), which
  reads the variable's runtime tag, converts the value, and updates the
  tag in place — see "A `value` can be retyped in place" below. The same
  statement applied to a *statically*-typed variable (`n is a text.` where
  `n` is a `number`) is still rejected by this rule exactly like any other
  mismatched assignment; only a `value`-declared name can be retyped.

**What this doesn't catch.** The check only rejects a mismatch it can prove
statically from the value's own shape (a literal, a cast, a read from a
list/map whose element type is provably uniform, a `'s <property>` read
whose property has the same type whatever it is read from — every property
in the tables under [Object Properties](#object-properties) except
`first`, `last`, `absolute`, `duration` and `elapsed`, whose type follows
the thing they are read from — ...). A value coming from a function call,
an unprovable list/map read (a map literal with mixed value types, for
instance), or anything else the compiler can't classify at compile time is
allowed through unchecked. This closes a large, concrete class of bugs — a
variable's compiler-tracked type disagreeing with what it actually holds at
runtime — not every possible source of type confusion, and it says nothing
about type agreement across a `.lib` import boundary (a library's declared
signature is currently trusted, not verified against its `.so`).

### Naming Rules

A name is an **identifier**, never a string literal. Three forms, no overlap,
no context-sensitivity:

| Form | Meaning | Example |
|---|---|---|
| `"..."` | **String literal. Always. Everywhere.** | `print "hello".` |
| `bare_word` | Identifier, single word | `a number called total is 5.` |
| `'multi word'` | Identifier, contains spaces | `a number called 'total items' is 5.` |

1. **`"..."` is never an identifier**, in any position. Where an identifier is
   expected and a string literal is found, that is a compile error.
2. A **bare identifier** matches `[A-Za-z_][A-Za-z0-9_]*` and is not a reserved
   keyword. Reserved keywords remain rejected as names — so a flag named
   `number` or `version` must be written `'number'` / `'version'`.
3. A **quoted identifier** is `'` … `'` containing **two or more characters**
   and no newline. Exactly one character between single quotes remains a
   **character literal** (`'A'`) — that is why single-character quoted
   identifiers do not exist. Write `x`, not `'x'`.
4. Single-word quoted identifiers (`'total'`) are legal but non-canonical; they
   lex identically to the bare form. Prefer bare.
5. **Possessive.** `'name's length` is canonical: after a closing identifier
   quote, an `s` immediately following (no space) and itself followed by a
   non-identifier character lexes as the possessive marker. `'name''s` also
   works; both are accepted.
6. **These are data, not names, and stay double-quoted:** map keys
   (`person's "name"`), file paths (`see "./utils.vox"`), flag aliases
   (`"-v"`), and versions (`version "1.0"`).

See [Names and strings](#names-and-strings) for why one token cannot mean two
things.

---

## Names and strings

One token cannot mean two things. `"..."` is a string literal everywhere, and
a name is a bare or single-quoted identifier:

```vox fragment
a number called "x" is "get five".
```

That is a compile error — `is "get five"` rejects the string in identifier
position and points you at `'get five'`. Were it accepted, `"get five"` in
expression position would read as a string literal — a pointer to the
function's code — and `x` would quietly receive that pointer as a number: a
wrong answer that looks like data, with no error and no warning.

---

## Functions

### Definition

```vox fragment
To <function name> with a <type> called <param1> and a <type> called <param2>. Return a <type>, <expression>.
```

No-parameter functions are also valid:

```
To 'show version'.
  Print "1.0.0".

To ping.
  Print "pong".
```

**Examples:**
```
To 'add numbers' with a number called x and a number called y. Return a number, the x add y.

To 'check divisibility' of a number called divisor and a number called dividend. Return a boolean, the divisor modulo the dividend is 0.
```

**Rules:**
- Function name is a bare single word (`add`) or a single-quoted multi-word name (`'add numbers'`)
- Parameters are optional. If present, introduce them with `with` or `of` (both work identically)
- Parameters use `a <type> called <name>` syntax (bare if single-word, `'single-quoted'` if it contains spaces)
- Multiple parameters joined with `and`
- Return type follows `Return a <type>,`

### Function Scope

- Variables declared at top level are global and can be used inside functions —
  including inside a function written **above** the declaration, because the
  body runs when it is called, and it reads the global as its declared type
  either way. A function that runs *before* the declaration has been reached
  reads the type's empty value — `""`, `[]`, `{}`, an empty buffer, `0`, `0.0`,
  `false` — never the value the declaration will go on to store. Top-level code
  has no such licence: see [Declaration Order](#declaration-order).
- Variables declared inside a function are local to that function and are not available at top level.
- Referencing an unknown variable inside a function is a compile-time error.
- Assigning to a top-level variable inside a function (`Set g to ...` /
  `the g is ...`) mutates the global itself, so the new value is visible after
  the call returns and to every other function.
- Declaring a variable inside a function **shadows** a top-level variable of
  the same name (`a number called g is 5.` inside a function creates a local
  `g`); the global is left untouched. Recursion still gets a fresh set of
  locals per call. This applies to `value` too: its payload and runtime type
  tag are stored as a pair, in whichever storage (function-local, or the
  top-level global's own pair of storage locations) that particular `value`
  uses, so a mutation inside one function is never visible to another unless
  it is genuinely the same global.

### Parameter and Local Types

Parameters may use any of the 11 expressible types — `number`, `float`,
`text`, `boolean`, `list`, `map`, `buffer`, `file`, `time`, `timer`, `value`
— and a typed parameter supports the same properties and operations as a
top-level variable of that type. The same 11 types are also legal as a
declared `Return a <type>,` return type — parameters and returns
share one vocabulary, not two. A parameter (or return type) may also be
`value`, the dynamic type whose runtime tag travels with its payload across
the call (a map rides this as payload + tag 5); see
[Dynamic Values (`value`)](#dynamic-values-value)
below.

```
To 'contains token' of a buffer called hay and a text called devname.
  a buffer called needle is " {devname}\n".
  a number called H is hay's size.
  a number called b is byte 1 of hay.
  ...
```

Key points:

- Buffer parameters support `'s size`/`'s empty`/`'s full` and byte
  access; list parameters support `'s length`/element access; map
  parameters support `'s length`/`'s empty`/`'s keys`/`'s values` and
  keyed access, and print as a whole map (`print holder.`, `"{holder}"`);
  file parameters support file properties.
- A `buffer` parameter **is** the caller's buffer, and stays the caller's
  buffer across a growth: an `append`, a `resize`, or a byte written past
  the current capacity moves the block, and the caller's variable follows
  it there. Declaring a buffer of the same name inside the function names
  a different buffer from that point on and leaves the caller's alone;
  `Set <parameter> to ...` is not a rebinding — on a buffer it copies
  bytes into the buffer the parameter already names, so the caller sees
  the new bytes.
- Buffers declared **inside** a function body work with every
  initializer form, including format strings (`is " {devname}\n"`).
- A function call's declared return type is tracked through
  assignment: reassigning an existing variable from a call
  (`the label is classify of n.`) preserves the correct type.

#### A collection parameter is the caller's collection

A `list` or `map` parameter names the caller's collection, not a copy of
it. Whatever the function does to it - setting an element, appending,
inserting a key, growing it past whatever size it started at - is what the
caller's variable holds when the call returns, however many calls deep the
collection was passed:

```
To 'add one to' with a list called items.
    append "x" to items.

a list called xs is ["a"].
'add one to' of xs.
'add one to' of xs.
Print xs's length.    (prints: 3)
```

This is the opposite of a `thing` parameter, which **is** a copy (see
[Things](#things) below): a thing has no reference to share, and a
collection is nothing but one. Only a variable can be written back to - a
collection built at the call itself (`'the size of' of [1, 2, 3]`) has
nowhere to return growth to, so the function may read and grow it freely
but the growth goes nowhere once the call ends.

A `.so` with a `list` or `map` parameter and the programs that `see` it must
be built by the same version of Vox.

### Function Calls

In expressions, use the function name followed by `of`, `to`, `with`, or `on` and arguments:

```vox fragment
'add numbers' of 3 and 5
'check divisibility' of the number and 6
calculate with x and y
```

**Rules:**
- Function name is a bare single word (`calculate`) or a single-quoted multi-word name (`'add numbers'`)
- For calls with arguments, use `of`, `to`, `with`, or `on`
- Multiple arguments separated by `and`

Calls with no arguments can be written directly:

```vox fragment
'show version'.
ping.
```

### Calling as Statement

```vox fragment
Print 'add numbers' of x and y.
```

### Reading a result

`Return a <type>,` is optional in the grammar, but it decides where the
result may be read. A declared return type travels to every call site, so
the result can be printed, interpolated, stored in a list or map slot, or
put in a `value` — each of those reads it back as what it is.

A result with **no** declared return type has nothing to be read as, and
the compiler will not guess: it is accepted only where the position itself
supplies the type, and refused where nothing does.

```vox fragment
To 'opaque label'. Return "hi".

a text called saved is 'opaque label'.   (fine — the declaration says text)
print saved.                             (prints: hi)

print 'opaque label'.                    (compile error: no declared return type)
```

Positions that supply a type: a declared variable's declaration, a later
assignment to one, and an argument landing on a declared parameter. Every
other position — `print <call>`, a `{...}` interpolation, `append`, a list
literal slot, `set element`, a map value, a `value` declaration — needs the
return type declared. See [Mixed-Type Lists](#mixed-type-lists).

---

## Things

Vox's eleven builtin types are the compiler's own composite values — a
buffer is `[capacity][length][flags][data]` with `'s` reading a field at a
fixed offset. A **thing** opens that same mechanism to the program: a
user-defined composite value type, built from named fields, with every
offset fixed at compile time. No vtables, no dispatch, no runtime
component — a thing is a layout, copied, printed, and compared by the
compiler the way a buffer is.

A thing is defined once, at the top level, and its name then works
everywhere a builtin type keyword works: in declarations, parameters, and
return types. A definition declares a type — it allocates nothing and
emits no code, so the only output around it comes from the ordinary
statements.

[`examples/delivery.vox`](examples/delivery.vox) is a complete program
built from two things of its own: it declares them, makes one with a
manifest member, nests one inside the other, copies, prints, and compares
them.

### Defining a thing

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

Print "defined".
```

The keyword is **`thing`**, and the verb is **`has`**. A definition has two
kinds of entry:

- a **data field** — `a <type> called <name>`, with an optional `is
  <literal>` default;
- a **function member** — `a function called <name>`, the manifest (see
  [The manifest](#the-manifest) below).

A field without a default takes its type's zero value. `thing` is a
keyword only inside this construct — everywhere else it is an ordinary
identifier, exactly like `send`, so a variable may be called `thing`:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

a number called thing is 42.
Print thing.
```

A thing name may be a bare word (`point`) or a quoted multi-word name
(`'bounding box'`), the same forms any identifier takes:

```
A thing called 'bounding box' has
  a number called width is 1,
  a number called height is 1.

a 'bounding box' called viewport.
Print viewport's width.
```

**Field types in v1.** A field may be `number`, `float`, `boolean`,
`time`, or any **previously defined** thing (things nest to any depth —
see [Nesting](#nesting)). `text`, `list`, `map`, and `buffer` fields are
deferred: they carry references and would reopen the aliasing question
value copy semantics (below) is designed to avoid.

#### The article rule

`a`/`an` pairs with **types** and with values coming into being; `the`
pairs with **known identifiers**. The rule is load-bearing in the surface
syntax, so it is worth naming once:

- `A thing called point has ...` — a *type* comes into being, so `A`.
- `a point called origin.` — a value of that type comes into being, so `a`.
- `the point's 'placed at'` in a member definition
  (`To do the point's 'placed at'`) — `point` is a known identifier (the
  type, declared in the manifest), so `the`.
- `a point's 'placed at' with 1 and 0` — a *new point* comes into being
  from the maker, so `a`.

The same word, two articles, two meanings: `the point's` reads a known
member; `a point's` calls a maker that brings a new point into being.

### Declarations and field access

A thing name is a type noun everywhere the builtin ones are, so every
declaration form works. All three lines below declare a `point` and give
every field its declared default:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

a point called origin.
Set origin's x to 3.
Set origin's y to 4.
Print origin's x.
origin's y is origin's y add 1.
increment origin's x.
Print "origin sits at {origin's x}, {origin's y}".
If origin's x is greater than 3 then,
    Print "the origin moved right".
```

A field is an ordinary expression and an ordinary lvalue everywhere
either is allowed — read, `Set ... to`, bare assignment, increment,
decrement, format-string interpolation, and a comparison in a condition
all appear above. `Create` declares with defaults too, and a quoted
variable name is read and written through the same possessive:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

Create a point called 'the far corner'.
Print 'the far corner''s x.
Set 'the far corner''s y to 2.
Print 'the far corner''s y.
```

A field with no default takes its type's zero. A `float` and a `boolean`
field carry defaults; a `number` field with none is `0`:

```
A thing called 'water tank' has
  a float called 'depth in metres' is 1.5,
  a boolean called 'the pump is running' is true,
  a number called 'litres drained'.

a 'water tank' called cistern.
Print cistern's 'depth in metres'.
If cistern's 'the pump is running' then,
    Print "the pump is running".
Print cistern's 'litres drained'.
```

A thing declared inside a function is local to that function (its storage
is the stack, not `.bss`):

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

To 'plot a point'.
  a point called cursor.
  Set cursor's x to 9.
  increment cursor's y.
  Print "the cursor sits at {cursor's x}, {cursor's y}".

'plot a point'.
```

### Nesting

A field may be a thing, so things nest to any depth. A nested thing
contributes its own bytes inline, so a chained possessive is one sum of
compile-time offsets — never a pointer chase — and the route's own
`'route number'` sits after the whole nested segment:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

A thing called segment has
  a point called start,
  a point called end.

A thing called route has
  a segment called leg,
  a number called 'route number'.

a route called commute.
Set commute's leg's start's x to 3.
Print commute's leg's start's x.
increment commute's leg's end's y.
Set commute's 'route number' to 66.
Print commute's 'route number'.
```

Defaults apply recursively: a field whose type is a thing takes that
thing's own defaults, written into the nested bytes at declaration, so a
stamp carried by a letter begins life with its own defaults even though
nothing initialises it:

```
A thing called stamp has
  a number called 'day sent' is 25,
  a number called 'cost in pence' is 12.

A thing called letter has
  a stamp called posted,
  a number called 'weight in grams' is 2.

a letter called invitation.
Print invitation's posted's 'day sent'.
Print invitation's posted's 'cost in pence'.
Print invitation's 'weight in grams'.
```

A thing containing itself — directly, or through other things — has no
finite size, so the definition that closes the cycle is a compile error
naming the chain:

```
A thing called ouroboros has
  an ouroboros called tail.
(compile error: ouroboros contains ouroboros
   no finite size)
```

Things are acyclic by **two mechanisms**. Within one file, the
**defined-earlier** ordering rule makes a cycle unconstructible: a field
type must be a thing defined above the line, so a thing can never name
itself or a thing defined below it. Across files reached by `see`, the
analyzer's registry DFS proves the merged registry is acyclic. The DFS is
load-bearing: it is what keeps the merged, multi-file registry acyclic,
and it stands as defence-in-depth alongside the within-file ordering rule.

### Value copy semantics

A thing is a value. Assignment copies the whole thing, and the copy
shares nothing with the original — a thing's size is a compile-time
constant, so a copy is a run of inline moves, no allocation and no
pointer left aliased:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

a point called origin.
Set origin's x to 5.
a point called moved is origin.
Set moved's x to 9.
Print origin's x.
Print moved's x.
```

The three spellings of assignment — a declaration with an initialiser, a
bare `is`, and `Set ... to` — are all assignment, so all three copy. A
copy is deep by construction: a nested thing is just more bytes, so
copying a letter carries its point along and neither half is shared:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

A thing called letter has
  a point called postbox,
  a number called 'weight in grams' is 2.

a letter called invitation.
Set invitation's postbox's x to 3.
a letter called reply is invitation.
Set reply's postbox's x to 7.
Print invitation's postbox's x.
Print reply's postbox's x.
```

The same is true across a call. A function receives a copy of a thing
and hands one back by returning it; nudging the parameter cannot reach
the caller's point, because the only way out is the `Return`, which
copies into the caller's own storage:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

To nudged with a point called start.
  Set start's x to start's x add 1.
  Return a point, start.

a point called before.
The after is nudged of before.
Print before's x.
Print after's x.
```

`The after is nudged of before.` declares `after` from what the call
returns, so a maker never has to have its type written twice. A whole
nested thing read out of a segment is copied the same way:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

A thing called segment has
  a point called start,
  a point called end.

To nudged with a point called start.
  Set start's x to start's x add 1.
  Return a point, start.

a segment called span.
Set span's start's x to 40.
a point called 'the far end' is nudged of span's start.
Print 'the far end''s x.
Print span's start's x.
```

Because a thing is a whole shape, not a value, the things you cannot do
to one are named rather than done to its first field. Assigning a single
value to a whole thing, or stepping one with `increment`, is rejected
with the field to write named instead:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

a point called origin.
Set origin to 5.
(compile error: 'origin' holds a whole point, so only a whole point can be copied into it
   A copy source is a variable holding a point, a field that holds one, or a call that returns one (plan 310 §5)
   To write one field instead, name it - point's fields are: x, y)
```

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

a point called origin.
increment origin.
(compile error: 'origin' holds a whole point, not a value
   A whole thing is copied, passed, and returned whole (plan 310 §5)
   its fields are: x, y)
```

Writing one field is what those lines mean: `Set origin's x to 5.`
A thing also cannot be interpolated into a text initializer (a text
initializer is a different sink from `Print`) or compared with a single
value; see [Printing](#printing) and [Equality](#equality).

Printing a call's result directly needs a variable, because the result
is a whole thing that must land in storage before it can be read:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

To nudged with a point called start.
  Set start's x to start's x add 1.
  Return a point, start.

a point called before.
Print nudged of before.
(compile error: A call to 'nudged' returns a whole point, which is not a value
   What a call returns is copied into a point)
```

The workaround is the inference form above — declare a scratch slot from
the call, then print it:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

To nudged with a point called start.
  Set start's x to start's x add 1.
  Return a point, start.

a point called before.
The after is nudged of before.
Print after.
```

### Printing

`Print p.` walks the fields in definition order and recurses into the
things they hold, map-style. Every field name is baked into the emitted
program, so nothing is read from a descriptor and nothing is allocated.
A quoted field name prints in the quotes it is written with, and a
function member takes no part — it is the type's API, not its state:

```
A thing called point has
  a function called 'placed at',
  a number called x is 0,
  a number called y is 0.

A thing called segment has
  a point called start,
  a point called end.

A thing called stamp has
  a number called 'day sent' is 25,
  a float called 'cost in pounds' is 1.5,
  a boolean called 'first class' is true.

To do the point's 'placed at', with a number called x and a number called y.
  a point called plotted.
  Set plotted's x to x.
  Set plotted's y to y.
  Return a point, plotted.

a point called origin.
Set origin's x to 5.
Print origin.

a segment called span.
Set span's end's y to 2.
Print span.
Print "the span runs {span}".

a stamp called posted.
Print posted.

The corner is a point's 'placed at' with 3 and 4.
Print corner.
```

A whole thing interpolates into a format string under `Print` (`Print "the
span runs {span}".`), because `Print` is the sink that renders the fields.
A text initializer is a different sink — it builds its bytes in a buffer
— and interpolating a whole thing there is rejected, naming the field to
interpolate instead:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

a point called origin.
a text called note is "the point is {origin}".
(compile error: 'origin' holds a whole point, which only `Print` can interpolate
   Interpolate a field instead - point's fields are: x, y)
```

### Equality

`is` between two values of the same thing compares those same fields at
the same depth; `is not` is its negation. Like printing, the comparison is
written out by the compiler, so it recurses into nested things:

```
A thing called point has
  a function called 'placed at',
  a number called x is 0,
  a number called y is 0.

To do the point's 'placed at', with a number called x and a number called y.
  a point called plotted.
  Set plotted's x to x.
  Set plotted's y to y.
  Return a point, plotted.

a point called origin.
Set origin's x to 5.
a point called marker.
Set marker's x to 5.
If origin is marker then,
    Print "the marker is where the origin is".
Set marker's y to 9.
If origin is not marker then,
    Print "the marker has moved off the origin".
```

Two things of *different* types cannot be compared (`origin is span` is
rejected — only two of the same thing have the same fields), and there is
no ordering on a whole thing — `origin is greater than marker` is
rejected, naming the field to compare instead:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

a point called origin.
a point called marker.
If origin is greater than marker then,
    Print "further along".
(compile error: 'origin' holds a whole point, which nothing puts in order
   Two things are compared for equality only (plan 310 §8)
   Compare a field instead - point's fields are: x, y)
```

### The manifest

A thing's callable API is declared in one place, the **manifest**: each
`a function called <name>` entry names a member. The member is then
defined with **`To do the <type>'s <name>`**, and `do` is a keyword only
in that position — everywhere else it is an ordinary identifier. The
member definition uses `the point's` (a known identifier) — the
[article rule](#the-article-rule):

```
A thing called point has
  a function called 'placed at',
  a function called 'reflected through the origin',
  a number called x is 0,
  a number called y is 0.

To do the point's 'placed at', with a number called x and a number called y.
  a point called plotted.
  Set plotted's x to x.
  Set plotted's y to y.
  Return a point, plotted.

To do the point's 'reflected through the origin', with a point called original.
  a point called reflection.
  Set reflection's x to 0 subtract original's x.
  Set reflection's y to 0 subtract original's y.
  Return a point, reflection.
```

Function members take no storage, so layout, copy, printing, and equality
see only the data fields.

**Every declared member returns its owner.** That is what gives the
manifest a crisp meaning — it lists the functions that *produce or
transform* the thing. A definition whose `Return` is not `Return a point,`
is a compile error naming both lines:

```
A thing called point has
  a function called 'placed at',
  a number called x is 0.

A thing called 'grid square' has
  a number called column is 0.

To do the point's 'placed at', with a number called x.
  a 'grid square' called square.
  Set square's column to x.
  Return a 'grid square', square.
(compile error: A declared member returns its own thing: point's 'placed at' must return a point
   hands back a grid square
   A function that computes something else from a point is an ordinary function)
```

A function computing some other type from a point (like `'magnitude
squared'`) is an ordinary global function, reached by the instance
possessive, with no manifest entry at all. The owner-return check reads
the body's `Return` lines, not the signature — so a member whose only
`Return` sits inside an `If` is not wrongly rejected.

The manifest is checked both ways. A `To do` naming a member the
manifest does not list errors at the definition, naming the entry to add:

```
A thing called point has
  a function called 'placed at',
  a number called x is 0,
  a number called y is 0.

To do the point's sparkle, with a point called original.
  Return a point, original.
(compile error: point does not declare sparkle - add `a function called sparkle` to the type
   Membership is declared in the thing's definition
   point declares: placed at)
```

and a declared member nothing defines errors at the type, where the
promise was made:

```
A thing called point has
  a function called 'never written',
  a number called x is 0.

a point called origin.
Print origin's x.
(compile error: point declares 'never written' but nothing defines it
   To do the point's 'never written', with <parameters>.
   Return a point, <value>.)
```

A member is defined once: a second `To do the point's 'placed at'`
errors at the second definition, naming the first.

### The three call forms

Three ways to call, one rule each.

**Free call** — the function's own name, unchanged, in the global
namespace. `of`, `to`, `with`, and `on` all introduce arguments:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

To 'magnitude squared' with a point called corner.
  a number called 'x squared' is corner's x multiply corner's x.
  a number called 'y squared' is corner's y multiply corner's y.
  Return a number, 'x squared' add 'y squared'.

a point called origin.
Set origin's x to 3.
Set origin's y to 4.
Print 'magnitude squared' of origin.
```

**Instance possessive** — `receiver's 'member'`: sugar for `'member' of
receiver`. The receiver fills the function's *first parameter*; any
further arguments follow the call preposition. A field always wins over
a function of the same name, because the [collision rule](#one-identifier-space)
refuses that program rather than letting one shadow the other. A
receiver is anything that names a whole thing, so a field holding one
reads the same way:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

A thing called segment has
  a point called start,
  a point called end.

To 'magnitude squared' with a point called corner.
  a number called 'x squared' is corner's x multiply corner's x.
  a number called 'y squared' is corner's y multiply corner's y.
  Return a number, 'x squared' add 'y squared'.

To 'scaled by' with a point called corner and a number called factor.
  a point called scaled.
  Set scaled's x to corner's x multiply factor.
  Set scaled's y to corner's y multiply factor.
  Return a point, scaled.

a point called origin.
Set origin's x to 3.
Set origin's y to 4.
Print origin's 'magnitude squared'.
The 'tripled corner' is origin's 'scaled by' on 3.
Print 'tripled corner''s x.

a segment called 'the line'.
Set 'the line''s end's y to 12.
Print 'the line''s end's 'magnitude squared'.
```

**Type possessive** — `a <type>'s 'member'`: calls a member *declared in
the manifest*. The article is `a` because a new thing comes into being.
This is the only way to call a **maker** — a member whose first parameter
is not the thing:

```
A thing called point has
  a function called 'placed at',
  a number called x is 0,
  a number called y is 0.

To do the point's 'placed at', with a number called x and a number called y.
  a point called plotted.
  Set plotted's x to x.
  Set plotted's y to y.
  Return a point, plotted.

The pin is a point's 'placed at' with 1 and 0.
Print pin's x.
```

A maker cannot be reached by the instance possessive (a receiver has
nothing to fill), and the message says so rather than reporting the
member as missing — the manifest does declare it:

```
A thing called point has
  a function called 'placed at',
  a number called x is 0.

To do the point's 'placed at', with a number called x.
  a point called plotted.
  Set plotted's x to x.
  Return a point, plotted.

a point called origin.
Print origin's 'placed at'.
(compile error: point declares 'placed at', but a receiver cannot reach it here
   'placed at' is a maker: its first parameter is not a point, so a receiver has nothing to fill
   Name the type instead: `a point's 'placed at' with <arguments>`)
```

A member whose first parameter *is* the thing gets both the type
possessive and the instance possessive:

```
A thing called point has
  a function called 'placed at',
  a function called 'reflected through the origin',
  a number called x is 0,
  a number called y is 0.

To do the point's 'placed at', with a number called x and a number called y.
  a point called plotted.
  Set plotted's x to x.
  Set plotted's y to y.
  Return a point, plotted.

To do the point's 'reflected through the origin', with a point called original.
  a point called reflection.
  Set reflection's x to 0 subtract original's x.
  Set reflection's y to 0 subtract original's y.
  Return a point, reflection.

The pin is a point's 'placed at' with 1 and 0.
The opposite is pin's 'reflected through the origin'.
The 'opposite of the opposite' is a point's 'reflected through the origin' of opposite.
Print opposite's x.
Print 'opposite of the opposite''s x.
```

A member name belongs to its owner, not to the program: two things may
each declare a `'placed at'`, and the two definitions compile under
distinct internal names, so the same member name is fine on two different
types:

```
A thing called point has
  a function called 'placed at',
  a number called x is 0,
  a number called y is 0.

A thing called 'grid square' has
  a function called 'placed at',
  a number called column is 0,
  a number called row is 0.

To do the point's 'placed at', with a number called x and a number called y.
  a point called plotted.
  Set plotted's x to x.
  Set plotted's y to y.
  Return a point, plotted.

To do the 'grid square''s 'placed at', with a number called column and a number called row.
  a 'grid square' called square.
  Set square's column to column.
  Set square's row to row.
  Return a 'grid square', square.

The 'marked square' is a 'grid square''s 'placed at' with 5 and 6.
Print 'marked square''s column.
Print 'marked square''s row.
```

`do` stays an ordinary identifier outside `To do the <type>'s`: `To do.`
defines a function called `do`, and `do.` calls it.

### One identifier space

Type names, variable names, and function names share a single global
identifier namespace. This is what makes `the point's` unambiguous: there
is only one `point`. Reusing a name is first-come-first-served, and the
second definition errors at its own line, naming the first — whatever
kind the first was:

```
a number called point is 0.
A thing called point has
  a number called x is 0.
(compile error: 'point' is already defined as a variable on line 1
   identifier space)
```

The same error names a function, a parameter, a loop variable, an
inferred variable, or another thing, whichever came first. A thing's own
fields and members live in a separate per-type **member space** (a type
owns one), so `point's x` and `segment's x` do not collide. The collision
rule there is first-come-first-served too: the second definition of any
name in a type's member space — a field, a declared member, or a global
function whose first parameter is that type — errors at its own line,
pointing at the first:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

To x with a point called corner.
  Return a number, corner's y.
(compile error: point already has a field called 'x', so a function taking a point cannot be called 'x' too
   point is defined on line 1. A type owns one member space)
```

### Definitions are top-level only

A thing is defined where a function is defined — at the top level. Its
layout is fixed for the whole program and has no block scope, so a
definition inside an `If`, a loop, or a function body is a compile error,
and the message says to move it above the block:

```
To 'take a reading'.
  A thing called measurement has
    a number called degrees is 0.
  Print "taken".
(compile error: A thing is defined at the top level, like a function
   Canonical form: A thing called measurement has <fields>.
   Move the definition above the block it is written in)
```

The ordering rule is about the **definition**, not about an instance of
it. A definition stands above every use of its name; an instance is an
ordinary top-level variable, so it obeys the ordinary rule instead —
"variables declared at top level are global and can be used inside
functions", wherever on the page the declaration is written:

```vox fragment
To 'show it'.
  Print origin's x.      (reads the global declared below)

a point called origin.
```

### Cross-file definitions

A thing defined in one file is usable from another via `see` (the
definition is parsed into the program the way a function is). The whole
surface crosses the boundary: the type noun in a declaration, a field
read and write, the manifest member reached by the type possessive, and
a global function taking the thing reached by the instance possessive.
The seen file arrives where the `see` is written, so the same
defined-earlier rule that orders one file orders the pair — every use
below stands after the definition it names.

```vox fragment
(./include/geometry.vox — the definition and the maker travel together)
A thing called point has
  a function called 'placed at',
  a number called x is 0,
  a number called y is 0.

To do the point's 'placed at', with a number called x and a number called y.
  a point called plotted.
  Set plotted's x to x.
  Set plotted's y to y.
  Return a point, plotted.

(An ordinary global function taking a point first, so the including file
 can reach it through the instance possessive as well as by name.)
To 'shifted east' with a point called start.
  Set start's x to start's x add 1.
  Return a point, start.
```

```vox fragment
(Consumer file — sees the definition above.)
see "./include/geometry.vox".

a point called origin.
Set origin's x to 11.
Print origin's x.

The corner is a point's 'placed at' with 3 and 4.
Print corner's x.
Print corner's y.

The 'shifted corner' is corner's 'shifted east'.
Print 'shifted corner''s x.
```

A type name is one identifier across the whole compilation: defining the
same thing in two files reached by `see` errors at the second definition,
naming the other file. The diagnostic reads `'point' is already defined
as a thing on line 4`, then names the file that defined it first
(`include/point_defined_elsewhere.vox`) and the rule (`identifier space`).

A `see` of a file that cannot be read is an error.

### `.lib` export of a thing is not yet supported

A `.lib` interface file names types by noun, and no noun spells a
user-defined thing, so an exported signature that takes or returns a
thing cannot be written. Ordinary compilation is unaffected; an exported
library function whose signature mentions a thing is refused with a
message naming the field and the canonical workaround — pass the thing's
fields across the boundary instead. A library that exports a function
`To 'nudged east' with a point called start.` — taking a point and, in the
same case, returning one — is refused when compiled with `--shared`:

> takes a point ('start'), which a library interface cannot describe yet  
> returns a point, which a library interface cannot describe yet  
> A thing is a layout private to one compilation

The same source compiles fine as an ordinary program; the refusal fires
only at the library interface, because the interface has no noun for a
user-defined thing. The diagnostic names each crossing field and points at
the workaround — pass `start's x` and `start's y` as separate values.

### Sentence consumption and multi-line definitions

A thing definition is a new place the [sentence consumption](#sentence-consumption)
rules bite. Its entries are comma-separated, and the construct closes on
a **period** or a **blank line**, the same termination rules every other
construct follows: a period closes the entry list, and a blank line
force-closes it (along with anything else still open). Indenting the
entries is conventional but not required — the commas and the terminator
carry the structure.

### Definition diagnostics

The definition construct creates a family of sentences that are never
valid Vox. Each gets a targeted error stating the intent it recognises
and naming the canonical form.

```
Create a thing called point.
(compile error: A thing is defined, not created as a variable
   Canonical form: A thing called point has <fields>.)
```

```
A thing called point is 5.
(compile error: 'is' declares a variable; a thing definition uses 'has'
   Canonical form: A thing called point has <fields>.)
```

```
A thing called point has.
(compile error: A thing needs at least one field
   Canonical form: A thing called point has)
```

A definition listing only manifest entries describes a zero-byte thing,
so v1 requires at least one data field:

```
A thing called point has
  a function called 'from polar'.
(compile error: A thing needs at least one field
   `a function called <name>` declares callable API, not storage.)
```

A field default must be a literal of the field's own type — a computed
value belongs in a function that returns the thing:

```
A thing called point has
  a number called x is 1.5.
(compile error: Field 'x' of thing 'point' is a number, but its default is a float
   literal of the field's own type)
```

Declaring with an unknown type name keeps the existing unknown-type
error, extended to suggest near-miss **user-defined** type names alongside
the builtins:

```
A thing called point has
  a number called x is 0,
  a number called y is 0.

a poimt called origin.
(compile error: Unknown type 'poimt'
   did you mean
   point)
```

### Type predicates and the runtime tag

User-defined things are not in the runtime tag system in v1. The type
nouns `is a <type>` recognises are the builtins (`number`, `text`,
`decimal`, `boolean`, `list`, `map`); there is no `is a point` yet, and a
`list` or `map` of user things, or a `value` holding one, is likewise
deferred. Things live in the compile-time type table, not the runtime tag.

---

## Expressions

### Literals

| Type | Example |
|---------|------------------------------------------|
| Integer | `42`, `0`, `-5` |
| Float | `3.14`, `-2.5`, `0.0` |
| String | `"Hello, World!"` |
| Boolean | `true`, `false` |
| Hexadecimal | `0xFF`, `0xDEADBEEF` |
| Binary | `0b10110100`, `0b1111` |
| Character | `'A'`, `'!'` |

**Note:** Float literals are recognized by the presence of a decimal point. Floats and integers can be mixed in arithmetic expressions.

**Note:** Arithmetic operates on numbers (booleans count as 0/1). Text, buffers, and lists must be cast with `as a number` or `as a float` before they can be used in arithmetic - using them directly is a compile error, since they hold pointers rather than numeric values.

**Hex and Binary:**
- Hexadecimal literals use `0x` prefix: `0xFF` equals 255
- Binary literals use `0b` prefix: `0b1010` equals 10
- Character literals use single quotes: `'A'` equals 65

### Variable Reference

- `the x` - references the variable `x`
- `the number` - references loop iterator (inside `for each`)
- `x` - direct identifier reference

### Arithmetic

```vox fragment
the x add 5
y subtract 3
the lhs multiply rhs
total divide 2
x modulo 3
{x add y} multiply z
{fibonacci of n subtract 1} add {fibonacci of n subtract 2}
```

Note: `the` is optional before variable names in expressions.

For complex arithmetic subexpressions, use curly braces `{...}` to group each subexpression.
A cast (`as a <type>`) binds tighter than arithmetic and applies to the expression immediately to its left, so `s as a number add 1` casts `s` and then adds 1. To cast a whole arithmetic expression, brace it: `{a add b} as a number`.
Comma-separated arithmetic continuation (for example `..., add ...`) is not valid syntax.

### Comparisons

```vox fragment
the x is greater than 5
y is less than 10
lhs is equal to rhs
x is 0
```

Note: `the` is optional before variable names in comparisons.

### Property Checks

```vox fragment
the x is even
the y is odd
the z is positive
the n is negative
the value is zero
the list is empty
```

### Logical Operators

```vox fragment
<condition> and <condition>    (true if both conditions are true)
<condition> or <condition>     (true if either condition is true)
not <condition>                (true if condition is false)
```

`not` takes the whole condition after it, exactly as the fence above says
and exactly as English does: `If not heat is limit then,` reads "if it is
not the case that heat is limit", never "if the negation of heat is
limit". So `not` binds looser than every comparison and property check,
and tighter than `and` and `or` — `not heat is 4 and limit is 6` is
`{not (heat is 4)} and (limit is 6)`. A `not` in front of a boolean is
that same rule with the shortest condition: `If not door_open then,`.

**A `not` always answers a boolean**, whatever it is applied to: `not 5` and
`not greeting` are booleans, not a number and a text. On a text, list, map or
buffer, `not` tests the value's pointer — which a declared variable always
has — so it answers false whether or not the collection holds anything. Ask
about contents with `is empty` (see Property Checks above), never with `not`.

### Plural Comparisons with `are`

Test multiple variables against the same value using comma-separated subjects:

```vox fragment
if x, y, and z are true
if a, b, and c are not false
if 'door open', lift_moving, and lift_full are not true
```

**Expansion:**
```vox fragment
if x, y, and z are true
```
expands internally to:
```vox fragment
if x is true and y is true and z is true
```

**Rules:**
- Subjects are separated by commas
- The word `and` before the last subject is optional but recommended for natural language readability
- The predicate after `are` applies to ALL subjects
- `are not` negates the comparison for all subjects

### Type Casting

Convert values between types using the `as` or `in` keywords.

**Syntax:**
```vox fragment
<value> as a <type>
<value> as <type>
<value> in <unit>
```

**Basic Conversions:**

| From | To | Syntax | Result |
|------|-----|--------|--------|
| float | number | `3.14 as a number` | `3` (truncated) |
| number | float | `42 as a float` | `42.0` |
| number | text | `25 as text` | `"25"` |
| text | number | `"123" as a number` | `123` |
| float | text | `3.14 as text` | `"3.14"` |
| text | float | `"3.14" as a float` | `3.14` |
| boolean | number | `true as a number` | `1` |
| boolean | number | `false as a number` | `0` |
| number | boolean | `0 as a boolean` | `false` |
| number | boolean | `42 as a boolean` | `true` |
| boolean | text | `true as text` | `"true"` |
| text | boolean | `"true" as a boolean` | `true` |
| buffer | text | `data as text` | a copy of the buffer's bytes |

A text made from a buffer is an **independent copy**, not a window onto
the buffer. `a text called line is data as text.` reads the buffer's
current bytes once and keeps its own copy, so clearing, refilling, or
resizing `data` afterwards leaves `line` exactly as it was — the same
promise format strings make (see "Format Strings as Values"). This
matters because resizing frees the buffer's old allocation: without the
copy, reading such a text would be reading freed memory.

**The cast is optional for this one conversion.** Every spelling that puts
a buffer into a slot that holds text means the same thing and makes the
same copy — `a text called line is data.`, `Set line to data.`, `the line
is data.`, a `text` parameter given a buffer argument, and `Return a text,
data.` — as do `data as text` and `"{data}"`. Writing the cast is still
good style where the type change is worth pointing at, but leaving it out
never changes what the sentence does. This does not loosen type
immutability: `line` is text before the write and text after it, and every
*other* mismatched write is still the compile error described under "Type
Immutability".

A `value` slot is one of those slots. A buffer written into a `value` — by
declaration, by `Set`, by `the ... is`, as a `value` argument, or by
`Return a value` — arrives as text and reports `Text (dynamic)`, carrying
the same independent copy of the buffer's bytes. A `value` never holds a
buffer as a buffer; there is no `Buffer (dynamic)` tag.

**A float read from text is the same double as the literal.** `"0.88" as
a float` and the literal `0.88` are one value, and comparing them with
`is` finds them equal: the runtime reads a decimal exactly the way the
compiler reads one written in the source. The guarantee covers up to
eighteen significant digits with the point up to twenty-two places away
from them - wider than a `float` can tell apart - and a longer decimal
is read as the nearest float those eighteen digits describe. This is
what lets a number read from a file, an argument or an environment
variable be compared against a literal in the same program.

**Radix (Base) Conversions:**

Text-to-number casting isn't limited to base 10. A radix word can be
inserted right before `number` to parse in a different base:

| Syntax | Base | Example | Result |
|--------|------|---------|--------|
| `as a number` | 10 (default) | `"42" as a number` | `42` |
| `as a hex number` / `as a hexadecimal number` | 16 | `"ff" as a hex number` | `255` |
| `as an octal number` | 8 | `"17" as an octal number` | `15` |
| `as a binary number` | 2 | `"1010" as a binary number` | `10` |
| `as a base N number` (spaced) | any 2-36 | `"z9a" as a base 36 number` | `45694` |
| `as a baseN number` (fused) | any 2-36 | `"6543" as a base7 number` | `2334` |

Any base from 2 through 36 is supported, not just the aliased ones
(hex/octal/binary) - digits above 9 use letters `a`-`z` (case-
insensitive), so base 36 is the practical maximum for a single-
character-per-digit representation.

```
(Hex string to number)
a text called hexstr is "3fa2c1e4".
a number called n is hexstr as a hex number.

(Arbitrary base, fused or spaced form - both work)
a text called s is "6543".
a number called n2 is s as a base7 number.
a number called n3 is s as a base 7 number.

(Negative numbers and uppercase hex digits both work)
a text called neg is "-1a".
a number called n4 is neg as a hex number.   (-26)
a text called upper is "FF".
a number called n5 is upper as a hex number. (255)
```

Like the base-10 case, parsing **stops at the first character invalid
for that base** rather than raising an error - `"12g5" as a hex number`
gives `18` (stops at `g`), and a string that's invalid from its very
first character (e.g. `"abc" as a base5 number`, since `a`'s value of
10 is too big for base 5) gives `0`.

**Examples:**

```
(Float to number - truncates)
a float called pi is 3.14159.
a number called 'pi truncated' is pi as a number.

(Number to text)
a number called age is 25.
a text called agestr is the age as text.

(Text to number - parsing)
a text called userinput is "123".
a number called parsed is the userinput as a number.

(Boolean to number)
a boolean called done is true.
a number called 'done num' is the done as a number.

(Inline casting)
Print 3.14159 as a number.
```

**The `in` Keyword:**

The `in` keyword reads more naturally for timer duration casts. It applies to
a timer's `duration` or `elapsed`, not to a plain number:

```
(Duration from timer)
Print the timer's duration in seconds.
Print the timer's elapsed in milliseconds.
```

`in` only works on a timer's `duration`/`elapsed` (it lowers to a duration
cast); `<number> in <unit>` on a plain number is not valid syntax. To convert a
plain number of milliseconds to seconds, divide: `the millis divide 1000`.

**Formatted Output:**

Numbers can be converted to padded text for display formatting with the
zero-pad format specifier:

```
(Pad to 2 digits - for times like 09:05)
a number called h is 9.
a text called hpadded is "{h:02}".
Print the hpadded.  (prints "09")
```

**Casting Rules:**
- `as a <type>` and `as <type>` are equivalent (article is optional)
- A cast binds tighter than arithmetic and applies to the expression immediately to its left: `n as a number add 1` is `(n as a number) add 1`. Brace to cast a whole expression: `{a add b} as a number`
- Float to number **truncates** (does not round)
- To round: add 0.5 before casting (`{3.7 add 0.5} as a number` → `4`)
- Text, buffers, and lists cannot be used directly in arithmetic; cast them with `as a number` / `as a float` first
- Text to number fails if text is not a valid number (sets error flag)
- Text to number in a non-default base (`as a hex/octal/binary/base N
  number`) stops parsing at the first character invalid for that base,
  rather than failing outright - it does not set the error flag
- Zero is `false`, any non-zero number is `true`
- `in` keyword is for timer `duration`/`elapsed` casts (see above)

---

## Control Flow

### If Statement

```vox fragment
If <condition> then, <statement>.
```

**With else:**
```vox fragment
If <condition> then, <statement>. Otherwise, <statement>.
```

**With else-if:**
```vox fragment
If <condition> then, <statement>. But if <condition> then, <statement>. Otherwise, <statement>.
```

**Sentence consumption rule (important):**
- Each `then,` / `but if ... then,` / `otherwise,` branch consumes actions until the sentence ends.
- Separate multiple actions in a branch with commas.
- Use a period to end the full `if` sentence.
- A period before `but if`/`otherwise` is treated as part of the same if-chain when the chain continues.

```vox fragment
If ready then, print "a", print "b", print "c".
```

**Alternative keywords:**
- `When` can replace `If`
- `Else` can replace `Otherwise`

### While Loop

```vox fragment
While <condition>, <statements>.
```

**Single-line example:**
```vox fragment
While the counter is less than 10, print the counter, increment the counter.
```

**Multi-action loops** are comma-separated actions within one sentence:

```vox fragment
While x is less than 5, print x, increment x, print "looping".
```

**Loops inside functions** work naturally:
```
To sum of a number called n.
  a number called total is 0.
  a number called i is 1.
  While i is less than or equal to n, total is total add i, i is i add 1.
  Return a number, total.
```

### For Each Loop

**Range-based:**
```vox fragment
For each number from <start> to <end>, <statement>.
```

**Example:**
```
For each number from 1 to 10, print the number.
```

**Inside the loop:**
- `the number` refers to the current iteration value

**List-based:**
```vox fragment
For each <variable> in <list>, <statement>.
```

**Example:**
```
a list called nums is [1, 2, 3].
For each n in nums, print the n.
```

### Repeat

Run a body a fixed number of times.

```vox fragment
Repeat <count> times, <statements>.
```

**Single-line example:**
```vox fragment
Repeat 3 times, print "hello".
```

**Multi-action loops** are comma-separated actions within one sentence,
exactly like `While`:

```vox fragment
Repeat 2 times, print "a", print "b".
```

This prints `a`, `b`, `a`, `b` — two actions per iteration, two iterations.

**Termination.** `Repeat` closes by the same rules as `While` and `For
each`: a period ends the body (and closes the construct — rule 1), and a
blank line force-closes it (rule 2). The statements after a closing
period belong to the surrounding scope, not the loop:

```vox
Repeat 2 times, print "r".
Print "after".
```
→ `r` `r` `after`

Because a period closes the construct, periods stack: write one period
per level you want to close, so a `Repeat` nested in another loop takes
two periods to close both (see [Closing more than one
level](#closing-more-than-one-level)):

```vox
For each n from 1 to 2,
    Repeat 2 times, print "r"..
Print "after".
```
→ `r` `r` `r` `r` `after`

### Loop Control

```vox fragment
Break.
Continue.
```

### Program Termination

Immediately exit the program with an exit code:

```vox fragment
Exit <code>.
```

**Examples:**
```
Exit 0.                              (Success)
Exit 1.                              (General error)

If arguments's empty then,
    Print "Usage: ./program <file>".
    Exit 1.
```

**Notes:**
- Exit code defaults to 0 if not specified
- All resources are automatically cleaned up before exit
- Alternative keywords: `quit`, `terminate`

### Increment/Decrement

```
Increment the counter.
Decrement the value.
```

---

## Lists and Collections

### List Literals

Create lists with square brackets containing comma-separated values:

```
a list called nums is [1, 2, 3].
a list called names is ["Alice", "Bob", "Charlie"].
a list called mixed is [1, "two", 3].
a list called emptylist is [].
```

**Key points:**
- Lists are **1-indexed** (like natural language: "the first element", "the second element")
- Lists can contain mixed types
- Empty lists `[]` are allowed
- Lists are allocated on the heap with automatic memory management

### Mixed-Type Lists

A list may freely hold numbers, texts, decimals, and booleans together.
The author never declares this - the compiler resolves it. Lists it can
prove homogeneous keep a statically-typed fast path; lists with mixed
elements carry a small per-slot type tag at runtime, so every element
prints and reads back as what it is:

```
a list called m is [1, "two", 3.5, yes].
For each item in m, print item.
(prints: 1, two, 3.5, 1)
```

Appending, `set element`, `element N of`, `first`/`last`, iteration, and
`{...}` format interpolation all respect each element's actual type.
Booleans print as `1`/`0`, matching homogeneous boolean lists.

The compiler earns the homogeneous fast path by **proof**, not assumption.
A value whose type it cannot statically prove widens the list to mixed, so
reads dispatch on each slot's runtime tag rather than on one assumed type.
A [`value`](#dynamic-values-value) is the everyday case: its type travels
with its payload as a runtime tag, so the slot is written with the type the
payload actually has, whatever that turns out to be.

```
a value called tally is 5.
a list called items is [].
append "hello" to items.
append tally to items.
print element 1 of items.   (prints: hello)
print element 2 of items.   (prints: 5)
```

A function result whose return type **is** declared (e.g. `Return a text,
"hi".`) is statically known, so it is tagged with that type at the write
and widens the list only because its type differs from the other elements.

A function whose return type is **not** declared is the one thing a slot
cannot be written from. Nothing proves what the result is, and nothing
carries a tag for it either, so the write would have to guess — and a
returned text stored under a guessed `number` tag reads back as the raw
address of its bytes, which is the silent wrong answer the
identifier/literal split exists to prevent (see
[Names and strings](#names-and-strings)). So it is refused at compile time
rather than guessed, and the error names both ways out: declare the return
type, or assign the result to a declared variable and append that.

```
To five with a number called x. Return x add 1.
a list called items is [].
append five of 4 to items.   (compile error: 'five' has no declared return type)
```

The same rule holds everywhere else a result lands with no type of its own
— `print <call>`, a `{...}` interpolation, a list literal slot, `set
element`, a map value, and a `value` declaration. A position that *does*
supply a type is unaffected: a declared variable, a later assignment to
one, and an argument landing on a declared parameter all read a result back
as what the declaration says it is.

Full runtime tag propagation, which would let an opaque call carry its own
tag the way a `value` does, is stage 1d — see
`docs/COLLECTIONS_ROADMAP.md` for the roadmap.

### Nested Lists

A list element may itself be a list. A nested list prints recursively with
brackets, and the same per-slot tag machinery tracks it — a list value in
a slot carries the list tag (4), so a mixed list like `[1, [2, 3], "four"]`
prints exactly as written, and a homogeneous list-of-lists like
`[[1, 2], [3, 4]]` keeps the statically-typed fast path (it is not mixed):

```
a list called nested is [1, [2, 3], "four"].
print nested.                       (prints: [1, [2, 3], "four"])
print element 2 of nested.          (prints: [2, 3])

a list called deep is [1, [2, [3, 4]], 5].
print element 2 of element 2 of deep.   (prints: [3, 4])
```

`element N of`, `first`/`last`, iteration, and whole-list print all yield
a usable child list, so an extracted child behaves as a list — its
`length`, its own `element N of`, and a `For each` over it all work:

```
a list called inner is element 2 of [1, [2, 3], "four"].
print inner's length.        (prints: 2)
For each y in inner, print y.   (prints: 2, then 3)
```

The `is a list` predicate recognises a nested-list element (runtime tag 4)
and folds to true on a statically-typed list variable, like the other
predicates:

```
For each item in [1, [2, 3], "x"],
  if item is a list then, print "L". otherwise print "s".
(prints: s, L, s)
```

Printing is recursive and **cycle-safe**: a list that contains itself
(for example `a list called x is []. append x to x.`) would recurse
forever, so printing is capped at a depth of 64. When the limit is hit
the over-deep subtree prints as `...`, the error flag is set, and printing
unwinds safely instead of overflowing the stack. Use `on error` to react:

```
a list called x is [].
append x to x.
print x.
on error print "cyclic".
(prints: [[...]] then cyclic — abbreviated: 64 opening brackets, then
 `...`, then 64 closing brackets, then `cyclic`)
```

One limitation remains for this stage. Extracting a child with `element N
of` yields a *reference* to the child list, not a copy: if the parent is
later grown by appending enough elements to force a reallocation, a child
extracted before that reallocation may point at freed memory. Extract a
child after the parent has finished growing, or copy it element-by-element.
See `docs/COLLECTIONS_ROADMAP.md` for the roadmap.

### Maps

A map is a key/value collection — a JSON object. Keys are text; values may
be any type (number, text, decimal, boolean, list, or another map). A map
literal uses braces with `"key": value` pairs, and an empty map is `{}`:

```
a map called person is {"name": "Ada", "age": 36}.
a map called emptymap is {}.
print person.            (prints: {"name": "Ada", "age": 36})
print emptymap.          (prints: {})
```

Read a value by key with `map's "key"` (the key is a text literal; a
quoted key with `{...}` interpolation builds a dynamic key). The value
carries its runtime tag, so a text prints as text and a number as a
number:

```
print person's "name".   (prints: Ada)
print person's "age".    (prints: 36)
```

Insert or replace an entry with `Set map's "key" to value` (mirroring
`Set element N of list to …`). The map may reallocate on growth, so the
returned pointer is stored back into the variable automatically - including
when the variable is a `map` parameter, in which case the caller's map is
what grows (see [A collection parameter is the caller's
collection](#a-collection-parameter-is-the-callers-collection)):

```
set person's "age" to 37.
print person's "age".    (prints: 37)
print person's length.   (prints: 2 — replace, not insert)
```

The properties `length` (live entry count) and `empty` (true when zero
entries) work as for lists. `keys` and `values` each yield a fresh list,
in insertion order, for iteration:

```
for each key in person's keys, print key.   (prints: name, then age)
for each v in person's values, print v.     (prints: Ada, then 37)
```

A missing key does not crash: the lookup sets the error flag, so an `on
error` handler can react, and yields a value the destination can hold.
Where the compiler can prove the key is absent — a map literal it can see
all of — the read is the **number** 0 whatever the map's values are, so
read it into a `number` (a `float` or a `boolean` holds 0 too), and a
`text`, `list` or `map` destination is refused with a diagnostic naming
the key. Where it cannot prove it — a dynamic key, or a map an `Append`, a
`Set`, an alias or a call can reach — the read yields the destination's
default value from the table under [Two Canonical
Forms](#two-canonical-forms): `0` for a `number`, the empty text for a
`text`, `[]` for a `list`, `{}` for a `map`, so no read ever dereferences
a null pointer. Note this is deliberately *not* the same as a key that
holds [`nothing`](#nothing-the-absent-value) — "no such key" stays
distinguishable from "the key is set to nothing":

```
print person's "nope".    (prints: 0)
on error print "missing". (prints: missing)
```

A map value may be a list or another map, and printing is recursive:
`_map_print` renders `{"key": value, …}` and shares the same 64-deep
`_print_depth` budget as `_list_print`, so a mixed map/list tree is
cycle-safe. A self-referential map (`set m's "self" to m.`) prints 64
levels deep, then `...`, sets the error flag, and unwinds safely.

The `is a map` predicate recognises a map (runtime tag 5): it folds to
true on a statically-typed map variable and compares the tag at run time
on a mixed value. A map also rides the `value` ABI (see Values): a map
passed to a `value` parameter or returned from a `value` function carries
its tag (5) alongside the payload, so it round-trips through functions
intact.

A map may also be an element of a list (`[{"a": 1}, {"b": 2}]`) — the
slot carries the map tag (5), so `is a map` fires on a `For each` loop
variable over such a list. The loop variable itself is deliberately
untyped, though, and reading a key with `'s "key"` is a *static* check,
so `entry's "tag"` inside the loop is a compile error ("Map access target
must be a map"). To read a key, loop over the positions and declare the
element:

```
a list called holder is [{"tag": 1}, {"tag": 2}].
For each position from 1 to holder's length,
  a map called entry is element position of holder,
  print entry's "tag".
(prints: 1, then 2)
```

Two limitations remain for this stage: keys are
text only (a non-text key is rejected with "Map keys must be text"), and
there is no entry deletion. See `docs/COLLECTIONS_ROADMAP.md`.

### Type Predicates

You can ask what type a value actually holds and branch on it. The
predicate `is a <type-noun>` compares the value's runtime type tag, so it
works on a mixed-list element whose type is only known at run time:

```
a list called m is [1, "two", 3.5, yes].
For each item in m,
  if item is a text, print "text: {item}",
  otherwise if item is a decimal, print "decimal: {item}",
  otherwise if item is a boolean, print "boolean: {item}",
  otherwise print "number: {item}".
(prints: number: 1 / text: two / decimal: 3.5 / boolean: 1)
```

The type nouns are `number`, `text`, `decimal`, `boolean`, `list`, and
`map`. The declaration synonyms also work (`integer`→number, `string`→text,
`float`/`real`→decimal, `bool`→boolean, `dictionary`→map). Negate with
`is not a`:

```
if item is not a number, print "not a number".
```

`is a boolean` and `is a number` are distinct even though both print as
numbers: a boolean carries tag 3, a number tag 0, and the predicate reads
that tag. On a **statically-typed** value the predicate folds at compile
time — `if x is a number` for a declared `a number called x` costs
nothing and is always true — so the sentence is legal on any value, not
just mixed ones.

This is the guard idiom that makes mixed lists programmable — with one
constraint worth stating plainly. The predicate reads the runtime tag; it
does **not** narrow the static type. Arithmetic still dispatches
statically, so operating on the tested value itself is refused inside the
guard exactly as it is outside it ("Cannot use a value item in
arithmetic"). Guarding therefore means getting the element into a
*declared* variable, which a `For each` loop variable can never be — loop
over the positions instead:

```
a list called mixedbag is [1, "two", 3.5].
For each position from 1 to mixedbag's length,
  if element position of mixedbag is a number,
    a number called got is element position of mixedbag,
    print got add 1.
  otherwise print "guarded away".
(prints: 2, then guarded away, then guarded away — 3.5 is a decimal,
 not a number, so `is a number` is false for it)
```

(Automatic guarding is a later decision; see the roadmap.) The cast
expression is *not* a way round this: `item as a number` on a
dynamically-tagged element is rejected for the same reason ("casting a
dynamically-tagged value is not currently supported by the compiler — a
known gap"). `<value> as a <type>` converts a **statically**-typed value;
see [Type Casting](#type-casting). Use the idiom above instead.

A predicate result is itself a boolean value, so you can store one in a
list — `append item is a number to flags` — and each stored slot carries
the boolean tag, so a later `is a boolean` recognises it.

**User-defined things are not in this tag system in v1.** The nouns
above are the builtins; there is no `is a point` for a thing you define,
and a `list` or `map` of user things, or a `value` holding one, is
likewise deferred. A thing lives in the compile-time type table, not the
runtime tag — see [Things](#things).

### Dynamic Values (`value`)

The `value` type is a declared dynamic type that carries its runtime tag
*alongside* its payload across the call, so a single function can accept
"whatever this slot holds" and ask `is a ...` inside to find out which.

Declare a `value` parameter with `with a value called x`, return one
with `Return a value, <expr>`, and a `value` local with
`a value called r`:

```
To describe with a value called item.
  If item is a number, print "number".
  Otherwise if item is a text, print "text".
  Otherwise print "decimal".

a list called m is [1, "two", 3.5].
For each item in m,
  describe of item.
(prints: number / text / decimal)
```

Inside the callee, `item` is a `value` (a tagged slot): the `is a ...`
predicates read its tag, printing dispatches on it, and you can forward it
or append it back into a list with the tag preserved. A function returning
`a value` carries its tag back out, so this round-trips:

```
To echo with a value called v. Return a value, v.

a list called data is [1, "two", 3.5].
a list called out is [].
For each item in data,
  append echo of item to out.
```

After the loop, `out` holds `[1, "two", 3.5]` with the original tags intact
— the value return brought each tag back out, and the append forwarded it.

**`value` is not a reserved word.** It is recognized only where a type is
expected: a parameter type, a return type, or directly before `called` in
`a value called x`. Everywhere else it is an ordinary identifier, so
`a value is 5.` still declares a variable named `value`.

A `value` local keeps its tag through reassignment, so `set r to 7.`
retags it as a number:

```
To echo with a value called v. Return a value, v.

a value called r is echo of "hello".
print r.                      (prints: hello)
set r to 7.
If r is a number, print "now a number".
```

**Bare arithmetic on a `value` is still rejected.** Because a `value` might
hold a string or a decimal, the compiler refuses to use it directly in
arithmetic:

```
To bump with a value called v. Return a number, v add 1.
(compile error: Cannot use a value v in arithmetic: its type is only known
 at runtime, and arithmetic on a dynamically-tagged value is not currently
 supported.)
```

**A `value` can be retyped in place.** This is the exception named in
[Type Immutability](#type-immutability) above: a *statically*-typed
variable's type is fixed forever, but `value` is deliberately not one. The
statement `<valuevar> is a <type>.` reads the variable's runtime tag,
performs the conversion that the corresponding static cast would use, and
stores the result back into the same variable with the new tag. This works
for `number`, `float`/`decimal`, `text`, and `boolean` targets:

```
a value called numstr is "357".
numstr is a number.
print numstr add 1.           (prints: 358)
```

The explicit `as` cast is not an alternative here: `numstr as number` is a
compile error on a `value`, because a cast needs its source type at compile
time and a `value` only knows its type at runtime — the in-place retype is
how a `value` is converted.

The same phrase in **condition** position keeps its old meaning: `If numstr
is a number then, ...` is still a type predicate that tests the runtime
tag and returns a boolean. Position — statement versus condition — is what
distinguishes a cast from a predicate:

```
a value called numstr is "357".
if numstr is a number then, print "num".
otherwise, print "not num".
(prints: not num)
```

After a successful in-place retype, the variable is tracked with the new
type for the rest of its lifetime, so arithmetic and further casts behave
accordingly. Retyping to the type it already holds is a no-op.

**Failed conversions set `_last_error` and leave the variable as 0.** A
text that cannot be parsed as a number, for instance, results in 0 and
raises the error flag so `On error` can catch it:

```
a value called bad is "abc".
bad is a number.
on error print "cast failed".
print bad.
(prints: cast failed / 0)
```

**Inspecting a `value`'s current type.** The universal `type` property reads the variable's runtime tag and returns a text description such as `Text (dynamic)`, `Number (dynamic)`, `Float (dynamic)`, `Boolean (dynamic)`, `List (dynamic)`, `Map (dynamic)`, or `Nothing (dynamic)`. Because it reads the tag, the reported type changes with reassignment:

```
a value called v is "hello".
print v's type.          (prints: Text (dynamic))
set v to 42.
print v's type.          (prints: Number (dynamic))
```

This is a display helper for debugging and logging; type tests still belong in the `is a <type>` predicate.

The list is the whole list: those seven are every tag a `value` can carry.
A buffer put into a `value` is converted to text on the way in (see "Type
Casting"), so it reads back as `Text (dynamic)`.

**Retyping a statically-typed variable is a compile error.** `n is a
text.` is only valid when `n` was declared as a `value`; for a `number`
variable the compiler reports the actual declared type and points at the
explicit cast (`a text called t is n as text.`) as the correct rewrite.

**Recursion with `value` works.** A `value` parameter threads its tag
through every frame, so a recursive walker over mixed data classifies
correctly at any depth. `value` parameters compose: a `value` passed
straight to another `value` function round-trips its tag.

**Conditional `value` returns work.** A function whose only returns sit
inside an `If`/`Otherwise` — the *factorial pattern*, with no `Return` on
the `To` line — carries its declared return type just as the
single-expression form does, and each branch hands back its own runtime
tag:

```
To score with a value called v.
  If v is a number, return a value, v.
  Otherwise, return a value, 99.

print score of 7.          (prints: 7)
print score of "hello".    (prints: 99)
```

The same is true of a conditional return of any declared type: `Return a
text, "big".` inside a branch makes the function a text-returning one. If
no branch fires and the function falls off its end, it hands back the
empty value of its declared type — empty text, zero, or a `value` tagged
as the number `0`.

**One limitation to know.** A function whose branches declare *different*
types — `Return a text` in one and `Return a number` in the other — has no
single type for its `To` line to promise, so it declares none and the
caller reads the result as a number. Declare the same type in every
branch, or return a `value`, which is exactly the type for a result whose
shape depends on the branch taken. Conditional `value` *parameters* (the
factorial pattern with a void return) work as they always have. The
internal ABI that carries the tag is documented in `docs/abi_value.md`;
the roadmap context is in `docs/COLLECTIONS_ROADMAP.md` (stage 1d).

### Nothing (the absent value)

`nothing` is the value that means "no value here" — the equivalent of null
in other languages. It can sit in a list slot, a map value, or a `value`
parameter or return, and it prints as the word `nothing`:

```
a list called L is [1, nothing, "x"].
print L.
(prints: [1, nothing, "x"])

a map called m is {"found": 4, "absent": nothing}.
print m.
(prints: {"found": 4, "absent": nothing})
```

`null` and `nil` are accepted spellings of the same literal; all three
produce the identical value. `nothing` is a reserved word, so it cannot be
used as a variable name.

**Test for it with `is nothing`**, which is an equality (like `is true`),
not a type predicate — there is no `is a nothing`:

```
If m's "absent" is nothing, print "no value stored".
If m's "found" is not nothing, print "has a value".
```

**`nothing` is not zero.** This is the distinction that matters most:

```
If 0 is nothing, print "never printed".
```

`0 is nothing` is **false**, and `nothing is 0` is false too. They are
different values, and `is nothing` compares the runtime type tag rather
than the stored number, so the two never collide.

**A missing map key is an error, not `nothing`.** Reading a key that was
never set sets the error flag; it does not silently hand back `nothing`.
So "the key is absent" and "the key holds nothing" stay distinguishable:

```
a map called m is {"k": nothing}.
If m's "k" is nothing, print "k is present and holds nothing".
a number called x is m's "never_set".
on error print "never_set is absent".
```

**Arithmetic on `nothing` is refused, not treated as 0.** Writing it
literally is a compile error:

```
a number called n is nothing add 1.
(compile error: Cannot use nothing in arithmetic; check it with
 'is nothing' first.)
```

When a value only turns out to be `nothing` at run time — read out of a
map or a mixed list — the compiler cannot catch it, so the operation sets
the error flag instead:

```
a map called m is {"absent": nothing}.
a number called bad is m's "absent" add 1.
on error print "cannot do arithmetic on nothing".
```

The reason for both is that the stored payload of `nothing` really is 0.
Left unchecked, `total add missing_field` would quietly evaluate to
`total` — a wrong answer that looks completely plausible. Guard with a
predicate first, exactly as you would for a mixed element:

```
If m's "absent" is not nothing, set total to total add m's "absent".
```

Comparisons are not arithmetic, so `is nothing`, `is not nothing`, and
ordinary equality keep working on a `nothing` without raising the flag.

### Printing a List

Printing a list variable directly renders its contents rather than its
heap address:

```
a list called nums is [1, 2, 3].
a list called m is [1, "two", 3.5, yes].
print nums.               (prints: [1, 2, 3])
print m.                  (prints: [1, "two", 3.5, 1])
print "list: {nums}".     (prints: list: [1, 2, 3])
```

Elements are separated by `, ` and wrapped in `[` `]`. Each element
renders by its own type, not the list's: text elements are
quoted (so `["1"]` is distinguishable from `[1]`), booleans as `1`/`0`,
floats and numbers as usual. Empty lists print `[]`. A nested list
element renders recursively with the same rules (see Nested Lists above),
so `[1, [2, 3], "four"]` prints with inner brackets intact. A map element
(or a whole map) renders as `{"key": value, …}` via `_map_print` (see Maps
above). The same rendering appears inside `{...}` format interpolation, in
both its forms and in every sink: the *variable* form (`print "{xs}"`) and
the *expression* form (`print "{element 2 of xs}"`) each dispatch on the
element's runtime tag, so an element renders in a hole exactly as it does
printed as a statement.

### List Properties

Access list properties using the `'s` syntax:

```
a list called items is [10, 20, 30].

print items's length.      (prints 3)
print items's size.        (same as length)
print items's first.       (prints 10)
print items's last.        (prints 30)
print items's empty.       (prints 0)
```

| Property | Description | Type |
|----------|-------------|------|
| `length` | Number of items in the list | Number |
| `size` | Same as length | Number |
| `empty` | Whether the list has no items | Boolean |
| `first` | The first item in the list | Item |
| `last` | The last item in the list | Item |

### List Element Access

Access elements by index (1-indexed):

```
a list called nums is [10, 20, 30].

Print element 1 of nums.   (prints 10)
Print element 2 of nums.   (prints 20)
Print nums's first.        (prints 10)
Print nums's last.         (prints 30)

(Using variable index)
a number called i is 2.
Print element i of nums.   (prints 20)
```

**Bounds checking:**
- Out-of-bounds access sets an error flag. Where the compiler can prove the
  index is past the end, it returns the **number** 0 whatever the list's
  elements are, so read it into a `number`; where it cannot, it returns the
  destination's default value from the table under [Two Canonical
  Forms](#two-canonical-forms) — `0` for a `number`, the empty text for a
  `text`, `[]` for a `list`, `{}` for a `map`
- Errors can be caught with `On error`

```
a list called items is [1, 2, 3].
a number called bad is element 100 of items.
On error print "Cannot access element 100 - out of bounds!".
```

### Appending to Lists

Add elements to the end of a list using the `append` keyword:

```
a list called nums is [1, 2, 3].
append 4 to nums.
append 5 to nums.
print nums's length.       (prints 5)
```

`append` is overloaded by destination type:
- `append <value> to <list>` appends one list element.
- `append <source_buffer> to <destination_buffer>` appends source bytes to destination buffer bytes.

Use `copy <source_buffer> to <destination_buffer>` to replace destination buffer contents.
Use `clear <buffer>` to reset a buffer to empty while preserving capacity.

**Key features:**
- **Dynamic growth**: Lists automatically allocate more memory as needed,
  wherever the list is named from - a variable, a global, or a `list`
  parameter naming the caller's list
- **Mixed types**: Appends of different types are allowed in any order; each
  element is printed by its own type, never by the list's (see Printing a
  List above)
- **Works with any value**: integers — a negative literal included, `append
  -5 to nums.` — floats, strings, booleans, `nothing`, variables, function
  calls, arithmetic, and the collection reads `element N of <list>`, `byte N
  of <buffer>` and `<name>'s <property>`
- **`to` is the separator, not an operator.** The value ends at the `to` that
  names the destination, so a value that would otherwise read `to` as a word
  of its own — a call written `'twice' to i` — is written in braces:
  `append {'twice' to i} to nums.` Braces hand the enclosed tokens to the
  general expression parser, exactly as they do in a value slot elsewhere
  (`append {i multiply i} to squares.`).

**Examples:**

```
(Append integers)
a list called nums is [].
append 10 to nums.
append 20 to nums.

(Append strings)
a list called words is [].
append "hello" to words.
append "world" to words.

(Append from variables)
a number called x is 42.
append x to nums.

(Append in loops)
a list called squares is [].
a number called i is 1.
While i is less than or equal to 5,
  append i multiply i to squares,
  increment i.
```

### Loop Expansion with Collections

The `each...from` syntax works with lists and ranges to execute an action for each item:

```
(Print each item from a list)
print each number from [1, 2, 3].

(Print each item from a range)
print each number from 1 to 10.

(Call a function for each item)
double of each n from [1, 2, 3].

(Append each item from a collection)
a list called source is [1, 2, 3].
a list called dest is [].
append each x from source to dest.
```

**Syntax:** `<action> each <variable> from <collection>`

**Supported collections:**
- **Lists**: `[1, 2, 3]`, any list variable
- **Ranges**: `1 to 10`, `start to end` (inclusive)
- **Arguments**: `arguments's all`

**Works with any action:**
- `print each X from Y` - print each item
- `function of each X from Y` - call function for each item
- `append each X from Y to Z` - append each item to a list
- `open ... at each X from Y` - open file for each path

**Examples:**

```
(Print each from list)
print each n from [10, 20, 30].

(Print each from range)
print each n from 1 to 5.

(Function call with loop expansion)
To double of a number called x.
  Return a number, x multiply 2.

print double of each n from [1, 2, 3].

(Append from range)
a list called range_list is [].
append each n from 1 to 5 to range_list.

(Append from list)
a list called source is [10, 20, 30].
a list called dest is [].
append each x from source to dest.

(Empty collection - does nothing)
print each n from [].
```

#### Chained clauses: the grid

`and` joins any number of `each` clauses in one sentence. The action runs
once per element of the **Cartesian product**, **row-major** (leftmost
clause = outermost loop):

```
'pair' of each x from [1, 2] and each y from [10, 20].
(triple grid: a list and two ranges, 2 x 2 x 2 = 8 calls)
'triple' of each first from [1, 2] and each second from 1 to 2 and each third from 7 to 8.
```

A fixed argument may appear in any position among the clauses:

```
'pair' of 5 and each y from [10, 20].
'pair' of each x from [1, 2] and 99.
```

**Arity is checked.** The number of argument clauses must equal the callee's
parameter count, just as for an ordinary call. A one-value action supplied
two `each` clauses is a compile error, not a concatenation:

```
print each x from [1, 2] and each y from [3, 4].
(`print` takes one value but this sentence supplies more than one argument clause.)
```

This is what stops `print each x from A and each y from B` from being misread
as printing both on one line. The single-value specialized forms (`print`,
`append`, `open`) therefore take one clause only; a second `each` is the
arity error above.

One asymmetry, kept deliberately: in `print <func> of ...` the grid form
requires the **first** clause to be an `each` — `print pair of 5 and each y
from B` stays an error, because grid-parsing every printed call would change
what `print f of x add 1` has always meant (`f(x) add 1`). When a fixed
argument must come first, use a plain call statement and print inside the
function.

**Empty collection anywhere → zero calls.** If any clause's collection is
empty, the whole grid produces no calls, regardless of position:

```
'pair' of each left from [] and each right from [10, 20].   (zero calls)
'triple' of each first from [1, 2] and each second from [] and each third from [5].  (zero calls)
```

**Duplicate loop variables in one sentence are a compile error**, naming the
variable:

```
'pair' of each x from [1, 2] and each x from [3, 4].
(Loop variable 'x' is bound twice in one sentence.
 Each `each` clause must use a different name.)
```

**`but if`** attaches to the innermost iteration; its condition may reference
every loop variable, since every loop is outside the conditional:

```
'pair' of each left from [1, 2, 3] and each right from [1, 2, 3], but if left is right print "diag".
```

**After-loop values.** Each loop variable retains its last-iteration value,
independently — the same shadowing rule as a single clause, applied per
variable. For a range clause, "last-iteration value" means what it means for
a handwritten `For each ... from 1 to N`: the counter that ended the loop.

```
'pair' of each left from [1, 2, 3] and each right from [10, 20].
print the left.   (prints 3)
print the right.  (prints 20)
```

**Zip is not the semantics.** `each x from A and each y from B` is a
Cartesian product, not a zip — matching comprehension syntax in Haskell,
Python, and Rust. English's zip marker is `respectively`, which is reserved
as a possible future marker for a zip mode; it is not parsed today.

**Variable shadowing:**

Loop variables shadow outer variables with the same name. After the loop, the variable retains the value from the last iteration:

```
a number called x is 100.
print the x.                  (prints 100)

print each x from [1, 2, 3].  (prints 1, 2, 3)

print the x.                  (prints 3 - last iteration value)
```

### Conditional Branching with `but if` (Lists and Collections)

Use `but if` as a generic conditional branch over any base action, including inside loops and loop expansion:

```
(Print numbers, but override with words for certain values)
print each number from 1 to 15,
    but if the number modulo 6 is equal to 0 print "fizzbuzz",
    but if the number modulo 2 is equal to 0 print "fizz",
    but if the number modulo 3 is equal to 0 print "buzz".

(Simple even/odd labeling)
print each number from 1 to 10,
    but if the number modulo 2 is equal to 0 print "even".

(Conditional append in a loop)
append each number from 1 to 5 to out,
    but if the number modulo 2 is equal to 0 append 0.
```

**How it works:**
1. The default action is the base statement.
2. Each `but if` clause is checked in order.
3. If a condition is true, that alternative action runs instead of the default.
4. If no conditions match, the default action runs.
5. An optional `otherwise` clause provides a final alternative.

**Key points:**
- Conditions are checked in order - first match wins
- Multiple `but if` clauses can be chained
- The alternative action can be any valid Vox statement
- `otherwise` provides a catch-all alternative
- Works with both ranges and collections
- The loop variable is available in conditions
- In an `append` branch, the `to <list/buffer>` target may be omitted and is inherited from the base append statement; retargeting to a different list/buffer is not allowed

### Inline Value Substitution with `treating`

The `treating X as Y` clause performs inline value substitution:

```
(Replace '-' with "/dev/stdin" for each filename)
open a file for reading called source at each filename from arguments's all treating "-" as "/dev/stdin",
  read from source into content,
  write content to output,
  close source.

(Print with default value)
print each name from names treating "" as "Anonymous".

(Call function with substitution)
process of each filename from files treating "-" as "/dev/stdin".

(Append with substitution - the clause goes with the `each` clause, before
 the `to <destination>`)
append each name from names treating "" as "Anonymous" to cleaned.
```

**Syntax:** `... each <var> from <collection> treating <match> as <replacement>, ...`

If the loop variable equals `<match>`, it's replaced with `<replacement>` for that iteration.

Equality is by type as well as by value: a `<match>` whose type differs from
the element's never fires, and that element comes through unchanged — and
where the compiler can prove the mismatch, it says so at compile time
instead. Where the element, the `<match>` or the `<replacement>` is a
`value`, the runtime tag it carries is what the comparison reads, and a
substitution that fires hands the `<replacement>`'s own type out with it.

---

## Input/Output

### Print

```
Print "Hello, World!".
Print the x.
Print 'add numbers' of 3 and 5.
```

**Print without newline:**
```
Print "Loading: " without newline.
Print progress without newline.
Print "%".
```

### Format Strings

Embed variables and expressions directly in strings using curly braces `{}`:

```
a text called name is "Alice".
a number called age is 25.
Print "Hello, {name}! You are {age} years old.".
```

#### Format Specifiers

| Specifier | Description | Example | Output |
|-----------|-------------|---------|--------|
| `{var}` | Default formatting | `{name}` | `Alice` |
| `{var:.N}` | N decimal places | `{pi:.2}` | `3.14` |
| `{var:N}` | Pad to N characters | `{x:6}` | `    42` |
| `{var:0N}` | Zero-pad to N chars | `{x:06}` | `000042` |
| `{var:x}` | Hexadecimal (lowercase) | `{n:x}` | `0xff` |
| `{var:X}` | Hexadecimal (uppercase) | `{n:X}` | `0xFF` |
| `{var:b}` | Binary | `{n:b}` | `101` |
| `{var:o}` | Octal | `{n:o}` | `0o10` |
| `{var:04x}` | Padded hex | `{n:04x}` | `0x00ff` |

The value inside `{}` must be a variable or expression, not a bare literal —
`{255:x}` is rejected (`255` is read as a variable name). The examples above
assume a declared `a number called n is 255.` (set `n` to 5 or 8 for the
binary and octal rows).

`N` is a count in both forms, and both render in full: `{var:N}` pads out to
`N` characters and `{var:.N}` prints exactly `N` decimal places, correctly
rounded (an exact tie goes to the even digit). Neither is capped — a very
large `N` is simply a very large amount of output — but `N` has to be a
count the compiler can hold, at most 9223372036854775807; past that it is a
compile error naming the limit, not a width that quietly does nothing. A
precision past the value's exact decimal expansion pads with zeros, since the
expansion has ended and not because accuracy has run out: a float is a
binary fraction, so it always has an exact finite expansion, and `{pi:.50}`
prints all fifty places of it. A whole number has an exact expansion too —
itself, then zeros — so `{n:.2}` on `a number called n is 255.` prints
`255.00`, and prints it exactly for every number Vox can hold.

**A specifier has to be one the value's type can answer.** A width asks
nothing of a type: every rendering is some number of characters long, so
`{var:N}` is accepted whatever `var` is (on a `float` or a `text` the value
is rendered and the padding is not applied yet). The other two do ask
something, and asking it of the wrong type is a compile error naming the way
out, not a wrong answer:

- `{var:.N}` counts places in a **number's** decimal expansion. A `number`,
  a `float` and a `boolean` have one; a `text` or a `buffer` does not.
- `{var:x}`, `{var:X}`, `{var:b}` and `{var:o}` write a **whole number** in
  another base. A `number` and a `boolean` are whole numbers. A `float` is
  not — `{ratio:b}` is refused rather than quietly dropping the fraction, so
  write `{ratio as a number:b}` when that is what you meant — and neither is
  a `text` or a `buffer`.

Inside an *expression* hole the cast has nowhere to go — the braces a
whole-expression cast needs are the hole's own — so work the value out into
a number first and render that:

```
a float called ratio is 2.5.
a number called total is {ratio multiply 2.0} as a number.
Print "{total:x}".                (0x5)
```

A `value`, a `list` and a `map` render through their own routines, which
ignore a specifier and print the value; a `value`'s type is not known until
it runs, so there is nothing to check.

The two compose: `{var:8.2}` asks for two decimal places, padded out to
eight characters. The precision decides the digits and the width decides the
padding, and each is honoured wherever there is something to honour it with —
the same rule the width follows on its own. So `{n:8.2}` on `a number called
n is 255.` prints `  255.00`, and `{n:08.2}` prints `00255.00`; on a `float`
the places are printed and the padding is not, because there is no float
padder yet — exactly as a bare `{f:8}` prints the float unpadded. (A width
composes with a radix too, which is the `{var:04x}` row above.)

#### Expressions in Format Strings

```
a number called x is 10.
a number called y is 3.
Print "Sum: {x add y}".
Print "Product: {x multiply y}".
Print "Arguments: {arguments's count}".
```

#### Format Strings as Values

Format strings are expressions, not just print arguments. Used as a
value, a format string materializes into a fresh NUL-terminated string,
so it works as a text initializer or assignment and survives being
carried through lists (e.g. into an `Execute` argument list):

```
a buffer called word is 64 bytes in size.
copy hello to word.

a text called tok is "{word}".        (text from buffer contents)
a text called path is "/bin/{tok}".   (text from another text)

a list called cmdargs is [].
append tok to cmdargs.
Execute "/bin/echo" with arguments cmdargs.
```

Each evaluation allocates a new string; the source buffer can be
cleared and reused without affecting texts already created from it.

#### Format Strings Everywhere

Every statement that takes a string value accepts a format string:
`write`, buffer `set`/`copy`/`append`, filesystem paths (`Create a
directory called "{base}/{name}"`), `treating` clauses, and function
arguments. All sinks share one name resolver, so special names like
`{arguments's first}` and `{current time's hour}`, format specifiers,
and the `0x`/`0o` hex/octal prefixes render identically whether the
result is printed, written to a file, or built into a text or a
buffer - a float's precision included: `{ratio:.2}` reads `2.50` in
every one of them.

#### Declarations in Branches

A variable (or file handle) declared in EVERY branch of an
`if`/`otherwise` chain definitely exists afterwards: it can be used
after the branch and from inside functions, exactly like a top-level
declaration. A name declared in only SOME branches remains scoped to
its condition, and cross-condition use is still a compile error.

```
if 'output file' is empty then,
  Open a file for writing called output at 1.
Otherwise,
  Open a file for writing called output at 'output file'.

(output exists on every path - usable here and in functions)
write "hello\n" to output.
```

#### Escape Sequences

| Escape | Description |
|--------|-------------|
| `{{` | Literal `{` |
| `}}` | Literal `}` |
| `\n` | Newline |
| `\t` | Tab |
| `\\` | Literal backslash |

**Example:**
```
Print "Use {{braces}} for literal braces.".
Print "Tab:\there".
Print "Line1\nLine2".
```

### Conditional Print

```vox fragment
Print <default>, but if <condition> print <value>.
```

**Chained conditions:**
```vox fragment
Print the number, but if <cond1> print "fizz buzz" but if <cond2> print "fizz" but if <cond3> print "buzz".
```

**Rules:**
- First matching condition wins
- Chain with `but if` or `and if`
- Default value prints if no conditions match

---

## File I/O

### Buffers

Buffers are memory blocks for I/O operations. They come in two types:

#### Dynamic Buffers (default)

```
a buffer called inputbuf.
a buffer called data.
```

**Features:**
- Start with zero capacity and grow automatically as needed
- No buffer overflows possible - memory expands dynamically
- Automatically freed on program exit

#### Fixed-Size Buffers

```
a buffer called small is 256 bytes in size.
a buffer called large is 8192 bytes in size.
```

**Features:**
- Allocates exactly the specified capacity
- Does NOT grow - a read or write past capacity is truncated at capacity and sets the error flag
- Useful when you need predictable memory usage
- User programs can check buffer length to detect truncation
- Automatically freed on program exit

**The size bound.** A fixed buffer's size must be between 1 and 1073741824
bytes (1 GiB), and the bound holds however the size is written - a literal,
a name, or a number the program only works out as it runs:

- A size the compiler can see is refused where it is written, whether that
  is the literal `a buffer called small is 0 bytes in size.` or a name
  whose value is fixed for the whole program.
- A size only run time can decide - one read from an argument, a file or a
  calculation - is refused when it is asked for. The buffer is made with no
  capacity and the error flag is raised, so `On error` catches it and the
  program carries on, exactly as it does for a fixed buffer that has become
  full.

A size of 0 is refused because a buffer with no fixed capacity is a
*dynamic* buffer, which is declared with no size at all: `a buffer called
small.`

**Truncation Behavior:**
When reading into a fixed buffer that becomes full:
- Reading stops and sets an error flag
- Data beyond capacity is discarded
- Program continues normally
- Use `On error` to catch and handle the overflow

### Object Properties

Access properties of objects using the `'s` syntax:

```
a number called len is mybuffer's size.
print myfile's size.

If mybuffer's size is equal to mybuffer's capacity then,
    print "Buffer is full!".
```

#### Universal Properties

Every variable has a `type` property that reports its declared type as text:

```
a number called n is 3.
a value called v is "hello".

print n's type.     (prints: Number (static))
print v's type.     (prints: Text (dynamic))
```

| Property | Description | Example |
|----------|-------------|---------|
| `type` | Declared type name plus `(static)` or `(dynamic)` | `Number (static)`, `Text (dynamic)` |

Statically-typed variables (`number`, `float`, `text`, `boolean`, `list`, `map`, `buffer`, `file`, `time`, `timer`) report their type with `(static)` because the compiler knows the type from the declaration. A `value` variable reports whatever its runtime tag currently holds, so it always uses `(dynamic)`.

This property is intended for printing and logging. For type *tests*, use the `is a <type>` predicate — comparing the display string is stringly-typed and can drift from the predicate.

#### Buffer Properties

| Property | Description | Type |
|----------|-------------|------|
| `size` | Current number of bytes stored | Number |
| `length` | Same as size | Number |
| `capacity` | Maximum bytes the buffer can hold | Number |
| `empty` | Whether the buffer has no data (size = 0) | Boolean |
| `full` | Whether size equals capacity (for fixed buffers) | Boolean |

**Example:**
```
a buffer called data is 256 bytes in size.
Read from file into data.

If data's full then,
    print "Buffer is at capacity".

If data's empty then,
    print "No data was read".
```

#### Buffer Resizing

Resize a buffer to a new capacity:

```
a buffer called buf is 64 bytes in size.
resize buf to 256 bytes.
resize buf to 128.
```

**Keywords:** `resize`, `reallocate`, `grow`, `shrink`

**Behavior:**
- Data is preserved up to min(old_length, new_capacity)
- If shrinking below current data length, data is truncated
- New buffer is allocated and old buffer is freed
- Texts already made from the buffer with `as text` are independent
  copies, so resizing never disturbs them

#### Buffer Byte Access

Read and write individual bytes in buffers and strings by position. Positions are **1-indexed** (like natural language: "the first byte", "the second byte").

**Reading bytes:**
```
a number called 'first' is byte 1 of data.
a number called 'byte value' is byte i of buf.
```

**Writing bytes:**
```
Set byte 1 of data to 0x48.
Set byte 2 of data to 'A'.
Set byte 3 of buf to value.
```

**Creating buffer from string:**
```
a buffer called buf is "Hello".
Set byte 1 of buf to 'J'.
Print buf.  (prints "Jello")
```

**Modifying string bytes:**
```
a buffer called msg is "Hello World".
Set byte 1 of msg to 'J'.
Print msg.  (prints "Jello")
```

**Bounds Checking:**
- Out-of-bounds access sets an error flag and returns 0
- Errors can be caught with `On error`
- Buffer overflow is impossible - the compiler enforces bounds

What "in bounds" means differs for a write and a read, and the worked
example below depends on it. A **write** (`Set byte N of buf to ...`)
accepts any position from 1 up to the buffer's *capacity*: writing past
the current size extends `size` to that position, zero-filling any gap
(a dynamic buffer grows its capacity as needed). A **read**
(`byte N of buf`) accepts positions from 1 up to the current *size* only -
a byte that has never been written or appended is out of bounds even
when the capacity has room for it. Position 0 is out of bounds for both.

#### Buffer Append and Copy

Efficiently combine buffers without byte-by-byte loops:

```vox fragment
append source to destination.
copy source to destination.
clear destination.

set destination to "line {n:06}\t{content}".
a buffer called destination is "line {n:06}\t{content}".
append "line {n:06}\t{content}" to destination.
copy "line {n:06}\t{content}" to destination.
```

**Behavior:**
- `append source to destination` adds source bytes to the end of destination.
- `copy source to destination` replaces destination contents with source bytes.
- `clear destination` sets destination length to `0` and preserves destination capacity.
- When destination is a buffer, format-string sources are supported for `set`, `is`, `append`, and `copy`.
- Format-string buffer writes are built in-place: literals/parts are appended directly to the destination buffer.
- Dynamic destination buffers grow automatically as needed.
- Fixed destination buffers truncate when full and set the error flag.
- Source buffer is never modified.

**Example:**
```
Create a buffer called data with size 16.
Set byte 1 of data to 0xDE.
Set byte 2 of data to 0xAD.
Set byte 3 of data to 0xBE.
Set byte 4 of data to 0xEF.

a number called b1 is byte 1 of data.
Print "First byte: {b1:02X}".

(Out of bounds - caught by error handler)
a number called bad is byte 100 of data.
On error print "Index out of bounds!".
```

#### File Properties

| Property | Description | Type |
|----------|-------------|------|
| `size` | File size in bytes | Number |
| `descriptor` | Raw file descriptor number | Number |
| `readable` | Whether file is open for reading | Boolean |
| `writable` | Whether file is open for writing | Boolean |
| `modified` | Last modification time (Unix timestamp) | Number |
| `accessed` | Last access time (Unix timestamp) | Number |
| `permissions` | File permission bits (e.g., 0644) | Number |

**Example:**
```
open a file for reading called src at "./data.txt".

print src's size.
print src's modified.

If src's size is greater than 1048576 then,
    print "File is larger than 1MB".
```

**Checking whether a file exists.** There is no `exists` property: every
property above describes a handle that is already open, and a file that
did not exist could not have been opened, so `exists` on a handle would
be trivially `true` and answer nothing. The question worth asking —
"can this path be opened?" — is answered by opening it and catching the
failure with `On error`, the same pattern used for every other file
operation that can fail:

```
open a file for reading called present at "./data.txt".
On error print "data.txt: cannot be opened".
If present's descriptor is greater than -1 then,
    print "data.txt: exists".

open a file for reading called missing at "./no-such-file.txt".
On error print "no-such-file.txt: cannot be opened".
```
→ `data.txt: exists` then `no-such-file.txt: cannot be opened`

A path-level `exists` predicate — asked before opening, with no handle
involved — is a planned future addition; today the `On error` idiom
above is how a program finds out.

#### List Properties (Object Properties)

| Property | Description | Type |
|----------|-------------|------|
| `length` | Number of items in the list | Number |
| `size` | Same as length | Number |
| `empty` | Whether the list has no items | Boolean |
| `first` | The first item in the list | Item |
| `last` | The last item in the list | Item |

**Example:**
```
a list called names is ["Alice", "Bob", "Charlie"].

print names's length.

If names's empty then,
    print "No names in list".
```

#### List Element Access (Object Properties)

Access list elements by index. Indexes are **1-indexed** (like natural language: "the first element", "the second element").

**By index:**
```
a list called nums is [10, 20, 30].

Print element 1 of nums.   (prints 10)
Print element 2 of nums.   (prints 20)

a number called i is 2.
Print element i of nums.   (prints 20)
```

**By property:**
```
Print nums's first.        (prints 10)
Print nums's last.         (prints 30)
```

**Bounds Checking:**
- Out-of-bounds access sets an error flag. Where the compiler can prove the
  index is past the end, it returns the **number** 0 whatever the list's
  elements are, so read it into a `number`; where it cannot, it returns the
  destination's default value from the table under [Two Canonical
  Forms](#two-canonical-forms) — `0` for a `number`, the empty text for a
  `text`, `[]` for a `list`, `{}` for a `map`
- Errors can be caught with `On error`

**Example with error handling:**
```
a list called items is [1, 2, 3].

a number called bad is element 100 of items.
On error print "Cannot access element 100 - out of bounds!".
```

#### Number Properties

| Property | Description | Type |
|----------|-------------|------|
| `even` | Whether the number is even | Boolean |
| `odd` | Whether the number is odd | Boolean |
| `positive` | Whether the number is > 0 | Boolean |
| `negative` | Whether the number is < 0 | Boolean |
| `zero` | Whether the number is 0 | Boolean |
| `absolute` | Absolute value | Number |
| `sign` | -1, 0, or 1 | Number |

**Example:**
```
a number called x is -42.

If x's negative then,
    print "x is negative".

print x's absolute.
```

### Opening Files

Open files for reading, writing, or appending:

```
open a file for reading called source at "./data.txt".
open a file for writing called output at "./result.txt".
open a file for appending called log at "./log.txt".
```

You can also open an existing file descriptor directly by number:

```
open a file for reading called stdin_handle at 0.
open a file for writing called stdout_handle at 1.
open a file for writing called stderr_handle at 2.
```

When `at` is numeric, Vox treats it as a borrowed file descriptor instead of a filesystem path.

**Flexible argument order:** The clauses `for reading/writing/appending`, `called <name>`, and `at <path>` can appear in any order:

```
open a file at "./data.txt" for reading called source.
open a file called output for writing at "./result.txt".
open a file at "./log.txt" called log for appending.
```

**Modes:**
- `reading` - Read from existing file
- `writing` - Create/overwrite file
- `appending` - Add to end of file

**`at` value rules (compile-time validation):**
- Use text for filesystem paths: `at "/path/to/file"`
- Use integers for file descriptors: `at 0`, `at 1`, `at 2`
- File descriptor literals must be in range `0..2147483647`
- Invalid types (for example `at 1.5` or `at true`) are compile-time errors

### Reading

**At a glance:**
- Use **`Read from ... into ...`** when you want to read raw bytes in chunks.
- Use **`Read line from ... into ...`** when you want one logical line at a time.

High-level behavior:
- `Read` replaces the buffer's contents with the bytes read; each `Read`
  continues from the file's current position, so it is best for bulk/stream
  processing.
- `Read line` replaces the buffer with the next line and is best for line-by-line loops.
- Both can read from files or standard input.

Read from files or standard input into a buffer:

```
Read from standard input into buf.
Read from source into contents.
```

Read one logical line (up to `\n` or EOF) into a buffer:

```
Read line from source into linebuf.
Read line from standard input into linebuf.
```

**`Read line` behavior:**
- Includes the trailing newline in the buffer (when a newline is present)
- Returns an empty buffer at EOF
- Resets buffer contents before each read (replace, not append)
- For fixed-size buffers, overlong lines are truncated and set the error flag

### Seeking

Move a file descriptor position before reading:

```
Seek source to line 1.
Seek source to byte 1.
Seek source to bytes 128.
```

**Seeking rules:**
- Positions are **1-indexed** (`line 1` = start of file, `byte 1` = file offset 0)
- `Seek ... to line N` moves to the first byte of line `N`
- `Seek ... to byte N`/`bytes N` moves to byte position `N`
- Invalid targets (e.g. line past EOF, position < 1, invalid fd) set the error
  flag, which `On error` catches
- Line `N` exists when the file holds at least `N-1` newlines before it, so a
  file that ends in a newline has one empty last line to seek to; anything
  beyond that is past EOF and sets the flag

### Writing

Write strings, buffers, or special values to files:

```
Write "Hello, World!" to output.
Write buf to output.
Write a newline to output.
```

`Write` takes a text, a buffer, or a format string; a bare number, float,
or boolean is a compile error, because a scalar holds a value where
`Write` needs the address of some bytes. Render it with a format string
instead:

```
a number called n is 72.
Write "{n}" to output.
```

A `value` is refused for the same reason — its type is only known at
runtime, so the compiler cannot tell a text it could write from a number
it could not. Copy it into a typed variable and write that:

```
a value called anything is "dynamic".
a text called settled is anything.
Write settled to output.
```

**Writing rules:**
- A failed `Write` sets the error flag and is catchable with `On error` — a
  write the system refused (no space, a handle opened for reading, a closed or
  never-opened handle) or one that transferred fewer bytes than asked for:

```
Write buf to output.
On error print "Write failed!", exit 1.
```

### Closing Files

Close file handles when done:

```
Close the source.
Close output.
```

### File Operations

Check if a file (or any path) is available:

```
If "data.txt" is available then,
    print "File found.".
```

`is available` (compiles to `access(2)` with `F_OK`) is the correct, current
form of this check. It works on any path expression - string literal, text
variable, or buffer - and is not limited to plain files; see
[Directories, Mounting, and Process Control](#directories-mounting-and-process-control)
for how it is used to poll for a device node.

Negate with `is not available`:

```
While the root_device is not available,
    Sleep for 100 milliseconds.
```

Delete a file:

```
Delete the file "data.txt".
```

### Error Handling

Operations that can fail (file reads, buffer operations, out-of-bounds access) set an error flag.

#### On Error Handler

Check for errors after specific operations with `On error`:

```
Read from source into buf.
On error print "Read failed or buffer overflow!".
```

**Catchable Errors:**
- Out-of-bounds list/buffer access
- Fixed buffer overflow (data exceeds capacity)
- File operation failures — opening, seeking, reading, writing and deleting
  alike. A failed `Write` sets the flag, and so does a `Read from`, a `Read
  line from` or a `Write` on a handle whose own `open` failed.

**Error Handling Patterns:**

```
(Handle file read errors)
Read from file into buffer.
On error print "Read failed!", exit 1.

(Handle out-of-bounds access)
a number called item is element 100 of mylist.
On error print "Index out of bounds!".

(Check buffer state manually)
If buffer's size is equal to buffer's capacity then,
    print "Warning: buffer may have been truncated".
```

### Resource Safety

`vox` provides **memory safety** through automatic resource management.

#### Memory Safety Guarantees

| Guarantee | How It's Enforced |
|-----------|-------------------|
| No buffer overflows | Buffers grow dynamically as needed |
| No use-after-free | Resources tracked and cleaned at exit |
| No resource leaks | Automatic cleanup of all FDs and buffers |
| No manual memory management | Compiler handles allocation/deallocation |

#### Automatic Cleanup

All resources are automatically cleaned up on program exit:

```
a buffer called data.                    (Auto-freed on exit)
open a file for writing called log at "x". (Auto-closed on exit)
(Even if you forget to close - it's handled!)
```

#### Dynamic Buffers

Buffers start at zero capacity and grow automatically. No size specification needed:

```
a buffer called inputbuf.     (Grows as needed - never overflows)
Read from source into inputbuf. (Safe regardless of file size)
```

**Internal structure:**
- 8 bytes: capacity (current allocation size)
- 8 bytes: length (bytes used)
- N bytes: data (grows via reallocation)

#### File Descriptor Tracking

Files are tracked at runtime for guaranteed cleanup:

1. **On open**: FD registered in tracking table
2. **On close**: FD unregistered from table
3. **On exit**: All remaining FDs automatically closed

This works correctly even with conditional file operations:

```
If condition is true then,
    open a file for writing called log at "debug.log",
    Write "Debug info" to log.
    (Close might be forgotten here - still safe!)
```

#### Safety vs C Comparison

| Issue | C Behavior | Vox Behavior |
|-------|------------|-------------|
| Buffer overflow | Undefined behavior, security vulnerability | Impossible - buffers auto-grow |
| Forgot to close file | Resource leak | Auto-closed on exit |
| Forgot to free memory | Memory leak | Auto-freed on exit |
| Double free | Undefined behavior | Tracked - can't happen |
| Use after free | Undefined behavior | Not possible by design |

---

## Directories, Mounting, and Process Control

These constructs were added for writing early-userspace/init-style programs
in Vox - see [examples/initramfs.vox](examples/initramfs.vox) for a complete,
working early-userspace init sequence exercising all of them together.

### Directories

```
Create a directory called "/proc".
Remove the directory called "/proc".
Delete the directory "/proc".
Change directory to "/newroot".
```

**Rules:**
- `Create a directory called '<path>'.` - `mkdir(2)`, mode `0755`. The article
  (`a`) is optional; `called` is required.
- `Remove the directory called '<path>'.` / `Delete the directory "<path>".` -
  `rmdir(2)`. Both `Remove` and `Delete` work; `the` and `called` are optional.
- `Change directory to "<path>".` - `chdir(2)`.
- All three set the error flag on failure - use `On error` to catch it.

### Mounting Filesystems

```
Mount "proc" at "/proc" with type "proc".
Mount "tmpfs" at "/dev/shm" with type "tmpfs" with options "size=64m".
On error print "mount failed", exit 1.

Unmount "/dev/shm".
Unmount "/dev/shm" lazily.
On error print "unmount failed".
```

**Rules:**
- `Mount "<source>" at "<target>" with type "<fstype>" [with options "<options>"].`
  lowers directly to `mount(2)`. `source`/`target`/`fstype`/`options` accept
  string literals, text variables, or buffers (including format-string-built
  buffers).
- Moving/binding an already-mounted filesystem uses `fstype "none"` with
  `options "move"` or `options "bind"` - Vox recognizes this pattern and
  translates it into the correct `MS_MOVE`/`MS_BIND` mount flags:
  ```
  Mount "/proc" at "/newroot/proc" with type "none" with options "move".
  ```
- `Unmount "<target>".` - `umount2(2)`. `umount` is accepted as an alias for
  `Unmount`. Append `lazily` for `MNT_DETACH` (detaches immediately and
  releases the mount once nothing is using it any longer, instead of failing
  with "device busy") - needed when unmounting a filesystem your own running
  program was loaded from.
- Both set the error flag on failure.

### Device Nodes

```
Create a device node called "/dev/null" with type "c" major 1 minor 3.
Create a device node called "/dev/loop0" with type "b" major 7 minor 0.
```

`mknod(2)`. `type` is `"c"` (character device) or `"b"` (block device);
`major`/`minor` are the standard Linux device-driver identification numbers
(see `man 4 null`/the kernel's `Documentation/admin-guide/devices.txt` for
the registry of standard values). Sets the error flag on failure.

### Symbolic Links

```
Create symbolic link from "/proc/self/fd" to "/dev/fd".
```

`symlink(2)`: `Create symbolic link from '<target>' to "<linkpath>".` Sets
the error flag on failure.

### Switching the Root Filesystem

```
Pivot root to "/newroot" with old root "/newroot/oldroot".
```

`pivot_root(2)`. `put_old` (the second path) must be a directory that
already exists *inside* `new_root` - create it after mounting the new root,
not before. After a successful pivot, the previous root filesystem is
accessible at `put_old`'s path relative to the new root (here, `/oldroot`),
and should typically be released with `Unmount "..." lazily` once your
program has `chdir`'d away from it. Sets the error flag on failure.

### Executing Programs

```
Execute "/bin/sh".
Execute "/bin/echo" with arguments ["hello", "world"].

a list called cmdargs is ["hello", "world"].
Execute "/bin/echo" with arguments cmdargs.

On error print "execve failed", exit 1.
```

`execve(2)` - replaces the current process image entirely. Three forms:

- **No arguments**: `Execute "<path>".` synthesizes `argv = [path, NULL]`
  (argc 1).
- **Literal argument list**: `Execute '<path>' with arguments [...].` - argv
  is built at compile time.
- **List variable**: `Execute '<path>' with arguments <list>.` - argv is
  built at runtime from the list's current length and contents, sized and
  bounds-checked from that single length read so the argv array cannot be
  overrun regardless of the list's contents.

The environment is inherited from the calling process in all three forms.
`execve` only ever returns on failure (there is no "success" path to return
to - the process image is gone), so `On error` after `Execute` is the normal
and only way to detect that it didn't work.

### Process Control: fork and reap

```
Set pid to fork the process.
If pid is 0 then,
    (this branch runs in the child)
    Execute "/bin/some-program".
If pid is greater than 0 then,
    (this branch runs in the parent - pid holds the child's real PID)
    Set reaped to reap any child process.
```

These are **expressions**, not statements - use them anywhere an expression
is valid (typically the right-hand side of `Set`/`a number called ... is`).

- `fork the process` (the trailing `the process` is optional; bare `fork`
  also works) - `fork(2)`. Returns `0` in the child, the child's PID in the
  parent, or a negative value on error. Sets the error flag on failure.
- `reap any child process` - `wait4(2)` with `pid = -1`, waiting for any
  child. Returns the reaped child's PID, or a negative value on error.
- `reap process <pid-expr>` / `reap child <pid-expr>` - `wait4(2)` for a
  specific PID.

Both set the error flag on failure (e.g. `On error` after `reap process 999999`
catches `ECHILD` when the PID is not actually your child).

#### Non-blocking reap: `without waiting`

Any reap form takes a `without waiting` suffix, which calls `wait4(2)`
with `WNOHANG` instead of blocking:

```
Set r to reap any child process without waiting.
Set r to reap child pid without waiting.
Set r to reap process pid without waiting.
```

The return value is the whole point of the form, and the three cases must
be told apart:

- a child finished → its PID, error flag cleared;
- children exist but none has finished → `0`, error flag cleared (this is
  **not** an error — it is how you tell "still running" from "gone");
- genuine error, e.g. no such child (`ECHILD`) → negative, error flag set,
  catchable with `On error`.

A non-blocking reap that returns `0` reaps nothing, so it does **not**
disturb `the reaped status` (below) — only a reap that actually returns a
child's PID changes it. `without` is already a reserved keyword (it is the
`print ... without newline` token), so the suffix cannot be confused with a
call argument after the pid expression, and `waiting` remains an ordinary
identifier everywhere it is not this suffix.

#### The reaped status

```
Set r to reap child pid.
Set status to the reaped status.
```

`the reaped status` is an expression yielding the raw `wait4` status word as
a plain number — exactly the `int status` the kernel writes, undecoded. It
reflects the most recent *successful* reap in the current process. Before
any successful reap it is `-1`, a sentinel no real status can take, so
"never reaped" is distinguishable from "exited 0". The sentinel lives in
loader-initialized `.data`, not `.bss`, because `_start` (which would zero
a `.bss` global) is only emitted for executables — a `--shared` library
would otherwise read `0` and silently report "exited cleanly" with no child
ever reaped.

`reaped` stays an ordinary identifier: `the reaped status` is consumed only
as that exact phrase, and `the reaped` followed by anything else is an
ordinary variable reference. (`tests/102_fork_reap.vox` does
`Set reaped to reap any child process.` and keeps passing.)

#### Decoding the status

The compiler knows nothing about the wait-status encoding — `the reaped
status` hands back the raw word, and a program decodes it with `divide`,
`modulo`, and `bit-and`. Vox has no standard library on purpose, and this
feature is complete with nothing installed:

```
To 'exit code of' with a number called status.
  Return a number, status divide 256 modulo 256.

To 'signal of' with a number called status.
  Return a number, status bit-and 127.
```

For ready-made decoding — these two plus `crashed` and `'exited
normally'`, matching the `<sys/wait.h>` macros — the `process` library
lives at [Vox-lang/vox-libs](https://github.com/Vox-lang/vox-libs),
installable as an ordinary shared library:

```
see process version "0.1" from "./libprocess.lib".
```

It provides four functions over the raw status word, matching the
`<sys/wait.h>` macros: `'exit code of'` (bits 8–15), `'signal of'` (the low
7 bits), `crashed` (true if a signal killed it), and `'exited normally'`
(true if no signal was involved). Use them at the call site, where they
read as English:

```
If crashed of status then,
    Print "died by signal {'signal of' of status}".
If 'exited normally' of status then,
    Print "exit {'exit code of' of status}".
```

#### A supervisor loop, with no shelling out

These pieces compose into a complete supervisor — poll a child with
non-blocking reap, time it out, kill it, and report how it died — using
only Vox, no `/bin/sh` and no coreutils.
[`examples/supervisor.vox`](examples/supervisor.vox) is this loop as a
runnable program, supervising both a job that finishes and a job that
hangs:

```
see process version "0.1" from "./libprocess.lib".

Set pid to fork the process.
If pid is 0 then,
    Exit 0.

a timer called clock.
Start the clock.
a boolean called 'child is still running' is true.
a boolean called 'child was killed' is false.
While 'child is still running',
    Set 'reap result' to reap child pid without waiting,
    If 'reap result' is pid then,
        Set 'child is still running' to false.
    If 'child is still running' then,
        a number called 'milliseconds waited' is the clock's elapsed in milliseconds,
        If 'milliseconds waited' is greater than 5000 then,
            Send signal 9 to process pid,
            Set 'reap result' to reap child pid,
            Set 'child is still running' to false,
            Set 'child was killed' to true.
    If 'child is still running' then,
        Wait 10 milliseconds.

If 'child was killed' then,
    Print "hang".
If 'child was killed' is false then,
    Set status to the reaped status,
    If crashed of status then,
        Print "died by signal {'signal of' of status}".
    If 'exited normally' of status then,
        Print "exit {'exit code of' of status}".
```

A note on timing: `the clock's elapsed in milliseconds` reports true
milliseconds, so the 5000-millisecond deadline above fires accurately at
the five-second mark.

#### Send a signal: `Send signal`

Unlike `fork`/`reap`, this is a **statement**, not an expression:

```vox fragment
Send signal <N-expr> to process <pid-expr>.
```

It performs `kill(2)` (syscall 62): `<pid-expr>` is the target PID (loaded
into `rdi`), `<N-expr>` is the signal number (loaded into `rsi`). `child` is
accepted as an alias for `process`, mirroring `reap process/child`:

```
Send signal 9 to child pid.
```

On success it clears the error flag; on failure (`ESRCH` no such process,
`EINVAL` invalid signal, `EPERM` not permitted) it sets it, exactly like the
other syscall statements, so `On error` catches the failure:

```
Send signal 0 to process 999999.
On error print "no such process".
```

Signal 0 is the standard existence check: it delivers nothing but returns an
error if no process has that PID, which makes it a safe way to probe the error
path. A common pattern is to send a real signal to a forked child and reap it:

```
Set pid to fork the process.
If pid is 0 then,
    Wait 30 seconds.
If pid is greater than 0 then,
    Send signal 9 to process pid.
    Set reaped to reap any child process.
    If reaped is pid then,
        Print "sigkilled child reaped with matching pid".
```

### System Control: Shutdown, Reboot, Halt

```
Shutdown.
On error print "shutdown failed - are you root?".

Reboot.
Halt.
```

`reboot(2)`, requiring `CAP_SYS_BOOT` (root). Each statement calls `sync(2)`
first to flush filesystem buffers, then issues the matching command:

| Statement | Aliases | Command |
|-----------|---------|---------|
| `Shutdown` | `Poweroff` | `LINUX_REBOOT_CMD_POWER_OFF` |
| `Reboot` | `Restart` | `LINUX_REBOOT_CMD_RESTART` |
| `Halt` | - | `LINUX_REBOOT_CMD_HALT` |

**On success, none of these return** - the machine powers off/restarts/halts.
On failure (not root, or no `CAP_SYS_BOOT`), the error flag is set instead of
crashing or exiting, so `On error` safely catches the failure and execution
continues - an unprivileged or accidental invocation can never bring down
the machine.

---

## Time and Timers

### Getting Current Time

Get the current date/time as a `time` value:

```vox fragment
Get current time into now.
a time called now is current time.
```

### Time Properties

Access components of a time value using the `'s` property syntax:

| Property | Description | Type |
|----------|-------------|------|
| `hour` | Hour of day (0-23) | Number |
| `minute` | Minute (0-59) | Number |
| `second` | Second (0-59) | Number |
| `day` | Day of month (1-31) | Number |
| `month` | Month (1-12) | Number |
| `year` | Year (e.g., 2026) | Number |
| `unix` | Unix timestamp (seconds since epoch) | Number |

**Example:**
```
Get current time into now.
Print "Current time: ".
Print the now's hour.
Print ":".
Print the now's minute.
Print ":".
Print the now's second.

Print "Date: ".
Print the now's year.
Print "-".
Print the now's month.
Print "-".
Print the now's day.
```

### Inline Time Access

Access current time properties directly without storing:

```
Print "It is currently hour ".
Print current time's hour.
Print " of the day.".
```

### Sleep / Wait

Pause program execution for a specified duration:

```
Wait 1 second.
Wait 2 seconds.
Wait 500 milliseconds.
Sleep for 3 seconds.
```

**Syntax variations:**
- `Wait <N> second.` / `Wait <N> seconds.`
- `Wait <N> millisecond.` / `Wait <N> milliseconds.`
- `Sleep for <N> seconds.`
- `Sleep for <N> milliseconds.`

### Timers

Timers are stopwatches for measuring durations. They track start time, end time, and elapsed duration.

#### Creating a Timer

```
Create a timer called 'job timer'.
a timer called benchmark.
```

#### Starting and Stopping

```
Start the 'job timer'.
(... do work ...)
Stop the 'job timer'.
```

**Alternative spellings:**
- `Start` / `Begin`
- `Stop` / `Finish`

These four words are **contextual, not reserved**. They open a timer
statement only when a name operand follows — `Start the t.`, `stop t.` —
and everywhere else they are ordinary identifiers, so `a number called
stop is 0.` compiles, and a program may define and call its own
zero-argument `start.` function. (`End` is not a Stop spelling: `end`
belongs to the `exit` family of keywords and remains reserved.)

#### Timer Properties

| Property | Description | Type |
|----------|-------------|------|
| `duration` | Total duration (requires cast) | Duration |
| `elapsed` | Elapsed time while running (requires cast) | Duration |
| `start time` | When timer was started (unix timestamp) | Number |
| `end time` | When timer was stopped (unix timestamp) | Number |
| `running` | Whether timer is currently running | Boolean |

#### Getting Duration

Use `in` to cast duration to a specific unit:

```
Print the 'job timer''s duration in seconds.
Print the 'job timer''s duration in milliseconds.
Print the 'job timer''s elapsed in seconds.
```

#### Complete Timer Example

```
(Measure job duration)
Print "Starting job...".
Create a timer called 'job timer'.
Start the 'job timer'.

(... do work ...)
Wait 1 second.
Print "Seconds elapsed so far: ".
Print the 'job timer''s elapsed in seconds.

Wait 500 milliseconds.
Stop the 'job timer'.

Print "Finished the job in: ".
Print the 'job timer''s duration in seconds.
Print " seconds".

(Access raw timestamps)
Print "Started at unix time: ".
Print the 'job timer''s start time.
Print "Stopped at unix time: ".
Print the 'job timer''s end time.
```

#### Formatted Time Output

Combine time properties with the zero-pad format specifier (see
[Format Specifiers](#format-specifiers)) for formatted output. A time
property can be read directly inside a format slot:

```
Get current time into now.
Print "{now's hour:02}:{now's minute:02}:{now's second:02}".
(Prints: 09:05:03)
```

Or, if you want the parts as named values first:

```
Get current time into now.
a text called h is "{now's hour:02}".
a text called m is "{now's minute:02}".
a text called s is "{now's second:02}".

Print "{h}:{m}:{s}".
(Prints: 09:05:03)
```

---

## Command-Line Arguments

Access command-line arguments using the `'s` property syntax.

### Arguments Properties

| Property | Syntax | Description |
|----------|--------|-------------|
| `count` | `arguments's count` | Total number of arguments (including program name) |
| `name` | `arguments's name` | Program name (argv[0]) |
| `first` | `arguments's first` | First user argument (argv[1]) |
| `second` | `arguments's second` | Second user argument (argv[2]) |
| `last` | `arguments's last` | Last argument |
| `empty` | `arguments's empty` | True if no user arguments (argc ≤ 1) |
| `all` | `arguments's all` | User arguments as a collection (for loop expansion) |
| `raw` | `arguments's raw` | Original unfiltered user arguments as a collection |

### Basic Usage

```
a number called argc is arguments's count.
Print "Argument count: ".
Print the argc.

a text called program is arguments's name.
Print "Program name: ".
Print the program.
```

### Accessing User Arguments

```
(Get the first argument passed by the user)
If arguments's count is greater than 1 then,
    a text called username is arguments's first,
    Print "Hello, ",
    Print the username.
Otherwise,
    Print "Hello, World!".
```

### Checking if Arguments Were Provided

```
If arguments's empty then,
    Print "No arguments provided.".
```

### Dynamic Index Access

For accessing arguments by a computed index, use the `argument at` syntax:

```
a number called i is 2.
a text called val is the argument at the i.
```

### Declarative Flag Parsing

Vox supports declarative CLI flag parsing with a schema-first style.

#### 1) Declare a flag schema

Define each supported flag once, including aliases and type:

```
a flag called verbose is "-v" or "--verbose", it is a boolean.
a flag called output is "-o" or "--output", it is a text.
a flag called retries is "-r" or "--retries", it is a number.
```

Supported flag value types:

- `boolean` (presence sets true)
- `text` (consumes the next token as text)
- `number` (consumes the next token and parses it as a number)

#### 2) Optional schema modifiers

Flags may be marked as required and/or given defaults:

```
a flag called output is "-o" or "--output", it is a text with default "out.txt".
a flag called retries is "-r" or "--retries", it is a number and is required.
```

- `with default ...` initializes the flag value if the flag is not passed.
- `and is required` requires the flag to be present at runtime.
- A flag with no `with default` that is not passed holds its type's empty
  value: `""` for a `text`, `0` for a `number`, and false for a `boolean`.
  An unsupplied `text` flag is therefore safe to read, and can be tested
  with `is empty`.

#### 3) Parse point: explicit or automatic

You can parse flags explicitly:

```
Parse flags.
```

Or omit it. If omitted, Vox inserts parsing automatically **immediately after the last flag schema declaration**.

#### 4) Placement rules

Flag schema declarations are valid as long as they appear **before parsing occurs**.

- You may place normal code before/between schema declarations.
- You may use explicit `Parse flags.` to choose exactly when parsing happens.
- Declaring new schemas **after** `Parse flags.` is a compile-time error.
- Using flag variables before the parse point is a compile-time error.

#### 5) `arguments's all` vs `arguments's raw`

After parsing:

- `arguments's all` is the filtered positional argument view (recognized flags removed).
- `arguments's raw` keeps the original user-provided argument sequence unchanged.

Example:

```
a flag called verbose is "-v" or "--verbose", it is a boolean.
a flag called output is "-o" or "--output", it is a text with default "out.txt".
Parse flags.

Print "output:{output}".

Print "ALL".
Print each item from arguments's all.

Print "RAW".
Print each item from arguments's raw.
```

#### 6) Unix `--` separator

`--` stops flag processing. Tokens after `--` are treated as positional arguments.

Example invocation:

```
myprog --verbose -- -v file.txt
```

In this case:

- `--verbose` is parsed as a flag
- `-v` after `--` is treated as a normal positional argument

#### 7) Practical pattern

```
a flag called help is "-h" or "--help", it is a boolean.
a flag called 'version' is "-V" or "--version", it is a boolean.
a flag called 'number' is "-n" or "--number", it is a boolean.

Parse flags.

If help then,
    Print "Usage: myprog [options] [files]".

If 'version' then,
    Print "myprog 1.0.0".

Print each item from arguments's all.
```

---

## Environment Variables

Access environment variables using the `'s` property syntax.

### Environment Properties

| Property | Syntax | Description |
|----------|--------|-------------|
| `count` | `environment's count` | Total number of environment variables |
| `first` | `environment's first` | First env var (full "NAME=value" string) |
| `last` | `environment's last` | Last env var |
| `empty` | `environment's empty` | True if no environment variables |
| `"NAME"` | `environment's "HOME"` | Value of specific env var by name |

### Reading Environment Variables

```
a text called home is environment's "HOME".
a text called user is environment's "USER".
a text called shell is environment's "SHELL".

Print "Home: ".
Print the home.
```

### Environment Variable Count

```
a number called 'env count' is environment's count.
Print "Total environment variables: ".
Print the env count.
```

### Iterating Environment Variables

```
a text called env1 is environment's first.
Print "First env var: ".
Print the env1.
```

### Checking if Variable Exists

```
If the environment variable "DEBUG" exists then,
    Print "Debug mode enabled".
```

### Complete Example

```
(A greeter using the 's property syntax)

a text called name is "World".

(Use argument if provided, otherwise use environment variable)
If arguments's count is greater than 1 then,
    the name is arguments's first.
But if the environment variable "GREET_NAME" exists then,
    the name is environment's "GREET_NAME".

Print "Hello, ".
Print the name.
Print "!".

(Show some environment info)
a text called user is environment's "USER".
Print "Current user: ".
Print the user.
```

**Note:** The argument and environment variable functions are only included in the binary when used, keeping programs that don't need them small and efficient.

---

## Operators

### Arithmetic Operators

| Operator | Keywords |
|----------|----------|
| Addition | `add`, `plus` |
| Subtraction | `subtract`, `minus` |
| Multiplication | `multiply`, `times` |
| Division | `divide` |
| Modulo | `modulo`, `mod`, `remainder` |

### Comparison Operators

| Comparison | Syntax |
|------------|--------|
| Equal | `is equal to`, `is` |
| Not Equal | `is not equal to`, `is not` |
| Greater Than | `is greater than` |
| Less Than | `is less than` |
| Greater or Equal | `is greater than or equal to` |
| Less or Equal | `is less than or equal to` |

### Logical Operators (table)

| Operator | Keyword |
|----------|---------|
| And | `and` |
| Or | `or` |
| Not | `not`, `isn't`, `aren't` |

`isn't` and `aren't` are contractions, and each stands for **two** words:
`isn't` is `is not`, `aren't` is `are not`. Write them exactly where the
spelled-out pair belongs — `If v1 isn't v2 then,` is `If v1 is not v2 then,`
— and write a bare `not` everywhere no `is`/`are` belongs. These two are the
only contractions in Vox: everywhere else an apostrophe is the possessive
marker, a quoted name, or a character literal, and a word like `don't` or
`it's` is not Vox (`it's length` is the possessive on a variable called
`it`). See [Names and strings](#names-and-strings).

### Bitwise Operators

| Operator | Keywords |
|----------|----------|
| Bitwise AND | `bit-and` |
| Bitwise OR | `bit-or` |
| Bitwise XOR | `bit-xor` |
| Shift Left | `bit-shift-left` |
| Shift Right | `bit-shift-right` |

**Examples:**
```
a number called lhs is 0b11110000.
a number called rhs is 0b10101010.

(Bitwise AND)
a number called result is lhs bit-and rhs.

(Bitwise OR)
Set result to lhs bit-or rhs.

(Bitwise XOR)
Set result to lhs bit-xor rhs.

(Bit shifting)
Set result to lhs bit-shift-left 2.
Set result to lhs bit-shift-right 4.

(Chained operations)
Set result to value bit-shift-right 8 bit-and 0xFF.
```

---

## Keywords

### Articles (Context-Dependent)

| Keyword | Usage |
|---------|-------|
| `a`, `an` | Declares new variable with type |
| `the` | References existing variable |

### Statement Starters

| Keyword | Purpose |
|---------|---------|
| `Print` | Output |
| `Set`, `Create` | Variable declaration |
| `If`, `When` | Conditional |
| `While` | Loop |
| `For` | Iteration |
| `To` | Function definition |
| `Return` | Return value |
| `Increment` | Add 1 to variable |
| `Decrement` | Subtract 1 from variable |
| `Break` | Exit loop |
| `Continue` | Skip to next iteration |
| `Exit` | Terminate program with exit code |
| `Append` | Add element to list |
| `Create`, `Change`, `Remove`/`Delete` | Directories, device nodes, symlinks, chdir (see [Directories, Mounting, and Process Control](#directories-mounting-and-process-control)) |
| `Mount`, `Unmount`/`Umount` | Mount/unmount filesystems |
| `Pivot` | `pivot_root` - switch the root filesystem |
| `Execute` | `execve` - replace the process image |
| `Shutdown`/`Poweroff`, `Reboot`/`Restart`, `Halt` | `reboot(2)` - power off/restart/halt the machine |
| `fork`, `reap` | Process control expressions - `fork(2)`/`wait4(2)` |
| `Send signal` | `kill(2)` - send a signal to a process (`child` aliases `process`) |

### Flag Schema

| Keyword | Purpose |
|---------|---------|
| `Flag` | Declare a command-line flag schema (`a flag called ...`) |
| `Parse` | Trigger command-line flag parsing (`Parse flags.`) |
| `Required` | Mark a flag as required |
| `Default` | Supply a default value for a flag |

### Connectors

| Keyword | Purpose |
|---------|---------|
| `with` | Function parameters, function arguments |
| `called`, `named` | Variable naming |
| `of`, `to`, `on` | Function arguments |
| `and` | Multiple uses (see below) |
| `or` | Logical OR |
| `but` | Conditional chaining |
| `then` | After condition |
| `otherwise`, `else` | Alternative branch |
| `from`, `to` | Range bounds |

### The `and` Keyword

The word `and` has multiple context-dependent meanings:

| Context | Example | Meaning |
|---------|---------|---------|
| Logical operator | `if x and y then` | Boolean AND of two conditions |
| Function parameters | `with a number called x and a number called y` | Separates parameter declarations |
| Function arguments | `'add' of 3 and 5` | Separates argument values |
| Subject list terminator | `x, y, and z are true` | Final item in comma-separated list before `are` |

**Disambiguation:**
- When `and` appears after a comma and before `are`, it's a list terminator
- When `and` appears between two conditions (no comma), it's a logical operator
- When `and` follows `with`/`of`/`to`/`on`, it separates arguments

### Reserved Aliases

A few alternate spellings are also reserved because the compiler recognizes them as aliases for canonical keywords:

| Alias | Canonical keyword | Context |
|-------|-------------------|---------|
| `ms` | `milliseconds` | Time duration units (`Wait 500 ms.`) |
| `message` | `text` | Type name (`a message called ...` is treated as `text`) |
| `string` | `text` | Type name (already listed in the type synonyms) |

These cannot be used as variable names. The diagnostic names the spelling you wrote and notes which canonical keyword it aliases — so `a number called ms is ...` reports `'ms'` as an alternate spelling of `'milliseconds'`, not the internal canonical name.

Every keyword listed in the tables above is likewise reserved as a variable name. Two that are easy to hit by accident are worth calling out: the flag-schema keyword **`flag`** (`a flag called ...`) and the property keyword **`empty`** (`x's empty`). Writing `a number called flag is 1.` or `a number called empty is 1.` is rejected with the same "reserved keyword" diagnostic. (As with any reserved word, you can still quote the name — `'flag'`, `'empty'` — if you genuinely need it.)

### Two classes of special word

Not every word with a special meaning is reserved. Vox distinguishes:

- **Reserved keywords** — banned as bare names everywhere, because they
  would be ambiguous anywhere: statement starters, operators (`times`,
  `add`), type names, connectors.
- **Contextual keywords** — claimed only in the position where they mean
  something, and ordinary identifiers everywhere else: `start`/`begin`/
  `stop`/`finish` for timers, `send` for signals, `waiting` in
  `without waiting`, `available` in `is available`, the things words, the
  property word `name`, and the property word `count` —
  claimed after a possessive marker and in the `the argument count` /
  `the environment variable count` phrases, so
  `a number called count is 0.` compiles while `arguments's count` keeps
  its meaning. The same treatment extends to the whole
  possessive/phrase family: `capacity` (also the `with capacity N` /
  `of capacity N` buffer phrase), `raw`, `all` (also the
  `all the numbers from/between …` range), `first`, `last`, `second`
  (also the `Wait 1 second.` unit — `Set second to 1. Wait second seconds.`
  compiles and waits one second), `size` and its synonym `length` (also
  `with size N` and `N bytes in size`), and `version` (the
  `Library <name> version "…"` and `see <lib> version "…"` headers). Each
  is a bare variable name everywhere except its one fixed grammatical
  position; `arguments's first` and `a number called first is 0.` both
  work in the same program.

The test for which class a word belongs in: if every position where the
word means something is grammatically identifiable, it is contextual; only
a word that would be ambiguous in ordinary positions is reserved.

### Contextual Keywords (Things)

Three words the things feature claims only inside their construct, and
treats as ordinary identifiers everywhere else — the same treatment
`send`/`begin`/`stop` get for timers. None of them is a reserved variable
name, so `a number called thing is 1.` and `To do.` (a function named
`do`) both compile.

| Word | Claimed in | Elsewhere |
|------|-----------|-----------|
| `thing` | `A thing called <name> has ...` (a definition) | ordinary identifier |
| `has` | the verb of a thing definition | ordinary identifier |
| `do` | `To do the <type>'s <member>` (a member definition) | ordinary identifier |

A fourth, **`the`**, gains a second reading in this company: in `To do
the point's 'placed at'` it pairs with a *known identifier* (the type),
where `a point's 'placed at'` calls a maker that brings a new point into
being. See the [article rule](#the-article-rule).

---

## Examples

### Hello World

```
Print "Hello, World!".
```

### Variables and Arithmetic

```
a number called x is 3.
a number called y is 5.
Print the x add the y.
```

### Function Definition and Call

```
To 'add numbers' with a number called x and a number called y. Return a number, the x add y.

Print 'add numbers' of 3 and 5.
```

### Counting Loop

```
Set the number called counter to 1.
While the counter is less than 10, print the counter, increment the counter.
```

### FizzBuzz

```
To 'check divisibility' with a number called divisor and a number called dividend. Return a boolean, the divisor modulo the dividend is 0.

For each number from 1 to 15, print the number, but if 'check divisibility' of the number and 6 is true print "fizz buzz" but if 'check divisibility' of the number and 2 is true print "fizz" but if 'check divisibility' of the number and 3 is true print "buzz".
```

---

## Libraries and Imports

### The `see` Keyword

`see` pulls in code from another file. It has two distinct jobs:

- **`see "<path>.vox".`** — include another Vox source file. This works today:
  the file is parsed as part of your program, so its functions become callable
  with no linking step. It is how you split a program across files.
- **`see '<lib>' version "<ver>" from "<path>.lib".`** — consume a shared
  library through its `.lib` interface. This is the library path; see
  [Shared libraries](#shared-libraries) below.

```vox fragment
see "./utils.vox".
see mathkit version "1.0" from "./libmathkit.lib".
```

There is exactly **one** library form. Three other shapes — `see "./path.so".`,
`see "lib" version "1.0" from "./path.so".`, and `see "./path.so" for "lib"
version "1.0".` — point `see` at a `.so` directly. A `.so` is binary ELF:
it carries mangled symbol *names* but no Vox type information, so the compiler
cannot check a call against it. All three are refused: `see` of a `.so`
errors and directs you to the `.lib`, and the `see ... for ...` form has its
own diagnostic — both name the canonical form `see '<lib>' version "<x.y>" from
"<path>.lib".`.

**Search paths.** `see` resolves the path by its shape:

- `./…` or `../…` — resolved against the directory of the file that contains
  the `see` statement, and only there.
- `/…` — used as-is (absolute).
- a bare name — `/usr/share/vox/lib/<name>` is checked **first**, and only if
  that does not exist does it fall back to the containing file's directory.
  Watch this: a bare `see "utils.vox".` can silently pick up a system file in
  preference to the one sitting next to your source. Write `./utils.vox` when
  you mean the local one.

Those three shapes describe a `.vox` source include. A `.lib` path resolves
differently: relative or bare, it is tried against the containing file's
directory first and then each `--lib-path` directory, and its `Location` `.so`
against the `.lib`'s own directory first and then `--lib-path`; absolute paths
are used as-is. `--lib-path` is not consulted for a `.vox` include at all; for
`--link` it only passes search paths to the linker (`-L`). See
[Consuming a library](#consuming-a-library).

**Circular includes.** The compiler tracks files already seen and skips a
`see` that would re-enter one.

### Shared libraries

A shared library is a `.so` you build from Vox and call from Vox — or from C,
Rust, or any other host. The chain is:

**`.vox` → `see` a `.lib` → `Location` → `.so`**

The `.lib` is the typed interface (the `.h` equivalent); the `.so` it points
at is linked, never read for types. This section covers writing one, the `.lib`
file, consuming one, putting several libraries in one `.so`, and the symbol
names a non-Vox caller needs.

> **What runs today.** The whole path runs: building a library with `--shared`
> produces a self-contained `.so` plus its `.lib` interface, `see` of a `.lib`
> consumes it from Vox, export names are mangled, and multi-input `--shared`
> links several libraries (and several versions of one library) into one `.so`.
> A foreign host can also call the `.so` directly — see
> [Calling a library from a non-Vox host](#calling-a-library-from-a-non-vox-host).

#### Writing a library

Add a `Library` declaration at the top of a `.vox` file, then build with
`--shared`:

```
Library mathkit version "1.0".

To 'add two numbers' with a number called x and a number called y. Return a number, x add y.

To greet.
  Print "hello from mathkit".
```

```bash
vox mathkit_lib.vox --shared -o libmathkit.so
```

That writes two files: `libmathkit.so`, and `libmathkit.lib` beside it — the
typed interface a Vox consumer `see`s, described in
[The `.lib` file](#the-lib-file) below. The `.lib` name comes from `-o`, so the
pair always travels together.

This compiles to a self-contained shared object. It carries its own copy of
the Vox runtime, so it is loadable from C, Rust, or any other host — not only
from Vox. The runtime is position-independent, so a library may use the full
core language — arithmetic, printing, buffers, files, floats, lists, maps —
not a runtime-free subset. Only the library's own function definitions are
exported; every runtime symbol is kept out of the dynamic symbol table.

Verify what you built:

```bash
$ nm -D --defined-only libmathkit.so
000000000000072c T mathkit_1_0_add_two_numbers
000000000000076c T mathkit_1_0_greet
$ readelf -r libmathkit.so
There are no relocations in this file.
```

Two exports and nothing else leaked; zero absolute relocations, so the whole
object is position-independent. The labels are the mangled
`<library>_<version>_<func>` form — `mathkit_1_0_add_two_numbers` and
`mathkit_1_0_greet` — so two versions of one library can live in one `.so`
without colliding; see [Mangling](#mangling) below.

**A library needs an identity.** The `Library` declaration gives the library
the name and version that drive mangling and the `.lib`. A `--shared` build
with no `Library` line has no identity and is rejected — add the declaration.

**Top-level statements are rejected.** A shared library has no entry point, so
a top-level executable statement (`Print`, assignment, `If`, a bare function
call, …) would be silently dropped. The compiler rejects it instead:

```text
error: Top-level print statement is not allowed in a shared library: only
function definitions, 'Library', and 'see' may appear at the top level.
```

Only function definitions, `Library`, and `see` may appear at the top level of
a `--shared` compile. Put any work you need inside a function.

**An empty library is rejected.** A `--shared` compile with no function
definitions exports nothing, which would yield a malformed version script and
an opaque linker error. The compiler rejects it instead: a shared library must
export at least one function.

#### The `.lib` file

The `.lib` is the public interface to a library: its name and version, where
its `.so` is, and a table of contents of every exported function's signature.
It is what a consumer `see`s, and the only place Vox types live — ELF carries
mangled names but no types, so the `.lib` is the type source. A `--shared`
build writes `<output-stem>.lib` beside the `.so`, one `Library` block per
input. The `.lib` is a declared output like the `.so`, derived from the same
`-o`: a rebuild overwrites it in place, so an edit-build loop needs no manual
cleanup and anything hand-edited into a `.lib` is lost. The pair is written
together, so a fresh `.so` never lands beside a stale `.lib`. The format:

```
Library mathkit version "1.0".
Location "./libmathkit.so".

Table of Contents:
    To 'add two numbers' with a number called x and a number called y, returning a number.
    To greet.
```

- **`Library '<name>' version "<ver>".`** — the block's identity. Several
  `Library` blocks may appear in one `.lib`, each with its own `Location`;
  parsing runs to EOF, and a `Library` line starts a new block.
- **`Location "<path>".`** — where the `.so` is. It resolves relative to the
  `.lib` first, then `--lib-path`, then error. Absolute paths are honoured but
  never generated, so a `.lib` is portable.
- **`Table of Contents:`** — one line per exported function, in the same
  11-type vocabulary as Vox source, in EITHER position: `number`, `float`,
  `text`, `boolean`, `list`, `map`, `buffer`, `file`, `time`, `timer`,
  `value`; anything else is an error naming the unsupported type. `void`
  isn't a spelling — a function returning nothing omits the `, returning`
  clause entirely — and neither is `unknown`, the compiler's own internal
  placeholder for an untyped parameter. A user-defined thing has no noun
  here either, so a `--shared` build refuses an export that takes or returns
  one — see [`.lib` export of a thing is not yet supported](#lib-export-of-a-thing-is-not-yet-supported).
- A `list` may optionally carry its element type: `a list of text called
  out`, `returning a list of text`. This is compiler-inferred, not author-
  declared — Vox source has no generic/typed-collection syntax, so a library
  author still just writes `a list called out`; a `--shared` build scans the
  exported function's own body and, when every appended/returned element
  provably agrees on one type, writes `list of <type>` for you. Disagreement
  or no evidence emits plain untyped `list`, same as always. `map`'s value
  type isn't carried this way; `map` stays element-untyped in both
  positions.
- **`, returning a <type>`** exists only in `.lib` files. Vox source declares
  return types in the body (`Return a number, x.`), which a bodiless `.lib`
  declaration has no room for. No `returning` clause means the function
  returns nothing — which is also why a list's element type only shows up in
  the `.lib` when the exporting function has a *declared* return type
  (`Return a list, out.`) in the first place; a bare `Return out.` records no
  return type at all, list-element-typing included.

A `.lib` is lexed with the Vox lexer but parsed by a dedicated parser, so it
cannot carry executable statements — only the interface above.

#### Consuming a library

```
see mathkit version "1.0" from "./libmathkit.lib".

a number called sum is 'add two numbers' of 3 and 4.
Print the sum.
```

```bash
$ vox mathkit_consumer.vox -o consumer
$ ./consumer
7
```

That is the whole consumer build — no `--link`, no `-l`, no `-L`. The `see`
does the linking, because the `.lib` says where the `.so` is.

`see` of a `.lib` is the consumption path. The compiler:

1. Resolves the `.lib` (relative to the source, then `--lib-path`).
2. Parses it and selects the block matching name **and** version.
3. Resolves `Location` relative to the `.lib`, then `--lib-path`.
4. **Verifies against the `.so`'s dynamic symbol table** — every mangled name
   the `.lib` promises must exist in the `.so`. This is the staleness check: a
   `.lib` that lies about a function is a compile error, not a runtime crash.
5. Registers the signatures, so calls type-check like any other function.
6. Emits `extern <mangled>` for each used function and adds the `.so` and an
   `-rpath` to the link line.

The `-rpath` in step 6 is the directory the `.so` was found in, recorded as an
absolute `RUNPATH`. So the program finds its library where it stood at build
time; move the `.so` afterwards and the loader will not find it, unless
`LD_LIBRARY_PATH` points at the new directory.

Each failure is its own diagnostic naming the file and what was expected:
missing `.lib`; no such library in it; **version mismatch, listing the
versions the `.lib` does offer**; missing `.so` at `Location`; symbol absent
from the `.so` (the stale-`.lib` case — it names the symbol); arity or type
mismatch at the call site; and reading the *result* of an entry that has no
`, returning` clause, which returns nothing, so there is no value to read —
call it as a statement instead.

The stale-`.lib` case is the one you meet by hand-editing a `.lib` or by
rebuilding a library with different exports:

```text
Error: the .lib entry 'To 'ghostgreet' ...' promises the symbol
'mathkit_1_0_ghostgreet', but 'libmathkit.so' does not export it (not in
.dynsym).
The .lib is stale: it does not match the library binary. Rebuild the library
with `vox --shared` to regenerate the pair.
```

The worked example set in [`examples/`](examples) shows the workflow:
`mathkit_lib.vox` is the library and `mathkit_consumer.vox` is the Vox consumer
above. A foreign caller — C, Rust, or assembly linking the `.so` directly — is
shown in [Calling a library from a non-Vox host](#calling-a-library-from-a-non-vox-host)
below.

#### Several libraries in one `.so`

`vox a.vox b.vox --shared -o lib.so` links several libraries into one `.so` in
a single step — you cannot append to a linked `.so`, so one link step is the
only way to combine them. The sources are parsed independently and then
compiled into one unit, so the runtime is included once and shared by every
library in the `.so`.

The reason this exists is **backwards compatibility**: two *versions* of the
same library can live in one `.so`, kept apart by mangling. A consumer who
upgrades the library keeps calling `mathkit_1_0_add_two_numbers` after
`mathkit_2_0_add_two_numbers` ships beside it, with no recompile — both symbols
are present and independently callable. That version isolation is why the
whole design looks the way it does, and it is the case to keep in mind when
the rest of it seems elaborate.

Duplicate `<library, version>` pairs across inputs are rejected with both
filenames. Multi-input is `--shared` only; it is rejected for executable
builds, where the semantics would be ambiguous.

#### Mangling

Every exported function is mangled to a single flat label:

```text
<library>_<version>_<func>
```

`mathkit` + `1.0` + `add two numbers` → `mathkit_1_0_add_two_numbers`. Each
component is sanitized by mapping every character outside `[A-Za-z0-9_]` to `_`.
The leading-digit prefix (a digit is not a legal C identifier start) applies
only to the **library** component, which begins the symbol; the version and
function components are interior and take the sanitizer alone, so the version
`1.0` appears as `1_0` (the `.` becomes a single `_`, no prefix — applying the
prefix per component would yield `mathkit__1_0_add_two_numbers`, a double
underscore). A
non-Vox caller — C, Rust, anything that links the `.so` — needs this mangled
name to call the function at all, which is why the scheme is documented here
and not only in [docs/SYMBOL_MANGLING.md](docs/SYMBOL_MANGLING.md) (the full
rules, including what is and is not mangled). There is no unmangled alias: an
alias would defeat the version isolation above.

**Runtime state is not mangled** — a deliberate non-goal. The runtime is
emitted once per `.so` and shared by every library in it (one resource table,
one `.fini_array`, one idempotent cleanup). Cross-`.so` isolation holds because
each `.so` carries its own runtime and the version script hides it. Only
function labels are mangled. See [docs/SYMBOL_MANGLING.md](docs/SYMBOL_MANGLING.md).

#### Calling a library from a non-Vox host

A shared library is a plain `.so`, so any caller that can link one can use it —
C, Rust, or hand-written assembly. This is also the case the mangling scheme
above exists for: the foreign caller must name the export by its mangled label.
Build the example library, then call it from a small assembly driver (nasm + ld
only — the tools Vox already requires). Run these from the `examples/` directory:

```bash
$ vox mathkit_lib.vox --shared -o libmathkit.so
$ nm -D --defined-only libmathkit.so
000000000000072c T mathkit_1_0_add_two_numbers
000000000000076c T mathkit_1_0_greet
```

```nasm
; mathkit_driver.asm — link against libmathkit.so and call its exports.
global _start
extern mathkit_1_0_add_two_numbers
extern mathkit_1_0_greet

section .text
_start:
    and rsp, -16            ; 16-byte stack alignment for the Vox prologue
    mov rdi, 3
    mov rsi, 4
    call mathkit_1_0_add_two_numbers  ; mathkit_1_0_add_two_numbers(3, 4) -> 7, in rax
    cmp rax, 7
    jne .fail
    call mathkit_1_0_greet            ; prints "hello from mathkit"
    mov rax, 60             ; SYS_exit
    xor rdi, rdi
    syscall
.fail:
    mov rax, 60
    mov rdi, 2
    syscall
```

```bash
$ nasm -f elf64 -o mathkit_driver.o mathkit_driver.asm
$ ld -dynamic-linker /lib64/ld-linux-x86-64.so.2 -rpath '$ORIGIN' \
      -o mathkit_driver mathkit_driver.o -L. -lmathkit
$ ./mathkit_driver
hello from mathkit
```

The driver declares the exports `extern` and calls them with the Vox calling
convention: integer arguments in `rdi`, `rsi`, … and the result in `rax`.
`-rpath '$ORIGIN'` makes it find `libmathkit.so` in its own directory, so the
pair is relocatable. (The `.asm` extension is gitignored under `examples/`
because the compiler emits `.asm` there as output, so this driver is shown here
rather than tracked as a file — copy it out to run it.) The `extern` names are
the mangled labels `mathkit_1_0_add_two_numbers` and `mathkit_1_0_greet`,
matching what `nm -D` showed above.

#### Linking an executable against a `.so` directly

If the library has a `.lib`, you do not need this: `see` it, which registers
its signatures *and* links its `.so`. `--link` is for a `.so` with no `.lib` —
foreign, or hand-built — where the compiler knows no Vox signatures and only
the linker is involved.

`--link` puts a built `.so` on the link line of an executable. It takes the
library's soname *stem* — the part between `lib` and `.so` — so a file named
`libmath.so` is linked as `--link math`:

```bash
$ vox hello.vox --link math --lib-path ./libs -o hello
$ readelf -d hello | grep -E 'NEEDED|RUNPATH'
 0x0000000000000001 (NEEDED)             Shared library: [libmath.so]
 0x000000000000001d (RUNPATH)            Library runpath: [./libs]
```

Because such an executable needs the dynamic loader at runtime, `--link`
automatically adds the loader (`/lib64/ld-linux-x86-64.so.2`) and an `-rpath`
for each `--lib-path` — but only when libraries are actually linked, so a plain
`vox hello.vox` build stays a flat static binary with no loader dependency.

`--link` alone does not teach the compiler a library's function signatures, so
it does not let Vox source call the library's functions — that is what `see` of
a `.lib` does (it registers the signatures *and* adds the `.so` to the link
line). `--link` is for the case where the program already references the
symbols another way, or for a non-Vox driver assembled by hand — the
[Calling a library from a non-Vox host](#calling-a-library-from-a-non-vox-host)
driver above is exactly that, linked with `ld` rather than `--link`.

---

## Compiler Usage

### Basic Usage (Compiler Invocation)

```bash
vox <source.vox> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--emit-asm` | Output assembly only (don't assemble/link) |
| `--run` | Compile and run the program |
| `--shared` | Build a shared library (.so) instead of executable |
| `--link <libs>` | Link against shared libraries by soname stem (comma-separated). A Vox library with a `.lib` is linked by `see`ing it instead |
| `--lib-path <paths>` | Additional library search paths (comma-separated) |
| `-o <file>` | Output file name |
| `-v`, `--verbose` | Verbose output |

### Examples

```bash
# Compile and run
vox hello.vox --run

# Build executable with custom name
vox hello.vox -o myprogram

# Build shared library
vox math.vox --shared -o libmath.so

# Consume a Vox library through its .lib (the `see` does the linking)
vox mathkit_consumer.vox -o consumer

# Link an executable against a .so that has no .lib (stem, not the lib prefix)
vox main.vox --link math --lib-path ./libs
```

---

## Grammar Summary

```ebnf
program     ::= statement*
statement   ::= print_stmt | var_decl | assignment | if_stmt | while_stmt
              | for_stmt | func_def | thing_def | member_def | increment | decrement
              | break | continue | append_stmt

var_decl    ::= ("a" | "an") type "called" name "is" expr "."
              | ("Set" | "Create") "the"? type? "called"? name "to" expr "."

assignment  ::= "the" name "is" expr "."

append_stmt ::= "append" expr "to" name "."
              | "append" "each" name "from" expr ("treating" expr "as" expr)? "to" name "."

func_def    ::= "To" identifier (("with" | "of") params)? "." "Return" "a" type "," expr "."
params      ::= param ("and" param)*
param       ::= "a" type "called" name

func_call   ::= identifier ("of" | "with" | "to" | "on") args
args        ::= arg_clause ("and" arg_clause)*
arg_clause  ::= loop_expansion | expr

thing_def   ::= "A" "thing" "called" name "has" thing_entry ("," thing_entry)* "."
thing_entry ::= field_decl | member_decl
field_decl  ::= "a" type "called" name ("is" literal)?
member_decl ::= "a" "function" "called" name

member_def  ::= "To" "do" "the" name "'s" name (("," ("with" | "of"))? params)? "."
                body "Return" "a" name "," expr "."

if_stmt     ::= ("If" | "When") condition "then" "," block
                ("but if" condition "then" "," block)*
                ("otherwise" | "else")? ","? block? "."

while_stmt  ::= "While" condition "," block "."

for_stmt    ::= "For each" name "from" expr "to" expr "," block "."
              | "For each" name "in" expr "," block "."

print_stmt  ::= "Print" expr ("," "but if" condition "print" expr)* "."
              | "Print" "each" name "from" expr ("treating" expr "as" expr)?
                ("," "but if" condition "print" expr)* "."
              | "Print" identifier "of" "each" name "from" expr ("treating" expr "as" expr)?
                ("," "but if" condition "print" expr)* "."

loop_expansion ::= "each" name "from" expr ("treating" expr "as" expr)?

condition   ::= expr
expr        ::= or_expr
or_expr     ::= and_expr ("or" and_expr)*
and_expr    ::= not_expr ("and" not_expr)*
not_expr    ::= "not" not_expr | comparison
comparison  ::= additive (comp_op additive)?
additive    ::= multiplicative ((add | subtract) multiplicative)*
multiplicative ::= primary ((multiply | times | divide | modulo) primary)*
primary     ::= literal | identifier | func_call | "(" expr ")"

type        ::= "number" | "float" | "text" | "boolean" | "list"
              | "map" | "buffer" | "file" | "time" | "timer" | "value"
              | <user-defined thing name>   ; defined by `thing_def`
name        ::= identifier
identifier  ::= bare | quoted          ; see Naming Rules for the lexical rule
literal     ::= string | number | "true" | "false" | "nothing"
string      ::= '"' ... '"'            ; a string literal is data, never a name
```
