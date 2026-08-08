# Vox Language Specification

**Version 0.2.0**

This document defines the syntax and semantics of Vox (sentence based code).

---

## Table of Contents

1. [Basics](#basics)
2. [Types](#types)
3. [Variables](#variables)
4. [Names and strings](#names-and-strings)
5. [Functions](#functions)
6. [Expressions](#expressions)
7. [Control Flow](#control-flow)
8. [Lists and Collections](#lists-and-collections)
9. [Input/Output](#inputoutput)
10. [File I/O](#file-io)
11. [Directories, Mounting, and Process Control](#directories-mounting-and-process-control)
12. [Time and Timers](#time-and-timers)
13. [Command-Line Arguments](#command-line-arguments)
14. [Environment Variables](#environment-variables)
15. [Operators](#operators)
16. [Keywords](#keywords)
17. [Examples](#examples)
18. [Libraries and Imports](#libraries-and-imports)
19. [Compiler Usage](#compiler-usage)
20. [Grammar Summary](#grammar-summary)

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

Blank lines (paragraph breaks) can be used freely to organize code into logical sections. They are optional and have no effect on program execution.

```
print "Section 1".

print "Section 2".
```

**Note:** Function definitions are typically followed by a blank line to visually separate them from other code, but this is a style convention, not a requirement.

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

1. **A period closes the most recently opened clause** — the innermost one currently open (`if`, `on error`, `for`, `while`, `repeat`), and only that one. This is why the nested `if` example above works: its period closes the `if`, not the `while`.
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

A blank line placed **after a comma** (mid-sentence, more actions still to come) is the one exception — it is still just visual spacing there, since the sentence is explicitly still open:

```
(Safe: this blank line follows a comma, so it stays cosmetic)
While retries is less than 3,
    print "attempt {retries}",

    increment retries.
```

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

### Conditional Branching with `but if`

The `but if` clause allows conditional output within loops. It's available in both `for each` loops and loop expansion (`print each`).

```
(FizzBuzz example - print number, but override with word if divisible)
print each number from 1 to 15,
    but if the number modulo 6 is equal to 0 print "fizzbuzz",
    but if the number modulo 2 is equal to 0 print "fizz",
    but if the number modulo 3 is equal to 0 print "buzz".

(Simple even/odd labeling)
print each number from 1 to 10,
    but if the number modulo 2 is equal to 0 print "even".

(With for-each loop)
For each number from 1 to 15,
  print the number,
    but if divisible of the number and 3 is true print "divisible by 3".
```

**Syntax:** `print each <var> from <collection>, but if <condition> print <value>, but if <condition> print <value>.`

**How it works:**
1. The default action is to print the loop variable
2. Each `but if` clause is checked in order
3. If a condition is true, that value is printed instead
4. If no conditions match, the default value is printed

**Key points:**
- Conditions are checked in order - first match wins
- Multiple `but if` clauses can be chained
- Works with both ranges and collections
- The loop variable (`the number`) is available in conditions

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
process of each file from files treating "-" as "/dev/stdin".
```

**Syntax:** `... each <var> from <collection> treating <match> as <replacement>, ...`

If the loop variable equals `<match>`, it's replaced with `<replacement>` for that iteration.

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

### Assignment (Existing Variable)

Use `the` to reference an existing variable:

```
the x is 10.
the counter is the counter add 1.
```

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

Before 0.3.0, a double-quoted token was *both* a string literal and an
identifier, decided by position. That single overload is the root of a family
of silent wrong answers. This is the one that decided the change:

```vox fragment
a number called "x" is "get five".
print x.                              (prints: 4198480)
```

The author meant to call the function `get five` and store its result in `x`.
But `"get five"` in expression position was read as a string literal — a
pointer to the function's code — and `x` quietly received that pointer as a
number. A function pointer, printed as a number, silently. No error, no
warning; the program runs and gives a wrong answer that looks like data.

That is what one token meaning two things costs. So in 0.3.0 the two are
split: `"..."` is a string literal everywhere, and a name is a bare or
single-quoted identifier. The program above is now a compile error — `is
"get five"` rejects the string in identifier position and points you at
`'get five'`. The cost is that every program written before 0.3.0 must be
migrated; the payoff is that this class of silent wrong answer is gone.

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

- Variables declared at top level are global and can be used inside functions.
- Variables declared inside a function are local to that function and are not available at top level.
- Referencing an unknown variable inside a function is a compile-time error.

### Parameter and Local Types (v0.1.16)

Parameters may use any variable type, including `buffer`, `list`, `map`,
and `file` - and a typed parameter supports the same properties and
operations as a top-level variable of that type. A parameter (or return
type) may also be `value`, the dynamic type whose runtime tag travels with
its payload across the call (a map rides this as payload + tag 5); see
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
  access; list parameters support `'s length`/element access; file
  parameters support file properties.
- Buffers declared **inside** a function body work with every
  initializer form, including format strings (`is " {devname}\n"`).
- A function call's declared return type is tracked through
  assignment: reassigning an existing variable from a call
  (`the label is classify of n.`) preserves the correct type.

(All three of the above were fixed in v0.1.16 - in earlier versions,
buffer-typed parameters and function-local buffer declarations with
initializers were rejected by the analyzer, and reassignment from a
function call silently corrupted the variable's tracked type.)

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
<condition> and <condition>    ; true if both conditions are true
<condition> or <condition>     ; true if either condition is true
not <condition>                ; true if condition is false
```

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
A value whose type it cannot statically prove — for example the result of a
function with an undeclared return type, or any other opaque expression —
widens the list to mixed, so the element is always read back as what it
is rather than silently reinterpreted:

```
To five with a number called x. Return x add 1.
a list called items is [].
append hello to items.
append five of 4 to items.
print element 1 of items.   (prints: hello)
print element 2 of items.   (prints: 5)
```

A function result whose return type **is** declared (e.g. `Return a text,
"hi".`) is statically known, so it is tagged with that type at the write
and widens the list only because its type differs from the other elements.

Residual limitation: for a genuinely opaque value (no declared return
type), the slot's own tag may still be a conservative `TAG_INTEGER` guess
until runtime tag propagation arrives in stage 1d; the list still widens
and reads dispatch on tags, so the value prints correctly when it really
is a number. See `docs/COLLECTIONS_ROADMAP.md` for the roadmap.

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
on error print "cyclic".    (prints: [[...]] then cyclic)
```

Two limitations remain for this stage. Extracting a child with `element N
of` yields a *reference* to the child list, not a copy: if the parent is
later grown by appending enough elements to force a reallocation, a child
extracted before that reallocation may point at freed memory. Extract a
child after the parent has finished growing, or copy it element-by-element.
And the *expression* form of format interpolation — `print "{element 2 of
nested}"` — has no runtime-tag dispatch, so a nested list does not render
there; use the *variable* form `print "{nested}"` (or `print element 2 of
nested.`) instead. See `docs/COLLECTIONS_ROADMAP.md` for the roadmap.

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
returned pointer is stored back into the variable automatically:

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

A missing key does not crash: the lookup yields 0 and sets the error
flag, so an `on error` handler can react. Note this is deliberately *not*
the same as a key that holds [`nothing`](#nothing-the-absent-value) — "no
such key" stays distinguishable from "the key is set to nothing":

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
slot carries the map tag (5) and a `For each` over such a list types the
loop variable as a map. Two limitations remain for this stage: keys are
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

This is the guard idiom that makes mixed lists programmable: arithmetic on
a mixed element still dispatches statically, so guard it yourself before
operating — `if item is a number, … item add 1 …`. (Automatic guarding is
a later decision; see the roadmap.) To *convert* a value rather than test
it, use the cast expression `<value> as a <type>` — e.g. `item as a number`
or `item as a float` (see Type Casting).

A predicate result is itself a boolean value, so you can store one in a
list — `append item is a number to flags` — and each stored slot carries
the boolean tag, so a later `is a boolean` recognises it.

### Dynamic Values (`value`)

A mixed-list element keeps its tag while it stays in the list, but the
moment you pass it to a function the tag used to be lost — parameters are
statically typed, so a mixed element passed `as a number` was reinterpreted
and one passed `as a text` was dereferenced as a pointer. The `value` type
fixes this: it is a declared dynamic type that carries its runtime tag
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

**A `value` is not usable in arithmetic without checking its type first.**
Because a `value` might hold a string or a decimal, the compiler rejects
bare arithmetic on it and points you at the predicate idiom:

```
To bump with a value called v. Return a number, v add 1.
(compile error: Cannot use a value v in arithmetic; check its type with
 'is a number'/'is a text' first.)
```

Guard it first — `if v is a number, … v add 1 …` — or cast it with
`v as a number` (see Type Casting). (Full flow-sensitive dispatch — where a
guard narrows the type *inside* the branch so `v add 1` just works — is a
later decision; see the roadmap.)

**Recursion with `value` works.** A `value` parameter threads its tag
through every frame, so a recursive walker over mixed data classifies
correctly at any depth. `value` parameters compose: a `value` passed
straight to another `value` function round-trips its tag.

**One limitation to know.** A *conditional* `value` return — using the
*factorial pattern* (`If ... return a value, <expr>. Otherwise ...`) inside
a function whose `To` line has no `Return` — does not track the return
type, so the value would print as a number. Use the single-expression
`Return a value, <expr>.` form on the `To` line for `value` returns.
Conditional `value` *parameters* (the factorial pattern with a void return)
work fine. The internal ABI that carries the tag is documented in
`docs/abi_value.md`; the roadmap context is in
`docs/COLLECTIONS_ROADMAP.md` (stage 1d).

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
renders exactly as it does when printed individually: text elements are
quoted (so `["1"]` is distinguishable from `[1]`), booleans as `1`/`0`,
floats and numbers as usual. Empty lists print `[]`. A nested list
element renders recursively with the same rules (see Nested Lists above),
so `[1, [2, 3], "four"]` prints with inner brackets intact. A map element
(or a whole map) renders as `{"key": value, …}` via `_map_print` (see Maps
above). The same rendering appears inside the *variable* form of `{...}`
format interpolation (`print "{xs}"`); the *expression* form (`print
"{element 2 of xs}"`) does not dispatch on a nested element's runtime tag.

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
- Out-of-bounds access sets an error flag and returns 0
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
- **Dynamic growth**: Lists automatically allocate more memory as needed
- **Type tracking**: The first append determines the list's element type for printing
- **Works with any value**: integers, strings, booleans, variables, expressions

**Examples:**

```
(Append integers)
a list called nums is [].
append 10 to nums.
append 20 to nums.

(Append strings)
a list called words is [].
append hello to words.
append world to words.

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

**Variable shadowing:**

Loop variables shadow outer variables with the same name. After the loop, the variable retains the value from the last iteration:

```
a number called x is 100.
print the x.                  (prints 100)

print each x from [1, 2, 3].  (prints 1, 2, 3)

print the x.                  (prints 3 - last iteration value)
```

### Conditional Output with `but if`

Use `but if` to conditionally override output within loops:

```
(Print numbers, but override with words for certain values)
print each number from 1 to 15,
    but if the number modulo 6 is equal to 0 print "fizzbuzz",
    but if the number modulo 2 is equal to 0 print "fizz",
    but if the number modulo 3 is equal to 0 print "buzz".

(Simple even/odd labeling)
print each number from 1 to 10,
    but if the number modulo 2 is equal to 0 print "even".
```

**How it works:**
1. The default action is to print the loop variable
2. Each `but if` clause is checked in order
3. If a condition is true, that value is printed instead
4. If no conditions match, the default value is printed

**Key points:**
- Conditions are checked in order - first match wins
- Multiple `but if` clauses can be chained
- Works with both ranges and collections
- The loop variable is available in conditions

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
process of each file from files treating "-" as "/dev/stdin".
```

**Syntax:** `... each <var> from <collection> treating <match> as <replacement>, ...`

If the loop variable equals `<match>`, it's replaced with `<replacement>` for that iteration.

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

#### Expressions in Format Strings

```
a number called x is 10.
a number called y is 3.
Print "Sum: {x add y}".
Print "Product: {x multiply y}".
Print "Arguments: {arguments's count}".
```

#### Format Strings as Values (v0.1.17)

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

(Before v0.1.17, a format string outside `Print` compiled to a NULL
pointer: it printed as empty and corrupted `execve` argv arrays.)

#### Format Strings Everywhere (v0.1.21)

Every statement that takes a string value accepts a format string:
`write`, buffer `set`/`copy`/`append`, filesystem paths (`Create a
directory called "{base}/{name}"`), `treating` clauses, and function
arguments. All sinks share one name resolver, so special names like
`{arguments's first}` and `{current time's hour}`, format specifiers,
and the `0x`/`0o` hex/octal prefixes render identically whether the
result is printed, written to a file, or built into a buffer.

#### Declarations in Branches (v0.1.21)

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
- Start with 4KB capacity and grow automatically as needed
- No buffer overflows possible - memory expands dynamically
- Automatically freed on program exit

#### Fixed-Size Buffers

```
a buffer called small is 256 bytes in size.
a buffer called large is 8192 bytes in size.
```

**Features:**
- Allocates exactly the specified capacity
- Does NOT grow - reads/writes are silently truncated at capacity
- Useful when you need predictable memory usage
- User programs can check buffer length to detect truncation
- Automatically freed on program exit

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

#### Buffer Append and Copy

Efficiently combine buffers without byte-by-byte loops:

```
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
| `exists` | Whether the file exists | Boolean |

**Example:**
```
open a file for reading called src at "./data.txt".

print src's size.
print src's modified.

If src's size is greater than 1048576 then,
    print "File is larger than 1MB".
```

#### List Properties

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

#### List Element Access

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
- Out-of-bounds access sets an error flag and returns 0
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
- `Read` appends incoming data to the buffer and is best for bulk/stream processing.
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
- Invalid targets (e.g. line past EOF, position < 1, invalid fd) set the error flag

### Writing

Write strings, buffers, or special values to files:

```
Write "Hello, World!" to output.
Write buf to output.
Write a newline to output.
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
- File operation failures

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

Buffers start at 4KB and grow automatically. No size specification needed:

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

```
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

**Alternative keywords:**
- `Start` / `Begin`
- `Stop` / `End` / `Finish`

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

Combine time properties with padded casting for formatted output:

```
Get current time into now.
a text called h is now's hour as text padded to 2.
a text called m is now's minute as text padded to 2.
a text called s is now's second as text padded to 2.

Print the h.
Print ":".
Print the m.
Print ":".
Print the s.
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

### Logical Operators

| Operator | Keyword |
|----------|---------|
| And | `and` |
| Or | `or` |
| Not | `not`, `isn't`, `aren't` |

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

```
see "./utils.vox".
see mathkit version "1.0" from "./libmathkit.lib".
```

There is exactly **one** library form. Earlier syntaxes — `see "./path.so".`,
`see "lib" version "1.0" from "./path.so".`, and `see "./path.so" for "lib"
version "1.0".` — all pointed `see` at a `.so` directly. A `.so` is binary ELF:
it carries mangled symbol *names* but no Vox type information, so the compiler
cannot check a call against it. Those forms are retired: `see` of a `.so`
errors and directs you to the `.lib`, and the `see ... for ...` form has its
own diagnostic — both name the canonical form `see '<lib>' version "<x.y>" from
"<path>.lib".`. `see` of a `.vox` source is unchanged.

**Search paths.** `see` resolves the path by its shape:

- `./…` or `../…` — resolved against the directory of the file that contains
  the `see` statement, and only there.
- `/…` — used as-is (absolute).
- a bare name — `/usr/share/vox/lib/<name>` is checked **first**, and only if
  that does not exist does it fall back to the containing file's directory.
  Watch this: a bare `see "utils.vox".` can silently pick up a system file in
  preference to the one sitting next to your source. Write `./utils.vox` when
  you mean the local one.

`--lib-path` is not consulted by `see` of a `.vox` source; it only passes
search paths to the linker (`-L`) for `--link`. It *is* consulted by `see` of
a `.lib` — both to find the `.lib` and to resolve its `Location` `.so` — see
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
> Every output below is real, captured from this compiler (vox v0.2.0). A
> foreign host can also call the `.so` directly — see
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

This compiles to a self-contained shared object. It carries its own copy of
the Vox runtime, so it is loadable from C, Rust, or any other host — not only
from Vox. The runtime is position-independent, so a library may use the full
core language — arithmetic, printing, buffers, files, floats, lists, maps —
not a runtime-free subset. Only the library's own function definitions are
exported; every runtime symbol is kept out of the dynamic symbol table.

Verify what you built:

```bash
$ nm -D --defined-only libmathkit.so
00000000000005c4 T mathkit_1_0_add_two_numbers
00000000000005f9 T mathkit_1_0_greet
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
input. It will not overwrite a `.lib` that already exists — a repeat
`--shared` build errors and asks you to remove the `.lib` first, then
regenerates the `.so` and `.lib` together, so a rebuild cannot silently
clobber an interface you have pinned or edited. The format:

```
Library mathkit version "1.0".
Location "./libmathkit.so".

Table of Contents:
    To 'add two numbers' with a number called x and a number called y, returning a number.
    greet.
```

- **`Library '<name>' version "<ver>".`** — the block's identity. Several
  `Library` blocks may appear in one `.lib`, each with its own `Location`;
  parsing runs to EOF, and a `Library` line starts a new block.
- **`Location "<path>".`** — where the `.so` is. It resolves relative to the
  `.lib` first, then `--lib-path`, then error. Absolute paths are honoured but
  never generated, so a `.lib` is portable.
- **`Table of Contents:`** — one line per exported function, in the same
  signature vocabulary as Vox source. Parameter and return types are drawn from
  `number`, `text`, `boolean`, `file`, `value`; anything else is an error
  naming the unsupported type.
- **`, returning a <type>`** is new and exists only in `.lib` files. Vox source
  declares return types in the body (`Return a number, x.`), which a bodiless
  `.lib` declaration has no room for.

A `.lib` is lexed with the Vox lexer but parsed by a dedicated parser, so it
cannot carry executable statements — only the interface above.

#### Consuming a library

```
see mathkit version "1.0" from "./libmathkit.lib".

a number called sum is 'add two numbers' of 3 and 4.
Print the sum.
```

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

Each failure is its own diagnostic naming the file and what was expected:
missing `.lib`; no such library in it; **version mismatch, listing the
versions the `.lib` does offer**; missing `.so` at `Location`; symbol absent
from the `.so` (the stale-`.lib` case — it names the symbol); arity or type
mismatch at the call site.

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
00000000000005c4 T mathkit_1_0_add_two_numbers
00000000000005f9 T mathkit_1_0_greet
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

### Basic Usage

```bash
vox <source.vox> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--emit-asm` | Output assembly only (don't assemble/link) |
| `--run` | Compile and run the program |
| `--shared` | Build a shared library (.so) instead of executable |
| `--link <libs>` | Link against shared libraries (comma-separated) |
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

# Link an executable against a built .so (stem, not the lib prefix)
vox main.vox --link math --lib-path ./libs
```

---

## Grammar Summary

```ebnf
program     ::= statement*
statement   ::= print_stmt | var_decl | assignment | if_stmt | while_stmt 
              | for_stmt | func_def | increment | decrement | break | continue
              | append_stmt

var_decl    ::= ("a" | "an") type "called" name "is" expr "."
              | ("Set" | "Create") "the"? type? "called"? name "to" expr "."

assignment  ::= "the" name "is" expr "."

append_stmt ::= "append" expr "to" name "."
              | "append" "each" name "from" expr "to" name ("treating" expr "as" expr)? "."

func_def    ::= "To" identifier (("with" | "of") params)? "." "Return" "a" type "," expr "."
params      ::= param ("and" param)*
param       ::= "a" type "called" name

func_call   ::= identifier ("of" | "with" | "to" | "on") args
args        ::= expr ("and" expr)*

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

expr        ::= or_expr
or_expr     ::= and_expr ("or" and_expr)*
and_expr    ::= comparison ("and" comparison)*
comparison  ::= additive (comp_op additive)?
additive    ::= multiplicative ((add | subtract) multiplicative)*
multiplicative ::= primary ((multiply | divide | modulo) primary)*
primary     ::= literal | identifier | func_call | "(" expr ")"

type        ::= "number" | "float" | "text" | "boolean" | "list"
              | "map" | "buffer" | "file" | "time" | "timer" | "value"
name        ::= identifier
identifier  ::= bare | quoted          ; see Naming Rules for the lexical rule
literal     ::= string | number | "true" | "false" | "nothing"
string      ::= '"' ... '"'            ; a string literal is data, never a name
```
