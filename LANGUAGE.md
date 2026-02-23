# Vox Language Specification

**Version 0.1.5**

This document defines the syntax and semantics of Vox (sentence based code).

---

## Table of Contents

1. [Basics](#basics)
2. [Types](#types)
3. [Variables](#variables)
4. [Functions](#functions)
5. [Expressions](#expressions)
6. [Control Flow](#control-flow)
7. [Lists and Collections](#lists-and-collections)
8. [Input/Output](#inputoutput)
9. [Operators](#operators)
10. [Keywords](#keywords)
11. [Libraries and Imports](#libraries-and-imports)
12. [Compiler Usage](#compiler-usage)
13. [Grammar Summary](#grammar-summary)

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

a number (the counter) called "x" is 5.

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
"process" of each item from mylist, print "done".

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
- `"function" of each X from Y` - call function for each item  
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
    but if "divisible" of the number and 3 is true print "divisible by 3".
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
(Replace "-" with "/dev/stdin" for each filename)
open a file for reading called source at each filename from arguments's all treating "-" as "/dev/stdin",
  read from source into content,
  write content to output,
  close source.

(Print with default value)
print each name from names treating "" as "Anonymous".

(Call function with substitution)
"process" of each file from files treating "-" as "/dev/stdin".
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
| Buffer | `buffer` | Memory block for I/O (dynamic or fixed-size) |
| File | `file` | File descriptor handle (auto-cleaned) |
| Time | `time` | Date/time value (unix timestamp with components) |
| Timer | `timer` | Stopwatch for measuring durations |

---

## Variables

### Declaration with Type

Use `a` or `an` before the type to declare a new variable:

```
a number called "x" is 5.
a text called "name" is "Alice".
a boolean called "flag" is true.
a list called "numbers" is [1, 2, 3].
```

### Declaration with Set/Create

```
Set a number called counter to 1.
Create a text called message to "Hello".
```

### Assignment (Existing Variable)

Use `the` to reference an existing variable:

```
the x is 10.
the counter is the counter add 1.
```

### Naming Rules

- Variable names are enclosed in **quotes** when declared: `called "variableName"`
- When referenced, use the name without quotes: `the x`, `the counter`
- Names can contain spaces: `called "my variable"`

---

## Functions

### Definition

```
To "<function name>" with a <type> called "<param1>" and a <type> called "<param2>". Return a <type>, <expression>.
```

No-parameter functions are also valid:

```
To "show version".
  Print "1.0.0".

To ping.
  Print "pong".
```

**Examples:**
```
To "add numbers" with a number called "x" and a number called "y". Return a number, the x add y.

To "check divisibility" of a number called "divisor" and a number called "dividend". Return a boolean, the divisor modulo the dividend is 0.
```

**Rules:**
- Function name can be quoted (`"add numbers"`) or unquoted single word (`add`)
- Parameters are optional. If present, introduce them with `with` or `of` (both work identically)
- Parameters use `a <type> called "<name>"` syntax (name can be unquoted if single word)
- Multiple parameters joined with `and`
- Return type follows `Return a <type>,`

### Function Scope

- Variables declared at top level are global and can be used inside functions.
- Variables declared inside a function are local to that function and are not available at top level.
- Referencing an unknown variable inside a function is a compile-time error.

### Function Calls

In expressions, use the function name followed by `of`, `to`, `with`, or `on` and arguments:

```
"add numbers" of 3 and 5
"check divisibility" of the number and 6
calculate with x and y
```

**Rules:**
- Function name can be quoted (`"add numbers"`) or unquoted single word (`calculate`)
- For calls with arguments, use `of`, `to`, `with`, or `on`
- Multiple arguments separated by `and`

Calls with no arguments can be written directly:

```
"show version".
ping.
```

### Calling as Statement

```
Print "add numbers" of x and y.
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

**Hex and Binary:**
- Hexadecimal literals use `0x` prefix: `0xFF` equals 255
- Binary literals use `0b` prefix: `0b1010` equals 10
- Character literals use single quotes: `'A'` equals 65

### Variable Reference

- `the x` - references variable named "x"
- `the number` - references loop iterator (inside `for each`)
- `x` - direct identifier reference

### Arithmetic

```
the x add 5
y subtract 3
the a multiply b
total divide 2
x modulo 3
```

Note: `the` is optional before variable names in expressions.

### Comparisons

```
the x is greater than 5
y is less than 10
a is equal to b
x is 0
```

Note: `the` is optional before variable names in comparisons.

### Property Checks

```
the x is even
the y is odd
the z is positive
the n is negative
the value is zero
the list is empty
```

### Logical Operators

```
<condition> and <condition>    ; true if both conditions are true
<condition> or <condition>     ; true if either condition is true
not <condition>                ; true if condition is false
```

### Plural Comparisons with `are`

Test multiple variables against the same value using comma-separated subjects:

```
if x, y, and z are true
if a, b, and c are not false
if "door open", lift_moving, and lift_full are not true
```

**Expansion:**
```
if x, y, and z are true
```
expands internally to:
```
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
```
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

**Examples:**

```
(Float to number - truncates)
a float called "pi" is 3.14159.
a number called "pi truncated" is pi as a number.

(Number to text)
a number called "age" is 25.
a text called "age text" is the age as text.

(Text to number - parsing)
a text called "input" is "123".
a number called "parsed" is the input as a number.

(Boolean to number)
a boolean called "flag" is true.
a number called "flag num" is the flag as a number.

(Inline casting)
Print 3.14159 as a number.
```

**The `in` Keyword:**

The `in` keyword is an alternative to `as` that reads more naturally for unit conversions and durations:

```
(Unit conversions)
a number called "ms" is 5000.
a number called "secs" is the ms in seconds.

(Duration from timer)
Print the timer's duration in seconds.
Print the timer's elapsed in milliseconds.
```

**Formatted Output:**

Numbers can be converted to padded text for display formatting:

```
(Pad to 2 digits - for times like 09:05)
a number called "hour" is 9.
a text called "hour padded" is the hour as text padded to 2.
Print the hour padded.  (prints "09")
```

**Casting Rules:**
- `as a <type>` and `as <type>` are equivalent (article is optional)
- Float to number **truncates** (does not round)
- To round: add 0.5 before casting (`3.7 add 0.5 as a number` → `4`)
- Text to number fails if text is not a valid number (sets error flag)
- Zero is `false`, any non-zero number is `true`
- `in` keyword is preferred for unit/time conversions

---

## Control Flow

### If Statement

```
If <condition> then, <statement>.
```

**With else:**
```
If <condition> then, <statement>. Otherwise, <statement>.
```

**With else-if:**
```
If <condition> then, <statement>. But if <condition> then, <statement>. Otherwise, <statement>.
```

**Sentence consumption rule (important):**
- Each `then,` / `but if ... then,` / `otherwise,` branch consumes actions until the sentence ends.
- Separate multiple actions in a branch with commas.
- Use a period to end the full `if` sentence.
- A period before `but if`/`otherwise` is treated as part of the same if-chain when the chain continues.

```
If ready then, print "a", print "b", print "c".
```

**Alternative keywords:**
- `When` can replace `If`
- `Else` can replace `Otherwise`

### While Loop

```
While <condition>, <statements>.
```

**Single-line example:**
```
While the counter is less than 10, print the counter, increment the counter.
```

**Multi-action loops** are comma-separated actions within one sentence:
 
```
While x is less than 5, print x, increment x, print "looping".
```

**Loops inside functions** work naturally:
```
To "sum" of a number called "n".
  a number called "total" is 0.
  a number called "i" is 1.
  While i is less than or equal to n, total is total add i, i is i add 1.
  Return a number, total.
```

### For Each Loop

**Range-based:**
```
For each number from <start> to <end>, <statement>.
```

**Example:**
```
For each number from 1 to 10, print the number.
```

**Inside the loop:**
- `the number` refers to the current iteration value

**List-based:**
```
For each <variable> in <list>, <statement>.
```

**Example:**
```
a list called "numbers" is [1, 2, 3].
For each n in numbers, print the n.
```

### Loop Control

```
Break.
Continue.
```

### Program Termination

Immediately exit the program with an exit code:

```
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
a list called "numbers" is [1, 2, 3].
a list called "names" is ["Alice", "Bob", "Charlie"].
a list called "mixed" is [1, "two", 3].
a list called "empty" is [].
```

**Key points:**
- Lists are **1-indexed** (like natural language: "the first element", "the second element")
- Lists can contain mixed types
- Empty lists `[]` are allowed
- Lists are allocated on the heap with automatic memory management

### List Properties

Access list properties using the `'s` syntax:

```
a list called "items" is [10, 20, 30].

print items's length.      (prints 3)
print items's size.        (same as length)
print items's first.       (prints 10)
print items's last.        (prints 30)
print items's empty.       (prints false)
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
a list called "numbers" is [10, 20, 30].

Print element 1 of numbers.   (prints 10)
Print element 2 of numbers.   (prints 20)
Print numbers's first.        (prints 10)
Print numbers's last.         (prints 30)

(Using variable index)
a number called "i" is 2.
Print element i of numbers.   (prints 20)
```

**Bounds checking:**
- Out-of-bounds access sets an error flag and returns 0
- Errors can be caught with `On error`

```
a list called "items" is [1, 2, 3].
a number called "bad" is element 100 of items.
On error print "Cannot access element 100 - out of bounds!".
```

### Appending to Lists

Add elements to the end of a list using the `append` keyword:

```
a list called "numbers" is [1, 2, 3].
append 4 to numbers.
append 5 to numbers.
print numbers's length.       (prints 5)
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
a list called "nums" is [].
append 10 to nums.
append 20 to nums.

(Append strings)
a list called "words" is [].
append "hello" to words.
append "world" to words.

(Append from variables)
a number called "x" is 42.
append x to nums.

(Append in loops)
a list called "squares" is [].
a number called "i" is 1.
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
"double" of each n from [1, 2, 3].

(Append each item from a collection)
a list called "source" is [1, 2, 3].
a list called "dest" is [].
append each x from source to dest.
```

**Syntax:** `<action> each <variable> from <collection>`

**Supported collections:**
- **Lists**: `[1, 2, 3]`, any list variable
- **Ranges**: `1 to 10`, `start to end` (inclusive)
- **Arguments**: `arguments's all`

**Works with any action:**
- `print each X from Y` - print each item
- `"function" of each X from Y` - call function for each item
- `append each X from Y to Z` - append each item to a list
- `open ... at each X from Y` - open file for each path

**Examples:**

```
(Print each from list)
print each n from [10, 20, 30].

(Print each from range)
print each n from 1 to 5.

(Function call with loop expansion)
To "double" of a number called "x".
  Return a number, x multiply 2.

print "double" of each n from [1, 2, 3].

(Append from range)
a list called "range_list" is [].
append each n from 1 to 5 to range_list.

(Append from list)
a list called "source" is [10, 20, 30].
a list called "dest" is [].
append each x from source to dest.

(Empty collection - does nothing)
print each n from [].
```

**Variable shadowing:**

Loop variables shadow outer variables with the same name. After the loop, the variable retains the value from the last iteration:

```
a number called "x" is 100.
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
(Replace "-" with "/dev/stdin" for each filename)
open a file for reading called source at each filename from arguments's all treating "-" as "/dev/stdin",
  read from source into content,
  write content to output,
  close source.

(Print with default value)
print each name from names treating "" as "Anonymous".

(Call function with substitution)
"process" of each file from files treating "-" as "/dev/stdin".
```

**Syntax:** `... each <var> from <collection> treating <match> as <replacement>, ...`

If the loop variable equals `<match>`, it's replaced with `<replacement>` for that iteration.

---

## Input/Output

### Print

```
Print "Hello, World!".
Print the x.
Print "add numbers" of 3 and 5.
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
a text called "name" is "Alice".
a number called "age" is 25.
Print "Hello, {name}! You are {age} years old.".
```

#### Format Specifiers

| Specifier | Description | Example | Output |
|-----------|-------------|---------|--------|
| `{var}` | Default formatting | `{name}` | `Alice` |
| `{var:.N}` | N decimal places | `{pi:.2}` | `3.14` |
| `{var:N}` | Pad to N characters | `{x:6}` | `    42` |
| `{var:0N}` | Zero-pad to N chars | `{x:06}` | `000042` |
| `{var:x}` | Hexadecimal (lowercase) | `{255:x}` | `0xff` |
| `{var:X}` | Hexadecimal (uppercase) | `{255:X}` | `0xFF` |
| `{var:b}` | Binary | `{5:b}` | `101` |
| `{var:o}` | Octal | `{8:o}` | `10` |
| `{var:04x}` | Padded hex | `{255:04x}` | `0x00ff` |

#### Expressions in Format Strings

```
a number called "x" is 10.
a number called "y" is 3.
Print "Sum: {x add y}".
Print "Product: {x multiply y}".
Print "Arguments: {arguments's count}".
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

```
Print <default>, but if <condition> print <value>.
```

**Chained conditions:**
```
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
a buffer called "input".
a buffer called "data".
```

**Features:**
- Start with 4KB capacity and grow automatically as needed
- No buffer overflows possible - memory expands dynamically
- Automatically freed on program exit

#### Fixed-Size Buffers

```
a buffer called "small" is 256 bytes in size.
a buffer called "large" is 8192 bytes in size.
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
a number called "len" is mybuffer's size.
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
a buffer called "data" is 256 bytes in size.
Read from file into data.

If data's full then,
    print "Buffer is at capacity".

If data's empty then,
    print "No data was read".
```

#### Buffer Resizing

Resize a buffer to a new capacity:

```
a buffer called "buf" is 64 bytes in size.
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
a number called "first" is byte 1 of data.
a number called "b" is byte i of buffer.
```

**Writing bytes:**
```
Set byte 1 of data to 0x48.
Set byte 2 of data to 'A'.
Set byte 3 of buffer to value.
```

**Creating buffer from string:**
```
a buffer called "buf" is "Hello".
Set byte 1 of buf to 'J'.
Print buf.  (prints "Jello")
```

**Modifying string bytes:**
```
Set byte 1 of "Hello World" to 'J'.
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
```

**Behavior:**
- `append source to destination` adds source bytes to the end of destination.
- `copy source to destination` replaces destination contents with source bytes.
- `clear destination` sets destination length to `0` and preserves destination capacity.
- Dynamic destination buffers grow automatically as needed.
- Fixed destination buffers truncate when full and set the error flag.
- Source buffer is never modified.

**Example:**
```
Create a buffer called "data" with size 16.
Set byte 1 of data to 0xDE.
Set byte 2 of data to 0xAD.
Set byte 3 of data to 0xBE.
Set byte 4 of data to 0xEF.

a number called "b1" is byte 1 of data.
Print "First byte: 0x{b1:02X}".

(Out of bounds - caught by error handler)
a number called "bad" is byte 100 of data.
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
a list of strings called "names" contains "Alice", "Bob", "Charlie".

print names's length.

If names's empty then,
    print "No names in list".
```

#### List Element Access

Access list elements by index. Indexes are **1-indexed** (like natural language: "the first element", "the second element").

**By index:**
```
a list called "numbers" is [10, 20, 30].

Print element 1 of numbers.   (prints 10)
Print element 2 of numbers.   (prints 20)

a number called "i" is 2.
Print element i of numbers.   (prints 20)
```

**By property:**
```
Print numbers's first.        (prints 10)
Print numbers's last.         (prints 30)
Print numbers's second.       (prints 20)
```

**Bounds Checking:**
- Out-of-bounds access sets an error flag and returns 0
- Errors can be caught with `On error`

**Example with error handling:**
```
a list called "items" is [1, 2, 3].

a number called "bad" is element 100 of items.
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
a number called "x" is -42.

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
Read from standard input into buffer.
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
Write buffer to output.
Write a newline to output.
```

### Closing Files

Close file handles when done:

```
Close the source.
Close output.
```

### File Operations

Check if a file exists:

```
If "data.txt" exists then,
    print "File found.".
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
Read from source into buffer.
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
a number called "item" is element 100 of mylist.
On error print "Index out of bounds!".

(Check buffer state manually)
If buffer's size is equal to buffer's capacity then,
    print "Warning: buffer may have been truncated".
```

### Resource Safety

`ec` provides **Rust-like memory safety** through automatic resource management.

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
a buffer called "data".                    # Auto-freed on exit
open a file for writing called log at "x". # Auto-closed on exit
# Even if you forget to close - it's handled!
```

#### Dynamic Buffers

Buffers start at 4KB and grow automatically. No size specification needed:

```
a buffer called "input".     # Grows as needed - never overflows
Read from source into input. # Safe regardless of file size
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
    open a file for writing called log at "debug.log".
    Write "Debug info" to log.
    # Close might be forgotten here - still safe!
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

## Time and Timers

### Getting Current Time

Get the current date/time as a `time` value:

```
Get current time into now.
a time called "now" is current time.
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
Create a timer called "job timer".
a timer called "benchmark".
```

#### Starting and Stopping

```
Start the "job timer".
(... do work ...)
Stop the "job timer".
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
Print the "job timer"'s duration in seconds.
Print the "job timer"'s duration in milliseconds.
Print the "job timer"'s elapsed in seconds.
```

#### Complete Timer Example

```
(Measure job duration)
Print "Starting job...".
Create a timer called "job timer".
Start the "job timer".

(... do work ...)
Wait 1 second.
Print "Seconds elapsed so far: ".
Print the "job timer"'s elapsed in seconds.

Wait 500 milliseconds.
Stop the "job timer".

Print "Finished the job in: ".
Print the "job timer"'s duration in seconds.
Print " seconds".

(Access raw timestamps)
Print "Started at unix time: ".
Print the "job timer"'s start time.
Print "Stopped at unix time: ".
Print the "job timer"'s end time.
```

#### Formatted Time Output

Combine time properties with padded casting for formatted output:

```
Get current time into now.
a text called "h" is now's hour as text padded to 2.
a text called "m" is now's minute as text padded to 2.
a text called "s" is now's second as text padded to 2.

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
a number called "argc" is arguments's count.
Print "Argument count: ".
Print the argc.

a text called "program" is arguments's name.
Print "Program name: ".
Print the program.
```

### Accessing User Arguments

```
(Get the first argument passed by the user)
If arguments's count is greater than 1 then,
    a text called "username" is arguments's first.
    Print "Hello, ".
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
a number called "i" is 2.
a text called "arg" is the argument at the i.
```

### Declarative Flag Parsing

Vox supports declarative CLI flag parsing with a schema-first style.

#### 1) Declare a flag schema

Define each supported flag once, including aliases and type:

```
a flag called "verbose" is "-v" or "--verbose", it is a boolean.
a flag called "output" is "-o" or "--output", it is a text.
a flag called "retries" is "-r" or "--retries", it is a number.
```

Supported flag value types:

- `boolean` (presence sets true)
- `text` (consumes the next token as text)
- `number` (consumes the next token and parses it as a number)

#### 2) Optional schema modifiers

Flags may be marked as required and/or given defaults:

```
a flag called "output" is "-o" or "--output", it is a text with default "out.txt".
a flag called "retries" is "-r" or "--retries", it is a number and is required.
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
a flag called "verbose" is "-v" or "--verbose", it is a boolean.
a flag called "output" is "-o" or "--output", it is a text with default "out.txt".
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
a flag called "help" is "-h" or "--help", it is a boolean.
a flag called "version" is "-V" or "--version", it is a boolean.
a flag called "number" is "-n" or "--number", it is a boolean.

Parse flags.

If help then,
    Print "Usage: myprog [options] [files]".

If version then,
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
a text called "home" is environment's "HOME".
a text called "user" is environment's "USER".
a text called "shell" is environment's "SHELL".

Print "Home: ".
Print the home.
```

### Environment Variable Count

```
a number called "env count" is environment's count.
Print "Total environment variables: ".
Print the env count.
```

### Iterating Environment Variables

```
a text called "env1" is environment's first.
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

a text called "name" is "World".

(Use argument if provided, otherwise use environment variable)
If arguments's count is greater than 1 then,
    the name is arguments's first.
But if the environment variable "GREET_NAME" exists then,
    the name is environment's "GREET_NAME".

Print "Hello, ".
Print the name.
Print "!".

(Show some environment info)
a text called "user" is environment's "USER".
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
| Bitwise AND | `bit-and`, `bitwise and` |
| Bitwise OR | `bit-or`, `bitwise or` |
| Bitwise XOR | `bit-xor`, `bitwise xor` |
| Bitwise NOT | `bit-not`, `bitwise not` |
| Shift Left | `bit-shift-left`, `shift left` |
| Shift Right | `bit-shift-right`, `shift right` |

**Examples:**
```
a number called "a" is 0b11110000.
a number called "b" is 0b10101010.

(Bitwise AND)
a number called "result" is a bit-and b.

(Bitwise OR)
Set result to a bit-or b.

(Bitwise XOR)
Set result to a bit-xor b.

(Bitwise NOT)
Set result to bit-not a.

(Bit shifting)
Set result to a shift left 2.
Set result to a shift right 4.

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
| Function parameters | `with a number called "x" and a number called "y"` | Separates parameter declarations |
| Function arguments | `"add" of 3 and 5` | Separates argument values |
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
a number called "x" is 3.
a number called "y" is 5.
Print the x add the y.
```

### Function Definition and Call

```
To "add numbers" with a number called "x" and a number called "y". Return a number, the x add y.

Print "add numbers" of 3 and 5.
```

### Counting Loop

```
Set the number called counter to 1.
While the counter is less than 10, print the counter, increment the counter.
```

### FizzBuzz

```
To "check divisibility" with a number called "divisor" and a number called "dividend". Return a boolean, the divisor modulo the dividend is 0.

For each number from 1 to 15, print the number, but if "check divisibility" of the number and 6 is true print "fizz buzz" but if "check divisibility" of the number and 2 is true print "fizz" but if "check divisibility" of the number and 3 is true print "buzz".
```

---

## Libraries and Imports

### The `see` Keyword

Use `see` to include other source files or libraries:

```
see "./utils.en".
see "./libraries/math.so".
see "math" version "1.0" from "./libraries/math.so".
```

**Syntax variations:**
- `see "./path/to/file.en".` - Include source file
- `see "./path/to/lib.so".` - Include compiled library
- `see "libname" version "1.0" from "./path.so".` - Include specific version
- `see "./path.so" for "libname" version "1.0".` - Alternative syntax

**Search paths:**
1. Relative to current file (`./` or `../`)
2. System library path (`/usr/share/vox/lib/`)

**Circular dependencies:** The compiler tracks included files and automatically skips files that have already been included.

### Creating Libraries

Declare a library with name and version:

```
Library "math" version "1.0".

To "square" a number x:
    return x multiply x.

To "cube" a number x:
    return x multiply x multiply x.
```

### Using Library Functions

After including a library, use its functions directly:

```
see "./math.en".

a number called "result" is "square" of 5.
print result.
```

---

## Compiler Usage

### Basic Usage

```bash
vox <source.en> [options]
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
vox hello.en --run

# Build executable with custom name
vox hello.en -o myprogram

# Build shared library
vox math.en --shared

# Link against shared library
vox main.en --link libmath --lib-path ./libs
```

---

## Grammar Summary

```
program     ::= statement*
statement   ::= print_stmt | var_decl | assignment | if_stmt | while_stmt 
              | for_stmt | func_def | increment | decrement | break | continue
              | append_stmt

var_decl    ::= ("a" | "an") type "called" name "is" expr "."
              | ("Set" | "Create") "the"? type? "called"? name "to" expr "."

assignment  ::= "the" name "is" expr "."

append_stmt ::= "append" expr "to" name "."
              | "append" "each" name "from" expr "to" name ("treating" expr "as" expr)? "."

func_def    ::= "To" string "with" params "." "Return" "a" type "," expr "."
params      ::= param ("and" param)*
param       ::= "a" type "called" name

func_call   ::= string "of" args
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
              | "Print" string "of" "each" name "from" expr ("treating" expr "as" expr)?
                ("," "but if" condition "print" expr)* "."

loop_expansion ::= "each" name "from" expr ("treating" expr "as" expr)?

expr        ::= or_expr
or_expr     ::= and_expr ("or" and_expr)*
and_expr    ::= comparison ("and" comparison)*
comparison  ::= additive (comp_op additive)?
additive    ::= multiplicative ((add | subtract) multiplicative)*
multiplicative ::= primary ((multiply | divide | modulo) primary)*
primary     ::= literal | identifier | func_call | "(" expr ")"

type        ::= "number" | "text" | "boolean" | "list"
name        ::= string | identifier
```
