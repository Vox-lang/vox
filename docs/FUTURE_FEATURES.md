# EC Language - Future Features and Improvements

This document brainstorms potential enhancements to the EC language, organized by category.

---

## Compiler Warnings

### Overview

The compiler should emit warnings for code patterns that are syntactically valid and will execute correctly, but likely indicate programmer error or poor practice.

### Warning Categories

#### 1. Unused Variables

**Pattern:** Variable declared but never referenced

```
a number called "x" is 5.
a number called "y" is 10.
print the y.
(x is never used - should warn)
```

**Rationale:** Unused variables consume memory and suggest incomplete code or copy-paste errors.

**Implementation:** Track all variable declarations and references during semantic analysis. Warn if a variable is declared but never read.

**Severity:** Warning (not an error)

**Suppressible:** Yes, with a comment like `(unused)` or compiler flag `--allow-unused`

---

#### 2. Unused Functions

**Pattern:** Function defined but never called

```
To "helper" with a number called "x". Return a number, x multiply 2.

print "Hello".
(helper is never called - should warn)
```

**Rationale:** Dead code suggests incomplete refactoring or accidental inclusion.

**Implementation:** Track all function definitions and calls. Warn if a function is defined but never invoked.

**Severity:** Warning

**Suppressible:** Yes, with comment or flag

---

#### 3. Loop Expansion in Return Statements

**Pattern:** Using `each...from` in a return statement

```
To "get_doubled" with a list called "nums". 
  Return a list, each x from nums.
(This is ambiguous - should warn or error)
```

**Rationale:** Loop expansion in return statements is ambiguous:
- Should it return a list with the expanded items?
- Should it return the last item?
- Should it return nothing?

**Current Status:** Not implemented (documented as future work)

**Implementation:** Detect `each...from` in return expression and emit warning/error.

**Severity:** Error (not just warning) - too ambiguous to allow

**Alternative Syntax (Future):**
```
Return a list, [each x from nums].
```

---

#### 4. Parameter Loop Expansion in Function Calls

**Pattern:** Using loop expansion in function parameters

```
To "process" with a number called "x". Return a number, x multiply 2.

a list called "nums" is [1, 2, 3].
print "process" of each n from nums.
(This is valid and works, but might be confusing)
```

**Rationale:** While this works correctly, it's a complex pattern that might confuse readers. Consider warning when:
- Loop expansion is used as a function argument
- The function has multiple parameters (ambiguous which gets the loop variable)
- The function is called with other arguments besides the loop expansion

**Current Status:** Implemented and working

**Implementation:** Detect function calls with loop expansion arguments and emit warning if:
- Function has multiple parameters
- Other arguments are also provided
- Function is user-defined (not built-in like `print`)

**Severity:** Warning (not error)

**Example of warning case:**
```
To "add" with a number called "x" and a number called "y". 
  Return a number, x add y.

(This is ambiguous - which parameter gets the loop variable?)
print "add" of each n from [1, 2, 3] and 10.
```

---

#### 5. Shadowed Variables

**Pattern:** Loop variable shadows outer variable

```
a number called "x" is 100.
print each x from [1, 2, 3].
print the x.
(x is shadowed - should warn)
```

**Rationale:** Variable shadowing can lead to confusion. After the loop, `x` has the value from the last iteration (3), not the original value (100).

**Current Status:** Implemented (documented behavior)

**Implementation:** Detect when loop variable name matches an outer variable and emit warning.

**Severity:** Warning

**Suppressible:** Yes, with comment like `(shadowing x)` or explicit variable rename

---

#### 6. Type Mismatches in Collections

**Pattern:** Appending different types to a list

```
a list called "items" is [1, 2, 3].
append "hello" to items.
(Type mismatch - list was integers, now appending string)
```

**Rationale:** While EC allows mixed-type lists, appending a different type than the initial elements is likely an error.

**Current Status:** Not implemented

**Implementation:** Track the element type from the first append (or list literal). Warn if subsequent appends have different types.

**Severity:** Warning

**Suppressible:** Yes, with explicit cast or comment

---

#### 7. Infinite Ranges

**Pattern:** Using infinite ranges in loops

```
print each n from 1 to infinity.
(This will loop forever - should error)
```

**Rationale:** Infinite loops are almost always unintentional.

**Current Status:** Not implemented (documented as future work)

**Implementation:** Detect range bounds that are infinite or very large and emit error.

**Severity:** Error

---

#### 8. Unreachable Code

**Pattern:** Code after unconditional exit/return

```
To "test".
  Return a number, 5.
  print "This never runs".
(Code after return is unreachable)
```

**Rationale:** Dead code suggests logic errors.

**Implementation:** Track control flow and detect statements after unconditional exits/returns.

**Severity:** Warning

---

#### 9. Empty Loop Bodies

**Pattern:** Loop with no statements

```
While x is less than 10,
  .
(Empty loop body - likely error)
```

**Rationale:** Empty loops are usually mistakes.

**Implementation:** Detect loops with no statements in body.

**Severity:** Warning

---

#### 10. Condition Always True/False

**Pattern:** Conditions that are statically determinable

```
If true then,
  print "Always prints".
(Condition is always true - should warn)
```

**Rationale:** Suggests incomplete conditional logic.

**Implementation:** Perform constant folding on conditions and warn if always true/false.

**Severity:** Warning

---

## List Comparison Operations

### Overview

Add support for comparing lists using quantifier operations: `any`, `all`, and `none`.

### 1. The `any` Quantifier

**Syntax:** `any <variable> in <list> <condition>`

**Semantics:** Returns true if ANY element in the list satisfies the condition.

**Examples:**

```
a list called "numbers" is [1, 2, 3, 4, 5].

(Check if any number is greater than 3)
If any n in numbers is greater than 3 then,
  print "Found a number greater than 3".

(Check if any name is "Alice")
a list called "names" is ["Bob", "Charlie", "Alice"].
If any name in names is equal to "Alice" then,
  print "Alice is in the list".

(With function calls)
To "is_even" with a number called "x". 
  Return a boolean, x modulo 2 is equal to 0.

If any num in numbers is_even then,
  print "Found an even number".
```

**Implementation Notes:**
- Short-circuit evaluation: stop checking once a true condition is found
- Loop variable available in condition
- Works with ranges and lists
- Can be combined with `and`/`or` in larger conditions

---

### 2. The `all` Quantifier

**Syntax:** `all <variable> in <list> <condition>`

**Semantics:** Returns true if ALL elements in the list satisfy the condition.

**Examples:**

```
a list called "numbers" is [2, 4, 6, 8].

(Check if all numbers are even)
If all n in numbers modulo 2 is equal to 0 then,
  print "All numbers are even".

(Check if all names are non-empty)
a list called "names" is ["Alice", "Bob", "Charlie"].
If all name in names is not equal to "" then,
  print "All names are provided".

(With function calls)
To "is_positive" with a number called "x".
  Return a boolean, x is greater than 0.

If all num in numbers is_positive then,
  print "All numbers are positive".

(Empty list - all returns true)
a list called "empty" is [].
If all x in empty is greater than 0 then,
  print "This prints (vacuous truth)".
```

**Implementation Notes:**
- Short-circuit evaluation: stop checking once a false condition is found
- Empty list returns true (vacuous truth)
- Loop variable available in condition
- Works with ranges and lists

---

### 3. The `none` Quantifier

**Syntax:** `none <variable> in <list> <condition>`

**Semantics:** Returns true if NO elements in the list satisfy the condition.

**Examples:**

```
a list called "numbers" is [1, 3, 5, 7].

(Check if no numbers are even)
If none n in numbers modulo 2 is equal to 0 then,
  print "No even numbers found".

(Check if no names are empty)
a list called "names" is ["Alice", "Bob", "Charlie"].
If none name in names is equal to "" then,
  print "All names are non-empty".

(With function calls)
To "is_negative" with a number called "x".
  Return a boolean, x is less than 0.

If none num in numbers is_negative then,
  print "No negative numbers".

(Empty list - none returns true)
a list called "empty" is [].
If none x in empty is less than 0 then,
  print "This prints (vacuous truth)".
```

**Implementation Notes:**
- Equivalent to `not any`
- Short-circuit evaluation: stop checking once a true condition is found
- Empty list returns true (vacuous truth)
- Loop variable available in condition

---

### 4. Combining Quantifiers with Boolean Logic

**Examples:**

```
(Multiple quantifiers)
If any x in list1 is greater than 5 and all y in list2 is less than 10 then,
  print "Condition met".

(Negation)
If not any n in numbers is equal to 0 then,
  print "No zeros in list".

(Complex conditions)
If any x in nums is greater than 100 or none y in nums is negative then,
  print "Complex condition".
```

---

### 5. Quantifiers with Ranges

**Examples:**

```
(Check if any number from 1 to 10 is divisible by 3)
If any n from 1 to 10 modulo 3 is equal to 0 then,
  print "Found a multiple of 3".

(Check if all numbers from 1 to 5 are positive)
If all n from 1 to 5 is greater than 0 then,
  print "All positive".
```

---

### 6. Quantifiers in Expressions

**Examples:**

```
(Use quantifier result in variable)
a boolean called "has_even" is any n in numbers modulo 2 is equal to 0.
print the has_even.

(Use in format strings)
print "Any greater than 5: {any x in nums is greater than 5}".

(Use in function calls)
To "check_list" with a list called "items".
  If all x in items is greater than 0 then,
    print "All positive".

check_list with numbers.
```

---

## Implementation Considerations

### Parser Changes

1. Add `any`, `all`, `none` as keywords
2. Extend condition parsing to recognize quantifier patterns
3. Parse loop variable and collection
4. Parse condition expression

### Semantic Analysis

1. Validate loop variable is not already in scope (or warn about shadowing)
2. Validate collection is iterable (list or range)
3. Validate condition is boolean
4. Type check the condition expression

### Code Generation

1. Generate loop with early exit on condition match/mismatch
2. For `any`: exit with true on first match, false if no matches
3. For `all`: exit with false on first non-match, true if all match
4. For `none`: exit with false on first match, true if no matches
5. Handle empty collections (return true for `all` and `none`, false for `any`)

### Optimization

1. Short-circuit evaluation (stop checking once result is determined)
2. Constant folding for literal collections
3. Loop unrolling for small known-size collections

---

## Future Considerations

### Nested Quantifiers

```
(Check if any list in a list of lists has all positive numbers)
If any list in lists has all n in list is greater than 0 then,
  print "Found a list with all positive numbers".
```

**Status:** Not planned for initial implementation (complex)

### Quantifiers with Multiple Variables

```
(Check if any pair of elements satisfies a condition)
If any x in list1 and any y in list2 x add y is greater than 10 then,
  print "Found a pair".
```

**Status:** Not planned for initial implementation (very complex)

### Custom Predicates

```
(Define a predicate function and use with quantifiers)
To "is_prime" with a number called "x". Return a boolean, ...

If any n from 1 to 100 is_prime then,
  print "Found a prime".
```

**Status:** Already supported with current function call syntax

---

## Summary of Priorities

### High Priority (Implement Soon)

1. **Compiler Warnings** - Unused variables, unused functions, shadowed variables
2. **List Quantifiers** - `any`, `all`, `none` operations
3. **Type Mismatch Warnings** - Warn on mixed-type appends

### Medium Priority (Implement Later)

1. **Return Statement Loop Expansion** - Error or new syntax
2. **Infinite Range Detection** - Error on infinite loops
3. **Unreachable Code Detection** - Warn on dead code

### Low Priority (Consider for Future)

1. **Nested Quantifiers** - Complex, low demand
2. **Multiple Variable Quantifiers** - Very complex
3. **Parameter Loop Expansion Warnings** - Edge case

