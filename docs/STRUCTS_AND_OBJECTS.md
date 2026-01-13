# Structs and Objects Design (Future)

## Overview

This document outlines the planned design for custom types, structs, and objects in English. The goal is to allow users to define their own data structures with properties accessible via the possessive `'s` syntax.

## Current State

Currently, property access with `'s` is hardcoded for built-in types:
- `arguments's count`, `arguments's all`, `arguments's empty`
- `current time's hour`, `current time's minute`, etc.
- `list's first`, `list's last`, `list's length`
- `buffer's size`, `buffer's capacity`
- `file's size`, `file's descriptor`

**Problem:** Keywords like `hour`, `byte`, `first` are reserved, preventing their use as user-defined property names.

## Proposed Design

### 1. Property Access as Identifiers

**Key Insight:** After `'s`, the next token should be treated as an **identifier**, not a keyword.

```english
(Currently fails - "left" is a keyword)
set dog's left leg to 3.

(Should work - "left" is just a property name here)
set dog's left leg to 3.
```

**Implementation:**
- In the lexer/parser, after consuming `'s`, read the next word as a raw identifier
- Do not resolve it against the keyword table
- This allows any word to be a property name

### 2. Struct Definition Syntax

```english
Define a struct called "Dog" with:
    a text called "name",
    a number called "age",
    a boolean called "is good".

Define a struct called "Point" with:
    a number called "x",
    a number called "y".
```

**Alternative (more English-like):**
```english
A Dog has:
    a name (text),
    an age (number),
    a boolean indicating whether it is good.

A Point has:
    an x coordinate (number),
    a y coordinate (number).
```

### 3. Struct Instantiation

```english
Create a Dog called "buddy" with name "Buddy", age 3, is good true.

(Or with defaults)
Create a Dog called "spot".
Set spot's name to "Spot".
Set spot's age to 5.
```

### 4. Property Access

```english
Print buddy's name.           (prints "Buddy")
Print buddy's age.            (prints 3)
If buddy's is good then print "Good dog!".
```

### 5. Nested Structs

```english
Define a struct called "Person" with:
    a text called "name",
    a Dog called "pet".

Create a Person called "alice" with name "Alice".
Create a Dog called "fido" with name "Fido", age 2.
Set alice's pet to fido.

Print alice's pet's name.     (prints "Fido")
```

## Built-in Types as Structs

Built-in "magic" types would be defined internally as structs:

### Arguments (implicit)
```english
(Internal definition - not user-visible)
Arguments has:
    count (number),
    all (list of text),
    empty (boolean).
```

### Current Time (implicit)
```english
(Internal definition - not user-visible)
Current Time has:
    hour (number),
    minute (number),
    second (number),
    day (number),
    month (number),
    year (number),
    unix (number).
```

### Lists
```english
(Every list implicitly has)
    first (element type),
    last (element type),
    length (number).
```

## Property Enumeration

To support IDE tooling and compile-time checking:

### Option A: Compile-Time Property Tables

Each struct type maintains a property table:
```
Dog -> { name: Text, age: Number, is_good: Boolean }
Point -> { x: Number, y: Number }
```

Property access `X's Y` is validated:
1. Look up type of `X`
2. Check if `Y` exists in that type's property table
3. Error if not found: "Dog has no property called 'tail'"

### Option B: Runtime Property Maps

Structs are hash maps at runtime:
- More flexible (duck typing)
- Less compile-time safety
- Simpler implementation

**Recommendation:** Option A for user-defined structs, with runtime fallback for dynamic cases.

## Implementation Phases

### Phase 1: Property-as-Identifier
- Modify parser to treat post-`'s` tokens as identifiers
- Allow any word as a property name
- **Unblocks:** Using words like `left`, `byte`, `hour` as property names

### Phase 2: Struct Definition
- Add `Define a struct` syntax
- Generate struct metadata at compile time
- Memory layout: contiguous fields

### Phase 3: Struct Instantiation
- Add `Create a <Type>` syntax
- Initialize fields from `with` clause or defaults

### Phase 4: Property Validation
- Validate property access at compile time
- Helpful error messages for typos

### Phase 5: Methods (Future)
```english
Define a method on Dog called "bark" that:
    prints "{self's name} says woof!".

Call buddy's bark.
```

## Memory Layout

```
Struct Dog (24 bytes):
  +0:  name pointer (8 bytes)
  +8:  age (8 bytes)
  +16: is_good (8 bytes, 0 or 1)
```

Property access compiles to offset calculation:
```asm
; buddy's age
mov rax, [rbp-8]      ; buddy pointer
mov rax, [rax+8]      ; age at offset 8
```

## Open Questions

1. **Inheritance?** Should structs support "A Dog is an Animal"?
2. **Mutability?** Should properties be immutable by default?
3. **Visibility?** Public vs private properties?
4. **Generics?** "A list of Dogs" vs "A list of numbers"?
5. **Null safety?** What if `alice's pet` is not set?

## Syntax Alternatives Considered

### Definition
- `Define a struct called "X"` (explicit, clear)
- `A X has` (more English-like)
- `Create a type called "X"` (verbose)

### Instantiation
- `Create a Dog called "buddy"` ✓
- `A Dog called "buddy"` (conflicts with variable declaration)
- `New Dog called "buddy"` (too programming-like)

## Timeline

This feature is **deferred** until core language features stabilize. The current priority is:
1. Memory safety ✓
2. Error handling (basic) ✓
3. File I/O ✓
4. Standard library

Structs/objects are planned for a future major version.
