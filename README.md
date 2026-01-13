# EC

A compiler that translates English to x86_64 Assembly.

## Overview

`ec` allows you to write programs in natural English sentences, which are then compiled directly to native x86_64 assembly code (with support for more architectures to come).

## Features

- **Natural Language Syntax**: Write code in English sentences
- **Compiles to Assembly**: Direct compilation to x86_64 NASM assembly
- **Modular Standard Library**: Only includes what you use (heap, strings, math, io)
- **Automated Memory Management**: Heap allocations are tracked
- **Zero External Dependencies**: No libc required, uses direct syscalls

## Requirements

- Rust (for building the compiler)
- NASM (Netwide Assembler)
- ld (GNU linker)

```bash
sudo apt install nasm
```

## Building

```bash
cargo build --release
```

## Usage

```bash
# Compile an English program
./target/release/ec program.en

# Compile and run
./target/release/ec program.en --run

# Output assembly only
./target/release/ec program.en --emit-asm
```

## Language Syntax

### Printing
```
Print "Hello, World!".
Print 42.
Print myVariable.
```

### Variables
```
Set x to 10.
Create counter as 0.
```

### Conditionals
```
If x is greater than 10, print "big".
If the number is even print "even" but if it is odd print "odd".
```

### Loops
```
For each number from 1 to 100, print the number.
While x is less than 10, increment x.
Repeat 5 times, print "hello".
```

### Properties
```
If x is even...
If x is odd...
If x is positive...
If x is negative...
If x is zero...
```

### Memory (Heap)
```
Allocate 1024 for buffer.
Free buffer.
```

## Examples

### Hello World
```
Print "Hello, World!".
```

### FizzBuzz-style
```
For each number from 0 to 100, if the number is even print "foo" but if it is odd print "bar".
```

## Architecture

```
Source (.en) → Lexer → Parser → Analyzer → CodeGen → Assembly (.asm)
                                    ↓
                           Dependency Tracking
                                    ↓
                        Modular stdlib inclusion
```

## Standard Library Modules

| Module | Included When |
|--------|---------------|
| core.asm | Always |
| io.asm | Using print |
| heap.asm | Using allocate/free |
| string.asm | Using strings |
| math.asm | Using division/modulo/properties |

## License

MIT
