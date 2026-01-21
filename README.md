# EC

![Open issues](https://img.shields.io/github/issues/eng-c/ec?style=flat-square)
![Repo size](https://img.shields.io/github/repo-size/eng-c/ec?style=flat-square)
![Last commit](https://img.shields.io/github/last-commit/eng-c/ec?style=flat-square)

**EC** is a minimal systems compiler that translates a constrained, sentence-based English syntax directly into native x86_64 assembly — without a runtime, virtual machine, or standard library.

It is an experiment in compiler design, language ergonomics, and low-level systems programming, focused on producing predictable, memory-safe, and extremely small executables.

---

## Motivation

EC explores how far a human-readable, deterministic syntax can be lowered *directly* to native assembly while preserving the kinds of guarantees typically associated with modern systems languages.

The project is intentionally minimal:
there is no libc, no garbage collector, and no hidden runtime. All abstractions are resolved at compile time, and the generated code consists of straightforward NASM assembly and direct system calls.

Rather than hiding system behavior, EC aims to make it explicit — just expressed in a readable form.

---

## Language Model

EC does **not** attempt free-form natural language understanding.

Instead, it uses a constrained, sentence-based grammar designed to remain readable while compiling deterministically. Every construct maps directly to well-defined compiler behavior, with no ambiguity or dynamic interpretation.

The goal is not to “write code like prose”, but to explore an alternative surface syntax that remains precise, analyzable, and predictable at compile time.

---

## Safety Model

EC is designed with strong safety guarantees in mind. The core language enforces rules that make common classes of memory errors — including buffer overflows, use-after-free, and double frees — extremely difficult to express.

Memory allocation, ownership, and lifetime are tracked at compile time. Heap-backed structures grow dynamically as needed, and resources such as files, buffers, and timers are automatically released, even if explicit cleanup is omitted.

While EC does not replicate Rust’s type system, it aims for a similar *practical outcome*: predictable, memory-safe programs without requiring a garbage collector or runtime checks.

---

## Minimal Executables

Because EC compiles directly to relatively simple assembly and avoids a runtime or standard library, the resulting executables are extremely small.

This property makes EC particularly well-suited for static utilities, constrained environments, and systems-level tooling.

---

## Features

* Direct compilation to native x86_64 NASM assembly
* No libc or runtime; uses direct system calls
* Deterministic sentence-based syntax
* Compile-time memory and resource tracking
* Modular standard library with dependency inclusion
* Extremely small statically linked executables

---

## Examples

EC is best understood by reading complete, working programs.

The repository includes a growing collection of example scripts that demonstrate control flow, file I/O, argument handling, environment access, timing, numeric computation, and resource management. These examples are not pseudocode — they compile to native executables and run without external dependencies.

Readers are encouraged to browse the examples directory to understand both the language model and the compiler’s lowering strategy.

Included examples demonstrate:

* Control systems and conditional logic
* Reimplementation of Unix utilities (`cat`)
* Numeric computation and floating-point math
* Secure file I/O with automatic cleanup
* Command-line arguments and environment variables
* Timers and time-based system calls

---

## Architecture

```
Source (.en)
   ↓
Lexer → Parser → Analyzer → CodeGen → Assembly (.asm)
                         ↓
                Dependency Tracking
                         ↓
             Modular coreasm inclusion
```

Each stage operates on explicit intermediate representations.
No dynamic analysis or runtime interpretation occurs after compilation.

---

## Requirements

* Rust (for building the compiler)
* NASM (Netwide Assembler)
* GNU ld

### Debian / Ubuntu

```sh
sudo apt install nasm rust make
```

### Fedora

```sh
sudo yum install nasm rust make
```

---

## Building

```sh
cargo build --release
```

---

## Installing

```sh
# Build and install system-wide
make build
sudo make install

# Uninstall
sudo make uninstall
```

---

## Usage

```sh
# Compile and run
ec example.en --run

# Compile only
ec example.en
```

---

## Roadmap

EC is under active development. Planned work includes:

1. **Shared Libraries**
   Versioned shared libraries with explicit naming, symbol scoping, and backward compatibility guarantees.

2. **User-Defined Types**
   Structs and custom types with compile-time layout and predictable memory semantics.

3. **Networking Abstractions**
   High-level interfaces built on top of system calls, provided via libraries (e.g. HTTP/1.0 reference implementation).

4. **Additional Architectures**
   Planned targets include Win64, AArch64, ARM64, MIPS, and RISC-V.

5. **Expanded System Interfaces**
   Higher-level abstractions for multithreading, file descriptor polling, filesystem operations, and system control.

6. **Math and Numeric Optimization**
   Continued optimization of numeric code generation, with a goal of matching or exceeding C performance in benchmarks.

---

## Non-Goals

* Free-form natural language interpretation
* JIT compilation or runtime reflection
* Dynamic typing or implicit control flow
* Hiding system behavior behind opaque abstractions

---

## Status

EC is experimental but functional.
Core language features are implemented and exercised by real programs, with additional capabilities under active development.