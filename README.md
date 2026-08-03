# Vox

![Open issues](https://img.shields.io/github/issues/Vox-lang/vox?style=flat-square)
![Repo size](https://img.shields.io/github/repo-size/Vox-lang/vox?style=flat-square)
![Last commit](https://img.shields.io/github/last-commit/Vox-lang/vox?style=flat-square)
![GPLv3 license](https://img.shields.io/badge/License-GPLv3-blue.svg)

**Vox** is a minimal systems compiler that translates a constrained, sentence-based English syntax directly into native x86_64 assembly — without a **resident runtime system**, virtual machine, or standard library.

The generated binaries consist solely of application code and direct system calls, with no background services, schedulers, garbage collectors, or support libraries.

Vox is an experiment in compiler design, language ergonomics, and low-level systems programming, focused on producing predictable, memory-safe, and extremely small executables.

---

## Motivation

Vox explores how far a human-readable, deterministic syntax can be lowered *directly* to native assembly while preserving the kinds of guarantees typically associated with modern systems languages.

The project is intentionally minimal:
there is no libc, no garbage collector, and no hidden runtime system. All abstractions are resolved at compile time, and the generated code consists of straightforward NASM assembly and direct system calls.

Rather than hiding system behavior, Vox aims to make it explicit — just expressed in a readable form.

---

## Language Model

Vox does **not** attempt free-form natural language understanding.

Instead, it uses a constrained, sentence-based grammar designed to remain readable while compiling deterministically. Every construct maps directly to well-defined compiler behavior, with no ambiguity or dynamic interpretation.

The goal is not to “write code like prose”, but to explore an alternative surface syntax that remains precise, analyzable, and predictable at compile time.

For a complete description of the grammar and semantics, see  
**[LANGUAGE.md](LANGUAGE.md)**.

---

## Memory Safety Model

Memory safety in Vox is achieved without garbage collection, heap tracing, or runtime supervision.  
All safety guarantees are enforced through compile-time structure and **local, inline checks** emitted directly into the generated assembly.

### Pointer Abstraction

User programs never manipulate raw pointers directly.  
Instead, memory is accessed through compiler-managed buffers, which encapsulate allocation, size tracking, and lifetime.

### Dynamic and Fixed Buffers

- Dynamic buffers grow as needed when appended to, with their size tracked
  explicitly.
- Fixed-size buffers are declared with a capacity and do **not** grow. A
  write past the end is refused rather than reallocating (see below), so a
  declared bound stays a bound.
- All buffer operations are lowered to predictable, explicit assembly.

### Bounds-Checked Access

Programs may read or write any byte within a buffer.

If an access attempts to exceed the buffer’s bounds:
- The operation becomes a **no-op**
- An **error flag** is set
- Execution continues, allowing the program to explicitly detect and handle the error

These checks are emitted inline at the access site and do not rely on traps, exceptions, or runtime handlers.

### Resource Tracking and Cleanup

Buffers, file descriptors, and other system resources are tracked by the compiler.

All tracked resources are:
- Explicitly released when possible
- Automatically freed or closed on program exit, even if cleanup is omitted

This cleanup is deterministic and non-allocating, and does not involve object tracing or liveness analysis. It is equivalent to explicit teardown code written manually in low-level systems programs.

While Vox does not replicate Rust’s type system, it aims for a similar *practical outcome*: predictable, memory-safe programs without a garbage collector or runtime system.

---

## Minimal Executables

Because Vox compiles directly to simple assembly and avoids a runtime system or standard library, the resulting executables are extremely small.

This makes Vox well-suited for static utilities, constrained environments, and systems-level tooling where predictability and size matter more than abstraction depth.

---

## Features

* Direct compilation to native x86_64 NASM assembly
* No resident runtime system or libc; uses direct system calls
* Deterministic sentence-based syntax
* Compile-time memory and resource tracking
* Modular library of core macros with dependency inclusion
* Extremely small statically linked executables
* Structured data: lists, key/value maps, and arbitrary nesting of the two.
  Elements carry a runtime type tag, so a collection may hold mixed types
  and still read back as what it is; `is a text` / `is a number` predicates
  branch on that tag, and homogeneous collections keep a fully static fast
  path with no tag checks emitted
* An explicit dynamic `value` type for carrying "whatever this slot holds"
  across function boundaries, and a `nothing` value distinct from `0`
* Filesystem, mount, and process-control operations (directories, device
  nodes, symlinks, mount/unmount, `pivot_root`, `execve`, `fork`/`reap`,
  `shutdown`/`reboot`/`halt`) - enough to write a working early-userspace
  init entirely in Vox; see [examples/initramfs.vox](examples/initramfs.vox)

---

## Example Program

Below is a complete Vox program reimplementing the Unix `cat` utility.

This example demonstrates:
- File I/O
- Argument handling
- Buffer reuse
- Loop expansion over arguments
- Automatic resource cleanup

```
Open a file for writing called output at "/dev/stdout".
Create a buffer called content.

If arguments's empty then,
    open a file for reading called source at "/dev/stdin",
    read from source into content,
    write content to output,
    close source,
    exit 0.

Open a file called source for reading at each filename from arguments's all treating "-" as "/dev/stdin",
    read from source into content,
    write content to output,
    close source.
```

The loop expansion construct:

```
open ... at each X from Y
```

is resolved entirely at compile time and expands into explicit control flow with no runtime interpretation.

This program compiles to native assembly and produces a working executable without libc, dynamic linking, or a runtime system.

---

## Architecture

```
Source (.vox)
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
sudo apt install nasm cargo make
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
make build # Skip this step if installing from .7z 
sudo make install

# Uninstall
sudo make uninstall
```

---

## Usage

```sh
# Compile and run
vox example.vox --run

# Compile only
vox example.vox
```