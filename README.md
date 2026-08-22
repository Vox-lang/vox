# Vox

![Open issues](https://img.shields.io/github/issues/Vox-lang/vox?style=flat-square)
![Repo size](https://img.shields.io/github/repo-size/Vox-lang/vox?style=flat-square)
![Last commit](https://img.shields.io/github/last-commit/Vox-lang/vox?style=flat-square)
![GPLv3 license](https://img.shields.io/badge/License-GPLv3-blue.svg)
[![Copr build status](https://copr.fedorainfracloud.org/coprs/vox-lang/Vox/package/vox/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/vox-lang/Vox/package/vox/)
[![crates.io](https://img.shields.io/crates/v/vox-lang?style=flat-square)](https://crates.io/crates/vox-lang)

**Vox** is a minimal systems compiler that translates a constrained, sentence-based English syntax directly into native x86_64 assembly — without a **resident runtime system**, virtual machine, or standard library.

The generated binaries consist solely of application code and direct system calls, with no background services, schedulers, garbage collectors, or support libraries.

Vox is an experiment in compiler design, language ergonomics, and low-level systems programming, focused on producing predictable, memory-safe, and extremely small executables.

---

## Documentation

The full language reference is browsable at
**[vox-lang.dev/docs/](https://vox-lang.dev/docs/)** — one page per
`LANGUAGE.md` section, plus the whole spec on one page at
[/docs/all/](https://vox-lang.dev/docs/all/). Every page has a Markdown
twin at the same path with `.md` appended (plain-Markdown twins for
tools and crawlers). It's generated from `LANGUAGE.md` on `main` at
build time, so it stays current; each page states the commit it was
built from. The canonical source stays `LANGUAGE.md` in this repo.

Also see the style guide, [docs/STYLE.md](docs/STYLE.md); how to
contribute, [CONTRIBUTING.md](CONTRIBUTING.md); and how to install,
[docs/INSTALL.md](docs/INSTALL.md).

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
**[LANGUAGE.md](LANGUAGE.md)** (or browse it at
[vox-lang.dev](https://vox-lang.dev)).

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
* User-defined composite types - **things**. `A thing called point has a
  number called x is 0, a number called y is 0.` declares a type with a
  compile-time layout; things nest to any depth, copy by value, print
  themselves, compare field by field, and carry their own function members,
  with no runtime component emitted; see
  [examples/delivery.vox](examples/delivery.vox) and the
  [Things](LANGUAGE.md#things) chapter
* Filesystem, mount, and process-control operations (directories, device
  nodes, symlinks, mount/unmount, `pivot_root`, `execve`, `fork`/`reap`,
  `Send signal` (`kill`), non-blocking `reap ... without waiting`,
  `the reaped status`, `shutdown`/`reboot`/`halt`) - enough to write a
  working early-userspace init entirely in Vox, see
  [examples/initramfs.vox](examples/initramfs.vox), or a process supervisor
  with no shell and no coreutils, see
  [examples/supervisor.vox](examples/supervisor.vox)

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

* Rust >= 1.71 (for building the compiler)
* NASM (Netwide Assembler)
* GNU ld

### Debian / Ubuntu

```sh
sudo apt install nasm cargo make
```

### Fedora

```sh
sudo dnf install nasm rust make
```

---

## Building

```sh
cargo build --release
```

---

## Installing

### RPM-based distros (Copr)

Vox is available via [Copr](https://copr.fedorainfracloud.org/coprs/vox-lang/Vox/)
for Fedora 43, 44, Rawhide, and ELN; RHEL, CentOS Stream 9/10, and EPEL 8/9/10;
openSUSE Leap 16.0; Mageia 9, 10, and Cauldron; Amazon Linux 2023; Azure Linux 3;
and openEuler 22.03/24.03 (mostly x86_64/ppc64le/s390x, some releases also i386
-- see the [project page](https://copr.fedorainfracloud.org/coprs/vox-lang/Vox/)
for the exact architecture list per release; aarch64 and riscv64 aren't
supported yet).

On `dnf`-based distros (Fedora, RHEL, CentOS Stream, EPEL, Amazon Linux,
openEuler):

```sh
sudo dnf copr enable vox-lang/Vox
sudo dnf install vox
```

Libraries live in their own project,
[Vox-lang/vox-libs](https://github.com/Vox-lang/vox-libs), and are optional —
Vox has no standard library and the compiler never needs them. They ship from
the same Copr repository, so no extra setup is required:

```sh
sudo dnf install vox-libs
```

Or with cargo, on any platform with a Rust toolchain — the compiler
carries its own `coreasm` and needs nothing else installed:

```bash
cargo install vox-lang
```

On `zypper`/`urpmi`/`tdnf`-based distros (openSUSE, Mageia, Azure Linux),
grab the matching repo file from the project page instead.

### Nix

Vox also ships as a flake in this repo, so it works straight from the
GitHub URL with no separate registry:

```sh
nix run github:Vox-lang/vox
# or, to install it into your profile:
nix profile install github:Vox-lang/vox
```

From a local clone:

```sh
nix build .#default
./result/bin/vox --version
```

### From source

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

---

## Roadmap

Vox is under active development. Planned work includes:

1. **Networking Abstractions**
   High-level interfaces built on top of system calls, provided via libraries (e.g. HTTP/1.0 reference implementation).

2. **Additional Architectures**
   Planned targets include Win64, AArch64, ARM64, MIPS, and RISC-V.

3. **Multithreading and Polling**
   Higher-level abstractions for multithreading and file descriptor polling (epoll/poll), on top of the process and filesystem interfaces already in place.

4. **Sized Integers**
   Integer widths below the 8-byte slot, and with them exact byte layout control for things (field widths, ordering, padding).

5. **Math and Numeric Optimization**
   Continued optimization of numeric code generation, with a goal of matching or exceeding C performance in benchmarks.

6. **Structured Data and Serialization**
   A JSON/YAML parser and emitter over lists and maps, plus matrices and tuples. See [docs/COLLECTIONS_ROADMAP.md](docs/COLLECTIONS_ROADMAP.md).

---

## Projects built with Vox

Actively developed, free and open-source projects written in Vox:

- **[voxos](https://github.com/TheJostler/voxos)** — a collection of utilities
  and an init for a minimal operating system, written in pure Vox.
- **[vox-fuzz](https://github.com/Vox-lang/vox-fuzz)** — a fuzzer for this
  compiler, written in Vox. It generates random valid programs, compiles
  them, and supervises the binaries natively (fork, non-blocking reap,
  deadline kill, raw wait status) to catch any that die by signal, hang,
  or make the compiler itself fall over. Its first hunt found two
  memory-safety bugs, both fixed in 0.4.3.
- **[vox-libs](https://github.com/Vox-lang/vox-libs)** — shared libraries
  for Vox, written in Vox. Not a standard library: the compiler builds and
  runs with none of them installed.

Building something in Vox? We'd like this list to point to real, actively
maintained FOSS projects — email **info@vox-lang.dev** to have yours added.

---

## Non-Goals

* Free-form natural language interpretation
* JIT compilation or runtime reflection
* *Implicit* dynamic typing or implicit control flow. Types are static by
  default; the dynamic `value` type is an opt-in, declared escape hatch,
  and the compiler refuses to use one in arithmetic until you have checked
  what it holds
* Hiding system behavior behind opaque abstractions
* Language-level runtime systems or background memory management

---

## Status

Vox is experimental but functional.
Core language features are implemented and exercised by real programs, with additional capabilities under active development.

