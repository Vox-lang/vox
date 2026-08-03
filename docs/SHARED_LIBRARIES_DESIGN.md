# Shared Libraries Design Document

> **Status:** Active design document — the authority for the shared-library
> feature. The `see "<lib>" version "<ver>" from "<path>.lib"` form and the
> `.lib`→`.so` chain are the live design, implemented on the code track (plan
> 230, Stages A1–A5); the earlier direct-`.so` model (plan 220) and per-version
> runtime-state mangling (plan 230 explicit non-goal) are abandoned. The
> library-export `<lib>_<ver>_<func>` composition is live (`nm -D` shows e.g.
> `mathkit_1_0_add_two_numbers`). _(assessed 2026-08, vox v0.1.24)_

## Overview

This document outlines the design and implementation considerations for a shared library system in the Vox compiler. The system allows developers to create reusable libraries that can be linked to other programs at compile time, enabling modular code organization and code reuse across multiple projects.

## Core Concepts

### Library Declaration

Any `.vox` file can become a library by adding a library declaration at the beginning:

```
Library 'lib_name' version '1.0'
```

When this declaration is present, the compiler will automatically generate both:
- A `.so` (shared object) file containing the compiled library code
- A `.lib` (library metadata) file containing library information and function signatures

### Library Metadata (.lib files)

The `.lib` file serves as the public interface for the library and contains:

1. **Library Identification**
   - Library name and version
   - Location of the corresponding `.so` file

2. **Table of Contents**
   - Function signatures available for external use
   - Parameter types and names
   - Return type information

Example `.lib` file structure (the normative format — see plan 230, "The `.lib`
format"; the code track emits this in Stage A3 and parses it in A4):
```
Library "flags" version "0.1".
Location "./libflags.so".

Table of Contents:
    To "hasflag" with a text called "flag", returning a boolean.
    To "isverbose", returning a boolean.
    To "wantshelp", returning a boolean.
    To "getoption" with a text called "flag", returning a text.
```

A `.lib` is a sequence of `Library` blocks. Each block has three parts: a
`Library "<name>" version "<ver>"` line, a `Location` line naming the `.so`, and
a `Table of Contents` of exported signatures. Several `Library` blocks may
appear in one `.lib` and parsing runs to EOF — a `Library` line starts a new
block (see "Parsing Multi-Library `.lib` Files" below).

`Location` resolves **relative to the `.lib` first**, then the `--lib-path`
flag, then error. It is relative by norm so a `.lib`/`.so` pair can be moved or
shipped together; an absolute `Location` is honoured when read but never
generated.

Parameter and return types are drawn from a fixed vocabulary — `number`,
`text`, `boolean`, `file`, `value`; anything else is an error naming the
unsupported type. The `, returning a <type>` suffix exists **only** in `.lib`
files: a `.lib` entry is a bodiless declaration, so the return type rides the
signature. In Vox source the return type lives in the body
(`Return a number, x.`), which a bodiless `.lib` line has no room for. An entry
with no `returning` clause denotes a function that returns nothing.

### Library Linking

Programs that want to use a library must include a see statement:

```
see "lib_name" version "1.0" from "Path/to/library.lib".
```

This is the sole canonical form (plan 230, decision 2): `see "<lib>" version
"<ver>" from "<path>.lib".` The earlier `See "…/library.lib" for "lib_name"
"version"` ordering is retired — the compiler's `see` of a `.lib` accepts only
this form, and the old `for`-form produces a diagnostic showing the canonical
syntax. (`see` of a `.vox` file remains a source include and is unchanged.)

This declaration:
- Automatically links the program to the specified library version
- No need for explicit `--link` compiler flags
- Enables compile-time validation of library availability

## Advanced Features

### Multi-Library .so Files

A single `.so` file can contain multiple libraries and different versions. This enables:

- **Backwards Compatibility**: Multiple versions of the same library can coexist
- **Reduced File Count**: Related libraries can be bundled together
- **Version Isolation**: Different versions don't interfere with each other

#### Parsing Multi-Library `.lib` Files

The compiler must parse `.lib` files from top to bottom, treating each `Library "<name>" version "<ver>"` declaration as the start of a new block, each with its own `Location` and `Table of Contents`. Parsing continues until EOF is reached.

> **A `.so` is binary ELF, not text.** An earlier draft of this section said
> the compiler "parses `.so` files" this way — that was the abandoned
> direct-`.so` model. A `.so` carries mangled symbol *names* in `.dynsym` but
> nothing about Vox types, so it cannot be parsed for `Library` blocks or
> signatures. The typed interface that *is* parsed top to bottom is the
> `.lib`: the chain is **`.vox` → `see` a `.lib` → `Location` → `.so`**. The
> `.lib` is the `.h` equivalent; the `.so` it points at is only ever linked,
> never read for types. (The multi-library `.so` *structure* — several
> libraries' mangled symbols bundled in one `.so` — is correct and stays;
> what was wrong was parsing the `.so` itself.)

### Name Mangling

To prevent conflicts and support versioning, all symbols (functions, types, etc.) are mangled in the raw assembly:

```
<LIB_NAME>_<VERSION>_<FUNC_NAME>
```

Examples:
- `flags_0_1_hasflag`
- `flags_0_1_isverbose`
- `flags_1_0_hasflag` (different version, same function name)

This mangling scheme:
- Enables multiple versions of the same function in one `.so`
- Prevents naming conflicts between libraries
- Maintains clean, readable names in `.lib` files
- Supports backwards compatibility when libraries evolve

> **Components are sanitized to valid C identifiers**, so the version `0.1`
> appears as `0_1`. Earlier drafts of this section wrote `flags_0.1_hasflag`;
> NASM accepts the dot, so that form assembles cleanly and only fails when a
> C or Rust consumer tries to name the function — dots are not legal in a C
> identifier. Since a standalone `.so` must be callable from other languages,
> the dot form is unusable.
>
> **Runtime state is deliberately *not* mangled — an explicit non-goal of
> Phase 3.** An earlier draft of this section said `_last_error` and the
> resource tables get per-version mangling (`flags_0_1_last_error`, etc.) so
> two versions inside one `.so` would not share them. **Phase 3 does not do
> this, on purpose.** Multi-input `--shared` compiles several libraries into
> one assembly unit, so the runtime is emitted once and shared by every
> library in that `.so` — which is correct and desirable: one resource
> table, one `.fini_array`, one idempotent `_cleanup_all`. Duplicating the
> runtime per library would multiply the `.so`'s size and give it several
> competing cleanup paths. Cross-`.so` isolation already holds without
> per-version mangling, because each `.so` carries its own runtime and the
> version script keeps those symbols out of `.dynsym`. Only **function
> labels** are mangled (`<lib>_<version>_<func>`); that scheme stands and is
> the project standard in [SYMBOL_MANGLING.md](SYMBOL_MANGLING.md). The
> per-version runtime-state mangling that document also describes is
> superseded by this decision — see plan 230, "Explicit non-goal: runtime
> state is not mangled".

## Implementation Considerations

### Compiler Changes

#### 1. Parser Modifications
- Detect `Library` declarations at file start
- Parse library name and version
- Handle multi-library parsing in `.lib` files
- Parse `See` statements for library linking

#### 2. Symbol Table Management
- Maintain separate symbol tables for each library
- Implement name mangling for all exported symbols
- Track library versions and dependencies

#### 3. Code Generation
- Generate appropriate assembly with mangled names
- Create `.so` files with proper export tables
- Generate `.lib` metadata files

#### 4. Linker Integration
- Resolve library dependencies during compilation
- Validate library availability and version compatibility
- Handle multiple library versions in single `.so` files

### Vox Language Abstraction Considerations

#### High-Level Language Features
The Vox compiler provides sophisticated abstractions that must be preserved in shared libraries:

**Property Access Patterns**
- Expressions like `buffer's size`, `current time's hour` must work across library boundaries
- Property access generates `PropertyAccess` AST nodes that compile to assembly calls
- Libraries must export property access functions with mangled names

**Argument/Environment Expressions**
- `argument's first`, `environment's first` return string pointers
- These expressions have specific type handling (`VarType::String`)
- Libraries using these features must include appropriate coreasm dependencies

**Time Expressions**
- `current time's hour` involves nested property access
- Time functionality requires `time.asm` coreasm inclusion
- Libraries using time features must declare this dependency

#### CoreASM Macro System
The compiler uses a sophisticated macro system that must be handled carefully:

**Macro Dependencies**
- Libraries must track which coreasm files they use (io.asm, time.asm, etc.)
- The `shared_lib_mode` flag already exists in `CodeGenerator`
- Shared libraries exclude coreasm includes but may need selected macros

**Position-Independent Code (PIC)**
- Shared libraries use `default rel` for RIP-relative addressing
- This is already implemented in the existing `shared_lib_mode`

**Function Export Mechanism**
- The `exported_functions` vector tracks functions to export
- Name mangling must be applied before the `global` directive

#### Type System Integration
The compiler's type system must work across library boundaries:

**Variable Type Tracking**
- `variable_types` HashMap tracks `VarType` for each variable
- Types include: `Integer`, `Float`, `String`, `Buffer`, `Boolean`, `Unknown`
- Library signatures must include type information

**Expression Type Inference**
- `is_float_expr()` determines floating-point context
- Property access on time expressions requires special handling
- Type information must be preserved in `.lib` files

### Enhanced Name Mangling Strategy

#### Symbol Types Requiring Mangling
Based on the codebase analysis, these symbols need mangling:

1. **Function Names**
   - User-defined functions: `flags_0_1_hasflag`
   - Property access functions: `flags_0_1_buffer_size`

2. **Property Access Functions**
   - Generated for object properties: `lib_ver_property_name`
   - Time properties: `lib_ver_current_time_hour`

3. **Built-in Expression Wrappers**
   - Argument expressions: `lib_ver_argument_first`
   - Environment expressions: `lib_ver_environment_first`
   - Time expressions: `lib_ver_current_time`

#### Mangling Implementation
```rust
fn mangle_symbol(lib_name: &str, version: &str, symbol: &str) -> String {
    format!("{}_{}_{}", lib_name, version, symbol.replace(' ', "_").replace('\'', "_"))
}
```

### Library Dependency Management

#### CoreASM Feature Tracking
The compiler already tracks feature usage with boolean flags:
- `uses_ints`, `uses_floats`, `uses_files`, `uses_buffers`
- `uses_io`, `uses_format`, `uses_time`, `uses_args`

Libraries must:
1. Track their own feature usage
2. Export this information in `.lib` files
3. Include required macros when generating `.so` files

#### Dependency Resolution
When linking a program that uses libraries:
1. Collect all library dependencies recursively
2. Merge feature requirements
3. Include necessary coreasm files in the final executable
4. Resolve symbol conflicts through mangling

### AST and Code Generation Modifications

#### New AST Nodes
```rust
// Add to ast.rs
Statement::LibraryDecl {
    name: String,
    version: String,
},

Statement::SeeStatement {
    lib_path: String,
    lib_name: String,
    version: String,
},
```

#### Code Generator Extensions
```rust
// Extend CodeGenerator struct
pub struct CodeGenerator {
    // ... existing fields
    current_library: Option<String>,
    current_version: Option<String>,
    library_dependencies: Vec<LibraryDependency>,
}

struct LibraryDependency {
    name: String,
    version: String,
    path: String,
    exported_functions: Vec<FunctionSignature>,
}
```

#### Property Access in Libraries
Property access expressions need special handling:
```rust
Expr::PropertyAccess { object, property } => {
    if self.shared_lib_mode {
        // Generate mangled property access function
        let mangled_name = self.mangle_symbol(&property.to_string());
        self.emit_indent(&format!("call {}", mangled_name));
    } else {
        // Existing property access logic
        // ... current implementation
    }
}
```

### File System and Build Process

#### Multi-Library .so Structure
```
libcombined.so:
├── Library "flags" version "0.1"
│   ├── flags_0_1_hasflag
│   ├── flags_0_1_isverbose
│   └── flags_0_1_getoption
├── Library "utils" version "1.2"
│   ├── utils_1_2_format_string
│   └── utils_1_2_parse_number
└── Library "flags" version "1.0"
    ├── flags_1_0_hasflag (newer version)
    └── flags_1_0_check_flag (new function)
```

#### Build Process Integration
1. **Parse Phase**: Identify library declarations and dependencies
2. **Analysis Phase**: Validate library availability and versions
3. **Code Generation Phase**: Generate mangled symbols and export tables
4. **Link Phase**: Resolve dependencies and create final executable

### Error Handling and Validation

#### Library-Specific Errors
- **Circular Dependencies**: Detect during analysis phase
- **Version Conflicts**: Multiple incompatible versions of same library
- **Missing Symbols**: Referenced but not exported functions
- **Type Mismatches**: Function signature incompatibilities

#### Runtime Considerations
- **Symbol Resolution**: Dynamic loading of mangled symbols
- **Library Initialization**: Proper setup of library state
- **Error Propagation**: Handle library errors in calling code

### File System Organization

#### Recommended Directory Structure
```
project/
├── libs/
│   ├── libflags.so
│   ├── flags.lib
│   ├── libutils.so
│   └── utils.lib
├── src/
│   └── main.vox
└── build/
    └── compiled_program
```

#### Library Discovery

> **Not implemented — future.** The automatic standard-path search and the
> environment variable below are aspirational, not built. Plan 230 specifies no
> automatic discovery: `Location` resolves relative to the `.lib` first, then
> the `--lib-path` flag, then error; `see` of a `.lib` resolves relative to the
> source file, then `--lib-path`. Nothing searches `/usr/lib/vox` or reads an
> env var today. Do not mistake the bullets below for current behaviour — that
> is the same failure mode plan 220 existed to clean up.

- Search standard library paths (`/usr/lib/vox`, `/usr/local/lib/vox`) — *future, not built*
- Support relative and absolute paths in `See` statements — *relative and absolute `Location` paths are honoured on read; see the resolution order above*
- Environment variable for additional library paths — *future, not built*

### Version Management

#### Semantic Versioning
- Use semantic versioning (MAJOR.MINOR.PATCH)
- MAJOR: Breaking changes
- MINOR: New features, backwards compatible
- PATCH: Bug fixes, backwards compatible

#### Compatibility Rules
- Programs specify minimum required version
- Linker selects appropriate available version
- Warn about version mismatches
- Prevent linking to incompatible versions

### Error Handling

#### Library-Related Errors
- **Library Not Found**: Clear error message with search paths
- **Version Mismatch**: Specify available vs required versions
- **Symbol Not Found**: List available symbols in library
- **Circular Dependencies**: Detect and report dependency cycles

#### Runtime Considerations
- **Dynamic Loading**: Load libraries at program startup
- **Symbol Resolution**: Resolve mangled names correctly
- **Error Recovery**: Graceful handling of missing libraries

## Security Considerations

### Library Validation
- Validate library file format and integrity
- Check for malicious code in libraries
- Implement library signing (optional)

### Sandboxing
- Restrict library file system access
- Limit system calls from library code
- Implement memory isolation between libraries

## Performance Optimizations

### Loading Strategies
- **Lazy Loading**: Load libraries only when needed
- **Prelinking**: Resolve symbols at compile time when possible
- **Caching**: Cache library metadata for faster compilation

### Symbol Resolution
- **Hash Tables**: Fast symbol lookup in large libraries
- **Index Files**: Pre-computed symbol indices
- **Compression**: Compress library metadata

## Future Enhancements

### Dynamic Library Loading
- Runtime library loading and unloading
- Plugin architecture support
- Hot-swappable libraries

### Cross-Language Compatibility
- C ABI compatibility for interop with other languages
- Foreign Function Interface (FFI)
- Wrapper generation for existing libraries

### Package Management
- Library repository and package manager
- Automatic dependency resolution
- Version constraint solving

### Development Tools
- Library documentation generator
- Dependency visualization tools
- Library compatibility checker

## Migration Path

### Phase 1: Basic Library Support
- Implement single-library `.so` files
- Basic `.lib` file generation
- Simple linking mechanism

### Phase 2: Multi-Library Support
- Multi-library `.so` files
- Advanced version management
- Name mangling implementation

### Phase 3: Advanced Features
- Dynamic loading
- Package management integration
- Development tooling

## Testing Strategy

### Unit Tests
- Library parsing and generation
- Name mangling correctness
- Version compatibility checking

### Integration Tests
- End-to-end library compilation and linking
- Multi-library `.so` file handling
- Cross-platform compatibility

### Performance Tests
- Library loading performance
- Symbol resolution speed
- Memory usage optimization

## Conclusion

The shared library system provides a robust foundation for modular development in the Vox compiler. By supporting versioning, multi-library files, and clean name mangling, it enables both simple use cases and complex dependency management scenarios.

The design prioritizes:
- **Developer Experience**: Simple syntax, clear error messages
- **Performance**: Efficient loading and symbol resolution
- **Compatibility**: Backwards compatibility and version management
- **Extensibility**: Room for future enhancements and features

This system will significantly enhance the Vox compiler's capabilities for building large, modular applications while maintaining the language's philosophy of readable, intuitive syntax.
