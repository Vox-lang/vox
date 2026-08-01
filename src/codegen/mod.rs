use crate::parser::ast::*;
use std::collections::HashMap;

pub struct CodeGenerator {
    output: String,
    data_section: String,
    bss_section: String,
    functions_section: String,
    label_counter: usize,
    string_counter: usize,
    float_counter: usize,
    variables: HashMap<String, i64>,
    variable_types: HashMap<String, VarType>,
    global_constants: HashMap<String, Expr>,
    list_element_types: HashMap<String, VarType>,
    // Lists proven heterogeneous by the pre-scan pass: their element reads
    // and prints dispatch on the per-slot runtime tag instead of a single
    // static element type. Homogeneous lists never enter this set and keep
    // the statically-typed fast path unchanged.
    mixed_lists: std::collections::HashSet<String>,
    // Scalar variables whose stored value the pre-scan could not prove a type
    // for (e.g. `a text called "s" is element 3 of <mixed list>.`). Their
    // declared type states the author's intent, not what the slot actually
    // holds, so `emit_time_expr_tag` must not claim a tag for them - a
    // TAG_STRING written over a non-pointer makes a tag-dispatching reader
    // dereference an arbitrary integer. See `emit_time_expr_tag`.
    unprovable_scalars: std::collections::HashSet<String>,
    // Stack slot ([rbp - offset]) holding the runtime type tag for each
    // Mixed-typed scalar variable (e.g. a for-each loop variable over a
    // mixed list). Written when the element is read, consulted on print.
    mixed_tag_slots: HashMap<String, i64>,
    file_writable: HashMap<String, bool>,
    stack_offset: i64,
    shared_lib_mode: bool,
    exported_functions: Vec<String>,
    // Per-library exported signatures for the Stage A3 `.lib` interface file:
    // one `LibBlock` per <library, version> identity, in first-seen order, each
    // carrying its functions in source order. Populated by
    // `collect_function_signatures` in shared mode only; empty for non-shared
    // builds. `main.rs` renders this beside the `.so` after a successful link.
    library_blocks: Vec<LibBlock>,
    // The identity of the library currently being compiled, set by a
    // `Library "name" version "x.y".` declaration. In shared library mode
    // this prefixes every exported label (and every intra-library call) as
    // `<lib>_<ver>_<func>` so two libraries linked into one .so can both
    // define `greet` without a duplicate-label collision. `None` outside
    // shared mode (and in shared mode only transiently, before the
    // declaration is seen — `collect_library_identity` runs a pre-pass so
    // the order of `Library` vs `To` in the source does not matter).
    current_library: Option<(String, String)>,
    // Feature tracking for conditional includes
    uses_ints: bool,
    uses_floats: bool,
    uses_files: bool,
    uses_buffers: bool,
    uses_io: bool,
    uses_format: bool,
    uses_time: bool,
    uses_funcs: bool,
    uses_lists: bool,
    // Set when codegen emits any map runtime call (_map_new/_map_insert/
    // _map_lookup/_map_keys/_map_values/_map_print) or a map-tagged dispatch.
    // Gates `%include "coreasm/<arch>/map.asm"`. _map_keys/_map_values also
    // set uses_lists (they return a list struct).
    uses_maps: bool,
    // Set when codegen itself emits a call to _str_eq (string/buffer
    // equality comparisons). Distinct from program.uses_strings, which the
    // analyzer computes from string literals/format strings and may miss
    // a pure variable-vs-variable comparison with no literal operand.
    uses_strings: bool,
    // Declared return type of each user function, keyed by function name.
    // Populated by collect_function_signatures() before codegen so
    // infer_expr_type() can report a FunctionCall's real type instead of
    // silently defaulting to Integer (see collect_function_signatures).
    function_return_types: std::collections::HashMap<String, VarType>,
    // Declared parameter types of each user function, in declaration order.
    // A `value` parameter occupies TWO argument words (payload, tag) in the
    // SysV stream; a scalar parameter occupies one. Both caller and callee
    // derive the word layout from this same vector so they agree.
    function_param_types: std::collections::HashMap<String, Vec<Type>>,
    // Return type of the function currently being codegen'd (None at top
    // level). When it is `Type::Value`, the `Return` path must leave the
    // value's runtime tag in r11 for the caller to consume.
    current_function_return_type: Option<Type>,
    loop_stack: Vec<(String, String)>, // (continue_label, break_label)
    flag_schemas: Vec<FlagSchemaRuntime>,
    parsed_args_active: bool,
    global_var_labels: HashMap<String, String>,
    global_var_counter: usize,
    in_function_codegen: bool,
    target_arch: String,
}

#[derive(Clone)]
struct FlagSchemaRuntime {
    name: String,
    short: String,
    long: String,
    value_type: FlagValueType,
    required: bool,
}

#[derive(Clone, PartialEq)]
enum VarType {
    Integer,
    Float,       // 64-bit IEEE 754 double
    String,      // Raw string pointer (from lists, etc.)
    Buffer,      // Dynamic buffer struct (has header)
    List,        // List struct [length, elem0, elem1, ...]
    Map,         // Map struct (tag 5); key/value collection
    Boolean,
    Mixed,       // Runtime-tagged value from a heterogeneous list; the
                 // actual type is dispatched via a per-slot tag byte
    Unknown,
}

// Per-slot list type tags. Must match LIST_TAG_* in coreasm/*/list.asm.
// 0 is integer so zero-filled (mmap'd) tag regions default correctly.
const TAG_INTEGER: u8 = 0;
const TAG_STRING: u8 = 1;
const TAG_FLOAT: u8 = 2;
const TAG_BOOLEAN: u8 = 3;
const TAG_LIST: u8 = 4;
const TAG_MAP: u8 = 5;
const TAG_NOTHING: u8 = 6;

/// Turn an author-written name into an assembly symbol, per the project
/// standard in `docs/SYMBOL_MANGLING.md`.
///
/// Every character outside `[A-Za-z0-9_]` becomes `_`, and a leading digit is
/// prefixed with `_`. The target is a valid **C** identifier, not merely a
/// valid NASM one: NASM happily assembles `my.helper` and `flags_0.1_hasflag`,
/// so a dot survives all the way to the symbol table and only fails when a C
/// or Rust consumer tries to name the function — which is the entire point of
/// a standalone `.so`. Catching it here keeps that failure impossible.
///
/// Used for function labels today and for the `<lib>_<version>_<name>` library
/// mangling when shared libraries land, so both go through one rule.
pub(crate) fn mangle_symbol(name: &str) -> String {
    let mut out = sanitize_symbol(name);
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// The per-character sanitizer that is the core of `mangle_symbol`: every
/// character outside `[A-Za-z0-9_]` becomes `_`. This is the ONE sanitizer —
/// `mangle_symbol` layers the leading-digit prefix on top, and the library
/// mangling applies it per component (prefixing only the first, since a digit
/// may start an interior component without making the whole joined symbol an
/// invalid C identifier). Factoring it out keeps a second sanitizer from
/// being written, per plan 230.
fn sanitize_symbol(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 1);
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

/// The library mangling: `<lib>_<version>_<func>`, built by applying the
/// shared `sanitize_symbol` to each of the three components and joining with
/// `_`. The library component goes through the full `mangle_symbol` (with the
/// leading-digit prefix) because it STARTS the symbol — a digit there would
/// make the whole result an invalid C identifier. The version and function
/// components are interior (joined with `_`), so a leading digit there is
/// fine and the prefix would only insert a spurious double underscore:
/// `1.0` sanitizes to `1_0`, giving `mathkit_1_0_greet` as the plan specifies
/// — not `mathkit__1_0_greet`, which a literal `mangle_symbol("1.0")` (whose
/// leading-digit rule turns `1.0` into `_1_0`) would produce. This is the
/// only place the three-component form is built — both the definition label
/// and the call site resolve through it, so a .so that defines
/// `mathkit_1_0_greet` also calls `mathkit_1_0_greet`, never the bare `greet`
/// it would otherwise emit.
pub(crate) fn mangle_library_symbol(lib: &str, version: &str, func: &str) -> String {
    format!(
        "{}_{}_{}",
        mangle_symbol(lib),
        sanitize_symbol(version),
        sanitize_symbol(func)
    )
}

/// The assembly label a function DEFINED in this compilation emits, independent
/// of any `CodeGenerator` state. This is the ONE rule both the codegen and the
/// analyzer use to key their per-function symbol tables, so the tables are
/// scoped by `<library, version>` rather than by the authored name: two
/// libraries in one .so each defining `greet` produce two distinct keys
/// (`alpha_1_0_greet`, `beta_2_0_greet`) instead of colliding on the bare
/// `greet`. In shared mode with an identity set, the key is the
/// `<lib>_<ver>_<func>` mangled label; otherwise (non-shared, or shared before
/// a `Library` declaration is seen) it is the plain `mangle_symbol(name)`,
/// preserving today's single-library and executable behaviour exactly. The
/// `current_lib` is passed in rather than read from a field so the pre-passes
/// that walk statements in order can track the identity in a local without
/// disturbing `self.current_library` (which the main generate walk owns).
pub(crate) fn make_function_label(
    shared: bool,
    current_lib: Option<&(String, String)>,
    name: &str,
) -> String {
    if shared {
        if let Some((lib, ver)) = current_lib {
            return mangle_library_symbol(lib, ver, name);
        }
    }
    mangle_symbol(name)
}

// ---- Stage A3: the `.lib` interface file emitted beside each `.so` ----
//
// A `--shared` build writes `<output-stem>.lib` beside the `.so`: one `Library`
// block per input, a `Location` relative to the `.lib`, and a `Table of
// Contents` of every exported signature. Stage A4 parses this back to type-check
// `see` calls, so the format is a contract: emit what the source declares, one
// entry per line (never wrapped), parameters joined with ` and ` exactly as Vox
// source joins them, and a `value` parameter/return rendered by its type name
// alone (the `value` ABI is fixed, so nothing about it is per-function).

/// One exported function's signature for the `.lib` table of contents: the
/// authored name, the full parameter list (name + type), and the declared
/// return type. The return type is read from the `Return a <type>,` annotation
/// (the only place Vox source states it); a bodiless `.lib` declaration has no
/// body, hence `, returning a <type>` existing only in `.lib` files.
#[derive(Debug, Clone, PartialEq)]
pub struct LibFunction {
    pub name: String,
    pub params: Vec<(String, Type)>,
    pub return_type: Type,
}

/// One `Library` block in a `.lib`: a <library, version> identity and the
/// exported functions declared under it, in source order. A multi-input
/// `--shared` build produces several blocks in one `.lib`, one per input.
#[derive(Debug, Clone, PartialEq)]
pub struct LibBlock {
    pub lib: String,
    pub version: String,
    pub funcs: Vec<LibFunction>,
}

/// Author-facing noun for a parameter type, matching the Vox source vocabulary
/// the parser accepts in `with a <type> called <name>` (`number`, `text`,
/// `boolean`, `file`, `buffer`, `list`, `map`, `value`). Returns `None` for
/// `Unknown` (an untyped `with n` parameter) and types the parser never produces
/// in a parameter position (`Float`/`decimal`, `Time`, `Timer`, `Void`).
fn param_type_noun(t: &Type) -> Option<&'static str> {
    match t {
        Type::Integer => Some("number"),
        Type::String => Some("text"),
        Type::Boolean => Some("boolean"),
        Type::File => Some("file"),
        Type::Buffer => Some("buffer"),
        Type::List(_) => Some("list"),
        Type::Map(_) => Some("map"),
        Type::Value => Some("value"),
        _ => None,
    }
}

/// Author-facing noun for a return type, matching the vocabulary the parser
/// accepts in `Return a <type>,` (`number`, `text`, `boolean`, `file`,
/// `value`). Returns `None` for `Void` (no `, returning` clause — the function
/// returns nothing) and types the return-annotation parser never produces
/// (`Float`, `Buffer`, `List`, `Map`, `Time`, `Timer`).
fn return_type_noun(t: &Type) -> Option<&'static str> {
    match t {
        Type::Integer => Some("number"),
        Type::String => Some("text"),
        Type::Boolean => Some("boolean"),
        Type::File => Some("file"),
        Type::Value => Some("value"),
        _ => None,
    }
}

/// Render the `.lib` text for `blocks` (one per library identity, in order)
/// whose `.so` is named `so_filename` (basename only — the `.lib` sits beside
/// it, so the `Location` is `./<so_filename>`, relative to the `.lib`). Each
/// table-of-contents entry is exactly one line, however long; entries are never
/// wrapped. A parameterless, void-returning function reads `To "name".`; a
/// `value` parameter or return needs only its type name (`a value called "v"`,
/// `, returning a value`).
pub fn render_lib_file(blocks: &[LibBlock], so_filename: &str) -> String {
    let mut out = String::new();
    for (i, block) in blocks.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!("Library \"{}\" version \"{}\".\n", block.lib, block.version));
        out.push_str(&format!("Location \"./{}\".\n", so_filename));
        out.push_str("\nTable of Contents:\n");
        for func in &block.funcs {
            out.push_str("    To \"");
            out.push_str(&func.name);
            out.push('"');
            if !func.params.is_empty() {
                out.push_str(" with ");
                let joined = func
                    .params
                    .iter()
                    .map(|(pname, ptype)| {
                        // An untyped (`Unknown`) parameter has no noun the `.lib`
                        // can express; render it as `number`, the 1-word scalar
                        // default an untyped parameter occupies (see
                        // `emit_function_call`'s `word_count`). Library authors
                        // should type their exports; see the A3 report for the
                        // caveat.
                        let noun = param_type_noun(ptype).unwrap_or("number");
                        format!("a {} called \"{}\"", noun, pname)
                    })
                    .collect::<Vec<_>>()
                    .join(" and ");
                out.push_str(&joined);
            }
            if let Some(rnoun) = return_type_noun(&func.return_type) {
                out.push_str(&format!(", returning a {}", rnoun));
            }
            out.push_str(".\n");
        }
    }
    out
}

/// Three-state result of statically classifying an expression into a list
/// slot tag for the pre-scan. `Known(tag)` is a proof: the value's type is
/// certain. `Unknowable` means no static proof is possible — stage 1b widens
/// the list to `Mixed` rather than optimistically guessing a type ("static is
/// a proof; mixed is the default").
#[derive(Clone, Copy, PartialEq, Eq)]
enum TagInfo {
    Known(u8),
    Unknowable,
}

/// Map a known `VarType` to its list slot tag. Returns `None` for `Mixed`
/// and `Unknown` (and anything without a single static tag): those need a
/// runtime tag (stage 1d) or the `TAG_INTEGER` fallback at the append site.
/// A `List` value in a slot is provably tag 4 (stage 1e1 activated the
/// reserved LIST tag for nested lists).
fn vartype_to_tag(vt: VarType) -> Option<u8> {
    match vt {
        VarType::Integer => Some(TAG_INTEGER),
        VarType::Float => Some(TAG_FLOAT),
        VarType::String | VarType::Buffer => Some(TAG_STRING),
        VarType::Boolean => Some(TAG_BOOLEAN),
        VarType::List => Some(TAG_LIST),
        VarType::Map => Some(TAG_MAP),
        // Mixed/Unknown: no single static tag — runtime tag (1d) or fallback.
        _ => None,
    }
}

/// Map a declared `Type` to the list slot tag a value of that type would
/// carry. Used to seed the pre-scan env from a variable's declared type
/// (a static proof) when the initializer's own type can't be inferred — e.g.
/// `a buffer called "b" is 4 bytes in size.` (the size expr is opaque, but
/// the declared type `buffer` proves the slot tag is `TAG_STRING`). Returns
/// `None` for non-scalar, non-list types (File/Time/Timer/Void/Unknown). A
/// `List` value carries tag 4 (stage 1e1) — this arm is load-bearing for the
/// `is a list` predicate, whose codegen does
/// `type_to_tag(type_noun).expect("type predicate noun is scalar")`.
fn type_to_tag(t: &Type) -> Option<u8> {
    match t {
        Type::Integer => Some(TAG_INTEGER),
        Type::Float => Some(TAG_FLOAT),
        Type::String => Some(TAG_STRING),
        Type::Boolean => Some(TAG_BOOLEAN),
        Type::Buffer => Some(TAG_STRING),
        Type::List(_) => Some(TAG_LIST),
        Type::Map(_) => Some(TAG_MAP),
        // File/Time/Timer/Void/Unknown: no scalar slot tag.
        _ => None,
    }
}

/// Where a value's runtime type tag lives once the value has been emitted.
/// See `CodeGenerator::runtime_tag_source`.
enum RuntimeTagSource {
    /// A mixed-list read left the slot's tag byte in r11. Must be consumed
    /// immediately - any call or syscall clobbers r11.
    R11,
    /// A Mixed variable's tag, at this rbp offset.
    ShadowSlot(i64),
}

/// Author-facing name for a type-predicate noun, for asm comments.
fn type_noun_name(t: &Type) -> &'static str {
    match t {
        Type::Integer => "number",
        Type::Float => "decimal",
        Type::String => "text",
        Type::Boolean => "boolean",
        Type::List(_) => "list",
        Type::Map(_) => "map",
        _ => "type",
    }
}

#[derive(Clone, Debug, PartialEq)]
enum IntegerBase {
    Decimal,
    HexLower,
    HexUpper,
    Binary,
    Octal,
}

#[derive(Clone, Debug, PartialEq)]
struct FormatSpec {
    width: Option<i32>,
    zero_pad: bool,
    base: IntegerBase,
    precision: Option<i32>,
}

/// Outcome of resolve_format_variable - how a `{name}` format part's value
/// was resolved, so each sink (print / buffer append) can render it.
enum FormatPartValue {
    /// Code was emitted leaving the value (or pointer) in rax; the VarType
    /// tells the sink how to render it (None = integer-ish fallback).
    Loaded(Option<VarType>),
    /// The part resolved to a compile-time string constant.
    Literal(String),
    /// Unknown name - sinks render the `{name}` placeholder literally.
    Unknown,
}

impl CodeGenerator {
    pub fn new() -> Self {
        CodeGenerator {
            output: String::new(),
            data_section: String::new(),
            bss_section: String::new(),
            functions_section: String::new(),
            label_counter: 0,
            string_counter: 0,
            float_counter: 0,
            variables: HashMap::new(),
            variable_types: HashMap::new(),
            global_constants: HashMap::new(),
            list_element_types: HashMap::new(),
            mixed_lists: std::collections::HashSet::new(),
            unprovable_scalars: std::collections::HashSet::new(),
            mixed_tag_slots: HashMap::new(),
            file_writable: HashMap::new(),
            stack_offset: 0,
            shared_lib_mode: false,
            exported_functions: Vec::new(),
            library_blocks: Vec::new(),
            current_library: None,
            uses_ints: false,
            uses_floats: false,
            uses_files: false,
            uses_buffers: false,
            uses_io: false,
            uses_format: false,
            uses_time: false,
            uses_funcs: false,
            uses_lists: false,
            uses_maps: false,
            uses_strings: false,
            function_return_types: std::collections::HashMap::new(),
            function_param_types: std::collections::HashMap::new(),
            current_function_return_type: None,
            loop_stack: Vec::new(),
            flag_schemas: Vec::new(),
            parsed_args_active: false,
            global_var_labels: HashMap::new(),
            global_var_counter: 0,
            in_function_codegen: false,
            target_arch: "x86_64".to_string(),
        }
    }

    fn ensure_global_var_label(&mut self, name: &str) {
        if self.global_var_labels.contains_key(name) {
            return;
        }
        let label = format!("gvar_{}", self.global_var_counter);
        self.global_var_counter += 1;
        self.global_var_labels.insert(name.to_string(), label.clone());
        self.bss_section.push_str(&format!("    {}: resq 1\n", label));
    }

    fn global_var_label(&self, name: &str) -> Option<&String> {
        self.global_var_labels.get(name)
    }

    /// Assign bss mirror labels to every definitely-declared main-line
    /// name (see collect_definite_decls): an `Open ... called "output"`
    /// present in BOTH arms of an if/otherwise still executes in _start's
    /// frame on every path, so functions must be able to reach it via its
    /// mirror global exactly like a top-level declaration. Uses the same
    /// walker as the analyzer so the two can never disagree. Names are
    /// sorted so label numbering stays deterministic across builds.
    fn collect_global_var_labels(&mut self, stmts: &[Statement]) {
        let definite = collect_definite_decls(stmts);
        let mut names: Vec<&String> = definite.keys().collect();
        names.sort();
        for name in names {
            self.ensure_global_var_label(name);
        }
        for stmt in stmts {
            if let Statement::FlagSchemaDecl { name, .. } = stmt {
                self.ensure_global_var_label(name);
            }
        }
    }

    fn emit_mirror_stack_var_to_global_if_needed(&mut self, name: &str, offset: i64) {
        if !self.in_function_codegen {
            if let Some(label) = self.global_var_label(name).cloned() {
                self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                self.emit_indent(&format!("mov [rel {}], rax", label));
            }
        }
    }

    fn emit_load_named_var_into_rax(&mut self, name: &str) -> bool {
        if let Some(offset) = self.get_var(name) {
            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
            true
        } else if let Some(label) = self.global_var_label(name).cloned() {
            self.emit_indent(&format!("mov rax, [rel {}]", label));
            true
        } else {
            false
        }
    }

    /// Load the address/pointer of a named variable into `rax`, looking in both
    /// the local function frame and the global BSS mirrors used for
    /// top-level/branch-declared names. Returns true if the name was found.
    fn emit_load_named_var_addr(&mut self, name: &str) -> bool {
        if let Some(offset) = self.get_var(name) {
            self.emit_indent(&format!("mov rax, [rbp-{}]  ; local {}", offset, name));
            true
        } else if let Some(label) = self.global_var_label(name).cloned() {
            self.emit_indent(&format!("mov rax, [rel {}]  ; global mirror {}", label, name));
            true
        } else {
            false
        }
    }

    fn emit_clear_buffer_slot(&mut self, offset: i64) {
        self.uses_buffers = true;
        self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
        self.emit_indent("call _buffer_clear");
        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
    }

    fn emit_append_literal_to_buffer_slot(&mut self, offset: i64, text: &str) {
        self.uses_buffers = true;
        let label = self.add_string(text);
        self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
        self.emit_indent(&format!("lea rsi, [rel {}]", label));
        self.emit_indent(&format!("mov rdx, {}_len", label));
        self.emit_indent("call _buffer_append_bytes");
        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
    }

    fn emit_append_formatted_int_to_buffer(&mut self, fmt: FormatSpec) {
        self.uses_buffers = true;
        let (base, uppercase) = match fmt.base {
            IntegerBase::Decimal => (0, 0),
            IntegerBase::HexLower => (1, 0),
            IntegerBase::HexUpper => (1, 1),
            IntegerBase::Binary => (2, 0),
            IntegerBase::Octal => (3, 0),
        };
        let width = fmt.width.unwrap_or(0);
        let zero_pad = if fmt.zero_pad { 1 } else { 0 };

        self.emit_indent("mov rsi, rax");
        self.emit_indent(&format!("mov rdx, {}", width));
        self.emit_indent(&format!("mov rcx, {}", zero_pad));
        self.emit_indent(&format!("mov r8, {}", base));
        self.emit_indent(&format!("mov r9, {}", uppercase));
        self.emit_indent("call _buffer_append_formatted_int");
    }

    fn emit_append_runtime_value_to_buffer_ptr(&mut self, value_type: Option<VarType>, fmt: FormatSpec) {
        match value_type {
            Some(VarType::Buffer) => {
                self.uses_buffers = true;
                self.emit_indent("mov rsi, rax");
                self.emit_indent("call _buffer_append");
            }
            Some(VarType::String) => {
                self.uses_buffers = true;
                self.emit_indent("mov rsi, rax");
                self.emit_indent("call _buffer_append_cstr");
            }
            _ => {
                self.emit_append_formatted_int_to_buffer(fmt);
            }
        }
    }

    fn emit_append_runtime_value_to_buffer_slot(
        &mut self,
        offset: i64,
        value_type: Option<VarType>,
        fmt: FormatSpec,
    ) {
        self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
        self.emit_append_runtime_value_to_buffer_ptr(value_type, fmt);
        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
    }

    /// Resolve a `{name}` format part: emit code leaving the runtime value
    /// (or pointer) in rax, and classify what was found. This is THE single
    /// name-resolution path shared by every format-string sink - Print, the
    /// buffer set/copy/append writers, and the expression materializer that
    /// write payloads, paths, and text initializers go through. Special
    /// names, variable/global lookup, and the constant fallback must never
    /// be re-implemented per sink: that duplication is exactly how the
    /// buffer sinks shipped without `{current time's hour}` support while
    /// Print had it.
    fn resolve_format_variable(&mut self, name: &str) -> FormatPartValue {
        match name {
            "current time's hour" => {
                self.emit_indent("TIME_GET");
                self.emit_indent("TIME_GET_HOUR rax");
                self.uses_time = true;
                FormatPartValue::Loaded(Some(VarType::Integer))
            }
            "current time's minute" => {
                self.emit_indent("TIME_GET");
                self.emit_indent("TIME_GET_MINUTE rax");
                self.uses_time = true;
                FormatPartValue::Loaded(Some(VarType::Integer))
            }
            "current time's second" => {
                self.emit_indent("TIME_GET");
                self.emit_indent("TIME_GET_SECOND rax");
                self.uses_time = true;
                FormatPartValue::Loaded(Some(VarType::Integer))
            }
            "arguments's count" | "argument's count" => {
                self.generate_expr(&Expr::ArgumentCount);
                FormatPartValue::Loaded(Some(VarType::Integer))
            }
            "arguments's name" | "argument's name" => {
                self.generate_expr(&Expr::ArgumentName);
                FormatPartValue::Loaded(Some(VarType::String))
            }
            "arguments's first" | "argument's first" => {
                self.generate_expr(&Expr::ArgumentFirst);
                FormatPartValue::Loaded(Some(VarType::String))
            }
            "arguments's last" | "argument's last" => {
                self.generate_expr(&Expr::ArgumentLast);
                FormatPartValue::Loaded(Some(VarType::String))
            }
            _ => {
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                    FormatPartValue::Loaded(self.variable_types.get(name).cloned())
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    self.emit_indent(&format!("mov rax, [rel {}]", label));
                    FormatPartValue::Loaded(self.variable_types.get(name).cloned())
                } else if let Some(expr) = self.global_constants.get(name).cloned() {
                    match expr {
                        Expr::StringLit(s) => FormatPartValue::Literal(s),
                        Expr::IntegerLit(n) => {
                            self.emit_indent(&format!("mov rax, {}", n));
                            FormatPartValue::Loaded(Some(VarType::Integer))
                        }
                        Expr::BoolLit(b) => {
                            self.emit_indent(&format!("mov rax, {}", if b { 1 } else { 0 }));
                            FormatPartValue::Loaded(Some(VarType::Integer))
                        }
                        _ => FormatPartValue::Unknown,
                    }
                } else {
                    FormatPartValue::Unknown
                }
            }
        }
    }

    fn emit_format_parts_into_buffer_slot(&mut self, offset: i64, parts: &[FormatPart], clear_first: bool) {
        if clear_first {
            self.emit_clear_buffer_slot(offset);
        }

        for part in parts {
            match part {
                FormatPart::Literal(s) => self.emit_append_literal_to_buffer_slot(offset, s),
                FormatPart::Variable { name, format } => {
                    match self.resolve_format_variable(name) {
                        FormatPartValue::Loaded(value_type) => {
                            let fmt_spec = self.parse_format_spec(format.as_deref());
                            self.emit_append_runtime_value_to_buffer_slot(offset, value_type, fmt_spec);
                        }
                        FormatPartValue::Literal(s) => {
                            self.emit_append_literal_to_buffer_slot(offset, &s);
                        }
                        FormatPartValue::Unknown => {
                            // Same placeholder Print renders for unknown names
                            let placeholder = format!("{{{}}}", name);
                            self.emit_append_literal_to_buffer_slot(offset, &placeholder);
                        }
                    }
                }
                FormatPart::Expression { expr, format } => {
                    self.generate_expr(expr);
                    let expr_type = self.infer_expr_type(expr);
                    let fmt_spec = self.parse_format_spec(format.as_deref());
                    self.emit_append_runtime_value_to_buffer_slot(offset, expr_type, fmt_spec);
                }
            }
        }
    }

    fn emit_format_parts_into_buffer(
        &mut self,
        dst_local: Option<i64>,
        dst_global: Option<&str>,
        parts: &[FormatPart],
    ) {
        let load_dst = |this: &mut Self| {
            if let Some(offset) = dst_local {
                this.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
            } else if let Some(label) = dst_global {
                this.emit_indent(&format!("mov rdi, [rel {}]", label));
            }
        };

        for part in parts {
            load_dst(self);
            self.emit_indent("push rdi  ; save destination buffer pointer");
            match part {
                FormatPart::Literal(s) => {
                    let label = self.add_string(s);
                    self.emit_indent(&format!("lea rsi, [rel {}]", label));
                    self.emit_indent(&format!("mov rdx, {}_len", label));
                    self.emit_indent("call _buffer_append_bytes");
                }
                FormatPart::Variable { name, format } => {
                    match self.resolve_format_variable(name) {
                        FormatPartValue::Loaded(value_type) => {
                            let fmt_spec = self.parse_format_spec(format.as_deref());
                            self.emit_append_runtime_value_to_buffer_ptr(value_type, fmt_spec);
                        }
                        FormatPartValue::Literal(s) => {
                            let label = self.add_string(&s);
                            self.emit_indent(&format!("lea rsi, [rel {}]", label));
                            self.emit_indent(&format!("mov rdx, {}_len", label));
                            self.emit_indent("call _buffer_append_bytes");
                        }
                        FormatPartValue::Unknown => {
                            let placeholder = format!("{{{}}}", name);
                            let label = self.add_string(&placeholder);
                            self.emit_indent(&format!("lea rsi, [rel {}]", label));
                            self.emit_indent(&format!("mov rdx, {}_len", label));
                            self.emit_indent("call _buffer_append_bytes");
                        }
                    }
                }
                FormatPart::Expression { expr, format } => {
                    self.generate_expr(expr);
                    let expr_type = self.infer_expr_type(expr);
                    let fmt_spec = self.parse_format_spec(format.as_deref());
                    self.emit_append_runtime_value_to_buffer_ptr(expr_type, fmt_spec);
                }
            }
            if let Some(offset) = dst_local {
                self.emit_indent(&format!("mov [rbp-{}], rax", offset));
            } else if let Some(label) = dst_global {
                self.emit_indent(&format!("mov [rel {}], rax", label));
            }
            self.emit_indent("pop rsi  ; discard saved pointer copy");
        }
    }

    fn emit_copy_expr_into_buffer_slot(
        &mut self,
        value: &Expr,
        clear_first: bool,
        dst_local: Option<i64>,
        dst_global: Option<&str>,
    ) -> bool {
        let emit_dst_load = |this: &mut Self| {
            if let Some(offset) = dst_local {
                this.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
            } else if let Some(label) = dst_global {
                this.emit_indent(&format!("mov rdi, [rel {}]", label));
            }
        };
        let emit_dst_store = |this: &mut Self| {
            if let Some(offset) = dst_local {
                this.emit_indent(&format!("mov [rbp-{}], rax", offset));
            } else if let Some(label) = dst_global {
                this.emit_indent(&format!("mov [rel {}], rax", label));
            }
        };

        match value {
            Expr::FormatString { parts } => {
                if clear_first {
                    emit_dst_load(self);
                    self.emit_indent("push rdi");
                    self.emit_indent("call _buffer_clear");
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("pop rsi  ; discard original pointer copy");
                }
                self.emit_format_parts_into_buffer(dst_local, dst_global, parts);
                true
            }
            Expr::StringLit(s) => {
                if self.variable_types.get(s) == Some(&VarType::Buffer) {
                    if let Some(src_offset) = self.get_var(s) {
                        self.uses_buffers = true;
                        emit_dst_load(self);
                        self.emit_indent(&format!("mov rsi, [rbp-{}]", src_offset));
                        self.emit_indent(if clear_first { "call _buffer_copy" } else { "call _buffer_append" });
                        emit_dst_store(self);
                        return true;
                    } else if let Some(label) = self.global_var_label(s).cloned() {
                        self.uses_buffers = true;
                        emit_dst_load(self);
                        self.emit_indent(&format!("mov rsi, [rel {}]", label));
                        self.emit_indent(if clear_first { "call _buffer_copy" } else { "call _buffer_append" });
                        emit_dst_store(self);
                        return true;
                    }
                }

                if clear_first {
                    if let Some(offset) = dst_local {
                        self.emit_clear_buffer_slot(offset);
                    } else if let Some(label) = dst_global {
                        self.emit_indent(&format!("mov rdi, [rel {}]", label));
                        self.emit_indent("call _buffer_clear");
                        self.emit_indent(&format!("mov [rel {}], rax", label));
                    }
                }
                if let Some(offset) = dst_local {
                    self.emit_append_literal_to_buffer_slot(offset, s);
                } else if let Some(label) = dst_global {
                    let lit_label = self.add_string(s);
                    self.emit_indent(&format!("mov rdi, [rel {}]", label));
                    self.emit_indent(&format!("lea rsi, [rel {}]", lit_label));
                    self.emit_indent(&format!("mov rdx, {}_len", lit_label));
                    self.emit_indent("call _buffer_append_bytes");
                    self.emit_indent(&format!("mov [rel {}], rax", label));
                }
                true
            }
            Expr::Identifier(name) => {
                if self.variable_types.get(name) == Some(&VarType::Buffer) {
                    if let Some(src_offset) = self.get_var(name) {
                        self.uses_buffers = true;
                        emit_dst_load(self);
                        self.emit_indent(&format!("mov rsi, [rbp-{}]", src_offset));
                        self.emit_indent(if clear_first { "call _buffer_copy" } else { "call _buffer_append" });
                        emit_dst_store(self);
                        return true;
                    } else if let Some(label) = self.global_var_label(name).cloned() {
                        self.uses_buffers = true;
                        emit_dst_load(self);
                        self.emit_indent(&format!("mov rsi, [rel {}]", label));
                        self.emit_indent(if clear_first { "call _buffer_copy" } else { "call _buffer_append" });
                        emit_dst_store(self);
                        return true;
                    }
                }
                false
            }
            _ => false,
        }
    }

    fn quoted_name_var_type(&self, name: &str) -> Option<VarType> {
        self.variable_types
            .get(name)
            .cloned()
            .or_else(|| {
                self.global_var_label(name)
                    .map(|_| self.variable_types.get(name).cloned().unwrap_or(VarType::Unknown))
            })
            .filter(|t| *t != VarType::Unknown)
    }
    
    fn emit_function_call(&mut self, name: &str, args: &[Expr]) {
        let param_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

        // A `value` parameter occupies TWO argument words (payload, tag) in the
        // SysV stream; a scalar parameter occupies one. We push words
        // right-to-left so word 0 (param 0 payload) ends on top (first pop).
        // When the callee's signature is unknown (e.g. an extern/builtin),
        // assume every parameter is scalar — preserving the original ABI for
        // statically-typed calls (criterion 6). The signature tables are keyed
        // by the function's mangled label (`<lib>_<ver>_<func>` in shared
        // mode, `mangle_symbol(name)` otherwise), so the lookup goes through
        // `function_label` — which reads the current library, the one whose
        // function body we are generating.
        let label = self.function_label(name);
        let param_types = self.function_param_types.get(&label).cloned().unwrap_or_default();
        let is_value_param = |i: usize| -> bool {
            param_types.get(i) == Some(&Type::Value)
        };
        // Number of argument words a given arg contributes.
        let word_count = |i: usize| if is_value_param(i) { 2 } else { 1 };
        let total_words: usize = (0..args.len()).map(word_count).sum();

        // Evaluate/push all arg words right-to-left. For a `value` param the
        // tag word is pushed BEFORE the payload word, so the payload lands on
        // top (lower word index) — matching how the callee reads them.
        for i in (0..args.len()).rev() {
            self.generate_expr(&args[i]); // rax = payload
            if is_value_param(i) {
                self.emit_load_value_tag(&args[i]); // r11 = tag (rax preserved)
                self.emit_indent("push r11  ; value param tag word");
            }
            self.emit_indent("push rax");
        }

        // Pop the first 6 argument WORDS into registers (word 0 -> rdi, ...).
        let reg_words = total_words.min(param_regs.len());
        for reg in param_regs.iter().take(reg_words) {
            self.emit_indent(&format!("pop {}", reg));
        }

        // Remaining words (7th+) stay on the stack.
        let stack_words = total_words.saturating_sub(param_regs.len());
        let stack_word_bytes = stack_words * 8;

        // Align stack before call (SysV: 16B-aligned at call instruction).
        let needs_pad = !stack_words.is_multiple_of(2);
        if needs_pad {
            self.emit_indent("sub rsp, 8  ; align stack before call");
        }

        // In shared library mode a call to a function DEFINED in this
        // library must target the same `<lib>_<ver>_<func>` label the
        // definition emitted — otherwise the .so defines
        // `mathkit_1_0_greet` while the call site branches to the bare
        // `greet`, which the version script does not export. The signature
        // tables are keyed by that mangled label, so `contains_key(&label)`
        // is true exactly for a function defined in the CURRENT library
        // (whose identity `function_label` reads). A call to a function in
        // a DIFFERENT library of the same .so never reaches here: the
        // analyzer scopes its own `functions` set per library, so a
        // cross-library name is the existing "Unknown function" error
        // before codegen runs. An (A4) extern or a runtime helper is not in
        // the table, so it falls through to the plain mangled name. Non-
        // shared builds take the plain path unconditionally (`label` is
        // already `mangle_symbol(name)` there), so their output is byte-
        // identical to today.
        let func_label = if self.shared_lib_mode
            && self.function_return_types.contains_key(&label)
        {
            label
        } else {
            mangle_symbol(name)
        };
        self.emit_indent(&format!("call {}", func_label));

        // Clean up stack words + pad (caller cleanup in SysV). The return tag
        // for a `value`-returning function rides in r11; `add rsp` does not
        // clobber it, so a caller that consumes the result sees r11=tag.
        let cleanup = stack_word_bytes + if needs_pad { 8 } else { 0 };
        if cleanup > 0 {
            self.emit_indent(&format!("add rsp, {}", cleanup));
        }
    }

    pub fn set_shared_lib_mode(&mut self, enabled: bool) {
        self.shared_lib_mode = enabled;
    }

    /// Resolve the assembly label for a function DEFINED in this compilation.
    /// In shared library mode with a library identity set, the label is
    /// `<lib>_<ver>_<func>` (each component through `mangle_symbol`); this is
    /// what makes two libraries in one .so both defining `greet` emit two
    /// distinct labels. In every other case it is the plain `mangle_symbol`
    /// of the name, so non-shared builds are byte-identical to today.
    fn function_label(&self, name: &str) -> String {
        make_function_label(self.shared_lib_mode, self.current_library.as_ref(), name)
    }

    /// Pre-pass: find the `Library` declaration that names this compilation's
    /// identity and stash it in `current_library` before any function is
    /// generated. Running this up front (rather than only when the statement
    /// is reached during `generate`) means the order of `Library` vs `To` in
    /// the source is irrelevant — a forward call to a function defined above
    /// the declaration still mangles correctly. The analyzer has already
    /// rejected `--shared` with no `Library` line, so in shared mode exactly
    /// one is expected; the first wins and a second is left for A2 to reject.
    fn collect_library_identity(&mut self, program: &Program) {
        for stmt in &program.statements {
            if let Statement::LibraryDecl { name, version } = stmt {
                self.current_library = Some((name.clone(), version.clone()));
                return;
            }
        }
    }

    /// The mangled labels of functions exported by a `--shared` compile, in
    /// emission order. Populated during `generate`; the linker's version
    /// script names exactly these as the library's public symbols.
    pub fn exported_functions(&self) -> &[String] {
        &self.exported_functions
    }

    /// The per-library exported signatures for the Stage A3 `.lib` interface
    /// file: one `LibBlock` per <library, version> identity, in first-seen
    /// order, each carrying its functions in source order. Empty for non-shared
    /// builds. `main.rs` renders this beside the `.so` after a successful link.
    pub fn library_blocks(&self) -> &[LibBlock] {
        &self.library_blocks
    }

    pub fn set_target_arch(&mut self, arch: &str) {
        self.target_arch = arch.to_string();
    }
    
    fn new_label(&mut self, prefix: &str) -> String {
        let label = format!(".{}_{}", prefix, self.label_counter);
        self.label_counter += 1;
        label
    }
    
    fn add_string(&mut self, s: &str) -> String {
        let label = format!("str_{}", self.string_counter);
        self.string_counter += 1;
        
        let escaped: String = s.chars().map(|c| {
            match c {
                '\n' => "', 10, '".to_string(),
                '\t' => "', 9, '".to_string(),
                '\r' => "', 13, '".to_string(),
                '\'' => "', 39, '".to_string(),  // Escape apostrophe for NASM
                _ => c.to_string(),
            }
        }).collect();
        
        self.data_section.push_str(&format!("    {}: db '{}', 0\n", label, escaped));
        self.data_section.push_str(&format!("    {}_len: equ $ - {} - 1\n", label, label));
        label
    }
    
    fn add_float(&mut self, f: f64) -> String {
        let label = format!("float_{}", self.float_counter);
        self.float_counter += 1;
        
        // Store as 64-bit IEEE 754 double
        let bits = f.to_bits();
        self.data_section.push_str(&format!("    {}: dq 0x{:016X}  ; {}\n", label, bits, f));
        label
    }
    
    fn alloc_var(&mut self, name: &str) -> i64 {
        self.stack_offset += 8;
        self.variables.insert(name.to_string(), self.stack_offset);
        self.stack_offset
    }
    
    fn get_var(&self, name: &str) -> Option<i64> {
        self.variables.get(name).copied()
    }

    fn collect_global_constants(&mut self, program: &Program) {
        self.global_constants.clear();
        for stmt in &program.statements {
            if let Statement::VarDecl { name, value: Some(expr), .. } = stmt {
                if matches!(expr, Expr::StringLit(_) | Expr::IntegerLit(_) | Expr::BoolLit(_)) {
                    self.global_constants.insert(name.clone(), expr.clone());
                }
            }
        }
    }

    // Record each function's declared return type so infer_expr_type() can
    // resolve Expr::FunctionCall correctly instead of falling through to
    // its generic "Integer for anything unrecognized" default. Without
    // this, reassigning an EXISTING variable from a function call (`the x
    // is "some func" of y.`) silently corrupted the variable's tracked
    // type to Integer - a fresh `a text called "x" is ...` declaration
    // happened to read the correct type from a different code path and
    // was unaffected, which is what made this easy to miss.
    fn collect_function_signatures(&mut self, program: &Program) {
        self.function_return_types.clear();
        self.function_param_types.clear();
        // Track the library identity as we walk so each function is keyed by
        // its OWN `<lib>_<ver>_<func>` label, not the authored name. This is
        // what scopes the signature tables: two libraries in one .so each
        // defining `greet` get distinct keys, so the second no longer silently
        // overwrites the first's return/parameter types (the wrong-code bug A1
        // found). A local, not `self.current_library`, so this pre-pass does
        // not disturb the identity the main generate walk manages.
        let mut current_lib: Option<(String, String)> = None;
        // Stage A3: collect per-library exported signatures for the `.lib`
        // interface file, in the same single walk. Shared mode only — a
        // non-shared build has no `Library` blocks and writes no `.lib`. The
        // block list is keyed by <lib, version> (first-seen order), so two
        // versions of one library become two blocks, each carrying its own
        // functions in source order. A function with no current_lib in shared
        // mode is a malformed input the analyzer has already rejected, so it
        // is skipped here rather than crash the collector.
        let mut lib_blocks: Vec<LibBlock> = Vec::new();
        let mut block_idx: HashMap<(String, String), usize> = HashMap::new();
        for stmt in &program.statements {
            match stmt {
                Statement::LibraryDecl { name, version } => {
                    current_lib = Some((name.clone(), version.clone()));
                }
                Statement::FunctionDef { name, params, return_type, .. } => {
                    let key = make_function_label(
                        self.shared_lib_mode,
                        current_lib.as_ref(),
                        name,
                    );
                    let vt = match return_type {
                        Type::Integer => VarType::Integer,
                        Type::Float => VarType::Float,
                        Type::String => VarType::String,
                        Type::Boolean => VarType::Boolean,
                        Type::Buffer => VarType::Buffer,
                        Type::List(_) => VarType::List,
                        // A `value` return is dynamic: the runtime tag travels
                        // back in r11 alongside the payload in rax, so the
                        // result is a Mixed-typed value (no static tag).
                        Type::Value => VarType::Mixed,
                        _ => VarType::Unknown,
                    };
                    self.function_return_types.insert(key.clone(), vt);
                    self.function_param_types
                        .insert(key, params.iter().map(|(_, t)| t.clone()).collect());

                    if self.shared_lib_mode {
                        if let Some((lib, ver)) = current_lib.as_ref() {
                            let id = (lib.clone(), ver.clone());
                            let idx = match block_idx.get(&id) {
                                Some(&i) => i,
                                None => {
                                    let i = lib_blocks.len();
                                    block_idx.insert(id, i);
                                    lib_blocks.push(LibBlock {
                                        lib: lib.clone(),
                                        version: ver.clone(),
                                        funcs: Vec::new(),
                                    });
                                    i
                                }
                            };
                            lib_blocks[idx].funcs.push(LibFunction {
                                name: name.clone(),
                                params: params.clone(),
                                return_type: return_type.clone(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        self.library_blocks = lib_blocks;
    }

    fn collect_flag_schemas(&mut self, program: &Program) {
        self.flag_schemas.clear();
        for stmt in &program.statements {
            if let Statement::FlagSchemaDecl {
                name,
                short,
                long,
                value_type,
                required,
                ..
            } = stmt
            {
                self.flag_schemas.push(FlagSchemaRuntime {
                    name: name.clone(),
                    short: short.clone(),
                    long: long.clone(),
                    value_type: value_type.clone(),
                    required: *required,
                });
            }
        }
    }

    fn emit_flag_parse_routine(&mut self) {
        if self.flag_schemas.is_empty() {
            return;
        }

        // The routine calls _str_eq to match argument tokens against flag
        // aliases, so string.asm must be included even when the program
        // itself uses no other strings. Without this, a program that
        // declares and parses flags but never prints/compares text failed
        // to assemble with "symbol `_str_eq' not defined".
        self.uses_strings = true;

        self.emit_indent("; Runtime flag schema parsing");
        self.emit_indent("call _reset_parsed_args");

        let schemas = self.flag_schemas.clone();
        let mut seen_entries: Vec<(FlagSchemaRuntime, i64, i64)> = Vec::new();
        for schema in &schemas {
            let flag_offset = if let Some(off) = self.get_var(&schema.name) {
                off
            } else {
                self.alloc_var(&schema.name)
            };
            let seen_offset = self.alloc_var(&format!("__flag_seen_{}", schema.name.replace(' ', "_")));
            self.emit_indent(&format!("mov qword [rbp-{}], 0", seen_offset));
            seen_entries.push((schema.clone(), seen_offset, flag_offset));
        }

        let argc_off = self.alloc_var("__flag_parse_argc");
        let idx_off = self.alloc_var("__flag_parse_idx");
        let cur_off = self.alloc_var("__flag_parse_cur");
        let stop_off = self.alloc_var("__flag_parse_stop");

        self.emit_indent("call _get_raw_argc");
        self.emit_indent(&format!("mov [rbp-{}], rax", argc_off));
        self.emit_indent(&format!("mov qword [rbp-{}], 0", idx_off));
        self.emit_indent(&format!("mov qword [rbp-{}], 0", stop_off));

        let loop_label = self.new_label("flag_parse_loop");
        let done_label = self.new_label("flag_parse_done");
        let append_pos_label = self.new_label("flag_parse_append_positional");
        let continue_label = self.new_label("flag_parse_continue");

        let stop_token = self.add_string("--");
        self.emit(&format!("{}:", loop_label));
        self.emit_indent(&format!("mov rax, [rbp-{}]", idx_off));
        self.emit_indent(&format!("cmp rax, [rbp-{}]", argc_off));
        self.emit_indent(&format!("jge {}", done_label));

        self.emit_indent("mov rdi, rax");
        self.emit_indent("call _get_raw_arg");
        self.emit_indent(&format!("mov [rbp-{}], rax", cur_off));

        self.emit_indent(&format!("cmp qword [rbp-{}], 0", stop_off));
        self.emit_indent(&format!("jne {}", append_pos_label));

        let not_stop_label = self.new_label("flag_parse_not_stop");
        self.emit_indent(&format!("mov rdi, [rbp-{}]", cur_off));
        self.emit_indent(&format!("lea rsi, [rel {}]", stop_token));
        self.emit_indent("call _str_eq");
        self.emit_indent("test rax, rax");
        self.emit_indent(&format!("jz {}", not_stop_label));
        self.emit_indent(&format!("mov qword [rbp-{}], 1", stop_off));
        self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
        self.emit_indent(&format!("jmp {}", continue_label));
        self.emit(&format!("{}:", not_stop_label));

        let mut next_check_label = append_pos_label.clone();
        for (schema, seen_off, flag_off) in &seen_entries {
            let no_match_label = self.new_label("flag_no_match");
            let matched_label = self.new_label("flag_matched");

            let short_label = self.add_string(&schema.short);
            self.emit_indent(&format!("mov rdi, [rbp-{}]", cur_off));
            self.emit_indent(&format!("lea rsi, [rel {}]", short_label));
            self.emit_indent("call _str_eq");
            self.emit_indent("test rax, rax");
            self.emit_indent(&format!("jnz {}", matched_label));

            let long_label = self.add_string(&schema.long);
            self.emit_indent(&format!("mov rdi, [rbp-{}]", cur_off));
            self.emit_indent(&format!("lea rsi, [rel {}]", long_label));
            self.emit_indent("call _str_eq");
            self.emit_indent("test rax, rax");
            self.emit_indent(&format!("jz {}", no_match_label));

            self.emit(&format!("{}:", matched_label));
            match schema.value_type {
                FlagValueType::Boolean => {
                    self.emit_indent(&format!("mov qword [rbp-{}], 1", flag_off));
                    self.emit_indent(&format!("mov qword [rbp-{}], 1", seen_off));
                    self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
                    self.emit_indent(&format!("jmp {}", continue_label));
                }
                FlagValueType::Text | FlagValueType::Number => {
                    self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
                    self.emit_indent(&format!("mov rax, [rbp-{}]", idx_off));
                    self.emit_indent(&format!("cmp rax, [rbp-{}]", argc_off));
                    self.emit_indent(&format!("jge {}", done_label));
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("call _get_raw_arg");
                    if matches!(schema.value_type, FlagValueType::Number) {
                        self.uses_ints = true;
                        self.emit_indent("mov rdi, rax");
                        self.emit_indent("call _parse_i64");
                    }
                    self.emit_indent(&format!("mov [rbp-{}], rax", flag_off));
                    self.emit_indent(&format!("mov qword [rbp-{}], 1", seen_off));
                    self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
                    self.emit_indent(&format!("jmp {}", continue_label));
                }
            }

            self.emit(&format!("{}:", no_match_label));
            next_check_label = no_match_label;
        }

        // Fall through from last no-match to positional append
        self.emit_indent(&format!("jmp {}", append_pos_label));

        self.emit(&format!("{}:", append_pos_label));
        self.emit_indent(&format!("mov rdi, [rbp-{}]", cur_off));
        self.emit_indent("call _append_parsed_arg");
        self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
        self.emit_indent(&format!("jmp {}", continue_label));

        self.emit(&format!("{}:", continue_label));
        self.emit_indent(&format!("jmp {}", loop_label));

        self.emit(&format!("{}:", done_label));
        for (schema, seen_off, _) in &seen_entries {
            if schema.required {
                let ok_label = self.new_label("flag_required_ok");
                self.emit_indent(&format!("cmp qword [rbp-{}], 1", seen_off));
                self.emit_indent(&format!("je {}", ok_label));
                self.emit_indent("EXIT 1");
                self.emit(&format!("{}:", ok_label));
            }
        }
        for (schema, _, flag_off) in &seen_entries {
            if let Some(label) = self.global_var_label(&schema.name).cloned() {
                self.emit_indent(&format!("mov rax, [rbp-{}]", flag_off));
                self.emit_indent(&format!("mov [rel {}], rax", label));
            }
        }
        let _ = next_check_label;
    }

    fn emit_global_constant_format_fallback(&mut self, name: &str, format: Option<&String>) -> bool {
        let Some(expr) = self.global_constants.get(name).cloned() else {
            return false;
        };

        match expr {
            Expr::StringLit(s) => {
                let label = self.add_string(&s);
                self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                true
            }
            Expr::IntegerLit(n) => {
                self.emit_indent(&format!("mov rdi, {}", n));
                let fmt_spec = self.parse_format_spec(format.map(|s| s.as_str()));
                self.emit_formatted_value(Some(VarType::Integer), fmt_spec);
                true
            }
            Expr::BoolLit(b) => {
                self.emit_indent(&format!("mov rdi, {}", if b { 1 } else { 0 }));
                let fmt_spec = self.parse_format_spec(format.map(|s| s.as_str()));
                self.emit_formatted_value(Some(VarType::Integer), fmt_spec);
                true
            }
            _ => false,
        }
    }
    
    fn is_float_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::FloatLit(_) => true,
            Expr::StringLit(s) => self.quoted_name_var_type(s) == Some(VarType::Float),
            Expr::Identifier(name) => {
                self.variable_types.get(name) == Some(&VarType::Float)
            }
            Expr::Cast { target_type, .. } => {
                // Cast to float produces a float
                matches!(target_type, Type::Float)
            }
            Expr::BinaryOp { left, op, right } => {
                // Comparison and boolean operators return integers, not floats
                // But arithmetic with floats returns floats
                match op {
                    BinaryOperator::Equal | BinaryOperator::NotEqual |
                    BinaryOperator::Greater | BinaryOperator::Less |
                    BinaryOperator::GreaterEqual | BinaryOperator::LessEqual |
                    BinaryOperator::And | BinaryOperator::Or => false,
                    _ => self.is_float_expr(left) || self.is_float_expr(right),
                }
            }
            Expr::UnaryOp { operand, .. } => self.is_float_expr(operand),
            _ => false,
        }
    }

    fn is_buffer_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::StringLit(s) => self.quoted_name_var_type(s) == Some(VarType::Buffer),
            Expr::Identifier(name) => {
                self.variable_types.get(name) == Some(&VarType::Buffer)
            }
            _ => false,
        }
    }

    fn is_boolean_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::BoolLit(_) => true,
            Expr::Identifier(name) => self.variable_types.get(name) == Some(&VarType::Boolean),
            Expr::Cast { target_type, .. } => matches!(target_type, Type::Boolean),
            Expr::UnaryOp { op: UnaryOperator::Not, .. } => true,
            Expr::BinaryOp { op, .. } => {
                matches!(op,
                    BinaryOperator::Equal | BinaryOperator::NotEqual |
                    BinaryOperator::Greater | BinaryOperator::Less |
                    BinaryOperator::GreaterEqual | BinaryOperator::LessEqual |
                    BinaryOperator::And | BinaryOperator::Or)
            }
            _ => false,
        }
    }

    /// Emit code for an equality comparison between two stringy (String or
    /// Buffer) expressions. Routes to _mem_eq when either side is a buffer
    /// (length-bounded, avoids NUL-scanning stale bytes after clear+rewrite)
    /// and falls back to _str_eq for pure string/string comparisons.
    /// Result in rax: 1 = equal, 0 = not equal.
    fn emit_stringy_equality(&mut self, left: &Expr, right: &Expr) {
        self.uses_strings = true;
        let left_is_buf = self.is_buffer_expr(left);
        let right_is_buf = self.is_buffer_expr(right);

        if left_is_buf || right_is_buf {
            // At least one side is a buffer - use _mem_eq(ptr1, ptr2, len1, len2).
            // Evaluate both sides, keeping data ptrs and lengths on the stack.

            // --- RIGHT side ---
            if right_is_buf {
                self.generate_expr(right);           // rax = struct ptr
                self.emit_indent("push rax           ; R: struct ptr");
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _buffer_length");
                self.emit_indent("push rax           ; R: len");
                self.emit_indent("mov rdi, [rsp+8]   ; reload struct ptr");
                self.emit_indent("call _buffer_data");
                self.emit_indent("push rax           ; R: data ptr");
                // stack (top): R_data | R_len | R_struct
            } else {
                self.generate_cstr_expr(right);      // rax = NUL-term str ptr
                self.emit_indent("push rax           ; R: str ptr");
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _str_len");
                self.emit_indent("push rax           ; R: len");
                // stack (top): R_len | R_str_ptr  (use R_str_ptr as data ptr later)
            }

            // --- LEFT side ---
            if left_is_buf {
                self.generate_expr(left);            // rax = struct ptr
                self.emit_indent("push rax           ; L: struct ptr");
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _buffer_length");
                self.emit_indent("mov rdx, rax       ; len1 = L len");
                self.emit_indent("mov rdi, [rsp]     ; reload L struct ptr");
                self.emit_indent("call _buffer_data");
                self.emit_indent("mov rdi, rax       ; ptr1 = L data");
                self.emit_indent("pop rax            ; drop L struct ptr");
            } else {
                self.generate_cstr_expr(left);       // rax = NUL-term str ptr
                self.emit_indent("mov rdi, rax       ; ptr1 = L str");
                self.emit_indent("push rdi");
                self.emit_indent("call _str_len");
                self.emit_indent("mov rdx, rax       ; len1 = L len");
                self.emit_indent("pop rdi            ; restore ptr1");
            }

            // --- Restore RIGHT from stack into rsi (ptr2) and rcx (len2) ---
            if right_is_buf {
                self.emit_indent("pop rsi            ; ptr2 = R data");
                self.emit_indent("pop rcx            ; len2 = R len");
                self.emit_indent("pop rax            ; drop R struct ptr");
            } else {
                self.emit_indent("pop rcx            ; len2 = R len");
                self.emit_indent("pop rsi            ; ptr2 = R str");
            }

            self.emit_indent("call _mem_eq");
        } else {
            // Pure string/string - both NUL-terminated, _str_eq is correct
            self.generate_cstr_expr(right);
            self.emit_indent("push rax  ; park right operand");
            self.generate_cstr_expr(left);
            self.emit_indent("mov rdi, rax  ; left operand");
            self.emit_indent("pop rsi  ; right operand");
            self.emit_indent("call _str_eq");
        }
    }
    
    // Check if operands involve floats (for choosing comparison instructions)
    fn has_float_operands(&self, expr: &Expr) -> bool {
        match expr {
            Expr::FloatLit(_) => true,
            Expr::StringLit(s) => self.quoted_name_var_type(s) == Some(VarType::Float),
            Expr::Identifier(name) => {
                self.variable_types.get(name) == Some(&VarType::Float)
            }
            Expr::Cast { target_type, .. } => {
                // A cast to float yields a float operand - must route through
                // the float arithmetic path, not the integer one. Without this
                // arm, `{s as a float} add 1` took the integer path and did
                // INT_ADD on the float's bit pattern (garbage). Mirrors
                // is_float_expr, which already handled this case.
                matches!(target_type, Type::Float)
            }
            Expr::BinaryOp { left, right, .. } => {
                self.has_float_operands(left) || self.has_float_operands(right)
            }
            Expr::UnaryOp { operand, .. } => self.has_float_operands(operand),
            _ => false,
        }
    }

    fn emit(&mut self, code: &str) {
        self.output.push_str(code);
        self.output.push('\n');
    }
    
    fn emit_indent(&mut self, code: &str) {
        self.output.push_str("    ");
        self.output.push_str(code);
        self.output.push('\n');
    }

    fn argument_view_uses_parsed(&self) -> bool {
        self.parsed_args_active
    }
    
    /// Static classification of an expression into a list slot tag, using
    /// only what is provable without emitting code. `env` maps scalar
    /// variable names to their inferred `TagInfo`; `list_seen_tags` records
    /// the single proven element type of each homogeneous list, so reads of
    /// `first`/`last`/`element N of` such a list are themselves provable.
    ///
    /// Sound by design: only literals, tracked scalars, functions with a
    /// declared return type, casts, provable binary/unary ops, and reads of
    /// homogeneous lists yield `Known`. Everything else is `Unknowable`, so
    /// the join in `prescan_note_list_value` widens the list to `Mixed`
    /// rather than guessing (stage 1b — "static is a proof; mixed is the
    /// default").
    fn prescan_expr_tag(
        &self,
        e: &Expr,
        env: &HashMap<String, TagInfo>,
        list_seen_tags: &HashMap<String, u8>,
    ) -> TagInfo {
        match e {
            Expr::IntegerLit(_) => TagInfo::Known(TAG_INTEGER),
            Expr::FloatLit(_) => TagInfo::Known(TAG_FLOAT),
            Expr::BoolLit(_) => TagInfo::Known(TAG_BOOLEAN),
            // The nothing/null literal is tag 6 (stage 1e3).
            Expr::NothingLit => TagInfo::Known(TAG_NOTHING),
            // A list value in a slot is tag 4 (stage 1e1). This makes a
            // homogeneous list-of-lists `[[1,2],[3,4]]` prove a single tag
            // (4) and stay non-mixed, while a mixed `[1, [2,3], "four"]` still
            // widens (tags {0, 4, 1}).
            Expr::ListLit { .. } => TagInfo::Known(TAG_LIST),
            // A map value in a slot is tag 5 (stage 1e2).
            Expr::MapLit { .. } => TagInfo::Known(TAG_MAP),
            // A type predicate yields a boolean, so appending its result to a
            // list does not widen the list (stage 1c).
            Expr::TypeCheck { .. } => TagInfo::Known(TAG_BOOLEAN),
            Expr::StringLit(s) => {
                // A quoted name can be a variable reference in Vox; if we
                // tracked it as a scalar, use that. Otherwise it's a string.
                match env.get(s) {
                    Some(info) => *info,
                    None => TagInfo::Known(TAG_STRING),
                }
            }
            Expr::Identifier(name) => match env.get(name) {
                Some(info) => *info,
                None => TagInfo::Unknowable,
            },
            // Function results and casts: their type comes from declared
            // metadata (function_return_types / the cast target), not from
            // operand variable_types, so infer_expr_type is sound here and
            // agrees with the tag written at emit time.
            Expr::FunctionCall { .. } | Expr::Cast { .. } => {
                match self.infer_expr_type(e).and_then(vartype_to_tag) {
                    Some(t) => TagInfo::Known(t),
                    None => TagInfo::Unknowable,
                }
            }
            Expr::UnaryOp { op, operand } => {
                // Logical negation is always a boolean, regardless of the
                // operand's type (`not 5` is a boolean), so tag it TAG_BOOLEAN
                // and keep `prescan_expr_tag` consistent with
                // `emit_time_expr_tag`. Other unary ops (e.g. arithmetic
                // negation) keep the operand's tag.
                if matches!(op, UnaryOperator::Not) {
                    TagInfo::Known(TAG_BOOLEAN)
                } else {
                    self.prescan_expr_tag(operand, env, list_seen_tags)
                }
            }
            Expr::BinaryOp { left, op, right } => {
                let lt = self.prescan_expr_tag(left, env, list_seen_tags);
                let rt = self.prescan_expr_tag(right, env, list_seen_tags);
                match (lt, rt) {
                    (TagInfo::Unknowable, _) | (_, TagInfo::Unknowable) => {
                        TagInfo::Unknowable
                    }
                    (TagInfo::Known(lt), TagInfo::Known(rt)) => {
                        let arithmetic = matches!(
                            op,
                            BinaryOperator::Add | BinaryOperator::Subtract
                            | BinaryOperator::Multiply | BinaryOperator::Divide
                            | BinaryOperator::Modulo
                        );
                        if arithmetic && (lt == TAG_FLOAT || rt == TAG_FLOAT) {
                            TagInfo::Known(TAG_FLOAT)
                        } else {
                            // Non-arithmetic ops (comparison/logical/bitwise)
                            // yield 0/1 integers, matching infer_expr_type's
                            // `_ => Some(VarType::Integer)` arm for them.
                            TagInfo::Known(TAG_INTEGER)
                        }
                    }
                }
            }
            Expr::PropertyAccess { object, property } => match property {
                ObjectProperty::First | ObjectProperty::Last => {
                    self.prescan_list_read_tag(object, list_seen_tags)
                }
                ObjectProperty::Size | ObjectProperty::Capacity => {
                    TagInfo::Known(TAG_INTEGER)
                }
                _ => TagInfo::Unknowable,
            },
            Expr::ElementAccess { list, .. } => match list.as_ref() {
                Expr::Identifier(name) | Expr::StringLit(name) => {
                    self.prescan_list_read_tag(name, list_seen_tags)
                }
                _ => TagInfo::Unknowable,
            },
            _ => TagInfo::Unknowable,
        }
    }

    /// Proven slot tag for reading one element out of `name` (`element N of`,
    /// `first`, `last`). `list_seen_tags` records the first element tag proven
    /// for a list and is deliberately never retracted, so it alone is NOT a
    /// proof of homogeneity: a list that starts `[1, 2]` and is later appended
    /// a text still has `Known(TAG_INTEGER)` recorded. Consulting
    /// `mixed_lists` is what makes the read sound — a widened list yields
    /// `Unknowable`, so whatever receives the element widens too rather than
    /// reinterpreting a string pointer as a number. The fixed-point loop in
    /// `prescan_mixed_lists` guarantees the widening is visible here even when
    /// the read appears earlier in the program than the write that widens.
    fn prescan_list_read_tag(
        &self,
        name: &str,
        list_seen_tags: &HashMap<String, u8>,
    ) -> TagInfo {
        if self.mixed_lists.contains(name) {
            return TagInfo::Unknowable;
        }
        match list_seen_tags.get(name) {
            Some(t) => TagInfo::Known(*t),
            None => TagInfo::Unknowable,
        }
    }

    /// Proven slot tag for a `For each <var> in <collection>` loop variable,
    /// derived from the collection's element type. A range yields integers;
    /// a list literal yields its (single) element tag; a homogeneous list
    /// variable yields its recorded tag; `arguments` yields strings. Anything
    /// else is `Unknowable`, so appending the loop variable widens rather
    /// than guesses. Used to seed `env` before walking the loop body.
    fn foreach_loop_var_tag(
        &self,
        collection: &Expr,
        env: &HashMap<String, TagInfo>,
        list_seen_tags: &HashMap<String, u8>,
    ) -> TagInfo {
        match collection {
            Expr::Range { .. } => TagInfo::Known(TAG_INTEGER),
            Expr::ArgumentAll | Expr::ArgumentRaw => TagInfo::Known(TAG_STRING),
            Expr::ListLit { elements } => {
                if elements.is_empty() {
                    return TagInfo::Unknowable;
                }
                let mut tags: Vec<u8> = Vec::new();
                for e in elements {
                    match self.prescan_expr_tag(e, env, list_seen_tags) {
                        TagInfo::Known(t) => {
                            if !tags.contains(&t) {
                                tags.push(t);
                            }
                        }
                        TagInfo::Unknowable => return TagInfo::Unknowable,
                    }
                }
                if tags.len() == 1 {
                    TagInfo::Known(tags[0])
                } else {
                    TagInfo::Unknowable
                }
            }
            Expr::Identifier(name) | Expr::StringLit(name) => {
                self.prescan_list_read_tag(name, list_seen_tags)
            }
            _ => TagInfo::Unknowable,
        }
    }

    /// Pre-scan pass: walk the whole program and decide, before any code is
    /// emitted, which lists are heterogeneous ("mixed"). A list is mixed
    /// when its homogeneity cannot be *proven* — i.e. some write is of an
    /// `Unknowable` type, or two writes provably differ in type (a mixed
    /// list literal, or an append/element-set whose value's tag conflicts
    /// with the list's established element type).
    ///
    /// Stage 1b flipped the default: a value whose type can't be proven
    /// (e.g. a function result without a declared return type) widens the
    /// list to `Mixed` so elements are never silently reinterpreted. Lists
    /// whose every write is provably one type keep the untagged fast path.
    /// Aliasing a mixed list (`a list called "b" is the a.`) propagates
    /// mixedness.
    fn prescan_mixed_lists(&mut self, statements: &[Statement]) {
        // Iterate to a fixed point so aliases and later evidence propagate
        // regardless of declaration order. Termination: each pass only ever
        // *adds* to `mixed_lists`, which is bounded by the number of list
        // names, so the loop always converges.
        let mut env: HashMap<String, TagInfo> = HashMap::new();
        let mut list_seen_tags: HashMap<String, u8> = HashMap::new();
        loop {
            let before = self.mixed_lists.len();
            env.clear();
            list_seen_tags.clear();
            self.prescan_walk(statements, &mut env, &mut list_seen_tags);
            if self.mixed_lists.len() == before {
                // Converged. `env` now holds the final verdict per scalar;
                // carry the unprovable ones into codegen so emit-time tag
                // selection agrees with the pre-scan instead of trusting a
                // declared type that the initializer never established.
                self.unprovable_scalars = env
                    .iter()
                    .filter(|(_, info)| matches!(info, TagInfo::Unknowable))
                    .map(|(name, _)| name.clone())
                    .collect();
                break;
            }
        }
    }

    /// Join a write's `TagInfo` into a list's running element-type record.
    /// `Known(t)` conflicts with a different prior tag (or joins an
    /// established one); `Unknowable` widens the list straight to `Mixed`
    /// (the write's type can't be proven, so homogeneity can't be claimed).
    fn prescan_note_list_value(
        &mut self,
        list: &str,
        tag: TagInfo,
        list_seen_tags: &mut HashMap<String, u8>,
    ) {
        match tag {
            TagInfo::Known(t) => match list_seen_tags.get(list) {
                Some(prev) if *prev != t => {
                    self.mixed_lists.insert(list.to_string());
                }
                Some(_) => {}
                None => {
                    list_seen_tags.insert(list.to_string(), t);
                }
            },
            TagInfo::Unknowable => {
                self.mixed_lists.insert(list.to_string());
            }
        }
    }

    fn prescan_walk(
        &mut self,
        statements: &[Statement],
        env: &mut HashMap<String, TagInfo>,
        list_seen_tags: &mut HashMap<String, u8>,
    ) {
        for stmt in statements {
            match stmt {
                Statement::VarDecl { name, value, var_type, .. } => {
                    // A declared scalar type is a static proof of the slot tag
                    // and seeds `env` even when the initializer is opaque (e.g.
                    // `a buffer called "b" is 4 bytes in size.` — the size expr
                    // is unknowable, but the declared `buffer` type proves the
                    // tag is `TAG_STRING`, so appending it doesn't widen).
                    let declared_tag = var_type.as_ref().and_then(type_to_tag);
                    match value {
                        Some(Expr::ListLit { elements }) => {
                            let mut tags: Vec<u8> = Vec::new();
                            let mut unknowable = false;
                            for e in elements {
                                match self.prescan_expr_tag(e, env, list_seen_tags) {
                                    TagInfo::Known(t) => {
                                        if !tags.contains(&t) {
                                            tags.push(t);
                                        }
                                    }
                                    TagInfo::Unknowable => unknowable = true,
                                }
                            }
                            // A list holding `nothing` is treated as mixed even
                            // when every element is nothing: the fast path
                            // reads a slot without its tag, and a nothing slot
                            // read that way is indistinguishable from 0.
                            if unknowable || tags.len() > 1 || tags.contains(&TAG_NOTHING) {
                                self.mixed_lists.insert(name.clone());
                            } else if let Some(t) = tags.first() {
                                list_seen_tags.insert(name.clone(), *t);
                            }
                        }
                        // Alias: `a list called "b" is the a.` inherits
                        // mixedness (both names refer to the same block).
                        Some(Expr::Identifier(src)) | Some(Expr::StringLit(src)) => {
                            if self.mixed_lists.contains(src) {
                                self.mixed_lists.insert(name.clone());
                            } else if let Some(t) = list_seen_tags.get(src).copied() {
                                list_seen_tags.insert(name.clone(), t);
                            } else if let Some(t) = declared_tag {
                                env.insert(name.clone(), TagInfo::Known(t));
                            } else {
                                // Scalar alias with no declared scalar type:
                                // track its provability (Unknowable overwrites
                                // a prior Known, so a later reassignment taints).
                                let info = self.prescan_expr_tag(
                                    value.as_ref().unwrap(),
                                    env,
                                    list_seen_tags,
                                );
                                env.insert(name.clone(), info);
                            }
                        }
                        Some(other) => {
                            // The initializer decides, not the declaration: a
                            // declared type is the author's intent, while the
                            // tag must describe the bits that actually land in
                            // the slot. `a text called "s" is element 3 of m.`
                            // (m mixed) stores whatever element 3 holds, which
                            // may not be a string pointer - trusting `text`
                            // here would write TAG_STRING over an integer and
                            // make a tag-dispatching reader dereference it.
                            // (`a buffer called "b" is 4 bytes in size.` does
                            // not reach this arm; it parses to BufferDecl,
                            // handled below.)
                            let info = self.prescan_expr_tag(other, env, list_seen_tags);
                            env.insert(name.clone(), info);
                        }
                        None => {
                            // No initializer: nothing foreign has been stored,
                            // so the declared type does prove the slot's tag.
                            if let Some(t) = declared_tag {
                                env.insert(name.clone(), TagInfo::Known(t));
                            }
                        }
                    }
                }
                // A buffer (fixed-size `is N bytes in size` or `Create a
                // buffer`) appends as a string-tagged slot, so record it as
                // Known(TAG_STRING) — otherwise appending it would widen.
                Statement::BufferDecl { name, .. } => {
                    env.insert(name.clone(), TagInfo::Known(TAG_STRING));
                }
                Statement::Assignment { name, value } => {
                    if let Expr::ListLit { elements } = value {
                        let mut tags: Vec<u8> = Vec::new();
                        let mut unknowable = false;
                        for e in elements {
                            match self.prescan_expr_tag(e, env, list_seen_tags) {
                                TagInfo::Known(t) => {
                                    if !tags.contains(&t) {
                                        tags.push(t);
                                    }
                                }
                                TagInfo::Unknowable => unknowable = true,
                            }
                        }
                        if unknowable || tags.len() > 1 || tags.contains(&TAG_NOTHING) {
                            self.mixed_lists.insert(name.clone());
                        } else if let Some(t) = tags.first() {
                            self.prescan_note_list_value(
                                name,
                                TagInfo::Known(*t),
                                list_seen_tags,
                            );
                        }
                    } else {
                        let info = self.prescan_expr_tag(value, env, list_seen_tags);
                        env.insert(name.clone(), info);
                    }
                }
                Statement::ListAppend { list, value } => {
                    let tag = self.prescan_expr_tag(value, env, list_seen_tags);
                    self.prescan_note_list_value(list, tag, list_seen_tags);
                }
                Statement::ElementSet { list, value, .. } => {
                    let tag = self.prescan_expr_tag(value, env, list_seen_tags);
                    self.prescan_note_list_value(list, tag, list_seen_tags);
                }
                Statement::If { then_block, else_if_blocks, else_block, .. } => {
                    self.prescan_walk(then_block, env, list_seen_tags);
                    for (_, block) in else_if_blocks {
                        self.prescan_walk(block, env, list_seen_tags);
                    }
                    if let Some(block) = else_block {
                        self.prescan_walk(block, env, list_seen_tags);
                    }
                }
                Statement::ForEach { variable, collection, body } => {
                    // A provably-empty collection runs its body zero times, so
                    // skip it — otherwise `append each x from [] to L` would
                    // widen L even though nothing is appended.
                    if let Expr::ListLit { elements } = collection {
                        if elements.is_empty() {
                            continue;
                        }
                    }
                    // Seed the loop variable's proven tag from the collection
                    // so appends of it inside the body don't widen (e.g.
                    // `append each x from [10, 20, 30] to copied` keeps copied
                    // homogeneous). Save/restore so a shadowing outer variable
                    // isn't clobbered.
                    let elem_tag =
                        self.foreach_loop_var_tag(collection, env, list_seen_tags);
                    let saved = env.insert(variable.clone(), elem_tag);
                    self.prescan_walk(body, env, list_seen_tags);
                    match saved {
                        Some(prev) => {
                            env.insert(variable.clone(), prev);
                        }
                        None => {
                            env.remove(variable);
                        }
                    }
                }
                Statement::ForRange { variable, body, .. } => {
                    // Range elements are integers; seed the loop variable so
                    // `append each n from 1 to 5 to L` keeps L homogeneous.
                    // Save/restore so a shadowing outer variable isn't clobbered.
                    let saved = env.insert(variable.clone(), TagInfo::Known(TAG_INTEGER));
                    self.prescan_walk(body, env, list_seen_tags);
                    match saved {
                        Some(prev) => {
                            env.insert(variable.clone(), prev);
                        }
                        None => {
                            env.remove(variable);
                        }
                    }
                }
                Statement::While { body, .. }
                | Statement::Repeat { body, .. }
                | Statement::FunctionDef { body, .. } => {
                    self.prescan_walk(body, env, list_seen_tags);
                }
                Statement::OnError { actions } => {
                    self.prescan_walk(actions, env, list_seen_tags);
                }
                // A `Library` declaration sets the identity for the function
                // definitions that follow it. The pre-scan classifies
                // FunctionCall results via `function_return_types`, keyed by
                // the mangled label, so `infer_expr_type` must see the SAME
                // library the call site sits in. The walk is in source order
                // and a `Library` precedes its functions, so setting the field
                // here (and again on each fixed-point pass) keeps it correct
                // as the walk enters each library's function bodies. This
                // mirrors the main generate walk's `LibraryDecl` arm.
                Statement::LibraryDecl { name, version } => {
                    self.current_library = Some((name.clone(), version.clone()));
                }
                _ => {}
            }
        }
    }

    /// Emit a print of the value in rdi dispatched on the runtime tag held
    /// in `tag_reg` (a full 64-bit register holding 0..=6).
    fn emit_mixed_print_dispatch(&mut self, tag_reg: &str) {
        let str_label = self.new_label("mixp_str");
        let flt_label = self.new_label("mixp_flt");
        let list_label = self.new_label("mixp_list");
        let map_label = self.new_label("mixp_map");
        let nothing_label = self.new_label("mixp_nothing");
        let done_label = self.new_label("mixp_done");
        self.emit_indent(&format!("cmp {}, {}  ; string tag?", tag_reg, TAG_STRING));
        self.emit_indent(&format!("je {}", str_label));
        self.emit_indent(&format!("cmp {}, {}  ; float tag?", tag_reg, TAG_FLOAT));
        self.emit_indent(&format!("je {}", flt_label));
        // A list element (tag 4): rdi already holds the child list pointer, so
        // recurse into `_list_print` (stage 1e1). The tag in `tag_reg` has
        // already been consumed by the comparisons above, so `_list_print`
        // clobbering r11/rax/etc. is safe.
        self.emit_indent(&format!("cmp {}, {}  ; list tag?", tag_reg, TAG_LIST));
        self.emit_indent(&format!("je {}", list_label));
        // A map element (tag 5, stage 1e2): rdi holds the child map pointer;
        // recurse into `_map_print`.
        self.emit_indent(&format!("cmp {}, {}  ; map tag?", tag_reg, TAG_MAP));
        self.emit_indent(&format!("je {}", map_label));
        // A nothing/null element (tag 6, stage 1e3): payload is 0 (unused),
        // so print the literal word `nothing` regardless of rdi.
        self.emit_indent(&format!("cmp {}, {}  ; nothing tag?", tag_reg, TAG_NOTHING));
        self.emit_indent(&format!("je {}", nothing_label));
        // Integer and boolean both print as numbers (matches homogeneous
        // boolean lists, which print 1/0 today).
        self.emit_indent("PRINT_INT rdi");
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", str_label));
        self.emit_indent("PRINT_CSTR rdi");
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", flt_label));
        self.emit_indent("movq xmm0, rdi");
        self.emit_indent("PRINT_FLOAT");
        self.uses_floats = true;
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", list_label));
        self.emit_indent("call _list_print  ; rdi = child list pointer");
        self.uses_lists = true;
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", map_label));
        self.emit_indent("call _map_print  ; rdi = child map pointer");
        self.uses_maps = true;
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", nothing_label));
        let nothing_str = self.add_string("nothing");
        self.emit_indent(&format!("PRINT_STR {}, {}_len", nothing_str, nothing_str));
        self.emit(&format!("{}:", done_label));
    }

    /// Whether a list-valued expression refers to a list whose elements are
    /// runtime-tagged (element reads must carry the runtime tag). A named
    /// mixed list is the base case; a read (element/first/last) from a mixed
    /// list yields a runtime-tagged value, so indexing it again is again a
    /// runtime-tagged read (chained access, stage 1e1); and a list literal is
    /// mixed iff its elements span more than one distinct tag (or any element
    /// is itself runtime-tagged).
    fn list_expr_is_mixed(&self, e: &Expr) -> bool {
        match e {
            Expr::Identifier(name) | Expr::StringLit(name) => {
                self.mixed_lists.contains(name)
                    || self.list_element_types.get(name) == Some(&VarType::Mixed)
            }
            // Chained read: a read from a mixed list yields a runtime-tagged
            // value, so indexing that result is again a runtime-tagged read.
            // (PropertyAccess `first`/`last` takes a bare variable name, so
            // it cannot chain; it is handled by the name arm above.)
            Expr::ElementAccess { list, .. } => self.list_expr_is_mixed(list),
            // A list literal is mixed iff its elements span >1 distinct tag,
            // or any element is itself runtime-tagged (no static tag).
            Expr::ListLit { elements } => {
                let mut tags: Vec<u8> = Vec::new();
                for el in elements {
                    match self.emit_time_expr_tag(el) {
                        Some(t) => {
                            if !tags.contains(&t) {
                                tags.push(t);
                            }
                        }
                        None => return true,
                    }
                }
                tags.len() > 1
            }
            _ => false,
        }
    }

    /// Where the runtime type tag of `e` can be found immediately after
    /// `generate_expr(e)` has run, or `None` when `e` carries no tag at all.
    ///
    /// A Mixed *variable* keeps its tag in a shadow stack slot, which survives
    /// anything. Everything else that has a tag leaves it in r11 (see
    /// `expr_leaves_tag_in_r11`), where it is only valid until the next call or
    /// syscall. For any other expression r11 holds an unrelated value, so
    /// comparing against it reads garbage - callers must fall back to a static
    /// answer instead.
    fn runtime_tag_source(&self, e: &Expr) -> Option<RuntimeTagSource> {
        if let Some(off) = self.mixed_element_tag_slot(e) {
            return Some(RuntimeTagSource::ShadowSlot(off));
        }
        if self.expr_leaves_tag_in_r11(e) {
            return Some(RuntimeTagSource::R11);
        }
        None
    }

    /// Operators that compute a number from their operands, so a `nothing`
    /// operand is meaningless. Comparisons and logical and/or are excluded:
    /// they are valid across types, and `is nothing` is itself an equality.
    /// Mirrors `Analyzer::is_arithmetic_op`.
    fn is_arithmetic_operator(&self, op: &BinaryOperator) -> bool {
        matches!(
            op,
            BinaryOperator::Add
                | BinaryOperator::Subtract
                | BinaryOperator::Multiply
                | BinaryOperator::Divide
                | BinaryOperator::Modulo
                | BinaryOperator::BitAnd
                | BinaryOperator::BitOr
                | BinaryOperator::BitXor
                | BinaryOperator::ShiftLeft
                | BinaryOperator::ShiftRight
        )
    }

    /// Flag an arithmetic operand that turned out to hold `nothing`.
    ///
    /// Emitted only for operands whose tag is dynamic - a mixed-list or map
    /// read, a `value`, a for-each variable. A statically-typed operand cannot
    /// be nothing, so homogeneous arithmetic emits nothing extra and keeps its
    /// fast path. A literal `nothing` never reaches here: the analyzer rejects
    /// it outright.
    ///
    /// Must follow `generate_expr(e)` immediately, while r11 still holds the
    /// operand's tag. Touches only r11 and the flags, never rax, so the
    /// operand's value survives.
    fn emit_nothing_operand_check(&mut self, e: &Expr) {
        // Provably nothing (e.g. an element of a homogeneous `[nothing]`
        // list): no test needed, the operand is always nothing. The analyzer
        // cannot see this one - it has no element-type tracking - so the flag
        // is set here rather than reported as a compile error.
        if self.emit_time_expr_tag(e) == Some(TAG_NOTHING) {
            self.emit_indent(
                "mov qword [rel _last_error], 1  ; nothing in arithmetic (static)",
            );
            return;
        }
        let Some(src) = self.runtime_tag_source(e) else {
            return;
        };
        if let RuntimeTagSource::ShadowSlot(off) = src {
            self.emit_indent(&format!(
                "movzx r11, byte [rbp-{}]  ; operand tag (shadow slot)", off
            ));
        }
        let ok = self.new_label("arith_not_nothing");
        self.emit_indent(&format!("cmp r11, {}  ; nothing operand?", TAG_NOTHING));
        self.emit_indent(&format!("jne {}", ok));
        self.emit_indent("mov qword [rel _last_error], 1  ; nothing in arithmetic");
        self.emit(&format!("{}:", ok));
    }

    /// Static tag for a *type predicate* operand. Identical to
    /// `emit_time_expr_tag` except that it still trusts a variable's declared
    /// type for an unprovable scalar: a predicate only reads a tag, it never
    /// writes one, so an over-confident answer here cannot produce the wild
    /// dereference `unprovable_scalars` guards against. Stage 1d gives these
    /// values real runtime tags and makes the answer exact.
    fn predicate_static_tag(&self, e: &Expr) -> Option<u8> {
        if let Expr::StringLit(name) | Expr::Identifier(name) = e {
            if self.unprovable_scalars.contains(name) {
                return self.variable_types.get(name).cloned().and_then(vartype_to_tag);
            }
        }
        self.emit_time_expr_tag(e)
    }

    /// If `e` is a reference to a Mixed-typed variable with a shadow tag
    /// slot, return that slot's rbp offset.
    fn mixed_element_tag_slot(&self, e: &Expr) -> Option<i64> {
        match e {
            Expr::Identifier(name) | Expr::StringLit(name) => {
                if self.variable_types.get(name) == Some(&VarType::Mixed) {
                    self.mixed_tag_slots.get(name).copied()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Best-effort static tag for a value being written into a list slot
    /// at emit time (richer than the pre-scan version: consults
    /// `variable_types`/`list_element_types`, which are populated by the
    /// time code is emitted). Returns `None` when only a runtime tag would
    /// do (a `Mixed` value's shadow-slot tag, or a genuinely opaque value
    /// whose actual type can't be proven — the latter falls back to
    /// `TAG_INTEGER` at the append site, with correct rendering deferred to
    /// stage 1d's runtime tag propagation).
    fn emit_time_expr_tag(&self, e: &Expr) -> Option<u8> {
        match e {
            Expr::IntegerLit(_) => Some(TAG_INTEGER),
            Expr::FloatLit(_) => Some(TAG_FLOAT),
            Expr::BoolLit(_) => Some(TAG_BOOLEAN),
            // The nothing/null literal is tag 6 (stage 1e3).
            Expr::NothingLit => Some(TAG_NOTHING),
            // A list literal value in a slot is tag 4 (stage 1e1). This is the
            // tag written to a nested-list element's slot at emit time.
            Expr::ListLit { .. } => Some(TAG_LIST),
            // A map literal value in a slot is tag 5 (stage 1e2).
            Expr::MapLit { .. } => Some(TAG_MAP),
            // A type predicate result is a boolean (stage 1c).
            Expr::TypeCheck { .. } => Some(TAG_BOOLEAN),
            // Logical negation is always a boolean. `infer_expr_type` maps
            // `Not` to `Integer` (codegen treats booleans as 0/1), which would
            // mis-tag a negated predicate — or any `not <expr>` list element —
            // as `TAG_INTEGER`. Tag it `TAG_BOOLEAN` explicitly so it matches
            // `prescan_expr_tag`, which recurses to the (boolean) operand.
            Expr::UnaryOp { op: UnaryOperator::Not, .. } => Some(TAG_BOOLEAN),
            Expr::StringLit(name) | Expr::Identifier(name)
                if self.unprovable_scalars.contains(name)
                    && self.variable_types.get(name) != Some(&VarType::List) =>
            {
                // The pre-scan could not prove what this variable holds, so
                // its declared type must not be turned into a slot tag. `None`
                // writes the integer tag, which a reader renders as a number -
                // wrong for a string, but never a wild dereference. Stage 1d's
                // runtime tag propagation replaces the guess with the real tag.
                //
                // Lists are exempt: the hazard is a declared type claiming a
                // pointer tag over bits that are not a pointer, and a list
                // variable's slot always holds a list pointer. Suppressing
                // TAG_LIST here would silently un-nest a nested list.
                None
            }
            Expr::StringLit(name) | Expr::Identifier(name) => {
                match self.variable_types.get(name) {
                    Some(VarType::Integer) => Some(TAG_INTEGER),
                    Some(VarType::Float) => Some(TAG_FLOAT),
                    Some(VarType::Boolean) => Some(TAG_BOOLEAN),
                    Some(VarType::String) | Some(VarType::Buffer) => Some(TAG_STRING),
                    Some(VarType::List) => Some(TAG_LIST),
                    Some(VarType::Map) => Some(TAG_MAP),
                    Some(VarType::Mixed) => None, // runtime tag in shadow slot
                    _ => {
                        if matches!(e, Expr::StringLit(_))
                            && !self.variables.contains_key(name)
                            && self.global_var_label(name).is_none()
                        {
                            Some(TAG_STRING) // a genuine string literal
                        } else {
                            // An identifier not in variable_types and not a
                            // genuine string literal. Every declared variable
                            // is in variable_types during codegen, so this is
                            // an edge (e.g. a global int mirror); defaulting to
                            // the zero (integer) tag is the same runtime effect
                            // as returning None (the append path writes 0).
                            Some(TAG_INTEGER)
                        }
                    }
                }
            }
            // Function results, binary/unary ops, casts, and property/element
            // reads: infer_expr_type resolves these from declared metadata and
            // the populated variable_types/list_element_types, so the written
            // tag matches the actual type. Mixed/Unknown map to None (runtime
            // tag or the TAG_INTEGER fallback); List maps to TAG_LIST via
            // vartype_to_tag.
            _ => self.infer_expr_type(e).and_then(vartype_to_tag),
        }
    }

    /// Load the runtime type tag of `expr` into r11, the single source of
    /// truth used by value-parameter passing, value returns, and (via the
    /// 1c predicates) type checks. Three cases, in priority order:
    ///
    /// 1. **Static tag** (`emit_time_expr_tag` returns `Some`): literals,
    ///    statically-typed variables, homogeneous-list element reads, and
    ///    scalar-returning function calls → `mov r11, <tag>`.
    /// 2. **Shadow tag slot** (`mixed_element_tag_slot` returns `Some`): a
    ///    `Mixed` *identifier* — a value parameter, a for-each variable over a
    ///    mixed list, or a declared `value` local — keeps its tag in a shadow
    ///    stack slot → `movzx r11, byte [rbp-<off>]`.
    /// 3. **Already in r11** (both return `None`): a freshly-read mixed-list
    ///    element (ElementAccess/First/Last leaves the slot's tag in r11) and a
    ///    value-returning function call (the callee leaves r11=tag; `call` and
    ///    `FUNC_EPILOGUE`/`_dec_call_depth` do not clobber r11). No emit needed.
    ///
    /// Register discipline: callers consume r11 immediately — between this
    /// load and the consumer there must be no `call`/syscall that clobbers r11.
    /// The inbound/return paths below respect this; if a future clobbering
    /// helper is inserted between the load and the consumer, spill r11 to a
    /// shadow slot first.
    fn emit_load_value_tag(&mut self, expr: &Expr) {
        match self.emit_time_expr_tag(expr) {
            Some(t) => self.emit_indent(&format!("mov r11, {}  ; value tag (static)", t)),
            None => match self.mixed_element_tag_slot(expr) {
                Some(off) => self
                    .emit_indent(&format!("movzx r11, byte [rbp-{}]  ; value tag (shadow slot)", off)),
                None => {
                    // r11 already holds the tag: a fresh mixed element read or a
                    // value-returning function call left it there. Nothing to do.
                }
            },
        }
    }

    /// Whether `generate_expr(expr)` leaves the value's runtime tag in r11, so a
    /// consumer can read the tag from r11 without an explicit load. True for:
    /// - a value-returning function call (the callee leaves r11=tag; `call`
    ///   and the epilogue do not clobber it), and
    /// - a freshly-read mixed-list element (`ElementAccess`, or `First`/`Last`
    ///   of a mixed list) — `generate_expr` captures the slot's tag into r11.
    /// Homogeneous reads never reach this question: `emit_time_expr_tag`
    /// returns their static tag (`Some`), so the caller never falls through to
    /// the no-slot path that consults this predicate.
    fn expr_leaves_tag_in_r11(&self, e: &Expr) -> bool {
        match e {
            Expr::FunctionCall { name, .. } => {
                self.function_return_types.get(&self.function_label(name)) == Some(&VarType::Mixed)
            }
            Expr::ElementAccess { list, .. } | Expr::ListAccess { list, .. } => {
                self.list_expr_is_mixed(list)
            }
            // A map key read: `_map_lookup` leaves the value in rax and its
            // runtime tag in r11 (stage 1e2), mirroring a mixed-list element.
            Expr::MapAccess { .. } => true,
            Expr::PropertyAccess { object, property }
                if matches!(property, ObjectProperty::First | ObjectProperty::Last) =>
            {
                self.mixed_lists.contains(object)
                    || self.list_element_types.get(object) == Some(&VarType::Mixed)
            }
            _ => false,
        }
    }

    pub fn generate(&mut self, program: &Program) -> String {
        // Collect function signatures BEFORE the pre-scan: prescan_expr_tag
        // classifies FunctionCall results via function_return_types, so it
        // must be populated for the pre-scan to prove (not widen) lists built
        // from declared-return functions. Signature collection only reads
        // FunctionDef.return_type from the AST, so this reorder is safe.
        self.collect_function_signatures(program);
        // Resolve the library identity before any function is generated so the
        // `<lib>_<ver>_<func>` label is correct regardless of where the
        // `Library` declaration sits in the source. No-op outside shared mode.
        self.collect_library_identity(program);
        self.prescan_mixed_lists(&program.statements);
        self.collect_global_constants(program);
        self.collect_flag_schemas(program);

        self.global_var_labels.clear();
        self.global_var_counter = 0;
        self.collect_global_var_labels(&program.statements);

        let explicit_parse_idx = program
            .statements
            .iter()
            .position(|s| matches!(s, Statement::ParseFlags));
        let auto_parse_idx = program
            .statements
            .iter()
            .rposition(|s| matches!(s, Statement::FlagSchemaDecl { .. }))
            .map(|i| i + 1);
        let parse_insert_idx = explicit_parse_idx.or(auto_parse_idx);
        self.parsed_args_active = parse_insert_idx.is_some() && !self.flag_schemas.is_empty();

        for (idx, stmt) in program.statements.iter().enumerate() {
            if parse_insert_idx == Some(idx) {
                self.emit_flag_parse_routine();
            }
            self.generate_statement(stmt);
        }

        if parse_insert_idx == Some(program.statements.len()) {
            self.emit_flag_parse_routine();
        }
        
        let mut result = String::new();
        
        result.push_str("; Generated by ec\n");
        result.push_str(&format!("; Target: {} Linux (NASM)\n\n", self.target_arch));
        
        // A shared library carries its own coreasm runtime so the .so is
        // self-contained and loadable from any host (C, Rust, Vox), not a
        // runtime-free pile of exports. It therefore emits the SAME
        // conditional include block as an executable, with two differences:
        // `default rel` is set (every reference must be RIP-relative so the
        // object can be relocated), and `args.asm` is excluded because it
        // reads the Linux loader's stack layout, which never exists in a
        // library. Function bodies are generated above into the functions
        // section, so the uses_* flags already reflect what the library
        // actually needs.
        if self.shared_lib_mode {
            result.push_str("default rel\n\n");
        }
        // Always needed: core
        result.push_str(&format!("%include \"coreasm/{}/core.asm\"\n", self.target_arch));
        // map.asm is included AFTER list.asm (it calls _list_print), so
        // its `__MAP_ASM_INCLUDED__` guard is not yet visible when
        // list.asm is assembled. Pre-define it here when maps are used so
        // list.asm's map-element print branch can call `_map_print`.
        if self.uses_maps {
            result.push_str("%define __MAP_ASM_INCLUDED__\n");
        }
        // Conditional includes based on usage
        // map.asm depends on io.asm (PRINT macros), string.asm (_str_eq),
        // and list.asm (_list_print), so uses_maps forces all three on.
        if self.uses_io || self.uses_maps {
            result.push_str(&format!("%include \"coreasm/{}/io.asm\"\n", self.target_arch));
        }
        if self.uses_files {
            result.push_str(&format!("%include \"coreasm/{}/file.asm\"\n", self.target_arch));
        }
        if self.uses_buffers || self.uses_files || self.uses_floats {
            result.push_str(&format!("%include \"coreasm/{}/resource.asm\"\n", self.target_arch));
        }
        if self.uses_ints {
            result.push_str(&format!("%include \"coreasm/{}/int.asm\"\n", self.target_arch));
        }
        if self.uses_floats {
            result.push_str(&format!("%include \"coreasm/{}/float.asm\"\n", self.target_arch));
        }
        if program.uses_heap {
            result.push_str(&format!("%include \"coreasm/{}/heap.asm\"\n", self.target_arch));
        }
        if program.uses_strings || self.uses_strings || self.uses_maps {
            result.push_str(&format!("%include \"coreasm/{}/string.asm\"\n", self.target_arch));
        }
        // args.asm parses the loader's stack (argc/argv/envp), which only an
        // executable receives - never a library - so it is excluded from
        // shared builds.
        if program.uses_args && !self.shared_lib_mode {
            result.push_str(&format!("%include \"coreasm/{}/args.asm\"\n", self.target_arch));
        }
        if self.uses_time {
            result.push_str(&format!("%include \"coreasm/{}/time.asm\"\n", self.target_arch));
        }
        if self.uses_format {
            result.push_str(&format!("%include \"coreasm/{}/format.asm\"\n", self.target_arch));
        }
        if self.uses_funcs {
            result.push_str(&format!("%include \"coreasm/{}/funcs.asm\"\n", self.target_arch));
        }
        if self.uses_lists || self.uses_maps {
            result.push_str(&format!("%include \"coreasm/{}/list.asm\"\n", self.target_arch));
        }
        if self.uses_maps {
            result.push_str(&format!("%include \"coreasm/{}/map.asm\"\n", self.target_arch));
        }
        result.push('\n');
        
        result.push_str("section .data\n");
        result.push_str(&self.data_section);
        result.push('\n');
        
        if !self.bss_section.is_empty() {
            result.push_str("section .bss\n");
            result.push_str(&self.bss_section);
            result.push('\n');
        }
        
        result.push_str("section .text\n");
        
        if self.shared_lib_mode {
            // A C/Rust host unloads the .so through libc's atexit -> _dl_fini,
            // which runs .fini_array. Register _cleanup_all there so the
            // library closes its tracked fds/buffers regardless of who loaded
            // it. A Vox host exits through sys_exit and never reaches
            // _dl_fini, so it must call cleanup explicitly before exit. Gate
            // the entry on the same condition that includes resource.asm,
            // where _cleanup_all is defined: a runtime-light library tracks
            // nothing and the symbol would otherwise be an undefined ref.
            if self.uses_buffers || self.uses_files || self.uses_floats {
                // `write` so ld can place the RELATIVE relocation here without
                // relaxing its read-only-segment check for the rest of the
                // .so — a targeted fix, not a blanket `-z notext`.
                result.push_str("section .fini_array progbits alloc write\n");
                result.push_str("    dq _cleanup_all\n\n");
                result.push_str("section .text\n");
            }

            // Shared library mode: export functions, no _start. The
            // `:function` type tag marks each export STT_FUNC: a NOTYPE
            // dynamic symbol resolves wrongly through the PLT and the first
            // cross-boundary call segfaults, so ld warns "type and size of
            // dynamic symbol ... are not defined" and the call traps.
            for func in &self.exported_functions {
                result.push_str(&format!("global {}:function\n", func));
            }
            result.push('\n');
            
            // Only include user-defined functions
            if !self.functions_section.is_empty() {
                result.push_str("; Exported library functions\n");
                result.push_str(&self.functions_section);
            }
        } else {
            // Executable mode: normal _start entry point
            result.push_str("global _start\n\n");
            result.push_str("_start:\n");
            
            // Save arguments BEFORE setting up stack frame (critical for correct argc/argv/envp capture)
            if program.uses_args {
                result.push_str("    ; Save command-line arguments and environment\n");
                result.push_str("    SAVE_ARGS\n\n");
            }
            
            result.push_str("    push rbp\n");
            result.push_str("    mov rbp, rsp\n");
            if self.stack_offset > 0 {
                result.push_str(&format!("    sub rsp, {}\n", (self.stack_offset + 15) & !15));
            }
            result.push('\n');
            
            result.push_str(&self.output);
            
            // Only cleanup if we used resources
            if self.uses_files || self.uses_buffers {
                result.push_str("\n    ; Cleanup all resources before exit\n");
                result.push_str("    call _cleanup_all\n");
            }
            result.push_str("\n    ; Exit program\n");
            result.push_str("    EXIT 0\n");
            
            // Append user-defined functions
            if !self.functions_section.is_empty() {
                result.push_str("\n; User-defined functions\n");
                result.push_str(&self.functions_section);
            }
        }
        
        result
    }
    
    fn generate_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Print { value, without_newline } => {
                self.generate_print(value, *without_newline);
            }
            
            Statement::VarDecl { name, var_type, value } => {
                // Reuse existing slot for reassignment, otherwise allocate new
                let had_existing_slot = self.variables.contains_key(name);
                let offset = if let Some(&existing) = self.variables.get(name) {
                    existing
                } else {
                    self.stack_offset += 8;
                    self.variables.insert(name.clone(), self.stack_offset);
                    self.stack_offset
                };
                
                // Track variable type from declaration
                if let Some(ref t) = var_type {
                    let vt = match t {
                        Type::String => VarType::String,
                        Type::Integer => VarType::Integer,
                        Type::Float => VarType::Float,
                        Type::Boolean => VarType::Boolean,
                        Type::Buffer => VarType::Buffer,
                        Type::List(_) => VarType::List,
                        Type::Map(_) => VarType::Map,
                        // A declared `value` local is a Mixed-typed scalar
                        // carrying its runtime tag in a shadow slot, exactly
                        // like a value parameter / for-each variable.
                        Type::Value => VarType::Mixed,
                        _ => VarType::Unknown,
                    };
                    self.variable_types.insert(name.clone(), vt);
                    if matches!(t, Type::Value) && !self.mixed_tag_slots.contains_key(name) {
                        let tag_slot = self.alloc_var(&format!("{}_mixtag", name));
                        self.mixed_tag_slots.insert(name.clone(), tag_slot);
                    }
                }
                
                if let Some(val) = value {
                    // Track list type and element type for lists
                    if let Expr::ListLit { elements } = val {
                        self.variable_types.insert(name.clone(), VarType::List);
                        // A nested map-literal element makes this a list-of-maps;
                        // the element type is Map so a for-each loop var prints
                        // via `_map_print` (stage 1e2).
                        if let Some(Expr::MapLit { .. }) = elements.first() {
                            self.list_element_types.insert(name.clone(), VarType::Map);
                        }
                        if self.mixed_lists.contains(name) {
                            // Pre-scan proved this list heterogeneous:
                            // element reads dispatch on runtime tags.
                            self.list_element_types.insert(name.clone(), VarType::Mixed);
                        }
                        // Track element type separately
                        else if let Some(first) = elements.first() {
                            let elem_type = match first {
                                Expr::StringLit(_) => VarType::String,
                                Expr::IntegerLit(_) => VarType::Integer,
                                Expr::FloatLit(_) => VarType::Float,
                                Expr::BoolLit(_) => VarType::Boolean,
                                // A nested list literal element means this is
                                // a list-of-lists; the element type is List
                                // (stage 1e1), so a for-each loop var prints
                                // via `_list_print`.
                                Expr::ListLit { .. } => VarType::List,
                                _ => VarType::Unknown,
                            };
                            self.list_element_types.insert(name.clone(), elem_type);
                        }
                    }
                    // Float literals set float type
                    else if self.is_float_expr(val) {
                        self.variable_types.insert(name.clone(), VarType::Float);
                    }
                    // ArgumentAll/ArgumentRaw produce lists of strings
                    else if matches!(val, Expr::ArgumentAll | Expr::ArgumentRaw) {
                        self.variable_types.insert(name.clone(), VarType::List);
                        self.list_element_types.insert(name.clone(), VarType::String);
                    }
                    // Argument/environment expressions return string pointers
                    else if matches!(val,
                        Expr::ArgumentAt { .. } | Expr::ArgumentName | Expr::ArgumentFirst |
                        Expr::ArgumentSecond | Expr::ArgumentLast |
                        Expr::EnvironmentVariable { .. } | Expr::EnvironmentVariableAt { .. } |
                        Expr::EnvironmentVariableFirst | Expr::EnvironmentVariableLast
                    ) {
                        self.variable_types.insert(name.clone(), VarType::String);
                    }
                    // Initializing from another variable: inherit its type
                    // (and element type, for lists) unless the declaration
                    // already pinned one. Without this, `a list called "b"
                    // is the a.` left "b" untyped and property access
                    // misrouted to the file fallback (_file_size).
                    else if var_type.is_none() || matches!(var_type, Some(Type::List(_))) {
                        let src_name = match val {
                            Expr::Identifier(src) => Some(src),
                            Expr::StringLit(src) if self.variables.contains_key(src) => Some(src),
                            _ => None,
                        };
                        if let Some(src) = src_name {
                            if let Some(vt) = self.variable_types.get(src).cloned() {
                                self.variable_types.insert(name.clone(), vt);
                            }
                            if let Some(et) = self.list_element_types.get(src).cloned() {
                                self.list_element_types.insert(name.clone(), et);
                            }
                        }
                        // Read-back from a parent list — `a list called
                        // "inner" is element 2 of nested.` / `... is nested's
                        // first.` The child list's elements are runtime-tagged
                        // (the parent may be mixed), so a for-each over `inner`
                        // must dispatch on each element's tag rather than
                        // assume a single static type; the tag-4 branch then
                        // renders nested lists. This is correct for both
                        // homogeneous and mixed inner lists (a homogeneous
                        // inner's uniform tags dispatch to the same printer).
                        let reads_element = matches!(val, Expr::ElementAccess { .. })
                            || matches!(
                                val,
                                Expr::PropertyAccess { property, .. }
                                    if matches!(property, ObjectProperty::First | ObjectProperty::Last)
                            );
                        if matches!(var_type, Some(Type::List(_))) && reads_element {
                            self.list_element_types.insert(name.clone(), VarType::Mixed);
                        }
                    }
                    
                    // Special handling for buffer initialization/assignment with text/format/buffer source
                    let is_buffer_target = matches!(var_type, Some(Type::Buffer))
                        || self.variable_types.get(name) == Some(&VarType::Buffer);
                    if is_buffer_target {
                        if matches!(val, Expr::FunctionCall { .. }) {
                            // Buffer declarations initialized from function calls should take
                            // the returned buffer pointer directly (rax), not format-append it.
                            self.generate_expr(val);
                            self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                            self.uses_buffers = true;
                        } else {
                        if !had_existing_slot {
                            self.emit_indent("mov rdi, 1024  ; default buffer size");
                            self.emit_indent("call _alloc_buffer");
                            self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                            self.uses_buffers = true;
                        }

                        if !self.emit_copy_expr_into_buffer_slot(val, true, Some(offset), None) {
                            // Clear before materializing the value: _buffer_clear
                            // returns the (possibly reallocated) buffer pointer in
                            // rax and would clobber a value loaded first.
                            self.emit_clear_buffer_slot(offset);
                            self.generate_expr(val);
                            let fmt_spec = self.parse_format_spec(None);
                            self.emit_append_runtime_value_to_buffer_slot(offset, self.infer_expr_type(val), fmt_spec);
                        }
                        }
                    } else {
                        self.generate_expr(val);
                        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                        // A declared `value` local stores its runtime tag in the
                        // shadow slot alongside the payload.
                        if let Some(&tag_slot) = self.mixed_tag_slots.get(name) {
                            self.emit_load_value_tag(val);
                            self.emit_indent(&format!(
                                "mov [rbp-{}], r11b  ; value local tag",
                                tag_slot
                            ));
                        }
                    }
                } else {
                    // No initial value - initialize based on type
                    if let Some(ref t) = var_type {
                        match t {
                            Type::Buffer => {
                                // Allocate an empty buffer with proper initialization
                                self.emit_indent("mov rdi, 1024  ; default buffer size");
                                self.emit_indent("call _alloc_buffer");
                                self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                                self.uses_buffers = true;
                            }
                            Type::List(_) => {
                                // Allocate an empty list; a null pointer here
                                // would make the first append dereference 0.
                                self.generate_expr(&Expr::ListLit { elements: vec![] });
                                self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                            }
                            _ => {
                                // Initialize to 0/null
                                self.emit_indent(&format!("mov qword [rbp-{}], 0", offset));
                            }
                        }
                    } else {
                        // No type info - initialize to 0
                        self.emit_indent(&format!("mov qword [rbp-{}], 0", offset));
                    }
                }

                self.emit_mirror_stack_var_to_global_if_needed(name, offset);
            }

            Statement::FlagSchemaDecl { name, value_type, default, .. } => {
                // Current bootstrap behavior: represent parsed flag value as a normal variable slot.
                // Runtime schema parsing/assignment is emitted in a later iteration.
                let offset = if let Some(&existing) = self.variables.get(name) {
                    existing
                } else {
                    self.stack_offset += 8;
                    self.variables.insert(name.clone(), self.stack_offset);
                    self.stack_offset
                };

                let vt = match value_type {
                    FlagValueType::Boolean => VarType::Boolean,
                    FlagValueType::Number => VarType::Integer,
                    FlagValueType::Text => VarType::String,
                };
                self.variable_types.insert(name.clone(), vt);

                if let Some(expr) = default {
                    self.generate_expr(expr);
                    self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                } else {
                    self.emit_indent(&format!("mov qword [rbp-{}], 0", offset));
                }

                self.emit_mirror_stack_var_to_global_if_needed(name, offset);
            }

            Statement::ParseFlags => {
                // Explicit parse point is currently a no-op placeholder. Runtime parsing is
                // planned to be emitted around this marker in a subsequent iteration.
            }
            
            Statement::Assignment { name, value } => {
                if let Some(offset) = self.get_var(name) {
                    // A `value` local (declared `a value called "r"`) keeps its
                    // Mixed type across reassignment — overwriting it with the
                    // assigned value's static type would drop the shadow-tag
                    // discipline and mis-classify later reads.
                    let is_value_local = self.mixed_tag_slots.contains_key(name);
                    if self.variable_types.get(name) != Some(&VarType::Buffer)
                        && !is_value_local
                    {
                        if let Some(vt) = self.infer_expr_type(value) {
                            match vt {
                                VarType::Float => {
                                    self.variable_types.insert(name.clone(), VarType::Float);
                                }
                                VarType::Integer | VarType::Boolean | VarType::String | VarType::List
                                | VarType::Map | VarType::Mixed => {
                                    self.variable_types.insert(name.clone(), vt);
                                }
                                VarType::Buffer | VarType::Unknown => {}
                            }
                        }
                    }
                    if self.variable_types.get(name) == Some(&VarType::Buffer) {
                        if !self.emit_copy_expr_into_buffer_slot(value, true, Some(offset), None) {
                            // Clear the buffer BEFORE materializing the value:
                            // _buffer_clear returns the (possibly reallocated)
                            // buffer pointer in rax, so generating the value
                            // first would leave append reading that pointer as
                            // the value. Clear, then load the value into rax,
                            // then append.
                            self.emit_clear_buffer_slot(offset);
                            self.generate_expr(value);
                            let fmt_spec = self.parse_format_spec(None);
                            self.emit_append_runtime_value_to_buffer_slot(offset, self.infer_expr_type(value), fmt_spec);
                        }
                    } else {
                        self.generate_expr(value);
                        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                        // Reassigning a `value` local must update its shadow tag
                        // slot too, or the runtime tag would go stale.
                        if let Some(&tag_slot) = self.mixed_tag_slots.get(name) {
                            self.emit_load_value_tag(value);
                            self.emit_indent(&format!(
                                "mov [rbp-{}], r11b  ; value local tag",
                                tag_slot
                            ));
                        }
                    }
                    self.emit_mirror_stack_var_to_global_if_needed(name, offset);
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    self.generate_expr(value);
                    self.emit_indent(&format!("mov [rel {}], rax", label));
                } else {
                    self.generate_expr(value);
                    let offset = self.alloc_var(name);
                    self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                }
            }
            
            Statement::If { condition, then_block, else_if_blocks, else_block } => {
                let end_label = self.new_label("if_end");
                let else_label = self.new_label("else");
                
                self.generate_condition(condition, &else_label);
                
                for s in then_block {
                    self.generate_statement(s);
                }
                self.emit_indent(&format!("jmp {}", end_label));
                
                self.emit(&format!("{}:", else_label));
                
                if !else_if_blocks.is_empty() {
                    for (i, (cond, block)) in else_if_blocks.iter().enumerate() {
                        let next_label = if i + 1 < else_if_blocks.len() || else_block.is_some() {
                            self.new_label("elif")
                        } else {
                            end_label.clone()
                        };
                        
                        self.generate_condition(cond, &next_label);
                        
                        for s in block {
                            self.generate_statement(s);
                        }
                        self.emit_indent(&format!("jmp {}", end_label));
                        if next_label != end_label {
                            self.emit(&format!("{}:", next_label));
                        }
                    }
                }
                
                if let Some(block) = else_block {
                    for s in block {
                        self.generate_statement(s);
                    }
                }
                
                self.emit(&format!("{}:", end_label));
            }
            
            Statement::While { condition, body } => {
                let start_label = self.new_label("while_start");
                let end_label = self.new_label("while_end");
                
                self.emit(&format!("{}:", start_label));
                self.generate_condition(condition, &end_label);

                self.loop_stack.push((start_label.clone(), end_label.clone()));
                
                for s in body {
                    self.generate_statement(s);
                }
                self.loop_stack.pop();
                
                self.emit_indent(&format!("jmp {}", start_label));
                self.emit(&format!("{}:", end_label));
            }
            
            Statement::ForRange { variable, range, body } => {
                let start_label = self.new_label("for_start");
                let continue_label = self.new_label("for_continue");
                let end_label = self.new_label("for_end");
                
                if let Expr::Range { start, end, inclusive } = range {
                    self.generate_expr(start);
                    let var_offset = self.alloc_var(variable);
                    self.variables.insert("_iter".to_string(), var_offset);
                    self.emit_indent(&format!("mov [rbp-{}], rax", var_offset));
                    
                    self.generate_expr(end);
                    let end_offset = self.alloc_var(&format!("{}_end", variable));
                    if *inclusive {
                        self.emit_indent("inc rax");
                    }
                    self.emit_indent(&format!("mov [rbp-{}], rax", end_offset));
                    
                    self.emit(&format!("{}:", start_label));
                    
                    self.emit_indent(&format!("mov rax, [rbp-{}]", var_offset));
                    self.emit_indent(&format!("cmp rax, [rbp-{}]", end_offset));
                    self.emit_indent(&format!("jge {}", end_label));

                    self.loop_stack.push((continue_label.clone(), end_label.clone()));
                    
                    for s in body {
                        self.generate_statement(s);
                    }
                    self.loop_stack.pop();

                    self.emit(&format!("{}:", continue_label));
                    
                    self.emit_indent(&format!("inc qword [rbp-{}]", var_offset));
                    self.emit_indent(&format!("jmp {}", start_label));
                    
                    self.emit(&format!("{}:", end_label));
                }
            }
            
            Statement::Repeat { count, body } => {
                let start_label = self.new_label("repeat_start");
                let continue_label = self.new_label("repeat_continue");
                let end_label = self.new_label("repeat_end");
                
                self.generate_expr(count);
                let counter_offset = self.alloc_var("_repeat_counter");
                self.emit_indent(&format!("mov [rbp-{}], rax", counter_offset));
                
                self.emit(&format!("{}:", start_label));
                
                self.emit_indent(&format!("cmp qword [rbp-{}], 0", counter_offset));
                self.emit_indent(&format!("jle {}", end_label));

                self.loop_stack.push((continue_label.clone(), end_label.clone()));
                
                for s in body {
                    self.generate_statement(s);
                }
                self.loop_stack.pop();

                self.emit(&format!("{}:", continue_label));
                
                self.emit_indent(&format!("dec qword [rbp-{}]", counter_offset));
                self.emit_indent(&format!("jmp {}", start_label));
                
                self.emit(&format!("{}:", end_label));
            }
            
            Statement::Allocate { name, size } => {
                self.generate_expr(size);
                self.emit_indent("HEAP_ALLOC rax");
                let offset = self.alloc_var(name);
                self.emit_indent(&format!("mov [rbp-{}], rax", offset));
            }
            
            Statement::Free { name } => {
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
                    self.emit_indent("HEAP_FREE rdi");
                }
            }
            
            Statement::Increment { name } => {
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("inc qword [rbp-{}]", offset));
                    self.emit_mirror_stack_var_to_global_if_needed(name, offset);
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    self.emit_indent(&format!("inc qword [rel {}]", label));
                }
            }
            
            Statement::Decrement { name } => {
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("dec qword [rbp-{}]", offset));
                    self.emit_mirror_stack_var_to_global_if_needed(name, offset);
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    self.emit_indent(&format!("dec qword [rel {}]", label));
                }
            }
            
            Statement::Break => {
                self.emit_indent("; break");
                if let Some((_, break_label)) = self.loop_stack.last() {
                    self.emit_indent(&format!("jmp {}", break_label));
                }
            }
            
            Statement::Exit { code } => {
                self.emit_indent("; exit program");
                self.generate_expr(code);
                self.emit_indent("mov rdi, rax  ; exit code");
                if self.uses_files || self.uses_buffers {
                    self.emit_indent("push rdi      ; save exit code");
                    self.emit_indent("call _cleanup_all");
                    self.emit_indent("pop rdi       ; restore exit code");
                }
                self.emit_indent("EXIT rdi");
            }
            
            Statement::Continue => {
                self.emit_indent("; continue");
                if let Some((continue_label, _)) = self.loop_stack.last() {
                    self.emit_indent(&format!("jmp {}", continue_label));
                }
            }
            
            Statement::Return { value } => {
                if let Some(v) = value {
                    self.generate_expr(v); // leaves return payload in RAX
                    // A `value` return carries its runtime tag in r11 for the
                    // caller. Load it AFTER generate_expr (which leaves r11=tag
                    // for fresh reads / value-returning calls, or nothing for a
                    // Mixed identifier). `_dec_call_depth` and `FUNC_EPILOGUE`
                    // (leave; ret) do not clobber r11, so no spill is needed.
                    if self.current_function_return_type == Some(Type::Value) {
                        self.emit_load_value_tag(v);
                    }
                }
                if self.in_function_codegen {
                    self.emit_indent("push rax  ; save return value");
                    self.emit_indent("call _dec_call_depth");
                    self.emit_indent("pop rax  ; restore return value");
                }
                self.emit_indent("FUNC_EPILOGUE");
            }
            
            Statement::FunctionCall { name, args } => {
                // Mark that we're using functions so funcs.asm gets included
                self.uses_funcs = true;
                self.emit_function_call(name, args);
            }
                        
            Statement::FunctionDef { name, params, body, return_type, .. } => {
                // Mark that we're using functions so funcs.asm gets included
                self.uses_funcs = true;
                
                let func_label = self.function_label(name);

                // Track exported functions for shared library mode
                if self.shared_lib_mode {
                    self.exported_functions.push(func_label.clone());
                }

                // Save outer codegen state
                let saved_output = std::mem::take(&mut self.output);
                let saved_vars = std::mem::take(&mut self.variables);
                let saved_stack = self.stack_offset;
                let saved_loop_stack = std::mem::take(&mut self.loop_stack);
                let saved_in_function_codegen = self.in_function_codegen;
                let saved_return_type = self.current_function_return_type.clone();

                // Fresh function-local state
                self.output = String::new();
                self.variables = std::collections::HashMap::new();
                self.stack_offset = 0;
                self.loop_stack = Vec::new();
                self.in_function_codegen = true;
                // Remember this function's declared return type so the `Return`
                // path knows to leave a `value` result's tag in r11.
                self.current_function_return_type = Some(return_type.clone());

                // ------------------------------------------------------------
                // PASS 1: Allocate stack slots for params, then generate body
                // into a temporary buffer to discover the true frame size.
                // ------------------------------------------------------------

                // A `value` parameter occupies two argument words (payload, tag).
                // The payload lives in the param's own slot; the tag lives in a
                // shadow `{name}_mixtag` slot, exactly like a for-each variable
                // over a mixed list, so the 1c predicates/print/append/forward
                // machinery all work on it unchanged.
                let word_count = |t: &Type| if matches!(t, Type::Value) { 2 } else { 1 };
                let total_words: usize = params.iter().map(|(_, t)| word_count(t)).sum();

                // Allocate param stack slots FIRST so offsets are stable.
                // Also register param types so they're known in function body.
                for (param_name, param_type) in params.iter() {
                    let var_type = match param_type {
                        Type::Integer => VarType::Integer,
                        Type::Float => VarType::Float,
                        Type::String => VarType::String,
                        Type::Boolean => VarType::Boolean,
                        Type::List(_) => VarType::List,
                        Type::Buffer => VarType::Buffer,
                        // A `value` parameter is a Mixed-typed scalar carrying
                        // its runtime tag in a shadow slot.
                        Type::Value => VarType::Mixed,
                        _ => VarType::Unknown,
                    };
                    self.alloc_var(param_name);
                    self.variable_types.insert(param_name.clone(), var_type);
                    if matches!(param_type, Type::Value) {
                        let tag_slot = self.alloc_var(&format!("{}_mixtag", param_name));
                        self.mixed_tag_slots.insert(param_name.clone(), tag_slot);
                    }
                }

                // Generate body into a temp buffer (this will call alloc_var for locals too)
                let mut has_return = false;

                let saved_tmp_out = std::mem::take(&mut self.output);
                self.output = String::new();

                for stmt in body {
                    if matches!(stmt, Statement::Return { .. }) {
                        has_return = true;
                    }
                    self.generate_statement(stmt);
                }

                // If no explicit return, add a default epilogue
                if !has_return {
                    self.emit_indent("call _dec_call_depth");
                    self.emit_indent("FUNC_EPILOGUE");
                }

                let body_code = std::mem::take(&mut self.output);
                self.output = saved_tmp_out;

                // Now we KNOW the frame size needed (params + locals + temps)
                let frame_size = (self.stack_offset + 15) & !15;

                // ------------------------------------------------------------
                // PASS 2: Emit the real function with correct prologue + param stores,
                // then append the already-generated body code.
                // ------------------------------------------------------------

                self.emit(&format!("{}:", func_label));
                self.emit_indent(&format!("FUNC_PROLOGUE {}", frame_size));
                // Recursion depth guard - save the first 6 argument WORDS
                // (not 6 params: a `value` param contributes two words), check
                // depth, restore. `_check_call_depth` touches only rax, so the
                // saved words are intact.
                let reg_words = total_words.min(6);
                for i in 0..reg_words {
                    self.emit_indent(&format!("push {}  ; save arg word", ["rdi", "rsi", "rdx", "rcx", "r8", "r9"][i]));
                }
                self.emit_indent("call _check_call_depth");
                for i in (0..reg_words).rev() {
                    self.emit_indent(&format!("pop {}  ; restore arg word", ["rdi", "rsi", "rdx", "rcx", "r8", "r9"][i]));
                }

                // Store parameters after frame is allocated. Walk params in
                // order, tracking the running argument-word index: a scalar
                // param consumes one word, a `value` param consumes two
                // (payload at `word_index`, tag at `word_index + 1`).
                let param_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
                // The caller inserts an 8-byte alignment pad below the stack
                // args when their count is odd, so the first stack arg lives at
                // [rbp + 16 + pad_offset], not [rbp + 16]. Both sides derive the
                // pad from the same word count, so they agree.
                let stack_words = total_words.saturating_sub(param_regs.len());
                let pad_offset: usize = if stack_words.is_multiple_of(2) { 0 } else { 8 };
                let mut word_index = 0usize;
                for (param_name, param_type) in params.iter() {
                    let payload_off = self.get_var(param_name);
                    let tag_off = self.mixed_tag_slots.get(param_name).copied();
                    let is_value = matches!(param_type, Type::Value);

                    // Read argument word `w` into rax: from a register if w < 6,
                    // else from the stack at [rbp + 16 + pad_offset + (w-6)*8].
                    let read_word = |w: usize| {
                        if w < param_regs.len() {
                            format!("mov rax, {}", param_regs[w])
                        } else {
                            let stack_arg_off = 16 + pad_offset + (w - param_regs.len()) * 8;
                            format!("mov rax, [rbp+{}]", stack_arg_off)
                        }
                    };

                    if let Some(offset) = payload_off {
                        // Payload word.
                        self.emit_indent(&read_word(word_index));
                        self.emit_indent(&format!("mov [rbp-{}], rax  ; param payload", offset));
                        if is_value {
                            // Tag word (stored as a byte into the shadow slot).
                            if let Some(tag_slot) = tag_off {
                                self.emit_indent(&read_word(word_index + 1));
                                self.emit_indent(&format!(
                                    "mov [rbp-{}], al  ; param value tag",
                                    tag_slot
                                ));
                            }
                            word_index += 2;
                        } else {
                            word_index += 1;
                        }
                    } else if is_value {
                        word_index += 2;
                    } else {
                        word_index += 1;
                    }
                }

                // Append the already-generated body
                self.output.push_str(&body_code);
                self.emit("");

                // Capture the finished function code
                let func_code = std::mem::take(&mut self.output);

                // Restore outer codegen state
                self.output = saved_output;
                self.variables = saved_vars;
                self.stack_offset = saved_stack;
                self.loop_stack = saved_loop_stack;
                self.in_function_codegen = saved_in_function_codegen;
                self.current_function_return_type = saved_return_type;

                // Append to functions section
                self.functions_section.push_str(&format!("; Function: {}\n", name));
                self.functions_section.push_str(&func_code);
            }

            
            Statement::ForEach { variable, collection, body } => {
                let start_label = self.new_label("foreach_start");
                let continue_label = self.new_label("foreach_continue");
                let end_label = self.new_label("foreach_end");
                
                // Special handling for arguments lists
                if matches!(collection, Expr::ArgumentAll | Expr::ArgumentRaw) {
                    if matches!(collection, Expr::ArgumentAll) {
                        self.emit_indent("call _get_parsed_argc");
                    } else {
                        self.emit_indent("call _get_raw_argc");
                    }
                    let argc_var = self.alloc_var(&format!("{}_argc", variable));
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; arg count", argc_var));

                    // Initialize index to 0 (user-arg-relative)
                    let index_var = self.alloc_var(&format!("{}_idx", variable));
                    self.emit_indent(&format!("mov qword [rbp-{}], 0", index_var));
                    
                    // Allocate variable for current element
                    let elem_var = self.alloc_var(variable);
                    self.variables.insert(variable.clone(), elem_var);
                    self.variable_types.insert(variable.clone(), VarType::String);
                    
                    self.emit(&format!("{}:", start_label));
                    
                    // Check if index < count
                    self.emit_indent(&format!("mov rax, [rbp-{}]  ; index", index_var));
                    self.emit_indent(&format!("cmp rax, [rbp-{}]  ; compare with count", argc_var));
                    self.emit_indent(&format!("jge {}", end_label));
                    
                    // Get current argument pointer from selected view
                    self.emit_indent("mov rdi, rax");
                    if matches!(collection, Expr::ArgumentAll) {
                        self.emit_indent("call _get_parsed_arg");
                    } else {
                        self.emit_indent("call _get_raw_arg");
                    }
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; store in {}", elem_var, variable));
                    
                    // Generate body
                    self.loop_stack.push((continue_label.clone(), end_label.clone()));
                    for s in body {
                        self.generate_statement(s);
                    }
                    self.loop_stack.pop();

                    self.emit(&format!("{}:", continue_label));
                    
                    // Increment index
                    self.emit_indent(&format!("inc qword [rbp-{}]", index_var));
                    self.emit_indent(&format!("jmp {}", start_label));
                    
                    self.emit(&format!("{}:", end_label));
                    return;
                }
                
                // Determine element type from list
                let elem_type = if let Expr::Identifier(list_name) = collection {
                    // Get element type from list_element_types, not variable_types
                    self.list_element_types.get(list_name).cloned().unwrap_or(VarType::Unknown)
                } else if let Expr::PropertyAccess { object, property } = collection {
                    // `map's keys` yields a list of text pointers; `map's
                    // values` yields a mixed-tagged list (each value carries
                    // its own runtime tag). (stage 1e2)
                    match property {
                        ObjectProperty::Keys => VarType::String,
                        ObjectProperty::Values => VarType::Mixed,
                        // `first`/`last` of a list-of-maps -> each is a map.
                        ObjectProperty::First | ObjectProperty::Last => {
                            match self.list_element_types.get(object) {
                                Some(VarType::Map) => VarType::Map,
                                _ => VarType::Unknown,
                            }
                        }
                        _ => VarType::Unknown,
                    }
                } else if let Expr::ListLit { elements } = collection {
                    // Inline literal: classify every element, not just the
                    // first - two distinct types means Mixed.
                    let mut tags: Vec<u8> = Vec::new();
                    let mut any_unknown = false;
                    for e in elements {
                        match self.emit_time_expr_tag(e) {
                            Some(t) => {
                                if !tags.contains(&t) {
                                    tags.push(t);
                                }
                            }
                            None => any_unknown = true,
                        }
                    }
                    if tags.len() > 1 {
                        VarType::Mixed
                    } else if let Some(first) = elements.first() {
                        let _ = any_unknown;
                        match first {
                            Expr::StringLit(_) => VarType::String,
                            Expr::IntegerLit(_) => VarType::Integer,
                            Expr::BoolLit(_) => VarType::Boolean,
                            Expr::FloatLit(_) => VarType::Float,
                            // Homogeneous list-of-lists literal: each element
                            // is a list (tag 4), so the loop var is a List and
                            // prints via `_list_print` (stage 1e1).
                            Expr::ListLit { .. } => VarType::List,
                            _ => VarType::Unknown,
                        }
                    } else {
                        VarType::Unknown
                    }
                } else {
                    VarType::Unknown
                };
                
                // Get list pointer
                // List structure: [capacity:8][length:8][elem_size:8][data...]
                self.generate_expr(collection);
                let list_ptr = self.alloc_var(&format!("{}_list", variable));
                self.emit_indent(&format!("mov [rbp-{}], rax  ; list pointer", list_ptr));
                
                // Get list length (at offset 8)
                self.emit_indent("mov rax, [rax + 8]  ; get length (offset 8)");
                let list_len = self.alloc_var(&format!("{}_len", variable));
                self.emit_indent(&format!("mov [rbp-{}], rax  ; list length", list_len));
                
                // Initialize index to 0
                let index_var = self.alloc_var(&format!("{}_idx", variable));
                self.emit_indent(&format!("mov qword [rbp-{}], 0  ; index", index_var));
                
                // Allocate variable for current element and track its type
                let elem_var = self.alloc_var(variable);
                self.variables.insert(variable.clone(), elem_var);
                self.variable_types.insert(variable.clone(), elem_type.clone());

                // For mixed lists the element's runtime type tag shadows the
                // loop variable in its own stack slot, refreshed every
                // iteration and consulted wherever the variable is printed.
                let tag_slot = if elem_type == VarType::Mixed {
                    let slot = self.alloc_var(&format!("{}_mixtag", variable));
                    self.mixed_tag_slots.insert(variable.clone(), slot);
                    Some(slot)
                } else {
                    self.mixed_tag_slots.remove(variable);
                    None
                };
                
                self.emit(&format!("{}:", start_label));
                
                // Check if index < length
                self.emit_indent(&format!("mov rax, [rbp-{}]  ; index", index_var));
                self.emit_indent(&format!("cmp rax, [rbp-{}]  ; compare with length", list_len));
                self.emit_indent(&format!("jge {}", end_label));
                
                // Get current element: data starts at offset 24
                self.emit_indent(&format!("mov rbx, [rbp-{}]  ; list pointer", list_ptr));
                if let Some(slot) = tag_slot {
                    // tag_addr = base + 24 + capacity*8 + index
                    self.emit_indent("mov r11, [rbx]  ; capacity");
                    self.emit_indent("shl r11, 3  ; * element size (8)");
                    self.emit_indent("add r11, rax  ; + index");
                    self.emit_indent("movzx r11, byte [rbx + r11 + 24]  ; slot type tag");
                    self.emit_indent(&format!("mov [rbp-{}], r11b  ; stash element's type tag", slot));
                }
                self.emit_indent("shl rax, 3  ; index * 8");
                self.emit_indent("add rax, 24  ; skip header (24 bytes)");
                self.emit_indent("add rbx, rax");
                self.emit_indent("mov rax, [rbx]  ; get element");
                self.emit_indent(&format!("mov [rbp-{}], rax  ; store in {}", elem_var, variable));
                
                // Generate body
                self.loop_stack.push((continue_label.clone(), end_label.clone()));
                for s in body {
                    self.generate_statement(s);
                }
                self.loop_stack.pop();

                self.emit(&format!("{}:", continue_label));
                
                // Increment index
                self.emit_indent(&format!("inc qword [rbp-{}]", index_var));
                self.emit_indent(&format!("jmp {}", start_label));
                
                self.emit(&format!("{}:", end_label));
            }
            
            // File I/O statements
            Statement::BufferDecl { name, size } => {
                // Reuse an existing slot for the same buffer name, exactly like
                // VarDecl reassignment. This ensures a buffer declared in both
                // branches of an if/otherwise pair shares a single stack slot,
                // so code after the branch reads the slot that was actually
                // written at runtime.
                let offset = if let Some(&existing) = self.variables.get(name) {
                    existing
                } else {
                    self.stack_offset += 8;
                    self.variables.insert(name.clone(), self.stack_offset);
                    self.stack_offset
                };
                self.variable_types.insert(name.clone(), VarType::Buffer);

                // Check if size is specified (non-zero)
                let is_sized = match size {
                    Expr::IntegerLit(0) => false,
                    Expr::IntegerLit(_) => true,
                    _ => true, // Any expression means sized
                };

                if is_sized {
                    // Fixed-size buffer (bounds checked, no auto-grow)
                    self.generate_expr(size);
                    self.emit_indent("mov rdi, rax  ; buffer size");
                    self.emit_indent("call _alloc_buffer_sized");
                } else {
                    // Dynamic buffer (auto-grows, tracked for cleanup)
                    self.emit_indent("call _alloc_buffer");
                }
                self.uses_buffers = true;
                self.emit_indent(&format!("mov [rbp-{}], rax  ; buffer struct pointer", offset));

                // Top-level/branch-declared buffers must be mirrored into BSS
                // so functions can read (and write) them via the global label.
                self.emit_mirror_stack_var_to_global_if_needed(name, offset);
            }
            
            Statement::ByteSet { buffer, index, value } => {
                let ok_label = self.new_label("bset_ok");
                let error_label = self.new_label("bset_err");
                let done_label = self.new_label("bset_done");
                let noupd_label = self.new_label("bset_noupd");

                self.emit_indent("; Set byte N of buffer to value (with bounds check)");
                // Get buffer pointer (local or global mirror)
                self.emit_load_named_var_addr(buffer);
                self.emit_indent("mov rbx, rax  ; buffer ptr");
                self.emit_indent("push rbx  ; save buffer pointer");
                // Get index
                self.generate_expr(index);
                self.emit_indent("mov rcx, rax  ; index in rcx (1-indexed)");
                self.emit_indent("pop rbx  ; buffer pointer in rbx");

                // Bounds check: index must be >= 1
                self.emit_indent("cmp rcx, 1");
                self.emit_indent(&format!("jl {}  ; index < 1 is error", error_label));
                self.emit_indent("mov rdx, [rbx]  ; get buffer capacity (offset 0)");
                self.emit_indent("cmp rcx, rdx");
                self.emit_indent(&format!("jle {}  ; index <= capacity is OK", ok_label));

                // Index beyond current capacity: dynamic buffers auto-grow,
                // fixed buffers are an error.
                self.emit_indent("mov rdx, [rbx + 16]  ; buffer flags");
                self.emit_indent("test rdx, 1  ; BUF_FLAG_FIXED");
                self.emit_indent(&format!("jnz {}  ; fixed buffer overflow", error_label));

                // Grow dynamic buffer so the 1-indexed position fits.
                self.emit_indent("push rcx  ; save index across grow call");
                self.emit_indent("mov rdi, rbx  ; buffer pointer");
                self.emit_indent("mov rsi, rcx  ; required capacity = index");
                self.emit_indent("call _grow_buffer");
                self.emit_indent("mov rbx, rax  ; new buffer pointer");
                if let Some(offset) = self.get_var(buffer) {
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; update buffer pointer", offset));
                }
                self.emit_indent("pop rcx  ; restore 1-indexed position");
                self.emit_indent(&format!("jmp {}  ; grown buffer now has space", ok_label));

                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent(&format!("jmp {}", done_label));

                // Success path: safe write
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("push rbx  ; save buffer pointer");
                self.emit_indent("push rcx  ; save 1-indexed position");
                // Get value
                self.generate_expr(value);
                self.emit_indent("mov rdx, rax  ; value in rdx");
                self.emit_indent("pop rcx  ; 1-indexed position in rcx");
                self.emit_indent("pop rbx  ; buffer pointer in rbx");
                // Update length = max(length, index) so reads see the written bytes
                self.emit_indent("cmp rcx, [rbx + 8]  ; compare index with current length");
                self.emit_indent(&format!("jle {}  ; skip if length already >= index", noupd_label));
                self.emit_indent("mov [rbx + 8], rcx  ; extend length to include this byte");
                self.emit(&format!("{}:", noupd_label));
                self.emit_indent("dec rcx  ; convert 1-indexed to 0-indexed");
                self.emit_indent("add rbx, 24  ; skip to buffer data area");
                self.emit_indent("mov [rbx + rcx], dl  ; write byte");

                self.emit(&format!("{}:", done_label));
            }
            
            Statement::ElementSet { list, index, value } => {
                let ok_label = self.new_label("eset_ok");
                let error_label = self.new_label("eset_err");
                let done_label = self.new_label("eset_done");

                self.emit_indent("; Set element N of list to value (with bounds check)");
                // Get list pointer (local or global mirror)
                self.emit_load_named_var_addr(list);
                self.emit_indent("mov rbx, rax  ; list ptr");
                self.emit_indent("push rbx  ; save list pointer");
                // Get index (1-indexed)
                self.generate_expr(index);
                self.emit_indent("mov rcx, rax  ; index in rcx (1-indexed)");
                self.emit_indent("pop rbx  ; list pointer in rbx");

                // Bounds check: index must be >= 1 and <= length
                self.emit_indent("cmp rcx, 1");
                self.emit_indent(&format!("jl {}  ; index < 1 is error", error_label));
                self.emit_indent("mov rdx, [rbx + 8]  ; get list length (offset 8)");
                self.emit_indent("cmp rcx, rdx");
                self.emit_indent(&format!("jle {}  ; index <= length is OK", ok_label));

                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent(&format!("jmp {}", done_label));

                // Success path: safe write
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("dec rcx  ; convert 1-indexed to 0-indexed");
                self.emit_indent("push rbx  ; save list pointer");
                self.emit_indent("push rcx  ; save index");
                // Get value
                self.generate_expr(value);
                self.emit_indent("mov r8, rax  ; value in r8");
                self.emit_indent("pop rcx  ; index in rcx");
                self.emit_indent("pop rbx  ; list pointer in rbx");
                // Write the slot's type tag:
                // tag_addr = base + 24 + capacity*elem_size + index
                self.emit_indent("mov rdx, [rbx]  ; capacity");
                self.emit_indent("imul rdx, [rbx + 16]  ; capacity * element_size");
                self.emit_indent("add rdx, rcx  ; + 0-based index");
                match self.emit_time_expr_tag(value) {
                    Some(tag) => {
                        self.emit_indent(&format!(
                            "mov byte [rbx + rdx + 24], {}  ; slot type tag",
                            tag
                        ));
                    }
                    None => {
                        if let Some(slot) = self.mixed_element_tag_slot(value) {
                            self.emit_indent(&format!(
                                "mov al, [rbp-{}]  ; runtime tag of mixed source",
                                slot
                            ));
                            self.emit_indent("mov [rbx + rdx + 24], al  ; slot type tag");
                        } else {
                            self.emit_indent("mov byte [rbx + rdx + 24], 0  ; default integer tag");
                        }
                    }
                }
                // Get element size (at offset 16 in list structure)
                self.emit_indent("mov rdx, [rbx + 16]  ; element size");
                // Calculate offset
                self.emit_indent("imul rcx, rdx  ; index * element_size");
                self.emit_indent("add rcx, 24  ; data starts at offset 24");
                // Write element
                self.emit_indent("mov [rbx + rcx], r8  ; write element");

                self.emit(&format!("{}:", done_label));
            }

            // Set map's "<key>" to value: insert or replace. _map_insert may
            // reallocate on growth, so the returned pointer is stored back
            // into the map variable's slot (mirroring ListAppend's store-back
            // — forgetting this corrupts the var after the first growth).
            // (stage 1e2, tag 5)
            Statement::MapSet { map, key, value } => {
                self.uses_maps = true;
                self.emit_indent("; Set map's key to value (insert/replace)");
                // map pointer -> stack
                self.emit_load_named_var_into_rax(map);
                self.emit_indent("push rax  ; save map pointer");
                // key -> stack (literal text; never a variable reference)
                self.generate_text_key(key);
                self.emit_indent("push rax  ; save key pointer");
                // value -> rdx
                self.generate_expr(value);
                self.emit_indent("mov rdx, rax  ; value");
                // tag -> rcx (forward runtime tag for mixed sources)
                match self.emit_time_expr_tag(value) {
                    Some(tag) => {
                        self.emit_indent(&format!("mov ecx, {}  ; value type tag", tag));
                    }
                    None => {
                        if let Some(slot) = self.mixed_element_tag_slot(value) {
                            self.emit_indent(&format!(
                                "movzx ecx, byte [rbp-{}]  ; runtime tag of mixed source",
                                slot
                            ));
                        } else if self.expr_leaves_tag_in_r11(value) {
                            self.emit_indent("mov ecx, r11d  ; forward runtime tag from r11");
                        } else {
                            self.emit_indent("xor ecx, ecx  ; default integer tag");
                        }
                    }
                }
                self.emit_indent("pop rsi  ; key pointer");
                self.emit_indent("pop rdi  ; map pointer");
                self.emit_indent("call _map_insert");
                // Store the (possibly reallocated) map pointer back.
                if let Some(offset) = self.get_var(map) {
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; store new map ptr", offset));
                } else if let Some(label) = self.global_var_label(map).cloned() {
                    self.emit_indent(&format!("mov [rel {}], rax  ; store new map ptr", label));
                }
            }

            Statement::ListAppend { list, value } => {
                if self.variable_types.get(list) == Some(&VarType::Buffer) {
                    let dst_local = self.get_var(list);
                    let dst_global = self.global_var_label(list).cloned();
                    if dst_local.is_some() || dst_global.is_some() {
                        if !self.emit_copy_expr_into_buffer_slot(value, false, dst_local, dst_global.as_deref()) {
                            self.generate_expr(value);
                            let fmt_spec = self.parse_format_spec(None);
                            if let Some(offset) = dst_local {
                                self.emit_append_runtime_value_to_buffer_slot(offset, self.infer_expr_type(value), fmt_spec);
                            } else if let Some(ref label) = dst_global {
                                self.emit_load_named_var_addr(list);
                                self.emit_indent("mov rdi, rax");
                                self.emit_append_runtime_value_to_buffer_ptr(self.infer_expr_type(value), fmt_spec);
                                self.emit_indent(&format!("mov [rel {}], rax", label));
                            }
                        }
                    }
                    return;
                }

                self.uses_lists = true;
                self.emit_indent("; Append value to list");
                
                // Track element type from appended value if not already set
                if self.mixed_lists.contains(list) {
                    self.list_element_types.insert(list.clone(), VarType::Mixed);
                } else if !self.list_element_types.contains_key(list) {
                    let elem_type = match value {
                        Expr::StringLit(_) => VarType::String,
                        Expr::IntegerLit(_) => VarType::Integer,
                        Expr::FloatLit(_) => VarType::Float,
                        Expr::BoolLit(_) => VarType::Boolean,
                        // A type predicate result (and its negation) is a
                        // boolean element, mirroring `BoolLit` so a for-each
                        // variable over a list of predicate results is typed
                        // Boolean and `is a boolean` recognises it (stage 1c).
                        Expr::TypeCheck { .. } => VarType::Boolean,
                        Expr::UnaryOp { op: UnaryOperator::Not, .. } => VarType::Boolean,
                        Expr::Identifier(name) => {
                            // Buffer variables produce string elements when appended
                            match self.variable_types.get(name) {
                                Some(VarType::Buffer) => VarType::String,
                                Some(t) => t.clone(),
                                None => VarType::Unknown,
                            }
                        }
                        _ => VarType::Unknown,
                    };
                    if elem_type != VarType::Unknown {
                        self.list_element_types.insert(list.clone(), elem_type);
                    }
                }
                
                // Resolve list pointer (local slot or global mirror) and save it.
                let list_ptr_loaded = self.emit_load_named_var_addr(list);
                if list_ptr_loaded {
                    self.emit_indent("push rax  ; save list pointer");

                    // Check if the value is a buffer variable
                    let is_buffer_value = match value {
                        Expr::StringLit(name) | Expr::Identifier(name) => {
                            self.variable_types.get(name).map(|t| t == &VarType::Buffer).unwrap_or(false)
                        }
                        _ => false,
                    };

                    // Evaluate value to append
                    self.generate_expr(value);

                    if is_buffer_value {
                        // For buffer values, extract string data and duplicate it.
                        // Bounded by the buffer's own tracked length rather than
                        // scanning for NUL - see _strdup_bounded's comment for why
                        // (buffer content isn't reliably NUL-terminated at its
                        // logical end after a clear+shorter-rewrite).
                        self.uses_strings = true;
                        self.emit_indent("push rbx");
                        self.emit_indent("push r12");
                        self.emit_indent("mov rbx, rax  ; save buffer pointer");
                        self.emit_indent("mov rdi, rbx");
                        self.emit_indent("call _buffer_length");
                        self.emit_indent("mov r12, rax  ; save length");
                        self.emit_indent("mov rdi, rbx");
                        self.emit_indent("call _buffer_data  ; get data pointer");
                        self.emit_indent("mov rdi, rax  ; source string");
                        self.emit_indent("mov rsi, r12  ; max length");
                        self.emit_indent("call _strdup_bounded  ; duplicate string");
                        self.emit_indent("pop r12");
                        self.emit_indent("pop rbx");
                    }

                    self.emit_indent("push rax  ; save value to append");

                    // rdi = list pointer, rsi = value to append, dl = type tag
                    match self.emit_time_expr_tag(value) {
                        Some(tag) => {
                            self.emit_indent(&format!(
                                "mov edx, {}  ; element type tag",
                                tag
                            ));
                        }
                        None => {
                            // Mixed-typed source variable: forward its
                            // runtime tag from the shadow slot.
                            if let Some(slot) = self.mixed_element_tag_slot(value) {
                                self.emit_indent(&format!(
                                    "movzx edx, byte [rbp-{}]  ; runtime tag of mixed source",
                                    slot
                                ));
                            } else if self.expr_leaves_tag_in_r11(value) {
                                // A freshly-read mixed element or a value-returning
                                // function call left its tag in r11 — forward it
                                // instead of dropping it (which previously mis-
                                // tagged appended mixed elements as integers).
                                self.emit_indent("mov edx, r11d  ; forward runtime tag from r11");
                            } else {
                                self.emit_indent("xor edx, edx  ; default integer tag");
                            }
                        }
                    }
                    self.emit_indent("pop rsi  ; value to append");
                    self.emit_indent("pop rdi  ; list ptr");
                    self.emit_indent("call _list_append");

                    // Store potentially new list pointer back to wherever it came from
                    if let Some(offset) = self.get_var(list) {
                        self.emit_indent(&format!("mov [rbp-{}], rax  ; store new list ptr", offset));
                    } else if let Some(label) = self.global_var_label(list).cloned() {
                        self.emit_indent(&format!("mov [rel {}], rax  ; store new list ptr", label));
                    }
                }
            }

            Statement::BufferCopy { source, destination } => {
                let dst_local = self.get_var(destination);
                let dst_global = self.global_var_label(destination).cloned();
                if dst_local.is_some() || dst_global.is_some() {
                    if !self.emit_copy_expr_into_buffer_slot(source, true, dst_local, dst_global.as_deref()) {
                        // Fallback for non-buffer source expressions.
                        // Load destination pointer into rdi, clear it, then append.
                        self.emit_load_named_var_addr(destination);
                        self.emit_indent("mov rdi, rax  ; destination buffer");
                        self.emit_indent("push rdi");
                        self.emit_indent("call _buffer_clear");
                        self.emit_indent("mov rdi, rax");
                        self.emit_indent("push rdi");
                        self.generate_expr(source);
                        let src_type = self.infer_expr_type(source);
                        let fmt_spec = self.parse_format_spec(None);
                        self.emit_append_runtime_value_to_buffer_ptr(src_type, fmt_spec);
                        self.emit_indent("pop rdi  ; original destination buffer pointer");
                        if let Some(offset) = dst_local {
                            self.emit_indent(&format!("mov [rbp-{}], rax  ; updated destination pointer", offset));
                        } else if let Some(ref label) = dst_global {
                            self.emit_indent(&format!("mov [rel {}], rax  ; updated destination pointer", label));
                        }
                    }
                }
            }

            Statement::BufferClear { name } => {
                self.uses_buffers = true;
                self.emit_indent("; Clear buffer contents");
                self.emit_load_named_var_addr(name);
                self.emit_indent("mov rdi, rax  ; buffer");
                self.emit_indent("call _buffer_clear");
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; buffer (unchanged pointer)", offset));
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    self.emit_indent(&format!("mov [rel {}], rax  ; buffer (unchanged pointer)", label));
                }
            }
            
            Statement::FileOpen { name, path, mode } => {
                self.uses_files = true;
                let path_is_fd = self.is_fd_path_expr(path);
                
                // Track if file is writable based on mode
                let is_writable = matches!(mode, FileMode::Writing | FileMode::Appending);
                self.file_writable.insert(name.clone(), is_writable);

                // Reuse the existing slot when the handle name is already
                // known, exactly like VarDecl reassignment. Two Opens of the
                // same name in an if/otherwise pair must share one slot -
                // separate slots meant code after the branch read whichever
                // slot the LAST-generated branch owned, which the branch
                // actually taken at runtime never wrote.
                let offset = if let Some(existing) = self.get_var(name) {
                    existing
                } else {
                    self.alloc_var(name)
                };

                if path_is_fd {
                    let fd_ok_label = self.new_label("fd_ok");
                    let fd_invalid_label = self.new_label("fd_invalid");
                    let fd_done_label = self.new_label("fd_done");

                    self.generate_expr(path);
                    self.emit_indent("; Treat numeric open path as file descriptor");
                    self.emit_indent("cmp rax, 0");
                    self.emit_indent(&format!("jl {}", fd_invalid_label));
                    self.emit_indent("mov rcx, 2147483647  ; i32::MAX");
                    self.emit_indent("cmp rax, rcx");
                    self.emit_indent(&format!("jle {}", fd_ok_label));
                    self.emit_indent(&format!("jmp {}", fd_invalid_label));

                    self.emit(&format!("{}:", fd_ok_label));
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; borrowed file descriptor", offset));
                    self.emit_indent("mov qword [rel _last_error], 0");
                    self.emit_indent(&format!("jmp {}", fd_done_label));

                    self.emit(&format!("{}:", fd_invalid_label));
                    self.emit_indent(&format!("mov qword [rbp-{}], -1  ; invalid fd", offset));
                    self.emit_indent("mov qword [rel _last_error], 22  ; EINVAL");

                    self.emit(&format!("{}:", fd_done_label));
                    self.emit_mirror_stack_var_to_global_if_needed(name, offset);
                    return;
                }

                // Generate path pointer for filesystem opens
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("lea rdi, [rel {}]", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("mov rdi, rax  ; path pointer");
                    }
                }
                
                // Open file with appropriate mode (path is in rdi)
                match mode {
                    FileMode::Reading => {
                        self.emit_indent("FILE_OPEN_READ rdi");
                    }
                    FileMode::Writing => {
                        self.emit_indent("FILE_OPEN_WRITE rdi");
                    }
                    FileMode::Appending => {
                        self.emit_indent("FILE_OPEN_APPEND rdi");
                    }
                }
                
                // Store file descriptor and register for tracking (only if valid)
                self.emit_indent(&format!("mov [rbp-{}], rax  ; file descriptor", offset));
                
                // Check for error (negative fd) and set _last_error
                let ok_label = self.new_label("file_ok");
                let done_label = self.new_label("file_done");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jns {}  ; jump if success (non-negative)", ok_label));
                
                // Error path: set _last_error
                self.emit_indent("neg rax  ; convert to positive errno");
                self.emit_indent("mov [rel _last_error], rax");
                self.emit_indent(&format!("jmp {}", done_label));
                
                // Success path: register fd for cleanup
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("mov qword [rel _last_error], 0  ; clear error");
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _register_fd  ; track for auto-cleanup");
                
                self.emit(&format!("{}:", done_label));
                self.emit_mirror_stack_var_to_global_if_needed(name, offset);
            }
            
            Statement::FileRead { source, buffer } => {
                // Get source fd
                let source_fd = if source == "stdin" {
                    "0".to_string()  // STDIN
                } else if let Some(offset) = self.get_var(source) {
                    format!("[rbp-{}]", offset)
                } else {
                    "0".to_string()
                };
                
                // Use dynamic read that auto-grows buffer (only if fd is valid)
                if let Some(buf_offset) = self.get_var(buffer) {
                    let skip_label = self.new_label("skip_fd");
                    self.emit_indent(&format!("mov rdi, {}", source_fd));
                    // Skip read if fd is invalid (negative)
                    self.emit_indent("test rdi, rdi");
                    self.emit_indent(&format!("js {}  ; skip if invalid fd", skip_label));
                    self.emit_indent(&format!("mov rsi, [rbp-{}]  ; buffer struct", buf_offset));
                    // Reset buffer length before reading (read replaces, not appends)
                    self.emit_indent("mov qword [rsi + 8], 0  ; reset buffer length");
                    self.emit_indent("call _read_into_buffer  ; auto-grows if needed");
                    // Update buffer pointer (may have changed if grown)
                    self.emit_indent(&format!("mov [rbp-{}], rsi  ; updated buffer ptr", buf_offset));
                    self.emit(&format!("{}:", skip_label));
                }
            }

            Statement::FileReadLine { source, buffer } => {
                let source_fd = if source == "stdin" {
                    "0".to_string()
                } else if let Some(offset) = self.get_var(source) {
                    format!("[rbp-{}]", offset)
                } else {
                    "0".to_string()
                };

                if let Some(buf_offset) = self.get_var(buffer) {
                    let skip_label = self.new_label("skip_fd");
                    let done_label = self.new_label("readline_done");
                    self.emit_indent(&format!("mov rdi, {}", source_fd));
                    self.emit_indent("test rdi, rdi");
                    self.emit_indent(&format!("js {}  ; skip if invalid fd", skip_label));
                    self.emit_indent(&format!("mov rsi, [rbp-{}]  ; buffer struct", buf_offset));
                    self.emit_indent("mov qword [rsi + 8], 0  ; reset buffer length");
                    self.emit_indent("call _read_line_into_buffer");
                    // _read_line_into_buffer already sets _last_error (1=EOF, 2=read error)
                    // Update buffer pointer (may have changed if grown)
                    self.emit_indent(&format!("mov [rbp-{}], rsi  ; updated buffer ptr", buf_offset));
                    self.emit_indent(&format!("jmp {}", done_label));
                    self.emit(&format!("{}:", skip_label));
                    // Invalid fd is an error - make On error fire
                    self.emit_indent("mov qword [rel _last_error], 1");
                    self.emit(&format!("{}:", done_label));
                }
            }

            Statement::FileSeekLine { file, line } => {
                self.uses_files = true;

                let file_fd = if let Some(offset) = self.get_var(file) {
                    format!("[rbp-{}]", offset)
                } else if let Some(label) = self.global_var_label(file).cloned() {
                    format!("[rel {}]", label)
                } else {
                    "0".to_string()
                };

                self.generate_expr(line);
                self.emit_indent("mov rsi, rax  ; target line (1-indexed)");
                self.emit_indent(&format!("mov rdi, {}", file_fd));
                self.emit_indent("call _seek_fd_line");
                // _seek_fd_line sets _last_error on failure and returns -1.
                // Ensure _last_error is cleared on success so On error doesn't
                // fire spuriously.
                let ok_label = self.new_label("seek_line_ok");
                let done_label = self.new_label("seek_line_done");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jns {}", ok_label));
                // Already set by _seek_fd_line, but ensure non-zero
                self.emit_indent("mov qword [rel _last_error], 1");
                self.emit_indent(&format!("jmp {}", done_label));
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("mov qword [rel _last_error], 0");
                self.emit(&format!("{}:", done_label));
            }

            Statement::FileSeekByte { file, byte } => {
                self.uses_files = true;

                let file_fd = if let Some(offset) = self.get_var(file) {
                    format!("[rbp-{}]", offset)
                } else if let Some(label) = self.global_var_label(file).cloned() {
                    format!("[rel {}]", label)
                } else {
                    "0".to_string()
                };

                self.generate_expr(byte);
                self.emit_indent("mov rsi, rax  ; target byte (1-indexed)");
                self.emit_indent(&format!("mov rdi, {}", file_fd));
                self.emit_indent("call _seek_fd_byte");
                // _seek_fd_byte sets _last_error on failure and returns -1.
                let ok_label = self.new_label("seek_byte_ok");
                let done_label = self.new_label("seek_byte_done");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jns {}", ok_label));
                self.emit_indent("mov qword [rel _last_error], 1");
                self.emit_indent(&format!("jmp {}", done_label));
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("mov qword [rel _last_error], 0");
                self.emit(&format!("{}:", done_label));
            }
            
            Statement::FileWrite { file, value } => {
                // Get file fd
                let file_fd = if let Some(offset) = self.get_var(file) {
                    format!("[rbp-{}]", offset)
                } else if let Some(label) = self.global_var_label(file).cloned() {
                    format!("[rel {}]", label)
                } else {
                    "1".to_string()  // STDOUT as fallback
                };
                
                let skip_label = self.new_label("skip_fd");
                self.emit_indent(&format!("mov rdi, {}", file_fd));
                // Skip write if fd is invalid (negative)
                self.emit_indent("test rdi, rdi");
                self.emit_indent(&format!("js {}  ; skip if invalid fd", skip_label));
                
                match value {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("FILE_WRITE_STR rdi, {}", label));
                    }
                    Expr::Identifier(name) => {
                        if let Some(offset) = self.get_var(name) {
                            let var_type = self.variable_types.get(name).cloned();
                            self.emit_indent(&format!("mov rsi, [rbp-{}]", offset));
                            if matches!(var_type, Some(VarType::Buffer)) {
                                self.emit_indent("FILE_WRITE_BUF rdi, rsi");
                            } else {
                                self.emit_indent("FILE_WRITE_STR rdi, rsi");
                            }
                        } else if let Some(label) = self.global_var_label(name).cloned() {
                            let var_type = self.variable_types.get(name).cloned();
                            self.emit_indent(&format!("mov rsi, [rel {}]", label));
                            if matches!(var_type, Some(VarType::Buffer)) {
                                self.emit_indent("FILE_WRITE_BUF rdi, rsi");
                            } else {
                                self.emit_indent("FILE_WRITE_STR rdi, rsi");
                            }
                        }
                    }
                    Expr::TreatingAs { value: inner_val, match_value, replacement } => {
                        // Check if inner value is a buffer
                        let is_buffer = if let Expr::Identifier(ref name) = **inner_val {
                            self.variable_types.get(name) == Some(&VarType::Buffer)
                        } else {
                            false
                        };
                        
                        if is_buffer {
                            // For buffers, we need different write macros for match vs no-match
                            let skip_label = self.new_label("treating_skip");
                            let done_label = self.new_label("treating_done");
                            
                            self.emit_indent("push rdi");  // save fd
                            
                            // Generate buffer value
                            self.generate_expr(inner_val);
                            self.emit_indent("push rax  ; save buffer struct ptr");
                            
                            // Get the buffer's tracked length and data pointer.
                            // Use _mem_eq rather than _str_eq to avoid the stale-byte
                            // bug: the buffer's data area may not be NUL-terminated at
                            // its logical end after a clear+shorter-rewrite.
                            self.emit_indent("mov rdi, rax");
                            self.emit_indent("call _buffer_length");
                            self.emit_indent("mov rdx, rax  ; len1 = buf length");
                            self.emit_indent("mov rdi, [rsp]  ; reload buf struct ptr");
                            self.emit_indent("call _buffer_data");
                            self.emit_indent("mov rdi, rax  ; ptr1 = buf data");
                            self.generate_expr(match_value);
                            self.emit_indent("mov rsi, rax  ; ptr2 = match string");
                            self.emit_indent("push rdi      ; save ptr1 across str_len call");
                            self.emit_indent("push rsi      ; save ptr2");
                            self.emit_indent("push rdx      ; save len1");
                            self.emit_indent("mov rdi, rsi");
                            self.emit_indent("call _str_len");
                            self.emit_indent("mov rcx, rax  ; len2 = match string len");
                            self.emit_indent("pop rdx       ; restore len1");
                            self.emit_indent("pop rsi       ; restore ptr2");
                            self.emit_indent("pop rdi       ; restore ptr1");
                            self.emit_indent("call _mem_eq");
                            self.emit_indent("test rax, rax");
                            self.emit_indent(&format!("jz {}", skip_label));
                            
                            // Match: write replacement string
                            self.emit_indent("add rsp, 8  ; discard buffer ptr");
                            self.emit_indent("pop rdi  ; restore fd");
                            self.generate_expr(replacement);
                            self.emit_indent("FILE_WRITE_STR rdi, rax");
                            self.emit_indent(&format!("jmp {}", done_label));
                            
                            // No match: write original buffer
                            self.emit(&format!("{}:", skip_label));
                            self.emit_indent("pop rsi  ; restore buffer ptr");
                            self.emit_indent("pop rdi  ; restore fd");
                            self.emit_indent("FILE_WRITE_BUF rdi, rsi");
                            
                            self.emit(&format!("{}:", done_label));
                        } else {
                            // For non-buffers, use standard treating logic
                            self.emit_indent("push rdi");  // save fd
                            self.generate_expr(value);
                            self.emit_indent("mov rsi, rax");
                            self.emit_indent("pop rdi");   // restore fd
                            self.emit_indent("FILE_WRITE_STR rdi, rsi");
                        }
                    }
                    _ => {
                        // For other expressions, generate and write
                        self.emit_indent("push rdi");  // save fd
                        self.generate_expr(value);
                        self.emit_indent("pop rdi");   // restore fd
                        self.emit_indent("FILE_WRITE_STR rdi, rax");
                    }
                }
                self.emit(&format!("{}:", skip_label));
            }
            
            Statement::FileWriteNewline { file } => {
                let file_fd = if let Some(offset) = self.get_var(file) {
                    format!("[rbp-{}]", offset)
                } else {
                    "1".to_string()
                };
                let skip_label = self.new_label("skip_fd");
                self.emit_indent(&format!("mov rdi, {}", file_fd));
                // Skip write if fd is invalid (negative)
                self.emit_indent("test rdi, rdi");
                self.emit_indent(&format!("js {}  ; skip if invalid fd", skip_label));
                self.emit_indent("FILE_WRITE_NEWLINE rdi");
                self.emit(&format!("{}:", skip_label));
            }
            
            Statement::FileClose { file } => {
                if let Some(offset) = self.get_var(file) {
                    let skip_label = self.new_label("skip_fd");
                    self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
                    // Skip close if fd is invalid (negative)
                    self.emit_indent("test rdi, rdi");
                    self.emit_indent(&format!("js {}  ; skip if invalid fd", skip_label));
                    self.emit_indent("call _unregister_fd  ; remove from tracking");
                    self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
                    self.emit_indent("FILE_CLOSE rdi");
                    self.emit(&format!("{}:", skip_label));
                }
            }
            
            Statement::FileDelete { path } => {
                self.uses_files = true;
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("FILE_DELETE {}", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("FILE_DELETE rax");
                    }
                }
            }

            Statement::Rmdir { path } => {
                self.uses_files = true;
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("RMDIR {}", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("RMDIR rax");
                    }
                }
            }

            Statement::Mkdir { path } => {
                self.uses_files = true;
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("MKDIR {}", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("MKDIR rax");
                    }
                }
            }

            Statement::Chdir { path } => {
                self.uses_files = true;
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("CHDIR {}", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("CHDIR rax");
                    }
                }
            }

            Statement::Mount { source, target, fstype, options } => {
                self.uses_files = true;

                // Detect the "move"/"bind" pseudo-mount pattern used for
                // relocating already-mounted filesystems to a new root
                // (fstype "none" + options "move"/"bind"): for these, the
                // real mount(2) syscall wants a NULL filesystemtype and
                // NULL data, with the operation encoded entirely in flags.
                let is_none_fstype = matches!(fstype, Expr::StringLit(s) if s == "none");
                let move_flag = matches!(options, Some(Expr::StringLit(s)) if s == "move");
                let bind_flag = matches!(options, Some(Expr::StringLit(s)) if s == "bind");
                let flags: i64 = if is_none_fstype && move_flag {
                    8192 // MS_MOVE
                } else if is_none_fstype && bind_flag {
                    4096 // MS_BIND
                } else {
                    0
                };
                let suppress_fstype_and_data = is_none_fstype && (move_flag || bind_flag);

                // Park each evaluated argument on the stack so later
                // expressions (function calls, format strings) cannot
                // clobber earlier results, then pop into the syscall
                // registers in reverse order.
                self.generate_cstr_expr(source);
                self.emit_indent("push rax  ; park source");

                self.generate_cstr_expr(target);
                self.emit_indent("push rax  ; park target");

                // fstype (NULL for move/bind pseudo-mounts)
                if suppress_fstype_and_data {
                    self.emit_indent("xor rax, rax  ; fstype = NULL (move/bind)");
                } else {
                    self.generate_cstr_expr(fstype);
                }
                self.emit_indent("push rax  ; park fstype");

                // options/data (NULL for move/bind pseudo-mounts, or if omitted)
                if suppress_fstype_and_data {
                    self.emit_indent("xor rax, rax  ; data = NULL (move/bind)");
                } else {
                    match options {
                        None => self.emit_indent("xor rax, rax  ; data = NULL (no options given)"),
                        Some(expr) => self.generate_cstr_expr(expr),
                    }
                }
                self.emit_indent("push rax  ; park data (options)");

                // NOTE: raw `syscall` uses r10 for arg4, NOT rcx (rcx/r11
                // get clobbered by the syscall instruction itself) -
                // matches the convention already established by the
                // existing MMAP macro in this file.
                self.emit_indent("pop r8   ; data (options)");
                self.emit_indent("pop rdx  ; fstype");
                self.emit_indent("pop rsi  ; target");
                self.emit_indent("pop rdi  ; source");
                self.emit_indent(&format!("mov r10, {}  ; mount flags", flags));
                self.emit_indent("MOUNT");
            }

            Statement::Shutdown => {
                self.uses_files = true;
                self.emit_indent("REBOOT_CMD 0x4321FEDC  ; LINUX_REBOOT_CMD_POWER_OFF");
            }

            Statement::Reboot => {
                self.uses_files = true;
                self.emit_indent("REBOOT_CMD 0x01234567  ; LINUX_REBOOT_CMD_RESTART");
            }

            Statement::Halt => {
                self.uses_files = true;
                self.emit_indent("REBOOT_CMD 0xCDEF0123  ; LINUX_REBOOT_CMD_HALT");
            }

            Statement::Unmount { target, lazy } => {
                self.uses_files = true;
                self.generate_cstr_expr(target);
                self.emit_indent("mov rdi, rax  ; mount target");
                let flags = if *lazy { 2 } else { 0 }; // MNT_DETACH = 2
                self.emit_indent(&format!(
                    "mov rsi, {}  ; flags{}",
                    flags,
                    if *lazy { " (MNT_DETACH)" } else { "" }
                ));
                self.emit_indent("UMOUNT");
            }

            Statement::PivotRoot { new_root, put_old } => {
                self.uses_files = true;
                self.emit_syscall_args(&[(new_root, "rdi"), (put_old, "rsi")]);
                self.emit_indent("PIVOT_ROOT");
            }

            Statement::Execute { path, args } => {
                self.uses_files = true;

                // A list variable (or any non-literal list expression):
                // argv is built at runtime by _list_to_argv, which sizes the
                // allocation and bounds the copy from a single read of the
                // list's length - the array cannot be overrun.
                let elements: &[Expr] = match args {
                    Expr::ListLit { elements } => elements,
                    other => {
                        self.uses_lists = true;
                        self.generate_expr(other);
                        self.emit_indent("push rax  ; park list pointer");
                        match path {
                            Expr::StringLit(s) => {
                                let label = self.add_string(s);
                                self.emit_indent(&format!("lea rax, [rel {}]", label));
                            }
                            _ => self.generate_cstr_expr(path),
                        }
                        self.emit_indent("mov rsi, rax  ; path (becomes argv[0])");
                        self.emit_indent("pop rdi  ; list pointer");
                        self.emit_indent("call _list_to_argv");
                        self.emit_indent("mov rsi, rax  ; argv array pointer");
                        self.emit_indent("mov rdi, [rsi]  ; path = argv[0]");
                        self.emit_indent("mov rdx, [rel _envp]  ; inherit the real environment");
                        self.emit_indent("EXECVE");
                        return;
                    }
                };

                let slot_count = elements.len() + 2; // path + args + NULL terminator
                let total_size = slot_count * 8;

                // Allocate the argv array via mmap (same pattern as list
                // literals elsewhere in this file), but WITHOUT the normal
                // Vox-list header - execve needs a plain C-style array.
                self.emit_indent("; Build argv array for execve");
                self.emit_indent("mov rdi, 0  ; addr = NULL");
                self.emit_indent(&format!("mov rsi, {}  ; size", total_size));
                self.emit_indent("mov rdx, 3  ; PROT_READ | PROT_WRITE");
                self.emit_indent("mov r10, 0x22  ; MAP_PRIVATE | MAP_ANONYMOUS");
                self.emit_indent("mov r8, -1  ; fd = -1");
                self.emit_indent("mov r9, 0  ; offset = 0");
                self.emit_indent("mov rax, 9  ; sys_mmap");
                self.emit_indent("syscall");
                let mmap_ok = self.new_label("execve_argv_mmap_ok");
                self.emit_indent("cmp rax, -4096  ; raw mmap returns -errno in [-4095,-1]");
                self.emit_indent(&format!("jbe {}", mmap_ok));
                self.emit_indent("mov rdi, 1");
                self.emit_indent("mov rax, 60");
                self.emit_indent("syscall");
                self.emit(&format!("{}:", mmap_ok));
                self.emit_indent("push rax  ; save argv array pointer");

                // Slot 0: path (also argv[0] by convention)
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("mov rbx, {}", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("mov rbx, rax");
                    }
                }
                self.emit_indent("mov rax, [rsp]  ; peek argv array pointer");
                self.emit_indent("mov [rax], rbx  ; argv[0] = path");

                // Slots 1..n: the rest of the arguments
                for (i, elem) in elements.iter().enumerate() {
                    match elem {
                        Expr::StringLit(s) => {
                            let label = self.add_string(s);
                            self.emit_indent(&format!("mov rbx, {}", label));
                        }
                        _ => {
                            self.generate_cstr_expr(elem);
                            self.emit_indent("mov rbx, rax");
                        }
                    }
                    self.emit_indent("mov rax, [rsp]  ; peek argv array pointer");
                    self.emit_indent(&format!("mov [rax+{}], rbx  ; argv[{}]", (i + 1) * 8, i + 1));
                }

                // Final slot: NULL terminator
                self.emit_indent("pop rax  ; argv array pointer");
                self.emit_indent(&format!("mov qword [rax+{}], 0  ; argv NULL terminator", (elements.len() + 1) * 8));

                // path -> rdi (argv[0], reloaded from the array, not re-generated)
                self.emit_indent("mov rsi, rax  ; argv array pointer");
                self.emit_indent("mov rdi, [rsi]  ; path = argv[0]");
                self.emit_indent("mov rdx, [rel _envp]  ; inherit the real environment");
                self.emit_indent("EXECVE");
            }

            Statement::Symlink { target, linkpath } => {
                self.uses_files = true;
                self.emit_syscall_args(&[(target, "rdi"), (linkpath, "rsi")]);
                self.emit_indent("SYMLINK");
            }

            Statement::Mknod { path, node_type, major, minor } => {
                self.uses_files = true;

                // Path -> rdi
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("lea rdi, [rel {}]", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("mov rdi, rax  ; path pointer");
                    }
                }
                self.emit_indent("push rdi  ; save path pointer");

                // Mode = S_IFCHR|S_IFBLK|S_IFIFO + 0666 permissions -> rsi
                // S_IFCHR = 0o020000 = 8192, S_IFBLK = 0o060000 = 24576,
                // S_IFIFO = 0o010000 = 4096, 0666 = 438
                let mode = match node_type {
                    DeviceNodeType::Character => 8192 + 438,
                    DeviceNodeType::Block => 24576 + 438,
                    DeviceNodeType::Fifo => 4096 + 438,
                };

                // dev = (major << 8) | minor -> rdx
                self.generate_expr(major);
                self.emit_indent("push rax  ; save major");
                self.generate_expr(minor);
                self.emit_indent("mov rcx, rax  ; minor");
                self.emit_indent("pop rax  ; major");
                self.emit_indent("shl rax, 8");
                self.emit_indent("or rax, rcx");
                self.emit_indent("mov rdx, rax  ; dev = (major << 8) | minor");

                self.emit_indent(&format!("mov rsi, {}  ; mode", mode));
                self.emit_indent("pop rdi  ; restore path pointer");
                self.emit_indent("MKNOD");
            }

            Statement::OnError { actions } => {
                // Check if last operation had an error
                let skip_label = self.new_label("skip_error");
                self.emit_indent("mov rax, [rel _last_error]");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jz {}  ; skip if no error", skip_label));
                
                // Execute all error actions
                for action in actions {
                    self.generate_statement(action);
                }
                
                // Clear the error
                self.emit_indent("mov qword [rel _last_error], 0");
                
                self.emit(&format!("{}:", skip_label));
            }
            
            Statement::BufferResize { name, new_size } => {
                if self.emit_load_named_var_addr(name) {
                    self.emit_indent("mov rdi, rax  ; buffer pointer");
                    self.generate_expr(new_size);
                    self.emit_indent("mov rsi, rax  ; new size");
                    self.emit_indent("call _realloc_buffer");
                    if let Some(offset) = self.get_var(name) {
                        self.emit_indent(&format!("mov [rbp-{}], rax  ; updated buffer pointer", offset));
                    } else if let Some(label) = self.global_var_label(name).cloned() {
                        self.emit_indent(&format!("mov [rel {}], rax  ; updated buffer pointer", label));
                    }
                }
            }
            
            Statement::LibraryDecl { name, version } => {
                // A `Library` declaration sets the codegen's current library
                // identity. Every `FunctionDef` and intra-library call site
                // after this point resolves its label through it (in shared
                // mode), so the exported symbol becomes `<lib>_<ver>_<func>`.
                // `collect_library_identity` already stashed the first
                // declaration before generation began, so a forward call to a
                // function defined above this line still mangles correctly;
                // re-setting here keeps the identity current as the walk
                // passes each declaration (matters once A2 concatenates
                // several libraries into one unit).
                self.current_library = Some((name.clone(), version.clone()));
                self.emit(&format!("; Library: {} version {}", name, version));
            }
            
            Statement::See { path, lib_name, lib_version } => {
                // See statement - emit as comment for now
                // The actual file inclusion is handled by the compiler frontend
                let lib_info = match (lib_name, lib_version) {
                    (Some(n), Some(v)) => format!(" (library: {} version {})", n, v),
                    (Some(n), None) => format!(" (library: {})", n),
                    _ => String::new(),
                };
                self.emit(&format!("; See: {}{}", path, lib_info));
            }
            
            // Time and Timer statements
            Statement::TimerDecl { name } => {
                self.uses_time = true;
                // Allocate the 8-byte name slot; the timer struct itself needs
                // TIMER_SIZE (56) bytes below it. Account for the full struct in
                // the frame size so later variables do not overlap the timer.
                let offset = self.alloc_var(name);
                self.variable_types.insert(name.clone(), VarType::Integer); // Track as integer for now
                self.stack_offset = std::cmp::max(self.stack_offset, offset + 48);
                self.emit_indent(&format!("; Timer declaration: {}", name));
                self.emit_indent(&format!("lea rax, [rbp - {}]", offset + 48)); // Point to timer area
                self.emit_indent("TIMER_INIT rax");
            }
            
            Statement::TimerStart { name } => {
                self.uses_time = true;
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("; Start timer: {}", name));
                    self.emit_indent(&format!("lea rax, [rbp - {}]", offset + 48));
                    self.emit_indent("TIMER_START rax");
                }
            }
            
            Statement::TimerStop { name } => {
                self.uses_time = true;
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("; Stop timer: {}", name));
                    self.emit_indent(&format!("lea rax, [rbp - {}]", offset + 48));
                    self.emit_indent("TIMER_STOP rax");
                }
            }
            
            Statement::Wait { duration, unit } => {
                self.uses_time = true;
                self.emit_indent("; Wait/Sleep");
                self.generate_expr(duration);
                match unit {
                    TimeUnit::Seconds => {
                        self.emit_indent("SLEEP_SECONDS rax");
                    }
                    TimeUnit::Milliseconds => {
                        self.emit_indent("SLEEP_MILLISECONDS rax");
                    }
                }
            }
            
            Statement::GetTime { into } => {
                self.uses_time = true;
                // Get current unix time and store in variable
                let offset = self.alloc_var(into);
                self.variable_types.insert(into.clone(), VarType::Integer);
                self.emit_indent(&format!("; Get current time into: {}", into));
                self.emit_indent("TIME_GET");
                self.emit_indent(&format!("mov [rbp - {}], rax", offset));
            }
        }
    }
    
    fn parse_format_spec(&self, fmt: Option<&str>) -> FormatSpec {
        match fmt {
            None => FormatSpec {
                width: None,
                zero_pad: false,
                base: IntegerBase::Decimal,
                precision: None,
            },
            Some(fmt_str) => {
                let mut spec = FormatSpec {
                    width: None,
                    zero_pad: false,
                    base: IntegerBase::Decimal,
                    precision: None,
                };
                
                // Check for precision format first (starts with '.')
                if fmt_str.starts_with('.') {
                    // Float precision format like .2, .4, etc.
                    if let Some(precision) = fmt_str.strip_prefix('.').and_then(|s| s.parse::<i32>().ok()) {
                        spec.precision = Some(precision);
                    }
                    return spec;
                }
                
                // Parse width and zero padding
                let mut remaining = fmt_str;
                let mut has_width = false;
                
                // Check if it starts with digit or '0' for width/padding
                if remaining.chars().next().map(|c| c.is_ascii_digit() || c == '0').unwrap_or(false) {
                    let zero_pad = remaining.starts_with('0');
                    let width_str = if zero_pad {
                        remaining.trim_start_matches('0')
                    } else {
                        remaining
                    };
                    
                    // Extract digits for width
                    let width_end = width_str.chars().take_while(|c| c.is_ascii_digit()).count();
                    if width_end > 0 {
                        let width_digits = &width_str[..width_end];
                        if let Ok(width) = width_digits.parse::<i32>() {
                            spec.width = Some(width);
                            spec.zero_pad = zero_pad;
                            has_width = true;
                            remaining = &fmt_str[if zero_pad { 1 + width_end } else { width_end }..];
                        }
                    }
                }
                
                // Parse base specifier from remaining characters
                if !remaining.is_empty() {
                    match remaining {
                        "x" => spec.base = IntegerBase::HexLower,
                        "X" => spec.base = IntegerBase::HexUpper,
                        "b" => spec.base = IntegerBase::Binary,
                        "o" => spec.base = IntegerBase::Octal,
                        _ => {
                            // If we parsed a width but no base, treat as decimal
                            if has_width {
                                spec.base = IntegerBase::Decimal;
                            }
                        }
                    }
                }
                
                spec
            }
        }
    }
    
    fn emit_formatted_value(&mut self, value_type: Option<VarType>, fmt: FormatSpec) {
        // Handle precision format for floats
        if let Some(precision) = fmt.precision {
            self.emit_indent("movq xmm0, rdi");
            self.emit_indent(&format!("mov rdi, {}", precision));
            self.emit_indent("call _print_float_precision");
            self.uses_floats = true;
            self.uses_format = true;
            return;
        }
        
        // If no specific format (default case), handle by type
        if fmt.width.is_none() && matches!(fmt.base, IntegerBase::Decimal) {
            match value_type {
                Some(VarType::Float) => {
                    self.emit_indent("movq xmm0, rdi");
                    self.emit_indent("PRINT_FLOAT");
                    self.uses_floats = true;
                }
                Some(VarType::Buffer) => {
                    // rdi must be the struct pointer (not data area) here.
                    // The fixed call sites guarantee this; it's documented on
                    // each one. Kept separate from VarType::String to make the
                    // contract explicit and catch any future callers that get
                    // it wrong (PRINT_BUF on a data pointer would print garbage).
                    self.emit_indent("PRINT_BUF rdi");
                }
                Some(VarType::String) => {
                    self.emit_indent("PRINT_CSTR rdi");
                }
                _ => {
                    self.emit_indent("PRINT_INT rdi");
                }
            }
            return;
        }
        
        // Handle integer formatting with width and base
        match fmt.base {
            IntegerBase::Decimal => {
                match (fmt.width, fmt.zero_pad) {
                    (Some(width), true) => {
                        self.emit_indent(&format!("PRINT_INT_ZEROPAD rdi, {}", width));
                    }
                    (Some(width), false) => {
                        self.emit_indent(&format!("PRINT_INT_PADDED rdi, {}", width));
                    }
                    _ => {
                        self.emit_indent("PRINT_INT rdi");
                    }
                }
                self.uses_format = true;
            }
            IntegerBase::HexLower => {
                if fmt.width.is_some() {
                    match (fmt.width, fmt.zero_pad) {
                        (Some(width), true) => {
                            self.emit_indent(&format!("PRINT_HEX_LOWER_ZEROPAD rdi, {}", width));
                        }
                        (Some(width), false) => {
                            self.emit_indent(&format!("PRINT_HEX_LOWER_PADDED rdi, {}", width));
                        }
                        _ => {
                            self.emit_indent("PRINT_HEX_LOWER rdi");
                        }
                    }
                } else {
                    self.emit_indent("PRINT_HEX_LOWER rdi");
                }
                self.uses_format = true;
            }
            IntegerBase::HexUpper => {
                if fmt.width.is_some() {
                    match (fmt.width, fmt.zero_pad) {
                        (Some(width), true) => {
                            self.emit_indent(&format!("PRINT_HEX_UPPER_ZEROPAD rdi, {}", width));
                        }
                        (Some(width), false) => {
                            self.emit_indent(&format!("PRINT_HEX_UPPER_PADDED rdi, {}", width));
                        }
                        _ => {
                            self.emit_indent("PRINT_HEX_UPPER rdi");
                        }
                    }
                } else {
                    self.emit_indent("PRINT_HEX_UPPER rdi");
                }
                self.uses_format = true;
            }
            IntegerBase::Binary => {
                if fmt.width.is_some() {
                    match (fmt.width, fmt.zero_pad) {
                        (Some(width), true) => {
                            self.emit_indent(&format!("PRINT_BINARY_ZEROPAD rdi, {}", width));
                        }
                        (Some(width), false) => {
                            self.emit_indent(&format!("PRINT_BINARY_PADDED rdi, {}", width));
                        }
                        _ => {
                            self.emit_indent("PRINT_BINARY rdi");
                        }
                    }
                } else {
                    self.emit_indent("PRINT_BINARY rdi");
                }
                self.uses_format = true;
            }
            IntegerBase::Octal => {
                if fmt.width.is_some() {
                    match (fmt.width, fmt.zero_pad) {
                        (Some(width), true) => {
                            self.emit_indent(&format!("PRINT_OCTAL_ZEROPAD rdi, {}", width));
                        }
                        (Some(width), false) => {
                            self.emit_indent(&format!("PRINT_OCTAL_PADDED rdi, {}", width));
                        }
                        _ => {
                            self.emit_indent("PRINT_OCTAL rdi");
                        }
                    }
                } else {
                    self.emit_indent("PRINT_OCTAL rdi");
                }
                self.uses_format = true;
            }
        }
    }
    
    fn generate_print(&mut self, value: &Expr, without_newline: bool) {
        self.uses_io = true;
        match value {
            Expr::FormatString { parts } => {
                // Print each part of the format string
                for part in parts {
                    match part {
                        FormatPart::Literal(s) => {
                            let label = self.add_string(s);
                            self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                        }
                        FormatPart::Variable { name, format } => {
                            let var_type: Option<VarType> = match self.resolve_format_variable(name) {
                                FormatPartValue::Loaded(t) => {
                                    self.emit_indent("mov rdi, rax");
                                    t
                                }
                                FormatPartValue::Literal(s) => {
                                    let label = self.add_string(&s);
                                    self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                                    continue;
                                }
                                FormatPartValue::Unknown => {
                                    let placeholder = format!("{{{}}}", name);
                                    let label = self.add_string(&placeholder);
                                    self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                                    continue;
                                }
                            };

                            // Parse format spec and emit formatted value.
                            // Buffer: use PRINT_BUF with the struct pointer (length-bounded,
                            // avoids the NUL-scan stale-byte bug). For all other types, rdi
                            // already holds the correct value/pointer.
                            if var_type == Some(VarType::Mixed) {
                                // Heterogeneous-list element: dispatch on its
                                // runtime tag. Format specs are parsed but
                                // only the default spec is honored for now.
                                if let Some(slot) = self.mixed_tag_slots.get(name.as_str()).copied() {
                                    self.emit_indent(&format!(
                                        "movzx r11, byte [rbp-{}]  ; element's runtime type tag",
                                        slot
                                    ));
                                    self.emit_mixed_print_dispatch("r11");
                                } else {
                                    self.emit_indent("PRINT_INT rdi");
                                }
                            } else if var_type == Some(VarType::Buffer) {
                                let fmt_spec = self.parse_format_spec(format.as_deref());
                                if fmt_spec.width.is_none() && matches!(fmt_spec.base, IntegerBase::Decimal) && fmt_spec.precision.is_none() {
                                    self.emit_indent("PRINT_BUF rdi");
                                } else {
                                    // Format spec: value is formatted as a number, so point
                                    // rdi at the data area so the formatter reads the string.
                                    self.emit_indent("add rdi, 24  ; buffer data area (header is 24 bytes)");
                                    self.emit_formatted_value(var_type, fmt_spec);
                                }
                            } else if var_type == Some(VarType::List) {
                                // Whole-list interpolation: rdi holds the list
                                // pointer; _list_print renders [elem, elem, ...].
                                // Format specs on a list are not honored (out of
                                // scope for stage 000 - the default rendering only).
                                self.uses_lists = true;
                                self.emit_indent("call _list_print");
                            } else if var_type == Some(VarType::Map) {
                                // Whole-map interpolation: rdi holds the map
                                // pointer; _map_print renders {"k": v, ...}.
                                // (stage 1e2)
                                self.uses_maps = true;
                                self.emit_indent("call _map_print");
                            } else {
                                let fmt_spec = self.parse_format_spec(format.as_deref());
                                self.emit_formatted_value(var_type, fmt_spec);
                            }
                        }
                        FormatPart::Expression { expr, format } => {
                            let expr_type = self.infer_expr_type(expr);
                            let fmt_spec = self.parse_format_spec(format.as_deref());

                            // A bare `nothing` literal interpolated into a
                            // format string renders `nothing` (it would else
                            // infer as Integer and print `0`). A `value`/
                            // mixed expression that *holds* nothing is
                            // already handled by the mixed dispatch below
                            // via VarType::Mixed; this is only for the literal
                            // itself. (stage 1e3)
                            if matches!(expr.as_ref(), Expr::NothingLit) {
                                let label = self.add_string("nothing");
                                self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                            } else if expr_type == Some(VarType::Buffer) {
                                // For buffer expressions: generate the struct pointer,
                                // not the data-area pointer - PRINT_BUF reads its own
                                // length from the struct, so it needs the base pointer.
                                self.generate_expr(expr);
                                self.emit_indent("mov rdi, rax");
                                if fmt_spec.width.is_none() && matches!(fmt_spec.base, IntegerBase::Decimal) && fmt_spec.precision.is_none() {
                                    self.emit_indent("PRINT_BUF rdi");
                                } else {
                                    // Format spec present: adjust to data area for
                                    // the NUL-scanned formatter.
                                    self.emit_indent("add rdi, 24  ; buffer data area");
                                    self.emit_formatted_value(expr_type, fmt_spec);
                                }
                            } else if expr_type == Some(VarType::Map) {
                                // Map expression interpolation: rdi holds the map
                                // pointer; _map_print renders it. (stage 1e2)
                                self.generate_expr(expr);
                                self.emit_indent("mov rdi, rax");
                                self.uses_maps = true;
                                self.emit_indent("call _map_print");
                            } else {
                                // Non-buffer: generate_cstr_expr adds +24 for buffer
                                // (irrelevant here), then falls through to normal path.
                                self.generate_cstr_expr(expr);
                                self.emit_indent("mov rdi, rax");
                                self.emit_formatted_value(expr_type, fmt_spec);
                            }
                        }
                    }
                }
                if !without_newline {
                    self.emit_indent("PRINT_NEWLINE");
                }
                return;
            }
            
            Expr::StringLit(s) => {
                // Check if this string literal is actually a variable reference
                if self.emit_load_named_var_into_rax(s) {
                    self.emit_indent("mov rdi, rax");
                    let var_type = self.variable_types.get(s).cloned();
                    match var_type {
                        Some(VarType::Mixed) => {
                            if let Some(slot) = self.mixed_tag_slots.get(s).copied() {
                                self.emit_indent(&format!(
                                    "movzx r11, byte [rbp-{}]  ; element's runtime type tag",
                                    slot
                                ));
                                self.emit_mixed_print_dispatch("r11");
                            } else {
                                self.emit_indent("PRINT_INT rdi");
                            }
                        }
                        Some(VarType::Buffer) => {
                            self.emit_indent("PRINT_BUF rdi");
                        }
                        Some(VarType::String) => {
                            self.emit_indent("PRINT_CSTR rdi");
                        }
                        Some(VarType::Float) => {
                            self.emit_indent("movq xmm0, rdi");
                            self.emit_indent("PRINT_FLOAT");
                            self.uses_floats = true;
                        }
                        Some(VarType::List) => {
                            // String literal that is actually a list variable
                            // reference - render the whole list.
                            self.uses_lists = true;
                            self.emit_indent("call _list_print");
                        }
                        Some(VarType::Map) => {
                            // String literal that is actually a map variable
                            // reference - render the whole map. (stage 1e2)
                            self.uses_maps = true;
                            self.emit_indent("call _map_print");
                        }
                        _ => {
                            self.emit_indent("PRINT_INT rdi");
                        }
                    }
                } else {
                    if !self.emit_global_constant_format_fallback(s, None) {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                    }
                }
            }
            
            Expr::IntegerLit(n) => {
                self.emit_indent(&format!("mov rdi, {}", n));
                self.emit_indent("PRINT_INT rdi");
            }
            
            Expr::FloatLit(n) => {
                let label = self.add_float(*n);
                self.emit_indent(&format!("FLOAT_LOAD {}", label));
                self.emit_indent("PRINT_FLOAT");
                self.uses_floats = true;
            }

            // `print nothing.` — the literal null (stage 1e3, tag 6). It
            // would otherwise fall to the catch-all (infer_expr_type maps it
            // to Integer) and print `0`, so handle it explicitly. Inside a
            // list/map slot or a `value`, the mixed print dispatch already
            // renders `nothing`; this arm is for a bare literal argument.
            Expr::NothingLit => {
                let label = self.add_string("nothing");
                self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
            }
            
            Expr::Identifier(name) => {
                if self.emit_load_named_var_into_rax(name) {
                    self.emit_indent("mov rdi, rax");
                    let var_type = self.variable_types.get(name).cloned();
                    match var_type {
                        Some(VarType::Mixed) => {
                            if let Some(slot) = self.mixed_tag_slots.get(name).copied() {
                                self.emit_indent(&format!(
                                    "movzx r11, byte [rbp-{}]  ; element's runtime type tag",
                                    slot
                                ));
                                self.emit_mixed_print_dispatch("r11");
                            } else {
                                self.emit_indent("PRINT_INT rdi");
                            }
                        }
                        Some(VarType::Buffer) => {
                            // Dynamic buffer - PRINT_BUF reads length/data directly
                            // from the struct, no NUL-scan needed
                            self.emit_indent("PRINT_BUF rdi");
                        }
                        Some(VarType::String) => {
                            // Raw string pointer (from lists, etc.)
                            self.emit_indent("PRINT_CSTR rdi");
                        }
                        Some(VarType::Float) => {
                            self.emit_indent("movq xmm0, rdi");
                            self.emit_indent("PRINT_FLOAT");
                            self.uses_floats = true;
                        }
                        Some(VarType::List) => {
                            // Whole-list print: rdi holds the list pointer;
                            // _list_print walks the slots and renders
                            // [elem, elem, ...] with per-tag dispatch.
                            self.uses_lists = true;
                            self.emit_indent("call _list_print");
                        }
                        Some(VarType::Map) => {
                            // Whole-map print: rdi holds the map pointer;
                            // _map_print walks the entries and renders
                            // {"key": value, ...} with per-tag dispatch.
                            // (stage 1e2)
                            self.uses_maps = true;
                            self.emit_indent("call _map_print");
                        }
                        _ => {
                            self.emit_indent("PRINT_INT rdi");
                        }
                    }
                } else if name == "_iter" {
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("PRINT_INT rdi");
                }
            }
            
            Expr::ElementAccess { list, .. } => {
                // Get the list's element type for proper printing. For a
                // named list this is the recorded element type; for a list
                // literal it is the literal's homogeneous element type (or
                // Mixed if the literal is heterogeneous); for any other
                // mixed list expression (e.g. a chained `element 2 of
                // element 2 of deep`) the elements are runtime-tagged, so
                // `generate_expr` left the slot's tag in r11 and we dispatch
                // on it (stage 1e1).
                let elem_type = if let Expr::Identifier(name) = list.as_ref() {
                    self.list_element_types.get(name).cloned()
                } else if let Expr::ListLit { elements } = list.as_ref() {
                    if self.list_expr_is_mixed(list) {
                        Some(VarType::Mixed)
                    } else if let Some(first) = elements.first() {
                        match first {
                            Expr::IntegerLit(_) => Some(VarType::Integer),
                            Expr::FloatLit(_) => Some(VarType::Float),
                            Expr::StringLit(_) => Some(VarType::String),
                            Expr::BoolLit(_) => Some(VarType::Boolean),
                            Expr::ListLit { .. } => Some(VarType::List),
                            Expr::MapLit { .. } => Some(VarType::Map),
                            _ => None,
                        }
                    } else {
                        None
                    }
                } else if self.list_expr_is_mixed(list) {
                    Some(VarType::Mixed)
                } else {
                    None
                };

                self.generate_expr(value);
                self.emit_indent("mov rdi, rax");

                match elem_type {
                    Some(VarType::Mixed) => {
                        // generate_expr left the slot's type tag in r11
                        // (captured immediately - nothing can clobber it
                        // between the element load and this dispatch).
                        self.emit_mixed_print_dispatch("r11");
                    }
                    Some(VarType::List) => {
                        // A homogeneous list-of-lists: rdi already holds the
                        // child list pointer, so recurse into `_list_print`
                        // (stage 1e1).
                        self.emit_indent("call _list_print");
                        self.uses_lists = true;
                    }
                    Some(VarType::Map) => {
                        // A homogeneous list-of-maps: rdi already holds the
                        // child map pointer, so recurse into `_map_print`
                        // (stage 1e2).
                        self.emit_indent("call _map_print");
                        self.uses_maps = true;
                    }
                    Some(VarType::String) => {
                        self.emit_indent("PRINT_CSTR rdi");
                    }
                    Some(VarType::Float) => {
                        self.emit_indent("movq xmm0, rdi");
                        self.emit_indent("PRINT_FLOAT");
                        self.uses_floats = true;
                    }
                    _ => {
                        self.emit_indent("PRINT_INT rdi");
                    }
                }
            }
            
            Expr::MapAccess { .. } => {
                // A map value read leaves its runtime tag in r11 (mirroring
                // ElementAccess), so dispatch on it immediately. The map's
                // value may be any tagged type (stage 1e2).
                self.generate_expr(value);
                self.emit_indent("mov rdi, rax");
                self.uses_maps = true;
                self.emit_mixed_print_dispatch("r11");
            }

            _ => {
                let is_float = self.is_float_expr(value);
                let expr_type = self.infer_expr_type(value);
                // A value carrying a runtime tag - `mixed's first`/`last`, a
                // mixed element read, or a `value`-returning call - must be
                // rendered by that tag, not by its static type. The tag is only
                // valid until the next call or syscall, so capture it here.
                let tag_source = self.runtime_tag_source(value);
                self.generate_expr(value);
                if let Some(src) = tag_source {
                    if let RuntimeTagSource::ShadowSlot(off) = src {
                        self.emit_indent(&format!(
                            "movzx r11, byte [rbp-{}]  ; value tag (shadow slot)", off
                        ));
                    }
                    self.emit_indent("mov rdi, rax");
                    self.emit_mixed_print_dispatch("r11");
                } else if is_float {
                    self.emit_indent("movq xmm0, rax");
                    self.emit_indent("PRINT_FLOAT");
                    self.uses_floats = true;
                } else {
                    self.emit_indent("mov rdi, rax");
                    if matches!(expr_type, Some(VarType::String)) {
                        self.emit_indent("PRINT_CSTR rdi");
                    } else if matches!(expr_type, Some(VarType::List)) {
                        // A bare list literal, or `first`/`last` of a
                        // homogeneous list-of-lists: rdi holds a list pointer,
                        // so recurse into `_list_print` (stage 1e1).
                        self.emit_indent("call _list_print");
                        self.uses_lists = true;
                    } else if matches!(expr_type, Some(VarType::Map)) {
                        // A bare map literal: rdi holds a map pointer, so
                        // recurse into `_map_print` (stage 1e2).
                        self.emit_indent("call _map_print");
                        self.uses_maps = true;
                    } else {
                        self.emit_indent("PRINT_INT rdi");
                    }
                }
            }
        }
        if !without_newline {
            self.emit_indent("PRINT_NEWLINE");
        }
    }
    
    /// Evaluate a sequence of syscall argument expressions safely.
    ///
    /// Each expression's result (in rax) is parked on the stack before the
    /// next expression is generated, then everything is popped into the
    /// target registers in reverse order. Loading argument registers
    /// directly between generate_expr calls is unsound: a later expression
    /// containing a function call, format string, or buffer operation can
    /// clobber any register already loaded (user functions only preserve
    /// rbp, and syscalls clobber rcx/r11).
    fn emit_syscall_args(&mut self, args: &[(&Expr, &'static str)]) {
        for (expr, _) in args {
            self.generate_cstr_expr(expr);
            self.emit_indent("push rax  ; park syscall arg");
        }
        for (_, reg) in args.iter().rev() {
            self.emit_indent(&format!("pop {}", reg));
        }
    }

    /// Evaluate an expression that will be handed to the kernel as a
    /// C-string (path, mount option, execve argument). Buffer variables
    /// evaluate to their struct pointer (capacity/length/flags header
    /// first), so adjust to the data area - the runtime maintains a
    /// trailing NUL at data[length], making buffer contents directly
    /// usable as a C string. Text variables and string literals already
    /// point at NUL-terminated bytes.
    fn generate_cstr_expr(&mut self, expr: &Expr) {
        self.generate_expr(expr);
        if self.infer_expr_type(expr) == Some(VarType::Buffer) {
            self.emit_indent("add rax, 24  ; buffer data area (header is 24 bytes, data is NUL-terminated)");
        }
    }

    /// Materialize a map key expression as a NUL-terminated text pointer in
    /// `rax`. A quoted key (`"name"`) is ALWAYS the literal text, even when a
    /// variable with that name exists — otherwise the key would silently
    /// become the variable's value (e.g. `{"inner": ...}` colliding with a
    /// later `a map called "inner"` stored the variable's pointer as the key
    /// and crashed `_map_print`'s C-string read). A non-literal key (a bare
    /// variable holding text) is evaluated normally. (stage 1e2)
    fn generate_text_key(&mut self, key: &Expr) {
        match key {
            Expr::StringLit(s) => {
                let label = self.add_string(s);
                self.emit_indent(&format!("lea rax, [rel {}]  ; literal map key", label));
            }
            _ => self.generate_expr(key),
        }
    }

    /// True when comparing this expression with `==`/`!=` needs byte-content
    /// comparison (_str_eq) rather than a raw pointer `cmp`. Text variables,
    /// string literals, and buffers all qualify - two equal-content strings
    /// are essentially never the same address (add_string mints a fresh
    /// label per literal occurrence with no deduplication), so pointer
    /// comparison silently fails for the overwhelmingly common case of
    /// `some_variable is "literal"`.
    fn is_stringy_expr(&self, expr: &Expr) -> bool {
        matches!(self.infer_expr_type(expr), Some(VarType::String) | Some(VarType::Buffer))
    }

    /// True if `expr` is a `nothing`/`null`/`nil` literal (stage 1e3, tag 6).
    /// Used by the nothing-equality guard in `generate_condition`.
    fn is_nothing_expr(&self, expr: &Expr) -> bool {
        matches!(expr, Expr::NothingLit)
    }

    fn generate_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::IntegerLit(n) => {
                self.emit_indent(&format!("mov rax, {}", n));
            }
            
            Expr::FloatLit(n) => {
                self.uses_floats = true;
                // Store float as 64-bit IEEE 754 in data section
                let label = self.add_float(*n);
                self.emit_indent(&format!("FLOAT_LOAD {}", label));
                // Store float bits in rax for stack operations
                self.emit_indent("XMM0_TO_RAX");
            }
            
            Expr::BoolLit(b) => {
                self.emit_indent(&format!("mov rax, {}", if *b { 1 } else { 0 }));
            }

            // The nothing/null literal (stage 1e3, tag 6). The payload is 0;
            // the tag is written by callers via `emit_time_expr_tag`
            // (returns `Some(TAG_NOTHING)`) at every store/forward site, so
            // here we only materialize the payload.
            Expr::NothingLit => {
                self.emit_indent("xor rax, rax  ; nothing literal, payload 0 (tag 6 set by caller)");
            }
            
            Expr::StringLit(s) => {
                // Check if this string literal is actually a variable reference
                if self.emit_load_named_var_into_rax(s) {
                } else {
                    let label = self.add_string(s);
                    self.emit_indent(&format!("lea rax, [rel {}]", label));
                }
            }
            
            Expr::Identifier(name) => {
                if self.emit_load_named_var_into_rax(name) {
                }
            }
            
            Expr::BinaryOp { left, op, right } => {
                // Use has_float_operands for instruction selection (includes comparisons)
                let has_floats = self.has_float_operands(left) || self.has_float_operands(right);

                // `x is nothing` / `x is not nothing` in expression position
                // (stage 1e3): tag-6 equality, result 0/1 in rax. MUST precede
                // the float/stringy/integer paths or `0 is nothing` would
                // compare payloads and be true. Mirrors the condition-position
                // guard in `generate_condition`.
                if matches!(op, BinaryOperator::Equal | BinaryOperator::NotEqual)
                    && (self.is_nothing_expr(left) || self.is_nothing_expr(right))
                {
                    let equal = matches!(op, BinaryOperator::Equal);
                    if self.is_nothing_expr(left) && self.is_nothing_expr(right) {
                        self.emit_indent(&format!("mov rax, {}  ; nothing is nothing", if equal { 1 } else { 0 }));
                    } else {
                        let value = if self.is_nothing_expr(left) { right } else { left };
                        match self.emit_time_expr_tag(value) {
                            Some(t) => {
                                let holds = if equal { t == TAG_NOTHING } else { t != TAG_NOTHING };
                                self.emit_indent(&format!(
                                    "mov rax, {}  ; is {}nothing folded (static tag {})",
                                    if holds { 1 } else { 0 }, if equal { "" } else { "not " }, t
                                ));
                            }
                            None => {
                                self.generate_expr(value);
                                match self.runtime_tag_source(value) {
                                    Some(src) => {
                                        if let RuntimeTagSource::ShadowSlot(off) = src {
                                            self.emit_indent(&format!(
                                                "movzx r11, byte [rbp-{}]  ; load mixed element tag",
                                                off
                                            ));
                                        }
                                        self.emit_indent("xor rax, rax");
                                        self.emit_indent(&format!(
                                            "cmp r11, {}  ; is nothing?", TAG_NOTHING
                                        ));
                                        self.emit_indent(if equal { "sete al" } else { "setne al" });
                                        self.emit_indent("movzx rax, al");
                                    }
                                    // No tag anywhere and r11 holds unrelated
                                    // data (a call or syscall clobbers it), so
                                    // the value cannot be nothing as far as the
                                    // compiler can tell - answer statically.
                                    None => self.emit_indent(&format!(
                                        "mov rax, {}  ; is {}nothing: operand carries no tag",
                                        u8::from(!equal), if equal { "" } else { "not " }
                                    )),
                                }
                            }
                        }
                    }
                } else if has_floats {
                    self.uses_floats = true;
                    // Float operations using coreasm macros
                    // Convert int operands to float if needed
                    let left_is_float = self.is_float_expr(left);
                    let right_is_float = self.is_float_expr(right);
                    
                    self.generate_expr(right);
                    if !right_is_float {
                        // Convert integer in rax to float
                        self.emit_indent("INT_TO_FLOAT");
                        self.emit_indent("XMM0_TO_RAX");
                    }
                    self.emit_indent("push rax");
                    self.generate_expr(left);
                    if !left_is_float {
                        // Convert integer in rax to float
                        self.emit_indent("INT_TO_FLOAT");
                        self.emit_indent("XMM0_TO_RAX");
                    }
                    self.emit_indent("RAX_TO_XMM0");          // left in xmm0
                    self.emit_indent("pop rax");
                    self.emit_indent("RAX_TO_XMM1");          // right in xmm1
                    
                    match op {
                        BinaryOperator::Add => {
                            self.emit_indent("FLOAT_ADD");
                        }
                        BinaryOperator::Subtract => {
                            self.emit_indent("FLOAT_SUB");
                        }
                        BinaryOperator::Multiply => {
                            self.emit_indent("FLOAT_MUL");
                        }
                        BinaryOperator::Divide => {
                            self.emit_indent("FLOAT_DIV");
                        }
                        BinaryOperator::Modulo => {
                            self.emit_indent("FLOAT_MOD");
                        }
                        BinaryOperator::Equal => {
                            self.emit_indent("FLOAT_EQ");
                        }
                        BinaryOperator::NotEqual => {
                            self.emit_indent("FLOAT_NE");
                        }
                        BinaryOperator::Greater => {
                            self.emit_indent("FLOAT_GT");
                        }
                        BinaryOperator::Less => {
                            self.emit_indent("FLOAT_LT");
                        }
                        BinaryOperator::GreaterEqual => {
                            self.emit_indent("FLOAT_GE");
                        }
                        BinaryOperator::LessEqual => {
                            self.emit_indent("FLOAT_LE");
                        }
                        BinaryOperator::And | BinaryOperator::Or => {
                            // Boolean ops - convert to int first
                            self.emit_indent("FLOAT_TO_INT");
                            self.emit_indent("mov rbx, rax");
                            self.emit_indent("RAX_TO_XMM0");
                            self.emit_indent("FLOAT_TO_INT");
                            if matches!(op, BinaryOperator::And) {
                                self.emit_indent("and rax, rbx");
                            } else {
                                self.emit_indent("or rax, rbx");
                            }
                        }
                        BinaryOperator::BitAnd | BinaryOperator::BitOr | 
                        BinaryOperator::BitXor | BinaryOperator::ShiftLeft |
                        BinaryOperator::ShiftRight => {
                            // Bitwise ops on floats - convert to int first
                            self.emit_indent("FLOAT_TO_INT");
                            self.emit_indent("mov rbx, rax");
                            self.emit_indent("RAX_TO_XMM0");
                            self.emit_indent("FLOAT_TO_INT");
                            match op {
                                BinaryOperator::BitAnd => self.emit_indent("and rax, rbx"),
                                BinaryOperator::BitOr => self.emit_indent("or rax, rbx"),
                                BinaryOperator::BitXor => self.emit_indent("xor rax, rbx"),
                                BinaryOperator::ShiftLeft => {
                                    self.emit_indent("mov cl, bl");
                                    self.emit_indent("shl rax, cl");
                                }
                                BinaryOperator::ShiftRight => {
                                    self.emit_indent("mov cl, bl");
                                    self.emit_indent("shr rax, cl");
                                }
                                _ => {}
                            }
                        }
                    }
                    // Store result back in rax (as float bits)
                    if !matches!(op, BinaryOperator::Equal | BinaryOperator::NotEqual |
                                     BinaryOperator::Greater | BinaryOperator::Less |
                                     BinaryOperator::GreaterEqual | BinaryOperator::LessEqual |
                                     BinaryOperator::And | BinaryOperator::Or) {
                        self.emit_indent("XMM0_TO_RAX");
                    }
                } else if matches!(op, BinaryOperator::Equal | BinaryOperator::NotEqual)
                    && (self.is_stringy_expr(left) || self.is_stringy_expr(right))
                {
                    // Content comparison via _str_eq/_mem_eq - see emit_stringy_equality.
                    self.emit_stringy_equality(left, right);
                    if matches!(op, BinaryOperator::NotEqual) {
                        self.emit_indent("xor rax, 1  ; 1=equal -> 0=notequal");
                    }
                } else {
                    // Integer operations
                    self.uses_ints = true;
                    let arith = self.is_arithmetic_operator(op);
                    self.generate_expr(right);
                    if arith {
                        self.emit_nothing_operand_check(right);
                    }
                    self.emit_indent("push rax");
                    self.generate_expr(left);
                    if arith {
                        self.emit_nothing_operand_check(left);
                    }
                    self.emit_indent("pop rbx");

                    match op {
                        BinaryOperator::Add => {
                            self.emit_indent("INT_ADD");
                        }
                        BinaryOperator::Subtract => {
                            self.emit_indent("INT_SUB");
                        }
                        BinaryOperator::Multiply => {
                            self.emit_indent("INT_MUL");
                        }
                        BinaryOperator::Divide => {
                            self.emit_indent("INT_DIV");
                        }
                        BinaryOperator::Modulo => {
                            self.emit_indent("INT_MOD");
                        }
                        BinaryOperator::Equal => {
                            self.emit_indent("INT_EQ");
                        }
                        BinaryOperator::NotEqual => {
                            self.emit_indent("INT_NE");
                        }
                        BinaryOperator::Greater => {
                            self.emit_indent("INT_GT");
                        }
                        BinaryOperator::Less => {
                            self.emit_indent("INT_LT");
                        }
                        BinaryOperator::GreaterEqual => {
                            self.emit_indent("INT_GE");
                        }
                        BinaryOperator::LessEqual => {
                            self.emit_indent("INT_LE");
                        }
                        BinaryOperator::And => {
                            self.emit_indent("INT_AND");
                        }
                        BinaryOperator::Or => {
                            self.emit_indent("INT_OR");
                        }
                        BinaryOperator::BitAnd => {
                            self.emit_indent("and rax, rbx");
                        }
                        BinaryOperator::BitOr => {
                            self.emit_indent("or rax, rbx");
                        }
                        BinaryOperator::BitXor => {
                            self.emit_indent("xor rax, rbx");
                        }
                        BinaryOperator::ShiftLeft => {
                            self.emit_indent("mov cl, bl");
                            self.emit_indent("shl rax, cl");
                        }
                        BinaryOperator::ShiftRight => {
                            self.emit_indent("mov cl, bl");
                            self.emit_indent("shr rax, cl");
                        }
                    }
                }
            }
            
            Expr::UnaryOp { op, operand } => {
                match op {
                    UnaryOperator::Negate => {
                        // Check operand type to use correct negate operation
                        match self.infer_expr_type(operand) {
                            Some(VarType::Float) => {
                                self.uses_floats = true;
                                // For float negate, generate operand and handle xmm0/rax properly
                                self.generate_expr(operand);
                                // Move result from rax back to xmm0 for negation
                                self.emit_indent("movq xmm0, rax");
                                // Apply architecture-specific float negation
                                self.emit_indent("FLOAT_NEG");
                                // Move result back to rax for consistency
                                self.emit_indent("XMM0_TO_RAX");
                            }
                            _ => {
                                self.uses_ints = true;
                                self.generate_expr(operand);
                                self.emit_indent("INT_NEG");
                            }
                        }
                    }
                    UnaryOperator::Not => {
                        self.uses_ints = true;
                        self.generate_expr(operand);
                        self.emit_indent("INT_NOT");
                    }
                }
            }
            
            Expr::PropertyCheck { value, property } => {
                self.generate_expr(value);
                match property {
                    Property::Even => {
                        self.emit_indent("test rax, 1");
                        self.emit_indent("setz al");
                        self.emit_indent("movzx rax, al");
                    }
                    Property::Odd => {
                        self.emit_indent("test rax, 1");
                        self.emit_indent("setnz al");
                        self.emit_indent("movzx rax, al");
                    }
                    Property::Zero => {
                        self.emit_indent("test rax, rax");
                        self.emit_indent("setz al");
                        self.emit_indent("movzx rax, al");
                    }
                    Property::Positive => {
                        self.emit_indent("test rax, rax");
                        self.emit_indent("setg al");
                        self.emit_indent("movzx rax, al");
                    }
                    Property::Negative => {
                        self.emit_indent("test rax, rax");
                        self.emit_indent("setl al");
                        self.emit_indent("movzx rax, al");
                    }
                    Property::Empty => {
                        // For buffer/list variables, check the size field at offset 8
                        let is_buffer_or_list = match value.as_ref() {
                            Expr::StringLit(s) | Expr::Identifier(s) => {
                                matches!(self.variable_types.get(s), Some(VarType::Buffer) | Some(VarType::List))
                            }
                            _ => false,
                        };
                        if is_buffer_or_list {
                            self.emit_indent("mov rax, [rax + 8]  ; get size/length");
                        }
                        self.emit_indent("test rax, rax");
                        self.emit_indent("setz al");
                        self.emit_indent("movzx rax, al");
                    }
                }
            }

            // Runtime type predicate (stage 1c): `item is a text` etc.
            // Folds to a constant when the operand's tag is statically
            // provable (via emit_time_expr_tag, which also handles the
            // BoolLit-is-boolean case correctly); otherwise reads the
            // slot's runtime tag (r11 for a fresh element read, the
            // variable's shadow tag slot for a Mixed identifier) and
            // compares it against the target noun's tag.
            Expr::TypeCheck { value, type_noun } => {
                let target = type_to_tag(type_noun).expect("type predicate noun is scalar");
                let noun = type_noun_name(type_noun);
                match self.predicate_static_tag(value) {
                    Some(t) => {
                        self.emit_indent(&format!(
                            "mov rax, {}  ; is a {} folded (static tag {})",
                            u8::from(t == target), noun, t
                        ));
                    }
                    None => {
                        self.generate_expr(value);
                        match self.runtime_tag_source(value) {
                            Some(src) => {
                                if let RuntimeTagSource::ShadowSlot(off) = src {
                                    self.emit_indent(&format!(
                                        "movzx r11, byte [rbp-{}]  ; load mixed element tag",
                                        off
                                    ));
                                }
                                self.emit_indent("xor rax, rax");
                                self.emit_indent(&format!(
                                    "cmp r11, {}  ; is a {}?", target, noun
                                ));
                                self.emit_indent("sete al");
                                self.emit_indent("movzx rax, al");
                            }
                            // No tag exists for this value and r11 holds
                            // something unrelated. Such a value is stored with
                            // the integer tag everywhere else, so answer
                            // consistently instead of comparing garbage.
                            None => self.emit_indent(&format!(
                                "mov rax, {}  ; is a {}: no runtime tag, treated as number",
                                u8::from(target == TAG_INTEGER), noun
                            )),
                        }
                    }
                }
            }

            Expr::FileAvailable { path } => {
                self.uses_files = true;
                self.generate_cstr_expr(path);
                self.emit_indent("FILE_AVAILABLE");
            }

            Expr::Range { .. } => {}

            Expr::FunctionCall { name, args } => {
                self.emit_function_call(name, args);
                // Return value already in rax
            }

            Expr::ListLit { elements } => {
                // List structure: [capacity:8][length:8][elem_size:8][data...][tags...]
                // Each element is 8 bytes, header is 24 bytes, plus one type
                // tag byte per slot after the data region.
                let capacity = std::cmp::max(elements.len(), 8); // minimum capacity 8
                let header_size = 24;
                let data_size = capacity * 8;
                let total_size = header_size + data_size + capacity;
                
                self.uses_lists = true;
                self.emit_indent(&format!("; List literal with {} elements (capacity {})", elements.len(), capacity));
                
                // Allocate memory using mmap (heap allocation)
                self.emit_indent("mov rdi, 0  ; addr = NULL");
                self.emit_indent(&format!("mov rsi, {}  ; size", total_size));
                self.emit_indent("mov rdx, 3  ; PROT_READ | PROT_WRITE");
                self.emit_indent("mov r10, 0x22  ; MAP_PRIVATE | MAP_ANONYMOUS");
                self.emit_indent("mov r8, -1  ; fd = -1");
                self.emit_indent("mov r9, 0  ; offset = 0");
                self.emit_indent("mov rax, 9  ; sys_mmap");
                self.emit_indent("syscall");
                // Check for mmap failure (raw syscall returns -errno, not MAP_FAILED)
                let mmap_ok = self.new_label("list_mmap_ok");
                self.emit_indent("cmp rax, -4096  ; raw mmap returns -errno in [-4095,-1]");
                self.emit_indent(&format!("jbe {}", mmap_ok));
                self.emit_indent("mov rdi, 1          ; exit code 1");
                self.emit_indent("mov rax, 60         ; sys_exit");
                self.emit_indent("syscall");
                self.emit(&format!("{}:", mmap_ok));
                self.emit_indent("push rax  ; save list pointer");
                
                // Store capacity
                self.emit_indent(&format!("mov qword [rax], {}  ; capacity", capacity));
                // Store length
                self.emit_indent(&format!("mov qword [rax + 8], {}  ; length", elements.len()));
                // Store element size
                self.emit_indent("mov qword [rax + 16], 8  ; element size");
                
                // Store elements (data starts at offset 24) along with each
                // slot's type tag (tags start at offset 24 + capacity*8).
                // mmap zero-fills, so only non-integer tags need a write.
                let tags_base = header_size + data_size;
                for (i, elem) in elements.iter().enumerate() {
                    self.emit_indent("pop rbx  ; get list pointer");
                    self.emit_indent("push rbx ; save it back");
                    self.generate_expr(elem);
                    self.emit_indent("pop rbx  ; get list pointer");
                    self.emit_indent(&format!("mov [rbx+{}], rax", header_size + i * 8));
                    match self.emit_time_expr_tag(elem) {
                        Some(tag) => {
                            if tag != TAG_INTEGER {
                                self.emit_indent(&format!(
                                    "mov byte [rbx+{}], {}  ; slot {} type tag",
                                    tags_base + i,
                                    tag,
                                    i + 1
                                ));
                            }
                        }
                        None => {
                            // Mixed-typed source variable: copy its runtime
                            // tag from the shadow slot.
                            if let Some(slot) = self.mixed_element_tag_slot(elem) {
                                self.emit_indent(&format!(
                                    "mov cl, [rbp-{}]  ; runtime tag of mixed source",
                                    slot
                                ));
                                self.emit_indent(&format!(
                                    "mov [rbx+{}], cl  ; slot {} type tag",
                                    tags_base + i,
                                    i + 1
                                ));
                            }
                        }
                    }
                    self.emit_indent("push rbx ; save list pointer");
                }
                
                self.emit_indent("pop rax  ; list pointer in rax");
            }

            // Map literal: {"key": value, ...}. Build via _map_new then one
            // _map_insert per pair. _map_insert may reallocate on growth, so
            // each call's returned pointer is pushed and becomes the next
            // call's map operand; the final pointer is left in rax. Keys are
            // text (validated by the analyzer); values carry their runtime
            // tag in rcx via the same forwarding pattern as ListAppend.
            // (stage 1e2, tag 5)
            Expr::MapLit { pairs } => {
                self.uses_maps = true;
                self.emit_indent(&format!(
                    "; Map literal with {} pair(s)",
                    pairs.len()
                ));
                let hint = std::cmp::max(pairs.len(), 8);
                self.emit_indent(&format!("mov rdi, {}  ; capacity hint", hint));
                self.emit_indent("call _map_new");
                self.emit_indent("push rax  ; save map pointer");

                for (key, value) in pairs {
                    // key -> rsi (text pointer). A quoted key is always the
                    // literal text (never a variable reference), so a key
                    // spelling that collides with a variable name still maps
                    // to the literal string.
                    self.generate_text_key(key);
                    self.emit_indent("push rax  ; save key pointer");
                    // value -> rdx
                    self.generate_expr(value);
                    self.emit_indent("mov rdx, rax  ; value");
                    // tag -> rcx (forward runtime tag for mixed sources)
                    match self.emit_time_expr_tag(value) {
                        Some(tag) => {
                            self.emit_indent(&format!(
                                "mov ecx, {}  ; value type tag",
                                tag
                            ));
                        }
                        None => {
                            if let Some(slot) = self.mixed_element_tag_slot(value) {
                                self.emit_indent(&format!(
                                    "movzx ecx, byte [rbp-{}]  ; runtime tag of mixed source",
                                    slot
                                ));
                            } else if self.expr_leaves_tag_in_r11(value) {
                                self.emit_indent(
                                    "mov ecx, r11d  ; forward runtime tag from r11",
                                );
                            } else {
                                self.emit_indent("xor ecx, ecx  ; default integer tag");
                            }
                        }
                    }
                    self.emit_indent("pop rsi  ; key pointer");
                    self.emit_indent("pop rdi  ; map pointer");
                    self.emit_indent("call _map_insert");
                    self.emit_indent("push rax  ; save (possibly reallocated) map pointer");
                }
                self.emit_indent("pop rax  ; final map pointer in rax");
            }

            // ListAccess: 0-indexed access (internal use)
            // MEMORY SAFETY: Always bounds-check before access
            // List structure: [capacity:8][length:8][elem_size:8][data...]
            Expr::ListAccess { list, index } => {
                let ok_label = self.new_label("list_ok");
                let error_label = self.new_label("list_err");
                let done_label = self.new_label("list_done");
                let is_mixed = self.list_expr_is_mixed(list);
                
                self.emit_indent("; List access (0-indexed) with bounds check");
                // Get list pointer
                self.generate_expr(list);
                self.emit_indent("push rax  ; save list pointer");
                
                // Get index
                self.generate_expr(index);
                self.emit_indent("mov rcx, rax  ; index in rcx");
                self.emit_indent("pop rbx  ; list pointer in rbx");
                
                // Bounds check: index must be >= 0 and < length
                self.emit_indent("cmp rcx, 0");
                self.emit_indent(&format!("jl {}  ; index < 0 is error", error_label));
                self.emit_indent("mov rdx, [rbx + 8]  ; get length (offset 8)");
                self.emit_indent("cmp rcx, rdx");
                self.emit_indent(&format!("jl {}  ; index < length is OK", ok_label));
                
                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent("xor rax, rax  ; return 0 on error");
                if is_mixed {
                    self.emit_indent("xor r11d, r11d  ; integer tag on error path");
                }
                self.emit_indent(&format!("jmp {}", done_label));
                
                // Success path: safe access
                // List structure: [capacity:8][length:8][elem_size:8][data...][tags...]
                // Data starts at offset 24
                self.emit(&format!("{}:", ok_label));
                if is_mixed {
                    // tag_addr = base + 24 + capacity*8 + index; tag rides in
                    // r11 for the immediate consumer.
                    self.emit_indent("mov r11, [rbx]  ; capacity");
                    self.emit_indent("shl r11, 3  ; * element size (8)");
                    self.emit_indent("add r11, rcx  ; + index");
                    self.emit_indent("movzx r11, byte [rbx + r11 + 24]  ; slot type tag");
                }
                self.emit_indent("mov rax, rcx");
                self.emit_indent("shl rax, 3  ; multiply by 8 (element size)");
                self.emit_indent("add rax, 24  ; skip header (24 bytes)");
                self.emit_indent("add rax, rbx");
                self.emit_indent("mov rax, [rax]  ; get element");
                
                self.emit(&format!("{}:", done_label));
            }
            
            Expr::PropertyAccess { object, property } => {
                let offset = self.get_var(object);
                // Load the variable's runtime value (pointer for containers,
                // raw value for scalars/time). Falls back to global mirrors so
                // top-level/branch-declared names are reachable inside functions.
                let found = if let Some(off) = offset {
                    self.emit_indent(&format!("mov rax, [rbp-{}]", off));
                    true
                } else if let Some(label) = self.global_var_label(object).cloned() {
                    self.emit_indent(&format!("mov rax, [rel {}]", label));
                    true
                } else {
                    false
                };

                if found {
                    let var_type = self.variable_types.get(object).cloned().unwrap_or(VarType::Unknown);

                    match property {
                        // Buffer/List properties
                        ObjectProperty::Size => {
                            if var_type == VarType::Buffer {
                                self.emit_indent("mov rax, [rax + 8]  ; buffer length/size");
                            } else if var_type == VarType::List {
                                self.emit_indent("mov rax, [rax + 8]  ; list length at offset 8");
                            } else if var_type == VarType::Map {
                                self.emit_indent("mov rax, [rax + 8]  ; map length (live entries)");
                            } else {
                                // For files, call _file_size
                                self.emit_indent("mov rdi, rax");
                                self.emit_indent("call _file_size");
                            }
                        }
                        ObjectProperty::Capacity => {
                            self.emit_indent("mov rax, [rax]  ; buffer capacity");
                        }
                        ObjectProperty::Empty => {
                            if var_type == VarType::List {
                                self.emit_indent("mov rax, [rax + 8]  ; get list length (offset 8)");
                            } else if var_type == VarType::Map {
                                self.emit_indent("mov rax, [rax + 8]  ; get map length (offset 8)");
                            } else {
                                self.emit_indent("mov rax, [rax + 8]  ; get buffer size");
                            }
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setz al");
                            self.emit_indent("movzx rax, al  ; 1 if empty, 0 otherwise");
                        }
                        // Map properties: keys/values yield a fresh list of
                        // the map's keys (text pointers) or values (with their
                        // runtime tags), in insertion order. Building a list
                        // forces the list runtime on, so set both flags.
                        // (stage 1e2, tag 5)
                        ObjectProperty::Keys => {
                            self.uses_maps = true;
                            self.uses_lists = true;
                            self.emit_indent("mov rdi, rax  ; map pointer");
                            self.emit_indent("call _map_keys  ; -> rax = list of key texts");
                        }
                        ObjectProperty::Values => {
                            self.uses_maps = true;
                            self.uses_lists = true;
                            self.emit_indent("mov rdi, rax  ; map pointer");
                            self.emit_indent("call _map_values  ; -> rax = list of values (tagged)");
                        }
                        ObjectProperty::Full => {
                            if var_type == VarType::List {
                                // Lists can grow dynamically, so never full
                                self.emit_indent("xor rax, rax  ; lists are never full");
                            } else {
                                // Buffer: compare size to capacity
                                self.emit_indent("mov rbx, [rax]      ; capacity");
                                self.emit_indent("mov rax, [rax + 8]  ; size");
                                self.emit_indent("cmp rax, rbx");
                                self.emit_indent("sete al");
                                self.emit_indent("movzx rax, al  ; 1 if full, 0 otherwise");
                            }
                        }

                        // File properties
                        ObjectProperty::Descriptor => {
                            // rax already holds the fd
                        }
                        ObjectProperty::Modified => {
                            self.emit_indent("mov rdi, rax  ; fd");
                            self.emit_indent("call _file_modified");
                        }
                        ObjectProperty::Accessed => {
                            self.emit_indent("mov rdi, rax  ; fd");
                            self.emit_indent("call _file_accessed");
                        }
                        ObjectProperty::Permissions => {
                            self.emit_indent("mov rdi, rax  ; fd");
                            self.emit_indent("call _file_permissions");
                        }
                        ObjectProperty::Readable => {
                            // Check if fd >= 0 (valid for reading)
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setns al");
                            self.emit_indent("movzx rax, al  ; 1 if readable, 0 otherwise");
                        }
                        ObjectProperty::Writable => {
                            // Check if file was opened for writing/appending
                            let is_writable = self.file_writable.get(object).copied().unwrap_or(false);
                            if is_writable {
                                self.emit_indent("mov rax, 1  ; file opened for writing");
                            } else {
                                self.emit_indent("xor rax, rax  ; file opened for reading only");
                            }
                        }

                        // List properties
                        // List structure: [capacity:8][length:8][elem_size:8][data...]
                        ObjectProperty::First => {
                            let ok_label = self.new_label("list_first_ok");
                            let error_label = self.new_label("list_first_err");
                            let done_label = self.new_label("list_first_done");
                            let is_mixed = self.mixed_lists.contains(object)
                                || self.list_element_types.get(object) == Some(&VarType::Mixed);
                            self.emit_indent("mov rbx, [rax + 8]  ; length (offset 8)");
                            self.emit_indent("test rbx, rbx");
                            self.emit_indent(&format!("jnz {}  ; non-empty list, safe to access", ok_label));
                            self.emit(&format!("{}:", error_label));
                            self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                            self.emit_indent("xor rax, rax  ; return 0 on error");
                            if is_mixed {
                                self.emit_indent("xor r11d, r11d  ; integer tag on error path");
                            }
                            self.emit_indent(&format!("jmp {}", done_label));
                            self.emit(&format!("{}:", ok_label));
                            if is_mixed {
                                // tags[0] = base + 24 + capacity*8
                                self.emit_indent("mov r11, [rax]  ; capacity");
                                self.emit_indent("shl r11, 3  ; * element size (8)");
                                self.emit_indent("movzx r11, byte [rax + r11 + 24]  ; slot type tag");
                            }
                            self.emit_indent("mov rax, [rax + 24]  ; first element (data at offset 24)");
                            self.emit(&format!("{}:", done_label));
                        }
                        ObjectProperty::Last => {
                            let ok_label = self.new_label("list_last_ok");
                            let error_label = self.new_label("list_last_err");
                            let done_label = self.new_label("list_last_done");
                            let is_mixed = self.mixed_lists.contains(object)
                                || self.list_element_types.get(object) == Some(&VarType::Mixed);
                            self.emit_indent("mov rbx, [rax + 8]  ; length (offset 8)");
                            self.emit_indent("test rbx, rbx");
                            self.emit_indent(&format!("jnz {}  ; non-empty list, safe to access", ok_label));
                            self.emit(&format!("{}:", error_label));
                            self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                            self.emit_indent("xor rax, rax  ; return 0 on error");
                            if is_mixed {
                                self.emit_indent("xor r11d, r11d  ; integer tag on error path");
                            }
                            self.emit_indent(&format!("jmp {}", done_label));
                            self.emit(&format!("{}:", ok_label));
                            self.emit_indent("dec rbx             ; 0-indexed");
                            if is_mixed {
                                // tags[len-1] = base + 24 + capacity*8 + (len-1)
                                self.emit_indent("mov r11, [rax]  ; capacity");
                                self.emit_indent("shl r11, 3  ; * element size (8)");
                                self.emit_indent("add r11, rbx  ; + 0-based last index");
                                self.emit_indent("movzx r11, byte [rax + r11 + 24]  ; slot type tag");
                            }
                            self.emit_indent("shl rbx, 3          ; * 8");
                            self.emit_indent("add rbx, 24         ; + header offset");
                            self.emit_indent("add rax, rbx        ; offset to last");
                            self.emit_indent("mov rax, [rax]      ; last element");
                            self.emit(&format!("{}:", done_label));
                        }

                        // Number properties
                        ObjectProperty::Absolute => {
                            let lbl = self.label_counter;
                            self.label_counter += 1;
                            self.emit_indent("test rax, rax");
                            self.emit_indent(&format!("jns .abs_done_{}", lbl));
                            self.emit_indent("neg rax");
                            self.emit(&format!(".abs_done_{}:", lbl));
                        }
                        ObjectProperty::Sign => {
                            self.emit_indent("test rax, rax");
                            self.emit_indent("mov rbx, 1");
                            self.emit_indent("mov rcx, -1");
                            self.emit_indent("cmovg rax, rbx  ; positive -> 1");
                            self.emit_indent("cmovl rax, rcx  ; negative -> -1");
                            self.emit_indent("cmovz rax, rax  ; zero -> 0 (already)");
                        }
                        ObjectProperty::Even => {
                            self.emit_indent("and rax, 1");
                            self.emit_indent("xor rax, 1  ; 1 if even, 0 if odd");
                        }
                        ObjectProperty::Odd => {
                            self.emit_indent("and rax, 1  ; 1 if odd, 0 if even");
                        }
                        ObjectProperty::Positive => {
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setg al");
                            self.emit_indent("movzx rax, al");
                        }
                        ObjectProperty::Negative => {
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setl al");
                            self.emit_indent("movzx rax, al");
                        }
                        ObjectProperty::Zero => {
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setz al");
                            self.emit_indent("movzx rax, al");
                        }

                        // Time properties (unix timestamp -> component extraction)
                        ObjectProperty::Hour => {
                            self.uses_time = true;
                            self.emit_indent("TIME_GET_HOUR rax");
                        }
                        ObjectProperty::Minute => {
                            self.uses_time = true;
                            self.emit_indent("TIME_GET_MINUTE rax");
                        }
                        ObjectProperty::Second => {
                            self.uses_time = true;
                            self.emit_indent("TIME_GET_SECOND rax");
                        }
                        ObjectProperty::Day => {
                            self.uses_time = true;
                            self.emit_indent("TIME_GET_DAY rax");
                        }
                        ObjectProperty::Month => {
                            self.uses_time = true;
                            self.emit_indent("TIME_GET_MONTH rax");
                        }
                        ObjectProperty::Year => {
                            self.uses_time = true;
                            self.emit_indent("TIME_GET_YEAR rax");
                        }
                        ObjectProperty::Unix => {
                            // Unix timestamp is the raw value
                        }

                        // Timer properties
                        ObjectProperty::Duration => {
                            self.uses_time = true;
                            self.emit_indent("; Timer duration");
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset.unwrap_or(0) + 48));
                            self.emit_indent("TIMER_DURATION_SECONDS rax");
                        }
                        ObjectProperty::Elapsed => {
                            self.uses_time = true;
                            self.emit_indent("; Timer elapsed");
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset.unwrap_or(0) + 48));
                            self.emit_indent("TIMER_ELAPSED_SECONDS rax");
                        }
                        ObjectProperty::StartTime => {
                            self.uses_time = true;
                            self.emit_indent("; Timer start time");
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset.unwrap_or(0) + 48));
                            self.emit_indent("TIMER_START_TIME rax");
                        }
                        ObjectProperty::EndTime => {
                            self.uses_time = true;
                            self.emit_indent("; Timer end time");
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset.unwrap_or(0) + 48));
                            self.emit_indent("TIMER_END_TIME rax");
                        }
                        ObjectProperty::Running => {
                            self.uses_time = true;
                            self.emit_indent("; Timer running status");
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset.unwrap_or(0) + 48));
                            self.emit_indent("mov rax, [rax + TIMER_RUNNING]");
                        }
                    }
                } else if object == "_current_time" {
                    // Special handling for current time's properties
                    self.uses_time = true;
                    self.emit_indent("TIME_GET");
                    match property {
                        ObjectProperty::Hour => self.emit_indent("TIME_GET_HOUR rax"),
                        ObjectProperty::Minute => self.emit_indent("TIME_GET_MINUTE rax"),
                        ObjectProperty::Second => self.emit_indent("TIME_GET_SECOND rax"),
                        ObjectProperty::Day => self.emit_indent("TIME_GET_DAY rax"),
                        ObjectProperty::Month => self.emit_indent("TIME_GET_MONTH rax"),
                        ObjectProperty::Year => self.emit_indent("TIME_GET_YEAR rax"),
                        ObjectProperty::Unix => { /* rax already has unix time */ }
                        _ => self.emit_indent("; Unknown time property"),
                    }
                }
            }
            
            Expr::LastError => {
                // Get the last error from the runtime
                self.emit_indent("mov rax, [rel _last_error]");
            }
            
            // Command-line arguments
            Expr::ArgumentCount => {
                if self.argument_view_uses_parsed() {
                    // Keep historical semantics: include program name in count.
                    self.emit_indent("call _get_parsed_argc");
                    self.emit_indent("inc rax");
                } else {
                    self.emit_indent("call _get_argc");
                }
            }
            
            Expr::ArgumentAt { index } => {
                self.generate_expr(index);
                if self.argument_view_uses_parsed() {
                    let not_name_label = self.new_label("arg_at_not_name");
                    let done_label = self.new_label("arg_at_done");
                    self.emit_indent("cmp rax, 0");
                    self.emit_indent(&format!("jne {}", not_name_label));
                    self.emit_indent("xor rdi, rdi  ; index 0 = program name");
                    self.emit_indent("call _get_arg");
                    self.emit_indent(&format!("jmp {}", done_label));
                    self.emit(&format!("{}:", not_name_label));
                    self.emit_indent("dec rax  ; map user-facing index to parsed positional index");
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("call _get_parsed_arg");
                    self.emit(&format!("{}:", done_label));
                } else {
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("call _get_arg");
                }
            }
            
            Expr::ArgumentName => {
                self.emit_indent("xor rdi, rdi  ; index 0 - program name");
                self.emit_indent("call _get_arg");
            }
            
            Expr::ArgumentFirst => {
                if self.argument_view_uses_parsed() {
                    self.emit_indent("xor rdi, rdi  ; parsed index 0 - first user arg");
                    self.emit_indent("call _get_parsed_arg");
                } else {
                    self.emit_indent("mov rdi, 1  ; index 1 - first user arg");
                    self.emit_indent("call _get_arg");
                }
            }
            
            Expr::ArgumentSecond => {
                if self.argument_view_uses_parsed() {
                    self.emit_indent("mov rdi, 1  ; parsed index 1 - second user arg");
                    self.emit_indent("call _get_parsed_arg");
                } else {
                    self.emit_indent("mov rdi, 2  ; index 2 - second user arg");
                    self.emit_indent("call _get_arg");
                }
            }
            
            Expr::ArgumentLast => {
                if self.argument_view_uses_parsed() {
                    let has_user_args_label = self.new_label("arg_last_has_user");
                    let done_label = self.new_label("arg_last_done");
                    self.emit_indent("call _get_parsed_argc");
                    self.emit_indent("test rax, rax");
                    self.emit_indent(&format!("jnz {}", has_user_args_label));
                    self.emit_indent("xor rdi, rdi  ; fallback to program name when no user args");
                    self.emit_indent("call _get_arg");
                    self.emit_indent(&format!("jmp {}", done_label));
                    self.emit(&format!("{}:", has_user_args_label));
                    self.emit_indent("dec rax  ; last parsed index = parsed argc - 1");
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("call _get_parsed_arg");
                    self.emit(&format!("{}:", done_label));
                } else {
                    self.emit_indent("call _get_argc");
                    self.emit_indent("dec rax  ; last index = argc - 1");
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("call _get_arg");
                }
            }
            
            Expr::ArgumentEmpty => {
                if self.argument_view_uses_parsed() {
                    self.emit_indent("call _get_parsed_argc");
                    self.emit_indent("test rax, rax");
                    self.emit_indent("setz al  ; 1 if no positional args after flag parsing");
                    self.emit_indent("movzx rax, al");
                } else {
                    self.emit_indent("call _get_argc");
                    self.emit_indent("cmp rax, 1");
                    self.emit_indent("setle al  ; 1 if argc <= 1 (no user args)");
                    self.emit_indent("movzx rax, al");
                }
            }
            
            Expr::ArgumentAll => {
                self.uses_lists = true;
                let min_ok = self.new_label("argall_min_ok");
                let loop_label = self.new_label("argall_loop");
                let done_label = self.new_label("argall_done");

                self.emit_indent("; Build list from parsed positional arguments");
                self.emit_indent("call _get_parsed_argc");
                self.emit_indent("mov r12, rax  ; r12 = count");

                // capacity = max(count, 8)
                self.emit_indent("mov r13, rax  ; r13 = capacity");
                self.emit_indent("cmp r13, 8");
                self.emit_indent(&format!("jge {}", min_ok));
                self.emit_indent("mov r13, 8");
                self.emit(&format!("{}:", min_ok));

                // Allocate: size = capacity*8 + 24 (header) + capacity tag bytes
                self.emit_indent("mov rax, r13");
                self.emit_indent("shl rax, 3");
                self.emit_indent("add rax, r13  ; + type tag bytes (1 per slot)");
                self.emit_indent("add rax, 24");
                self.emit_indent("mov rsi, rax  ; size");
                self.emit_indent("xor rdi, rdi  ; addr = NULL");
                self.emit_indent("mov rdx, 3  ; PROT_READ | PROT_WRITE");
                self.emit_indent("mov r10, 0x22  ; MAP_PRIVATE | MAP_ANONYMOUS");
                self.emit_indent("mov r8, -1  ; fd = -1");
                self.emit_indent("xor r9, r9  ; offset = 0");
                self.emit_indent("mov rax, 9  ; sys_mmap");
                self.emit_indent("syscall");
                // Check for mmap failure (raw syscall returns -errno, not MAP_FAILED)
                let mmap_ok = self.new_label("arglist_mmap_ok");
                self.emit_indent("cmp rax, -4096  ; raw mmap returns -errno in [-4095,-1]");
                self.emit_indent(&format!("jbe {}", mmap_ok));
                self.emit_indent("mov rdi, 1          ; exit code 1");
                self.emit_indent("mov rax, 60         ; sys_exit");
                self.emit_indent("syscall");
                self.emit(&format!("{}:", mmap_ok));
                self.emit_indent("mov r14, rax  ; r14 = list ptr");

                // Initialize header
                self.emit_indent("mov [r14], r13  ; capacity");
                self.emit_indent("mov [r14 + 8], r12  ; length");
                self.emit_indent("mov qword [r14 + 16], 8  ; element size");

                // Fill data from parsed args
                self.emit_indent("xor r15, r15  ; r15 = index");
                self.emit(&format!("{}:", loop_label));
                self.emit_indent("cmp r15, r12");
                self.emit_indent(&format!("jge {}", done_label));
                self.emit_indent("mov rdi, r15");
                self.emit_indent("call _get_parsed_arg");
                self.emit_indent("mov [r14 + r15*8 + 24], rax");
                self.emit_indent("inc r15");
                self.emit_indent(&format!("jmp {}", loop_label));
                self.emit(&format!("{}:", done_label));
                self.emit_indent("mov rax, r14  ; return list pointer");
            }

            Expr::ArgumentRaw => {
                self.uses_lists = true;
                // Preserve callee-saved registers used in this expression.
                self.emit_indent("push r12");
                self.emit_indent("push r13");
                self.emit_indent("push r14");
                self.emit_indent("push r15");

                let min_ok = self.new_label("argraw_min_ok");
                let loop_label = self.new_label("argraw_loop");
                let done_label = self.new_label("argraw_done");

                self.emit_indent("; Build list from raw arguments");
                self.emit_indent("call _get_raw_argc");
                self.emit_indent("mov r12, rax  ; r12 = count");

                self.emit_indent("mov r13, rax  ; r13 = capacity");
                self.emit_indent("cmp r13, 8");
                self.emit_indent(&format!("jge {}", min_ok));
                self.emit_indent("mov r13, 8");
                self.emit(&format!("{}:", min_ok));

                self.emit_indent("mov rax, r13");
                self.emit_indent("shl rax, 3");
                self.emit_indent("add rax, r13  ; + type tag bytes (1 per slot)");
                self.emit_indent("add rax, 24");
                self.emit_indent("mov rsi, rax  ; size");
                self.emit_indent("xor rdi, rdi  ; addr = NULL");
                self.emit_indent("mov rdx, 3  ; PROT_READ | PROT_WRITE");
                self.emit_indent("mov r10, 0x22  ; MAP_PRIVATE | MAP_ANONYMOUS");
                self.emit_indent("mov r8, -1  ; fd = -1");
                self.emit_indent("xor r9, r9  ; offset = 0");
                self.emit_indent("mov rax, 9  ; sys_mmap");
                self.emit_indent("syscall");
                // Check for mmap failure (raw syscall returns -errno, not MAP_FAILED)
                let mmap_ok = self.new_label("argraw_mmap_ok");
                self.emit_indent("cmp rax, -4096  ; raw mmap returns -errno in [-4095,-1]");
                self.emit_indent(&format!("jbe {}", mmap_ok));
                self.emit_indent("mov rdi, 1          ; exit code 1");
                self.emit_indent("mov rax, 60         ; sys_exit");
                self.emit_indent("syscall");
                self.emit(&format!("{}:", mmap_ok));
                self.emit_indent("mov r14, rax  ; r14 = list ptr");

                self.emit_indent("mov [r14], r13  ; capacity");
                self.emit_indent("mov [r14 + 8], r12  ; length");
                self.emit_indent("mov qword [r14 + 16], 8  ; element size");

                self.emit_indent("xor r15, r15  ; r15 = index");
                self.emit(&format!("{}:", loop_label));
                self.emit_indent("cmp r15, r12");
                self.emit_indent(&format!("jge {}", done_label));
                self.emit_indent("mov rdi, r15");
                self.emit_indent("call _get_raw_arg");
                self.emit_indent("mov [r14 + r15*8 + 24], rax");
                self.emit_indent("inc r15");
                self.emit_indent(&format!("jmp {}", loop_label));
                self.emit(&format!("{}:", done_label));
                self.emit_indent("mov rax, r14  ; return list pointer");
                // Restore callee-saved registers.
                self.emit_indent("pop r15");
                self.emit_indent("pop r14");
                self.emit_indent("pop r13");
                self.emit_indent("pop r12");
            }

            Expr::ArgumentHas { value } => {
                let loop_label = self.new_label("arg_has_loop");
                let found_label = self.new_label("arg_has_found");
                let done_label = self.new_label("arg_has_done");

                // Evaluate target value to match and keep it in rbx
                self.generate_expr(value);
                self.emit_indent("mov rbx, rax  ; target argument value");

                // count in rcx, start index in r8
                if self.argument_view_uses_parsed() {
                    self.emit_indent("call _get_parsed_argc");
                    self.emit_indent("mov rcx, rax  ; parsed positional argc");
                    self.emit_indent("xor r8, r8  ; start at parsed[0]");
                } else {
                    self.emit_indent("call _get_raw_argc");
                    self.emit_indent("mov rcx, rax  ; raw user argc");
                    self.emit_indent("xor r8, r8  ; start at raw[0]");
                }
                self.emit_indent("xor rax, rax  ; default result: false");

                self.emit(&format!("{}:", loop_label));
                self.emit_indent("cmp r8, rcx");
                self.emit_indent(&format!("jge {}", done_label));

                // current arg from selected argument view
                self.emit_indent("mov rdi, r8");
                if self.argument_view_uses_parsed() {
                    self.emit_indent("call _get_parsed_arg");
                } else {
                    self.emit_indent("call _get_raw_arg");
                }

                // compare current arg with target
                self.emit_indent("mov rdi, rax");
                self.emit_indent("mov rsi, rbx");
                self.emit_indent("call _str_eq");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jnz {}", found_label));

                self.emit_indent("inc r8");
                self.emit_indent(&format!("jmp {}", loop_label));

                self.emit(&format!("{}:", found_label));
                self.emit_indent("mov rax, 1");
                self.emit_indent(&format!("jmp {}", done_label));

                self.emit(&format!("{}:", done_label));
            }
            
            Expr::TreatingAs { value, match_value, replacement } => {
                // Inline substitution: if value == match_value, use replacement
                let skip_label = self.new_label("treating_skip");
                let done_label = self.new_label("treating_done");
                let treating_type = self.infer_expr_type(value);
                
                // Check if value is a buffer variable
                let is_buffer = if let Expr::Identifier(ref name) = **value {
                    self.variable_types.get(name) == Some(&VarType::Buffer)
                } else {
                    false
                };

                if is_buffer || matches!(treating_type, Some(VarType::String)) {
                    // Evaluate the value
                    self.generate_expr(value);
                    self.emit_indent("push rax  ; save original value (struct ptr if buffer)");

                    if is_buffer {
                        // Get length and data pointer from struct - avoid NUL-scanning
                        // stale bytes (same fix applied to all other buffer comparisons)
                        self.emit_indent("mov rdi, rax");
                        self.emit_indent("call _buffer_length");
                        self.emit_indent("mov rdx, rax  ; len1");
                        self.emit_indent("mov rdi, [rsp]");
                        self.emit_indent("call _buffer_data");
                        self.emit_indent("mov rdi, rax  ; ptr1 = data");
                        self.generate_expr(match_value);
                        self.emit_indent("mov rsi, rax  ; ptr2 = match");
                        self.emit_indent("push rdi");
                        self.emit_indent("push rsi");
                        self.emit_indent("push rdx");
                        self.emit_indent("mov rdi, rsi");
                        self.emit_indent("call _str_len");
                        self.emit_indent("mov rcx, rax  ; len2");
                        self.emit_indent("pop rdx");
                        self.emit_indent("pop rsi");
                        self.emit_indent("pop rdi");
                        self.emit_indent("call _mem_eq");
                    } else {
                        self.emit_indent("mov rdi, rax  ; comparison ptr in rdi");
                        self.generate_expr(match_value);
                        self.emit_indent("mov rsi, rax  ; match value in rsi");
                        self.emit_indent("call _str_eq");
                    }
                    self.emit_indent("test rax, rax");
                    self.emit_indent(&format!("jz {}", skip_label));

                    // Match found - use replacement
                    self.emit_indent("add rsp, 8  ; discard saved value");
                    self.generate_expr(replacement);
                    self.emit_indent(&format!("jmp {}", done_label));

                    // No match - use original value
                    self.emit(&format!("{}:", skip_label));
                    self.emit_indent("pop rax  ; restore original value");
                } else {
                    // Non-string treating uses value comparison in registers.
                    self.generate_expr(value);
                    self.emit_indent("push rax  ; save original value");
                    self.generate_expr(match_value);
                    self.emit_indent("mov rbx, rax  ; match value");
                    self.emit_indent("pop rax  ; restore original value");
                    self.emit_indent("cmp rax, rbx");
                    self.emit_indent(&format!("jne {}", skip_label));

                    // Match found - use replacement
                    self.generate_expr(replacement);
                    self.emit_indent(&format!("jmp {}", done_label));

                    // No match - keep original value in rax
                    self.emit(&format!("{}:", skip_label));
                }

                self.emit(&format!("{}:", done_label));
            }
            
            // Environment variables
            Expr::EnvironmentVariable { name } => {
                self.generate_expr(name);
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _get_env");
            }
            
            Expr::EnvironmentVariableCount => {
                self.emit_indent("call _get_env_count");
            }
            
            Expr::EnvironmentVariableAt { index } => {
                self.generate_expr(index);
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _get_env_at");
            }
            
            Expr::EnvironmentVariableExists { name } => {
                self.generate_expr(name);
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _get_env");
                self.emit_indent("test rax, rax");
                self.emit_indent("setnz al");
                self.emit_indent("movzx rax, al  ; 1 if exists, 0 otherwise");
            }
            
            Expr::EnvironmentVariableFirst => {
                self.emit_indent("xor rdi, rdi  ; index 0");
                self.emit_indent("call _get_env_at");
            }
            
            Expr::EnvironmentVariableLast => {
                self.emit_indent("call _get_env_count");
                self.emit_indent("dec rax  ; last index = count - 1");
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _get_env_at");
            }
            
            Expr::EnvironmentVariableEmpty => {
                self.emit_indent("call _get_env_count");
                self.emit_indent("test rax, rax");
                self.emit_indent("setz al  ; 1 if count == 0");
                self.emit_indent("movzx rax, al");
            }
            
            // Time expressions
            Expr::CurrentTime => {
                self.uses_time = true;
                self.emit_indent("; Get current time");
                self.emit_indent("TIME_GET");
            }

            Expr::Fork => {
                self.uses_files = true;
                self.emit_indent("; fork() - 0 in child, child pid in parent, negative on error");
                self.emit_indent("FORK");
            }

            Expr::ReapChild { pid } => {
                self.uses_files = true;
                match pid {
                    None => {
                        self.emit_indent("mov rdi, -1  ; wait for any child");
                    }
                    Some(pid_expr) => {
                        self.generate_expr(pid_expr);
                        self.emit_indent("mov rdi, rax  ; wait for this specific pid");
                    }
                }
                self.emit_indent("; wait4() - reap a child, returns its pid (or -1 on error)");
                self.emit_indent("REAP_CHILD");
            }
            
            // Type casting
            Expr::Cast { value, target_type, radix } => {
                self.generate_expr(value);
                match target_type {
                    Type::Integer => {
                        // Float to integer - truncate using cvttsd2si
                        if self.is_float_expr(value) {
                            self.emit_indent("; Cast float to integer");
                            // Float expressions are represented as 64-bit float bits in RAX.
                            // Ensure XMM0 has the correct value before converting.
                            self.emit_indent("RAX_TO_XMM0");
                            self.emit_indent("cvttsd2si rax, xmm0");
                        } else {
                            match self.infer_expr_type(value) {
                                Some(VarType::Buffer) => {
                                    self.uses_ints = true;
                                    self.uses_buffers = true;
                                    // Buffer content isn't reliably NUL-terminated at its
                                    // logical end (_buffer_clear only zeroes the first byte,
                                    // not the whole allocation), so a NUL-scanning parse could
                                    // read stale bytes left over from a longer previous value.
                                    // Use the buffer's own tracked length as a hard bound instead.
                                    self.emit_indent("push rbx");
                                    self.emit_indent("push r12");
                                    self.emit_indent("mov rbx, rax  ; save buffer pointer");
                                    self.emit_indent("mov rdi, rbx");
                                    self.emit_indent("call _buffer_length");
                                    self.emit_indent("mov r12, rax  ; save length");
                                    self.emit_indent("mov rdi, rbx");
                                    self.emit_indent("call _buffer_data");
                                    self.emit_indent("mov rdi, rax");
                                    if *radix == 10 {
                                        self.emit_indent("mov rsi, r12  ; max length");
                                        self.emit_indent("call _parse_i64_bounded");
                                    } else {
                                        self.emit_indent(&format!("mov rsi, {}", radix));
                                        self.emit_indent("mov rdx, r12  ; max length");
                                        self.emit_indent("call _parse_int_radix_bounded");
                                    }
                                    self.emit_indent("pop r12");
                                    self.emit_indent("pop rbx");
                                }
                                Some(VarType::String) => {
                                    self.uses_ints = true;
                                    self.emit_indent("mov rdi, rax");
                                    if *radix == 10 {
                                        self.emit_indent("call _parse_i64");
                                    } else {
                                        self.emit_indent(&format!("mov rsi, {}", radix));
                                        self.emit_indent("call _parse_int_radix");
                                    }
                                }
                                _ => {
                                    // Other types stay as-is (already integer)
                                }
                            }
                        }
                    }
                    Type::Float => {
                        if self.is_float_expr(value) {
                            // Already float bits in rax
                        } else {
                            match self.infer_expr_type(value) {
                                Some(VarType::Buffer) => {
                                    self.uses_floats = true;
                                    self.uses_buffers = true;
                                    // Buffer content isn't reliably NUL-terminated at its
                                    // logical end (see the int.asm bounded parsers for the
                                    // full explanation) - use the buffer's own tracked
                                    // length as a hard bound instead of scanning for NUL.
                                    self.emit_indent("push rbx");
                                    self.emit_indent("push r12");
                                    self.emit_indent("mov rbx, rax  ; save buffer pointer");
                                    self.emit_indent("mov rdi, rbx");
                                    self.emit_indent("call _buffer_length");
                                    self.emit_indent("mov r12, rax  ; save length");
                                    self.emit_indent("mov rdi, rbx");
                                    self.emit_indent("call _buffer_data");
                                    self.emit_indent("mov rdi, rax");
                                    self.emit_indent("mov rsi, r12  ; max length");
                                    self.emit_indent("call _parse_f64_bounded");
                                    self.emit_indent("pop r12");
                                    self.emit_indent("pop rbx");
                                }
                                Some(VarType::String) => {
                                    self.uses_floats = true;
                                    self.emit_indent("mov rdi, rax");
                                    self.emit_indent("call _parse_f64");
                                }
                                _ => {
                                    // Integer to float
                                    self.emit_indent("; Cast integer to float");
                                    self.emit_indent("cvtsi2sd xmm0, rax");
                                    // Keep the invariant that expressions leave their value in RAX.
                                    // For floats, RAX holds the IEEE-754 bits.
                                    self.emit_indent("XMM0_TO_RAX");
                                    self.uses_floats = true;
                                }
                            }
                        }
                    }
                    Type::Boolean => {
                        let src_type = self.infer_expr_type(value);
                        if matches!(src_type, Some(VarType::String) | Some(VarType::Buffer)) {
                            // A text/buffer cast to boolean must inspect the
                            // content, not the pointer. "true" (case-insensitive)
                            // yields 1, everything else yields 0.
                            self.uses_strings = true;
                            self.emit_indent("; Cast text/buffer to boolean");
                            self.emit_indent("test rax, rax");
                            let null_label = self.new_label("bool_null");
                            let done_label = self.new_label("bool_done");
                            self.emit_indent(&format!("jz {}", null_label));
                            if src_type == Some(VarType::Buffer) {
                                self.emit_indent("add rax, 24  ; buffer data area");
                            }
                            self.emit_indent("mov rdi, rax");
                            self.emit_indent("call _text_to_boolean");
                            self.emit_indent(&format!("jmp {}", done_label));
                            self.emit(&format!("{}:", null_label));
                            self.emit_indent("xor rax, rax");
                            self.emit(&format!("{}:", done_label));
                        } else {
                            // Convert to boolean (0 = false, non-zero = true)
                            self.emit_indent("; Cast to boolean");
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setne al");
                            self.emit_indent("movzx rax, al");
                        }
                    }
                    Type::String => {
                        // "as text" must materialise a NUL-terminated C string
                        // pointer. Booleans become "true"/"false", integers
                        // become decimal digits, and floats become a trimmed
                        // decimal representation. Text/buffer values are already
                        // valid text pointers, so they are left unchanged.
                        let src_type = self.infer_expr_type(value);
                        if !matches!(src_type, Some(VarType::String) | Some(VarType::Buffer)) {
                            self.uses_buffers = true;
                            self.stack_offset += 8;
                            let tmp = self.stack_offset;

                            self.emit_indent("push rax  ; value to format");
                            self.emit_indent("mov rdi, 1024  ; default buffer size");
                            self.emit_indent("call _alloc_buffer");
                            self.emit_indent(&format!("mov [rbp-{}], rax  ; format result buffer", tmp));
                            self.emit_indent(&format!("mov rdi, [rbp-{}]", tmp));
                            self.emit_indent("pop rax  ; restore value to format");

                            if self.is_float_expr(value) {
                                self.uses_floats = true;
                                self.emit_indent("call _buffer_append_float");
                            } else if self.is_boolean_expr(value) {
                                let true_label = self.add_string("true");
                                let false_label = self.add_string("false");
                                let true_branch = self.new_label("cast_bool_true");
                                let done_label = self.new_label("cast_bool_done");
                                self.emit_indent("test rax, rax");
                                self.emit_indent(&format!("jnz {}", true_branch));
                                self.emit_indent(&format!("lea rsi, [rel {}]", false_label));
                                self.emit_indent(&format!("mov rdx, {}_len", false_label));
                                self.emit_indent(&format!("jmp {}", done_label));
                                self.emit(&format!("{}:", true_branch));
                                self.emit_indent(&format!("lea rsi, [rel {}]", true_label));
                                self.emit_indent(&format!("mov rdx, {}_len", true_label));
                                self.emit(&format!("{}:", done_label));
                                self.emit_indent("call _buffer_append_bytes");
                            } else {
                                let fmt_spec = FormatSpec {
                                    base: IntegerBase::Decimal,
                                    width: None,
                                    zero_pad: false,
                                    precision: None,
                                };
                                self.emit_append_formatted_int_to_buffer(fmt_spec);
                            }

                            self.emit_indent(&format!("mov rax, [rbp-{}]", tmp));
                            self.emit_indent("add rax, 24  ; buffer data area -> NUL-terminated C string");
                        }
                    }
                    _ => {
                        // Other casts - no-op
                        self.emit_indent("; Cast (no-op)");
                    }
                }
            }
            
            // Duration cast (timer's duration in seconds/milliseconds)
            Expr::DurationCast { value, unit } => {
                self.uses_time = true;
                self.generate_expr(value);
                match unit {
                    TimeUnit::Seconds => {
                        // Value is already in seconds
                        self.emit_indent("; Duration in seconds");
                    }
                    TimeUnit::Milliseconds => {
                        // Multiply by 1000
                        self.emit_indent("; Duration in milliseconds");
                        self.emit_indent("imul rax, 1000");
                    }
                }
            }
            
            // Byte access: byte N of buffer (1-indexed)
            // Buffer structure: [capacity:8][length:8][data at offset 24]
            // MEMORY SAFETY: Always bounds-check before access
            Expr::ByteAccess { buffer, index } => {
                let ok_label = self.new_label("byte_ok");
                let error_label = self.new_label("byte_err");
                let done_label = self.new_label("byte_done");

                self.emit_indent("; Byte access (1-indexed) with bounds check");
                // Get buffer pointer
                self.generate_expr(buffer);
                self.emit_indent("push rax  ; save buffer pointer");
                // Get index
                self.generate_expr(index);
                self.emit_indent("mov rcx, rax  ; index in rcx");
                self.emit_indent("pop rbx  ; buffer pointer in rbx");

                // Bounds check: index must be >= 1 and <= length
                self.emit_indent("cmp rcx, 1");
                self.emit_indent(&format!("jl {}  ; index < 1 is error", error_label));
                self.emit_indent("mov rdx, [rbx + 8]  ; get buffer length (offset 8)");
                self.emit_indent("cmp rcx, rdx");
                self.emit_indent(&format!("jle {}  ; index <= length is OK", ok_label));

                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent("xor rax, rax  ; return 0 on error");
                self.emit_indent(&format!("jmp {}", done_label));

                // Success path: safe access
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("dec rcx  ; convert 1-indexed to 0-indexed");
                self.emit_indent("add rbx, 24  ; skip to buffer data area");
                self.emit_indent("xor rax, rax");
                self.emit_indent("mov al, [rbx + rcx]");

                self.emit(&format!("{}:", done_label));
            }
            
            // Element access: element N of list (1-indexed)
            // List structure: [capacity:8][length:8][elem_size:8][data...] 
            // MEMORY SAFETY: Always bounds-check before access
            Expr::ElementAccess { list, index } => {
                let ok_label = self.new_label("elem_ok");
                let error_label = self.new_label("elem_err");
                let done_label = self.new_label("elem_done");
                let is_mixed = self.list_expr_is_mixed(list);
                
                self.emit_indent("; Element access (1-indexed) with bounds check");
                // Get list pointer
                self.generate_expr(list);
                self.emit_indent("push rax  ; save list pointer");
                // Get index
                self.generate_expr(index);
                self.emit_indent("mov rcx, rax  ; index in rcx");
                self.emit_indent("pop rbx  ; list pointer in rbx");
                
                // Bounds check: index must be >= 1 and <= length
                self.emit_indent("cmp rcx, 1");
                self.emit_indent(&format!("jl {}  ; index < 1 is error", error_label));
                self.emit_indent("mov rdx, [rbx + 8]  ; get length (offset 8)");
                self.emit_indent("cmp rcx, rdx");
                self.emit_indent(&format!("jle {}  ; index <= length is OK", ok_label));
                
                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent("xor rax, rax  ; return 0 on error");
                if is_mixed {
                    self.emit_indent("xor r11d, r11d  ; integer tag on error path");
                }
                self.emit_indent(&format!("jmp {}", done_label));
                
                // Success path: safe access
                // Data starts at offset 24, 1-indexed so element 1 is at offset 24
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("dec rcx  ; convert 1-indexed to 0-indexed");
                if is_mixed {
                    // Runtime type tag travels in r11 (captured immediately
                    // by the consumer - never held across calls/syscalls):
                    // tag_addr = base + 24 + capacity*8 + index
                    self.emit_indent("mov r11, [rbx]  ; capacity");
                    self.emit_indent("shl r11, 3  ; * element size (8)");
                    self.emit_indent("add r11, rcx  ; + 0-based index");
                    self.emit_indent("movzx r11, byte [rbx + r11 + 24]  ; slot type tag");
                }
                self.emit_indent("mov rax, rcx");
                self.emit_indent("shl rax, 3  ; index * 8");
                self.emit_indent("add rax, 24  ; skip header (24 bytes)");
                self.emit_indent("add rax, rbx");
                self.emit_indent("mov rax, [rax]  ; get element");
                
                self.emit(&format!("{}:", done_label));
            }

            // Map key access: person's "name". Loads the map variable, looks
            // up the key, and returns the value in rax with its runtime tag in
            // r11 (mirroring ElementAccess). A miss sets _last_error and
            // yields rax=0/r11=0. (stage 1e2, tag 5)
            Expr::MapAccess { map, key } => {
                self.uses_maps = true;
                self.emit_indent("; Map key access (lookup)");
                // map pointer -> rax, save on stack
                self.emit_load_named_var_into_rax(map);
                self.emit_indent("push rax  ; save map pointer");
                // key -> rsi (literal text; never a variable reference)
                self.generate_text_key(key);
                self.emit_indent("mov rsi, rax  ; key pointer");
                self.emit_indent("pop rdi  ; map pointer");
                self.emit_indent("call _map_lookup");
                // rax = value, r11 = tag (set by _map_lookup); on miss
                // _map_lookup sets _last_error=1, rax=0, r11=0.
            }

            // Format string in expression context (e.g. a text initializer
            // or a function argument): materialize it into a fresh dynamic
            // buffer and yield a pointer to the data area - a NUL-terminated
            // C string usable anywhere a text is. Previously this returned 0,
            // so `a text called "t" is "{buf}"` silently produced a NULL
            // text that printed as empty and crashed execve argv arrays.
            Expr::FormatString { parts } => {
                self.uses_buffers = true;
                self.stack_offset += 8;
                let tmp = self.stack_offset;
                self.emit_indent("mov rdi, 1024  ; default buffer size");
                self.emit_indent("call _alloc_buffer");
                self.emit_indent(&format!("mov [rbp-{}], rax", tmp));
                self.emit_format_parts_into_buffer_slot(tmp, parts, false);
                self.emit_indent(&format!("mov rax, [rbp-{}]", tmp));
                self.emit_indent("add rax, 24  ; buffer data area (header is 24 bytes)");
            }
        }
    }
    
    fn generate_condition(&mut self, condition: &Expr, false_label: &str) {
        match condition {
            Expr::PropertyCheck { value, property } => {
                self.generate_expr(value);
                match property {
                    Property::Even => {
                        self.emit_indent("test rax, 1");
                        self.emit_indent(&format!("jnz {}", false_label));
                    }
                    Property::Odd => {
                        self.emit_indent("test rax, 1");
                        self.emit_indent(&format!("jz {}", false_label));
                    }
                    Property::Zero => {
                        self.emit_indent("test rax, rax");
                        self.emit_indent(&format!("jnz {}", false_label));
                    }
                    Property::Positive => {
                        self.emit_indent("cmp rax, 0");
                        self.emit_indent(&format!("jle {}", false_label));
                    }
                    Property::Negative => {
                        self.emit_indent("cmp rax, 0");
                        self.emit_indent(&format!("jge {}", false_label));
                    }
                    Property::Empty => {
                        // For buffer/list variables, check the size field at offset 8
                        let is_buffer_or_list = match value.as_ref() {
                            Expr::StringLit(s) | Expr::Identifier(s) => {
                                matches!(self.variable_types.get(s), Some(VarType::Buffer) | Some(VarType::List))
                            }
                            _ => false,
                        };
                        if is_buffer_or_list {
                            self.emit_indent("mov rax, [rax + 8]  ; get size/length");
                        }
                        self.emit_indent("test rax, rax");
                        self.emit_indent(&format!("jnz {}", false_label));
                    }
                }
            }

            // Runtime type predicate (stage 1c) — branch form: jump to
            // false_label when the predicate is false. Folds statically; a
            // statically-true predicate falls through (no jump), a
            // statically-false one jumps straight to false_label.
            Expr::TypeCheck { value, type_noun } => {
                let target = type_to_tag(type_noun).expect("type predicate noun is scalar");
                let noun = type_noun_name(type_noun);
                match self.predicate_static_tag(value) {
                    Some(t) => {
                        if t != target {
                            self.emit_indent(&format!(
                                "jmp {}  ; is a {} statically false (static tag {})",
                                false_label, noun, t
                            ));
                        }
                        // t == target: statically true -> fall through to then.
                    }
                    None => {
                        self.generate_expr(value);
                        match self.runtime_tag_source(value) {
                            Some(src) => {
                                if let RuntimeTagSource::ShadowSlot(off) = src {
                                    self.emit_indent(&format!(
                                        "movzx r11, byte [rbp-{}]  ; load mixed element tag",
                                        off
                                    ));
                                }
                                self.emit_indent(&format!(
                                    "cmp r11, {}  ; is a {}?", target, noun
                                ));
                                self.emit_indent(&format!(
                                    "jne {}  ; not a {}", false_label, noun
                                ));
                            }
                            // No tag to compare (see the value form above).
                            None if target != TAG_INTEGER => {
                                self.emit_indent(&format!(
                                    "jmp {}  ; is a {}: no runtime tag, treated as number",
                                    false_label, noun
                                ));
                            }
                            None => {}
                        }
                    }
                }
            }

            Expr::FileAvailable { path } => {
                self.uses_files = true;
                self.generate_cstr_expr(path);
                self.emit_indent("FILE_AVAILABLE");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jz {}", false_label));
            }

            Expr::BinaryOp { left, op, right } => {
                match op {
                    BinaryOperator::And => {
                        self.generate_condition(left, false_label);
                        self.generate_condition(right, false_label);
                    }
                    BinaryOperator::Or => {
                        let true_label = self.new_label("or_true");
                        self.generate_expr(left);
                        self.emit_indent("test rax, rax");
                        self.emit_indent(&format!("jnz {}", true_label));
                        self.generate_condition(right, false_label);
                        self.emit(&format!("{}:", true_label));
                    }
                    // `x is nothing` / `x is not nothing` (stage 1e3): tag-6
                    // equality. Two values are equal-as-nothing iff BOTH have
                    // runtime tag 6 (payloads are ignored). This guard MUST
                    // precede the stringy and numeric equality arms: without
                    // it, `0 is nothing` would fall into the numeric arm
                    // (`cmp rax, rbx` on payloads) and wrongly be true, since
                    // nothing's payload is 0. Modelled on the `TypeCheck`
                    // runtime path (~line 4940): generate the non-nothing
                    // side, load its tag into r11 (shadow slot for a Mixed
                    // identifier, else r11 already holds it from an element
                    // read / `_map_lookup` / `value` call), and compare to 6.
                    BinaryOperator::Equal | BinaryOperator::NotEqual
                        if self.is_nothing_expr(left) || self.is_nothing_expr(right) =>
                    {
                        let equal = matches!(op, BinaryOperator::Equal);
                        if self.is_nothing_expr(left) && self.is_nothing_expr(right) {
                            // `nothing is nothing`: tag 6 == tag 6.
                            if !equal {
                                self.emit_indent(&format!("jmp {}  ; nothing is not nothing -> false", false_label));
                            }
                        } else {
                            let value = if self.is_nothing_expr(left) { right } else { left };
                            match self.emit_time_expr_tag(value) {
                                Some(t) => {
                                    // Folded: equal iff the static tag is 6.
                                    let holds = if equal { t == TAG_NOTHING } else { t != TAG_NOTHING };
                                    if !holds {
                                        self.emit_indent(&format!(
                                            "jmp {}  ; is {}nothing folded (static tag {})",
                                            false_label, if equal { "not " } else { "" }, t
                                        ));
                                    }
                                }
                                None => {
                                    self.generate_expr(value);
                                    match self.runtime_tag_source(value) {
                                        Some(src) => {
                                            if let RuntimeTagSource::ShadowSlot(off) = src {
                                                self.emit_indent(&format!(
                                                    "movzx r11, byte [rbp-{}]  ; load mixed element tag",
                                                    off
                                                ));
                                            }
                                            self.emit_indent("xor rax, rax");
                                            self.emit_indent(&format!(
                                                "cmp r11, {}  ; is nothing?", TAG_NOTHING
                                            ));
                                            self.emit_indent(
                                                if equal { "sete al" } else { "setne al" },
                                            );
                                            self.emit_indent("movzx rax, al");
                                            self.emit_indent("test rax, rax");
                                            self.emit_indent(&format!("jz {}", false_label));
                                        }
                                        // No tag anywhere and r11 holds
                                        // unrelated data, so the operand cannot
                                        // be shown to be nothing - decide
                                        // statically rather than read garbage.
                                        None if equal => self.emit_indent(&format!(
                                            "jmp {}  ; is nothing: operand carries no tag",
                                            false_label
                                        )),
                                        None => {}
                                    }
                                }
                            }
                        }
                    }
                    BinaryOperator::Equal | BinaryOperator::NotEqual
                        if self.is_stringy_expr(left) || self.is_stringy_expr(right) =>
                    {
                        // Content comparison - see emit_stringy_equality for why
                        // _mem_eq is used when either side is a buffer.
                        self.emit_stringy_equality(left, right);
                        self.emit_indent("test rax, rax");
                        let jmp = if matches!(op, BinaryOperator::Equal) { "jz" } else { "jnz" };
                        self.emit_indent(&format!("{} {}  ; 1=equal", jmp, false_label));
                    }
                    BinaryOperator::Equal | BinaryOperator::NotEqual |
                    BinaryOperator::Greater | BinaryOperator::Less |
                    BinaryOperator::GreaterEqual | BinaryOperator::LessEqual => {
                        let is_float = self.is_float_expr(left) || self.is_float_expr(right);

                        if is_float {
                            // Float comparison using SSE2. Use the helper macros so that
                            // NaN/unordered results behave like Vox comparisons: ordered
                            // comparisons are false when either operand is NaN, and != is
                            // true for NaN. The macro leaves a 0/1 result in rax.
                            self.generate_expr(right);
                            self.emit_indent("push rax");
                            self.generate_expr(left);
                            self.emit_indent("movq xmm0, rax");       // left in xmm0
                            self.emit_indent("pop rax");
                            self.emit_indent("movq xmm1, rax");       // right in xmm1

                            let macro_name = match op {
                                BinaryOperator::Equal => "FLOAT_EQ",
                                BinaryOperator::NotEqual => "FLOAT_NE",
                                BinaryOperator::Greater => "FLOAT_GT",
                                BinaryOperator::Less => "FLOAT_LT",
                                BinaryOperator::GreaterEqual => "FLOAT_GE",
                                BinaryOperator::LessEqual => "FLOAT_LE",
                                _ => unreachable!(),
                            };
                            self.emit_indent(macro_name);
                            self.emit_indent("test rax, rax");
                            self.emit_indent(&format!("jz {}", false_label));
                        } else {
                            // Integer comparison
                            self.generate_expr(right);
                            self.emit_indent("push rax");
                            self.generate_expr(left);
                            self.emit_indent("pop rbx");
                            self.emit_indent("cmp rax, rbx");
                            
                            let jmp = match op {
                                BinaryOperator::Equal => "jne",
                                BinaryOperator::NotEqual => "je",
                                BinaryOperator::Greater => "jle",
                                BinaryOperator::Less => "jge",
                                BinaryOperator::GreaterEqual => "jl",
                                BinaryOperator::LessEqual => "jg",
                                _ => unreachable!(),
                            };
                            self.emit_indent(&format!("{} {}", jmp, false_label));
                        }
                    }
                    _ => {
                        self.generate_expr(condition);
                        self.emit_indent("test rax, rax");
                        self.emit_indent(&format!("jz {}", false_label));
                    }
                }
            }
            
            Expr::UnaryOp { op: UnaryOperator::Not, operand } => {
                let true_label = self.new_label("not_true");
                self.generate_condition(operand, &true_label);
                self.emit_indent(&format!("jmp {}", false_label));
                self.emit(&format!("{}:", true_label));
            }
            
            _ => {
                self.generate_expr(condition);
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jz {}", false_label));
            }
        }
    }
    
    fn infer_expr_type(&self, expr: &Expr) -> Option<VarType> {
        match expr {
            Expr::IntegerLit(_) => Some(VarType::Integer),
            Expr::FloatLit(_) => Some(VarType::Float),
            Expr::StringLit(s) => self.quoted_name_var_type(s).or(Some(VarType::String)),
            Expr::BoolLit(_) => Some(VarType::Integer), // Booleans are integers (0/1)
            // A list literal is a list value (stage 1e1). This feeds the
            // emit_time_expr_tag catch-all so a nested-list element's slot
            // gets tag 4, and lets a bare `print <list-literal>` route to
            // `_list_print`.
            Expr::ListLit { .. } => Some(VarType::List),
            // A map literal is a map value (stage 1e2). Lets a bare
            // `print <map-literal>` route to `_map_print` and a map element's
            // slot get tag 5.
            Expr::MapLit { .. } => Some(VarType::Map),
            // A type predicate is boolean-valued; codegen treats booleans as
            // integers (0/1), matching BoolLit above (stage 1c).
            Expr::TypeCheck { .. } => Some(VarType::Integer),
            Expr::ArgumentCount => Some(VarType::Integer),
            Expr::ArgumentAt { .. } | Expr::ArgumentName | Expr::ArgumentFirst
            | Expr::ArgumentSecond | Expr::ArgumentLast => Some(VarType::String),
            Expr::ArgumentEmpty | Expr::ArgumentHas { .. } => Some(VarType::Integer),
            Expr::EnvironmentVariable { .. } | Expr::EnvironmentVariableAt { .. }
            | Expr::EnvironmentVariableFirst | Expr::EnvironmentVariableLast => Some(VarType::String),
            Expr::EnvironmentVariableCount | Expr::EnvironmentVariableExists { .. }
            | Expr::EnvironmentVariableEmpty => Some(VarType::Integer),
            Expr::ArgumentAll | Expr::ArgumentRaw => Some(VarType::List),
            Expr::Identifier(name) => self.variable_types.get(name).cloned(),
            Expr::FunctionCall { name, .. } => {
                self.function_return_types.get(&self.function_label(name)).cloned()
            }
            Expr::PropertyAccess { object, property } => {
                // For First/Last on lists, return the list's element type
                match property {
                    ObjectProperty::First | ObjectProperty::Last => {
                        if self.variable_types.get(object) == Some(&VarType::List) {
                            self.list_element_types.get(object).cloned()
                        } else {
                            Some(VarType::Integer)
                        }
                    }
                    // A map's keys/values yield a list (stage 1e2).
                    ObjectProperty::Keys | ObjectProperty::Values => Some(VarType::List),
                    ObjectProperty::Size | ObjectProperty::Capacity => Some(VarType::Integer),
                    _ => Some(VarType::Integer),
                }
            }
            Expr::ElementAccess { list, .. } => {
                // For element access, return the list's element type
                if let Expr::Identifier(name) = list.as_ref() {
                    self.list_element_types.get(name).cloned().or(Some(VarType::Integer))
                } else {
                    Some(VarType::Integer)
                }
            }
            // A map key read yields a runtime-tagged value (the value's type
            // depends on the key); `_map_lookup` leaves its tag in r11, so the
            // Mixed/value-ABI machinery handles it. Returning None marks it
            // unknowable, matching ElementAccess on a mixed list. (stage 1e2)
            Expr::MapAccess { .. } => None,
            Expr::BinaryOp { left, op, right } => match op {
                BinaryOperator::Add | BinaryOperator::Subtract | 
                BinaryOperator::Multiply | BinaryOperator::Divide |
                BinaryOperator::Modulo if self.is_float_expr(left) || self.is_float_expr(right) => Some(VarType::Float),
                _ => Some(VarType::Integer),
            },
            Expr::UnaryOp { operand, .. } => self.infer_expr_type(operand),
            Expr::TreatingAs { value, .. } => self.infer_expr_type(value),
            Expr::Cast { target_type, .. } => match target_type {
                Type::Integer => Some(VarType::Integer),
                Type::Float => Some(VarType::Float),
                Type::String => Some(VarType::String),
                Type::Boolean => Some(VarType::Integer),
                Type::Buffer => Some(VarType::Buffer),
                _ => Some(VarType::Integer),
            },
            _ => Some(VarType::Integer), // Default to integer for complex expressions
        }
    }

    fn is_fd_path_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::IntegerLit(_) => true,
            Expr::Identifier(name) => matches!(
                self.variable_types.get(name),
                Some(VarType::Integer)
            ),
            Expr::BinaryOp { .. }
            | Expr::UnaryOp { .. }
            | Expr::PropertyAccess { .. }
            | Expr::ByteAccess { .. }
            | Expr::ElementAccess { .. }
            | Expr::DurationCast { .. }
            | Expr::LastError
            | Expr::TreatingAs { .. } => self.infer_expr_type(expr) == Some(VarType::Integer),
            Expr::Cast { target_type, .. } => *target_type == Type::Integer,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Codegen routing tests for whole-list printing (plan 000). These lock
    //! the routing in at the compiler level - independent of the runtime -
    //! so a regression in `generate_print` is caught without assembling.
    use crate::analyzer::Analyzer;
    use crate::lexer::Lexer;
    use crate::parser::Parser;
    use super::{CodeGenerator, LibBlock};

    /// Parse, analyze, and generate asm for a source snippet. Panics with a
    /// clear message if parsing or analysis fails, so test failures point at
    /// the snippet rather than at silently-empty output.
    fn compile_to_asm(source: &str) -> String {
        let mut lexer = Lexer::new(source);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens).with_source("unit_test.vox", source);
        let mut program = parser
            .parse()
            .expect("test snippet should parse cleanly");
        let mut analyzer = Analyzer::new().with_source("unit_test.vox", source);
        analyzer.analyze(&mut program);
        assert!(
            analyzer.errors.is_empty(),
            "test snippet should analyze cleanly, got: {:?}",
            analyzer.errors
        );
        let mut gen = CodeGenerator::new();
        gen.generate(&program)
    }

    /// Like `compile_to_asm`, but in `--shared` mode: the analyzer enforces the
    /// library top-level rules (a `Library` declaration, only function defs)
    /// and the codegen mangles labels by library and version. Used to test the
    /// shared-library path without shelling out to nasm/ld.
    fn compile_to_asm_shared(source: &str) -> String {
        let mut lexer = Lexer::new(source);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens).with_source("lib_test.vox", source);
        let mut program = parser
            .parse()
            .expect("shared test snippet should parse cleanly");
        let mut analyzer = Analyzer::new()
            .with_source("lib_test.vox", source)
            .with_shared_mode(true);
        analyzer.analyze(&mut program);
        assert!(
            analyzer.errors.is_empty(),
            "shared test snippet should analyze cleanly, got: {:?}",
            analyzer.errors
        );
        let mut gen = CodeGenerator::new();
        gen.set_shared_lib_mode(true);
        gen.generate(&program)
    }

    #[test]
    fn whole_list_print_routes_to_list_print() {
        let asm = compile_to_asm("a list called \"xs\" is [1, 2, 3].\nprint xs.\n");
        assert!(
            asm.contains("call _list_print"),
            "a whole-list print must route to _list_print, not PRINT_INT"
        );
        // Exactly one whole-list print in the source -> exactly one call.
        assert_eq!(
            asm.matches("call _list_print").count(),
            1,
            "expected exactly one `call _list_print`"
        );
    }

    #[test]
    fn list_format_interpolation_routes_to_list_print() {
        let asm = compile_to_asm("a list called \"xs\" is [1, 2, 3].\nprint \"xs: {xs}\".\n");
        assert!(
            asm.contains("call _list_print"),
            "a {{list}} interpolation must route to _list_print"
        );
        assert_eq!(asm.matches("call _list_print").count(), 1);
    }

    #[test]
    fn mixed_list_whole_print_routes_to_list_print() {
        // A mixed list variable has variable_types == List (its element type
        // is tracked separately in list_element_types), so the whole-list
        // print must still take the _list_print branch - not the per-element
        // Mixed dispatch, which would print a single pointer.
        let asm = compile_to_asm("a list called \"m\" is [1, \"two\", 3.5].\nprint m.\n");
        assert!(asm.contains("call _list_print"));
        assert_eq!(asm.matches("call _list_print").count(), 1);
    }

    #[test]
    fn non_list_print_does_not_route_to_list_print() {
        let asm = compile_to_asm("a number called \"n\" is 5.\nprint n.\n");
        assert!(
            !asm.contains("call _list_print"),
            "a non-list print must not route to _list_print"
        );
    }

    #[test]
    fn multiple_list_prints_each_route_to_list_print() {
        // Two whole-list prints (one direct, one interpolated) -> two calls.
        let asm = compile_to_asm(
            "a list called \"xs\" is [1, 2, 3].\nprint xs.\nprint \"xs: {xs}\".\n",
        );
        assert_eq!(asm.matches("call _list_print").count(), 2);
    }

    // ---- Stage 1b: inference soundness flip (plan 010) ----
    //
    // These lock in the three-state pre-scan: a list whose every write is
    // provable keeps the untagged fast path; an unprovable write widens to
    // Mixed so reads dispatch on runtime tags.

    #[test]
    fn homogeneous_int_list_keeps_fast_path() {
        // Acceptance criterion 1: a list built only from integer literals
        // emits no tag writes and no runtime-tag dispatch.
        let asm =
            compile_to_asm("a list called \"xs\" is [1, 2, 3].\nprint element 1 of xs.\n");
        assert!(
            !asm.contains("mixp_"),
            "a homogeneous int list must not emit mixed-dispatch labels"
        );
        assert!(
            !asm.contains("movzx r11, byte"),
            "a homogeneous int list read must not load a runtime tag into r11"
        );
    }

    #[test]
    fn mixed_list_emits_dispatch() {
        // Contrast: a genuinely mixed list DOES dispatch on tags.
        let asm =
            compile_to_asm("a list called \"m\" is [1, \"two\"].\nprint element 1 of m.\n");
        assert!(
            asm.contains("mixp_"),
            "a mixed list read must emit mixed-dispatch labels"
        );
    }

    #[test]
    fn declared_text_function_append_tagged_string() {
        // Acceptance criterion 2: a function result of declared text type
        // appended alongside an integer is tagged STRING (not the old
        // TAG_INTEGER guess), and the list widens to Mixed.
        let asm = compile_to_asm(
            "To \"greet\" with a number called \"x\".\n  Return a text, \"hi\".\n\
             a list called \"items\" is [].\n\
             append 1 to items.\n\
             append \"greet\" of 0 to items.\n\
             print element 1 of items.\n\
             print element 2 of items.\n",
        );
        assert!(
            asm.contains("mov edx, 1  ; element type tag"),
            "the text-returning function result must be written with TAG_STRING (1)"
        );
        assert!(
            asm.contains("mixp_"),
            "the list widened to Mixed (int + text function result)"
        );
    }

    #[test]
    fn read_of_widened_list_does_not_prove_a_type() {
        // `list_seen_tags` records the FIRST tag proven for a list and is
        // never retracted, so a list that starts homogeneous and is later
        // appended a different type still has its original tag recorded.
        // Reading an element out of it must consult `mixed_lists` and yield
        // Unknowable - otherwise the destination stays on the fast path while
        // holding a value of the wrong type.
        let asm = compile_to_asm(
            "a list called \"m\" is [1, 2].\n\
             append \"hi\" to m.\n\
             a list called \"out\" is [0, 0].\n\
             set element 1 of out to element 3 of m.\n\
             print element 1 of out.\n",
        );
        assert!(
            asm.contains("mixp_"),
            "reading an element of a widened list must widen the destination"
        );
    }

    #[test]
    fn declared_type_does_not_forge_a_string_tag() {
        // A declared type is the author's intent, not a proof about the bits
        // that land in the slot. Tagging an unprovable value TAG_STRING makes
        // the tag-dispatching printer dereference whatever integer is there.
        let asm = compile_to_asm(
            "a list called \"m\" is [\"a\", \"b\"].\n\
             append 42 to m.\n\
             a text called \"s\" is element 3 of m.\n\
             a list called \"out\" is [].\n\
             append s to out.\n",
        );
        assert!(
            !asm.contains("mov edx, 1  ; element type tag"),
            "an unprovable value must not be written with TAG_STRING"
        );
    }

    #[test]
    fn declared_type_still_tags_a_provable_string() {
        // Contrast with the above: when the initializer IS provable, the
        // string tag must still be written, or homogeneous text lists would
        // print pointers.
        let asm = compile_to_asm(
            "a text called \"s\" is \"hello\".\n\
             a list called \"out\" is [].\n\
             append s to out.\n",
        );
        assert!(
            asm.contains("mov edx, 1  ; element type tag"),
            "a provably-text value must still be written with TAG_STRING"
        );
    }

    #[test]
    fn undeclared_return_function_append_widens() {
        // Acceptance criterion 3: a function with an undeclared return type
        // (`Return x add 1.` — no `a number,` prefix) is genuinely opaque to
        // the compiler, so appending its result widens the list to Mixed and
        // reads dispatch on tags (the flip from 1a's optimistic default).
        let asm = compile_to_asm(
            "To \"five\" with a number called \"x\".\n  Return x add 1.\n\
             a list called \"items\" is [].\n\
             append \"hello\" to items.\n\
             append \"five\" of 4 to items.\n\
             print element 1 of items.\n\
             print element 2 of items.\n",
        );
        assert!(
            asm.contains("mixp_"),
            "an unknowable (undeclared-return) append must widen the list to Mixed"
        );
    }

    // ---- Stage 1c: runtime type predicates (plan 020) ----
    //
    // Lock in the two codegen paths: a mixed operand emits a runtime tag
    // compare against r11; a statically-typed operand folds to a constant
    // with no runtime compare.

    #[test]
    fn type_predicate_mixed_emits_runtime_compare() {
        // A for-each over a mixed list binds a Mixed loop variable, whose
        // tag lives in its shadow slot. `item is a text` must load that tag
        // and compare it against TAG_STRING (1) at runtime.
        let asm = compile_to_asm(
            "a list called \"m\" is [1, \"x\"].\n\
             For each item in m, if item is a text, print item.\n",
        );
        assert!(
            asm.contains("cmp r11, 1"),
            "a mixed-element type predicate must compare the runtime tag against TAG_STRING"
        );
        assert!(
            asm.contains("movzx r11, byte [rbp-"),
            "the for-each variable's tag must be loaded from its shadow slot"
        );
    }

    #[test]
    fn mangle_symbol_produces_c_identifiers() {
        use super::mangle_symbol;
        // Spaces, the existing case.
        assert_eq!(mangle_symbol("greet user"), "greet_user");
        // Dots - the case that matters, because library versions contain one.
        assert_eq!(mangle_symbol("my.helper"), "my_helper");
        assert_eq!(mangle_symbol("flags_0.1_hasflag"), "flags_0_1_hasflag");
        // Anything else outside [A-Za-z0-9_].
        assert_eq!(mangle_symbol("parse-line"), "parse_line");
        assert_eq!(mangle_symbol("add%"), "add_");
        // A leading digit is not a legal identifier start in C.
        assert_eq!(mangle_symbol("2fast"), "_2fast");
        // Already-valid names are untouched.
        assert_eq!(mangle_symbol("already_fine"), "already_fine");
    }

    #[test]
    fn mangle_library_symbol_joins_three_components() {
        use super::mangle_library_symbol;
        // The plan 230 example: mathkit + 1.0 + "add two numbers".
        assert_eq!(
            mangle_library_symbol("mathkit", "1.0", "add two numbers"),
            "mathkit_1_0_add_two_numbers"
        );
        // Each component is mangled independently, then joined with `_`.
        // A version with a dot folds to `_` only inside that component.
        assert_eq!(
            mangle_library_symbol("my.lib", "2.0", "greet"),
            "my_lib_2_0_greet"
        );
        // A leading-digit version component is prefixed per mangle_symbol.
        assert_eq!(
            mangle_library_symbol("lib", "1", "greet"),
            "lib_1_greet"
        );
    }

    // ---- Stage A1: mangle exported symbols by library and version ----
    //
    // The label itself must change, not just the export list. These lock in
    // both halves: the definition emits `<lib>_<ver>_<func>`, and a call
    // site inside the library targets the same mangled label (never the bare
    // name the version script does not export).

    #[test]
    fn shared_lib_mangles_exported_labels_by_library_and_version() {
        // The tests/shared/libmath.vox corpus, in source form: a Library
        // declaration plus the three exports. In --shared mode every defined
        // label becomes <lib>_<ver>_<func>.
        let src = "\
Library \"mathkit\" version \"1.0\".\n\
To \"add two numbers\" with a number called \"n\".\n  Return n add 2.\n\
To \"greet\".\n  Print \"hello from libmath\".\n\
To \"makebuf\".\n  Create a buffer called \"b\".\n  Append \"hello\" to b.\n  Return b's size.\n";
        let asm = compile_to_asm_shared(src);
        // The three definitions emit the mangled labels...
        assert!(
            asm.contains("mathkit_1_0_add_two_numbers:"),
            "the 'add two numbers' definition must emit the mangled label"
        );
        assert!(
            asm.contains("mathkit_1_0_greet:"),
            "the 'greet' definition must emit the mangled label"
        );
        assert!(
            asm.contains("mathkit_1_0_makebuf:"),
            "the 'makebuf' definition must emit the mangled label"
        );
        // ...and each is exported as a STT_FUNC dynamic symbol.
        assert!(
            asm.contains("global mathkit_1_0_add_two_numbers:function"),
            "the mangled label must be the exported symbol, not the bare name"
        );
        assert!(
            asm.contains("global mathkit_1_0_greet:function"),
            "greet must be exported under its mangled name"
        );
        assert!(
            asm.contains("global mathkit_1_0_makebuf:function"),
            "makebuf must be exported under its mangled name"
        );
        // The bare labels must NOT appear as definitions or exports — that is
        // the half-right failure mode the plan warns about.
        assert!(
            !asm.contains("\nadd_two_numbers:"),
            "the bare label must not be defined alongside the mangled one"
        );
        assert!(
            !asm.contains("global greet:function"),
            "the bare 'greet' must not be exported"
        );
    }

    #[test]
    fn shared_lib_call_site_targets_mangled_label() {
        // A function that calls a sibling in the same library must `call` the
        // mangled label, not the bare name — otherwise the .so defines
        // mathkit_1_0_greet while the call branches to greet, which the
        // version script does not export.
        let src = "\
Library \"mathkit\" version \"1.0\".\n\
To \"double\" with a number called \"n\".\n  Return n add n.\n\
To \"run\".\n  Print \"double\" of 21.\n";
        let asm = compile_to_asm_shared(src);
        assert!(
            asm.contains("call mathkit_1_0_double"),
            "an intra-library call must target the mangled label, not the bare name"
        );
        assert!(
            !asm.contains("call double\n") && !asm.contains("call double "),
            "the bare name must not be the call target in shared mode"
        );
    }

    // Acceptance item 2 — two source files each defining `greet` in one .so
    // — was deferred from A1. A1 mangled the labels but could not demonstrate
    // coexistence: the per-compilation symbol tables were keyed by the
    // AUTHORED name, so two `greet`s collided in `function_return_types` /
    // `function_param_types` (and the analyzer's `functions` /
    // `mangled_functions` / `function_param_counts`) even with distinct labels.
    // A2 scopes those tables by `<lib,version>` (keyed on the mangled label),
    // so the case is now provable. The unit test below mirrors it at the
    // codegen level; the end-to-end proof is `run_two_version_library_test` in
    // test.sh, which builds a real two-version .so through the CLI and calls
    // both versions from an assembly driver.

    #[test]
    fn two_versions_of_one_library_coexist_in_one_unit() {
        // The A1 finding, now resolved. Two VERSIONS of `flags` in one
        // compilation unit (exactly what the CLI concatenates from two inputs),
        // both defining `hasflag`, no longer collide: the signature tables are
        // keyed by the `<lib>_<ver>_<func>` label, so each definition emits and
        // exports its own mangled symbol. A call inside each library would
        // resolve to its own body; here we assert the definitions survive
        // side by side rather than the second overwriting the first.
        let src = "\
Library \"flags\" version \"0.1\".\n\
To \"hasflag\" with a number called \"n\".\n  Return n add 1.\n\
Library \"flags\" version \"1.0\".\n\
To \"hasflag\" with a number called \"n\".\n  Return n add 100.\n";
        let asm = compile_to_asm_shared(src);
        assert!(
            asm.contains("flags_0_1_hasflag:"),
            "version 0.1 must emit its own mangled label"
        );
        assert!(
            asm.contains("flags_1_0_hasflag:"),
            "version 1.0 must emit its own mangled label"
        );
        assert!(
            asm.contains("global flags_0_1_hasflag:function"),
            "version 0.1 must be exported under its mangled name"
        );
        assert!(
            asm.contains("global flags_1_0_hasflag:function"),
            "version 1.0 must be exported under its mangled name"
        );
        // The collision A1 found would let the second definition's signature
        // overwrite the first's; both labels must still be defined exactly
        // once (no silent merge, no duplicate-label NASM error pending). The
        // `\n` prefix counts the label DEFINITION line, not the
        // `global <label>:function` export line, which also ends in `:`.
        assert_eq!(
            asm.matches("\nflags_0_1_hasflag:").count(),
            1,
            "version 0.1 label defined exactly once"
        );
        assert_eq!(
            asm.matches("\nflags_1_0_hasflag:").count(),
            1,
            "version 1.0 label defined exactly once"
        );
    }

    #[test]
    fn two_version_call_resolves_within_its_own_library() {
        // A call to `hasflag` inside version 0.1's body must target
        // flags_0_1_hasflag, and a call inside 1.0's body must target
        // flags_1_0_hasflag — the same-library resolution that the scoped
        // tables make work. This is the wrong-code bug A1 warned about: with
        // name-keyed tables both calls would resolve against one signature.
        let src = "\
Library \"flags\" version \"0.1\".\n\
To \"hasflag\" with a number called \"n\".\n  Return n add 1.\n\
To \"call0\".\n  Return \"hasflag\" of 5.\n\
Library \"flags\" version \"1.0\".\n\
To \"hasflag\" with a number called \"n\".\n  Return n add 100.\n\
To \"call1\".\n  Return \"hasflag\" of 5.\n";
        let asm = compile_to_asm_shared(src);
        // `call0` lives in the 0.1 library, so its `hasflag` call targets the
        // 0.1 mangled label; `call1` lives in 1.0, so its call targets 1.0.
        assert!(
            asm.contains("call flags_0_1_hasflag"),
            "a call in the 0.1 library must target flags_0_1_hasflag"
        );
        assert!(
            asm.contains("call flags_1_0_hasflag"),
            "a call in the 1.0 library must target flags_1_0_hasflag"
        );
    }

    // ---- Stage A2 (corpus fix): differing signatures prove table scoping ----
    //
    // The flags corpus above (`two_versions_of_one_library_coexist_in_one_unit`
    // and `two_version_call_resolves_within_its_own_library`) gives both
    // versions of `hasflag` the SAME signature — a number in, a number out.
    // That proves the mangled LABELS are distinct and intra-library calls
    // target the right label, but it is blind to the bug A2 exists to prevent:
    // a failure to scope the SIGNATURE tables (`function_return_types` /
    // `function_param_types`) by <lib,version>. With identical signatures, a
    // collapsed (name-keyed) table produces byte-identical codegen to a scoped
    // one — the second library's return type "wins" but is the same value, so
    // nothing observable changes. A test that passes for the wrong reason
    // reports safety it is not checking.
    //
    // This case gives the two `get`s DIFFERENT return types — number in 0.1,
    // text in 1.0 — and consumes each result with `print`. The print routing
    // (PRINT_INT for a number, PRINT_CSTR for text) is driven by
    // `infer_expr_type`, which reads `function_return_types[function_label(name)]`
    // — the scoped lookup. If the table were keyed by authored name, 1.0's
    // `text` return would win for 0.1's `useit` too, and a number would be
    // printed with PRINT_CSTR: wrong code, no diagnostic. The assertions below
    // fail in exactly that collapse, so the case is now sensitive to the
    // signature-table scoping the flags corpus cannot see.

    /// The first `PRINT_*` instruction occurring after `anchor` in `asm`, used
    /// to check that a function-call result is routed by its inferred (scoped)
    /// return type. `"PRINT_INT "` / `"PRINT_CSTR "` (with the trailing space)
    /// avoid matching `PRINT_INT_ZEROPAD` / `PRINT_INT_PADDED`, which embed the
    /// `PRINT_INT` prefix under an underscore.
    fn first_print_after(asm: &str, anchor: &str) -> &'static str {
        let i = asm
            .find(anchor)
            .unwrap_or_else(|| panic!("anchor {:?} not found in asm", anchor));
        let rest = &asm[i..];
        let int = rest.find("PRINT_INT ");
        let cstr = rest.find("PRINT_CSTR ");
        match (int, cstr) {
            (Some(a), Some(b)) => {
                if a < b {
                    "PRINT_INT"
                } else {
                    "PRINT_CSTR"
                }
            }
            (Some(_), None) => "PRINT_INT",
            (None, Some(_)) => "PRINT_CSTR",
            (None, None) => panic!("no PRINT_* found after anchor {:?}", anchor),
        }
    }

    #[test]
    fn two_versions_differing_signatures_resolve_per_library() {
        let src = "\
Library \"sig\" version \"0.1\".\n\
To \"get\" with a number called \"n\".\n  Return a number, n add 1.\n\
To \"useit\" with a number called \"n\".\n  Print \"get\" of n.\n\n\
Library \"sig\" version \"1.0\".\n\
To \"get\" with a number called \"n\".\n  Return a text, \"hello\".\n\
To \"useit2\" with a number called \"n\".\n  Print \"get\" of n.\n";
        let asm = compile_to_asm_shared(src);
        // The call inside each library targets its own `get` (the property
        // A2 scoped; restated here because this is the case that also carries
        // the return-type value).
        assert!(
            asm.contains("call sig_0_1_get"),
            "a call in the 0.1 library must target sig_0_1_get"
        );
        assert!(
            asm.contains("call sig_1_0_get"),
            "a call in the 1.0 library must target sig_1_0_get"
        );
        // The return-type VALUE is scoped per library: 0.1's `get` returns a
        // number, so `useit` prints it with PRINT_INT; 1.0's `get` returns text,
        // so `useit2` prints it with PRINT_CSTR. A name-keyed table would let
        // 1.0's `text` win for 0.1's call, making `useit` print a number with
        // PRINT_CSTR — the wrong-code bug, caught here.
        assert_eq!(
            first_print_after(&asm, "call sig_0_1_get"),
            "PRINT_INT",
            "0.1's get returns a number, so its result must print as PRINT_INT"
        );
        assert_eq!(
            first_print_after(&asm, "call sig_1_0_get"),
            "PRINT_CSTR",
            "1.0's get returns text, so its result must print as PRINT_CSTR"
        );
    }

    // ---- Stage A3: emit the `.lib` interface file ----

    /// Compile `source` in `--shared` mode and return the collected per-library
    /// signature blocks plus the mangled export labels, so the `.lib` render
    /// and the ToC↔export round-trip can be tested without shelling out to
    /// nasm/ld. Mirrors `compile_to_asm_shared` but exposes the codegen state.
    fn compile_shared_with_libs(source: &str) -> (Vec<LibBlock>, Vec<String>) {
        let mut lexer = Lexer::new(source);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens).with_source("lib_test.vox", source);
        let mut program = parser
            .parse()
            .expect("shared test snippet should parse cleanly");
        let mut analyzer = Analyzer::new()
            .with_source("lib_test.vox", source)
            .with_shared_mode(true);
        analyzer.analyze(&mut program);
        assert!(
            analyzer.errors.is_empty(),
            "shared test snippet should analyze cleanly, got: {:?}",
            analyzer.errors
        );
        let mut gen = CodeGenerator::new();
        gen.set_shared_lib_mode(true);
        gen.generate(&program);
        (gen.library_blocks().to_vec(), gen.exported_functions().to_vec())
    }

    #[test]
    fn lib_file_two_version_round_trip() {
        // The showcase case: two versions of `flags` in one .so, each with a
        // typed return (`Return a number, ...`), so the `.lib` carries a
        // return type. The emitted `.lib` is pasted in the A3 report; this test
        // pins it to the normative format so a formatting drift fails here.
        let src = "\
Library \"flags\" version \"0.1\".\n\
To \"hasflag\" with a number called \"n\".\n  Return a number, n add 1.\n\
Library \"flags\" version \"1.0\".\n\
To \"hasflag\" with a number called \"n\".\n  Return a number, n add 100.\n";
        let (blocks, exports) = compile_shared_with_libs(src);

        // Two Library blocks, one per version, in source order.
        assert_eq!(blocks.len(), 2, "two inputs -> two Library blocks in one .lib");
        assert_eq!(blocks[0].lib, "flags");
        assert_eq!(blocks[0].version, "0.1");
        assert_eq!(blocks[1].lib, "flags");
        assert_eq!(blocks[1].version, "1.0");

        // Round-trip invariant (the one thing to test): each ToC entry, mangled
        // by its block's <lib, version>, must equal the exported dynamic
        // symbol set one-for-one. A4 will re-parse this `.lib` and verify the
        // same against `.dynsym`; here we verify it against the codegen's own
        // export list, which becomes `.dynsym` via the version script.
        let toc_mangled: Vec<String> = blocks
            .iter()
            .flat_map(|b| {
                b.funcs
                    .iter()
                    .map(|f| super::mangle_library_symbol(&b.lib, &b.version, &f.name))
            })
            .collect();
        let mut got = toc_mangled.clone();
        got.sort();
        let mut exp = exports.clone();
        exp.sort();
        assert_eq!(
            got, exp,
            "ToC mangled names must match exported_functions one-for-one"
        );

        // The emitted `.lib` for libflags.so (the normative format; one entry
        // per line, never wrapped; `Location` relative to the `.lib`). Written
        // as one literal — Rust's `\` line continuation strips leading
        // whitespace, which would silently drop the 4-space indent the format
        // requires, so the entry lines are kept on their `\n` continuation
        // line instead of split across one.
        let lib = super::render_lib_file(&blocks, "libflags.so");
        let expected = "Library \"flags\" version \"0.1\".\nLocation \"./libflags.so\".\n\nTable of Contents:\n    To \"hasflag\" with a number called \"n\", returning a number.\n\nLibrary \"flags\" version \"1.0\".\nLocation \"./libflags.so\".\n\nTable of Contents:\n    To \"hasflag\" with a number called \"n\", returning a number.\n";
        assert_eq!(lib, expected, "emitted .lib must match the normative format");
    }

    #[test]
    fn lib_file_signatures_carry_params_names_types_and_return() {
        // A library whose export has multiple parameters and a `value` return:
        // the `.lib` must carry every parameter (name + type), joined with
        // ` and `, and the return type as `, returning a value` (the `value` ABI
        // is fixed, so the type name alone is complete — no extra fields).
        let src = "\
Library \"m\" version \"2.0\".\n\
To \"f\" with a number called \"a\" and a text called \"s\" and a value called \"v\".\n  Return a value, v.\n";
        let (blocks, _exports) = compile_shared_with_libs(src);
        assert_eq!(blocks.len(), 1);
        let lib = super::render_lib_file(&blocks, "libm.so");
        assert!(
            lib.contains("To \"f\" with a number called \"a\" and a text called \"s\" and a value called \"v\", returning a value."),
            "multi-param entry joined with ` and `, value param/return by type name only; got:\n{}",
            lib
        );
    }

    #[test]
    fn lib_file_parameterless_and_void_return_omits_clauses() {
        // `To "greet".` — no params, void return — reads as a bare entry with
        // no `with` clause and no `, returning` clause. A parameterless function
        // with a return reads `To "makebuf", returning a number.`. This is the
        // parameterless / value-parameter readability the steer asked to settle.
        let src = "\
Library \"m\" version \"1.0\".\n\
To \"greet\".\n  Print \"hi\".\n\n\
To \"makebuf\".\n  Return a number, 7.\n";
        let (blocks, _exports) = compile_shared_with_libs(src);
        let lib = super::render_lib_file(&blocks, "libm.so");
        assert!(
            lib.contains("To \"greet\"."),
            "a parameterless void-return function reads `To \"greet\".`; got:\n{}",
            lib
        );
        assert!(
            lib.contains("To \"makebuf\", returning a number."),
            "a parameterless function with a return reads `To \"makebuf\", returning a number.`; got:\n{}",
            lib
        );
    }

    #[test]
    fn non_shared_builds_keep_plain_labels() {
        // Non-shared builds must be completely unaffected: same labels as
        // today. The same source without --shared emits the bare mangled
        // name, no library prefix, no `:function` export.
        let src = "\
To \"greet\".\n  Print \"hi\".\n\
To \"double\" with a number called \"n\".\n  Return n add n.\n\
To \"run\".\n  Print \"double\" of 21.\n";
        let asm = compile_to_asm(src);
        assert!(
            asm.contains("greet:"),
            "non-shared builds keep the plain mangled label"
        );
        assert!(
            asm.contains("call double"),
            "non-shared call sites target the plain mangled name"
        );
        assert!(
            !asm.contains("_1_0_"),
            "no library/version mangling outside shared mode"
        );
        assert!(
            !asm.contains(":function"),
            "the :function export tag is shared-mode only"
        );
    }

    #[test]
    fn unprovable_guard_never_suppresses_a_list_tag() {
        // The unprovable-scalar guard must not reach list-typed names: a list
        // variable's slot always holds a list pointer, so TAG_LIST is always
        // truthful. Suppressing it would write the integer tag and print the
        // nested list as a pointer instead of its contents.
        let asm = compile_to_asm(
            "a list called \"one\" is [1, 2].\n\
             a list called \"two\" is [3].\n\
             set two to one.\n\
             a list called \"outer\" is [].\n\
             append two to outer.\n",
        );
        assert!(
            asm.contains("mov edx, 4  ; element type tag"),
            "appending a list must write TAG_LIST even when the pre-scan could \
             not prove the alias's contents"
        );
    }

    #[test]
    fn type_predicate_never_compares_an_unset_r11() {
        // r11 carries a runtime tag only straight out of a mixed-list read.
        // An opaque function result has no tag anywhere, and the `call` that
        // produced it has already clobbered r11 - comparing against it would
        // read garbage. The predicate must answer statically instead.
        let asm = compile_to_asm(
            "To \"opaque\" with a number called \"n\".\n  Return n add 1.\n\
             if \"opaque\" of 4 is a text, print \"t\".\n",
        );
        assert!(
            !asm.contains("cmp r11,"),
            "a tagless operand must not be compared against r11"
        );
    }

    #[test]
    fn type_predicate_on_unprovable_scalar_uses_declared_type() {
        // `unprovable_scalars` stops a declared type from being written as a
        // slot tag (it would forge a pointer), but a predicate only reads a
        // tag. It must still fold on the declared type rather than fall
        // through to a runtime compare against an unset r11.
        let asm = compile_to_asm(
            "a list called \"m\" is [\"a\", \"b\"].\n\
             append 42 to m.\n\
             a text called \"s\" is element 3 of m.\n\
             print \"sep\".\n\
             if s is a text, print \"t\".\n",
        );
        assert!(
            !asm.contains("cmp r11,"),
            "an unprovable scalar predicate must fold, not compare a stale r11"
        );
    }

    #[test]
    fn type_predicate_static_folds() {
        // A declared `a number called "x"` is statically integer, so
        // `x is a number` folds to true (no runtime compare) and `x is a
        // text` folds to false (a static-false jump, no cmp r11).
        let asm_true = compile_to_asm(
            "a number called \"x\" is 5.\nif x is a number, print \"n\".\n",
        );
        assert!(
            !asm_true.contains("cmp r11,"),
            "a statically-true predicate must fold (no runtime tag compare)"
        );

        let asm_false = compile_to_asm(
            "a number called \"x\" is 5.\nif x is a text, print \"t\".\n",
        );
        assert!(
            !asm_false.contains("cmp r11,"),
            "a statically-false predicate must fold (no runtime tag compare)"
        );
        assert!(
            asm_false.contains("statically false"),
            "a statically-false predicate must emit a fold-time jump to the false label"
        );
    }

    #[test]
    fn type_predicate_result_appends_tagged_boolean() {
        // Appending a predicate result (`append item is a number to flags`)
        // must tag the slot TAG_BOOLEAN (3) — not TAG_INTEGER — so the list
        // is a homogeneous boolean list (no mixed widening) and a later
        // `is a boolean` recognises its elements. Covers the TypeCheck arms
        // of prescan_expr_tag / emit_time_expr_tag and the append
        // element-type classifier reached only via `append <value> is a ...`.
        let asm = compile_to_asm(
            "a list called \"m\" is [1, 2, 3].\n\
             a list called \"flags\" is [].\n\
             For each item in m, append item is a number to flags.\n\
             For each f in flags, if f is a boolean, print \"B\".\n",
        );
        // The append stores tag 3 (TAG_BOOLEAN), not 0 (TAG_INTEGER).
        assert!(
            asm.contains("mov edx, 3"),
            "an appended predicate result must be tagged TAG_BOOLEAN (edx=3)"
        );
        // The list of predicate results stays homogeneous (no mixed widening
        // from the predicate appends), so it must not use the mixed print
        // dispatch.
        assert!(
            !asm.contains("mixp_"),
            "a list of predicate results must not widen to mixed"
        );
        // `f is a boolean` on the boolean-typed for-each variable folds true
        // (no runtime tag compare for f).
    }

    // ---- Stage 1d: dynamic `value` type across function boundaries (plan 030)
    //
    // A `value` parameter/return carries its runtime type tag through the
    // calling convention. These lock the ABI in at the asm level, independent
    // of the runtime: inbound (2 words per value param), outbound (tag in r11,
    // no spill), the 7-word straddle (reg/stack pad), and the append tag
    // forwarding for a value-returning call.

    #[test]
    fn value_param_carries_tag_inbound() {
        // Acceptance 1: a value parameter gets a shadow tag slot in the callee,
        // and the caller pushes a 2nd (tag) word for it. Inside the callee, a
        // predicate classifies by comparing the loaded tag to TAG_INTEGER (0).
        let asm = compile_to_asm(
            "To \"describe\" with a value called \"v\".\n\
             If v is a number, print \"N\". Otherwise print \"T\".\n\
             a list called \"m\" is [1, \"two\"].\n\
             For each item in m, \"describe\" of item.\n",
        );
        // Caller pushes the value param's tag word (payload pushed after, on top).
        assert!(
            asm.contains("value param tag word"),
            "a value param must push a 2nd (tag) word at the call site"
        );
        // Callee stores the inbound tag byte to the value's shadow slot.
        assert!(
            asm.contains("param value tag"),
            "the callee must store the inbound value tag byte to a shadow slot"
        );
        // The predicate inside the callee compares the loaded tag to TAG_INTEGER.
        assert!(
            asm.contains("cmp r11, 0"),
            "the `v is a number` predicate must compare the loaded tag to 0"
        );
    }

    #[test]
    fn value_return_leaves_tag_in_r11() {
        // Acceptance 2: a value-returning function loads its result's tag into
        // r11 on the return path, and — because FUNC_EPILOGUE (`leave; ret`)
        // and `_dec_call_depth` clobber neither r11 nor the saved words — no
        // r11 spill is needed across the return.
        let asm = compile_to_asm(
            "To \"id\" with a value called \"v\". Return a value, v.\n\
             a list called \"m\" is [1, \"two\"].\n\
             a list called \"out\" is [].\n\
             For each item in m, append \"id\" of item to out.\n",
        );
        // The return path loads the tag from the shadow slot, then the existing
        // `push rax / call _dec_call_depth / pop rax` epilogue. (This sequence
        // is distinct from the call-site tag load, which is followed by
        // `push r11  ; value param tag word`.)
        assert!(
            asm.contains("value tag (shadow slot)\n    push rax  ; save return value"),
            "the return path must load the value tag into r11 before the epilogue"
        );
        // No r11 spill: r11 is never pushed/popped around the return. r11 is not
        // a param register, so it is never saved in the prologue either.
        assert!(
            !asm.contains("pop r11"),
            "the value return tag rides in r11 across leave;ret with no spill"
        );
    }

    #[test]
    fn value_param_two_words_in_call() {
        // Acceptance 3: a value param occupies 2 argument words (payload, tag).
        // With 5 scalar params + 1 value param = 7 words, 6 fill the registers
        // and the 7th spills to the stack; an odd stack-word count needs the
        // alignment pad (`sub rsp, 8`), cleaned up by `add rsp, 16` (1 word + pad).
        let asm = compile_to_asm(
            "To \"f\" with a number called \"a\" and a number called \"b\" and \
             a number called \"c\" and a number called \"d\" and a number called \
             \"e\" and a value called \"v\".\n\
             If v is a text, print \"T\". Otherwise print \"N\".\n\
             \"f\" of 1 and 2 and 3 and 4 and 5 and \"hi\".\n",
        );
        // The value arg pushes a tag word then its payload (2 words for 1 param).
        assert!(
            asm.contains("value param tag word"),
            "a value argument must push a tag word in addition to its payload"
        );
        // 7 words total: 6 register words (popped into rdi..r9) + 1 stack word.
        assert!(
            asm.contains("pop r9") && asm.contains("pop rdi"),
            "the 6 register words must be popped into rdi..r9"
        );
        // Odd stack-word count (1) needs an alignment pad before the call.
        assert!(
            asm.contains("align stack before call"),
            "a 7-word call (1 stack word) must pad the stack before the call"
        );
        // Cleanup releases the 1 stack word + the 8-byte pad = 16 bytes.
        assert!(
            asm.contains("add rsp, 16"),
            "cleanup must release the stack word plus the alignment pad"
        );
    }

    #[test]
    fn append_fresh_mixed_element_keeps_tag() {
        // Plan 3f regression: appending a freshly-produced mixed value (here a
        // value-returning function call, whose tag is left in r11 by the callee)
        // must forward that tag into the list slot, not zero it. Previously the
        // append None-branch did `xor edx, edx`, dropping the tag.
        let asm = compile_to_asm(
            "To \"id\" with a value called \"v\". Return a value, v.\n\
             a list called \"m\" is [1, \"two\"].\n\
             a list called \"out\" is [].\n\
             For each item in m, append \"id\" of item to out.\n",
        );
        // The append forwards the runtime tag from r11 into the slot.
        assert!(
            asm.contains("mov edx, r11d"),
            "appending a value-returning call must forward its tag from r11"
        );
        // The append must not zero the tag for a value-returning source.
        assert!(
            !asm.contains("xor edx, edx"),
            "the value-append must not zero the tag (the 3f latent-bug fix)"
        );
    }

    /// A nested list literal element's slot carries tag 4 (LIST), and a read
    /// of that element from the mixed parent dispatches on the runtime tag
    /// with a tag-4 branch that recurses into `_list_print` (plan 040 §1/§5).
    #[test]
    fn nested_list_literal_tags_slot_4() {
        let asm = compile_to_asm(
            "a list called \"nested\" is [1, [2, 3], \"four\"].\n\
             print element 2 of nested.\n",
        );
        // The nested element is index 1 -> "slot 2"; its slot tag is 4.
        assert!(
            asm.contains("4  ; slot 2 type tag"),
            "a nested list literal element's slot must carry tag 4 (LIST)"
        );
        // Reading element 2 of a mixed list uses the runtime-tag dispatch.
        assert!(
            asm.contains("mixp_"),
            "a mixed-list element read must use the mixed print dispatch"
        );
        assert!(
            asm.contains("cmp r11, 4"),
            "the mixed dispatch must branch on tag 4 (LIST)"
        );
        assert!(
            asm.contains("call _list_print"),
            "the tag-4 branch must recurse into _list_print"
        );
    }

    /// A homogeneous list-of-lists literal `[[1,2],[3,4]]` does NOT widen to
    /// mixed (all elements are tag 4), and a for-each loop var over it is
    /// typed `List` and prints via `_list_print`, not `PRINT_INT` (plan 040 §3).
    #[test]
    fn homogeneous_list_of_lists_not_mixed() {
        let asm = compile_to_asm(
            "a list called \"lol\" is [[1, 2], [3, 4]].\n\
             for each row in lol, print row.\n",
        );
        assert!(
            !asm.contains("mixp_"),
            "a homogeneous list-of-lists must not widen to mixed"
        );
        assert!(
            asm.contains("call _list_print"),
            "a list-typed for-each loop var must print via _list_print"
        );
    }

    /// `is a list` compiles to a runtime `cmp r11, 4` on a mixed element,
    /// and folds statically on a statically-typed list variable (plan 040
    /// §1/§6). In condition context a statically-true predicate falls through
    /// and a statically-false one jumps to the else branch with a comment
    /// naming the folded tag, so the false case is the observable evidence.
    #[test]
    fn is_a_list_predicate_compiles_to_cmp_4() {
        // Runtime path: a mixed-list element read leaves its tag in r11.
        let asm = compile_to_asm(
            "a list called \"m\" is [1, [2, 3], \"x\"].\n\
             if element 2 of m is a list, print \"L\".\n",
        );
        assert!(
            asm.contains("cmp r11, 4"),
            "`is a list` on a mixed element must compare the runtime tag to 4"
        );

        // Static fold: a declared list variable provably carries tag 4, so
        // `is a number` (tag 0) is statically false and jumps to the else
        // branch with a comment naming the folded static tag.
        let asm = compile_to_asm(
            "a list called \"xs\" is [1, 2, 3].\n\
             if xs is a number\n\
               print \"yes\"\n\
             otherwise\n\
               print \"no\".\n",
        );
        assert!(
            asm.contains("is a number statically false (static tag 4)"),
            "a static list (tag 4) must fold `is a number` to false"
        );
        assert!(
            !asm.contains("cmp r11, 4"),
            "a static list must not emit a runtime tag compare"
        );
    }

    /// Appending a list-typed value forwards tag 4 into the slot, not the
    /// integer default (plan 040 §1).
    #[test]
    fn append_list_value_forwards_tag_4() {
        let asm = compile_to_asm(
            "a list called \"inner\" is [9, 8].\n\
             a list called \"outer\" is [].\n\
             append inner to outer.\n",
        );
        assert!(
            asm.contains("mov edx, 4  ; element type tag"),
            "appending a list value must forward tag 4 (LIST)"
        );
        assert!(
            !asm.contains("xor edx, edx"),
            "appending a list value must not fall back to the integer tag"
        );
    }

    /// The recursive `_list_print` runtime has a depth guard (limit 64) that
    /// sets `_last_error` instead of overflowing the stack on a cycle, and a
    /// tag-4 branch that recurses (plan 040 §7). This locks the runtime asm
    /// in at the source level (independent of assembling/linking).
    #[test]
    fn list_print_has_depth_guard() {
        let list_asm = include_str!("../../coreasm/x86_64/list.asm");
        assert!(
            list_asm.contains("%define LIST_TAG_LIST           4"),
            "_list_print must define the LIST tag constant"
        );
        assert!(
            list_asm.contains("cmp qword [rel _print_depth], 64"),
            "_list_print must cap recursion at depth 64 (shared _print_depth, stage 1e2)"
        );
        assert!(
            list_asm.contains("mov qword [rel _last_error], 1"),
            "the depth-guard path must set the error flag"
        );
        assert!(
            list_asm.contains("je .lp_list") && list_asm.contains("call _list_print"),
            "_list_print must recurse on the LIST tag"
        );
    }

    // ---- Stage 1e2: maps (tag 5) ----
    // These lock the map codegen routing in at the compiler level so a
    // regression is caught without assembling/linking (plan 050).

    #[test]
    fn map_literal_emits_map_insert() {
        let asm = compile_to_asm("a map called \"m\" is {\"a\": 1, \"b\": 2}.\n");
        assert!(
            asm.contains("call _map_new"),
            "a map literal must allocate via _map_new"
        );
        // One insert per pair.
        assert_eq!(
            asm.matches("call _map_insert").count(),
            2,
            "expected one _map_insert per pair"
        );
        assert!(
            asm.contains("%include \"coreasm/x86_64/map.asm\""),
            "map usage must include map.asm"
        );
    }

    #[test]
    fn map_literal_empty_emits_map_new() {
        let asm = compile_to_asm("a map called \"m\" is {}.\nprint m.\n");
        assert!(
            asm.contains("call _map_new"),
            "an empty map literal must still allocate via _map_new"
        );
        // No pairs -> no inserts.
        assert_eq!(
            asm.matches("call _map_insert").count(),
            0,
            "an empty map literal must not insert anything"
        );
        assert!(
            asm.contains("call _map_print"),
            "printing a map must route to _map_print"
        );
    }

    #[test]
    fn is_a_map_compiles_to_cmp_5() {
        // Runtime predicate on a value holding a map: the element's tag
        // travels in r11, so `is a map` compiles to `cmp r11, 5`. Mirrors the
        // `is a list` test (170) - iterate a mixed list so each item is a
        // runtime-tagged value.
        let asm = compile_to_asm(
            "for each item in [{\"a\": 1}, 2]\n  if item is a map, print \"M\".\n",
        );
        assert!(
            asm.contains("cmp r11, 5"),
            "`is a map` on a runtime-tagged value must compare against tag 5"
        );
    }

    #[test]
    fn is_a_map_folds_on_static_map() {
        // A statically-typed map variable is known to be a map at compile
        // time, so `is a map` folds to constant true and emits NO runtime
        // `cmp r11, 5` - the taken-branch print runs unconditionally.
        let asm = compile_to_asm(
            "a map called \"m\" is {\"a\": 1}.\nif m is a map, print \"yes\".\n",
        );
        assert!(
            !asm.contains("cmp r11, 5"),
            "`is a map` on a static map variable must fold (no runtime cmp)"
        );
        assert!(
            asm.contains("PRINT_STR") || asm.contains("PRINT_CSTR"),
            "the folded-true branch's print must still be emitted"
        );
    }

    #[test]
    fn map_access_emits_map_lookup_and_sets_r11() {
        let asm = compile_to_asm("a map called \"m\" is {\"a\": 1}.\nprint m's \"a\".\n");
        assert!(
            asm.contains("call _map_lookup"),
            "map key access must call _map_lookup"
        );
        // The looked-up value's tag travels in r11 and is dispatched on.
        assert!(
            asm.contains("cmp r11, 1"),
            "map access print must dispatch on the r11 tag"
        );
    }

    #[test]
    fn map_missing_key_emits_last_error_path() {
        // _map_lookup sets _last_error on a miss; the codegen doesn't need a
        // special path (the runtime owns the flag), but the lookup must be
        // emitted and the error flag must be observable.
        let asm = compile_to_asm(
            "a map called \"m\" is {\"a\": 1}.\nprint m's \"nope\".\non error print \"miss\".\n",
        );
        assert!(asm.contains("call _map_lookup"));
        // The on-error handler reads _last_error.
        assert!(
            asm.contains("_last_error"),
            "the on-error handler must reference _last_error"
        );
    }

    #[test]
    fn map_print_dispatch_tag_5() {
        // Mixed dispatch (used when a map is read into a value slot and
        // printed) must branch on tag 5 to _map_print. A `value` parameter
        // carries the map with its tag in a shadow slot, and `print v`
        // dispatches on it.
        let asm = compile_to_asm(
            "To \"show\" with a value called \"v\".\n  print v.\n\na map called \"m\" is {\"a\": 1}.\n\"show\" of m.\n",
        );
        assert!(
            asm.contains("cmp r11, 5") && asm.contains("call _map_print"),
            "mixed print dispatch must branch on tag 5 to _map_print"
        );
    }

    #[test]
    fn map_asm_has_fnv_constants() {
        let map_asm = include_str!("../../coreasm/x86_64/map.asm");
        assert!(
            map_asm.contains("0xcbf29ce484222325"),
            "map.asm must define the FNV-1a 64-bit offset basis"
        );
        assert!(
            map_asm.contains("0x100000001b3"),
            "map.asm must define the FNV-1a 64-bit prime"
        );
    }

    #[test]
    fn map_print_depth_guard_shared() {
        // The recursion-depth counter was renamed from _list_print_depth to a
        // shared _print_depth so a mixed map/list tree is cycle-safe under
        // one 64-deep budget. Both printers must reference the shared name.
        let list_asm = include_str!("../../coreasm/x86_64/list.asm");
        let map_asm = include_str!("../../coreasm/x86_64/map.asm");
        assert!(
            !list_asm.contains("_list_print_depth"),
            "list.asm must no longer reference the old _list_print_depth"
        );
        assert!(
            list_asm.contains("_print_depth"),
            "list.asm must reference the shared _print_depth"
        );
        assert!(
            map_asm.contains("_print_depth"),
            "map.asm must reference the shared _print_depth"
        );
    }

    #[test]
    fn homogeneous_map_values_dont_widen() {
        // A whole-map print routes straight to _map_print (which reads each
        // entry's stored tag); it must NOT emit the mixp_ dispatch for the
        // whole-map print itself.
        let asm = compile_to_asm("a map called \"m\" is {\"a\": 1, \"b\": 2}.\nprint m.\n");
        assert!(
            asm.contains("call _map_print"),
            "whole-map print must route to _map_print"
        );
        assert!(
            !asm.contains("mixp_"),
            "a homogeneous whole-map print must not emit mixp_ dispatch"
        );
    }

    #[test]
    fn keys_values_sets_uses_lists() {
        // `map's keys`/`values` build a fresh list, so both list.asm and
        // map.asm must be included.
        let asm = compile_to_asm("a map called \"m\" is {\"a\": 1}.\nprint m's keys.\n");
        assert!(
            asm.contains("%include \"coreasm/x86_64/map.asm\""),
            "keys/values must include map.asm"
        );
        assert!(
            asm.contains("%include \"coreasm/x86_64/list.asm\""),
            "keys/values must also include list.asm (they build a list)"
        );
        assert!(
            asm.contains("call _map_keys"),
            "map's keys must call _map_keys"
        );
    }

    // ---- Stage 1e3: nothing/null (tag 6) ----
    // These lock the null feature in at the compiler level, independent of
    // the runtime: the literal threads tag 6 through the tag oracles, the
    // `is nothing` equality routes to a tag-6 compare (NOT the numeric
    // payload compare, so `0 is nothing` is false), the mixed print
    // dispatch has a nothing arm, and the recursive printers carry a
    // nothing label. The `nothing`/`null`/`nil` spellings are reserved.

    #[test]
    fn nothing_lit_emits_tag_6() {
        // A nothing literal inside a mixed list literal threads tag 6 via
        // prescan_expr_tag / emit_time_expr_tag: the element payload is 0
        // (`xor rax, rax`) and its slot tag byte is written as 6.
        let asm = compile_to_asm("a list called \"xs\" is [1, nothing, 2].\n");
        assert!(
            asm.contains("xor rax, rax  ; nothing literal, payload 0"),
            "a nothing literal must emit payload 0 with the nothing-literal comment"
        );
        assert!(
            asm.contains(", 6  ; slot 2 type tag"),
            "the nothing list element's slot must carry tag 6 (TAG_NOTHING)"
        );
    }

    #[test]
    fn is_nothing_emits_tag_compare() {
        // `is nothing` is the equality route. On a runtime-tagged `value`
        // parameter it must compare the loaded tag against 6 — NOT fall
        // through to the numeric `cmp rax, rbx` payload compare (which
        // would make `0 is nothing` true, since a nothing payload is 0).
        let asm = compile_to_asm(
            "To \"check\" with a value called \"v\".\n\
             If v is nothing, print \"y\".\n\
             \"check\" of nothing.\n",
        );
        assert!(
            asm.contains("cmp r11, 6"),
            "`is nothing` on a value must compare the runtime tag against 6"
        );
        assert!(
            !asm.contains("cmp rax, rbx"),
            "`is nothing` must NOT use the numeric payload compare (0 is nothing must be false)"
        );
        // The static fold: `0 is nothing` is statically false (tag 0) and
        // jumps to the else branch with a comment naming the folded tag.
        let asm_fold = compile_to_asm("a number called \"n\" is 0.\nif n is nothing, print \"bug\".\n");
        assert!(
            asm_fold.contains("is not nothing folded (static tag 0)"),
            "a static integer (tag 0) must fold `is nothing` to false"
        );
        assert!(
            !asm_fold.contains("cmp r11, 6"),
            "a statically-folded `is nothing` must not emit a runtime tag compare"
        );
    }

    #[test]
    fn print_dispatch_has_nothing_arm() {
        // Printing a `value` that holds nothing dispatches on the runtime
        // tag and must branch on tag 6 to a nothing arm that prints the
        // `nothing` rodata string (mirrors the map/list dispatch arms).
        let asm = compile_to_asm(
            "To \"show\" with a value called \"v\".\n  print v.\n\n\
             a map called \"m\" is {\"k\": nothing}.\n\"show\" of m's \"k\".\n",
        );
        assert!(
            asm.contains("cmp r11, 6") && asm.contains("mixp_nothing"),
            "mixed print dispatch must branch on tag 6 to a nothing arm"
        );
        // A bare `print nothing.` routes through the explicit NothingLit
        // print arm (a `nothing` rodata string + PRINT_STR), not PRINT_INT.
        let asm_lit = compile_to_asm("print nothing.\n");
        assert!(
            asm_lit.contains("db 'nothing'") || asm_lit.contains("db \"nothing\""),
            "`print nothing.` must materialize a `nothing` rodata string"
        );
        assert!(
            !asm_lit.contains("PRINT_INT"),
            "`print nothing.` must not fall through to PRINT_INT"
        );
    }

    #[test]
    fn list_and_map_print_have_nothing_arms() {
        // The recursive printers must carry a nothing dispatch arm + label
        // so a nothing slot inside a list or map prints as `nothing` (and
        // closes the pre-existing LIST_TAG_MAP gap in list.asm).
        let list_asm = include_str!("../../coreasm/x86_64/list.asm");
        assert!(
            list_asm.contains("%define LIST_TAG_NOTHING        6"),
            "list.asm must define LIST_TAG_NOTHING (6)"
        );
        assert!(
            list_asm.contains("cmp r8, LIST_TAG_NOTHING") && list_asm.contains(".lp_nothing:"),
            "_list_print must dispatch the nothing tag to a .lp_nothing label"
        );
        assert!(
            list_asm.contains("%define LIST_TAG_MAP            5")
                && list_asm.contains(".lp_map:"),
            "_list_print must also carry the map (tag 5) arm closed in 1e3"
        );

        let map_asm = include_str!("../../coreasm/x86_64/map.asm");
        assert!(
            map_asm.contains("%define MAP_TAG_NOTHING        6"),
            "map.asm must define MAP_TAG_NOTHING (6)"
        );
        assert!(
            map_asm.contains("cmp r8, MAP_TAG_NOTHING") && map_asm.contains(".mp_nothing:"),
            "_map_print must dispatch the nothing tag to a .mp_nothing label"
        );
    }

    #[test]
    fn nothing_keyword_reserved() {
        // The three null spellings lex to Token::Nothing and reserve via
        // as_keyword / string_is_keyword; `empty` stays its own keyword
        // (the size-emptiness property), so the split is clean.
        use crate::lexer::{Lexer, Token};
        let toks: Vec<Token> = Lexer::new("nothing null nil empty")
            .tokenize()
            .into_iter()
            .map(|ti| ti.token)
            .filter(|t| !matches!(t, Token::EOF))
            .collect();
        assert_eq!(toks.len(), 4, "the four words must each produce one token");
        assert!(toks.iter().all(|t| matches!(t, Token::Nothing | Token::Empty)),
            "nothing/null/nil -> Token::Nothing; empty -> Token::Empty");
        assert_eq!(toks[0], Token::Nothing);
        assert_eq!(toks[1], Token::Nothing);
        assert_eq!(toks[2], Token::Nothing);
        assert_eq!(toks[3], Token::Empty);
        // as_keyword reserves the word (drives check_not_keyword).
        assert_eq!(Token::Nothing.as_keyword(), Some("nothing"));
        assert_eq!(Token::Empty.as_keyword(), Some("empty"));
        // string_is_keyword catches the quoted-name form too.
        assert_eq!(Token::string_is_keyword("nothing"), Some("nothing"));
        assert_eq!(Token::string_is_keyword("null"), Some("nothing"));
        assert_eq!(Token::string_is_keyword("nil"), Some("nothing"));
        assert_eq!(Token::string_is_keyword("empty"), Some("empty"));

        // Using `nothing` as a variable name is rejected at parse time
        // (both the bare and quoted forms), proving the word is reserved.
        use crate::parser::Parser;
        fn parse_snippet(src: &str) -> Result<(), String> {
            let toks = Lexer::new(src).tokenize();
            match Parser::new(toks).parse() {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        let bare = parse_snippet("a number called nothing is 1.");
        assert!(bare.is_err(), "bare `nothing` as a name must be rejected");
        assert!(
            bare.unwrap_err().to_lowercase().contains("reserved"),
            "the error must call `nothing` a reserved keyword"
        );
        let quoted = parse_snippet("a number called \"nothing\" is 1.");
        assert!(quoted.is_err(), "quoted \"nothing\" as a name must be rejected");
        assert!(
            quoted.unwrap_err().to_lowercase().contains("reserved"),
            "the quoted-form error must call `nothing` a reserved keyword"
        );
    }
}
