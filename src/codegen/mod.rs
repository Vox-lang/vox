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
    // Shared `.rodata` label for the empty string, lazily created and reused
    // by every uninitialised `text` declaration in the program - an empty
    // string is immutable, so there is no reason to allocate one per
    // declaration the way a fresh string literal would.
    empty_string_label: Option<String>,
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
    // for (e.g. `a text called s is element 3 of <mixed list>.`). Their
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
    // Per-function partitions of `mixed_lists`/`unprovable_scalars`, keyed by
    // the function's assembly label. The pre-scan walks each function body on
    // a SNAPSHOT of the global env so a function's own locals never leak into
    // the shared sets (and thence into another function's codegen or the
    // top-level). Two functions can declare a local with the SAME name but
    // opposite verdicts — a proven map in one, an unprovable value in the
    // other — and a flat global set cannot hold both, so each function's
    // locals are stored separately and applied only while that function is
    // being generated. `local_names` is the full set of names local to each
    // function (params + body VarDecls); codegen removes them from the outer
    // sets first so a local shadowing a global takes its own verdict.
    local_mixed_lists: HashMap<String, std::collections::HashSet<String>>,
    local_unprovable_scalars: HashMap<String, std::collections::HashSet<String>>,
    local_names: HashMap<String, std::collections::HashSet<String>>,
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
    // `Library name version "x.y".` declaration. In shared library mode
    // this prefixes every exported label (and every intra-library call) as
    // `<lib>_<ver>_<func>` so two libraries linked into one .so can both
    // define `greet` without a duplicate-label collision. `None` outside
    // shared mode (and in shared mode only transiently, before the
    // declaration is seen — `collect_library_identity` runs a pre-pass so
    // the order of `Library` vs `To` in the source does not matter).
    current_library: Option<(String, String)>,
    // Stage A4: functions imported by `see '<lib>' version "<ver>" from
    // "...lib".`, resolved and .dynsym-verified by the driver. A call to an
    // imported name targets the import's mangled `<lib>_<ver>_<func>` symbol
    // and the link line gets the `.so` + an rpath. Local definitions shadow
    // imports (the analyzer warns), so a call always prefers the locally
    // defined label. Ambiguity between imports is an analyzer error, so at
    // most one import claimant reaches codegen per authored name.
    imports: Vec<crate::lib_file::ImportedFunction>,
    import_labels: HashMap<String, String>,
    imported_symbols: Vec<String>,
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
    // The full declared return `Type` of each user/imported function, keyed
    // the same way as `function_return_types` (which only keeps the coarse
    // `VarType`). Needed so a `VarDecl` initialized from a call to a `.lib`
    // function returning `list of <type>` can recover the element type and
    // seed `list_element_types` for the declared variable (plan 296 -
    // element typing crossing the `.lib` boundary in return position).
    function_return_full_types: std::collections::HashMap<String, Type>,
    // Return type of the function currently being codegen'd (None at top
    // level). When it is `Type::Value`, the `Return` path must leave the
    // value's runtime tag in r11 for the caller to consume.
    current_function_return_type: Option<Type>,
    loop_stack: Vec<(String, String)>, // (continue_label, break_label)
    flag_schemas: Vec<FlagSchemaRuntime>,
    parsed_args_active: bool,
    global_var_labels: HashMap<String, String>,
    global_var_counter: usize,
    // BSS label holding the runtime type tag byte for a top-level `value`
    // global, keyed by the variable's author-facing name. A top-level
    // `value` needs the SAME pairing discipline as a local one (payload and
    // tag always updated together, see `mixed_tag_slots`) but must be
    // reachable from every function, not just the frame that declared it -
    // so both halves live in BSS instead of one frame's stack. Lazily
    // populated by `ensure_global_value_tag_label`, mirroring how
    // `global_var_labels` mirrors the payload. `mixed_element_tag_slot`
    // checks `mixed_tag_slots` (local) first and falls back here, so a
    // function-local `value` of the same name still shadows correctly.
    global_value_tag_labels: HashMap<String, String>,
    // Declared type of each user variable, populated from VarDecl, function
    // parameters, `open ... called`, and `start a timer called`. Used by the
    // `type` property to choose between a static literal and runtime tag
    // dispatch (a `value` is the only dynamic case).
    declared_types: HashMap<String, Type>,
    // Top-level global variables whose BSS mirror has already received an
    // initial value (allocated buffer, list, map, etc.). For buffer targets
    // this avoids clearing/appending into a null pointer on redeclaration or
    // assignment; for other types the initial `generate_expr` already produces
    // a valid pointer/value.
    initialized_globals: std::collections::HashSet<String>,
    in_function_codegen: bool,
    target_arch: String,
}


#[derive(Clone, PartialEq)]
pub(crate) enum VarType {
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

/// Storage target selected for a variable declaration or assignment.
/// `Local` keeps a per-frame stack slot; `Global` uses the BSS mirror so
/// top-level code and every function share the same location.
pub(crate) enum VarTarget {
    Local(i64),
    Global(String),
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

// Header data offsets. These are numerically equal today (all three headers
// are 24 bytes), but each names a distinct struct so the offsets do not silently
// diverge when one header gains a field.
const BUF_DATA_OFFSET: i64 = 24;
const LIST_DATA_OFFSET: i64 = 24;
#[allow(dead_code)]
const MAP_HEADER_SIZE: i64 = 24;

mod mangling;
pub(crate) use mangling::{mangle_symbol, mangle_library_symbol, make_function_label, format_lib_name};
mod lib_output;
pub use lib_output::{LibFunction, LibBlock, render_lib_file};
use lib_output::{collect_lib_function_return_types, infer_list_element_type, infer_return_list_element_type, list_element_vartype, type_noun_name};
mod flags;
use flags::FlagSchemaRuntime;
mod syscalls;
mod buffers;
mod format;
mod vars;
mod functions;
mod tags;
use tags::type_to_tag;
mod collections;
mod print;

// ---- Stage A3: the `.lib` interface file emitted beside each `.so` ----
//
// A `--shared` build writes `<output-stem>.lib` beside the `.so`: one `Library`
// block per input, a `Location` relative to the `.lib`, and a `Table of
// Contents` of every exported signature. Stage A4 parses this back to type-check
// `see` calls, so the format is a contract: emit what the source declares, one
// entry per line (never wrapped), parameters joined with ` and ` exactly as Vox
// source joins them, and a `value` parameter/return rendered by its type name
// alone (the `value` ABI is fixed, so nothing about it is per-function).





// ---------------------------------------------------------------------------
// Stage A3: inferring a `.lib`-exported list's element type
// ---------------------------------------------------------------------------
//
// Vox source has no typed-list declaration syntax (plan 296 confirmed this
// by inspection: every `Token::List` match in the parser hard-codes
// `Type::List(Box::new(Type::Unknown))`) — the language's own design
// principle is that the author picks the data and the compiler picks the
// representation, so element type is inferred from how a list is built
// (first append/literal), never declared. These functions apply that same
// "infer, don't declare" rule specifically to a `.lib`-exported function's
// OWN list parameters and list return, so the `.lib` can record a real
// element type without any new Vox source syntax: the library author writes
// nothing new, and an ordinary (non-exported) function's lists are
// completely unaffected (only `collect_function_signatures`'s `LibFunction`
// construction calls these — never `function_param_types` /
// `function_return_types`, which drive this compilation unit's own codegen).
//
// This is a narrow, single-pass, non-flow-sensitive scan — deliberately NOT
// the existing fixed-point `prescan_mixed_lists` machinery, which already
// walks every function body but never seeds a function's own parameters
// into its environment (so `Append s to out` with `s` a text parameter is
// invisible to it; a separate, out-of-scope bug, see plan 296). Reusing or
// extending that whole-program pre-scan here would carry its blast radius
// into a change meant to touch only `.lib` emission. Any expression this
// scan can't classify (a call result, an element read, disagreement between
// two sites) makes it give up and report `Unknown` — the safe fallback that
// exactly matches today's behavior (no annotation), never a wrong guess.














/// Three-state result of statically classifying an expression into a list
/// slot tag for the pre-scan. `Known(tag)` is a proof: the value's type is
/// certain. `Unknowable` means no static proof is possible — stage 1b widens
/// the list to `Mixed` rather than optimistically guessing a type ("static is
/// a proof; mixed is the default").
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagInfo {
    Known(u8),
    Unknowable,
}



/// Where a value's runtime type tag lives once the value has been emitted.
/// See `CodeGenerator::runtime_tag_source`.
pub(crate) enum RuntimeTagSource {
    /// A mixed-list read left the slot's tag byte in r11. Must be consumed
    /// immediately - any call or syscall clobbers r11.
    R11,
    /// A Mixed variable's tag, at this rbp offset.
    ShadowSlot(i64),
    /// A top-level `value` global's tag, in this BSS label.
    ShadowSlotGlobal(String),
}


/// Where a Mixed variable's shadow tag slot lives: a local stack offset
/// (function locals, params, for-each variables, and a function-local
/// `value`), or a BSS label (a top-level `value` global). See
/// `CodeGenerator::mixed_element_tag_slot`.
pub(crate) enum ShadowTagLoc {
    Local(i64),
    Global(String),
}


/// Author-facing display name for the `type` property on a statically-
/// typed variable. `value` is dynamic and handled separately.
fn type_property_display_name(t: &Type) -> Option<&'static str> {
    match t {
        Type::Integer => Some("Number"),
        Type::Float => Some("Float"),
        Type::String => Some("Text"),
        Type::Boolean => Some("Boolean"),
        Type::List(_) => Some("List"),
        Type::Map(_) => Some("Map"),
        Type::Buffer => Some("Buffer"),
        Type::File => Some("File"),
        Type::Time => Some("Time"),
        Type::Timer => Some("Timer"),
        _ => None,
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
pub(crate) struct FormatSpec {
    width: Option<i32>,
    zero_pad: bool,
    base: IntegerBase,
    precision: Option<i32>,
}

/// Outcome of resolve_format_variable - how a `{name}` format part's value
/// was resolved, so each sink (print / buffer append) can render it.
pub(crate) enum FormatPartValue {
    /// Code was emitted leaving the value (or pointer) in rax; the VarType
    /// tells the sink how to render it (None = integer-ish fallback).
    Loaded(Option<VarType>),
    /// The part resolved to a compile-time string constant.
    Literal(String),
    /// Unknown name - sinks render the `{name}` placeholder literally.
    Unknown,
}

#[cfg(test)]
mod tests;

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
            empty_string_label: None,
            variables: HashMap::new(),
            variable_types: HashMap::new(),
            global_constants: HashMap::new(),
            list_element_types: HashMap::new(),
            mixed_lists: std::collections::HashSet::new(),
            unprovable_scalars: std::collections::HashSet::new(),
            mixed_tag_slots: HashMap::new(),
            file_writable: HashMap::new(),
            local_mixed_lists: HashMap::new(),
            local_unprovable_scalars: HashMap::new(),
            local_names: HashMap::new(),
            stack_offset: 0,
            shared_lib_mode: false,
            exported_functions: Vec::new(),
            library_blocks: Vec::new(),
            current_library: None,
            imports: Vec::new(),
            import_labels: HashMap::new(),
            imported_symbols: Vec::new(),
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
            function_return_full_types: std::collections::HashMap::new(),
            current_function_return_type: None,
            loop_stack: Vec::new(),
            flag_schemas: Vec::new(),
            parsed_args_active: false,
            global_var_labels: HashMap::new(),
            global_var_counter: 0,
            global_value_tag_labels: HashMap::new(),
            declared_types: HashMap::new(),
            initialized_globals: std::collections::HashSet::new(),
            in_function_codegen: false,
            target_arch: "x86_64".to_string(),
        }
    }































    
    fn new_label(&mut self, prefix: &str) -> String {
        let label = format!(".{}_{}", prefix, self.label_counter);
        self.label_counter += 1;
        label
    }
    


    
    





    fn is_float_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::FloatLit(_) => true,
            // A string literal is text, unconditionally - never resolved
            // against a same-spelled variable's type (BUGS_FOUND #19).
            Expr::StringLit(_) => false,
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
            Expr::FunctionCall { name, .. } => {
                self.function_return_types.get(&self.resolved_call_label(name))
                    == Some(&VarType::Float)
            }
            _ => false,
        }
    }

    fn is_buffer_expr(&self, expr: &Expr) -> bool {
        match expr {
            // A string literal is text, unconditionally - never resolved
            // against a same-spelled variable's type (BUGS_FOUND #19).
            Expr::StringLit(_) => false,
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
            // A string literal is text, unconditionally - never resolved
            // against a same-spelled variable's type (BUGS_FOUND #19).
            Expr::StringLit(_) => false,
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
        if let Some(operand) = src.shadow_operand() {
            self.emit_indent(&format!(
                "movzx r11, byte {}  ; operand tag (shadow slot)", operand
            ));
        }
        let ok = self.new_label("arith_not_nothing");
        self.emit_indent(&format!("cmp r11, {}  ; nothing operand?", TAG_NOTHING));
        self.emit_indent(&format!("jne {}", ok));
        self.emit_indent("mov qword [rel _last_error], 1  ; nothing in arithmetic");
        self.emit(&format!("{}:", ok));
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

        // Stage A4: one NASM extern per imported symbol. These are the
        // mangled <lib>_<ver>_<func> names resolve_see_import verified
        // against the .so's .dynsym; the .so itself is on the link line
        // (`main` adds it plus an rpath). No `see`, no imports, no lines —
        // non-importing builds are byte-identical.
        if !self.imported_symbols.is_empty() {
            for sym in &self.imported_symbols {
                result.push_str(&format!("extern {}\n", sym));
            }
            result.push('\n');
        }

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
                // Decide whether this statement updates a local stack slot or
                // the global BSS mirror.  A typed declaration (`a number called
                // x is ...`) always gets a local slot so it can shadow a
                // top-level variable of the same name.  A bare assignment
                // (`Set x to ...` / `the x is ...`) with no local in scope
                // writes the global BSS mirror directly, matching the read
                // path's local-then-global resolution.
                let had_existing_slot = self.variables.contains_key(name);
                let target = if had_existing_slot {
                    // A local slot already exists (branch-declared name, loop
                    // variable, function parameter, or local shadow).
                    VarTarget::Local(self.get_var(name).unwrap())
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    // The name has a BSS mirror.  Use it for:
                    //   - bare assignments (`Set x to ...`, `the x is ...`)
                    //   - top-level typed declarations, `value` included (so
                    //     top-level code and functions share one storage; see
                    //     `global_value_tag_labels` for how a `value`'s tag
                    //     half stays paired with this payload half)
                    // Typed declarations inside a function still allocate a
                    // local slot to shadow the global. A `value` declared
                    // inside a function is included here too (`var_type` is
                    // `Some(Type::Value)`), so its runtime tag slot stays
                    // paired with the payload in the SAME frame
                    // (docs/BUGS_FOUND.md #4's local/shadowing case).
                    if var_type.is_some() && self.in_function_codegen {
                        self.stack_offset += 8;
                        self.variables.insert(name.clone(), self.stack_offset);
                        VarTarget::Local(self.stack_offset)
                    } else {
                        VarTarget::Global(label)
                    }
                } else {
                    // No global mirror (e.g. a branch-only declaration): local.
                    self.stack_offset += 8;
                    self.variables.insert(name.clone(), self.stack_offset);
                    VarTarget::Local(self.stack_offset)
                };
                let is_fresh_local = matches!(target, VarTarget::Local(_)) && !had_existing_slot;

                // Track variable type from declaration
                if let Some(ref t) = var_type {
                    self.declared_types.insert(name.clone(), t.clone());
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
                    if matches!(t, Type::Value) {
                        if matches!(target, VarTarget::Global(_)) {
                            // Top-level `value`: tag lives in BSS, paired with
                            // the payload's own global mirror.
                            self.ensure_global_value_tag_label(name);
                        } else if !self.mixed_tag_slots.contains_key(name) {
                            let tag_slot = self.alloc_var(&format!("{}_mixtag", name));
                            self.mixed_tag_slots.insert(name.clone(), tag_slot);
                        }
                    }
                }
                
                if let Some(val) = value {
                    // A declared `value` (Mixed) carries its runtime type in a
                    // shadow tag slot (local) or BSS tag byte (global), dispatched
                    // on at every read. Demoting it to a concrete type from the
                    // initializer's static shape would make later reads ignore the
                    // tag and dispatch on the static type instead — the
                    // tag/payload desync of BUGS_FOUND #15: a `value` holding 3.5
                    // reassigned to 1 printed 0.0 because `Print` emitted
                    // PRINT_FLOAT from the clobbered static type while the tag (and
                    // payload) said integer. The bare-assignment arm already skips
                    // this for value locals via `is_value_local`; this is the same
                    // guard for the declare and `Set x to` / `the x is` spellings,
                    // which also route through VarDecl.
                    let is_value_var = matches!(var_type, Some(Type::Value))
                        || self.variable_types.get(name) == Some(&VarType::Mixed)
                        || self.mixed_tag_slots.contains_key(name)
                        || self.global_value_tag_labels.contains_key(name);
                    // Track list type and element type for lists
                    if !is_value_var {
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
                    // A call to a `.lib` function declared `returning a
                    // list of <type>` carries a real element type (plan
                    // 296) — the symmetric case to `emit_function_call`'s
                    // parameter-side propagation above. Covers BOTH call
                    // shapes: an explicit `of`/`with` argument list
                    // (`Expr::FunctionCall`) and a bare zero-argument call
                    // (`Expr::Identifier`, see `call_label_for_list_return`).
                    // A call to anything else (a local function, an
                    // unannotated `.lib` return, a runtime helper) resolves
                    // to `Type::List(Unknown)` here, so this is a no-op for
                    // it, exactly today's behavior.
                    else if let Some(label) = self.call_label_for_list_return(val) {
                        if let Some(Type::List(inner)) = self.function_return_full_types.get(&label) {
                            if !matches!(**inner, Type::Unknown) {
                                self.list_element_types
                                    .insert(name.clone(), list_element_vartype(inner));
                            }
                        }
                    }
                    // Initializing from another variable: inherit its type
                    // (and element type, for lists) unless the declaration
                    // already pinned one. Without this, `a list called b
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
                                // A `value` (Mixed) source carries a runtime-tagged
                                // payload whose bits/pointer are reinterpreted as the
                                // destination's declared type, so it must NOT overwrite
                                // a concrete-typed declaration: `a list called xs is
                                // item.` with item: value would otherwise demote xs to
                                // Mixed, making `{xs}` print the raw pointer and
                                // `xs's length` route to the file fallback (-1). Only
                                // inherit the source's type when the destination has no
                                // concrete type of its own. The declare-with-initializer
                                // paths for float/map never enter this branch, which is
                                // why only the `list` arm was broken. Sibling of the
                                // v0.3.5 fix (COMPILER-ISSUES #5).
                                let dst_concrete = matches!(
                                    self.variable_types.get(name),
                                    Some(VarType::Integer | VarType::Float | VarType::String
                                        | VarType::Buffer | VarType::List | VarType::Map
                                        | VarType::Boolean)
                                );
                                if vt != VarType::Mixed || !dst_concrete {
                                    self.variable_types.insert(name.clone(), vt);
                                }
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
                                    if matches!(
                                        property,
                                        ObjectProperty::First
                                            | ObjectProperty::Last
                                            | ObjectProperty::Keys
                                            | ObjectProperty::Values
                                    )
                            );
                        if matches!(var_type, Some(Type::List(_))) && reads_element {
                            let elem_type =
                                if matches!(
                                    val,
                                    Expr::PropertyAccess { property: ObjectProperty::Keys, .. }
                                ) {
                                    // `map's keys` always yields text pointers.
                                    VarType::String
                                } else {
                                    // `first`/`last`/`values` and element reads
                                    // carry runtime tags per slot.
                                    VarType::Mixed
                                };
                            self.list_element_types.insert(name.clone(), elem_type);
                        }
                    }
                    } // end `if !is_value_var` — a `value` keeps Mixed

                    // Special handling for buffer initialization/assignment with text/format/buffer source
                    let is_buffer_target = matches!(var_type, Some(Type::Buffer))
                        || self.variable_types.get(name) == Some(&VarType::Buffer);
                    if is_buffer_target {
                        if matches!(val, Expr::FunctionCall { .. }) {
                            // Buffer declarations initialized from function calls should take
                            // the returned buffer pointer directly (rax), not format-append it.
                            self.generate_expr(val);
                            self.uses_buffers = true;
                            self.emit_store_rax_to_target(
                                &target, &format!("buffer {}", name));
                            if target.global_label().is_some() {
                                self.initialized_globals.insert(name.clone());
                            }
                        } else {
                            let is_fresh_global_buffer = target.global_label().is_some()
                                && !self.initialized_globals.contains(name);
                            if is_fresh_local || is_fresh_global_buffer {
                                self.emit_indent("mov rdi, 1024  ; default buffer size");
                                self.emit_indent("call _alloc_buffer");
                                self.emit_store_rax_to_target(
                                    &target, &format!("buffer {}", name));
                                self.uses_buffers = true;
                                if is_fresh_global_buffer {
                                    self.initialized_globals.insert(name.clone());
                                }
                            }

                            if !self.emit_copy_expr_into_buffer_slot(
                                val,
                                true,
                                target.local_offset(),
                                target.global_label(),
                            ) {
                                // Clear before materializing the value: _buffer_clear
                                // returns the (possibly reallocated) buffer pointer in
                                // rax and would clobber a value loaded first.
                                self.emit_clear_buffer_target(&target);
                                self.generate_expr(val);
                                let fmt_spec = self.parse_format_spec(None);
                                self.emit_append_runtime_value_to_buffer_target(
                                    &target,
                                    self.infer_expr_type(val),
                                    fmt_spec,
                                );
                            }
                        }
                    } else {
                        self.generate_expr(val);
                        self.emit_store_rax_to_target(&target, &format!("{}", name));
                        // A declared `value` stores its runtime tag alongside
                        // the payload, in whichever storage (local shadow
                        // slot or global BSS mirror) the payload itself used.
                        if let Some(&tag_slot) = self.mixed_tag_slots.get(name) {
                            if target.local_offset().is_some() {
                                self.emit_load_value_tag(val);
                                self.emit_indent(&format!(
                                    "mov [rbp-{}], r11b  ; value local tag",
                                    tag_slot
                                ));
                            }
                        } else if let Some(tag_label) =
                            self.global_value_tag_labels.get(name).cloned()
                        {
                            self.emit_load_value_tag(val);
                            self.emit_indent(&format!(
                                "mov [rel {}], r11b  ; value global tag",
                                tag_label
                            ));
                        }
                    }
                } else {
                    // No initial value - initialize based on type.
                    if let Some(ref t) = var_type {
                        match t {
                            Type::Buffer => {
                                // Allocate an empty buffer with proper initialization
                                self.emit_indent("mov rdi, 1024  ; default buffer size");
                                self.emit_indent("call _alloc_buffer");
                                self.emit_store_rax_to_target(
                                    &target, &format!("buffer {}", name));
                                self.uses_buffers = true;
                                if target.global_label().is_some() {
                                    self.initialized_globals.insert(name.clone());
                                }
                            }
                            Type::List(_) => {
                                // Allocate an empty list; a null pointer here
                                // would make the first append dereference 0.
                                self.generate_expr(&Expr::ListLit { elements: vec![] });
                                self.emit_store_rax_to_target(
                                    &target, &format!("list {}", name));
                            }
                            Type::Map(_) => {
                                // Allocate an empty map so printing yields "{}"
                                // instead of dereferencing a null pointer.
                                self.generate_expr(&Expr::MapLit { pairs: vec![] });
                                self.emit_store_rax_to_target(
                                    &target, &format!("map {}", name));
                            }
                            Type::Float => {
                                self.generate_expr(&Expr::FloatLit(0.0));
                                self.emit_store_rax_to_target(
                                    &target, &format!("float {}", name));
                            }
                            Type::String => {
                                // A null pointer here makes the first read
                                // (print, interpolation, 's length, ...)
                                // dereference 0. Point at a real, shared
                                // empty string instead.
                                let label = self.get_empty_string_label();
                                self.emit_indent(&format!(
                                    "lea rax, [rel {}]  ; empty text default", label));
                                self.emit_store_rax_to_target(
                                    &target, &format!("text {}", name));
                                self.uses_strings = true;
                            }
                            Type::Value => {
                                // An uninitialized `value` holds `nothing`, not
                                // the number 0.  The payload is zero; the tag
                                // must be TAG_NOTHING.
                                self.emit_indent("mov rax, 0  ; nothing payload");
                                self.emit_store_rax_to_target(
                                    &target, &format!("value {}", name));
                                if let Some(&tag_slot) = self.mixed_tag_slots.get(name) {
                                    if target.local_offset().is_some() {
                                        self.emit_indent(&format!(
                                            "mov byte [rbp-{}], {}  ; value local tag = nothing",
                                            tag_slot, TAG_NOTHING
                                        ));
                                    }
                                } else if let Some(tag_label) =
                                    self.global_value_tag_labels.get(name).cloned()
                                {
                                    self.emit_indent(&format!(
                                        "mov byte [rel {}], {}  ; value global tag = nothing",
                                        tag_label, TAG_NOTHING
                                    ));
                                }
                            }
                            _ => {
                                // Initialize to 0/null
                                self.emit_indent("xor rax, rax");
                                self.emit_store_rax_to_target(
                                    &target, &format!("{}", name));
                            }
                        }
                    } else {
                        // No type info - initialize to 0
                        self.emit_indent("xor rax, rax");
                        self.emit_store_rax_to_target(
                            &target, &format!("{}", name));
                    }
                }

                if let Some(offset) = target.local_offset() {
                    self.emit_mirror_stack_var_to_global_if_needed(name, offset);
                }
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
                    // A `value` local (declared `a value called r`) keeps its
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
                                | VarType::Map => {
                                    self.variable_types.insert(name.clone(), vt);
                                }
                                // A `value` (Mixed) source carries a runtime-tagged
                                // payload whose bits/pointer are reinterpreted as the
                                // destination's existing type, so it must NOT demote a
                                // concrete-typed local: `the y is vf.` / `Set y to vf.`
                                // with y: float would otherwise print the raw IEEE bits
                                // (4615063718147915776) instead of 3.5. The destination
                                // keeps its declared type, exactly as the
                                // declare-with-initializer path does. The value-local
                                // reassignment case is already skipped via
                                // `is_value_local` above. Sibling of the v0.3.5 fix
                                // (COMPILER-ISSUES #5), which covered value->value tag
                                // retention but missed value->concrete extraction.
                                VarType::Buffer | VarType::Unknown | VarType::Mixed => {}
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
                    if self.variable_types.get(name) == Some(&VarType::Buffer) {
                        // Reassigning an existing global buffer: copy/append the
                        // source into the buffer, preserving the allocated struct,
                        // rather than storing a raw string pointer over it.
                        if !self.emit_copy_expr_into_buffer_slot(
                            value,
                            true,
                            None,
                            Some(&label),
                        ) {
                            let target = VarTarget::Global(label);
                            self.emit_clear_buffer_target(&target);
                            self.generate_expr(value);
                            let fmt_spec = self.parse_format_spec(None);
                            self.emit_append_runtime_value_to_buffer_target(
                                &target,
                                self.infer_expr_type(value),
                                fmt_spec,
                            );
                        }
                    } else {
                        self.generate_expr(value);
                        self.emit_indent(
                            &format!("mov [rel {}], rax", label));
                        // A top-level `value` keeps its runtime tag paired
                        // with the payload in a parallel BSS byte, updated on
                        // every assignment exactly like the local `value`
                        // case above — including a reassignment from inside a
                        // function, which is the whole point of routing a
                        // `value` global through BSS instead of a stack slot.
                        if self.variable_types.get(name) == Some(&VarType::Mixed) {
                            let tag_label = self.ensure_global_value_tag_label(name);
                            self.emit_load_value_tag(value);
                            self.emit_indent(&format!(
                                "mov [rel {}], r11b  ; value global tag",
                                tag_label
                            ));
                        }
                    }
                } else {
                    self.generate_expr(value);
                    let offset = self.alloc_var(name);
                    self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                }
            }

            Statement::ValueRetype { name, target_type } => {
                self.emit_value_retype(name, target_type);
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
            
            Statement::Return { value, .. } => {
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
                // `variable_types`/`mixed_tag_slots` are a flat, unscoped
                // namespace (unlike `self.variables`, which resets to empty
                // per function): a function body still needs to resolve the
                // type of an already-declared global by name, so it cannot
                // start empty. Clone-and-restore instead, so this function's
                // OWN params/locals (registered into these maps below and
                // during body codegen) are visible while generating its body
                // but do not leak into whatever is generated after it. Before
                // this, a parameter name from one function (e.g. `aa`) stayed
                // in `variable_types` forever, so a later, unrelated string
                // literal that happened to equal that name (e.g. `"aa"` in a
                // call argument) inherited the stale parameter's type instead
                // of being read as literal text — see
                // tests/203_value_param_word_boundary.vox and
                // `emit_time_expr_tag`'s `Expr::StringLit` handling, which
                // trusts `variable_types` by name with no scope check.
                let saved_variable_types = self.variable_types.clone();
                let saved_declared_types = self.declared_types.clone();
                let saved_mixed_tag_slots = self.mixed_tag_slots.clone();
                // `mixed_lists`/`unprovable_scalars` are a flat, unscoped set
                // just like `variable_types`, so they need the same
                // clone-and-restore isolation: a function's own locals must not
                // leak into whatever is generated after it. The pre-scan
                // already partitioned each function's locals into
                // `local_*`/`local_names` keyed by `func_label`; apply this
                // function's partition on top of the outer (global) state, first
                // dropping any names this function redeclares as locals so a
                // local shadowing a global takes its own verdict. `list_element_types`
                // and `file_writable` are maps overwritten per-VarDecl during
                // body codegen, so a plain save/restore is enough for them.
                let saved_mixed_lists = self.mixed_lists.clone();
                let saved_unprovable_scalars = self.unprovable_scalars.clone();
                let saved_list_element_types = self.list_element_types.clone();
                let saved_file_writable = self.file_writable.clone();
                if let Some(locals) = self.local_names.get(&func_label).cloned() {
                    for n in &locals {
                        self.mixed_lists.remove(n);
                        self.unprovable_scalars.remove(n);
                    }
                    if let Some(loc) = self.local_mixed_lists.get(&func_label) {
                        for n in loc {
                            self.mixed_lists.insert(n.clone());
                        }
                    }
                    if let Some(loc) = self.local_unprovable_scalars.get(&func_label) {
                        for n in loc {
                            self.unprovable_scalars.insert(n.clone());
                        }
                    }
                }

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
                    self.declared_types.insert(param_name.clone(), param_type.clone());
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
                let pad_offset: usize = if stack_words % 2 == 0 { 0 } else { 8 };
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
                self.variable_types = saved_variable_types;
                self.declared_types = saved_declared_types;
                self.mixed_tag_slots = saved_mixed_tag_slots;
                self.mixed_lists = saved_mixed_lists;
                self.unprovable_scalars = saved_unprovable_scalars;
                self.list_element_types = saved_list_element_types;
                self.file_writable = saved_file_writable;

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
                    // A list parameter (or any list with no proven element type)
                    // stores a per-slot runtime tag, so widen the loop variable
                    // to Mixed and read the tag each iteration — see
                    // `list_expr_is_mixed`.
                    match self.list_element_types.get(list_name) {
                        None | Some(&VarType::Unknown) => VarType::Mixed,
                        Some(other) => other.clone(),
                    }
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
                    self.emit_indent(&format!(
                        "movzx r11, byte [rbx + r11 + {}]  ; slot type tag",
                        LIST_DATA_OFFSET
                    ));
                    self.emit_indent(&format!("mov [rbp-{}], r11b  ; stash element's type tag", slot));
                }
                self.emit_indent("shl rax, 3  ; index * 8");
                self.emit_indent(&format!(
                    "add rax, {}  ; skip header ({} bytes)",
                    LIST_DATA_OFFSET, LIST_DATA_OFFSET
                ));
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
                self.emit_store_back_after_realloc(buffer, "rax");
                self.emit_indent("pop rcx  ; restore 1-indexed position");
                self.emit_indent(&format!("jmp {}  ; grown buffer now has space", ok_label));

                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent(&format!("jmp {}", done_label));

                // Success path: safe write
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("mov qword [rel _last_error], 0  ; clear error on success");
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
                self.emit_indent(&format!("add rbx, {}  ; skip to buffer data area", BUF_DATA_OFFSET));
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
                self.emit_indent("mov qword [rel _last_error], 0  ; clear error on success");
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
                            "mov byte [rbx + rdx + {0}], {1}  ; slot type tag",
                            LIST_DATA_OFFSET, tag
                        ));
                    }
                    None => {
                        if let Some(loc) = self.mixed_element_tag_slot(value) {
                            self.emit_indent(&format!(
                                "mov al, {}  ; runtime tag of mixed source",
                                loc.operand()
                            ));
                            self.emit_indent(&format!(
                                "mov [rbx + rdx + {}], al  ; slot type tag",
                                LIST_DATA_OFFSET
                            ));
                        } else {
                            self.emit_indent(&format!(
                                "mov byte [rbx + rdx + {}], 0  ; default integer tag",
                                LIST_DATA_OFFSET
                            ));
                        }
                    }
                }
                // Get element size (at offset 16 in list structure)
                self.emit_indent("mov rdx, [rbx + 16]  ; element size");
                // Calculate offset
                self.emit_indent("imul rcx, rdx  ; index * element_size");
                self.emit_indent(&format!(
                    "add rcx, {}  ; data starts at offset {}",
                    LIST_DATA_OFFSET, LIST_DATA_OFFSET
                ));
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
                        if let Some(loc) = self.mixed_element_tag_slot(value) {
                            self.emit_indent(&format!(
                                "movzx ecx, byte {}  ; runtime tag of mixed source",
                                loc.operand()
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
                self.emit_store_back_after_realloc(map, "rax");
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
                                self.emit_indent("push rax  ; save source value across destination address load");
                                self.emit_load_named_var_addr(list);
                                self.emit_indent("mov rdi, rax");
                                self.emit_indent("pop rax  ; restore source value");
                                self.emit_append_runtime_value_to_buffer_ptr(self.infer_expr_type(value), fmt_spec);
                                self.emit_indent(&format!("mov [rel {}], rax", label));
                            }
                        }
                        // Top-level/branch-declared buffers live in both a stack
                        // slot and a BSS mirror. Any append that updated the stack
                        // slot must also update the mirror so functions see the
                        // possibly-reallocated pointer.
                        if let Some(offset) = dst_local {
                            self.emit_mirror_stack_var_to_global_if_needed(list, offset);
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
                            if let Some(loc) = self.mixed_element_tag_slot(value) {
                                self.emit_indent(&format!(
                                    "movzx edx, byte {}  ; runtime tag of mixed source",
                                    loc.operand()
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
                    self.emit_store_back_after_realloc(list, "rax");
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
                    // Mirror any stack-slot update back to the global BSS copy so
                    // functions see the (possibly reallocated) buffer pointer.
                    if let Some(offset) = dst_local {
                        self.emit_mirror_stack_var_to_global_if_needed(destination, offset);
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
                    self.emit_mirror_stack_var_to_global_if_needed(name, offset);
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    self.emit_indent(&format!("mov [rel {}], rax  ; buffer (unchanged pointer)", label));
                }
            }
            
            Statement::FileOpen { name, path, mode } => {
                self.uses_files = true;
                self.declared_types.insert(name.clone(), Type::File);
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
                let source_fd = if source == "stdin" {
                    "0".to_string()  // STDIN
                } else if let Some(offset) = self.get_var(source) {
                    format!("[rbp-{}]", offset)
                } else if let Some(label) = self.global_var_label(source).cloned() {
                    format!("[rel {}]", label)
                } else {
                    "0".to_string()
                };

                let skip_label = self.new_label("skip_fd");
                self.emit_indent(&format!("mov rdi, {}", source_fd));
                // Skip read if fd is invalid (negative)
                self.emit_indent("test rdi, rdi");
                self.emit_indent(&format!("js {}  ; skip if invalid fd", skip_label));
                if self.emit_load_named_var_addr(buffer) {
                    self.emit_indent("mov rsi, rax  ; buffer struct");
                    // Reset buffer length before reading (read replaces, not appends)
                    self.emit_indent("mov qword [rsi + 8], 0  ; reset buffer length");
                    self.emit_indent("call _read_into_buffer  ; auto-grows if needed");
                    // Update buffer pointer (may have changed if grown)
                    self.emit_store_back_after_realloc(buffer, "rsi");
                }
                self.emit(&format!("{}:", skip_label));
            }

            Statement::FileReadLine { source, buffer } => {
                let source_fd = if source == "stdin" {
                    "0".to_string()
                } else if let Some(offset) = self.get_var(source) {
                    format!("[rbp-{}]", offset)
                } else if let Some(label) = self.global_var_label(source).cloned() {
                    format!("[rel {}]", label)
                } else {
                    "0".to_string()
                };

                let skip_label = self.new_label("skip_fd");
                let done_label = self.new_label("readline_done");
                self.emit_indent(&format!("mov rdi, {}", source_fd));
                self.emit_indent("test rdi, rdi");
                self.emit_indent(&format!("js {}  ; skip if invalid fd", skip_label));
                if self.emit_load_named_var_addr(buffer) {
                    self.emit_indent("mov rsi, rax  ; buffer struct");
                    self.emit_indent("mov qword [rsi + 8], 0  ; reset buffer length");
                    self.emit_indent("call _read_line_into_buffer");
                    // _read_line_into_buffer already sets _last_error (1=EOF, 2=read error)
                    // Update buffer pointer (may have changed if grown)
                    self.emit_store_back_after_realloc(buffer, "rsi");
                }
                self.emit_indent(&format!("jmp {}", done_label));
                self.emit(&format!("{}:", skip_label));
                // Invalid fd is an error - make On error fire
                self.emit_indent("mov qword [rel _last_error], 1");
                self.emit(&format!("{}:", done_label));
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
                    self.emit_store_back_after_realloc(name, "rax");
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
                self.declared_types.insert(name.clone(), Type::Timer);
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

    /// True when `expr`'s type is a concrete, known type that can never be
    /// `String`/`Buffer` (BUGS_FOUND #20). Comparing such an operand for
    /// equality against a stringy operand can never be true - the two
    /// representations aren't comparable. `Mixed`/`Unknown`/unclassifiable
    /// expressions stay `false`: a `value` might hold text at runtime and
    /// `is_stringy_expr` can't rule that out statically, so a stringy-vs-
    /// dynamic comparison keeps taking the existing `emit_stringy_equality`
    /// path (correct when the value does hold text, unchanged from before
    /// this fix when it doesn't - not this bug's scope).
    fn is_definitely_non_stringy_expr(&self, expr: &Expr) -> bool {
        matches!(
            self.infer_expr_type(expr),
            Some(VarType::Integer)
                | Some(VarType::Float)
                | Some(VarType::Boolean)
                | Some(VarType::List)
                | Some(VarType::Map)
        )
    }

    /// True when comparing `left`/`right` for equality reaches the stringy-
    /// vs-provably-non-stringy mismatch (BUGS_FOUND #20): one side is
    /// `String`/`Buffer` and the other is a concrete type that never is.
    /// The two representations can never be byte-equal, and evaluating the
    /// non-stringy side as if it were a C-string pointer is what crashed
    /// (or, for `list`/`map`, read out of bounds) before this fix.
    fn is_stringy_type_mismatch(&self, left: &Expr, right: &Expr) -> bool {
        (self.is_stringy_expr(left) && self.is_definitely_non_stringy_expr(right))
            || (self.is_stringy_expr(right) && self.is_definitely_non_stringy_expr(left))
    }

    /// True if `expr` is a `nothing`/`null`/`nil` literal (stage 1e3, tag 6).
    /// Used by the nothing-equality guard in `generate_condition`.
    fn is_nothing_expr(&self, expr: &Expr) -> bool {
        matches!(expr, Expr::NothingLit)
    }

    /// Emit the `type` property for a variable: static types produce a fixed
    /// text literal, `value` dispatches on the runtime tag already kept in its
    /// shadow slot (local) or BSS mirror (global).
    fn emit_type_property(&mut self, object: &str) {
        if let Some(declared) = self.declared_types.get(object) {
            if *declared != Type::Value {
                let name = type_property_display_name(declared).unwrap_or("Unknown");
                let text = format!("{} (static)", name);
                let label = self.add_string(&text);
                self.emit_indent(&format!("lea rax, [rel {}]  ; {}'s type: {}", label, object, text));
                return;
            }
        }

        // Dynamic: dispatch on the runtime tag in r11.
        self.emit_load_value_tag(&Expr::Identifier(object.to_string()));

        let arms = [
            (TAG_INTEGER, "Number"),
            (TAG_STRING, "Text"),
            (TAG_FLOAT, "Float"),
            (TAG_BOOLEAN, "Boolean"),
            (TAG_LIST, "List"),
            (TAG_MAP, "Map"),
            (TAG_NOTHING, "Nothing"),
        ];

        let mut case_labels = Vec::new();
        for (tag, _name) in &arms {
            let case_label = self.new_label(&format!("type_case_{}", tag));
            case_labels.push((*tag, case_label));
        }
        let unknown_label = self.new_label("type_unknown");
        let done_label = self.new_label("type_done");

        for (i, (tag, _name)) in arms.iter().enumerate() {
            let case_label = &case_labels[i].1;
            self.emit_indent(&format!("cmp r11, {}  ; {}?", tag, _name));
            self.emit_indent(&format!("je {}", case_label));
        }
        self.emit_indent(&format!("jmp {}", unknown_label));

        for (i, (_tag, name)) in arms.iter().enumerate() {
            let case_label = &case_labels[i].1;
            let text = format!("{} (dynamic)", name);
            let label = self.add_string(&text);
            self.emit(&format!("{}:", case_label));
            self.emit_indent(&format!("lea rax, [rel {}]  ; {}'s type: {}", label, object, text));
            self.emit_indent(&format!("jmp {}", done_label));
        }

        let unknown_text = "Unknown (dynamic)";
        let unknown_str = self.add_string(unknown_text);
        self.emit(&format!("{}:", unknown_label));
        self.emit_indent(&format!("lea rax, [rel {}]  ; {}'s type: {}", unknown_str, object, unknown_text));
        self.emit(&format!("{}:", done_label));
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
            
            // A string literal materializes its own bytes, unconditionally -
            // its content is never resolved against a same-spelled variable
            // (BUGS_FOUND #19).
            Expr::StringLit(s) => {
                let label = self.add_string(s);
                self.emit_indent(&format!("lea rax, [rel {}]", label));
            }
            
            Expr::Identifier(name) => {
                if self.emit_load_named_var_into_rax(name) {
                    // loaded as a variable
                } else if self.zero_arg_func_return_type(name).is_some() {
                    // Plan 270 G4: a zero-argument function name in expression
                    // position is a call, not a variable lookup. The result
                    // is left in rax (and, for a `value` return, its tag in r11)
                    // exactly as a written `Expr::FunctionCall` would be.
                    self.uses_funcs = true;
                    self.emit_function_call(name, &[]);
                }
                // else: the analyzer reported "Unknown variable"; a rejected
                // program never reaches codegen, so rax is left undefined.
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
                                        if let Some(operand) = src.shadow_operand() {
                                            self.emit_indent(&format!(
                                                "movzx r11, byte {}  ; load mixed element tag",
                                                operand
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
                    && self.is_stringy_type_mismatch(left, right)
                {
                    // Stringy vs a provably non-stringy operand (BUGS_FOUND
                    // #20): the two representations can never be byte-equal.
                    // Fold to a constant without evaluating (and
                    // dereferencing) either operand - the wider guard below
                    // treated the non-stringy operand's raw value as a
                    // C-string pointer and dereferenced it. Expression-
                    // position twin of the same fix in generate_condition;
                    // no known surface syntax reaches this arm today, but it
                    // carries the identical defect and must not regress.
                    let never_equal_result = if matches!(op, BinaryOperator::Equal) { 0 } else { 1 };
                    self.emit_indent(&format!(
                        "mov rax, {}  ; stringy vs non-stringy operand: never equal",
                        never_equal_result
                    ));
                } else if matches!(op, BinaryOperator::Equal | BinaryOperator::NotEqual)
                    && (self.is_stringy_expr(left) || self.is_stringy_expr(right))
                {
                    // Content comparison via _str_eq/_mem_eq - see
                    // emit_stringy_equality. Reached when both sides are
                    // stringy, or one side is stringy and the other is
                    // `value`/Mixed (whose runtime tag might be text).
                    self.emit_stringy_equality(left, right);
                    if matches!(op, BinaryOperator::NotEqual) {
                        self.emit_indent("xor rax, 1  ; 1=equal -> 0=notequal");
                    }
                } else {
                    // Integer operations
                    self.uses_ints = true;
                    let arith = self.is_arithmetic_operator(op);
                    if arith {
                        self.emit_indent(
                            "mov qword [rel _last_error], 0  ; clear error before arithmetic",
                        );
                    }
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
                                if let Some(operand) = src.shadow_operand() {
                                    self.emit_indent(&format!(
                                        "movzx r11, byte {}  ; load mixed element tag",
                                        operand
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
                let header_size = LIST_DATA_OFFSET as usize;
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
                            if let Some(loc) = self.mixed_element_tag_slot(elem) {
                                self.emit_indent(&format!(
                                    "mov cl, {}  ; runtime tag of mixed source",
                                    loc.operand()
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
                            if let Some(loc) = self.mixed_element_tag_slot(value) {
                                self.emit_indent(&format!(
                                    "movzx ecx, byte {}  ; runtime tag of mixed source",
                                    loc.operand()
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
                self.emit_indent("mov qword [rel _last_error], 0  ; clear error on success");
                if is_mixed {
                    // tag_addr = base + 24 + capacity*8 + index; tag rides in
                    // r11 for the immediate consumer.
                    self.emit_indent("mov r11, [rbx]  ; capacity");
                    self.emit_indent("shl r11, 3  ; * element size (8)");
                    self.emit_indent("add r11, rcx  ; + index");
                    self.emit_indent(&format!(
                        "movzx r11, byte [rbx + r11 + {}]  ; slot type tag",
                        LIST_DATA_OFFSET
                    ));
                }
                self.emit_indent("mov rax, rcx");
                self.emit_indent("shl rax, 3  ; multiply by 8 (element size)");
                self.emit_indent(&format!(
                    "add rax, {}  ; skip header ({} bytes)",
                    LIST_DATA_OFFSET, LIST_DATA_OFFSET
                ));
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
                        // Universal property: reports the variable's type as text.
                        // Does not need the variable's payload; static types fold
                        // to a literal, `value` dispatches on its runtime tag.
                        ObjectProperty::Type => {
                            self.emit_type_property(object);
                        }
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
                            self.emit_indent("mov qword [rel _last_error], 0  ; clear error on success");
                            if is_mixed {
                                // tags[0] = base + 24 + capacity*8
                                self.emit_indent("mov r11, [rax]  ; capacity");
                                self.emit_indent("shl r11, 3  ; * element size (8)");
                                self.emit_indent(&format!(
                            "movzx r11, byte [rax + r11 + {}]  ; slot type tag",
                            LIST_DATA_OFFSET
                        ));
                            }
                            self.emit_indent(&format!(
                                "mov rax, [rax + {}]  ; first element (data at offset {})",
                                LIST_DATA_OFFSET, LIST_DATA_OFFSET
                            ));
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
                            self.emit_indent("mov qword [rel _last_error], 0  ; clear error on success");
                            self.emit_indent("dec rbx             ; 0-indexed");
                            if is_mixed {
                                // tags[len-1] = base + 24 + capacity*8 + (len-1)
                                self.emit_indent("mov r11, [rax]  ; capacity");
                                self.emit_indent("shl r11, 3  ; * element size (8)");
                                self.emit_indent("add r11, rbx  ; + 0-based last index");
                                self.emit_indent(&format!(
                            "movzx r11, byte [rax + r11 + {}]  ; slot type tag",
                            LIST_DATA_OFFSET
                        ));
                            }
                            self.emit_indent("shl rbx, 3          ; * 8");
                            self.emit_indent(&format!("add rbx, {}         ; + header offset", LIST_DATA_OFFSET));
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
                self.emit_indent(&format!("add rax, {}", LIST_DATA_OFFSET));
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
                self.emit_indent(&format!("mov [r14 + r15*8 + {}], rax", LIST_DATA_OFFSET));
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
                self.emit_indent(&format!("add rax, {}", LIST_DATA_OFFSET));
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
                self.emit_indent(&format!("mov [r14 + r15*8 + {}], rax", LIST_DATA_OFFSET));
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
                                self.emit_indent(&format!("add rax, {}  ; buffer data area", BUF_DATA_OFFSET));
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
                        // decimal representation. Text values are already valid
                        // text pointers, so they are left unchanged. A buffer is
                        // NOT: it is a struct with a 24-byte header (BUF_DATA_OFFSET)
                        // whose NUL-terminated character data lives at
                        // struct + BUF_DATA_OFFSET, so the cast must return the
                        // data-area pointer, not the struct pointer it was given.
                        let src_type = self.infer_expr_type(value);
                        if matches!(src_type, Some(VarType::Buffer)) {
                            // Buffer data is always NUL-terminated at its logical
                            // end (_buffer_append_bytes writes a trailing NUL at
                            // data+length; _buffer_clear zeroes the first byte), so
                            // the data-area pointer is a valid C string. Same
                            // adjustment the boolean cast makes for a buffer source.
                            self.uses_buffers = true;
                            self.emit_indent(&format!(
                                "add rax, {}  ; buffer data area -> NUL-terminated text",
                                BUF_DATA_OFFSET
                            ));
                        } else if !matches!(src_type, Some(VarType::String)) {
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
                            self.emit_indent(&format!(
                                "add rax, {}  ; buffer data area -> NUL-terminated C string",
                                BUF_DATA_OFFSET
                            ));
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
            // Buffer structure: [capacity:8][length:8][flags:8][data at offset 24]
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
                self.emit_indent("mov qword [rel _last_error], 0  ; clear error on success");
                self.emit_indent("dec rcx  ; convert 1-indexed to 0-indexed");
                self.emit_indent(&format!("add rbx, {}  ; skip to buffer data area", BUF_DATA_OFFSET));
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
                self.emit_indent("mov qword [rel _last_error], 0  ; clear error on success");
                self.emit_indent("dec rcx  ; convert 1-indexed to 0-indexed");
                if is_mixed {
                    // Runtime type tag travels in r11 (captured immediately
                    // by the consumer - never held across calls/syscalls):
                    // tag_addr = base + 24 + capacity*8 + index
                    self.emit_indent("mov r11, [rbx]  ; capacity");
                    self.emit_indent("shl r11, 3  ; * element size (8)");
                    self.emit_indent("add r11, rcx  ; + 0-based index");
                    self.emit_indent(&format!(
                        "movzx r11, byte [rbx + r11 + {}]  ; slot type tag",
                        LIST_DATA_OFFSET
                    ));
                }
                self.emit_indent("mov rax, rcx");
                self.emit_indent("shl rax, 3  ; index * 8");
                self.emit_indent(&format!(
                    "add rax, {}  ; skip header ({} bytes)",
                    LIST_DATA_OFFSET, LIST_DATA_OFFSET
                ));
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
            // so `a text called t is "{buf}"` silently produced a NULL
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
                self.emit_indent(&format!(
                    "add rax, {}  ; buffer data area (header is {} bytes)",
                    BUF_DATA_OFFSET, BUF_DATA_OFFSET
                ));
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
                                if let Some(operand) = src.shadow_operand() {
                                    self.emit_indent(&format!(
                                        "movzx r11, byte {}  ; load mixed element tag",
                                        operand
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
                                            if let Some(operand) = src.shadow_operand() {
                                                self.emit_indent(&format!(
                                                    "movzx r11, byte {}  ; load mixed element tag",
                                                    operand
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
                        if self.is_stringy_type_mismatch(left, right) =>
                    {
                        // Stringy vs a provably non-stringy operand
                        // (BUGS_FOUND #20): the two representations can
                        // never be byte-equal. Fold to a compile-time
                        // constant without evaluating (and dereferencing)
                        // either operand - the old, wider guard below
                        // treated the non-stringy operand's raw value as a
                        // C-string pointer and dereferenced it.
                        if matches!(op, BinaryOperator::Equal) {
                            self.emit_indent(&format!(
                                "jmp {}  ; stringy vs non-stringy operand: never equal",
                                false_label
                            ));
                        }
                        // `is not equal to` is always true here - the
                        // condition holds, so fall through with no jump.
                    }
                    BinaryOperator::Equal | BinaryOperator::NotEqual
                        if self.is_stringy_expr(left) || self.is_stringy_expr(right) =>
                    {
                        // Content comparison - see emit_stringy_equality for
                        // why _mem_eq is used when either side is a buffer.
                        // Reached when both sides are stringy, or one side
                        // is stringy and the other is `value`/Mixed (whose
                        // runtime tag might be text - the mismatch arm
                        // above only fires for a PROVABLY non-stringy type).
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
            // A string literal is text, unconditionally - never resolved
            // against a same-spelled variable's type (BUGS_FOUND #19).
            Expr::StringLit(_) => Some(VarType::String),
            // A format string always materializes text (bug #17): its
            // interpolated parts affect the bytes, never the result type.
            Expr::FormatString { .. } => Some(VarType::String),
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
            Expr::Identifier(name) => self
                .variable_types
                .get(name)
                .cloned()
                .or_else(|| self.zero_arg_func_return_type(name)),
            Expr::FunctionCall { name, .. } => {
                self.function_return_types.get(&self.resolved_call_label(name)).cloned()
            }
            Expr::PropertyAccess { object, property } => {
                // For First/Last on lists, return the list's element type
                match property {
                    ObjectProperty::Type => Some(VarType::String),
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
                // For element access, return the list's element type. A named
                // list with no proven element type (a bare `list` parameter, or
                // any list the pre-scan left untyped) is runtime-tagged
                // per-slot, so return None and let `emit_load_value_tag` use the
                // tag `generate_expr` left in r11 — instead of defaulting to
                // Integer, which would overwrite the real tag with 0.
                match list.as_ref() {
                    Expr::Identifier(name) => match self.list_element_types.get(name) {
                        Some(VarType::Unknown) | None => None,
                        Some(other) => Some(other.clone()),
                    },
                    // `element N of m's keys` is a string; `element N of m's
                    // values` is runtime-tagged like a mixed list.
                    Expr::PropertyAccess { property, .. }
                        if matches!(property, ObjectProperty::Keys | ObjectProperty::Values) =>
                    {
                        match property {
                            ObjectProperty::Keys => Some(VarType::String),
                            _ => None, // Values: runtime tag, do not guess
                        }
                    }
                    _ => Some(VarType::Integer),
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

}

