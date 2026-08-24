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
    // docs/BUGS_FOUND.md #90. A `buffer` parameter's argument word is the
    // ADDRESS of the cell where the CALLER keeps its buffer pointer, not the
    // pointer itself. This maps a buffer parameter's payload slot offset to
    // the hidden `{name}_cell` slot holding that address, so every store of a
    // (possibly reallocated) buffer pointer into the payload slot can travel
    // on to the caller's cell in the same breath. `_reallocate_buffer` frees
    // the block it grew out of - mremap consumes it, the fallback munmaps it -
    // so a caller left holding the old pointer is holding unmapped memory.
    // Keyed by slot offset rather than by name because the buffer helpers in
    // `buffers.rs`/`format.rs` only ever know the destination's offset. Reset
    // and restored per function, like every other per-frame table.
    buffer_param_cells: HashMap<i64, i64>,
    // BUGS_FOUND #75. Stack slot ([rbp - offset]) holding the address of the
    // CALLER's storage for each `list`/`map` parameter of the function being
    // generated. A collection argument travels as the address of the caller's
    // slot (the shape a `thing` argument already uses), the prologue reads the
    // pointer out of it into the parameter's own slot, and every store-back
    // after a realloc writes the new pointer through this address as well - so
    // growth inside a callee reaches the caller's variable instead of stopping
    // at the block the caller still points at. Empty outside a function body.
    collection_backing_slots: HashMap<String, i64>,
    // The single source of truth for a file handle's open mode. `readable`
    // and `writable` are both derived from this at the point they are read,
    // instead of one being derived (writable) and the other left as a
    // constant true (readable) - see bug #37.
    file_mode: HashMap<String, FileMode>,
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
    // What a call writes into the CALLER's list through a `list` parameter,
    // keyed by the callee's resolved label and indexed by parameter position.
    // `None` means the parameter is not a list, or the body never writes into
    // it. The per-function pre-scan decides each function's lists in
    // isolation, so without this the caller proves a list homogeneous that a
    // callee then widens through the parameter, and the caller's reads take
    // an untagged path over tagged slots (docs/BUGS_FOUND.md #97).
    list_param_writes: HashMap<String, Vec<Option<TagInfo>>>,
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
    // Set when codegen emits a process-control macro (MOUNT/UMOUNT/
    // REBOOT_CMD/PIVOT_ROOT/EXECVE/FORK/REAP_CHILD/SEND_SIGNAL/MKNOD).
    // Gates `%include "coreasm/<arch>/proc.asm"` so a program that only
    // does filesystem I/O no longer pulls fork/reboot/mount symbols
    // (audit rec 2). The process-control statements also set uses_files,
    // so file.asm is still included before proc.asm.
    uses_proc: bool,
    // Set when codegen emits `call _read_line_into_buffer` (a `Read line`
    // statement) or `call _seek_fd_line` (a `Seek line` statement, which
    // scans newlines). Gates the line-reading half of the read-ahead
    // module so a buffer/file program that never reads lines never pulls
    // it (audit rec 1).
    uses_readline: bool,
    // Set when codegen emits `call _seek_fd_byte` (a `Seek byte`
    // statement). Gates the byte-seek half of the read-ahead module
    // alongside uses_readline (audit rec 1).
    uses_seek: bool,
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
    // Frame slot holding the caller's destination address for a function that
    // returns a whole thing (plan 310 §5). The address arrives as a hidden
    // first argument word; `Return` copies the thing into it and hands it
    // back in rax, so a thing-returning call is an address like every other
    // thing-valued expression. `None` for every other function.
    current_thing_return_slot: Option<i64>,
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
    // The declared type of every top-level (global) name and flag, collected
    // by `collect_global_var_types` BEFORE any statement is generated. The
    // analyzer already makes every top-level name available from the very
    // first statement (`analyzer::statements`'s `self.variables =
    // self.global_variables.clone()`), so a function body may legally read a
    // global declared BELOW it (LANGUAGE.md: "Variables declared at top level
    // are global and can be used inside functions"). Codegen's own
    // `variable_types` is filled as statements are walked, so that read used
    // to reach a slot whose type was not known yet and be printed as a raw
    // machine word - docs/BUGS_FOUND.md #66. This map is the whole-program
    // half, seeded into `variable_types` at the top of every function body,
    // exactly as #32 made the analyzer's flag types whole-program.
    global_var_types: HashMap<String, Type>,
    // The element type of every top-level list, read off its initializer by
    // the same pre-pass. A list's element type is inferred rather than
    // declared, so it is not in `global_var_types` - and without it a forward
    // read of `<list>'s first` on a list of texts still printed the element's
    // address.
    global_list_element_types: HashMap<String, VarType>,
    // Globals whose type a function body took from `global_var_types` because
    // their declaration had not been walked yet. Their BSS mirror still holds
    // zero until that declaration runs, so a pointer type among them needs its
    // empty default written at frame setup - #25's rule, for the forward case.
    forward_typed_globals: std::collections::HashSet<String>,
    // Top-level global variables whose BSS mirror has already received an
    // initial value (allocated buffer, list, map, etc.). For buffer targets
    // this avoids clearing/appending into a null pointer on redeclaration or
    // assignment; for other types the initial `generate_expr` already produces
    // a valid pointer/value.
    initialized_globals: std::collections::HashSet<String>,
    in_function_codegen: bool,
    target_arch: String,
    /// Every thing defined in the program (plan 310), keyed by name. Sizes and
    /// field offsets are read from `analyzer::things`, so validation and
    /// emission compute one layout from one place.
    things: crate::analyzer::things::ThingRegistry,
    /// Which thing each thing variable holds, by variable name. Seeded from
    /// the whole main line before any label or statement is emitted, then
    /// extended by each declaration as it is generated. Clone-and-restored
    /// around a function body like `declared_types`, so a function's own
    /// locals do not leak into what is generated after it.
    thing_vars: HashMap<String, String>,
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

/// The codegen `VarType` a declared type noun stands for — one table, read by
/// every position that writes one: a declaration, a parameter, and a function's
/// declared return type (local and imported). It used to be copied out four
/// times, and `map` had reached only the declaration's copy, so a `map`
/// parameter and a `map` return both fell to `Unknown` — which every property
/// and print dispatch reads as the *file* branch (bug #76: `holder's length`
/// emitted `_file_size` and the program failed to assemble, `Print holder`
/// leaked a heap address, `holder's length` answered `-1` where it linked).
/// One table now, so the next type added cannot land in only some of them.
///
/// `file`, `time`, `timer` and `thing` are deliberately `Unknown`: they are
/// handles whose property reads go through their own paths, not through the
/// `VarType` dispatch.
///
/// The `map` arm answers for a declared map RETURN as well, local and
/// imported (`returning a map` is a spelling a `.lib` states): without it
/// every consumer that asks what a call answers with - Print's catch-all, a
/// format hole, a `value` declaration's tag - fell through to the integer
/// formatter and rendered the map's heap address, on both sides of the
/// library boundary (bug #67).
pub(crate) fn vartype_of_declared_type(t: &Type) -> VarType {
    match t {
        Type::Integer => VarType::Integer,
        Type::Float => VarType::Float,
        Type::String => VarType::String,
        Type::Boolean => VarType::Boolean,
        Type::Buffer => VarType::Buffer,
        Type::List(_) => VarType::List,
        Type::Map(_) => VarType::Map,
        // A declared `value` is a Mixed-typed scalar carrying its runtime tag
        // in a shadow slot — the same in a declaration, in a parameter, and
        // coming home from a call (where the tag rides back in r11).
        Type::Value => VarType::Mixed,
        _ => VarType::Unknown,
    }
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
//
// BUF_DATA_OFFSET is now a MIRROR of coreasm/x86_64/core.asm's
// `%define BUF_DATA_OFFSET 24` (the BUFFER_HEADER block). core.asm is the
// single source of truth for the dynamic-buffer layout; this Rust const is
// kept only so codegen comments and any future Rust-side reference share the
// same name. The codegen data-area sites emit `BUFFER_DATA_ADDR` (which
// expands to `add <reg>, BUF_DATA_OFFSET` in core.asm) rather than this
// const, so it is not read at runtime — hence the allow.
#[allow(dead_code)]
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
pub(crate) use format::{read_format_spec, read_format_spec_ask, FormatSpecAsk, FormatSpecFault, FORMAT_MAX_COUNT};
mod vars;
use vars::list_literal_element_vartype;
mod functions;
mod tags;
use tags::type_to_tag;
mod collections;
use collections::is_fallible_collection_read;
mod print;
mod expr;
mod statements;
use statements::declared_slot_vartype;
mod things;

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


/// Where one operand of a `treating` clause keeps its type tag (bug #69).
///
/// A literal, or a variable whose type is fixed, has a tag at emit time and
/// the clause can be compiled against it. A `value` does not: its tag travels
/// with its payload and is only readable at runtime, so the tag test - and
/// with it the choice between comparing bytes and comparing registers - has
/// to become a runtime branch. See `CodeGenerator::treating_clause_tag`.
pub(crate) enum ClauseTag {
    Static(u8),
    Runtime(RuntimeTagSource),
}


/// Where a Mixed variable's shadow tag slot lives: a local stack offset
/// (function locals, params, for-each variables, and a function-local
/// `value`), or a BSS label (a top-level `value` global). See
/// `CodeGenerator::mixed_element_tag_slot`.
pub(crate) enum ShadowTagLoc {
    Local(i64),
    Global(String),
}




#[derive(Clone, Debug, PartialEq)]
enum IntegerBase {
    Decimal,
    HexLower,
    HexUpper,
    Binary,
    Octal,
}

/// A `{value:SPEC}` clause, read. Both counts are i64 because both render
/// literally - `width` characters of padding, `precision` decimal places -
/// and nothing in LANGUAGE.md:3101-3119 caps either one, so the only limit
/// is the largest count the runtime can hold. They were i32, and the parse
/// that filled them dropped its `Err` on the floor: `{n:2147483648}` built
/// the same spec as a bare `{n}` and printed with no padding and no
/// diagnostic (docs/BUGS_FOUND.md #61).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct FormatSpec {
    width: Option<i64>,
    zero_pad: bool,
    base: IntegerBase,
    precision: Option<i64>,
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
            buffer_param_cells: HashMap::new(),
            collection_backing_slots: HashMap::new(),
            file_mode: HashMap::new(),
            local_mixed_lists: HashMap::new(),
            list_param_writes: HashMap::new(),
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
            uses_proc: false,
            uses_readline: false,
            uses_seek: false,
            function_return_types: std::collections::HashMap::new(),
            function_param_types: std::collections::HashMap::new(),
            function_return_full_types: std::collections::HashMap::new(),
            current_function_return_type: None,
            current_thing_return_slot: None,
            loop_stack: Vec::new(),
            flag_schemas: Vec::new(),
            parsed_args_active: false,
            global_var_labels: HashMap::new(),
            global_var_counter: 0,
            global_value_tag_labels: HashMap::new(),
            declared_types: HashMap::new(),
            global_var_types: HashMap::new(),
            global_list_element_types: HashMap::new(),
            forward_typed_globals: std::collections::HashSet::new(),
            initialized_globals: std::collections::HashSet::new(),
            in_function_codegen: false,
            target_arch: "x86_64".to_string(),
            things: HashMap::new(),
            thing_vars: HashMap::new(),
        }
    }































    
    fn new_label(&mut self, prefix: &str) -> String {
        let label = format!(".{}_{}", prefix, self.label_counter);
        self.label_counter += 1;
        label
    }
    


    
    








    

    fn emit(&mut self, code: &str) {
        self.output.push_str(code);
        self.output.push('\n');
    }
    
    /// The instructions emitted so far, for a unit test that drives one
    /// emitter directly rather than compiling a whole program. Codegen's
    /// guarantees about what it will never emit (docs/BUGS_FOUND.md #71: a
    /// text's address, a float's bit pattern) have to be checkable for
    /// types no legal source can route here, because the analyzer refuses
    /// those programs before codegen sees them.
    #[cfg(test)]
    pub(crate) fn emitted_for_test(&self) -> String {
        self.output.clone()
    }

    fn emit_indent(&mut self, code: &str) {
        self.output.push_str("    ");
        self.output.push_str(code);
        self.output.push('\n');
    }

    

















    
    
    
    
    








    
    

}

