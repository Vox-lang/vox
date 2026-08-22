use crate::parser::ast::*;
use crate::errors::{CompileError, SourceFile, SourceLocation, find_similar_keyword, ENGLISH_KEYWORDS};
use std::collections::{HashMap, HashSet};
use crate::codegen::{read_format_spec, read_format_spec_ask, FormatSpecAsk, FormatSpecFault, FORMAT_MAX_COUNT};

const FD_MAX: i64 = 2_147_483_647;

#[derive(Debug, Default)]
pub struct Dependencies {
    pub uses_io: bool,
    pub uses_heap: bool,
    pub uses_strings: bool,
    pub uses_args: bool,
    pub uses_funcs: bool,
}

#[cfg(test)]
mod buffer_append_copy_analysis_tests;
#[cfg(test)]
mod guard_env_tests;
mod scope;
mod expressions;
mod statements;
pub(crate) mod things;
mod types;
mod untyped_returns;
mod void_results;

pub struct Analyzer {
    pub deps: Dependencies,
    pub variables: HashSet<String>,
    pub functions: HashSet<String>,
    /// Assembly symbol -> the function name that claimed it. Two names that
    /// differ only in characters the mangler folds to `_` ("my.helper" and
    /// "my helper") would emit one label and silently share a body.
    mangled_functions: std::collections::HashMap<String, String>,
    pub used_identifiers: HashSet<String>,  // Track all identifiers seen
    typo_candidates: HashSet<String>,
    pub errors: Vec<CompileError>,
    source_file: Option<SourceFile>,
    guarded_scopes: HashMap<String, HashSet<String>>,
    symbol_error_counts: HashMap<String, usize>,
    /// Where each concretely-typed variable was first declared, captured at
    /// declaration time for the type-lock check's "note: declared here"
    /// (a variable's type is fixed at declaration and never changes).
    declared_locations: HashMap<String, SourceLocation>,
    active_guards: Vec<String>,
    in_function_scope: bool,
    block_depth: usize,
    global_variables: HashSet<String>,
    /// Declared flag name -> its declared value type. A set was not
    /// enough: every flag then answered `boolean` to a type query,
    /// which mis-typed text and number flags read inside a function
    /// body (docs/BUGS_FOUND.md #32).
    flag_variables: HashMap<String, Type>,
    buffer_variables: HashSet<String>,
    list_variables: HashSet<String>,
    map_variables: HashSet<String>,
    file_variables: HashSet<String>,
    timer_variables: HashSet<String>,
    /// Variables holding a raw heap pointer from `Allocate`. They are not
    /// buffers (no length/capacity header), but `Free` must accept them -
    /// that is the whole point of Allocate.
    allocated_variables: HashSet<String>,
    /// Declared/inferred scalar category (Integer/Float/String/Boolean) for
    /// non-buffer, non-list, non-file, non-timer variables. Vox is dynamically
    /// typed - a variable's runtime category is whatever its last assignment
    /// stored - so this map is updated on every VarDecl and Assignment to stay
    /// current. It lets the arithmetic type check distinguish a text variable
    /// (must be cast with `as a number`/`as a float` before arithmetic) from a
    /// numeric one, which the buffer/list/flag sets alone cannot do.
    scalar_types: HashMap<String, Type>,
    function_param_counts: HashMap<String, usize>,
    /// Declared parameter types and return type of each local function,
    /// keyed exactly like `function_param_counts`. A thing crosses a call
    /// boundary by value (plan 310 §5), so the call site is the only place
    /// an argument's shape and the result's shape can be checked against
    /// what the definition declared.
    function_signatures: HashMap<String, (Vec<(String, Type)>, Type)>,
    /// Functions that hand a value back but never declared its type - keyed
    /// exactly like `function_signatures` (bug #45). A caller reading one of
    /// these into a slot that supplies no type of its own has nothing to read
    /// the value AS, and the conservative "it is a number" fallback turns a
    /// returned text into the address of its bytes. See
    /// `untyped_returns.rs` for the whole rule and every rejection site.
    untyped_result_functions: HashSet<String>,
    /// Functions that return nothing - a `To` with no `Return` at all -
    /// keyed exactly like `function_signatures` (BUGS_FOUND #63). There is
    /// no result at a call to one of these, so a caller that reads one in
    /// value position reads the return register's leftover instead. See
    /// `void_results.rs` for the whole rule, its `.lib` half (#62), and
    /// every rejection site.
    procedures: HashSet<String>,
    /// Names declared as the dynamic `value` type (value parameters and `a
    /// value called x` locals). A bare `value` is not usable in arithmetic
    /// without an explicit type check (stage 1c predicate); the arithmetic
    /// operand check uses this set to reject unguarded use with a clear error.
    value_typed_names: HashSet<String>,
    /// Lists proven heterogeneous from their own literal initializer at
    /// declaration time (plan 294 finding 18) - e.g. `a list called data is
    /// [42, "hello"].`. Deliberately narrower than codegen's `mixed_lists`
    /// pre-scan: this only looks at a direct `ListLit` initializer, not
    /// aliasing through other variables or widening via later `Append`s.
    /// That asymmetry is safe in the direction it's used (a `for each` loop
    /// variable over a list this set doesn't catch keeps today's existing,
    /// unchanged behaviour rather than being wrongly tightened), but it
    /// means a list built up entirely through `Append` calls of differing
    /// types is not detected as mixed here the way it would be by codegen.
    list_mixed: HashSet<String>,
    /// A map's value type, proven from its own literal initializer when
    /// every value shares one provable type (plan 294 findings 4, 14) -
    /// e.g. `{"k": 42}` is a map of number. `Type::Map` is otherwise never
    /// given a value type anywhere in the analyzer, so a mismatched read
    /// (`a text called s is m's "k".` where `m`'s values are numbers) was
    /// unprovable and silently passed the type lock. Absent (not `None`
    /// stored, just no entry) for a map whose literal has mixed value
    /// types, an empty map, or a non-literal initializer - `arithmetic_
    /// operand_type` then returns `None` for a read from it, same
    /// "can't prove it, so allow" policy as everywhere else in this file.
    /// Narrower than a full type system: only the map's own declaration
    /// site is consulted, not aliasing or later `Set <map>'s "k" to
    /// <value>` writes that could widen it.
    map_value_type: HashMap<String, Type>,
    /// A list's element type, proven from its own literal initializer when
    /// every element shares one provable type (bug #54) - e.g. `[1, 2]` is
    /// a list of number. Consulted by `arithmetic_operand_type` so a read
    /// of an element (`element 1 of counts`, `counts's first`) carries that
    /// type, which makes a read into a differently-typed variable a
    /// statically-provable type-lock violation instead of a segfault at
    /// runtime.
    ///
    /// Only offered for a name absent from `widened_lists`: the proof holds
    /// exactly as long as nothing can change or share the elements after
    /// the declaration. Absent (no entry) for an empty literal, a mixed
    /// one, or a non-literal initializer - `arithmetic_operand_type` then
    /// answers `None` for a read from it, the same "can't prove it, so
    /// allow" policy as everywhere else in this file.
    list_element_type: HashMap<String, Type>,
    /// Names that hold one fixed integer for the whole program - see
    /// `collect_constant_numbers`. Filled once, before the walk, so a size
    /// named before its own declaration line gets the same answer as one
    /// named after it, and a name anything writes to is simply absent
    /// (bug #78: a buffer sized from a variable escaped the size bound).
    number_constants: HashMap<String, i64>,
    /// Every list name some statement in the program can widen or alias -
    /// see `collect_widened_lists`. Filled once, before the walk, so the
    /// answer does not depend on where in the file a read appears.
    widened_lists: HashSet<String>,
    /// Set when some function in the program appends to (or element-sets)
    /// one of its own parameters - see `any_function_widens_a_parameter`.
    /// That is the one widening move no name can be pinned on, so while it
    /// is true no list gets an element-type proof at all.
    functions_widen_lists: bool,
    /// How many elements a list literal wrote, for every list the program
    /// declares exactly once - mixed literals included, unlike
    /// `list_element_type`, because a length is provable whether or not
    /// the elements share a type (bug #72). Filled by
    /// `collect_literal_collection_shapes` before the walk. Read through
    /// `list_literal_len_of`, which withholds it under exactly the
    /// conditions `list_element_type_of` withholds an element type: an
    /// `Append` makes the list longer, so a proof that index N is past the
    /// end only holds while nothing can grow it.
    list_literal_len: HashMap<String, usize>,
    /// The exact key set a map literal wrote, for every map the program
    /// declares exactly once and whose keys are all string literals (bug
    /// #72). A key the literal does not contain is absent, and
    /// LANGUAGE.md:2429 says an absent key's read yields the number 0 -
    /// which is a different type from the map's values, and the type the
    /// read must be judged as. Filled by
    /// `collect_literal_collection_shapes` before the walk. Read through
    /// `map_literal_keys_of`, which withholds it for any map some `Set` or
    /// alias can reach.
    map_literal_keys: HashMap<String, HashSet<String>>,
    /// Every map name some `Set <map>'s "k" to <value>.` in the program can
    /// insert a key into - see `collect_map_key_writers`. Filled once,
    /// before the walk, so the answer does not depend on where in the file
    /// a read appears.
    map_key_writers: HashSet<String>,
    /// Set when some function in the program inserts a key into a map it
    /// was handed - see `any_function_writes_a_map_parameter`. The map
    /// twin of `functions_widen_lists`, and equally blunt: while it is
    /// true no map gets a key-set proof at all.
    functions_write_map_keys: bool,
    loop_depth: usize,
    /// True when compiling `--shared`. A shared library has no `_start`, so a
    /// top-level executable statement would be generated into the discarded
    /// main body and silently dropped. Reject such statements up front rather
    /// than mislead the author.
    shared_mode: bool,
    /// The identity of the library whose function definitions surround the
    /// statement currently being analyzed, set by `Library` declarations as
    /// the walk proceeds. The per-function tables (`functions`,
    /// `function_param_counts`, `mangled_functions`) are keyed by the
    /// `<lib>_<ver>_<func>` mangled label, so a call resolves only against the
    /// current library's functions: a name defined in a DIFFERENT library of
    /// the same .so is not in this library's key set and stays the existing
    /// "Unknown function" error (cross-library calls are out of scope for A2).
    /// `None` outside shared mode, where the key is plain `mangle_symbol(name)`.
    current_library: Option<(String, String)>,
    /// Set right after analyzing a function whose body a blank line force-
    /// closed early. Consulted by errors in the top-level statements that
    /// follow, since that's where such a function's "missing" params actually
    /// surface as errors. Cleared as soon as the next FunctionDef or Library
    /// starts analysis, bounding it to just the orphaned statements in between.
    pending_blank_line_truncation: Option<(String, Vec<String>, SourceLocation)>,
    // (function_name, its parameter names, the blank line's location)
    /// Set right after analyzing a function whose body a body-level `Return`
    /// (not the function's first statement) closed early - the "Gate B"
    /// case in `src/parser/functions.rs`. Same lifecycle and purpose as
    /// `pending_blank_line_truncation` above, but for the sibling cause: a
    /// `Return` closes the function it's in, exactly like a blank line does,
    /// so a second Return written after it (meant as another branch of the
    /// same function) is silently promoted to top-level code instead.
    pending_return_truncation: Option<(String, SourceLocation)>,
    // (function_name, the closing Return's own location)
    /// Stage A4: functions imported by `see '<lib>' version "<ver>" from
    /// "...lib".`, resolved against the filesystem by the driver (parse +
    /// .dynsym verification) and handed here for name resolution and call
    /// checking. A call resolves local-first (a local definition SHADOWS a
    /// same-named import, with a warning naming the library), then by import
    /// (exactly one exporting <lib,version>), then ambiguity (two imports
    /// exporting the same name — an error by design, never a pick).
    imports: Vec<crate::lib_file::ImportedFunction>,
    /// Non-fatal diagnostics (currently: local-definitions-shadow-imports).
    /// Printed by the driver with a `warning:` prefix; they never stop a
    /// build, but shadowing is never silent either.
    pub warnings: Vec<String>,
    /// Every thing defined in the program (plan 310), keyed by name. Layout,
    /// sizes, and field offsets are all read from here - see
    /// `analyzer::things`.
    things: things::ThingRegistry,
    /// Which thing each thing variable holds, by variable name. Seeded from
    /// the whole main line before the walk (so a function body may reach a
    /// global declared later in the file, like any other global) and extended
    /// as each declaration is analyzed.
    thing_vars: HashMap<String, String>,
    /// The declared return type of the function whose body is being walked,
    /// `None` at the top level. `Return` needs it: returning a thing copies
    /// the whole shape into the caller's storage (plan 310 §5), and only the
    /// signature says whether that is what this `Return` means.
    current_function_return_type: Option<Type>,
    /// The name of the function currently being walked, paired with the
    /// return type above and saved/restored beside it. A diagnostic about
    /// the return needs somewhere to put its caret, and the signature line
    /// - where the return type is declared - is the place the author has to
    /// change (bug #57).
    current_function_name: Option<String>,
}

#[derive(Clone, Default)]
pub(crate) struct AnalysisEnv {
    always: HashSet<String>,
    guarded: HashMap<String, HashSet<String>>,
}


impl Analyzer {
    pub fn new() -> Self {
        Analyzer {
            deps: Dependencies::default(),
            variables: HashSet::new(),
            functions: HashSet::new(),
            mangled_functions: std::collections::HashMap::new(),
            used_identifiers: HashSet::new(),
            typo_candidates: HashSet::new(),
            errors: Vec::new(),
            source_file: None,
            guarded_scopes: HashMap::new(),
            symbol_error_counts: HashMap::new(),
            declared_locations: HashMap::new(),
            active_guards: Vec::new(),
            in_function_scope: false,
            block_depth: 0,
            global_variables: HashSet::new(),
            flag_variables: HashMap::new(),
            buffer_variables: HashSet::new(),
            list_variables: HashSet::new(),
            map_variables: HashSet::new(),
            file_variables: HashSet::new(),
            timer_variables: HashSet::new(),
            allocated_variables: HashSet::new(),
            scalar_types: HashMap::new(),
            function_param_counts: HashMap::new(),
            function_signatures: HashMap::new(),
            untyped_result_functions: HashSet::new(),
            procedures: HashSet::new(),
            value_typed_names: HashSet::new(),
            list_mixed: HashSet::new(),
            map_value_type: HashMap::new(),
            list_element_type: HashMap::new(),
            number_constants: HashMap::new(),
            widened_lists: HashSet::new(),
            list_literal_len: HashMap::new(),
            map_literal_keys: HashMap::new(),
            map_key_writers: HashSet::new(),
            functions_write_map_keys: false,
            functions_widen_lists: false,
            loop_depth: 0,
            shared_mode: false,
            current_library: None,
            pending_blank_line_truncation: None,
            pending_return_truncation: None,
            imports: Vec::new(),
            warnings: Vec::new(),
            things: HashMap::new(),
            thing_vars: HashMap::new(),
            current_function_return_type: None,
            current_function_name: None,
        }
    }

    pub fn with_source(mut self, filename: &str, content: &str) -> Self {
        self.source_file = Some(SourceFile::new(filename, content));
        self
    }

    pub fn with_shared_mode(mut self, enabled: bool) -> Self {
        self.shared_mode = enabled;
        self
    }

    /// Register the functions imported by the program's `see ... from
    /// "*.lib"` statements (already parsed and .dynsym-verified by the
    /// driver). Names are authorship-level here: `imports` is matched by the
    /// authored name, and the `<lib>_<ver>_<func>` label only matters to the
    /// codegen, which gets the same list.
    pub fn with_imports(mut self, imports: Vec<crate::lib_file::ImportedFunction>) -> Self {
        self.imports = imports;
        self
    }

}

