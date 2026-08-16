use crate::parser::ast::*;
use crate::errors::{CompileError, SourceFile, SourceLocation, find_similar_keyword, ENGLISH_KEYWORDS};
use std::collections::{HashMap, HashSet};

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
mod types;

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
    flag_variables: HashSet<String>,
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
            flag_variables: HashSet::new(),
            buffer_variables: HashSet::new(),
            list_variables: HashSet::new(),
            map_variables: HashSet::new(),
            file_variables: HashSet::new(),
            timer_variables: HashSet::new(),
            allocated_variables: HashSet::new(),
            scalar_types: HashMap::new(),
            function_param_counts: HashMap::new(),
            value_typed_names: HashSet::new(),
            list_mixed: HashSet::new(),
            map_value_type: HashMap::new(),
            loop_depth: 0,
            shared_mode: false,
            current_library: None,
            pending_blank_line_truncation: None,
            imports: Vec::new(),
            warnings: Vec::new(),
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

