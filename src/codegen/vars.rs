use super::*;

impl VarTarget {
    pub(crate) fn local_offset(&self) -> Option<i64> {
        match self {
            VarTarget::Local(o) => Some(*o),
            VarTarget::Global(_) => None,
        }
    }

    pub(crate) fn global_label(&self) -> Option<&str> {
        match self {
            VarTarget::Local(_) => None,
            VarTarget::Global(l) => Some(l.as_str()),
        }
    }
}

impl CodeGenerator {
    pub(crate) fn ensure_global_var_label(&mut self, name: &str) {
        if self.global_var_labels.contains_key(name) {
            return;
        }
        let label = format!("gvar_{}", self.global_var_counter);
        self.global_var_counter += 1;
        self.global_var_labels.insert(name.to_string(), label.clone());
        // A thing global's label reserves the thing's whole size and IS its
        // storage - field offsets index into it (plan 310 §9). Every other
        // global holds one quadword: a scalar's value, or a pointer to a
        // buffer/list/map allocated elsewhere.
        match self.thing_global_size(name) {
            Some(size) => self.bss_section.push_str(&format!(
                "    {}: resb {}  ; {} is a thing\n",
                label, size, name
            )),
            None => self.bss_section.push_str(&format!("    {}: resq 1\n", label)),
        }
    }

    pub(crate) fn global_var_label(&self, name: &str) -> Option<&String> {
        self.global_var_labels.get(name)
    }

    /// Lazily allocate (or return the existing) BSS label for a top-level
    /// `value` global's runtime tag byte. Named off the payload's own label
    /// so the two stay visibly paired in the emitted asm. Zero-filled BSS
    /// means an uninitialized tag defaults to `TAG_INTEGER` (0), matching
    /// the payload's own zero default - see the no-initializer VarDecl path.
    pub(crate) fn ensure_global_value_tag_label(&mut self, name: &str) -> String {
        if let Some(label) = self.global_value_tag_labels.get(name) {
            return label.clone();
        }
        let payload_label = self
            .global_var_label(name)
            .cloned()
            .unwrap_or_else(|| name.to_string());
        let label = format!("{}_tag", payload_label);
        self.global_value_tag_labels
            .insert(name.to_string(), label.clone());
        self.bss_section.push_str(&format!("    {}: resb 1\n", label));
        label
    }

    /// Assign bss mirror labels to every definitely-declared main-line
    /// name (see collect_definite_decls): an `Open ... called 'output'`
    /// present in BOTH arms of an if/otherwise still executes in _start's
    /// frame on every path, so functions must be able to reach it via its
    /// mirror global exactly like a top-level declaration. Uses the same
    /// walker as the analyzer so the two can never disagree. Names are
    /// sorted so label numbering stays deterministic across builds.
    pub(crate) fn collect_global_var_labels(&mut self, stmts: &[Statement]) {
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

    /// The declared type of every top-level name, collected before the walk
    /// that generates the program - the type half of what
    /// `collect_global_var_labels` does for storage (docs/BUGS_FOUND.md #66).
    ///
    /// The analyzer already resolves names whole-program: every top-level
    /// declaration is visible from the first statement, so a function body may
    /// read a global declared BELOW it and a name that is never declared is
    /// rejected outright. Codegen's `variable_types`, by contrast, was filled
    /// as the walk reached each declaration, so a function generated above the
    /// declaration had no type for the name and every read fell through to the
    /// integer printer: a `text` printed its rodata address, a `float` its
    /// IEEE-754 bits, a `list`/`buffer`/`map` a live heap address. That is the
    /// same order/type split #32 closed for flag types inside the analyzer;
    /// this closes it for ordinary globals inside codegen.
    ///
    /// Only DEFINITE declarations count - the same set that gets a bss mirror,
    /// so the type map and the storage map can never disagree about which
    /// names behave as globals. A name declared on only some path has no
    /// mirror and is not reachable from a function at all.
    pub(crate) fn collect_global_var_types(&mut self, stmts: &[Statement]) {
        let definite = collect_definite_decls(stmts);
        let mut typed: Vec<(String, Type)> = collect_all_typed_decls(stmts)
            .into_iter()
            .filter(|(name, _)| definite.contains_key(name))
            .collect();
        // Deterministic output across builds (a `value` allocates a bss label).
        typed.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, ty) in typed {
            if matches!(ty, Type::Value) {
                // A `value` read inside a function dispatches on its tag byte,
                // so the payload's type is useless without the tag's label.
                // Allocating it here rather than at the declaration keeps the
                // pair complete for a function generated above that
                // declaration; the label is derived from the payload's own, so
                // a declaration that reaches `ensure_global_value_tag_label`
                // later gets this same label back.
                self.ensure_global_value_tag_label(&name);
            }
            self.global_var_types.insert(name, ty);
        }
        // A list's ELEMENT type is inferred, never declared (the author picks
        // the data, the compiler picks the representation), so it is not in
        // `collect_all_typed_decls` and has to be read off the initializer -
        // the same reading the declaration itself does. Without it a forward
        // read of `names's first` on a list of texts still printed the
        // element's address. Top-level declarations only: a list declared in
        // both arms of an if/otherwise keeps today's answer (no element proof)
        // rather than one taken from a single arm.
        for stmt in stmts {
            let Statement::VarDecl { name, value: Some(value), .. } = stmt else { continue };
            if !definite.contains_key(name) {
                continue;
            }
            match value {
                Expr::ListLit { elements } => {
                    let elem = if self.mixed_lists.contains(name) {
                        // The pre-scan proved this list heterogeneous: element
                        // reads dispatch on the per-slot runtime tag.
                        Some(VarType::Mixed)
                    } else {
                        elements.first().map(list_literal_element_vartype)
                    };
                    if let Some(elem) = elem {
                        self.global_list_element_types.insert(name.clone(), elem);
                    }
                }
                // `arguments's all` / the raw argument list are lists of text.
                Expr::ArgumentAll | Expr::ArgumentRaw => {
                    self.global_list_element_types
                        .insert(name.clone(), VarType::String);
                }
                _ => {}
            }
        }
        // A flag's schema is a top-level declaration like any other, and #32
        // made the ANALYZER's flag types order-independent. Codegen's were not:
        // a flag read inside a function defined above its schema printed the
        // address of the flag's own default string.
        for stmt in stmts {
            if let Statement::FlagSchemaDecl { name, value_type, .. } = stmt {
                let ty = match value_type {
                    FlagValueType::Boolean => Type::Boolean,
                    FlagValueType::Number => Type::Integer,
                    FlagValueType::Text => Type::String,
                };
                self.global_var_types.insert(name.clone(), ty);
            }
        }
    }

    /// Give every global its declared type before a function body is
    /// generated, so a read inside that body is typed by the declaration
    /// wherever it sits in the file. Call at the top of a function's codegen,
    /// BEFORE its parameters and locals are registered, so a name the function
    /// binds itself still shadows the global exactly as it does today.
    ///
    /// A name already carrying a type keeps it: this only fills the gap left
    /// by a declaration the walk has not reached, so nothing about a global
    /// declared ABOVE the function changes.
    pub(crate) fn seed_global_var_types(&mut self) {
        let mut names: Vec<String> = self.global_var_types.keys().cloned().collect();
        names.sort();
        for name in names {
            if self.variable_types.contains_key(&name) {
                continue;
            }
            let ty = self.global_var_types[&name].clone();
            self.variable_types.insert(name.clone(), declared_vartype(&ty));
            self.declared_types.entry(name.clone()).or_insert(ty);
            if let Some(elem) = self.global_list_element_types.get(&name).cloned() {
                self.list_element_types.insert(name.clone(), elem);
            }
            self.forward_typed_globals.insert(name);
        }
    }

    /// Fix a name's type from the value that brings it into being. A
    /// declaration that names no type still declares - `NAME is <value>.`,
    /// `the NAME is <value>.` and `Set NAME to <value>.` all do, on a name
    /// that does not exist yet - and the name is then an ordinary
    /// statically-typed one (LANGUAGE.md "Two Canonical Forms").
    ///
    /// Nothing recorded that type, so the slot carried none: every read of
    /// it went to the integer formatter, which is how `Set t to "hello".
    /// Print t.` printed the string's ADDRESS and a map printed its struct
    /// pointer; and `t's type` fell through to the runtime-tag dispatch,
    /// answering `(dynamic)` off a tag byte nothing but a `value` ever
    /// writes (docs/BUGS_FOUND.md #95). Both halves are recorded here, so
    /// such a name renders and reports its type exactly as `a <type> called
    /// NAME is <value>.` does.
    ///
    /// Only ever fills a gap: a name that already carries a type keeps it,
    /// so this can never retag a slot out from under an earlier read.
    pub(crate) fn declare_untyped_from_value(&mut self, name: &str, value: &Expr) {
        if self.variable_types.contains_key(name) {
            return;
        }
        let Some(inferred) = self.infer_expr_type(value) else {
            return;
        };
        let declared = match inferred {
            // `true`/`false` infer as `Integer` because a boolean is stored
            // as 0/1, but the name IS a boolean and `name's type` must say
            // `Boolean (static)`, exactly as the declared spelling does.
            VarType::Integer if matches!(value, Expr::BoolLit(_)) => Type::Boolean,
            VarType::Integer => Type::Integer,
            VarType::Float => Type::Float,
            VarType::String => Type::String,
            VarType::Boolean => Type::Boolean,
            // Element and value types are not written down in an untyped
            // declaration, which is the same thing `a list called xs is
            // [...]` records - Vox source has no typed-collection syntax.
            VarType::List => Type::List(Box::new(Type::Unknown)),
            VarType::Map => Type::Map(Box::new(Type::Unknown)),
            // A buffer name reaches its storage through its own paths, and
            // the other two mean "not known statically" - which is what an
            // unlabelled slot already says. Left exactly as they were.
            VarType::Buffer | VarType::Mixed | VarType::Unknown => return,
        };
        self.variable_types
            .insert(name.to_string(), vartype_of_declared_type(&declared));
        self.declared_types.insert(name.to_string(), declared);
    }

    /// Frame setup for the forward case of `docs/BUGS_FOUND.md` #25: a global
    /// whose type a function body had to take from the declaration below it is
    /// now read AS that type, so the window before the declaration executes -
    /// a call placed above it - must not hand a pointer type the zero its bss
    /// mirror starts life with. Write the type's empty value first, exactly as
    /// #25 does for a name declared inside a body that may never run.
    ///
    /// Only the pointer types need it. A `number`, `float` or `boolean` reads
    /// its zero as 0, 0.0 and false, which are the right defaults already.
    pub(crate) fn emit_forward_global_defaults(&mut self) {
        let mut names: Vec<String> = self.forward_typed_globals.iter().cloned().collect();
        names.sort();
        for name in names {
            let Some(ty) = self.global_var_types.get(&name).cloned() else { continue };
            if !matches!(
                ty,
                Type::String | Type::Buffer | Type::List(_) | Type::Map(_) | Type::Value
            ) {
                continue;
            }
            let Some(label) = self.global_var_label(&name).cloned() else { continue };
            self.emit_type_default(&ty, &VarTarget::Global(label), &name);
        }
    }

    pub(crate) fn emit_mirror_stack_var_to_global_if_needed(&mut self, name: &str, offset: i64) {
        if !self.in_function_codegen {
            if let Some(label) = self.global_var_label(name).cloned() {
                self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                self.emit_indent(&format!("mov [rel {}], rax", label));
            }
        }
    }

    pub(crate) fn emit_load_named_var_into_rax(&mut self, name: &str) -> bool {
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
    pub(crate) fn emit_load_named_var_addr(&mut self, name: &str) -> bool {
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

    /// Store a (possibly reallocated) pointer back to a named variable,
    /// resolving the name through the local function frame first and then
    /// through the global BSS mirror. At top level, stack variables are also
    /// mirrored to their global label so branch and function bodies see the
    /// updated value.
    pub(crate) fn emit_store_back_after_realloc(&mut self, name: &str, new_ptr_reg: &str) -> bool {
        if let Some(offset) = self.get_var(name) {
            self.emit_indent(&format!(
                "mov [rbp-{}], {}  ; store new pointer for {}",
                offset, new_ptr_reg, name
            ));
            // A `buffer` parameter's slot is only the callee's copy; the
            // caller's own copy has to follow the reallocation in the same
            // breath or it is left pointing at freed memory (#90). A no-op
            // for every other name, including a `list` or `map`.
            self.emit_buffer_param_cell_writeback(offset, new_ptr_reg);
            // BUGS_FOUND #75: a `list`/`map` parameter's slot is this frame's
            // copy of a pointer the CALLER also holds. Writing only here left
            // the caller pointing at the block the collection outgrew, so
            // every append past its capacity was dropped and its block leaked.
            // The parameter's word is the address of the caller's storage
            // (see `emit_collection_argument_address`); write the new pointer
            // through it too. rbx is callee-saved and never a `new_ptr_reg`,
            // and nothing between the push and the pop touches the stack.
            if let Some(back_slot) = self.collection_backing_slots.get(name).copied() {
                self.emit_indent("push rbx");
                self.emit_indent(&format!(
                    "mov rbx, [rbp-{}]  ; where the caller keeps {}",
                    back_slot, name
                ));
                self.emit_indent(&format!("mov [rbx], {}  ; the caller grows too", new_ptr_reg));
                self.emit_indent("pop rbx");
            }
            self.emit_mirror_stack_var_to_global_if_needed(name, offset);
            true
        } else if let Some(label) = self.global_var_label(name).cloned() {
            self.emit_indent(&format!(
                "mov [rel {}], {}  ; store new pointer for {}",
                label, new_ptr_reg, name
            ));
            true
        } else {
            false
        }
    }

    pub(crate) fn emit_store_rax_to_target(&mut self, target: &VarTarget, name: &str) {
        match target {
            VarTarget::Local(offset) => {
                self.emit_indent(&format!("mov [rbp-{}], rax  ; store {}", offset, name));
            }
            VarTarget::Global(label) => {
                self.emit_indent(
                    &format!("mov [rel {}], rax  ; global store {}", label, name),
                );
            }
        }
    }

    pub(crate) fn add_string(&mut self, s: &str) -> String {
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

    // Returns the shared empty-string label, creating it on first use.
    pub(crate) fn get_empty_string_label(&mut self) -> String {
        if let Some(label) = &self.empty_string_label {
            return label.clone();
        }
        let label = self.add_string("");
        self.empty_string_label = Some(label.clone());
        label
    }

    /// `docs/BUGS_FOUND.md #26`: a positional `arguments`/`environment`
    /// accessor (`first`, `second`, `last`, `at N`) is backed by a coreasm
    /// lookup (`_get_arg`, `_get_parsed_arg`, `_get_env_at`) that already
    /// returns a NULL pointer when the index is out of range - the same
    /// shape `_get_env` has for a missing name, which `Expr::EnvironmentVariable`
    /// (BUGS_FOUND #24) already handles this way. Call this immediately
    /// after such a lookup, with the result still in `rax`: on NULL it sets
    /// `_last_error` and substitutes the shared empty-text pointer so the
    /// read behaves like every other fallible read (`On error` catches it,
    /// nothing dereferences 0); on a real pointer it just clears the flag.
    /// `label_prefix` only needs to be unique per call site.
    pub(crate) fn emit_text_or_empty_on_null(&mut self, label_prefix: &str) {
        let missing_label = self.new_label(&format!("{}_missing", label_prefix));
        let done_label = self.new_label(&format!("{}_done", label_prefix));
        self.emit_indent("test rax, rax");
        self.emit_indent(&format!("jz {}  ; out of range", missing_label));
        self.emit_indent("CLEAR_LAST_ERROR  ; in range");
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", missing_label));
        let empty_label = self.get_empty_string_label();
        self.emit_indent(&format!(
            "lea rax, [rel {}]  ; empty text for out-of-range positional read", empty_label));
        self.emit_indent("SET_LAST_ERROR 1  ; out of range");
        self.emit(&format!("{}:", done_label));
        self.uses_strings = true;
    }

    /// The empty value of a pointer-typed slot, left in `rax`: the shared
    /// empty text, a freshly allocated empty list, or a freshly allocated
    /// empty map. This is the value half of `emit_type_default`
    /// (`docs/BUGS_FOUND.md #25`) — the same value a no-initializer
    /// `a text called t.` / `a list called xs.` / `a map called m.` writes —
    /// factored out so a fallible read that misses can hand a slot exactly
    /// what an unwritten slot already holds (#91). Returns `false` (emitting
    /// nothing) for every other type, whose empty value is the number 0 and
    /// is never dereferenced.
    pub(crate) fn emit_empty_value_for(&mut self, t: VarType) -> bool {
        match t {
            VarType::String => {
                let label = self.get_empty_string_label();
                self.emit_indent(&format!(
                    "lea rax, [rel {}]  ; empty text", label));
                self.uses_strings = true;
                true
            }
            VarType::List => {
                self.generate_expr(&Expr::ListLit { elements: vec![] });
                true
            }
            VarType::Map => {
                self.generate_expr(&Expr::MapLit { pairs: vec![] });
                true
            }
            _ => false,
        }
    }

    /// `docs/BUGS_FOUND.md #91`. A fallible collection read — `element N of`,
    /// `<map>'s <key>`, `<list>'s first`/`last` — yields the number 0 on a
    /// miss (LANGUAGE.md: "the lookup yields 0 and sets the error flag",
    /// "Out-of-bounds access sets an error flag and returns 0"). Where the
    /// miss is provable, #72 rejects the program; where it is not — a
    /// variable index, a dynamic key, an `Append`-grown or non-literal
    /// collection — the 0 reaches the destination, and a `text`/`list`/`map`
    /// destination dereferences it as a pointer on the first read.
    ///
    /// Call this with the read's result still in `rax` and the destination's
    /// own type in `slot`: on a miss the slot takes its type's empty value
    /// instead of the raw 0, which is what every *other* way of leaving such
    /// a slot unwritten already does (`emit_type_default`, #25). The error
    /// flag is left exactly as the read set it, so `On error` still fires.
    pub(crate) fn emit_empty_value_if_missed(&mut self, expr: &Expr, slot: Option<VarType>) {
        let slot = match slot {
            Some(t @ (VarType::String | VarType::List | VarType::Map)) => t,
            _ => return,
        };
        if !is_fallible_collection_read(expr) {
            return;
        }
        let done_label = self.new_label("miss_empty_done");
        self.emit_indent("; #91: a missed collection read must not enter a pointer slot as 0");
        self.emit_indent("test rax, rax");
        self.emit_indent(&format!("jnz {}", done_label));
        self.emit_empty_value_for(slot);
        self.emit(&format!("{}:", done_label));
    }

    pub(crate) fn add_float(&mut self, f: f64) -> String {
        let label = format!("float_{}", self.float_counter);
        self.float_counter += 1;
        
        // Store as 64-bit IEEE 754 double
        let bits = f.to_bits();
        self.data_section.push_str(&format!("    {}: dq 0x{:016X}  ; {}\n", label, bits, f));
        label
    }

    /// Emit the type's default value into `target`: the same code a
    /// no-initializer declaration (`a text called x.`) has always emitted,
    /// factored out so a conditionally-declared name (While/On error/for
    /// each/Repeat body - docs/BUGS_FOUND.md #25, plan 318 §1) can get the
    /// identical default written at frame setup, before the declaration it
    /// belongs to is known to have run at all.
    pub(crate) fn emit_type_default(&mut self, t: &Type, target: &VarTarget, name: &str) {
        match t {
            Type::Buffer => {
                // Allocate an empty buffer with proper initialization
                self.emit_indent("mov rdi, 1024  ; default buffer size");
                self.emit_indent("call _alloc_buffer");
                self.emit_store_rax_to_target(target, &format!("buffer {}", name));
                self.uses_buffers = true;
                if target.global_label().is_some() {
                    self.initialized_globals.insert(name.to_string());
                }
            }
            Type::List(_) => {
                // Allocate an empty list; a null pointer here
                // would make the first append dereference 0.
                self.emit_empty_value_for(VarType::List);
                self.emit_store_rax_to_target(target, &format!("list {}", name));
            }
            Type::Map(_) => {
                // Allocate an empty map so printing yields "{}"
                // instead of dereferencing a null pointer.
                self.emit_empty_value_for(VarType::Map);
                self.emit_store_rax_to_target(target, &format!("map {}", name));
            }
            Type::Float => {
                self.generate_expr(&Expr::FloatLit(0.0));
                self.emit_store_rax_to_target(target, &format!("float {}", name));
            }
            Type::String => {
                // A null pointer here makes the first read
                // (print, interpolation, 's length, ...)
                // dereference 0. Point at a real, shared
                // empty string instead.
                self.emit_empty_value_for(VarType::String);
                self.emit_store_rax_to_target(target, &format!("text {}", name));
            }
            Type::Value => {
                // An uninitialized `value` holds `nothing`, not
                // the number 0.  The payload is zero; the tag
                // must be TAG_NOTHING.
                self.emit_indent("mov rax, 0  ; nothing payload");
                self.emit_store_rax_to_target(target, &format!("value {}", name));
                if let Some(&tag_slot) = self.mixed_tag_slots.get(name) {
                    if target.local_offset().is_some() {
                        self.emit_indent(&format!(
                            "mov byte [rbp-{}], {}  ; value local tag = nothing",
                            tag_slot, TAG_NOTHING
                        ));
                    }
                } else if let Some(tag_label) = self.global_value_tag_labels.get(name).cloned() {
                    self.emit_indent(&format!(
                        "mov byte [rel {}], {}  ; value global tag = nothing",
                        tag_label, TAG_NOTHING
                    ));
                }
            }
            _ => {
                // Initialize to 0/null
                self.emit_indent("xor rax, rax");
                self.emit_store_rax_to_target(target, name);
            }
        }
    }

    /// Frame setup for `docs/BUGS_FOUND.md #25` (plan 318 §1): a name
    /// declared inside `On error`, `While`, `for each`, or `Repeat` stays
    /// in scope for the rest of `stmts` whether or not that body ever ran
    /// (LANGUAGE.md:526 - no block scoping), but nothing wrote its slot on
    /// the zero-execution path - a `number` reads a neighbouring frame's
    /// leftover value, a `text`/`buffer`/`list`/`map` reads a wild pointer
    /// and segfaults.
    ///
    /// `collect_definite_decls` is the analyzer's own proof of which names
    /// are guaranteed initialized by the end of `stmts`; every OTHER typed
    /// declaration found anywhere in `stmts` (`collect_all_typed_decls`)
    /// gets its type's default written here, unconditionally, before any
    /// of `stmts`' real code runs. When the declaring statement's own path
    /// DOES execute, its ordinary VarDecl/BufferDecl codegen overwrites
    /// this default with the real initializer (or re-writes the same
    /// default) exactly as before - a taken path still stores what it
    /// always stored.
    ///
    /// Call once per frame: with the top-level program's statements before
    /// its body is appended, and with a function's body statements before
    /// ITS body is appended. Must run after whatever pass already visited
    /// `stmts` for real (so a slot already exists for every name - the
    /// analyzer's own walk registers one for any non-definite declaration
    /// exactly like a branch-only one), which is why every call site below
    /// generates this into its own buffer and splices it in ahead of the
    /// already-generated body rather than emitting it inline during that
    /// walk.
    pub(crate) fn emit_conditional_decl_defaults(&mut self, stmts: &[Statement]) {
        let definite = collect_definite_decls(stmts);
        let all_typed = collect_all_typed_decls(stmts);
        let mut conditional: Vec<(&String, &Type)> = all_typed
            .iter()
            .filter(|(name, _)| !definite.contains_key(name.as_str()))
            .collect();
        // Deterministic output across builds.
        conditional.sort_by(|a, b| a.0.cmp(b.0));
        for (name, ty) in conditional {
            let offset = self.get_var(name).unwrap_or_else(|| self.alloc_var(name));
            let target = VarTarget::Local(offset);
            self.emit_type_default(ty, &target, name);
            self.emit_mirror_stack_var_to_global_if_needed(name, offset);
        }
    }

    pub(crate) fn alloc_var(&mut self, name: &str) -> i64 {
        self.stack_offset += 8;
        self.variables.insert(name.to_string(), self.stack_offset);
        self.stack_offset
    }

    pub(crate) fn get_var(&self, name: &str) -> Option<i64> {
        self.variables.get(name).copied()
    }

    pub(crate) fn collect_global_constants(&mut self, program: &Program) {
        self.global_constants.clear();
        for stmt in &program.statements {
            if let Statement::VarDecl { name, value: Some(expr), .. } = stmt {
                if matches!(expr, Expr::StringLit(_) | Expr::IntegerLit(_) | Expr::BoolLit(_)) {
                    self.global_constants.insert(name.clone(), expr.clone());
                }
            }
        }
    }

}

/// The storage class a declared type is read as. The declaration is the
/// authority - LANGUAGE.md: "A variable's type is fixed at its declaration and
/// never changes" - so a global's read site takes its answer from here rather
/// than from whatever the walk has inferred so far.
pub(crate) fn declared_vartype(t: &Type) -> VarType {
    match t {
        Type::String => VarType::String,
        Type::Integer => VarType::Integer,
        Type::Float => VarType::Float,
        Type::Boolean => VarType::Boolean,
        Type::Buffer => VarType::Buffer,
        Type::List(_) => VarType::List,
        Type::Map(_) => VarType::Map,
        // A `value` is a Mixed-typed scalar carrying its runtime tag beside
        // the payload, exactly like a value parameter or a for-each variable.
        Type::Value => VarType::Mixed,
        _ => VarType::Unknown,
    }
}

/// The element type a list literal's first element proves for the whole list.
/// Read at the declaration, and again by `collect_global_var_types` for a
/// top-level list, so a function generated above that declaration reads its
/// elements as the same type the declaration itself would give them (#66).
pub(crate) fn list_literal_element_vartype(first: &Expr) -> VarType {
    match first {
        Expr::StringLit(_) => VarType::String,
        // A format string always materializes text (bug #17); this named-list
        // element-type inference never carried that arm (bug #39).
        Expr::FormatString { .. } => VarType::String,
        Expr::IntegerLit(_) => VarType::Integer,
        Expr::FloatLit(_) => VarType::Float,
        Expr::BoolLit(_) => VarType::Boolean,
        // A nested list literal element means this is a list-of-lists; the
        // element type is List (stage 1e1), so a for-each loop var prints via
        // `_list_print`.
        Expr::ListLit { .. } => VarType::List,
        _ => VarType::Unknown,
    }
}
