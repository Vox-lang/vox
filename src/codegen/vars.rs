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

    /// The memory operand that names this storage.
    pub(crate) fn operand(&self) -> String {
        match self {
            VarTarget::Local(offset) => format!("[rbp-{}]", offset),
            VarTarget::Global(label) => format!("[rel {}]", label),
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
            Some(size) => {
                self.bss_section.push_str(&format!(
                    "    {}: resb {}  ; {} is a thing\n",
                    label, size, name
                ));
                if let Some(thing) = self.thing_of_variable(name) {
                    self.register_collection_fields(name, &thing);
                }
            }
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

    /// Lazily allocate (or return the existing) BSS label for a
    /// `freeable_texts` global's runtime ownership-flag byte, paired with
    /// the payload label exactly as `ensure_global_value_tag_label` pairs a
    /// `value`'s tag (docs/BUGS_FOUND.md #108). Zero-filled BSS means an
    /// uninitialized flag defaults to "not owned", matching the payload's
    /// own zero default (an uninitialised text global) and matching a fresh
    /// declaration's initial value - see `emit_owned_text_global_store`.
    pub(crate) fn ensure_global_text_owned_label(&mut self, name: &str) -> String {
        if let Some(label) = self.global_text_owned_labels.get(name) {
            return label.clone();
        }
        let payload_label = self
            .global_var_label(name)
            .cloned()
            .unwrap_or_else(|| name.to_string());
        let label = format!("{}_owned", payload_label);
        self.global_text_owned_labels
            .insert(name.to_string(), label.clone());
        self.bss_section.push_str(&format!("    {}: resb 1\n", label));
        label
    }

    /// True if `source`, written into a text slot by `generate_expr_as_text`,
    /// allocates a string this write EXCLUSIVELY owns: a format-string
    /// evaluation, or an `as text`/bare conversion that copies a buffer's or
    /// a scalar's bytes into a brand-new buffer (docs/BUGS_FOUND.md #108,
    /// the runtime half of the ownership design). Every other source -
    /// another text variable, a parameter, a literal, a list/map read, a
    /// function result - hands back a pointer this write does not own, even
    /// one that happens to answer `Some(VarType::Buffer)` by inferred type:
    /// `generate_expr_as_text` copies EVERY buffer-typed source into a fresh
    /// buffer before it reaches a text slot (`emit_buffer_to_text_copy`),
    /// whatever expression shape produced it, so the inferred-type check
    /// below is exactly as safe as checking the expression shape would be.
    ///
    /// A `Cast` to `Type::String` is the one shape that can go EITHER way:
    /// `t2 as text` on an already-text `t2` is a bare pointer copy (not
    /// owned, matching `generate_expr`'s Cast/String branch, which leaves a
    /// text source untouched), while `n as text` on a number/float/boolean
    /// or `b as text` on a buffer always allocates fresh (owned).
    pub(crate) fn text_write_is_owned(&self, source: &Expr) -> bool {
        match source {
            Expr::FormatString { .. } => true,
            Expr::Cast { target_type: Type::String, value, .. } => {
                !matches!(self.infer_expr_type(value), Some(VarType::String))
            }
            _ => matches!(self.infer_expr_type(source), Some(VarType::Buffer)),
        }
    }

    /// The write half of docs/BUGS_FOUND.md #108, for a GLOBAL (BSS-
    /// resident) text variable the whole-program `freeable_texts` scan has
    /// proven never shared. `rax` already holds the freshly computed
    /// replacement value (from `generate_expr_as_text`); the OLD pointer is
    /// still sitting in the payload mirror, untouched, when this is called.
    ///
    /// Sequence: save the new value (the accumulate idiom - `Set acc to
    /// "{acc}x"` - reads the old string while building the new one, so the
    /// old pointer must not move before that read finishes, and this runs
    /// after it has); if the OWNED flag says the current pointer is this
    /// variable's own, free it (struct = data pointer - `BUF_DATA_OFFSET`,
    /// `_free_buffer` clears its buffer-record entry if it has one and always
    /// munmaps, docs/BUGS_FOUND.md #108's coreasm half); store the new
    /// value; set the flag from the new value's own provenance. A BSS flag
    /// starts zero-filled ("not owned"), so the very first write to a given
    /// global - the declaration itself - takes this exact path safely: the
    /// flag check reads 0, the free is skipped, and only the flag write
    /// happens.
    ///
    /// Global-only (see `global_text_owned_labels`'s doc comment): a LOCAL
    /// freeable text keeps the plain, unconditional store it always had.
    pub(crate) fn emit_owned_text_global_store(&mut self, name: &str, label: &str, source: &Expr) {
        self.uses_buffers = true;
        let flag_label = self.ensure_global_text_owned_label(name);
        self.emit_indent(&format!(
            "push rax  ; new value for {}, across its old one's free check", name));
        let skip_label = self.new_label("text_not_owned");
        self.emit_indent(&format!(
            "cmp byte [rel {}], 0  ; was the current {} owned?", flag_label, name));
        self.emit_indent(&format!("je {}", skip_label));
        self.emit_indent(&format!(
            "mov rdi, [rel {}]  ; the string {} no longer holds", label, name));
        self.emit_indent(&format!(
            "sub rdi, {}  ; text data pointer -> its buffer struct", BUF_DATA_OFFSET));
        self.emit_indent("call _free_buffer  ; docs/BUGS_FOUND.md #108");
        self.emit(&format!("{}:", skip_label));
        self.emit_indent("pop rax  ; restore the new value");
        self.emit_indent(&format!("mov [rel {}], rax", label));
        let owned: u8 = if self.text_write_is_owned(source) { 1 } else { 0 };
        self.emit_indent(&format!(
            "mov byte [rel {}], {}  ; {} owned flag", flag_label, owned, name));
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

    /// A top-level list, map or buffer lives in its `.bss` label alone. A
    /// variable of another type declared under the same name earlier, in a
    /// branch (a file opened inside an `If`), left a frame slot behind; that
    /// slot was the other variable's, so the declaration lets go of it and
    /// takes the label.
    pub(crate) fn forget_frame_slot_of_another_type(&mut self, name: &str, declared: &Type) {
        if self.in_function_codegen
            || !matches!(declared, Type::List(_) | Type::Map(_) | Type::Buffer)
            || !self.variables.contains_key(name)
            || self.global_var_label(name).is_none()
        {
            return;
        }
        let same_type = self
            .declared_types
            .get(name)
            .is_some_and(|before| std::mem::discriminant(before) == std::mem::discriminant(declared));
        if !same_type {
            self.variables.remove(name);
        }
    }

    /// A file opened in a branch at the top level has a frame slot, mirrored
    /// into the name's global label so functions can reach it. A top-level
    /// list, map or buffer declared under the same name further down owns
    /// that label: the two are different variables, so the file keeps to
    /// its slot and leaves the label to its owner.
    pub(crate) fn emit_mirror_file_to_global(&mut self, name: &str, offset: i64) {
        if matches!(
            self.global_var_types.get(name),
            Some(Type::List(_) | Type::Map(_) | Type::Buffer)
        ) || matches!(
            self.variable_types.get(name),
            Some(VarType::List | VarType::Map | VarType::Buffer)
        ) {
            return;
        }
        self.emit_mirror_stack_var_to_global_if_needed(name, offset);
    }

    pub(crate) fn emit_mirror_stack_var_to_global_if_needed(&mut self, name: &str, offset: i64) {
        if !self.in_function_codegen {
            if let Some(label) = self.global_var_label(name).cloned() {
                // One owning place: a list, map or buffer is held by exactly
                // one word. A top-level one lives in its `.bss` label alone,
                // so a frame slot mirrored into that label would be a second
                // holder, the shape that let a function grow or free a buffer
                // the top level then read from its stale slot.
                assert!(
                    !matches!(
                        self.variable_types.get(name),
                        Some(VarType::List | VarType::Map | VarType::Buffer)
                    ),
                    "internal compiler error: the {} '{}' would have two holders, \
                     a frame slot and its global label",
                    match self.variable_types.get(name) {
                        Some(VarType::List) => "list",
                        Some(VarType::Map) => "map",
                        _ => "buffer",
                    },
                    name
                );
                self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                self.emit_indent(&format!("mov [rel {}], rax", label));
            }
        }
    }

    /// True when the frame slot at `offset` holds a cell: the address of the
    /// word that owns a `list`, `map` or `buffer` parameter's collection.
    pub(crate) fn is_cell_slot(&self, offset: i64) -> bool {
        self.cell_slots.contains(&offset)
    }

    /// Load into `reg` what the variable in the slot at `offset` holds. For a
    /// cell, that is the block the owning word holds NOW, read through the
    /// cell at this point of use: a parameter never keeps a copy of it.
    pub(crate) fn emit_load_slot(&mut self, reg: &str, offset: i64) {
        if self.is_cell_slot(offset) {
            self.emit_indent(&format!("mov {}, [rbp-{}]  ; cell: where the owner keeps it", reg, offset));
            self.emit_indent(&format!("mov {0}, [{0}]  ; the collection, as it is now", reg));
        } else {
            self.emit_indent(&format!("mov {}, [rbp-{}]", reg, offset));
        }
    }

    /// Store `reg` into the variable in the slot at `offset`. For a cell, the
    /// store lands in the owning word, so the caller's variable (and every
    /// other name of it) holds the new block from this moment on. Changes no
    /// register and no flag.
    pub(crate) fn emit_store_slot(&mut self, offset: i64, reg: &str) {
        if self.is_cell_slot(offset) {
            let scratch = if reg == "rbx" { "rcx" } else { "rbx" };
            self.emit_indent(&format!("push {}", scratch));
            self.emit_indent(&format!("mov {}, [rbp-{}]  ; cell: where the owner keeps it", scratch, offset));
            self.emit_indent(&format!("mov [{}], {}  ; the owner holds the new block", scratch, reg));
            self.emit_indent(&format!("pop {}", scratch));
        } else {
            self.emit_indent(&format!("mov [rbp-{}], {}", offset, reg));
        }
    }

    /// Leave in `reg` the address of the word that owns the variable in the
    /// slot at `offset`: the slot itself, or, for a cell, the word it names.
    /// This is what a `list`, `map` or `buffer` argument carries, so a name
    /// that is itself a parameter passes its owner on, however deep the calls.
    pub(crate) fn emit_slot_owner_address(&mut self, reg: &str, offset: i64) {
        if self.is_cell_slot(offset) {
            self.emit_indent(&format!("mov {}, [rbp-{}]  ; cell: the owner's address, passed on", reg, offset));
        } else {
            self.emit_indent(&format!("lea {}, [rbp-{}]", reg, offset));
        }
    }

    pub(crate) fn emit_load_named_var_into_rax(&mut self, name: &str) -> bool {
        if let Some(offset) = self.get_var(name) {
            self.emit_load_slot("rax", offset);
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
            self.emit_load_slot("rax", offset);
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
    /// through the global BSS label. A parameter's store goes through its
    /// cell into the owning word (`emit_store_slot`), so growth or `Free`
    /// through a parameter is the owner's growth or `Free` at that moment.
    pub(crate) fn emit_store_back_after_realloc(&mut self, name: &str, new_ptr_reg: &str) -> bool {
        if let Some(offset) = self.get_var(name) {
            self.emit_store_slot(offset, new_ptr_reg);
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
                self.emit_store_slot(*offset, "rax");
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
        // No string.asm routine is called here: the empty-text pointer is a
        // shared .data label (get_empty_string_label -> add_string ""), so
        // uses_strings must not be set (audit rec 6).
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
                // Shared .data label, not a string.asm routine (audit rec 6).
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

    /// docs/BUGS_FOUND.md #115, generalising #114 (owner ruling 2026-08-30)
    /// from its one landing site (`MapAccess`) to every expression whose
    /// value carries a runtime-only type tag (`expr_has_runtime_only_tag`,
    /// `src/codegen/tags.rs`): a `value` identifier, an element/first/last of
    /// a mixed list, a `treating` clause dispatching at runtime, a
    /// `value`-returning call, or a map key read. None of these has a type
    /// `infer_expr_type` can prove, so reading one into a scalar-typed
    /// destination whose declared type does not match the payload's actual
    /// runtime type used to hand the raw bits straight into the slot - a
    /// `547` landing in a `text` slot is then dereferenced as a `char*` on
    /// first string use and segfaults, and a pointer landing in a `number`
    /// slot prints as a raw address. A LITERAL source catches a mismatch
    /// statically (`check_declared_read_type`); a dynamic one cannot, so the
    /// answer has to be a runtime one, exactly like #91's miss handling.
    ///
    /// The owner's #114 ruling generalises the same way: this is not an
    /// error, it is an implicit cast to the destination's declared type,
    /// exactly what an explicit `<value> as a <type>` already does for a
    /// `value` variable (`emit_scalar_cast_from_runtime_tag`, shared with
    /// this). Call with the read's result already in `rax` (r11 need not be
    /// loaded yet - this loads it itself, immediately after any miss check,
    /// so no intervening call may clobber either register).
    ///
    /// A miss (`rax == 0`) only exists for a *fallible collection read*
    /// (`is_fallible_collection_read`: `MapAccess`, `ElementAccess`,
    /// `ListAccess`, `first`/`last` of a mixed list) and is deliberately left
    /// untouched here, falling through to `emit_empty_value_if_missed`,
    /// called right after this at every one of this function's call sites: a
    /// miss's tag is always `TAG_INTEGER` with payload 0, indistinguishable
    /// from a genuinely stored integer 0, and casting that through this
    /// switch would turn "absent key into a text" into the text `"0"`
    /// instead of #91's empty text. A `value` identifier or a
    /// `value`-returning call has no such ambiguity - there is no lookup to
    /// miss, so a `0` payload is always cast like any other.
    ///
    /// Returns whether the scalar cast actually ran (a matching `slot` on a
    /// runtime-tagged `expr`). On BOTH its outcomes - a defined conversion or
    /// `emit_scalar_cast_from_runtime_tag`'s own "no defined cast" fallback
    /// (empty text, or 0/0.0/false, never a raw pointer or unconverted bit
    /// pattern) - the destination is left holding a value that genuinely,
    /// safely matches its declared scalar type. A caller writing into a
    /// NAMED variable should use this to drop that name from
    /// `unprovable_scalars` (`src/codegen/collections.rs`'s pre-scan): that
    /// set exists because a declared type used to not describe what a slot
    /// actually held, and this call is what now makes it describe it again.
    pub(crate) fn emit_dynamic_value_cast_if_needed(&mut self, expr: &Expr, slot: Option<VarType>) -> bool {
        if !self.expr_has_runtime_only_tag(expr) {
            return false;
        }
        let target_type = match slot {
            Some(VarType::Integer) => Type::Integer,
            Some(VarType::Float) => Type::Float,
            Some(VarType::String) => Type::String,
            Some(VarType::Boolean) => Type::Boolean,
            _ => return false,
        };
        self.emit_indent("; #115: a dynamically-typed value is cast to its destination's type");
        if is_fallible_collection_read(expr) {
            let done_label = self.new_label("dyn_cast_done");
            self.emit_indent("test rax, rax");
            self.emit_indent(&format!("jz {}  ; a miss: #91 gives the destination's empty value next", done_label));
            self.emit_load_value_tag(expr);
            self.emit_scalar_cast_from_runtime_tag(&target_type);
            self.emit(&format!("{}:", done_label));
        } else {
            self.emit_load_value_tag(expr);
            self.emit_scalar_cast_from_runtime_tag(&target_type);
        }
        true
    }

    /// docs/BUGS_FOUND.md #115, the collection half of the same
    /// generalisation (an assumption flagged for the owner, unchanged
    /// from #114). `<number> as a list` has no defined meaning - unlike the
    /// four scalar casts above, there is no existing lowering to reuse - so a
    /// dynamically-typed value whose runtime tag is not the destination
    /// collection's own tag raises the error flag and yields that
    /// destination's empty value (`emit_empty_value_for`, shared with #91's
    /// miss handling) rather than storing a scalar payload where every later
    /// list/map op expects a heap pointer.
    ///
    /// A genuine miss (`rax == 0`) on a fallible collection read is left to
    /// `emit_empty_value_if_missed`, called right after this at every call
    /// site, for the same indistinguishable-from-a-real-zero reason
    /// `emit_dynamic_value_cast_if_needed` documents; this only guards the
    /// non-zero, wrong-tag case that miss handling does not reach
    /// (`_map_lookup`'s `emit_copy_if_collection_reg` already copies a
    /// correctly-tagged list/map value, so the matching-tag path here is a
    /// no-op). A non-collection-read source (a `value` identifier, a
    /// `value`-returning call) has no miss to skip and is always checked.
    pub(crate) fn emit_dynamic_value_collection_guard(&mut self, expr: &Expr, slot: Option<VarType>) {
        if !self.expr_has_runtime_only_tag(expr) {
            return;
        }
        let (slot, expect_tag) = match slot {
            Some(VarType::List) => (VarType::List, TAG_LIST),
            Some(VarType::Map) => (VarType::Map, TAG_MAP),
            _ => return,
        };
        let done_label = self.new_label("dyn_cast_collection_done");
        self.emit_indent("; #115: a dynamic value with no defined cast into this collection slot");
        if is_fallible_collection_read(expr) {
            self.emit_indent("test rax, rax");
            self.emit_indent(&format!("jz {}  ; a miss: #91 handles it next", done_label));
        }
        self.emit_load_value_tag(expr);
        self.emit_indent(&format!("cmp r11, {}", expect_tag));
        self.emit_indent(&format!("je {}", done_label));
        self.emit_indent("SET_LAST_ERROR 1");
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
            // A parameter's cell is the caller's, never a default's to fill:
            // a declaration of its name made only on some path names a
            // collection of its own, which exists only on that path.
            if self.is_cell_slot(offset) {
                continue;
            }
            let target = VarTarget::Local(offset);
            self.emit_type_default(ty, &target, name);
            self.emit_mirror_stack_var_to_global_if_needed(name, offset);
        }
    }

    /// The slot a declaration gets when it gives a name a new meaning inside
    /// a function: a parameter's name (never its cell), a top-level name
    /// (shadowed), or an outer local of another type. One slot per name per
    /// function, shared by every such declaration (one is live at a time),
    /// so a name declared in every branch of an `If` names one variable
    /// after it.
    pub(crate) fn fresh_slot_for_redeclared_parameter(&mut self, name: &str) -> i64 {
        let slot = match self.redeclared_parameter_slots.get(name) {
            Some(&slot) => slot,
            None => {
                self.stack_offset += 8;
                self.redeclared_parameter_slots.insert(name.to_string(), self.stack_offset);
                self.stack_offset
            }
        };
        self.variables.insert(name.to_string(), slot);
        slot
    }

    /// Whether a typed declaration of `name` as `declared` inside a function
    /// gives it a new meaning, and so a slot of its own: the name is a
    /// parameter's cell, a top-level name, or an outer local of another type.
    pub(crate) fn declaration_shadows(&self, name: &str, declared: &Type) -> bool {
        if !self.in_function_codegen {
            return false;
        }
        match self.get_var(name) {
            Some(slot) => {
                self.is_cell_slot(slot)
                    || self
                        .declared_types
                        .get(name)
                        .is_some_and(|outer| std::mem::discriminant(outer) != std::mem::discriminant(declared))
            }
            None => self.global_var_label(name).is_some(),
        }
    }

    /// What every name visible at this point of a function means: its slot
    /// (or none, for a top-level name read through its label) and what
    /// codegen knows about it, so a body that runs only on some paths can be
    /// generated and the names put back when it ends. Empty at the top level.
    pub(crate) fn outer_bindings(&self, except: Option<&str>) -> Vec<OuterBinding> {
        if !self.in_function_codegen {
            return Vec::new();
        }
        let mut names: Vec<&String> = self
            .variables
            .keys()
            .chain(self.global_var_labels.keys())
            .filter(|name| Some(name.as_str()) != except)
            .collect();
        names.sort();
        names.dedup();
        names.into_iter().map(|name| self.binding_of(name)).collect()
    }

    fn binding_of(&self, name: &str) -> OuterBinding {
        OuterBinding {
            name: name.to_string(),
            slot: self.get_var(name),
            variable_type: self.variable_types.get(name).cloned(),
            declared_type: self.declared_types.get(name).cloned(),
            element_type: self.list_element_types.get(name).cloned(),
            tag_slot: self.mixed_tag_slots.get(name).copied(),
            thing: self.thing_vars.get(name).cloned(),
        }
    }

    fn apply_binding(&mut self, binding: &OuterBinding) {
        let name = binding.name.clone();
        match binding.slot {
            Some(slot) => self.variables.insert(name.clone(), slot),
            None => self.variables.remove(&name),
        };
        match &binding.variable_type {
            Some(t) => self.variable_types.insert(name.clone(), t.clone()),
            None => self.variable_types.remove(&name),
        };
        match &binding.declared_type {
            Some(t) => self.declared_types.insert(name.clone(), t.clone()),
            None => self.declared_types.remove(&name),
        };
        match &binding.element_type {
            Some(t) => self.list_element_types.insert(name.clone(), t.clone()),
            None => self.list_element_types.remove(&name),
        };
        match binding.tag_slot {
            Some(t) => self.mixed_tag_slots.insert(name.clone(), t),
            None => self.mixed_tag_slots.remove(&name),
        };
        match &binding.thing {
            Some(t) => self.thing_vars.insert(name, t.clone()),
            None => self.thing_vars.remove(&name),
        };
    }

    /// Put every name back as `outer_bindings` found it. Returns the names
    /// the body gave a new slot, each with the meaning the body gave it.
    pub(crate) fn rebind_outer(&mut self, outer: &[OuterBinding]) -> Vec<OuterBinding> {
        let mut changed = Vec::new();
        for binding in outer {
            let now = self.binding_of(&binding.name);
            if now.slot != binding.slot {
                changed.push(now);
                self.apply_binding(binding);
            }
        }
        changed
    }

    /// After a chain that declares a name in every branch, the name is that
    /// declaration's variable, in the slot the branches share. The branches
    /// may have filled a list with different kinds of element, so every
    /// element read dispatches on the slot's own tag.
    pub(crate) fn bind_redeclared(&mut self, binding: &OuterBinding) {
        self.apply_binding(binding);
        if self.variable_types.get(&binding.name) == Some(&VarType::List) {
            self.list_element_types.insert(binding.name.clone(), VarType::Mixed);
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

/// A name as codegen knew it at one point of a function (see
/// `outer_bindings`).
#[derive(Clone)]
pub(crate) struct OuterBinding {
    pub(crate) name: String,
    pub(crate) slot: Option<i64>,
    variable_type: Option<VarType>,
    declared_type: Option<Type>,
    element_type: Option<VarType>,
    tag_slot: Option<i64>,
    thing: Option<String>,
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
