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
        self.emit_indent("mov qword [rel _last_error], 0  ; in range");
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", missing_label));
        let empty_label = self.get_empty_string_label();
        self.emit_indent(&format!(
            "lea rax, [rel {}]  ; empty text for out-of-range positional read", empty_label));
        self.emit_indent("mov qword [rel _last_error], 1  ; out of range");
        self.emit(&format!("{}:", done_label));
        self.uses_strings = true;
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
                self.generate_expr(&Expr::ListLit { elements: vec![] });
                self.emit_store_rax_to_target(target, &format!("list {}", name));
            }
            Type::Map(_) => {
                // Allocate an empty map so printing yields "{}"
                // instead of dereferencing a null pointer.
                self.generate_expr(&Expr::MapLit { pairs: vec![] });
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
                let label = self.get_empty_string_label();
                self.emit_indent(&format!(
                    "lea rax, [rel {}]  ; empty text default", label));
                self.emit_store_rax_to_target(target, &format!("text {}", name));
                self.uses_strings = true;
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
