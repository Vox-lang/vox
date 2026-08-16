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
        self.bss_section.push_str(&format!("    {}: resq 1\n", label));
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

    pub(crate) fn add_float(&mut self, f: f64) -> String {
        let label = format!("float_{}", self.float_counter);
        self.float_counter += 1;
        
        // Store as 64-bit IEEE 754 double
        let bits = f.to_bits();
        self.data_section.push_str(&format!("    {}: dq 0x{:016X}  ; {}\n", label, bits, f));
        label
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
