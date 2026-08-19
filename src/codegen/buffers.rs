use super::*;

impl CodeGenerator {
    pub(crate) fn emit_clear_buffer_target(&mut self, target: &VarTarget) {
        self.uses_buffers = true;
        match target {
            VarTarget::Local(offset) => {
                self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
                self.emit_indent("call _buffer_clear");
                self.emit_indent(&format!("mov [rbp-{}], rax", offset));
            }
            VarTarget::Global(label) => {
                self.emit_indent(&format!("mov rdi, [rel {}]", label));
                self.emit_indent("call _buffer_clear");
                self.emit_indent(&format!("mov [rel {}], rax", label));
            }
        }
    }

    pub(crate) fn emit_append_runtime_value_to_buffer_target(
        &mut self,
        target: &VarTarget,
        value_type: Option<VarType>,
        fmt: FormatSpec,
    ) {
        match target {
            VarTarget::Local(offset) => {
                self.emit_append_runtime_value_to_buffer_slot(*offset, value_type, fmt);
            }
            VarTarget::Global(label) => {
                self.emit_indent(&format!("mov rdi, [rel {}]", label));
                self.emit_append_runtime_value_to_buffer_ptr(value_type, fmt);
                self.emit_indent(&format!("mov [rel {}], rax", label));
            }
        }
    }

    pub(crate) fn emit_clear_buffer_slot(&mut self, offset: i64) {
        self.uses_buffers = true;
        self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
        self.emit_indent("call _buffer_clear");
        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
    }

    pub(crate) fn emit_append_literal_to_buffer_slot(&mut self, offset: i64, text: &str) {
        self.uses_buffers = true;
        let label = self.add_string(text);
        self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
        self.emit_indent(&format!("lea rsi, [rel {}]", label));
        self.emit_indent(&format!("mov rdx, {}_len", label));
        self.emit_indent("call _buffer_append_bytes");
        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
    }

    pub(crate) fn emit_append_formatted_int_to_buffer(&mut self, fmt: FormatSpec) {
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

    pub(crate) fn emit_append_runtime_value_to_buffer_ptr(&mut self, value_type: Option<VarType>, fmt: FormatSpec) {
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
            Some(VarType::Float) => {
                // A float interpolated into a text/buffer destination (e.g.
                // `a text called t is "{y}".`) has its IEEE-754 bits in rax.
                // Without this arm it fell through to the integer formatter
                // and printed the raw bit pattern as a decimal integer
                // (e.g. 3.5 -> 4615063718147915776). _buffer_append_float takes
                // rdi = destination buffer (already loaded by the caller) and
                // rax = raw float bits, and returns the (possibly reallocated)
                // destination buffer in rax — matching the Buffer/String arms.
                // The Print path never hit this because it formats through
                // emit_formatted_value, which already had a Float arm.
                self.uses_buffers = true;
                self.uses_floats = true;
                self.emit_indent("call _buffer_append_float");
            }
            _ => {
                self.emit_append_formatted_int_to_buffer(fmt);
            }
        }
    }

    pub(crate) fn emit_append_runtime_value_to_buffer_slot(
        &mut self,
        offset: i64,
        value_type: Option<VarType>,
        fmt: FormatSpec,
    ) {
        self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
        self.emit_append_runtime_value_to_buffer_ptr(value_type, fmt);
        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
    }

    pub(crate) fn emit_copy_expr_into_buffer_slot(
        &mut self,
        value: &Expr,
        clear_first: bool,
        dst_local: Option<i64>,
        dst_global: Option<&str>,
    ) -> bool {
        self.uses_buffers = true;
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
                // A string literal is data, never a name (bug #30 / #19's
                // family). Initialise from the literal bytes unconditionally;
                // the text is never looked up as a variable. Copying a named
                // buffer into another is spelled with an *unquoted* identifier
                // (the `Expr::Identifier` arm below), never a string literal,
                // so deleting this lookup removes the silent substitution
                // without losing the buffer-to-buffer feature.
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

}
