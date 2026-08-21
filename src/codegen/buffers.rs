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
            Some(VarType::List) => {
                // A list interpolated into anything that is not `Print` -
                // a text initializer, buffer set/copy/append, `write`, a
                // filesystem path, a `treating` clause, a function argument.
                // LANGUAGE.md promises a format string renders identically
                // in every one of those sinks, so this renders through the
                // SAME routine Print calls, pointed at the destination
                // buffer instead of stdout (coreasm `_list_render_to_buffer`
                // -> `_list_print`). Without this arm the pointer in rax fell
                // to the integer formatter below and the program printed a
                // heap address that changed between runs
                // (docs/BUGS_FOUND.md #44) - the same missing-arm shape the
                // Float case above was added to fix.
                //
                // rdi = destination buffer (loaded by the caller), rax = list
                // pointer, rax = the possibly-reallocated buffer on return:
                // the Buffer/String/Float contract exactly.
                self.uses_buffers = true;
                self.uses_lists = true;
                self.emit_indent("call _list_render_to_buffer");
            }
            Some(VarType::Map) => {
                // The map twin of the List arm above; `_map_render_to_buffer`
                // redirects `_map_print`, so `{person}` renders
                // `{"name": "Ada"}` in every sink (docs/BUGS_FOUND.md #44).
                self.uses_buffers = true;
                self.uses_maps = true;
                self.emit_indent("call _map_render_to_buffer");
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

    /// rax holds a buffer struct pointer; on return rax points at an
    /// INDEPENDENT NUL-terminated copy of that buffer's bytes (a null
    /// source stays null).
    ///
    /// This is the one place the buffer-to-text conversion is written.
    /// `b as text` was the first spelling to need it (BUGS_FOUND #41:
    /// handing back the data-area pointer aliased the buffer, so rewriting
    /// the buffer silently rewrote the text, and resizing it freed the
    /// allocation the text pointed at — a use-after-free). The cast-free
    /// spellings need exactly the same bytes (#51), so they call this
    /// rather than carrying a second copy of the sequence; #58's lesson is
    /// that a per-site duplicate is how the two spellings drift apart.
    ///
    /// The copy goes into a fresh dynamic buffer from `_alloc_buffer` —
    /// the same allocation the other text-producing conversions and format
    /// strings use, so exit cleanup tracks it the same way. The source's
    /// own tracked length is the bound (buffer content is not reliably
    /// NUL-terminated at its logical end), and `_buffer_append_bytes`
    /// writes the terminating NUL and returns the destination, which may
    /// have moved if the copy outgrew the initial capacity.
    pub(crate) fn emit_buffer_to_text_copy(&mut self) {
        self.uses_buffers = true;
        let null_label = self.new_label("buf_text_null");
        let done_label = self.new_label("buf_text_done");
        self.emit_indent("; Buffer to text (independent copy)");
        self.emit_indent("push rbx");
        self.emit_indent("push r12");
        self.emit_indent("mov rbx, rax  ; source buffer struct");
        self.emit_indent("test rbx, rbx");
        self.emit_indent(&format!("jz {}", null_label));
        self.emit_indent("call _alloc_buffer");
        self.emit_indent("mov r12, rax  ; destination buffer");
        self.emit_indent("mov rdi, rbx");
        self.emit_indent("call _buffer_length");
        self.emit_indent("mov rdx, rax  ; bytes to copy");
        self.emit_indent(&format!(
            "lea rsi, [rbx + {}]  ; source data area",
            BUF_DATA_OFFSET
        ));
        self.emit_indent("mov rdi, r12");
        self.emit_indent("call _buffer_append_bytes  ; rax = destination");
        self.emit_indent(&format!(
            "add rax, {}  ; buffer data area -> NUL-terminated text",
            BUF_DATA_OFFSET
        ));
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", null_label));
        self.emit_indent("xor rax, rax");
        self.emit(&format!("{}:", done_label));
        self.emit_indent("pop r12");
        self.emit_indent("pop rbx");
    }

    /// Generate `expr` for a slot that holds TEXT. Identical to
    /// `generate_expr` except that a buffer-valued source is converted the
    /// way `as text` converts it, instead of leaving the buffer's struct
    /// pointer in a text slot.
    ///
    /// LANGUAGE.md's Basic Conversions table gives `buffer -> text` one
    /// meaning — "a copy of the buffer's bytes" — and the language owner's
    /// ruling on BUGS_FOUND #51 is that the cast-free spellings mean the
    /// same thing as the cast: `a text called t is b.`, `Set t to b.` /
    /// `the t is b.`, a text parameter receiving a buffer argument, and
    /// `Return a text, b.`. Before this, each of those stored the struct
    /// pointer verbatim, so the first read printed the capacity field's low
    /// byte (`@` for a 64-byte buffer) — a silent wrong answer that was
    /// stable across mutation, because the text was reading the header and
    /// never touched the data.
    ///
    /// An expression that is ALREADY a cast to text has done the copy
    /// itself and infers as text, so it does not double-copy here.
    pub(crate) fn generate_expr_as_text(&mut self, expr: &Expr) {
        self.generate_expr(expr);
        if matches!(self.infer_expr_type(expr), Some(VarType::Buffer)) {
            self.emit_buffer_to_text_copy();
        }
    }

}
