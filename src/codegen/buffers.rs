use super::*;

impl CodeGenerator {
    /// Store a (possibly reallocated) buffer pointer into the slot at
    /// `[rbp-offset]` and, when that slot belongs to a `buffer` parameter,
    /// on through the cell where the CALLER keeps its own copy.
    ///
    /// docs/BUGS_FOUND.md #90. A parameter's slot is the callee's private
    /// copy of the pointer, so before this every reallocation inside a
    /// function stopped at the callee's frame. For a list that was a stale
    /// read (#75); for a buffer it is worse, because `_reallocate_buffer`
    /// RELEASES the block it grew out of - `mremap` consumes the old mapping
    /// and the mmap fallback `munmap`s it - so the caller was left holding
    /// unmapped memory. The next read of the caller's buffer segfaulted.
    ///
    /// The write-back happens HERE, at the reallocation, and not when the
    /// call returns: between the two the callee can call another function
    /// that reaches the same buffer through its global mirror, and that read
    /// must not land in the freed block either.
    ///
    /// `rcx` (or `rdx`, when the new pointer is itself in rcx) carries the
    /// cell address. A call's result is still live in rax and a `value`
    /// result's tag in r11, so neither may be touched.
    pub(crate) fn emit_store_buffer_ptr_to_slot(&mut self, offset: i64, reg: &str, note: &str) {
        self.emit_indent(&format!("mov [rbp-{}], {}{}", offset, reg, note));
        self.emit_buffer_param_cell_writeback(offset, reg);
    }

    /// The second half of `emit_store_buffer_ptr_to_slot`, for the sites that
    /// have already written the slot themselves.
    pub(crate) fn emit_buffer_param_cell_writeback(&mut self, offset: i64, reg: &str) {
        let cell = match self.buffer_param_cells.get(&offset) {
            Some(cell) => *cell,
            None => return,
        };
        let scratch = if reg == "rcx" { "rdx" } else { "rcx" };
        self.emit_indent(&format!(
            "mov {}, [rbp-{}]  ; where the caller keeps this buffer",
            scratch, cell
        ));
        self.emit_indent(&format!(
            "mov [{}], {}  ; the caller's buffer follows the realloc (#90)",
            scratch, reg
        ));
    }

    pub(crate) fn emit_clear_buffer_target(&mut self, target: &VarTarget) {
        self.uses_buffers = true;
        match target {
            VarTarget::Local(offset) => {
                self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
                self.emit_indent("call _buffer_clear");
                self.emit_store_buffer_ptr_to_slot(*offset, "rax", "");
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
        self.emit_store_buffer_ptr_to_slot(offset, "rax", "");
    }

    pub(crate) fn emit_append_literal_to_buffer_slot(&mut self, offset: i64, text: &str) {
        self.uses_buffers = true;
        let label = self.add_string(text);
        self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
        self.emit_indent(&format!("lea rsi, [rel {}]", label));
        self.emit_indent(&format!("mov rdx, {}_len", label));
        self.emit_indent("call _buffer_append_bytes");
        self.emit_store_buffer_ptr_to_slot(offset, "rax", "");
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
                if let Some(precision) = fmt.precision {
                    // `{ratio:.2}` in any of those destinations. A precision
                    // is a format specifier, and LANGUAGE.md promises those
                    // "render identically whether the result is printed,
                    // written to a file, or built into a text or a
                    // buffer" - so this renders through the SAME routine
                    // Print calls (`_print_float_precision`), pointed at
                    // the destination buffer instead of stdout (coreasm
                    // `_buffer_append_float_precision`). Without this the
                    // spec fell to `_buffer_append_float`, which takes only
                    // the raw bits and has nowhere to put N, so every sink
                    // but Print printed the default trimmed rendering:
                    // `2.5` where Print gave `2.50` (docs/BUGS_FOUND.md #86),
                    // the same missing-arm shape as the List case below (#44).
                    //
                    // rdi = destination buffer (loaded by the caller),
                    // rax = raw float bits, rsi = N, rax = the possibly
                    // reallocated buffer on return: the contract the
                    // Buffer/String/Float/List arms all share.
                    //
                    // uses_format brings in format.asm, where the precision
                    // printer lives; uses_floats above brings in float.asm,
                    // whose digit routine it shares. uses_io brings in
                    // io.asm, which gates the render-sink writers the
                    // redirect goes through - a program that builds
                    // `{ratio:.2}` into a buffer and never prints has no
                    // other reason to include it, and without it the
                    // redirect is not assembled at all.
                    self.uses_format = true;
                    self.uses_io = true;
                    self.emit_indent(&format!("mov rsi, {}", precision));
                    self.emit_indent("call _buffer_append_float_precision");
                } else {
                    self.emit_indent("call _buffer_append_float");
                }
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
                // The integer family: a `number`, a `boolean`, and anything
                // whose type codegen could not name. rax holds the value
                // itself, so the integer formatter is the right one - which
                // is why the type arms above all come first
                // (docs/BUGS_FOUND.md #71: `emit_formatted_value` did not,
                // and printed a text's address).
                if let Some(places) = fmt.precision {
                    self.emit_append_int_with_decimal_places(places, fmt);
                } else {
                    self.emit_append_formatted_int_to_buffer(fmt);
                }
            }
        }
    }

    /// Append a runtime-TAGGED value to the buffer in rdi, dispatching on the
    /// tag in r11 - the buffer twin of `emit_mixed_print_dispatch`
    /// (src/codegen/collections.rs), branch for branch.
    ///
    /// Contract, identical to every arm of
    /// `emit_append_runtime_value_to_buffer_ptr`: rdi = destination buffer,
    /// rax = the value's payload, r11 = its slot tag, and the (possibly
    /// reallocated) buffer comes back in rax. The comparisons run before any
    /// call, because r11 is only valid until the next call or syscall.
    ///
    /// Every branch calls the SAME routine the Print dispatch calls, pointed
    /// at the destination buffer instead of stdout - `_buffer_append_cstr`
    /// for PRINT_CSTR, `_buffer_append_float` for PRINT_FLOAT,
    /// `_list_render_to_buffer` / `_map_render_to_buffer` for
    /// `_list_print` / `_map_print`. That is docs/BUGS_FOUND.md #44's rule
    /// ("value rendering must not be re-implemented per sink") applied to the
    /// one type it did not reach: a value whose type is only known at
    /// runtime.
    ///
    /// A format spec is read but only the default rendering is honoured for a
    /// tagged value, matching what the Print dispatch already does - the two
    /// paths agree rather than one guessing.
    pub(crate) fn emit_append_mixed_value_to_buffer_ptr(&mut self, fmt: FormatSpec) {
        self.uses_buffers = true;
        let str_label = self.new_label("mixa_str");
        let flt_label = self.new_label("mixa_flt");
        let list_label = self.new_label("mixa_list");
        let map_label = self.new_label("mixa_map");
        let nothing_label = self.new_label("mixa_nothing");
        let done_label = self.new_label("mixa_done");
        self.emit_indent(&format!("cmp r11, {}  ; string tag?", TAG_STRING));
        self.emit_indent(&format!("je {}", str_label));
        self.emit_indent(&format!("cmp r11, {}  ; float tag?", TAG_FLOAT));
        self.emit_indent(&format!("je {}", flt_label));
        self.emit_indent(&format!("cmp r11, {}  ; list tag?", TAG_LIST));
        self.emit_indent(&format!("je {}", list_label));
        self.emit_indent(&format!("cmp r11, {}  ; map tag?", TAG_MAP));
        self.emit_indent(&format!("je {}", map_label));
        self.emit_indent(&format!("cmp r11, {}  ; nothing tag?", TAG_NOTHING));
        self.emit_indent(&format!("je {}", nothing_label));
        // Integer and boolean both render as numbers, matching the Print
        // dispatch and a homogeneous boolean list's `1`/`0`.
        self.emit_append_formatted_int_to_buffer(fmt);
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", str_label));
        self.emit_indent("mov rsi, rax");
        self.emit_indent("call _buffer_append_cstr");
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", flt_label));
        self.uses_floats = true;
        self.emit_indent("call _buffer_append_float  ; rdi = buffer, rax = float bits");
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", list_label));
        self.uses_lists = true;
        self.emit_indent("call _list_render_to_buffer  ; rdi = buffer, rax = child list");
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", map_label));
        self.uses_maps = true;
        self.emit_indent("call _map_render_to_buffer  ; rdi = buffer, rax = child map");
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", nothing_label));
        let nothing_str = self.add_string("nothing");
        self.emit_indent(&format!("lea rsi, [rel {}]", nothing_str));
        self.emit_indent(&format!("mov rdx, {}_len", nothing_str));
        self.emit_indent("call _buffer_append_bytes");
        self.emit(&format!("{}:", done_label));
    }

    /// The buffer-slot form of `emit_append_mixed_value_to_buffer_ptr`. Only
    /// `mov` instructions separate the caller's tag load from the dispatch,
    /// so r11 still holds the tag when the comparisons run.
    pub(crate) fn emit_append_mixed_value_to_buffer_slot(&mut self, offset: i64, fmt: FormatSpec) {
        self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
        self.emit_append_mixed_value_to_buffer_ptr(fmt);
        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
    }

    /// `{n:.N}` on a whole number, into a text or buffer destination.
    ///
    /// LANGUAGE.md:3226 promises a format specifier renders identically
    /// "whether the result is printed, written to a file, or built into a
    /// buffer", so the decimal places #71 gave `Print` have to arrive here
    /// too - otherwise `Print "{n:.2}"` says `255.00` and `a text called
    /// owed is "{n:.2}".` says `255`.
    ///
    /// Rendered as the integer, a point, and N zeros, exactly as the print
    /// path does it and for the same reason: a whole number's decimal
    /// expansion IS the integer followed by zeros, so this is exact for
    /// every i64, where converting to a double first would round anything
    /// past 2^53 on its way to being printed "exactly".
    ///
    /// A precision on a FLOAT goes the other way, through the `Float` arm
    /// above and into `_buffer_append_float_precision`. #71 left that arm
    /// dropping the precision and recorded the gap under its "Incidental";
    /// #86 closed it, so both arms now honour a `.N` in every sink.
    fn emit_append_int_with_decimal_places(&mut self, places: i64, fmt: FormatSpec) {
        // A width beside the precision pads the DIGITS, so the whole
        // `<digits>.<zeros>` rendering reaches the width the author asked
        // for - the same arithmetic Print's twin does, so the two sinks
        // agree (docs/BUGS_FOUND.md #85).
        let digit_width = fmt.width.map(|w| w - 1 - places).unwrap_or(0);
        let leading = FormatSpec {
            width: if digit_width > 0 { Some(digit_width) } else { None },
            zero_pad: fmt.zero_pad && digit_width > 0,
            base: IntegerBase::Decimal,
            precision: None,
        };
        self.emit_append_formatted_int_to_buffer(leading);
        if places <= 0 {
            return;
        }
        // Each append takes the destination in rdi and answers with the
        // (possibly reallocated) destination in rax, so each one reloads
        // rdi from the previous answer.
        let point = self.add_string(".");
        self.emit_indent("mov rdi, rax");
        self.emit_indent(&format!("lea rsi, [rel {}]", point));
        self.emit_indent(&format!("mov rdx, {}_len", point));
        self.emit_indent("call _buffer_append_bytes");
        // The fraction: a zero, zero-padded out to N places.
        self.emit_indent("mov rdi, rax");
        self.emit_indent("mov rax, 0");
        self.emit_append_formatted_int_to_buffer(FormatSpec {
            width: Some(places),
            zero_pad: true,
            base: IntegerBase::Decimal,
            precision: None,
        });
    }

    pub(crate) fn emit_append_runtime_value_to_buffer_slot(
        &mut self,
        offset: i64,
        value_type: Option<VarType>,
        fmt: FormatSpec,
    ) {
        self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
        self.emit_append_runtime_value_to_buffer_ptr(value_type, fmt);
        self.emit_store_buffer_ptr_to_slot(offset, "rax", "");
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
                this.emit_store_buffer_ptr_to_slot(offset, "rax", "");
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
    /// A `value` slot asks for the same copy, and for the same reason
    /// (BUGS_FOUND #87). A `value` carries a runtime tag beside its payload,
    /// and `vartype_to_tag` maps a buffer source to `TAG_STRING` — so the
    /// slot has already announced itself as text (`carried's type` answers
    /// `Text (dynamic)`, `If carried is a text` is true) before the payload
    /// is stored. Storing the struct pointer under that tag is #51's defect
    /// with a self-description attached: every read dereferences the header,
    /// and the capacity's low byte is what prints. The five `value` write
    /// sites are the five text ones — declaration, `Set`, `the ... is`, a
    /// `value` parameter, and `Return a value` — and all five come here.
    ///
    /// An expression that is ALREADY a cast to text has done the copy
    /// itself and infers as text, so it does not double-copy here.
    pub(crate) fn generate_expr_as_text(&mut self, expr: &Expr) {
        self.generate_expr(expr);
        if matches!(self.infer_expr_type(expr), Some(VarType::Buffer)) {
            self.emit_buffer_to_text_copy();
        }
    }

    /// Bug #78: hold a buffer size that only run time can decide to the
    /// same bound the parser and the analyzer hold a size they can see.
    /// Emitted with the size in `rax`, immediately before the call to
    /// `_alloc_buffer_sized`, and only for a size that is not a literal —
    /// every literal is decided at compile time, so a program that sizes
    /// its buffers with numbers assembles byte-for-byte as it did before.
    ///
    /// Out of bound, the request becomes a fixed buffer of no capacity and
    /// sets the error flag. That is the buffer the manual already
    /// describes: writes past capacity "truncated at capacity", the error
    /// flag set, "program continues normally", `On error` able to catch it
    /// (LANGUAGE.md, "Truncation Behavior"). What it replaces is worse than
    /// a full buffer — a negative size mapped 24 bytes and reported
    /// `capacity -1`, and a size past what mmap can serve returned 0, which
    /// was stored as the buffer and dereferenced by the next read.
    ///
    /// The flag is cleared on the in-bound path, per `_last_error`'s
    /// lifecycle rule (coreasm/x86_64/core.asm): an operation that can set
    /// it on failure clears it on success.
    pub(crate) fn emit_buffer_size_guard(&mut self) {
        let refuse_label = self.new_label("bufsize_refused");
        let done_label = self.new_label("bufsize_ok");
        self.emit_indent("; bug #78: a size only run time can decide, held to the same bound");
        self.emit_indent(&format!("cmp rax, {}", MIN_BUFFER_SIZE));
        self.emit_indent(&format!("jl {}", refuse_label));
        self.emit_indent(&format!("cmp rax, {}", MAX_BUFFER_SIZE));
        self.emit_indent(&format!("jg {}", refuse_label));
        self.emit_indent("mov qword [rel _last_error], 0  ; size in bounds");
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", refuse_label));
        self.emit_indent("xor rax, rax  ; refused: a fixed buffer with no capacity");
        self.emit_indent("mov qword [rel _last_error], 1  ; buffer overflow - nothing fits");
        self.emit(&format!("{}:", done_label));
    }

}
