use super::*;

/// Author-facing display name for the `type` property on a statically-
/// typed variable. `value` is dynamic and handled separately.
fn type_property_display_name(t: &Type) -> Option<&'static str> {
    match t {
        Type::Integer => Some("Number"),
        Type::Float => Some("Float"),
        Type::String => Some("Text"),
        Type::Boolean => Some("Boolean"),
        Type::List(_) => Some("List"),
        Type::Map(_) => Some("Map"),
        Type::Buffer => Some("Buffer"),
        Type::File => Some("File"),
        Type::Time => Some("Time"),
        Type::Timer => Some("Timer"),
        _ => None,
    }
}

impl CodeGenerator {
    pub(crate) fn is_float_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::FloatLit(_) => true,
            // A string literal is text, unconditionally - never resolved
            // against a same-spelled variable's type (BUGS_FOUND #19).
            Expr::StringLit(_) => false,
            Expr::Identifier(name) => {
                self.variable_types.get(name) == Some(&VarType::Float)
            }
            Expr::Cast { target_type, .. } => {
                // Cast to float produces a float
                matches!(target_type, Type::Float)
            }
            Expr::BinaryOp { left, op, right } => {
                // Comparison and boolean operators return integers, not floats
                // But arithmetic with floats returns floats
                match op {
                    BinaryOperator::Equal | BinaryOperator::NotEqual |
                    BinaryOperator::Greater | BinaryOperator::Less |
                    BinaryOperator::GreaterEqual | BinaryOperator::LessEqual |
                    BinaryOperator::And | BinaryOperator::Or => false,
                    _ => self.is_float_expr(left) || self.is_float_expr(right),
                }
            }
            Expr::UnaryOp { operand, .. } => self.is_float_expr(operand),
            Expr::FunctionCall { name, .. } => {
                self.function_return_types.get(&self.resolved_call_label(name))
                    == Some(&VarType::Float)
            }
            _ => false,
        }
    }

    pub(crate) fn is_buffer_expr(&self, expr: &Expr) -> bool {
        match expr {
            // A string literal is text, unconditionally - never resolved
            // against a same-spelled variable's type (BUGS_FOUND #19).
            Expr::StringLit(_) => false,
            Expr::Identifier(name) => {
                self.variable_types.get(name) == Some(&VarType::Buffer)
            }
            _ => false,
        }
    }

    pub(crate) fn is_boolean_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::BoolLit(_) => true,
            Expr::Identifier(name) => self.variable_types.get(name) == Some(&VarType::Boolean),
            Expr::Cast { target_type, .. } => matches!(target_type, Type::Boolean),
            Expr::UnaryOp { op: UnaryOperator::Not, .. } => true,
            Expr::BinaryOp { op, .. } => {
                matches!(op,
                    BinaryOperator::Equal | BinaryOperator::NotEqual |
                    BinaryOperator::Greater | BinaryOperator::Less |
                    BinaryOperator::GreaterEqual | BinaryOperator::LessEqual |
                    BinaryOperator::And | BinaryOperator::Or)
            }
            _ => false,
        }
    }

    /// Emit code for an equality comparison between two stringy (String or
    /// Buffer) expressions. Routes to _mem_eq when either side is a buffer
    /// (length-bounded, avoids NUL-scanning stale bytes after clear+rewrite)
    /// and falls back to _str_eq for pure string/string comparisons.
    /// Result in rax: 1 = equal, 0 = not equal.
    pub(crate) fn emit_stringy_equality(&mut self, left: &Expr, right: &Expr) {
        self.uses_strings = true;
        let left_is_buf = self.is_buffer_expr(left);
        let right_is_buf = self.is_buffer_expr(right);

        if left_is_buf || right_is_buf {
            // At least one side is a buffer - use _mem_eq(ptr1, ptr2, len1, len2).
            // Evaluate both sides, keeping data ptrs and lengths on the stack.

            // --- RIGHT side ---
            if right_is_buf {
                self.generate_expr(right);           // rax = struct ptr
                self.emit_indent("push rax           ; R: struct ptr");
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _buffer_length");
                self.emit_indent("push rax           ; R: len");
                self.emit_indent("mov rdi, [rsp+8]   ; reload struct ptr");
                self.emit_indent("call _buffer_data");
                self.emit_indent("push rax           ; R: data ptr");
                // stack (top): R_data | R_len | R_struct
            } else {
                self.generate_cstr_expr(right);      // rax = NUL-term str ptr
                self.emit_indent("push rax           ; R: str ptr");
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _str_len");
                self.emit_indent("push rax           ; R: len");
                // stack (top): R_len | R_str_ptr  (use R_str_ptr as data ptr later)
            }

            // --- LEFT side ---
            if left_is_buf {
                self.generate_expr(left);            // rax = struct ptr
                self.emit_indent("push rax           ; L: struct ptr");
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _buffer_length");
                self.emit_indent("mov rdx, rax       ; len1 = L len");
                self.emit_indent("mov rdi, [rsp]     ; reload L struct ptr");
                self.emit_indent("call _buffer_data");
                self.emit_indent("mov rdi, rax       ; ptr1 = L data");
                self.emit_indent("pop rax            ; drop L struct ptr");
            } else {
                self.generate_cstr_expr(left);       // rax = NUL-term str ptr
                self.emit_indent("mov rdi, rax       ; ptr1 = L str");
                self.emit_indent("push rdi");
                self.emit_indent("call _str_len");
                self.emit_indent("mov rdx, rax       ; len1 = L len");
                self.emit_indent("pop rdi            ; restore ptr1");
            }

            // --- Restore RIGHT from stack into rsi (ptr2) and rcx (len2) ---
            if right_is_buf {
                self.emit_indent("pop rsi            ; ptr2 = R data");
                self.emit_indent("pop rcx            ; len2 = R len");
                self.emit_indent("pop rax            ; drop R struct ptr");
            } else {
                self.emit_indent("pop rcx            ; len2 = R len");
                self.emit_indent("pop rsi            ; ptr2 = R str");
            }

            self.emit_indent("call _mem_eq");
        } else {
            // Pure string/string - both NUL-terminated, _str_eq is correct
            self.generate_cstr_expr(right);
            self.emit_indent("push rax  ; park right operand");
            self.generate_cstr_expr(left);
            self.emit_indent("mov rdi, rax  ; left operand");
            self.emit_indent("pop rsi  ; right operand");
            self.emit_indent("call _str_eq");
        }
    }

    // Check if operands involve floats (for choosing comparison instructions)
    pub(crate) fn has_float_operands(&self, expr: &Expr) -> bool {
        match expr {
            Expr::FloatLit(_) => true,
            // A string literal is text, unconditionally - never resolved
            // against a same-spelled variable's type (BUGS_FOUND #19).
            Expr::StringLit(_) => false,
            Expr::Identifier(name) => {
                self.variable_types.get(name) == Some(&VarType::Float)
            }
            Expr::Cast { target_type, .. } => {
                // A cast to float yields a float operand - must route through
                // the float arithmetic path, not the integer one. Without this
                // arm, `{s as a float} add 1` took the integer path and did
                // INT_ADD on the float's bit pattern (garbage). Mirrors
                // is_float_expr, which already handled this case.
                matches!(target_type, Type::Float)
            }
            Expr::BinaryOp { left, right, .. } => {
                self.has_float_operands(left) || self.has_float_operands(right)
            }
            Expr::UnaryOp { operand, .. } => self.has_float_operands(operand),
            _ => false,
        }
    }

    /// Operators that compute a number from their operands, so a `nothing`
    /// operand is meaningless. Comparisons and logical and/or are excluded:
    /// they are valid across types, and `is nothing` is itself an equality.
    /// Mirrors `Analyzer::is_arithmetic_op`.
    pub(crate) fn is_arithmetic_operator(&self, op: &BinaryOperator) -> bool {
        matches!(
            op,
            BinaryOperator::Add
                | BinaryOperator::Subtract
                | BinaryOperator::Multiply
                | BinaryOperator::Divide
                | BinaryOperator::Modulo
                | BinaryOperator::BitAnd
                | BinaryOperator::BitOr
                | BinaryOperator::BitXor
                | BinaryOperator::ShiftLeft
                | BinaryOperator::ShiftRight
        )
    }

    /// Flag an arithmetic operand that turned out to hold `nothing`.
    ///
    /// Emitted only for operands whose tag is dynamic - a mixed-list or map
    /// read, a `value`, a for-each variable. A statically-typed operand cannot
    /// be nothing, so homogeneous arithmetic emits nothing extra and keeps its
    /// fast path. A literal `nothing` never reaches here: the analyzer rejects
    /// it outright.
    ///
    /// Must follow `generate_expr(e)` immediately, while r11 still holds the
    /// operand's tag. Touches only r11 and the flags, never rax, so the
    /// operand's value survives.
    pub(crate) fn emit_nothing_operand_check(&mut self, e: &Expr) {
        // Provably nothing (e.g. an element of a homogeneous `[nothing]`
        // list): no test needed, the operand is always nothing. The analyzer
        // cannot see this one - it has no element-type tracking - so the flag
        // is set here rather than reported as a compile error.
        if self.emit_time_expr_tag(e) == Some(TAG_NOTHING) {
            self.emit_indent(
                "mov qword [rel _last_error], 1  ; nothing in arithmetic (static)",
            );
            return;
        }
        let Some(src) = self.runtime_tag_source(e) else {
            return;
        };
        if let Some(operand) = src.shadow_operand() {
            self.emit_indent(&format!(
                "movzx r11, byte {}  ; operand tag (shadow slot)", operand
            ));
        }
        let ok = self.new_label("arith_not_nothing");
        self.emit_indent(&format!("cmp r11, {}  ; nothing operand?", TAG_NOTHING));
        self.emit_indent(&format!("jne {}", ok));
        self.emit_indent("mov qword [rel _last_error], 1  ; nothing in arithmetic");
        self.emit(&format!("{}:", ok));
    }

    /// True when comparing this expression with `==`/`!=` needs byte-content
    /// comparison (_str_eq) rather than a raw pointer `cmp`. Text variables,
    /// string literals, and buffers all qualify - two equal-content strings
    /// are essentially never the same address (add_string mints a fresh
    /// label per literal occurrence with no deduplication), so pointer
    /// comparison silently fails for the overwhelmingly common case of
    /// `some_variable is "literal"`.
    pub(crate) fn is_stringy_expr(&self, expr: &Expr) -> bool {
        matches!(self.infer_expr_type(expr), Some(VarType::String) | Some(VarType::Buffer))
    }

    /// True when `expr`'s type is a concrete, known type that can never be
    /// `String`/`Buffer` (BUGS_FOUND #20). Comparing such an operand for
    /// equality against a stringy operand can never be true - the two
    /// representations aren't comparable. `Mixed`/`Unknown`/unclassifiable
    /// expressions stay `false`: a `value` might hold text at runtime and
    /// `is_stringy_expr` can't rule that out statically, so a stringy-vs-
    /// dynamic comparison keeps taking the existing `emit_stringy_equality`
    /// path (correct when the value does hold text, unchanged from before
    /// this fix when it doesn't - not this bug's scope).
    pub(crate) fn is_definitely_non_stringy_expr(&self, expr: &Expr) -> bool {
        matches!(
            self.infer_expr_type(expr),
            Some(VarType::Integer)
                | Some(VarType::Float)
                | Some(VarType::Boolean)
                | Some(VarType::List)
                | Some(VarType::Map)
        )
    }

    /// True when comparing `left`/`right` for equality reaches the stringy-
    /// vs-provably-non-stringy mismatch (BUGS_FOUND #20): one side is
    /// `String`/`Buffer` and the other is a concrete type that never is.
    /// The two representations can never be byte-equal, and evaluating the
    /// non-stringy side as if it were a C-string pointer is what crashed
    /// (or, for `list`/`map`, read out of bounds) before this fix.
    pub(crate) fn is_stringy_type_mismatch(&self, left: &Expr, right: &Expr) -> bool {
        (self.is_stringy_expr(left) && self.is_definitely_non_stringy_expr(right))
            || (self.is_stringy_expr(right) && self.is_definitely_non_stringy_expr(left))
    }

    /// True if `expr` is a `nothing`/`null`/`nil` literal (stage 1e3, tag 6).
    /// Used by the nothing-equality guard in `generate_condition`.
    pub(crate) fn is_nothing_expr(&self, expr: &Expr) -> bool {
        matches!(expr, Expr::NothingLit)
    }

    /// Emit the `type` property for a variable: static types produce a fixed
    /// text literal, `value` dispatches on the runtime tag already kept in its
    /// shadow slot (local) or BSS mirror (global).
    pub(crate) fn emit_type_property(&mut self, object: &str) {
        if let Some(declared) = self.declared_types.get(object) {
            if *declared != Type::Value {
                let name = type_property_display_name(declared).unwrap_or("Unknown");
                let text = format!("{} (static)", name);
                let label = self.add_string(&text);
                self.emit_indent(&format!("lea rax, [rel {}]  ; {}'s type: {}", label, object, text));
                return;
            }
        }

        // Dynamic: dispatch on the runtime tag in r11.
        self.emit_load_value_tag(&Expr::Identifier(object.to_string()));

        let arms = [
            (TAG_INTEGER, "Number"),
            (TAG_STRING, "Text"),
            (TAG_FLOAT, "Float"),
            (TAG_BOOLEAN, "Boolean"),
            (TAG_LIST, "List"),
            (TAG_MAP, "Map"),
            (TAG_NOTHING, "Nothing"),
        ];

        let mut case_labels = Vec::new();
        for (tag, _name) in &arms {
            let case_label = self.new_label(&format!("type_case_{}", tag));
            case_labels.push((*tag, case_label));
        }
        let unknown_label = self.new_label("type_unknown");
        let done_label = self.new_label("type_done");

        for (i, (tag, _name)) in arms.iter().enumerate() {
            let case_label = &case_labels[i].1;
            self.emit_indent(&format!("cmp r11, {}  ; {}?", tag, _name));
            self.emit_indent(&format!("je {}", case_label));
        }
        self.emit_indent(&format!("jmp {}", unknown_label));

        for (i, (_tag, name)) in arms.iter().enumerate() {
            let case_label = &case_labels[i].1;
            let text = format!("{} (dynamic)", name);
            let label = self.add_string(&text);
            self.emit(&format!("{}:", case_label));
            self.emit_indent(&format!("lea rax, [rel {}]  ; {}'s type: {}", label, object, text));
            self.emit_indent(&format!("jmp {}", done_label));
        }

        let unknown_text = "Unknown (dynamic)";
        let unknown_str = self.add_string(unknown_text);
        self.emit(&format!("{}:", unknown_label));
        self.emit_indent(&format!("lea rax, [rel {}]  ; {}'s type: {}", unknown_str, object, unknown_text));
        self.emit(&format!("{}:", done_label));
    }

    pub(crate) fn generate_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::IntegerLit(n) => {
                self.emit_indent(&format!("mov rax, {}", n));
            }
            
            Expr::FloatLit(n) => {
                self.uses_floats = true;
                // Store float as 64-bit IEEE 754 in data section
                let label = self.add_float(*n);
                self.emit_indent(&format!("FLOAT_LOAD {}", label));
                // Store float bits in rax for stack operations
                self.emit_indent("XMM0_TO_RAX");
            }
            
            Expr::BoolLit(b) => {
                self.emit_indent(&format!("mov rax, {}", if *b { 1 } else { 0 }));
            }

            // The nothing/null literal (stage 1e3, tag 6). The payload is 0;
            // the tag is written by callers via `emit_time_expr_tag`
            // (returns `Some(TAG_NOTHING)`) at every store/forward site, so
            // here we only materialize the payload.
            Expr::NothingLit => {
                self.emit_indent("xor rax, rax  ; nothing literal, payload 0 (tag 6 set by caller)");
            }
            
            // A string literal materializes its own bytes, unconditionally -
            // its content is never resolved against a same-spelled variable
            // (BUGS_FOUND #19).
            Expr::StringLit(s) => {
                let label = self.add_string(s);
                self.emit_indent(&format!("lea rax, [rel {}]", label));
            }
            
            Expr::Identifier(name) => {
                if self.emit_load_named_var_into_rax(name) {
                    // loaded as a variable
                } else if self.zero_arg_func_return_type(name).is_some() {
                    // Plan 270 G4: a zero-argument function name in expression
                    // position is a call, not a variable lookup. The result
                    // is left in rax (and, for a `value` return, its tag in r11)
                    // exactly as a written `Expr::FunctionCall` would be.
                    self.uses_funcs = true;
                    self.emit_function_call(name, &[]);
                }
                // else: the analyzer reported "Unknown variable"; a rejected
                // program never reaches codegen, so rax is left undefined.
            }
            
            Expr::BinaryOp { left, op, right } => {
                // Use has_float_operands for instruction selection (includes comparisons)
                let has_floats = self.has_float_operands(left) || self.has_float_operands(right);

                // `x is nothing` / `x is not nothing` in expression position
                // (stage 1e3): tag-6 equality, result 0/1 in rax. MUST precede
                // the float/stringy/integer paths or `0 is nothing` would
                // compare payloads and be true. Mirrors the condition-position
                // guard in `generate_condition`.
                if matches!(op, BinaryOperator::Equal | BinaryOperator::NotEqual)
                    && (self.is_nothing_expr(left) || self.is_nothing_expr(right))
                {
                    let equal = matches!(op, BinaryOperator::Equal);
                    if self.is_nothing_expr(left) && self.is_nothing_expr(right) {
                        self.emit_indent(&format!("mov rax, {}  ; nothing is nothing", if equal { 1 } else { 0 }));
                    } else {
                        let value = if self.is_nothing_expr(left) { right } else { left };
                        match self.emit_time_expr_tag(value) {
                            Some(t) => {
                                let holds = if equal { t == TAG_NOTHING } else { t != TAG_NOTHING };
                                self.emit_indent(&format!(
                                    "mov rax, {}  ; is {}nothing folded (static tag {})",
                                    if holds { 1 } else { 0 }, if equal { "" } else { "not " }, t
                                ));
                            }
                            None => {
                                self.generate_expr(value);
                                match self.runtime_tag_source(value) {
                                    Some(src) => {
                                        if let Some(operand) = src.shadow_operand() {
                                            self.emit_indent(&format!(
                                                "movzx r11, byte {}  ; load mixed element tag",
                                                operand
                                            ));
                                        }
                                        self.emit_indent("xor rax, rax");
                                        self.emit_indent(&format!(
                                            "cmp r11, {}  ; is nothing?", TAG_NOTHING
                                        ));
                                        self.emit_indent(if equal { "sete al" } else { "setne al" });
                                        self.emit_indent("movzx rax, al");
                                    }
                                    // No tag anywhere and r11 holds unrelated
                                    // data (a call or syscall clobbers it), so
                                    // the value cannot be nothing as far as the
                                    // compiler can tell - answer statically.
                                    None => self.emit_indent(&format!(
                                        "mov rax, {}  ; is {}nothing: operand carries no tag",
                                        u8::from(!equal), if equal { "" } else { "not " }
                                    )),
                                }
                            }
                        }
                    }
                } else if has_floats {
                    self.uses_floats = true;
                    // Float operations using coreasm macros
                    // Convert int operands to float if needed
                    let left_is_float = self.is_float_expr(left);
                    let right_is_float = self.is_float_expr(right);
                    
                    self.generate_expr(right);
                    if !right_is_float {
                        // Convert integer in rax to float
                        self.emit_indent("INT_TO_FLOAT");
                        self.emit_indent("XMM0_TO_RAX");
                    }
                    self.emit_indent("push rax");
                    self.generate_expr(left);
                    if !left_is_float {
                        // Convert integer in rax to float
                        self.emit_indent("INT_TO_FLOAT");
                        self.emit_indent("XMM0_TO_RAX");
                    }
                    self.emit_indent("RAX_TO_XMM0");          // left in xmm0
                    self.emit_indent("pop rax");
                    self.emit_indent("RAX_TO_XMM1");          // right in xmm1
                    
                    match op {
                        BinaryOperator::Add => {
                            self.emit_indent("FLOAT_ADD");
                        }
                        BinaryOperator::Subtract => {
                            self.emit_indent("FLOAT_SUB");
                        }
                        BinaryOperator::Multiply => {
                            self.emit_indent("FLOAT_MUL");
                        }
                        BinaryOperator::Divide => {
                            self.emit_indent("FLOAT_DIV");
                        }
                        BinaryOperator::Modulo => {
                            self.emit_indent("FLOAT_MOD");
                        }
                        BinaryOperator::Equal => {
                            self.emit_indent("FLOAT_EQ");
                        }
                        BinaryOperator::NotEqual => {
                            self.emit_indent("FLOAT_NE");
                        }
                        BinaryOperator::Greater => {
                            self.emit_indent("FLOAT_GT");
                        }
                        BinaryOperator::Less => {
                            self.emit_indent("FLOAT_LT");
                        }
                        BinaryOperator::GreaterEqual => {
                            self.emit_indent("FLOAT_GE");
                        }
                        BinaryOperator::LessEqual => {
                            self.emit_indent("FLOAT_LE");
                        }
                        BinaryOperator::And | BinaryOperator::Or => {
                            // Boolean ops - convert to int first
                            self.emit_indent("FLOAT_TO_INT");
                            self.emit_indent("mov rbx, rax");
                            self.emit_indent("RAX_TO_XMM0");
                            self.emit_indent("FLOAT_TO_INT");
                            if matches!(op, BinaryOperator::And) {
                                self.emit_indent("and rax, rbx");
                            } else {
                                self.emit_indent("or rax, rbx");
                            }
                        }
                        BinaryOperator::BitAnd | BinaryOperator::BitOr | 
                        BinaryOperator::BitXor | BinaryOperator::ShiftLeft |
                        BinaryOperator::ShiftRight => {
                            // Bitwise ops on floats - convert to int first
                            self.emit_indent("FLOAT_TO_INT");
                            self.emit_indent("mov rbx, rax");
                            self.emit_indent("RAX_TO_XMM0");
                            self.emit_indent("FLOAT_TO_INT");
                            match op {
                                BinaryOperator::BitAnd => self.emit_indent("and rax, rbx"),
                                BinaryOperator::BitOr => self.emit_indent("or rax, rbx"),
                                BinaryOperator::BitXor => self.emit_indent("xor rax, rbx"),
                                BinaryOperator::ShiftLeft => {
                                    self.emit_indent("mov cl, bl");
                                    self.emit_indent("shl rax, cl");
                                }
                                BinaryOperator::ShiftRight => {
                                    self.emit_indent("mov cl, bl");
                                    self.emit_indent("shr rax, cl");
                                }
                                _ => {}
                            }
                        }
                    }
                    // Store result back in rax (as float bits)
                    if !matches!(op, BinaryOperator::Equal | BinaryOperator::NotEqual |
                                     BinaryOperator::Greater | BinaryOperator::Less |
                                     BinaryOperator::GreaterEqual | BinaryOperator::LessEqual |
                                     BinaryOperator::And | BinaryOperator::Or) {
                        self.emit_indent("XMM0_TO_RAX");
                    }
                } else if matches!(op, BinaryOperator::Equal | BinaryOperator::NotEqual)
                    && self.is_stringy_type_mismatch(left, right)
                {
                    // Stringy vs a provably non-stringy operand (BUGS_FOUND
                    // #20): the two representations can never be byte-equal.
                    // Fold to a constant without evaluating (and
                    // dereferencing) either operand - the wider guard below
                    // treated the non-stringy operand's raw value as a
                    // C-string pointer and dereferenced it. Expression-
                    // position twin of the same fix in generate_condition;
                    // no known surface syntax reaches this arm today, but it
                    // carries the identical defect and must not regress.
                    let never_equal_result = if matches!(op, BinaryOperator::Equal) { 0 } else { 1 };
                    self.emit_indent(&format!(
                        "mov rax, {}  ; stringy vs non-stringy operand: never equal",
                        never_equal_result
                    ));
                } else if matches!(op, BinaryOperator::Equal | BinaryOperator::NotEqual)
                    && (self.is_stringy_expr(left) || self.is_stringy_expr(right))
                {
                    // Content comparison via _str_eq/_mem_eq - see
                    // emit_stringy_equality. Reached when both sides are
                    // stringy, or one side is stringy and the other is
                    // `value`/Mixed (whose runtime tag might be text).
                    self.emit_stringy_equality(left, right);
                    if matches!(op, BinaryOperator::NotEqual) {
                        self.emit_indent("xor rax, 1  ; 1=equal -> 0=notequal");
                    }
                } else {
                    // Integer operations
                    self.uses_ints = true;
                    let arith = self.is_arithmetic_operator(op);
                    if arith {
                        self.emit_indent(
                            "mov qword [rel _last_error], 0  ; clear error before arithmetic",
                        );
                    }
                    self.generate_expr(right);
                    if arith {
                        self.emit_nothing_operand_check(right);
                    }
                    self.emit_indent("push rax");
                    self.generate_expr(left);
                    if arith {
                        self.emit_nothing_operand_check(left);
                    }
                    self.emit_indent("pop rbx");

                    match op {
                        BinaryOperator::Add => {
                            self.emit_indent("INT_ADD");
                        }
                        BinaryOperator::Subtract => {
                            self.emit_indent("INT_SUB");
                        }
                        BinaryOperator::Multiply => {
                            self.emit_indent("INT_MUL");
                        }
                        BinaryOperator::Divide => {
                            self.emit_indent("INT_DIV");
                        }
                        BinaryOperator::Modulo => {
                            self.emit_indent("INT_MOD");
                        }
                        BinaryOperator::Equal => {
                            self.emit_indent("INT_EQ");
                        }
                        BinaryOperator::NotEqual => {
                            self.emit_indent("INT_NE");
                        }
                        BinaryOperator::Greater => {
                            self.emit_indent("INT_GT");
                        }
                        BinaryOperator::Less => {
                            self.emit_indent("INT_LT");
                        }
                        BinaryOperator::GreaterEqual => {
                            self.emit_indent("INT_GE");
                        }
                        BinaryOperator::LessEqual => {
                            self.emit_indent("INT_LE");
                        }
                        BinaryOperator::And => {
                            self.emit_indent("INT_AND");
                        }
                        BinaryOperator::Or => {
                            self.emit_indent("INT_OR");
                        }
                        BinaryOperator::BitAnd => {
                            self.emit_indent("and rax, rbx");
                        }
                        BinaryOperator::BitOr => {
                            self.emit_indent("or rax, rbx");
                        }
                        BinaryOperator::BitXor => {
                            self.emit_indent("xor rax, rbx");
                        }
                        BinaryOperator::ShiftLeft => {
                            self.emit_indent("mov cl, bl");
                            self.emit_indent("shl rax, cl");
                        }
                        BinaryOperator::ShiftRight => {
                            self.emit_indent("mov cl, bl");
                            self.emit_indent("shr rax, cl");
                        }
                    }
                }
            }
            
            Expr::UnaryOp { op, operand } => {
                match op {
                    UnaryOperator::Negate => {
                        // Check operand type to use correct negate operation
                        match self.infer_expr_type(operand) {
                            Some(VarType::Float) => {
                                self.uses_floats = true;
                                // For float negate, generate operand and handle xmm0/rax properly
                                self.generate_expr(operand);
                                // Move result from rax back to xmm0 for negation
                                self.emit_indent("movq xmm0, rax");
                                // Apply architecture-specific float negation
                                self.emit_indent("FLOAT_NEG");
                                // Move result back to rax for consistency
                                self.emit_indent("XMM0_TO_RAX");
                            }
                            _ => {
                                self.uses_ints = true;
                                self.generate_expr(operand);
                                self.emit_indent("INT_NEG");
                            }
                        }
                    }
                    UnaryOperator::Not => {
                        self.uses_ints = true;
                        self.generate_expr(operand);
                        self.emit_indent("INT_NOT");
                    }
                }
            }
            
            Expr::PropertyCheck { value, property } => {
                self.generate_expr(value);
                match property {
                    Property::Even => {
                        self.emit_indent("test rax, 1");
                        self.emit_indent("setz al");
                        self.emit_indent("movzx rax, al");
                    }
                    Property::Odd => {
                        self.emit_indent("test rax, 1");
                        self.emit_indent("setnz al");
                        self.emit_indent("movzx rax, al");
                    }
                    Property::Zero => {
                        self.emit_indent("test rax, rax");
                        self.emit_indent("setz al");
                        self.emit_indent("movzx rax, al");
                    }
                    Property::Positive => {
                        self.emit_indent("test rax, rax");
                        self.emit_indent("setg al");
                        self.emit_indent("movzx rax, al");
                    }
                    Property::Negative => {
                        self.emit_indent("test rax, rax");
                        self.emit_indent("setl al");
                        self.emit_indent("movzx rax, al");
                    }
                    Property::Empty => {
                        // For buffer/list variables, check the size field at offset 8
                        let is_buffer_or_list = match value.as_ref() {
                            Expr::StringLit(s) | Expr::Identifier(s) => {
                                matches!(self.variable_types.get(s), Some(VarType::Buffer) | Some(VarType::List))
                            }
                            _ => false,
                        };
                        if is_buffer_or_list {
                            self.emit_indent("mov rax, [rax + 8]  ; get size/length");
                        }
                        self.emit_indent("test rax, rax");
                        self.emit_indent("setz al");
                        self.emit_indent("movzx rax, al");
                    }
                }
            }

            // Runtime type predicate (stage 1c): `item is a text` etc.
            // Folds to a constant when the operand's tag is statically
            // provable (via emit_time_expr_tag, which also handles the
            // BoolLit-is-boolean case correctly); otherwise reads the
            // slot's runtime tag (r11 for a fresh element read, the
            // variable's shadow tag slot for a Mixed identifier) and
            // compares it against the target noun's tag.
            Expr::TypeCheck { value, type_noun } => {
                let target = type_to_tag(type_noun).expect("type predicate noun is scalar");
                let noun = type_noun_name(type_noun);
                match self.predicate_static_tag(value) {
                    Some(t) => {
                        self.emit_indent(&format!(
                            "mov rax, {}  ; is a {} folded (static tag {})",
                            u8::from(t == target), noun, t
                        ));
                    }
                    None => {
                        self.generate_expr(value);
                        match self.runtime_tag_source(value) {
                            Some(src) => {
                                if let Some(operand) = src.shadow_operand() {
                                    self.emit_indent(&format!(
                                        "movzx r11, byte {}  ; load mixed element tag",
                                        operand
                                    ));
                                }
                                self.emit_indent("xor rax, rax");
                                self.emit_indent(&format!(
                                    "cmp r11, {}  ; is a {}?", target, noun
                                ));
                                self.emit_indent("sete al");
                                self.emit_indent("movzx rax, al");
                            }
                            // No tag exists for this value and r11 holds
                            // something unrelated. Such a value is stored with
                            // the integer tag everywhere else, so answer
                            // consistently instead of comparing garbage.
                            None => self.emit_indent(&format!(
                                "mov rax, {}  ; is a {}: no runtime tag, treated as number",
                                u8::from(target == TAG_INTEGER), noun
                            )),
                        }
                    }
                }
            }

            Expr::FileAvailable { path } => {
                self.uses_files = true;
                self.generate_cstr_expr(path);
                self.emit_indent("FILE_AVAILABLE");
            }

            Expr::Range { .. } => {}

            Expr::FunctionCall { name, args } => {
                self.emit_function_call(name, args);
                // Return value already in rax
            }

            Expr::ListLit { elements } => {
                // List structure: [capacity:8][length:8][elem_size:8][data...][tags...]
                // Each element is 8 bytes, header is 24 bytes, plus one type
                // tag byte per slot after the data region.
                let capacity = std::cmp::max(elements.len(), 8); // minimum capacity 8
                let header_size = LIST_DATA_OFFSET as usize;
                let data_size = capacity * 8;
                let total_size = header_size + data_size + capacity;
                
                self.uses_lists = true;
                self.emit_indent(&format!("; List literal with {} elements (capacity {})", elements.len(), capacity));
                
                // Allocate memory using mmap (heap allocation)
                self.emit_indent("mov rdi, 0  ; addr = NULL");
                self.emit_indent(&format!("mov rsi, {}  ; size", total_size));
                self.emit_indent("mov rdx, 3  ; PROT_READ | PROT_WRITE");
                self.emit_indent("mov r10, 0x22  ; MAP_PRIVATE | MAP_ANONYMOUS");
                self.emit_indent("mov r8, -1  ; fd = -1");
                self.emit_indent("mov r9, 0  ; offset = 0");
                self.emit_indent("mov rax, 9  ; sys_mmap");
                self.emit_indent("syscall");
                // Check for mmap failure (raw syscall returns -errno, not MAP_FAILED)
                let mmap_ok = self.new_label("list_mmap_ok");
                self.emit_indent("cmp rax, -4096  ; raw mmap returns -errno in [-4095,-1]");
                self.emit_indent(&format!("jbe {}", mmap_ok));
                self.emit_indent("mov rdi, 1          ; exit code 1");
                self.emit_indent("mov rax, 60         ; sys_exit");
                self.emit_indent("syscall");
                self.emit(&format!("{}:", mmap_ok));
                self.emit_indent("push rax  ; save list pointer");
                
                // Store capacity
                self.emit_indent(&format!("mov qword [rax], {}  ; capacity", capacity));
                // Store length
                self.emit_indent(&format!("mov qword [rax + 8], {}  ; length", elements.len()));
                // Store element size
                self.emit_indent("mov qword [rax + 16], 8  ; element size");
                
                // Store elements (data starts at offset 24) along with each
                // slot's type tag (tags start at offset 24 + capacity*8).
                // mmap zero-fills, so only non-integer tags need a write.
                let tags_base = header_size + data_size;
                for (i, elem) in elements.iter().enumerate() {
                    self.emit_indent("pop rbx  ; get list pointer");
                    self.emit_indent("push rbx ; save it back");
                    self.generate_expr(elem);
                    self.emit_indent("pop rbx  ; get list pointer");
                    self.emit_indent(&format!("mov [rbx+{}], rax", header_size + i * 8));
                    match self.emit_time_expr_tag(elem) {
                        Some(tag) => {
                            if tag != TAG_INTEGER {
                                self.emit_indent(&format!(
                                    "mov byte [rbx+{}], {}  ; slot {} type tag",
                                    tags_base + i,
                                    tag,
                                    i + 1
                                ));
                            }
                        }
                        None => {
                            // Mixed-typed source variable: copy its runtime
                            // tag from the shadow slot.
                            if let Some(loc) = self.mixed_element_tag_slot(elem) {
                                self.emit_indent(&format!(
                                    "mov cl, {}  ; runtime tag of mixed source",
                                    loc.operand()
                                ));
                                self.emit_indent(&format!(
                                    "mov [rbx+{}], cl  ; slot {} type tag",
                                    tags_base + i,
                                    i + 1
                                ));
                            }
                        }
                    }
                    self.emit_indent("push rbx ; save list pointer");
                }
                
                self.emit_indent("pop rax  ; list pointer in rax");
            }

            // Map literal: {"key": value, ...}. Build via _map_new then one
            // _map_insert per pair. _map_insert may reallocate on growth, so
            // each call's returned pointer is pushed and becomes the next
            // call's map operand; the final pointer is left in rax. Keys are
            // text (validated by the analyzer); values carry their runtime
            // tag in rcx via the same forwarding pattern as ListAppend.
            // (stage 1e2, tag 5)
            Expr::MapLit { pairs } => {
                self.uses_maps = true;
                self.emit_indent(&format!(
                    "; Map literal with {} pair(s)",
                    pairs.len()
                ));
                let hint = std::cmp::max(pairs.len(), 8);
                self.emit_indent(&format!("mov rdi, {}  ; capacity hint", hint));
                self.emit_indent("call _map_new");
                self.emit_indent("push rax  ; save map pointer");

                for (key, value) in pairs {
                    // key -> rsi (text pointer). A quoted key is always the
                    // literal text (never a variable reference), so a key
                    // spelling that collides with a variable name still maps
                    // to the literal string.
                    self.generate_text_key(key);
                    self.emit_indent("push rax  ; save key pointer");
                    // value -> rdx
                    self.generate_expr(value);
                    self.emit_indent("mov rdx, rax  ; value");
                    // tag -> rcx (forward runtime tag for mixed sources)
                    match self.emit_time_expr_tag(value) {
                        Some(tag) => {
                            self.emit_indent(&format!(
                                "mov ecx, {}  ; value type tag",
                                tag
                            ));
                        }
                        None => {
                            if let Some(loc) = self.mixed_element_tag_slot(value) {
                                self.emit_indent(&format!(
                                    "movzx ecx, byte {}  ; runtime tag of mixed source",
                                    loc.operand()
                                ));
                            } else if self.expr_leaves_tag_in_r11(value) {
                                self.emit_indent(
                                    "mov ecx, r11d  ; forward runtime tag from r11",
                                );
                            } else {
                                self.emit_indent("xor ecx, ecx  ; default integer tag");
                            }
                        }
                    }
                    self.emit_indent("pop rsi  ; key pointer");
                    self.emit_indent("pop rdi  ; map pointer");
                    self.emit_indent("call _map_insert");
                    self.emit_indent("push rax  ; save (possibly reallocated) map pointer");
                }
                self.emit_indent("pop rax  ; final map pointer in rax");
            }

            // ListAccess: 0-indexed access (internal use)
            // MEMORY SAFETY: Always bounds-check before access
            // List structure: [capacity:8][length:8][elem_size:8][data...]
            Expr::ListAccess { list, index } => {
                let ok_label = self.new_label("list_ok");
                let error_label = self.new_label("list_err");
                let done_label = self.new_label("list_done");
                let is_mixed = self.list_expr_is_mixed(list);
                
                self.emit_indent("; List access (0-indexed) with bounds check");
                // Get list pointer
                self.generate_expr(list);
                self.emit_indent("push rax  ; save list pointer");
                
                // Get index
                self.generate_expr(index);
                self.emit_indent("mov rcx, rax  ; index in rcx");
                self.emit_indent("pop rbx  ; list pointer in rbx");
                
                // Bounds check: index must be >= 0 and < length
                self.emit_indent("cmp rcx, 0");
                self.emit_indent(&format!("jl {}  ; index < 0 is error", error_label));
                self.emit_indent("mov rdx, [rbx + 8]  ; get length (offset 8)");
                self.emit_indent("cmp rcx, rdx");
                self.emit_indent(&format!("jl {}  ; index < length is OK", ok_label));
                
                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent("xor rax, rax  ; return 0 on error");
                if is_mixed {
                    self.emit_indent("xor r11d, r11d  ; integer tag on error path");
                }
                self.emit_indent(&format!("jmp {}", done_label));
                
                // Success path: safe access
                // List structure: [capacity:8][length:8][elem_size:8][data...][tags...]
                // Data starts at offset 24
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("mov qword [rel _last_error], 0  ; clear error on success");
                if is_mixed {
                    // tag_addr = base + 24 + capacity*8 + index; tag rides in
                    // r11 for the immediate consumer.
                    self.emit_indent("mov r11, [rbx]  ; capacity");
                    self.emit_indent("shl r11, 3  ; * element size (8)");
                    self.emit_indent("add r11, rcx  ; + index");
                    self.emit_indent(&format!(
                        "movzx r11, byte [rbx + r11 + {}]  ; slot type tag",
                        LIST_DATA_OFFSET
                    ));
                }
                self.emit_indent("mov rax, rcx");
                self.emit_indent("shl rax, 3  ; multiply by 8 (element size)");
                self.emit_indent(&format!(
                    "add rax, {}  ; skip header ({} bytes)",
                    LIST_DATA_OFFSET, LIST_DATA_OFFSET
                ));
                self.emit_indent("add rax, rbx");
                self.emit_indent("mov rax, [rax]  ; get element");
                
                self.emit(&format!("{}:", done_label));
            }
            
            Expr::PropertyAccess { object, property } => {
                let offset = self.get_var(object);
                // Load the variable's runtime value (pointer for containers,
                // raw value for scalars/time). Falls back to global mirrors so
                // top-level/branch-declared names are reachable inside functions.
                let found = if let Some(off) = offset {
                    self.emit_indent(&format!("mov rax, [rbp-{}]", off));
                    true
                } else if let Some(label) = self.global_var_label(object).cloned() {
                    self.emit_indent(&format!("mov rax, [rel {}]", label));
                    true
                } else {
                    false
                };

                if found {
                    let var_type = self.variable_types.get(object).cloned().unwrap_or(VarType::Unknown);

                    match property {
                        // Universal property: reports the variable's type as text.
                        // Does not need the variable's payload; static types fold
                        // to a literal, `value` dispatches on its runtime tag.
                        ObjectProperty::Type => {
                            self.emit_type_property(object);
                        }
                        // Buffer/List properties
                        ObjectProperty::Size => {
                            if var_type == VarType::Buffer {
                                self.emit_indent("mov rax, [rax + 8]  ; buffer length/size");
                            } else if var_type == VarType::List {
                                self.emit_indent("mov rax, [rax + 8]  ; list length at offset 8");
                            } else if var_type == VarType::Map {
                                self.emit_indent("mov rax, [rax + 8]  ; map length (live entries)");
                            } else {
                                // For files, call _file_size
                                self.emit_indent("mov rdi, rax");
                                self.emit_indent("call _file_size");
                            }
                        }
                        ObjectProperty::Capacity => {
                            self.emit_indent("mov rax, [rax]  ; buffer capacity");
                        }
                        ObjectProperty::Empty => {
                            if var_type == VarType::List {
                                self.emit_indent("mov rax, [rax + 8]  ; get list length (offset 8)");
                            } else if var_type == VarType::Map {
                                self.emit_indent("mov rax, [rax + 8]  ; get map length (offset 8)");
                            } else {
                                self.emit_indent("mov rax, [rax + 8]  ; get buffer size");
                            }
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setz al");
                            self.emit_indent("movzx rax, al  ; 1 if empty, 0 otherwise");
                        }
                        // Map properties: keys/values yield a fresh list of
                        // the map's keys (text pointers) or values (with their
                        // runtime tags), in insertion order. Building a list
                        // forces the list runtime on, so set both flags.
                        // (stage 1e2, tag 5)
                        ObjectProperty::Keys => {
                            self.uses_maps = true;
                            self.uses_lists = true;
                            self.emit_indent("mov rdi, rax  ; map pointer");
                            self.emit_indent("call _map_keys  ; -> rax = list of key texts");
                        }
                        ObjectProperty::Values => {
                            self.uses_maps = true;
                            self.uses_lists = true;
                            self.emit_indent("mov rdi, rax  ; map pointer");
                            self.emit_indent("call _map_values  ; -> rax = list of values (tagged)");
                        }
                        ObjectProperty::Full => {
                            if var_type == VarType::List {
                                // Lists can grow dynamically, so never full
                                self.emit_indent("xor rax, rax  ; lists are never full");
                            } else {
                                // Buffer: compare size to capacity
                                self.emit_indent("mov rbx, [rax]      ; capacity");
                                self.emit_indent("mov rax, [rax + 8]  ; size");
                                self.emit_indent("cmp rax, rbx");
                                self.emit_indent("sete al");
                                self.emit_indent("movzx rax, al  ; 1 if full, 0 otherwise");
                            }
                        }

                        // File properties
                        ObjectProperty::Descriptor => {
                            // rax already holds the fd
                        }
                        ObjectProperty::Modified => {
                            self.emit_indent("mov rdi, rax  ; fd");
                            self.emit_indent("call _file_modified");
                        }
                        ObjectProperty::Accessed => {
                            self.emit_indent("mov rdi, rax  ; fd");
                            self.emit_indent("call _file_accessed");
                        }
                        ObjectProperty::Permissions => {
                            self.emit_indent("mov rdi, rax  ; fd");
                            self.emit_indent("call _file_permissions");
                        }
                        ObjectProperty::Readable => {
                            // Check if fd >= 0 (valid for reading)
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setns al");
                            self.emit_indent("movzx rax, al  ; 1 if readable, 0 otherwise");
                        }
                        ObjectProperty::Writable => {
                            // Check if file was opened for writing/appending
                            let is_writable = self.file_writable.get(object).copied().unwrap_or(false);
                            if is_writable {
                                self.emit_indent("mov rax, 1  ; file opened for writing");
                            } else {
                                self.emit_indent("xor rax, rax  ; file opened for reading only");
                            }
                        }

                        // List properties
                        // List structure: [capacity:8][length:8][elem_size:8][data...]
                        ObjectProperty::First => {
                            let ok_label = self.new_label("list_first_ok");
                            let error_label = self.new_label("list_first_err");
                            let done_label = self.new_label("list_first_done");
                            let is_mixed = self.mixed_lists.contains(object)
                                || self.list_element_types.get(object) == Some(&VarType::Mixed);
                            self.emit_indent("mov rbx, [rax + 8]  ; length (offset 8)");
                            self.emit_indent("test rbx, rbx");
                            self.emit_indent(&format!("jnz {}  ; non-empty list, safe to access", ok_label));
                            self.emit(&format!("{}:", error_label));
                            self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                            self.emit_indent("xor rax, rax  ; return 0 on error");
                            if is_mixed {
                                self.emit_indent("xor r11d, r11d  ; integer tag on error path");
                            }
                            self.emit_indent(&format!("jmp {}", done_label));
                            self.emit(&format!("{}:", ok_label));
                            self.emit_indent("mov qword [rel _last_error], 0  ; clear error on success");
                            if is_mixed {
                                // tags[0] = base + 24 + capacity*8
                                self.emit_indent("mov r11, [rax]  ; capacity");
                                self.emit_indent("shl r11, 3  ; * element size (8)");
                                self.emit_indent(&format!(
                            "movzx r11, byte [rax + r11 + {}]  ; slot type tag",
                            LIST_DATA_OFFSET
                        ));
                            }
                            self.emit_indent(&format!(
                                "mov rax, [rax + {}]  ; first element (data at offset {})",
                                LIST_DATA_OFFSET, LIST_DATA_OFFSET
                            ));
                            self.emit(&format!("{}:", done_label));
                        }
                        ObjectProperty::Last => {
                            let ok_label = self.new_label("list_last_ok");
                            let error_label = self.new_label("list_last_err");
                            let done_label = self.new_label("list_last_done");
                            let is_mixed = self.mixed_lists.contains(object)
                                || self.list_element_types.get(object) == Some(&VarType::Mixed);
                            self.emit_indent("mov rbx, [rax + 8]  ; length (offset 8)");
                            self.emit_indent("test rbx, rbx");
                            self.emit_indent(&format!("jnz {}  ; non-empty list, safe to access", ok_label));
                            self.emit(&format!("{}:", error_label));
                            self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                            self.emit_indent("xor rax, rax  ; return 0 on error");
                            if is_mixed {
                                self.emit_indent("xor r11d, r11d  ; integer tag on error path");
                            }
                            self.emit_indent(&format!("jmp {}", done_label));
                            self.emit(&format!("{}:", ok_label));
                            self.emit_indent("mov qword [rel _last_error], 0  ; clear error on success");
                            self.emit_indent("dec rbx             ; 0-indexed");
                            if is_mixed {
                                // tags[len-1] = base + 24 + capacity*8 + (len-1)
                                self.emit_indent("mov r11, [rax]  ; capacity");
                                self.emit_indent("shl r11, 3  ; * element size (8)");
                                self.emit_indent("add r11, rbx  ; + 0-based last index");
                                self.emit_indent(&format!(
                            "movzx r11, byte [rax + r11 + {}]  ; slot type tag",
                            LIST_DATA_OFFSET
                        ));
                            }
                            self.emit_indent("shl rbx, 3          ; * 8");
                            self.emit_indent(&format!("add rbx, {}         ; + header offset", LIST_DATA_OFFSET));
                            self.emit_indent("add rax, rbx        ; offset to last");
                            self.emit_indent("mov rax, [rax]      ; last element");
                            self.emit(&format!("{}:", done_label));
                        }

                        // Number properties
                        ObjectProperty::Absolute => {
                            let lbl = self.label_counter;
                            self.label_counter += 1;
                            self.emit_indent("test rax, rax");
                            self.emit_indent(&format!("jns .abs_done_{}", lbl));
                            self.emit_indent("neg rax");
                            self.emit(&format!(".abs_done_{}:", lbl));
                        }
                        ObjectProperty::Sign => {
                            self.emit_indent("test rax, rax");
                            self.emit_indent("mov rbx, 1");
                            self.emit_indent("mov rcx, -1");
                            self.emit_indent("cmovg rax, rbx  ; positive -> 1");
                            self.emit_indent("cmovl rax, rcx  ; negative -> -1");
                            self.emit_indent("cmovz rax, rax  ; zero -> 0 (already)");
                        }
                        ObjectProperty::Even => {
                            self.emit_indent("and rax, 1");
                            self.emit_indent("xor rax, 1  ; 1 if even, 0 if odd");
                        }
                        ObjectProperty::Odd => {
                            self.emit_indent("and rax, 1  ; 1 if odd, 0 if even");
                        }
                        ObjectProperty::Positive => {
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setg al");
                            self.emit_indent("movzx rax, al");
                        }
                        ObjectProperty::Negative => {
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setl al");
                            self.emit_indent("movzx rax, al");
                        }
                        ObjectProperty::Zero => {
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setz al");
                            self.emit_indent("movzx rax, al");
                        }

                        // Time properties (unix timestamp -> component extraction)
                        ObjectProperty::Hour => {
                            self.uses_time = true;
                            self.emit_indent("TIME_GET_HOUR rax");
                        }
                        ObjectProperty::Minute => {
                            self.uses_time = true;
                            self.emit_indent("TIME_GET_MINUTE rax");
                        }
                        ObjectProperty::Second => {
                            self.uses_time = true;
                            self.emit_indent("TIME_GET_SECOND rax");
                        }
                        ObjectProperty::Day => {
                            self.uses_time = true;
                            self.emit_indent("TIME_GET_DAY rax");
                        }
                        ObjectProperty::Month => {
                            self.uses_time = true;
                            self.emit_indent("TIME_GET_MONTH rax");
                        }
                        ObjectProperty::Year => {
                            self.uses_time = true;
                            self.emit_indent("TIME_GET_YEAR rax");
                        }
                        ObjectProperty::Unix => {
                            // Unix timestamp is the raw value
                        }

                        // Timer properties
                        ObjectProperty::Duration => {
                            self.uses_time = true;
                            self.emit_indent("; Timer duration");
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset.unwrap_or(0) + 48));
                            self.emit_indent("TIMER_DURATION_SECONDS rax");
                        }
                        ObjectProperty::Elapsed => {
                            self.uses_time = true;
                            self.emit_indent("; Timer elapsed");
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset.unwrap_or(0) + 48));
                            self.emit_indent("TIMER_ELAPSED_SECONDS rax");
                        }
                        ObjectProperty::StartTime => {
                            self.uses_time = true;
                            self.emit_indent("; Timer start time");
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset.unwrap_or(0) + 48));
                            self.emit_indent("TIMER_START_TIME rax");
                        }
                        ObjectProperty::EndTime => {
                            self.uses_time = true;
                            self.emit_indent("; Timer end time");
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset.unwrap_or(0) + 48));
                            self.emit_indent("TIMER_END_TIME rax");
                        }
                        ObjectProperty::Running => {
                            self.uses_time = true;
                            self.emit_indent("; Timer running status");
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset.unwrap_or(0) + 48));
                            self.emit_indent("mov rax, [rax + TIMER_RUNNING]");
                        }
                    }
                } else if object == "_current_time" {
                    // Special handling for current time's properties
                    self.uses_time = true;
                    self.emit_indent("TIME_GET");
                    match property {
                        ObjectProperty::Hour => self.emit_indent("TIME_GET_HOUR rax"),
                        ObjectProperty::Minute => self.emit_indent("TIME_GET_MINUTE rax"),
                        ObjectProperty::Second => self.emit_indent("TIME_GET_SECOND rax"),
                        ObjectProperty::Day => self.emit_indent("TIME_GET_DAY rax"),
                        ObjectProperty::Month => self.emit_indent("TIME_GET_MONTH rax"),
                        ObjectProperty::Year => self.emit_indent("TIME_GET_YEAR rax"),
                        ObjectProperty::Unix => { /* rax already has unix time */ }
                        _ => self.emit_indent("; Unknown time property"),
                    }
                }
            }
            
            Expr::LastError => {
                // Get the last error from the runtime
                self.emit_indent("mov rax, [rel _last_error]");
            }
            
            // Command-line arguments
            Expr::ArgumentCount => {
                if self.argument_view_uses_parsed() {
                    // Keep historical semantics: include program name in count.
                    self.emit_indent("call _get_parsed_argc");
                    self.emit_indent("inc rax");
                } else {
                    self.emit_indent("call _get_argc");
                }
            }
            
            Expr::ArgumentAt { index } => {
                self.generate_expr(index);
                if self.argument_view_uses_parsed() {
                    let not_name_label = self.new_label("arg_at_not_name");
                    let done_label = self.new_label("arg_at_done");
                    self.emit_indent("cmp rax, 0");
                    self.emit_indent(&format!("jne {}", not_name_label));
                    self.emit_indent("xor rdi, rdi  ; index 0 = program name");
                    self.emit_indent("call _get_arg");
                    self.emit_indent(&format!("jmp {}", done_label));
                    self.emit(&format!("{}:", not_name_label));
                    self.emit_indent("dec rax  ; map user-facing index to parsed positional index");
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("call _get_parsed_arg");
                    self.emit(&format!("{}:", done_label));
                } else {
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("call _get_arg");
                }
            }
            
            Expr::ArgumentName => {
                self.emit_indent("xor rdi, rdi  ; index 0 - program name");
                self.emit_indent("call _get_arg");
            }
            
            Expr::ArgumentFirst => {
                if self.argument_view_uses_parsed() {
                    self.emit_indent("xor rdi, rdi  ; parsed index 0 - first user arg");
                    self.emit_indent("call _get_parsed_arg");
                } else {
                    self.emit_indent("mov rdi, 1  ; index 1 - first user arg");
                    self.emit_indent("call _get_arg");
                }
            }
            
            Expr::ArgumentSecond => {
                if self.argument_view_uses_parsed() {
                    self.emit_indent("mov rdi, 1  ; parsed index 1 - second user arg");
                    self.emit_indent("call _get_parsed_arg");
                } else {
                    self.emit_indent("mov rdi, 2  ; index 2 - second user arg");
                    self.emit_indent("call _get_arg");
                }
            }
            
            Expr::ArgumentLast => {
                if self.argument_view_uses_parsed() {
                    let has_user_args_label = self.new_label("arg_last_has_user");
                    let done_label = self.new_label("arg_last_done");
                    self.emit_indent("call _get_parsed_argc");
                    self.emit_indent("test rax, rax");
                    self.emit_indent(&format!("jnz {}", has_user_args_label));
                    self.emit_indent("xor rdi, rdi  ; fallback to program name when no user args");
                    self.emit_indent("call _get_arg");
                    self.emit_indent(&format!("jmp {}", done_label));
                    self.emit(&format!("{}:", has_user_args_label));
                    self.emit_indent("dec rax  ; last parsed index = parsed argc - 1");
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("call _get_parsed_arg");
                    self.emit(&format!("{}:", done_label));
                } else {
                    self.emit_indent("call _get_argc");
                    self.emit_indent("dec rax  ; last index = argc - 1");
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("call _get_arg");
                }
            }
            
            Expr::ArgumentEmpty => {
                if self.argument_view_uses_parsed() {
                    self.emit_indent("call _get_parsed_argc");
                    self.emit_indent("test rax, rax");
                    self.emit_indent("setz al  ; 1 if no positional args after flag parsing");
                    self.emit_indent("movzx rax, al");
                } else {
                    self.emit_indent("call _get_argc");
                    self.emit_indent("cmp rax, 1");
                    self.emit_indent("setle al  ; 1 if argc <= 1 (no user args)");
                    self.emit_indent("movzx rax, al");
                }
            }
            
            Expr::ArgumentAll => {
                self.uses_lists = true;
                let min_ok = self.new_label("argall_min_ok");
                let loop_label = self.new_label("argall_loop");
                let done_label = self.new_label("argall_done");

                self.emit_indent("; Build list from parsed positional arguments");
                self.emit_indent("call _get_parsed_argc");
                self.emit_indent("mov r12, rax  ; r12 = count");

                // capacity = max(count, 8)
                self.emit_indent("mov r13, rax  ; r13 = capacity");
                self.emit_indent("cmp r13, 8");
                self.emit_indent(&format!("jge {}", min_ok));
                self.emit_indent("mov r13, 8");
                self.emit(&format!("{}:", min_ok));

                // Allocate: size = capacity*8 + 24 (header) + capacity tag bytes
                self.emit_indent("mov rax, r13");
                self.emit_indent("shl rax, 3");
                self.emit_indent("add rax, r13  ; + type tag bytes (1 per slot)");
                self.emit_indent(&format!("add rax, {}", LIST_DATA_OFFSET));
                self.emit_indent("mov rsi, rax  ; size");
                self.emit_indent("xor rdi, rdi  ; addr = NULL");
                self.emit_indent("mov rdx, 3  ; PROT_READ | PROT_WRITE");
                self.emit_indent("mov r10, 0x22  ; MAP_PRIVATE | MAP_ANONYMOUS");
                self.emit_indent("mov r8, -1  ; fd = -1");
                self.emit_indent("xor r9, r9  ; offset = 0");
                self.emit_indent("mov rax, 9  ; sys_mmap");
                self.emit_indent("syscall");
                // Check for mmap failure (raw syscall returns -errno, not MAP_FAILED)
                let mmap_ok = self.new_label("arglist_mmap_ok");
                self.emit_indent("cmp rax, -4096  ; raw mmap returns -errno in [-4095,-1]");
                self.emit_indent(&format!("jbe {}", mmap_ok));
                self.emit_indent("mov rdi, 1          ; exit code 1");
                self.emit_indent("mov rax, 60         ; sys_exit");
                self.emit_indent("syscall");
                self.emit(&format!("{}:", mmap_ok));
                self.emit_indent("mov r14, rax  ; r14 = list ptr");

                // Initialize header
                self.emit_indent("mov [r14], r13  ; capacity");
                self.emit_indent("mov [r14 + 8], r12  ; length");
                self.emit_indent("mov qword [r14 + 16], 8  ; element size");

                // Fill data from parsed args
                self.emit_indent("xor r15, r15  ; r15 = index");
                self.emit(&format!("{}:", loop_label));
                self.emit_indent("cmp r15, r12");
                self.emit_indent(&format!("jge {}", done_label));
                self.emit_indent("mov rdi, r15");
                self.emit_indent("call _get_parsed_arg");
                self.emit_indent(&format!("mov [r14 + r15*8 + {}], rax", LIST_DATA_OFFSET));
                self.emit_indent("inc r15");
                self.emit_indent(&format!("jmp {}", loop_label));
                self.emit(&format!("{}:", done_label));
                self.emit_indent("mov rax, r14  ; return list pointer");
            }

            Expr::ArgumentRaw => {
                self.uses_lists = true;
                // Preserve callee-saved registers used in this expression.
                self.emit_indent("push r12");
                self.emit_indent("push r13");
                self.emit_indent("push r14");
                self.emit_indent("push r15");

                let min_ok = self.new_label("argraw_min_ok");
                let loop_label = self.new_label("argraw_loop");
                let done_label = self.new_label("argraw_done");

                self.emit_indent("; Build list from raw arguments");
                self.emit_indent("call _get_raw_argc");
                self.emit_indent("mov r12, rax  ; r12 = count");

                self.emit_indent("mov r13, rax  ; r13 = capacity");
                self.emit_indent("cmp r13, 8");
                self.emit_indent(&format!("jge {}", min_ok));
                self.emit_indent("mov r13, 8");
                self.emit(&format!("{}:", min_ok));

                self.emit_indent("mov rax, r13");
                self.emit_indent("shl rax, 3");
                self.emit_indent("add rax, r13  ; + type tag bytes (1 per slot)");
                self.emit_indent(&format!("add rax, {}", LIST_DATA_OFFSET));
                self.emit_indent("mov rsi, rax  ; size");
                self.emit_indent("xor rdi, rdi  ; addr = NULL");
                self.emit_indent("mov rdx, 3  ; PROT_READ | PROT_WRITE");
                self.emit_indent("mov r10, 0x22  ; MAP_PRIVATE | MAP_ANONYMOUS");
                self.emit_indent("mov r8, -1  ; fd = -1");
                self.emit_indent("xor r9, r9  ; offset = 0");
                self.emit_indent("mov rax, 9  ; sys_mmap");
                self.emit_indent("syscall");
                // Check for mmap failure (raw syscall returns -errno, not MAP_FAILED)
                let mmap_ok = self.new_label("argraw_mmap_ok");
                self.emit_indent("cmp rax, -4096  ; raw mmap returns -errno in [-4095,-1]");
                self.emit_indent(&format!("jbe {}", mmap_ok));
                self.emit_indent("mov rdi, 1          ; exit code 1");
                self.emit_indent("mov rax, 60         ; sys_exit");
                self.emit_indent("syscall");
                self.emit(&format!("{}:", mmap_ok));
                self.emit_indent("mov r14, rax  ; r14 = list ptr");

                self.emit_indent("mov [r14], r13  ; capacity");
                self.emit_indent("mov [r14 + 8], r12  ; length");
                self.emit_indent("mov qword [r14 + 16], 8  ; element size");

                self.emit_indent("xor r15, r15  ; r15 = index");
                self.emit(&format!("{}:", loop_label));
                self.emit_indent("cmp r15, r12");
                self.emit_indent(&format!("jge {}", done_label));
                self.emit_indent("mov rdi, r15");
                self.emit_indent("call _get_raw_arg");
                self.emit_indent(&format!("mov [r14 + r15*8 + {}], rax", LIST_DATA_OFFSET));
                self.emit_indent("inc r15");
                self.emit_indent(&format!("jmp {}", loop_label));
                self.emit(&format!("{}:", done_label));
                self.emit_indent("mov rax, r14  ; return list pointer");
                // Restore callee-saved registers.
                self.emit_indent("pop r15");
                self.emit_indent("pop r14");
                self.emit_indent("pop r13");
                self.emit_indent("pop r12");
            }

            Expr::ArgumentHas { value } => {
                let loop_label = self.new_label("arg_has_loop");
                let found_label = self.new_label("arg_has_found");
                let done_label = self.new_label("arg_has_done");

                // Evaluate target value to match and keep it in rbx
                self.generate_expr(value);
                self.emit_indent("mov rbx, rax  ; target argument value");

                // count in rcx, start index in r8
                if self.argument_view_uses_parsed() {
                    self.emit_indent("call _get_parsed_argc");
                    self.emit_indent("mov rcx, rax  ; parsed positional argc");
                    self.emit_indent("xor r8, r8  ; start at parsed[0]");
                } else {
                    self.emit_indent("call _get_raw_argc");
                    self.emit_indent("mov rcx, rax  ; raw user argc");
                    self.emit_indent("xor r8, r8  ; start at raw[0]");
                }
                self.emit_indent("xor rax, rax  ; default result: false");

                self.emit(&format!("{}:", loop_label));
                self.emit_indent("cmp r8, rcx");
                self.emit_indent(&format!("jge {}", done_label));

                // current arg from selected argument view
                self.emit_indent("mov rdi, r8");
                if self.argument_view_uses_parsed() {
                    self.emit_indent("call _get_parsed_arg");
                } else {
                    self.emit_indent("call _get_raw_arg");
                }

                // compare current arg with target
                self.emit_indent("mov rdi, rax");
                self.emit_indent("mov rsi, rbx");
                self.emit_indent("call _str_eq");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jnz {}", found_label));

                self.emit_indent("inc r8");
                self.emit_indent(&format!("jmp {}", loop_label));

                self.emit(&format!("{}:", found_label));
                self.emit_indent("mov rax, 1");
                self.emit_indent(&format!("jmp {}", done_label));

                self.emit(&format!("{}:", done_label));
            }
            
            Expr::TreatingAs { value, match_value, replacement } => {
                // Inline substitution: if value == match_value, use replacement
                let skip_label = self.new_label("treating_skip");
                let done_label = self.new_label("treating_done");
                let treating_type = self.infer_expr_type(value);
                
                // Check if value is a buffer variable
                let is_buffer = if let Expr::Identifier(ref name) = **value {
                    self.variable_types.get(name) == Some(&VarType::Buffer)
                } else {
                    false
                };

                if is_buffer || matches!(treating_type, Some(VarType::String)) {
                    // Evaluate the value
                    self.generate_expr(value);
                    self.emit_indent("push rax  ; save original value (struct ptr if buffer)");

                    if is_buffer {
                        // Get length and data pointer from struct - avoid NUL-scanning
                        // stale bytes (same fix applied to all other buffer comparisons)
                        self.emit_indent("mov rdi, rax");
                        self.emit_indent("call _buffer_length");
                        self.emit_indent("mov rdx, rax  ; len1");
                        self.emit_indent("mov rdi, [rsp]");
                        self.emit_indent("call _buffer_data");
                        self.emit_indent("mov rdi, rax  ; ptr1 = data");
                        self.generate_expr(match_value);
                        self.emit_indent("mov rsi, rax  ; ptr2 = match");
                        self.emit_indent("push rdi");
                        self.emit_indent("push rsi");
                        self.emit_indent("push rdx");
                        self.emit_indent("mov rdi, rsi");
                        self.emit_indent("call _str_len");
                        self.emit_indent("mov rcx, rax  ; len2");
                        self.emit_indent("pop rdx");
                        self.emit_indent("pop rsi");
                        self.emit_indent("pop rdi");
                        self.emit_indent("call _mem_eq");
                    } else {
                        self.emit_indent("mov rdi, rax  ; comparison ptr in rdi");
                        self.generate_expr(match_value);
                        self.emit_indent("mov rsi, rax  ; match value in rsi");
                        self.emit_indent("call _str_eq");
                    }
                    self.emit_indent("test rax, rax");
                    self.emit_indent(&format!("jz {}", skip_label));

                    // Match found - use replacement
                    self.emit_indent("add rsp, 8  ; discard saved value");
                    self.generate_expr(replacement);
                    self.emit_indent(&format!("jmp {}", done_label));

                    // No match - use original value
                    self.emit(&format!("{}:", skip_label));
                    self.emit_indent("pop rax  ; restore original value");
                } else {
                    // Non-string treating uses value comparison in registers.
                    self.generate_expr(value);
                    self.emit_indent("push rax  ; save original value");
                    self.generate_expr(match_value);
                    self.emit_indent("mov rbx, rax  ; match value");
                    self.emit_indent("pop rax  ; restore original value");
                    self.emit_indent("cmp rax, rbx");
                    self.emit_indent(&format!("jne {}", skip_label));

                    // Match found - use replacement
                    self.generate_expr(replacement);
                    self.emit_indent(&format!("jmp {}", done_label));

                    // No match - keep original value in rax
                    self.emit(&format!("{}:", skip_label));
                }

                self.emit(&format!("{}:", done_label));
            }
            
            // Environment variables
            Expr::EnvironmentVariable { name } => {
                self.generate_expr(name);
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _get_env");
            }
            
            Expr::EnvironmentVariableCount => {
                self.emit_indent("call _get_env_count");
            }
            
            Expr::EnvironmentVariableAt { index } => {
                self.generate_expr(index);
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _get_env_at");
            }
            
            Expr::EnvironmentVariableExists { name } => {
                self.generate_expr(name);
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _get_env");
                self.emit_indent("test rax, rax");
                self.emit_indent("setnz al");
                self.emit_indent("movzx rax, al  ; 1 if exists, 0 otherwise");
            }
            
            Expr::EnvironmentVariableFirst => {
                self.emit_indent("xor rdi, rdi  ; index 0");
                self.emit_indent("call _get_env_at");
            }
            
            Expr::EnvironmentVariableLast => {
                self.emit_indent("call _get_env_count");
                self.emit_indent("dec rax  ; last index = count - 1");
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _get_env_at");
            }
            
            Expr::EnvironmentVariableEmpty => {
                self.emit_indent("call _get_env_count");
                self.emit_indent("test rax, rax");
                self.emit_indent("setz al  ; 1 if count == 0");
                self.emit_indent("movzx rax, al");
            }
            
            // Time expressions
            Expr::CurrentTime => {
                self.uses_time = true;
                self.emit_indent("; Get current time");
                self.emit_indent("TIME_GET");
            }

            Expr::Fork => {
                self.uses_files = true;
                self.emit_indent("; fork() - 0 in child, child pid in parent, negative on error");
                self.emit_indent("FORK");
            }

            Expr::ReapChild { pid, no_hang } => {
                self.uses_files = true;
                match pid {
                    None => {
                        self.emit_indent("mov rdi, -1  ; wait for any child");
                    }
                    Some(pid_expr) => {
                        self.generate_expr(pid_expr);
                        self.emit_indent("mov rdi, rax  ; wait for this specific pid");
                    }
                }
                // plan 311: WNOHANG (1) for non-blocking reap, 0 for blocking.
                // REAP_CHILD stores the raw status word to _reaped_status only
                // when a child is actually reaped (rax > 0); a WNOHANG reap that
                // returns 0 leaves it untouched.
                if *no_hang {
                    self.emit_indent("; wait4() with WNOHANG - non-blocking reap");
                    self.emit_indent("REAP_CHILD 1");
                } else {
                    self.emit_indent("; wait4() - reap a child, returns its pid (or -1 on error)");
                    self.emit_indent("REAP_CHILD 0");
                }
            }

            // plan 311: the raw wait4 status word from the most recent
            // successful reap. -1 sentinel before any reap. _reaped_status is
            // in core.asm (always linked), so this needs no feature gate.
            Expr::ReapedStatus => {
                self.emit_indent("; the reaped status - raw wait4 status word (plan 311)");
                self.emit_indent("mov rax, [rel _reaped_status]");
            }
            
            // Type casting
            Expr::Cast { value, target_type, radix } => {
                self.generate_expr(value);
                match target_type {
                    Type::Integer => {
                        // Float to integer - truncate using cvttsd2si
                        if self.is_float_expr(value) {
                            self.emit_indent("; Cast float to integer");
                            // Float expressions are represented as 64-bit float bits in RAX.
                            // Ensure XMM0 has the correct value before converting.
                            self.emit_indent("RAX_TO_XMM0");
                            self.emit_indent("cvttsd2si rax, xmm0");
                        } else {
                            match self.infer_expr_type(value) {
                                Some(VarType::Buffer) => {
                                    self.uses_ints = true;
                                    self.uses_buffers = true;
                                    // Buffer content isn't reliably NUL-terminated at its
                                    // logical end (_buffer_clear only zeroes the first byte,
                                    // not the whole allocation), so a NUL-scanning parse could
                                    // read stale bytes left over from a longer previous value.
                                    // Use the buffer's own tracked length as a hard bound instead.
                                    self.emit_indent("push rbx");
                                    self.emit_indent("push r12");
                                    self.emit_indent("mov rbx, rax  ; save buffer pointer");
                                    self.emit_indent("mov rdi, rbx");
                                    self.emit_indent("call _buffer_length");
                                    self.emit_indent("mov r12, rax  ; save length");
                                    self.emit_indent("mov rdi, rbx");
                                    self.emit_indent("call _buffer_data");
                                    self.emit_indent("mov rdi, rax");
                                    if *radix == 10 {
                                        self.emit_indent("mov rsi, r12  ; max length");
                                        self.emit_indent("call _parse_i64_bounded");
                                    } else {
                                        self.emit_indent(&format!("mov rsi, {}", radix));
                                        self.emit_indent("mov rdx, r12  ; max length");
                                        self.emit_indent("call _parse_int_radix_bounded");
                                    }
                                    self.emit_indent("pop r12");
                                    self.emit_indent("pop rbx");
                                }
                                Some(VarType::String) => {
                                    self.uses_ints = true;
                                    self.emit_indent("mov rdi, rax");
                                    if *radix == 10 {
                                        self.emit_indent("call _parse_i64");
                                    } else {
                                        self.emit_indent(&format!("mov rsi, {}", radix));
                                        self.emit_indent("call _parse_int_radix");
                                    }
                                }
                                _ => {
                                    // Other types stay as-is (already integer)
                                }
                            }
                        }
                    }
                    Type::Float => {
                        if self.is_float_expr(value) {
                            // Already float bits in rax
                        } else {
                            match self.infer_expr_type(value) {
                                Some(VarType::Buffer) => {
                                    self.uses_floats = true;
                                    self.uses_buffers = true;
                                    // Buffer content isn't reliably NUL-terminated at its
                                    // logical end (see the int.asm bounded parsers for the
                                    // full explanation) - use the buffer's own tracked
                                    // length as a hard bound instead of scanning for NUL.
                                    self.emit_indent("push rbx");
                                    self.emit_indent("push r12");
                                    self.emit_indent("mov rbx, rax  ; save buffer pointer");
                                    self.emit_indent("mov rdi, rbx");
                                    self.emit_indent("call _buffer_length");
                                    self.emit_indent("mov r12, rax  ; save length");
                                    self.emit_indent("mov rdi, rbx");
                                    self.emit_indent("call _buffer_data");
                                    self.emit_indent("mov rdi, rax");
                                    self.emit_indent("mov rsi, r12  ; max length");
                                    self.emit_indent("call _parse_f64_bounded");
                                    self.emit_indent("pop r12");
                                    self.emit_indent("pop rbx");
                                }
                                Some(VarType::String) => {
                                    self.uses_floats = true;
                                    self.emit_indent("mov rdi, rax");
                                    self.emit_indent("call _parse_f64");
                                }
                                _ => {
                                    // Integer to float
                                    self.emit_indent("; Cast integer to float");
                                    self.emit_indent("cvtsi2sd xmm0, rax");
                                    // Keep the invariant that expressions leave their value in RAX.
                                    // For floats, RAX holds the IEEE-754 bits.
                                    self.emit_indent("XMM0_TO_RAX");
                                    self.uses_floats = true;
                                }
                            }
                        }
                    }
                    Type::Boolean => {
                        let src_type = self.infer_expr_type(value);
                        if matches!(src_type, Some(VarType::String) | Some(VarType::Buffer)) {
                            // A text/buffer cast to boolean must inspect the
                            // content, not the pointer. "true" (case-insensitive)
                            // yields 1, everything else yields 0.
                            self.uses_strings = true;
                            self.emit_indent("; Cast text/buffer to boolean");
                            self.emit_indent("test rax, rax");
                            let null_label = self.new_label("bool_null");
                            let done_label = self.new_label("bool_done");
                            self.emit_indent(&format!("jz {}", null_label));
                            if src_type == Some(VarType::Buffer) {
                                self.emit_indent(&format!("add rax, {}  ; buffer data area", BUF_DATA_OFFSET));
                            }
                            self.emit_indent("mov rdi, rax");
                            self.emit_indent("call _text_to_boolean");
                            self.emit_indent(&format!("jmp {}", done_label));
                            self.emit(&format!("{}:", null_label));
                            self.emit_indent("xor rax, rax");
                            self.emit(&format!("{}:", done_label));
                        } else {
                            // Convert to boolean (0 = false, non-zero = true)
                            self.emit_indent("; Cast to boolean");
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setne al");
                            self.emit_indent("movzx rax, al");
                        }
                    }
                    Type::String => {
                        // "as text" must materialise a NUL-terminated C string
                        // pointer. Booleans become "true"/"false", integers
                        // become decimal digits, and floats become a trimmed
                        // decimal representation. Text values are already valid
                        // text pointers, so they are left unchanged. A buffer is
                        // NOT: it is a struct with a 24-byte header (BUF_DATA_OFFSET)
                        // whose NUL-terminated character data lives at
                        // struct + BUF_DATA_OFFSET, so the cast must return the
                        // data-area pointer, not the struct pointer it was given.
                        let src_type = self.infer_expr_type(value);
                        if matches!(src_type, Some(VarType::Buffer)) {
                            // Buffer data is always NUL-terminated at its logical
                            // end (_buffer_append_bytes writes a trailing NUL at
                            // data+length; _buffer_clear zeroes the first byte), so
                            // the data-area pointer is a valid C string. Same
                            // adjustment the boolean cast makes for a buffer source.
                            self.uses_buffers = true;
                            self.emit_indent(&format!(
                                "add rax, {}  ; buffer data area -> NUL-terminated text",
                                BUF_DATA_OFFSET
                            ));
                        } else if !matches!(src_type, Some(VarType::String)) {
                            self.uses_buffers = true;
                            self.stack_offset += 8;
                            let tmp = self.stack_offset;

                            self.emit_indent("push rax  ; value to format");
                            self.emit_indent("mov rdi, 1024  ; default buffer size");
                            self.emit_indent("call _alloc_buffer");
                            self.emit_indent(&format!("mov [rbp-{}], rax  ; format result buffer", tmp));
                            self.emit_indent(&format!("mov rdi, [rbp-{}]", tmp));
                            self.emit_indent("pop rax  ; restore value to format");

                            if self.is_float_expr(value) {
                                self.uses_floats = true;
                                self.emit_indent("call _buffer_append_float");
                            } else if self.is_boolean_expr(value) {
                                let true_label = self.add_string("true");
                                let false_label = self.add_string("false");
                                let true_branch = self.new_label("cast_bool_true");
                                let done_label = self.new_label("cast_bool_done");
                                self.emit_indent("test rax, rax");
                                self.emit_indent(&format!("jnz {}", true_branch));
                                self.emit_indent(&format!("lea rsi, [rel {}]", false_label));
                                self.emit_indent(&format!("mov rdx, {}_len", false_label));
                                self.emit_indent(&format!("jmp {}", done_label));
                                self.emit(&format!("{}:", true_branch));
                                self.emit_indent(&format!("lea rsi, [rel {}]", true_label));
                                self.emit_indent(&format!("mov rdx, {}_len", true_label));
                                self.emit(&format!("{}:", done_label));
                                self.emit_indent("call _buffer_append_bytes");
                            } else {
                                let fmt_spec = FormatSpec {
                                    base: IntegerBase::Decimal,
                                    width: None,
                                    zero_pad: false,
                                    precision: None,
                                };
                                self.emit_append_formatted_int_to_buffer(fmt_spec);
                            }

                            self.emit_indent(&format!("mov rax, [rbp-{}]", tmp));
                            self.emit_indent(&format!(
                                "add rax, {}  ; buffer data area -> NUL-terminated C string",
                                BUF_DATA_OFFSET
                            ));
                        }
                    }
                    _ => {
                        // Other casts - no-op
                        self.emit_indent("; Cast (no-op)");
                    }
                }
            }
            
            // Duration cast (timer's duration in seconds/milliseconds)
            Expr::DurationCast { value, unit } => {
                self.uses_time = true;
                match unit {
                    TimeUnit::Seconds => {
                        // Whole seconds, unchanged: bare `the timer's
                        // duration` and `... in seconds` must keep reading
                        // whole seconds exactly as before.
                        self.generate_expr(value);
                        self.emit_indent("; Duration in seconds");
                    }
                    TimeUnit::Milliseconds => {
                        // True milliseconds. The old code re-used the
                        // whole-seconds macro and multiplied by 1000, so a
                        // 30 ms wait read 0 and a 1500 ms wait read 1000.
                        // Instead, resolve the same timer pointer the
                        // seconds path loads and call the millisecond macro,
                        // which subtracts the full timespec and divides
                        // down from nanoseconds.
                        self.emit_indent("; Duration in milliseconds");
                        if let Expr::PropertyAccess { object, property } = value.as_ref() {
                            let offset = self.get_var(object);
                            self.emit_indent(&format!(
                                "lea rax, [rbp - {}]",
                                offset.unwrap_or(0) + 48
                            ));
                            match property {
                                ObjectProperty::Duration => {
                                    self.emit_indent("TIMER_DURATION_MILLISECONDS rax");
                                }
                                ObjectProperty::Elapsed => {
                                    self.emit_indent("TIMER_ELAPSED_MILLISECONDS rax");
                                }
                                _ => {
                                    self.emit_indent("TIMER_DURATION_MILLISECONDS rax");
                                }
                            }
                        } else {
                            // Defensive: a duration cast's inner expression
                            // is always a timer property access.
                            self.generate_expr(value);
                            self.emit_indent("imul rax, 1000");
                        }
                    }
                }
            }
            
            // Byte access: byte N of buffer (1-indexed)
            // Buffer structure: [capacity:8][length:8][flags:8][data at offset 24]
            // MEMORY SAFETY: Always bounds-check before access
            Expr::ByteAccess { buffer, index } => {
                let ok_label = self.new_label("byte_ok");
                let error_label = self.new_label("byte_err");
                let done_label = self.new_label("byte_done");

                self.emit_indent("; Byte access (1-indexed) with bounds check");
                // Get buffer pointer
                self.generate_expr(buffer);
                self.emit_indent("push rax  ; save buffer pointer");
                // Get index
                self.generate_expr(index);
                self.emit_indent("mov rcx, rax  ; index in rcx");
                self.emit_indent("pop rbx  ; buffer pointer in rbx");

                // Bounds check: index must be >= 1 and <= length
                self.emit_indent("cmp rcx, 1");
                self.emit_indent(&format!("jl {}  ; index < 1 is error", error_label));
                self.emit_indent("mov rdx, [rbx + 8]  ; get buffer length (offset 8)");
                self.emit_indent("cmp rcx, rdx");
                self.emit_indent(&format!("jle {}  ; index <= length is OK", ok_label));

                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent("xor rax, rax  ; return 0 on error");
                self.emit_indent(&format!("jmp {}", done_label));

                // Success path: safe access
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("mov qword [rel _last_error], 0  ; clear error on success");
                self.emit_indent("dec rcx  ; convert 1-indexed to 0-indexed");
                self.emit_indent(&format!("add rbx, {}  ; skip to buffer data area", BUF_DATA_OFFSET));
                self.emit_indent("xor rax, rax");
                self.emit_indent("mov al, [rbx + rcx]");

                self.emit(&format!("{}:", done_label));
            }
            
            // Element access: element N of list (1-indexed)
            // List structure: [capacity:8][length:8][elem_size:8][data...] 
            // MEMORY SAFETY: Always bounds-check before access
            Expr::ElementAccess { list, index } => {
                let ok_label = self.new_label("elem_ok");
                let error_label = self.new_label("elem_err");
                let done_label = self.new_label("elem_done");
                let is_mixed = self.list_expr_is_mixed(list);
                
                self.emit_indent("; Element access (1-indexed) with bounds check");
                // Get list pointer
                self.generate_expr(list);
                self.emit_indent("push rax  ; save list pointer");
                // Get index
                self.generate_expr(index);
                self.emit_indent("mov rcx, rax  ; index in rcx");
                self.emit_indent("pop rbx  ; list pointer in rbx");
                
                // Bounds check: index must be >= 1 and <= length
                self.emit_indent("cmp rcx, 1");
                self.emit_indent(&format!("jl {}  ; index < 1 is error", error_label));
                self.emit_indent("mov rdx, [rbx + 8]  ; get length (offset 8)");
                self.emit_indent("cmp rcx, rdx");
                self.emit_indent(&format!("jle {}  ; index <= length is OK", ok_label));
                
                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent("xor rax, rax  ; return 0 on error");
                if is_mixed {
                    self.emit_indent("xor r11d, r11d  ; integer tag on error path");
                }
                self.emit_indent(&format!("jmp {}", done_label));
                
                // Success path: safe access
                // Data starts at offset 24, 1-indexed so element 1 is at offset 24
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("mov qword [rel _last_error], 0  ; clear error on success");
                self.emit_indent("dec rcx  ; convert 1-indexed to 0-indexed");
                if is_mixed {
                    // Runtime type tag travels in r11 (captured immediately
                    // by the consumer - never held across calls/syscalls):
                    // tag_addr = base + 24 + capacity*8 + index
                    self.emit_indent("mov r11, [rbx]  ; capacity");
                    self.emit_indent("shl r11, 3  ; * element size (8)");
                    self.emit_indent("add r11, rcx  ; + 0-based index");
                    self.emit_indent(&format!(
                        "movzx r11, byte [rbx + r11 + {}]  ; slot type tag",
                        LIST_DATA_OFFSET
                    ));
                }
                self.emit_indent("mov rax, rcx");
                self.emit_indent("shl rax, 3  ; index * 8");
                self.emit_indent(&format!(
                    "add rax, {}  ; skip header ({} bytes)",
                    LIST_DATA_OFFSET, LIST_DATA_OFFSET
                ));
                self.emit_indent("add rax, rbx");
                self.emit_indent("mov rax, [rax]  ; get element");
                
                self.emit(&format!("{}:", done_label));
            }

            // Map key access: person's "name". Loads the map variable, looks
            // up the key, and returns the value in rax with its runtime tag in
            // r11 (mirroring ElementAccess). A miss sets _last_error and
            // yields rax=0/r11=0. (stage 1e2, tag 5)
            Expr::MapAccess { map, key } => {
                self.uses_maps = true;
                self.emit_indent("; Map key access (lookup)");
                // map pointer -> rax, save on stack
                self.emit_load_named_var_into_rax(map);
                self.emit_indent("push rax  ; save map pointer");
                // key -> rsi (literal text; never a variable reference)
                self.generate_text_key(key);
                self.emit_indent("mov rsi, rax  ; key pointer");
                self.emit_indent("pop rdi  ; map pointer");
                self.emit_indent("call _map_lookup");
                // rax = value, r11 = tag (set by _map_lookup); on miss
                // _map_lookup sets _last_error=1, rax=0, r11=0.
            }

            // Format string in expression context (e.g. a text initializer
            // or a function argument): materialize it into a fresh dynamic
            // buffer and yield a pointer to the data area - a NUL-terminated
            // C string usable anywhere a text is. Previously this returned 0,
            // so `a text called t is "{buf}"` silently produced a NULL
            // text that printed as empty and crashed execve argv arrays.
            Expr::FormatString { parts } => {
                self.uses_buffers = true;
                self.stack_offset += 8;
                let tmp = self.stack_offset;
                self.emit_indent("mov rdi, 1024  ; default buffer size");
                self.emit_indent("call _alloc_buffer");
                self.emit_indent(&format!("mov [rbp-{}], rax", tmp));
                self.emit_format_parts_into_buffer_slot(tmp, parts, false);
                self.emit_indent(&format!("mov rax, [rbp-{}]", tmp));
                self.emit_indent(&format!(
                    "add rax, {}  ; buffer data area (header is {} bytes)",
                    BUF_DATA_OFFSET, BUF_DATA_OFFSET
                ));
            }
        }
    }

    pub(crate) fn infer_expr_type(&self, expr: &Expr) -> Option<VarType> {
        match expr {
            Expr::IntegerLit(_) => Some(VarType::Integer),
            Expr::FloatLit(_) => Some(VarType::Float),
            // A string literal is text, unconditionally - never resolved
            // against a same-spelled variable's type (BUGS_FOUND #19).
            Expr::StringLit(_) => Some(VarType::String),
            // A format string always materializes text (bug #17): its
            // interpolated parts affect the bytes, never the result type.
            Expr::FormatString { .. } => Some(VarType::String),
            Expr::BoolLit(_) => Some(VarType::Integer), // Booleans are integers (0/1)
            // A list literal is a list value (stage 1e1). This feeds the
            // emit_time_expr_tag catch-all so a nested-list element's slot
            // gets tag 4, and lets a bare `print <list-literal>` route to
            // `_list_print`.
            Expr::ListLit { .. } => Some(VarType::List),
            // A map literal is a map value (stage 1e2). Lets a bare
            // `print <map-literal>` route to `_map_print` and a map element's
            // slot get tag 5.
            Expr::MapLit { .. } => Some(VarType::Map),
            // A type predicate is boolean-valued; codegen treats booleans as
            // integers (0/1), matching BoolLit above (stage 1c).
            Expr::TypeCheck { .. } => Some(VarType::Integer),
            Expr::ArgumentCount => Some(VarType::Integer),
            Expr::ArgumentAt { .. } | Expr::ArgumentName | Expr::ArgumentFirst
            | Expr::ArgumentSecond | Expr::ArgumentLast => Some(VarType::String),
            Expr::ArgumentEmpty | Expr::ArgumentHas { .. } => Some(VarType::Integer),
            Expr::EnvironmentVariable { .. } | Expr::EnvironmentVariableAt { .. }
            | Expr::EnvironmentVariableFirst | Expr::EnvironmentVariableLast => Some(VarType::String),
            Expr::EnvironmentVariableCount | Expr::EnvironmentVariableExists { .. }
            | Expr::EnvironmentVariableEmpty => Some(VarType::Integer),
            Expr::ArgumentAll | Expr::ArgumentRaw => Some(VarType::List),
            Expr::Identifier(name) => self
                .variable_types
                .get(name)
                .cloned()
                .or_else(|| self.zero_arg_func_return_type(name)),
            Expr::FunctionCall { name, .. } => {
                self.function_return_types.get(&self.resolved_call_label(name)).cloned()
            }
            Expr::PropertyAccess { object, property } => {
                // For First/Last on lists, return the list's element type
                match property {
                    ObjectProperty::Type => Some(VarType::String),
                    ObjectProperty::First | ObjectProperty::Last => {
                        if self.variable_types.get(object) == Some(&VarType::List) {
                            self.list_element_types.get(object).cloned()
                        } else {
                            Some(VarType::Integer)
                        }
                    }
                    // A map's keys/values yield a list (stage 1e2).
                    ObjectProperty::Keys | ObjectProperty::Values => Some(VarType::List),
                    ObjectProperty::Size | ObjectProperty::Capacity => Some(VarType::Integer),
                    _ => Some(VarType::Integer),
                }
            }
            Expr::ElementAccess { list, .. } => {
                // For element access, return the list's element type. A named
                // list with no proven element type (a bare `list` parameter, or
                // any list the pre-scan left untyped) is runtime-tagged
                // per-slot, so return None and let `emit_load_value_tag` use the
                // tag `generate_expr` left in r11 — instead of defaulting to
                // Integer, which would overwrite the real tag with 0.
                match list.as_ref() {
                    Expr::Identifier(name) => match self.list_element_types.get(name) {
                        Some(VarType::Unknown) | None => None,
                        Some(other) => Some(other.clone()),
                    },
                    // `element N of m's keys` is a string; `element N of m's
                    // values` is runtime-tagged like a mixed list.
                    Expr::PropertyAccess { property, .. }
                        if matches!(property, ObjectProperty::Keys | ObjectProperty::Values) =>
                    {
                        match property {
                            ObjectProperty::Keys => Some(VarType::String),
                            _ => None, // Values: runtime tag, do not guess
                        }
                    }
                    _ => Some(VarType::Integer),
                }
            }
            // A map key read yields a runtime-tagged value (the value's type
            // depends on the key); `_map_lookup` leaves its tag in r11, so the
            // Mixed/value-ABI machinery handles it. Returning None marks it
            // unknowable, matching ElementAccess on a mixed list. (stage 1e2)
            Expr::MapAccess { .. } => None,
            Expr::BinaryOp { left, op, right } => match op {
                BinaryOperator::Add | BinaryOperator::Subtract | 
                BinaryOperator::Multiply | BinaryOperator::Divide |
                BinaryOperator::Modulo if self.is_float_expr(left) || self.is_float_expr(right) => Some(VarType::Float),
                _ => Some(VarType::Integer),
            },
            Expr::UnaryOp { operand, .. } => self.infer_expr_type(operand),
            Expr::TreatingAs { value, .. } => self.infer_expr_type(value),
            Expr::Cast { target_type, .. } => match target_type {
                Type::Integer => Some(VarType::Integer),
                Type::Float => Some(VarType::Float),
                Type::String => Some(VarType::String),
                Type::Boolean => Some(VarType::Integer),
                Type::Buffer => Some(VarType::Buffer),
                _ => Some(VarType::Integer),
            },
            _ => Some(VarType::Integer), // Default to integer for complex expressions
        }
    }

}
