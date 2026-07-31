use crate::parser::ast::*;
use std::collections::HashMap;

pub struct CodeGenerator {
    output: String,
    data_section: String,
    bss_section: String,
    functions_section: String,
    label_counter: usize,
    string_counter: usize,
    float_counter: usize,
    variables: HashMap<String, i64>,
    variable_types: HashMap<String, VarType>,
    global_constants: HashMap<String, Expr>,
    list_element_types: HashMap<String, VarType>,
    file_writable: HashMap<String, bool>,
    stack_offset: i64,
    shared_lib_mode: bool,
    exported_functions: Vec<String>,
    // Feature tracking for conditional includes
    uses_ints: bool,
    uses_floats: bool,
    uses_files: bool,
    uses_buffers: bool,
    uses_io: bool,
    uses_format: bool,
    uses_time: bool,
    uses_funcs: bool,
    uses_lists: bool,
    // Set when codegen itself emits a call to _str_eq (string/buffer
    // equality comparisons). Distinct from program.uses_strings, which the
    // analyzer computes from string literals/format strings and may miss
    // a pure variable-vs-variable comparison with no literal operand.
    uses_strings: bool,
    // Declared return type of each user function, keyed by function name.
    // Populated by collect_function_signatures() before codegen so
    // infer_expr_type() can report a FunctionCall's real type instead of
    // silently defaulting to Integer (see collect_function_signatures).
    function_return_types: std::collections::HashMap<String, VarType>,
    loop_stack: Vec<(String, String)>, // (continue_label, break_label)
    flag_schemas: Vec<FlagSchemaRuntime>,
    parsed_args_active: bool,
    global_var_labels: HashMap<String, String>,
    global_var_counter: usize,
    in_function_codegen: bool,
    target_arch: String,
}

#[derive(Clone)]
struct FlagSchemaRuntime {
    name: String,
    short: String,
    long: String,
    value_type: FlagValueType,
    required: bool,
}

#[derive(Clone, PartialEq)]
enum VarType {
    Integer,
    Float,       // 64-bit IEEE 754 double
    String,      // Raw string pointer (from lists, etc.)
    Buffer,      // Dynamic buffer struct (has header)
    List,        // List struct [length, elem0, elem1, ...]
    Boolean,
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
enum IntegerBase {
    Decimal,
    HexLower,
    HexUpper,
    Binary,
    Octal,
}

#[derive(Clone, Debug, PartialEq)]
struct FormatSpec {
    width: Option<i32>,
    zero_pad: bool,
    base: IntegerBase,
    precision: Option<i32>,
}

/// Outcome of resolve_format_variable - how a `{name}` format part's value
/// was resolved, so each sink (print / buffer append) can render it.
enum FormatPartValue {
    /// Code was emitted leaving the value (or pointer) in rax; the VarType
    /// tells the sink how to render it (None = integer-ish fallback).
    Loaded(Option<VarType>),
    /// The part resolved to a compile-time string constant.
    Literal(String),
    /// Unknown name - sinks render the `{name}` placeholder literally.
    Unknown,
}

impl CodeGenerator {
    pub fn new() -> Self {
        CodeGenerator {
            output: String::new(),
            data_section: String::new(),
            bss_section: String::new(),
            functions_section: String::new(),
            label_counter: 0,
            string_counter: 0,
            float_counter: 0,
            variables: HashMap::new(),
            variable_types: HashMap::new(),
            global_constants: HashMap::new(),
            list_element_types: HashMap::new(),
            file_writable: HashMap::new(),
            stack_offset: 0,
            shared_lib_mode: false,
            exported_functions: Vec::new(),
            uses_ints: false,
            uses_floats: false,
            uses_files: false,
            uses_buffers: false,
            uses_io: false,
            uses_format: false,
            uses_time: false,
            uses_funcs: false,
            uses_lists: false,
            uses_strings: false,
            function_return_types: std::collections::HashMap::new(),
            loop_stack: Vec::new(),
            flag_schemas: Vec::new(),
            parsed_args_active: false,
            global_var_labels: HashMap::new(),
            global_var_counter: 0,
            in_function_codegen: false,
            target_arch: "x86_64".to_string(),
        }
    }

    fn ensure_global_var_label(&mut self, name: &str) {
        if self.global_var_labels.contains_key(name) {
            return;
        }
        let label = format!("gvar_{}", self.global_var_counter);
        self.global_var_counter += 1;
        self.global_var_labels.insert(name.to_string(), label.clone());
        self.bss_section.push_str(&format!("    {}: resq 1\n", label));
    }

    fn global_var_label(&self, name: &str) -> Option<&String> {
        self.global_var_labels.get(name)
    }

    /// Assign bss mirror labels to every definitely-declared main-line
    /// name (see collect_definite_decls): an `Open ... called "output"`
    /// present in BOTH arms of an if/otherwise still executes in _start's
    /// frame on every path, so functions must be able to reach it via its
    /// mirror global exactly like a top-level declaration. Uses the same
    /// walker as the analyzer so the two can never disagree. Names are
    /// sorted so label numbering stays deterministic across builds.
    fn collect_global_var_labels(&mut self, stmts: &[Statement]) {
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

    fn emit_mirror_stack_var_to_global_if_needed(&mut self, name: &str, offset: i64) {
        if !self.in_function_codegen {
            if let Some(label) = self.global_var_label(name).cloned() {
                self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                self.emit_indent(&format!("mov [rel {}], rax", label));
            }
        }
    }

    fn emit_load_named_var_into_rax(&mut self, name: &str) -> bool {
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
    fn emit_load_named_var_addr(&mut self, name: &str) -> bool {
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

    fn emit_clear_buffer_slot(&mut self, offset: i64) {
        self.uses_buffers = true;
        self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
        self.emit_indent("call _buffer_clear");
        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
    }

    fn emit_append_literal_to_buffer_slot(&mut self, offset: i64, text: &str) {
        self.uses_buffers = true;
        let label = self.add_string(text);
        self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
        self.emit_indent(&format!("lea rsi, [{}]", label));
        self.emit_indent(&format!("mov rdx, {}_len", label));
        self.emit_indent("call _buffer_append_bytes");
        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
    }

    fn emit_append_formatted_int_to_buffer(&mut self, fmt: FormatSpec) {
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

    fn emit_append_runtime_value_to_buffer_ptr(&mut self, value_type: Option<VarType>, fmt: FormatSpec) {
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
            _ => {
                self.emit_append_formatted_int_to_buffer(fmt);
            }
        }
    }

    fn emit_append_runtime_value_to_buffer_slot(
        &mut self,
        offset: i64,
        value_type: Option<VarType>,
        fmt: FormatSpec,
    ) {
        self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
        self.emit_append_runtime_value_to_buffer_ptr(value_type, fmt);
        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
    }

    /// Resolve a `{name}` format part: emit code leaving the runtime value
    /// (or pointer) in rax, and classify what was found. This is THE single
    /// name-resolution path shared by every format-string sink - Print, the
    /// buffer set/copy/append writers, and the expression materializer that
    /// write payloads, paths, and text initializers go through. Special
    /// names, variable/global lookup, and the constant fallback must never
    /// be re-implemented per sink: that duplication is exactly how the
    /// buffer sinks shipped without `{current time's hour}` support while
    /// Print had it.
    fn resolve_format_variable(&mut self, name: &str) -> FormatPartValue {
        match name {
            "current time's hour" => {
                self.emit_indent("TIME_GET");
                self.emit_indent("TIME_GET_HOUR rax");
                self.uses_time = true;
                FormatPartValue::Loaded(Some(VarType::Integer))
            }
            "current time's minute" => {
                self.emit_indent("TIME_GET");
                self.emit_indent("TIME_GET_MINUTE rax");
                self.uses_time = true;
                FormatPartValue::Loaded(Some(VarType::Integer))
            }
            "current time's second" => {
                self.emit_indent("TIME_GET");
                self.emit_indent("TIME_GET_SECOND rax");
                self.uses_time = true;
                FormatPartValue::Loaded(Some(VarType::Integer))
            }
            "arguments's count" | "argument's count" => {
                self.generate_expr(&Expr::ArgumentCount);
                FormatPartValue::Loaded(Some(VarType::Integer))
            }
            "arguments's name" | "argument's name" => {
                self.generate_expr(&Expr::ArgumentName);
                FormatPartValue::Loaded(Some(VarType::String))
            }
            "arguments's first" | "argument's first" => {
                self.generate_expr(&Expr::ArgumentFirst);
                FormatPartValue::Loaded(Some(VarType::String))
            }
            "arguments's last" | "argument's last" => {
                self.generate_expr(&Expr::ArgumentLast);
                FormatPartValue::Loaded(Some(VarType::String))
            }
            _ => {
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                    FormatPartValue::Loaded(self.variable_types.get(name).cloned())
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    self.emit_indent(&format!("mov rax, [rel {}]", label));
                    FormatPartValue::Loaded(self.variable_types.get(name).cloned())
                } else if let Some(expr) = self.global_constants.get(name).cloned() {
                    match expr {
                        Expr::StringLit(s) => FormatPartValue::Literal(s),
                        Expr::IntegerLit(n) => {
                            self.emit_indent(&format!("mov rax, {}", n));
                            FormatPartValue::Loaded(Some(VarType::Integer))
                        }
                        Expr::BoolLit(b) => {
                            self.emit_indent(&format!("mov rax, {}", if b { 1 } else { 0 }));
                            FormatPartValue::Loaded(Some(VarType::Integer))
                        }
                        _ => FormatPartValue::Unknown,
                    }
                } else {
                    FormatPartValue::Unknown
                }
            }
        }
    }

    fn emit_format_parts_into_buffer_slot(&mut self, offset: i64, parts: &[FormatPart], clear_first: bool) {
        if clear_first {
            self.emit_clear_buffer_slot(offset);
        }

        for part in parts {
            match part {
                FormatPart::Literal(s) => self.emit_append_literal_to_buffer_slot(offset, s),
                FormatPart::Variable { name, format } => {
                    match self.resolve_format_variable(name) {
                        FormatPartValue::Loaded(value_type) => {
                            let fmt_spec = self.parse_format_spec(format.as_deref());
                            self.emit_append_runtime_value_to_buffer_slot(offset, value_type, fmt_spec);
                        }
                        FormatPartValue::Literal(s) => {
                            self.emit_append_literal_to_buffer_slot(offset, &s);
                        }
                        FormatPartValue::Unknown => {
                            // Same placeholder Print renders for unknown names
                            let placeholder = format!("{{{}}}", name);
                            self.emit_append_literal_to_buffer_slot(offset, &placeholder);
                        }
                    }
                }
                FormatPart::Expression { expr, format } => {
                    self.generate_expr(expr);
                    let expr_type = self.infer_expr_type(expr);
                    let fmt_spec = self.parse_format_spec(format.as_deref());
                    self.emit_append_runtime_value_to_buffer_slot(offset, expr_type, fmt_spec);
                }
            }
        }
    }

    fn emit_format_parts_into_buffer(
        &mut self,
        dst_local: Option<i64>,
        dst_global: Option<&str>,
        parts: &[FormatPart],
    ) {
        let load_dst = |this: &mut Self| {
            if let Some(offset) = dst_local {
                this.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
            } else if let Some(label) = dst_global {
                this.emit_indent(&format!("mov rdi, [rel {}]", label));
            }
        };

        for part in parts {
            load_dst(self);
            self.emit_indent("push rdi  ; save destination buffer pointer");
            match part {
                FormatPart::Literal(s) => {
                    let label = self.add_string(s);
                    self.emit_indent(&format!("lea rsi, [{}]", label));
                    self.emit_indent(&format!("mov rdx, {}_len", label));
                    self.emit_indent("call _buffer_append_bytes");
                }
                FormatPart::Variable { name, format } => {
                    match self.resolve_format_variable(name) {
                        FormatPartValue::Loaded(value_type) => {
                            let fmt_spec = self.parse_format_spec(format.as_deref());
                            self.emit_append_runtime_value_to_buffer_ptr(value_type, fmt_spec);
                        }
                        FormatPartValue::Literal(s) => {
                            let label = self.add_string(&s);
                            self.emit_indent(&format!("lea rsi, [{}]", label));
                            self.emit_indent(&format!("mov rdx, {}_len", label));
                            self.emit_indent("call _buffer_append_bytes");
                        }
                        FormatPartValue::Unknown => {
                            let placeholder = format!("{{{}}}", name);
                            let label = self.add_string(&placeholder);
                            self.emit_indent(&format!("lea rsi, [{}]", label));
                            self.emit_indent(&format!("mov rdx, {}_len", label));
                            self.emit_indent("call _buffer_append_bytes");
                        }
                    }
                }
                FormatPart::Expression { expr, format } => {
                    self.generate_expr(expr);
                    let expr_type = self.infer_expr_type(expr);
                    let fmt_spec = self.parse_format_spec(format.as_deref());
                    self.emit_append_runtime_value_to_buffer_ptr(expr_type, fmt_spec);
                }
            }
            if let Some(offset) = dst_local {
                self.emit_indent(&format!("mov [rbp-{}], rax", offset));
            } else if let Some(label) = dst_global {
                self.emit_indent(&format!("mov [rel {}], rax", label));
            }
            self.emit_indent("pop rsi  ; discard saved pointer copy");
        }
    }

    fn emit_copy_expr_into_buffer_slot(
        &mut self,
        value: &Expr,
        clear_first: bool,
        dst_local: Option<i64>,
        dst_global: Option<&str>,
    ) -> bool {
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
                if self.variable_types.get(s) == Some(&VarType::Buffer) {
                    if let Some(src_offset) = self.get_var(s) {
                        self.uses_buffers = true;
                        emit_dst_load(self);
                        self.emit_indent(&format!("mov rsi, [rbp-{}]", src_offset));
                        self.emit_indent(if clear_first { "call _buffer_copy" } else { "call _buffer_append" });
                        emit_dst_store(self);
                        return true;
                    } else if let Some(label) = self.global_var_label(s).cloned() {
                        self.uses_buffers = true;
                        emit_dst_load(self);
                        self.emit_indent(&format!("mov rsi, [rel {}]", label));
                        self.emit_indent(if clear_first { "call _buffer_copy" } else { "call _buffer_append" });
                        emit_dst_store(self);
                        return true;
                    }
                }

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
                    self.emit_indent(&format!("lea rsi, [{}]", lit_label));
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

    fn quoted_name_var_type(&self, name: &str) -> Option<VarType> {
        self.variable_types
            .get(name)
            .cloned()
            .or_else(|| {
                self.global_var_label(name)
                    .map(|_| self.variable_types.get(name).cloned().unwrap_or(VarType::Unknown))
            })
            .filter(|t| *t != VarType::Unknown)
    }
    
    fn emit_function_call(&mut self, name: &str, args: &[Expr]) {
        let param_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

        // Evaluate/push all args right-to-left (so arg0 ends up deepest)
        for arg in args.iter().rev() {
            self.generate_expr(arg);
            self.emit_indent("push rax");
        }

        // Pop first 6 args into registers (arg0 -> rdi, arg1 -> rsi, ...)
        let reg_count = args.len().min(param_regs.len());
        for reg in param_regs.iter().take(reg_count) {
            self.emit_indent(&format!("pop {}", reg));
        }

        // Remaining args (7th+) stay on the stack.
        let stack_arg_count = args.len().saturating_sub(param_regs.len());
        let stack_arg_bytes = stack_arg_count * 8;

        // Align stack before call (SysV: 16B-aligned at call instruction).
        let needs_pad = !stack_arg_count.is_multiple_of(2);
        if needs_pad {
            self.emit_indent("sub rsp, 8  ; align stack before call");
        }

        let func_label = name.replace(' ', "_");
        self.emit_indent(&format!("call {}", func_label));

        // Clean up stack args + pad (caller cleanup in SysV)
        let cleanup = stack_arg_bytes + if needs_pad { 8 } else { 0 };
        if cleanup > 0 {
            self.emit_indent(&format!("add rsp, {}", cleanup));
        }
    }

    pub fn set_shared_lib_mode(&mut self, enabled: bool) {
        self.shared_lib_mode = enabled;
    }
    
    pub fn set_target_arch(&mut self, arch: &str) {
        self.target_arch = arch.to_string();
    }
    
    fn new_label(&mut self, prefix: &str) -> String {
        let label = format!(".{}_{}", prefix, self.label_counter);
        self.label_counter += 1;
        label
    }
    
    fn add_string(&mut self, s: &str) -> String {
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
    
    fn add_float(&mut self, f: f64) -> String {
        let label = format!("float_{}", self.float_counter);
        self.float_counter += 1;
        
        // Store as 64-bit IEEE 754 double
        let bits = f.to_bits();
        self.data_section.push_str(&format!("    {}: dq 0x{:016X}  ; {}\n", label, bits, f));
        label
    }
    
    fn alloc_var(&mut self, name: &str) -> i64 {
        self.stack_offset += 8;
        self.variables.insert(name.to_string(), self.stack_offset);
        self.stack_offset
    }
    
    fn get_var(&self, name: &str) -> Option<i64> {
        self.variables.get(name).copied()
    }

    fn collect_global_constants(&mut self, program: &Program) {
        self.global_constants.clear();
        for stmt in &program.statements {
            if let Statement::VarDecl { name, value: Some(expr), .. } = stmt {
                if matches!(expr, Expr::StringLit(_) | Expr::IntegerLit(_) | Expr::BoolLit(_)) {
                    self.global_constants.insert(name.clone(), expr.clone());
                }
            }
        }
    }

    // Record each function's declared return type so infer_expr_type() can
    // resolve Expr::FunctionCall correctly instead of falling through to
    // its generic "Integer for anything unrecognized" default. Without
    // this, reassigning an EXISTING variable from a function call (`the x
    // is "some func" of y.`) silently corrupted the variable's tracked
    // type to Integer - a fresh `a text called "x" is ...` declaration
    // happened to read the correct type from a different code path and
    // was unaffected, which is what made this easy to miss.
    fn collect_function_signatures(&mut self, program: &Program) {
        self.function_return_types.clear();
        for stmt in &program.statements {
            if let Statement::FunctionDef { name, return_type, .. } = stmt {
                let vt = match return_type {
                    Type::Integer => VarType::Integer,
                    Type::Float => VarType::Float,
                    Type::String => VarType::String,
                    Type::Boolean => VarType::Boolean,
                    Type::Buffer => VarType::Buffer,
                    Type::List(_) => VarType::List,
                    _ => VarType::Unknown,
                };
                self.function_return_types.insert(name.clone(), vt);
            }
        }
    }

    fn collect_flag_schemas(&mut self, program: &Program) {
        self.flag_schemas.clear();
        for stmt in &program.statements {
            if let Statement::FlagSchemaDecl {
                name,
                short,
                long,
                value_type,
                required,
                ..
            } = stmt
            {
                self.flag_schemas.push(FlagSchemaRuntime {
                    name: name.clone(),
                    short: short.clone(),
                    long: long.clone(),
                    value_type: value_type.clone(),
                    required: *required,
                });
            }
        }
    }

    fn emit_flag_parse_routine(&mut self) {
        if self.flag_schemas.is_empty() {
            return;
        }

        self.emit_indent("; Runtime flag schema parsing");
        self.emit_indent("call _reset_parsed_args");

        let schemas = self.flag_schemas.clone();
        let mut seen_entries: Vec<(FlagSchemaRuntime, i64, i64)> = Vec::new();
        for schema in &schemas {
            let flag_offset = if let Some(off) = self.get_var(&schema.name) {
                off
            } else {
                self.alloc_var(&schema.name)
            };
            let seen_offset = self.alloc_var(&format!("__flag_seen_{}", schema.name.replace(' ', "_")));
            self.emit_indent(&format!("mov qword [rbp-{}], 0", seen_offset));
            seen_entries.push((schema.clone(), seen_offset, flag_offset));
        }

        let argc_off = self.alloc_var("__flag_parse_argc");
        let idx_off = self.alloc_var("__flag_parse_idx");
        let cur_off = self.alloc_var("__flag_parse_cur");
        let stop_off = self.alloc_var("__flag_parse_stop");

        self.emit_indent("call _get_raw_argc");
        self.emit_indent(&format!("mov [rbp-{}], rax", argc_off));
        self.emit_indent(&format!("mov qword [rbp-{}], 0", idx_off));
        self.emit_indent(&format!("mov qword [rbp-{}], 0", stop_off));

        let loop_label = self.new_label("flag_parse_loop");
        let done_label = self.new_label("flag_parse_done");
        let append_pos_label = self.new_label("flag_parse_append_positional");
        let continue_label = self.new_label("flag_parse_continue");

        let stop_token = self.add_string("--");
        self.emit(&format!("{}:", loop_label));
        self.emit_indent(&format!("mov rax, [rbp-{}]", idx_off));
        self.emit_indent(&format!("cmp rax, [rbp-{}]", argc_off));
        self.emit_indent(&format!("jge {}", done_label));

        self.emit_indent("mov rdi, rax");
        self.emit_indent("call _get_raw_arg");
        self.emit_indent(&format!("mov [rbp-{}], rax", cur_off));

        self.emit_indent(&format!("cmp qword [rbp-{}], 0", stop_off));
        self.emit_indent(&format!("jne {}", append_pos_label));

        let not_stop_label = self.new_label("flag_parse_not_stop");
        self.emit_indent(&format!("mov rdi, [rbp-{}]", cur_off));
        self.emit_indent(&format!("lea rsi, [rel {}]", stop_token));
        self.emit_indent("call _str_eq");
        self.emit_indent("test rax, rax");
        self.emit_indent(&format!("jz {}", not_stop_label));
        self.emit_indent(&format!("mov qword [rbp-{}], 1", stop_off));
        self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
        self.emit_indent(&format!("jmp {}", continue_label));
        self.emit(&format!("{}:", not_stop_label));

        let mut next_check_label = append_pos_label.clone();
        for (schema, seen_off, flag_off) in &seen_entries {
            let no_match_label = self.new_label("flag_no_match");
            let matched_label = self.new_label("flag_matched");

            let short_label = self.add_string(&schema.short);
            self.emit_indent(&format!("mov rdi, [rbp-{}]", cur_off));
            self.emit_indent(&format!("lea rsi, [rel {}]", short_label));
            self.emit_indent("call _str_eq");
            self.emit_indent("test rax, rax");
            self.emit_indent(&format!("jnz {}", matched_label));

            let long_label = self.add_string(&schema.long);
            self.emit_indent(&format!("mov rdi, [rbp-{}]", cur_off));
            self.emit_indent(&format!("lea rsi, [rel {}]", long_label));
            self.emit_indent("call _str_eq");
            self.emit_indent("test rax, rax");
            self.emit_indent(&format!("jz {}", no_match_label));

            self.emit(&format!("{}:", matched_label));
            match schema.value_type {
                FlagValueType::Boolean => {
                    self.emit_indent(&format!("mov qword [rbp-{}], 1", flag_off));
                    self.emit_indent(&format!("mov qword [rbp-{}], 1", seen_off));
                    self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
                    self.emit_indent(&format!("jmp {}", continue_label));
                }
                FlagValueType::Text | FlagValueType::Number => {
                    self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
                    self.emit_indent(&format!("mov rax, [rbp-{}]", idx_off));
                    self.emit_indent(&format!("cmp rax, [rbp-{}]", argc_off));
                    self.emit_indent(&format!("jge {}", done_label));
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("call _get_raw_arg");
                    if matches!(schema.value_type, FlagValueType::Number) {
                        self.uses_ints = true;
                        self.emit_indent("mov rdi, rax");
                        self.emit_indent("call _parse_i64");
                    }
                    self.emit_indent(&format!("mov [rbp-{}], rax", flag_off));
                    self.emit_indent(&format!("mov qword [rbp-{}], 1", seen_off));
                    self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
                    self.emit_indent(&format!("jmp {}", continue_label));
                }
            }

            self.emit(&format!("{}:", no_match_label));
            next_check_label = no_match_label;
        }

        // Fall through from last no-match to positional append
        self.emit_indent(&format!("jmp {}", append_pos_label));

        self.emit(&format!("{}:", append_pos_label));
        self.emit_indent(&format!("mov rdi, [rbp-{}]", cur_off));
        self.emit_indent("call _append_parsed_arg");
        self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
        self.emit_indent(&format!("jmp {}", continue_label));

        self.emit(&format!("{}:", continue_label));
        self.emit_indent(&format!("jmp {}", loop_label));

        self.emit(&format!("{}:", done_label));
        for (schema, seen_off, _) in &seen_entries {
            if schema.required {
                let ok_label = self.new_label("flag_required_ok");
                self.emit_indent(&format!("cmp qword [rbp-{}], 1", seen_off));
                self.emit_indent(&format!("je {}", ok_label));
                self.emit_indent("EXIT 1");
                self.emit(&format!("{}:", ok_label));
            }
        }
        for (schema, _, flag_off) in &seen_entries {
            if let Some(label) = self.global_var_label(&schema.name).cloned() {
                self.emit_indent(&format!("mov rax, [rbp-{}]", flag_off));
                self.emit_indent(&format!("mov [rel {}], rax", label));
            }
        }
        let _ = next_check_label;
    }

    fn emit_global_constant_format_fallback(&mut self, name: &str, format: Option<&String>) -> bool {
        let Some(expr) = self.global_constants.get(name).cloned() else {
            return false;
        };

        match expr {
            Expr::StringLit(s) => {
                let label = self.add_string(&s);
                self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                true
            }
            Expr::IntegerLit(n) => {
                self.emit_indent(&format!("mov rdi, {}", n));
                let fmt_spec = self.parse_format_spec(format.map(|s| s.as_str()));
                self.emit_formatted_value(Some(VarType::Integer), fmt_spec);
                true
            }
            Expr::BoolLit(b) => {
                self.emit_indent(&format!("mov rdi, {}", if b { 1 } else { 0 }));
                let fmt_spec = self.parse_format_spec(format.map(|s| s.as_str()));
                self.emit_formatted_value(Some(VarType::Integer), fmt_spec);
                true
            }
            _ => false,
        }
    }
    
    fn is_float_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::FloatLit(_) => true,
            Expr::StringLit(s) => self.quoted_name_var_type(s) == Some(VarType::Float),
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
            _ => false,
        }
    }

    fn is_buffer_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::StringLit(s) => self.quoted_name_var_type(s) == Some(VarType::Buffer),
            Expr::Identifier(name) => {
                self.variable_types.get(name) == Some(&VarType::Buffer)
            }
            _ => false,
        }
    }

    fn is_boolean_expr(&self, expr: &Expr) -> bool {
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
    fn emit_stringy_equality(&mut self, left: &Expr, right: &Expr) {
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
    fn has_float_operands(&self, expr: &Expr) -> bool {
        match expr {
            Expr::FloatLit(_) => true,
            Expr::StringLit(s) => self.quoted_name_var_type(s) == Some(VarType::Float),
            Expr::Identifier(name) => {
                self.variable_types.get(name) == Some(&VarType::Float)
            }
            Expr::BinaryOp { left, right, .. } => {
                self.has_float_operands(left) || self.has_float_operands(right)
            }
            Expr::UnaryOp { operand, .. } => self.has_float_operands(operand),
            _ => false,
        }
    }
    
    fn emit(&mut self, code: &str) {
        self.output.push_str(code);
        self.output.push('\n');
    }
    
    fn emit_indent(&mut self, code: &str) {
        self.output.push_str("    ");
        self.output.push_str(code);
        self.output.push('\n');
    }

    fn argument_view_uses_parsed(&self) -> bool {
        self.parsed_args_active
    }
    
    pub fn generate(&mut self, program: &Program) -> String {
        self.collect_global_constants(program);
        self.collect_flag_schemas(program);
        self.collect_function_signatures(program);

        self.global_var_labels.clear();
        self.global_var_counter = 0;
        self.collect_global_var_labels(&program.statements);

        let explicit_parse_idx = program
            .statements
            .iter()
            .position(|s| matches!(s, Statement::ParseFlags));
        let auto_parse_idx = program
            .statements
            .iter()
            .rposition(|s| matches!(s, Statement::FlagSchemaDecl { .. }))
            .map(|i| i + 1);
        let parse_insert_idx = explicit_parse_idx.or(auto_parse_idx);
        self.parsed_args_active = parse_insert_idx.is_some() && !self.flag_schemas.is_empty();

        for (idx, stmt) in program.statements.iter().enumerate() {
            if parse_insert_idx == Some(idx) {
                self.emit_flag_parse_routine();
            }
            self.generate_statement(stmt);
        }

        if parse_insert_idx == Some(program.statements.len()) {
            self.emit_flag_parse_routine();
        }
        
        let mut result = String::new();
        
        result.push_str("; Generated by ec\n");
        result.push_str(&format!("; Target: {} Linux (NASM)\n\n", self.target_arch));
        
        if self.shared_lib_mode {
            result.push_str("default rel  ; Use RIP-relative addressing for PIC\n\n");
            // Shared libraries don't include coreasm - they're pure function exports
        } else {
            // Always needed: core
            result.push_str(&format!("%include \"coreasm/{}/core.asm\"\n", self.target_arch));
            // Conditional includes based on usage
            if self.uses_io {
                result.push_str(&format!("%include \"coreasm/{}/io.asm\"\n", self.target_arch));
            }
            if self.uses_files {
                result.push_str(&format!("%include \"coreasm/{}/file.asm\"\n", self.target_arch));
            }
            if self.uses_buffers || self.uses_files || self.uses_floats {
                result.push_str(&format!("%include \"coreasm/{}/resource.asm\"\n", self.target_arch));
            }
            if self.uses_ints {
                result.push_str(&format!("%include \"coreasm/{}/int.asm\"\n", self.target_arch));
            }
            if self.uses_floats {
                result.push_str(&format!("%include \"coreasm/{}/float.asm\"\n", self.target_arch));
            }
            if program.uses_heap {
                result.push_str(&format!("%include \"coreasm/{}/heap.asm\"\n", self.target_arch));
            }
            if program.uses_strings || self.uses_strings {
                result.push_str(&format!("%include \"coreasm/{}/string.asm\"\n", self.target_arch));
            }
            if program.uses_args {
                result.push_str(&format!("%include \"coreasm/{}/args.asm\"\n", self.target_arch));
            }
            if self.uses_time {
                result.push_str(&format!("%include \"coreasm/{}/time.asm\"\n", self.target_arch));
            }
            if self.uses_format {
                result.push_str(&format!("%include \"coreasm/{}/format.asm\"\n", self.target_arch));
            }
            if self.uses_funcs {
                result.push_str(&format!("%include \"coreasm/{}/funcs.asm\"\n", self.target_arch));
            }
            if self.uses_lists {
                result.push_str(&format!("%include \"coreasm/{}/list.asm\"\n", self.target_arch));
            }
        }
        result.push('\n');
        
        result.push_str("section .data\n");
        result.push_str(&self.data_section);
        result.push('\n');
        
        if !self.bss_section.is_empty() {
            result.push_str("section .bss\n");
            result.push_str(&self.bss_section);
            result.push('\n');
        }
        
        result.push_str("section .text\n");
        
        if self.shared_lib_mode {
            // Shared library mode: export functions, no _start
            for func in &self.exported_functions {
                result.push_str(&format!("global {}\n", func));
            }
            result.push('\n');
            
            // Only include user-defined functions
            if !self.functions_section.is_empty() {
                result.push_str("; Exported library functions\n");
                result.push_str(&self.functions_section);
            }
        } else {
            // Executable mode: normal _start entry point
            result.push_str("global _start\n\n");
            result.push_str("_start:\n");
            
            // Save arguments BEFORE setting up stack frame (critical for correct argc/argv/envp capture)
            if program.uses_args {
                result.push_str("    ; Save command-line arguments and environment\n");
                result.push_str("    SAVE_ARGS\n\n");
            }
            
            result.push_str("    push rbp\n");
            result.push_str("    mov rbp, rsp\n");
            if self.stack_offset > 0 {
                result.push_str(&format!("    sub rsp, {}\n", (self.stack_offset + 15) & !15));
            }
            result.push('\n');
            
            result.push_str(&self.output);
            
            // Only cleanup if we used resources
            if self.uses_files || self.uses_buffers {
                result.push_str("\n    ; Cleanup all resources before exit\n");
                result.push_str("    call _cleanup_all\n");
            }
            result.push_str("\n    ; Exit program\n");
            result.push_str("    EXIT 0\n");
            
            // Append user-defined functions
            if !self.functions_section.is_empty() {
                result.push_str("\n; User-defined functions\n");
                result.push_str(&self.functions_section);
            }
        }
        
        result
    }
    
    fn generate_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Print { value, without_newline } => {
                self.generate_print(value, *without_newline);
            }
            
            Statement::VarDecl { name, var_type, value } => {
                // Reuse existing slot for reassignment, otherwise allocate new
                let had_existing_slot = self.variables.contains_key(name);
                let offset = if let Some(&existing) = self.variables.get(name) {
                    existing
                } else {
                    self.stack_offset += 8;
                    self.variables.insert(name.clone(), self.stack_offset);
                    self.stack_offset
                };
                
                // Track variable type from declaration
                if let Some(ref t) = var_type {
                    let vt = match t {
                        Type::String => VarType::String,
                        Type::Integer => VarType::Integer,
                        Type::Float => VarType::Float,
                        Type::Boolean => VarType::Boolean,
                        Type::Buffer => VarType::Buffer,
                        Type::List(_) => VarType::List,
                        _ => VarType::Unknown,
                    };
                    self.variable_types.insert(name.clone(), vt);
                }
                
                if let Some(val) = value {
                    // Track list type and element type for lists
                    if let Expr::ListLit { elements } = val {
                        self.variable_types.insert(name.clone(), VarType::List);
                        // Track element type separately
                        if let Some(first) = elements.first() {
                            let elem_type = match first {
                                Expr::StringLit(_) => VarType::String,
                                Expr::IntegerLit(_) => VarType::Integer,
                                Expr::FloatLit(_) => VarType::Float,
                                Expr::BoolLit(_) => VarType::Boolean,
                                _ => VarType::Unknown,
                            };
                            self.list_element_types.insert(name.clone(), elem_type);
                        }
                    }
                    // Float literals set float type
                    else if self.is_float_expr(val) {
                        self.variable_types.insert(name.clone(), VarType::Float);
                    }
                    // ArgumentAll/ArgumentRaw produce lists of strings
                    else if matches!(val, Expr::ArgumentAll | Expr::ArgumentRaw) {
                        self.variable_types.insert(name.clone(), VarType::List);
                        self.list_element_types.insert(name.clone(), VarType::String);
                    }
                    // Argument/environment expressions return string pointers
                    else if matches!(val,
                        Expr::ArgumentAt { .. } | Expr::ArgumentName | Expr::ArgumentFirst |
                        Expr::ArgumentSecond | Expr::ArgumentLast |
                        Expr::EnvironmentVariable { .. } | Expr::EnvironmentVariableAt { .. } |
                        Expr::EnvironmentVariableFirst | Expr::EnvironmentVariableLast
                    ) {
                        self.variable_types.insert(name.clone(), VarType::String);
                    }
                    // Initializing from another variable: inherit its type
                    // (and element type, for lists) unless the declaration
                    // already pinned one. Without this, `a list called "b"
                    // is the a.` left "b" untyped and property access
                    // misrouted to the file fallback (_file_size).
                    else if var_type.is_none() || matches!(var_type, Some(Type::List(_))) {
                        let src_name = match val {
                            Expr::Identifier(src) => Some(src),
                            Expr::StringLit(src) if self.variables.contains_key(src) => Some(src),
                            _ => None,
                        };
                        if let Some(src) = src_name {
                            if let Some(vt) = self.variable_types.get(src).cloned() {
                                self.variable_types.insert(name.clone(), vt);
                            }
                            if let Some(et) = self.list_element_types.get(src).cloned() {
                                self.list_element_types.insert(name.clone(), et);
                            }
                        }
                    }
                    
                    // Special handling for buffer initialization/assignment with text/format/buffer source
                    let is_buffer_target = matches!(var_type, Some(Type::Buffer))
                        || self.variable_types.get(name) == Some(&VarType::Buffer);
                    if is_buffer_target {
                        if matches!(val, Expr::FunctionCall { .. }) {
                            // Buffer declarations initialized from function calls should take
                            // the returned buffer pointer directly (rax), not format-append it.
                            self.generate_expr(val);
                            self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                            self.uses_buffers = true;
                        } else {
                        if !had_existing_slot {
                            self.emit_indent("mov rdi, 1024  ; default buffer size");
                            self.emit_indent("call _alloc_buffer");
                            self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                            self.uses_buffers = true;
                        }

                        if !self.emit_copy_expr_into_buffer_slot(val, true, Some(offset), None) {
                            self.generate_expr(val);
                            self.emit_clear_buffer_slot(offset);
                            let fmt_spec = self.parse_format_spec(None);
                            self.emit_append_runtime_value_to_buffer_slot(offset, self.infer_expr_type(val), fmt_spec);
                        }
                        }
                    } else {
                        self.generate_expr(val);
                        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                    }
                } else {
                    // No initial value - initialize based on type
                    if let Some(ref t) = var_type {
                        match t {
                            Type::Buffer => {
                                // Allocate an empty buffer with proper initialization
                                self.emit_indent("mov rdi, 1024  ; default buffer size");
                                self.emit_indent("call _alloc_buffer");
                                self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                                self.uses_buffers = true;
                            }
                            Type::List(_) => {
                                // Allocate an empty list; a null pointer here
                                // would make the first append dereference 0.
                                self.generate_expr(&Expr::ListLit { elements: vec![] });
                                self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                            }
                            _ => {
                                // Initialize to 0/null
                                self.emit_indent(&format!("mov qword [rbp-{}], 0", offset));
                            }
                        }
                    } else {
                        // No type info - initialize to 0
                        self.emit_indent(&format!("mov qword [rbp-{}], 0", offset));
                    }
                }

                self.emit_mirror_stack_var_to_global_if_needed(name, offset);
            }

            Statement::FlagSchemaDecl { name, value_type, default, .. } => {
                // Current bootstrap behavior: represent parsed flag value as a normal variable slot.
                // Runtime schema parsing/assignment is emitted in a later iteration.
                let offset = if let Some(&existing) = self.variables.get(name) {
                    existing
                } else {
                    self.stack_offset += 8;
                    self.variables.insert(name.clone(), self.stack_offset);
                    self.stack_offset
                };

                let vt = match value_type {
                    FlagValueType::Boolean => VarType::Boolean,
                    FlagValueType::Number => VarType::Integer,
                    FlagValueType::Text => VarType::String,
                };
                self.variable_types.insert(name.clone(), vt);

                if let Some(expr) = default {
                    self.generate_expr(expr);
                    self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                } else {
                    self.emit_indent(&format!("mov qword [rbp-{}], 0", offset));
                }

                self.emit_mirror_stack_var_to_global_if_needed(name, offset);
            }

            Statement::ParseFlags => {
                // Explicit parse point is currently a no-op placeholder. Runtime parsing is
                // planned to be emitted around this marker in a subsequent iteration.
            }
            
            Statement::Assignment { name, value } => {
                if let Some(offset) = self.get_var(name) {
                    if self.variable_types.get(name) != Some(&VarType::Buffer) {
                        if let Some(vt) = self.infer_expr_type(value) {
                            match vt {
                                VarType::Float => {
                                    self.variable_types.insert(name.clone(), VarType::Float);
                                }
                                VarType::Integer | VarType::Boolean | VarType::String | VarType::List => {
                                    self.variable_types.insert(name.clone(), vt);
                                }
                                VarType::Buffer | VarType::Unknown => {}
                            }
                        }
                    }
                    if self.variable_types.get(name) == Some(&VarType::Buffer) {
                        if !self.emit_copy_expr_into_buffer_slot(value, true, Some(offset), None) {
                            self.generate_expr(value);
                            self.emit_clear_buffer_slot(offset);
                            let fmt_spec = self.parse_format_spec(None);
                            self.emit_append_runtime_value_to_buffer_slot(offset, self.infer_expr_type(value), fmt_spec);
                        }
                    } else {
                        self.generate_expr(value);
                        self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                    }
                    self.emit_mirror_stack_var_to_global_if_needed(name, offset);
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    self.generate_expr(value);
                    self.emit_indent(&format!("mov [rel {}], rax", label));
                } else {
                    self.generate_expr(value);
                    let offset = self.alloc_var(name);
                    self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                }
            }
            
            Statement::If { condition, then_block, else_if_blocks, else_block } => {
                let end_label = self.new_label("if_end");
                let else_label = self.new_label("else");
                
                self.generate_condition(condition, &else_label);
                
                for s in then_block {
                    self.generate_statement(s);
                }
                self.emit_indent(&format!("jmp {}", end_label));
                
                self.emit(&format!("{}:", else_label));
                
                if !else_if_blocks.is_empty() {
                    for (i, (cond, block)) in else_if_blocks.iter().enumerate() {
                        let next_label = if i + 1 < else_if_blocks.len() || else_block.is_some() {
                            self.new_label("elif")
                        } else {
                            end_label.clone()
                        };
                        
                        self.generate_condition(cond, &next_label);
                        
                        for s in block {
                            self.generate_statement(s);
                        }
                        self.emit_indent(&format!("jmp {}", end_label));
                        if next_label != end_label {
                            self.emit(&format!("{}:", next_label));
                        }
                    }
                }
                
                if let Some(block) = else_block {
                    for s in block {
                        self.generate_statement(s);
                    }
                }
                
                self.emit(&format!("{}:", end_label));
            }
            
            Statement::While { condition, body } => {
                let start_label = self.new_label("while_start");
                let end_label = self.new_label("while_end");
                
                self.emit(&format!("{}:", start_label));
                self.generate_condition(condition, &end_label);

                self.loop_stack.push((start_label.clone(), end_label.clone()));
                
                for s in body {
                    self.generate_statement(s);
                }
                self.loop_stack.pop();
                
                self.emit_indent(&format!("jmp {}", start_label));
                self.emit(&format!("{}:", end_label));
            }
            
            Statement::ForRange { variable, range, body } => {
                let start_label = self.new_label("for_start");
                let continue_label = self.new_label("for_continue");
                let end_label = self.new_label("for_end");
                
                if let Expr::Range { start, end, inclusive } = range {
                    self.generate_expr(start);
                    let var_offset = self.alloc_var(variable);
                    self.variables.insert("_iter".to_string(), var_offset);
                    self.emit_indent(&format!("mov [rbp-{}], rax", var_offset));
                    
                    self.generate_expr(end);
                    let end_offset = self.alloc_var(&format!("{}_end", variable));
                    if *inclusive {
                        self.emit_indent("inc rax");
                    }
                    self.emit_indent(&format!("mov [rbp-{}], rax", end_offset));
                    
                    self.emit(&format!("{}:", start_label));
                    
                    self.emit_indent(&format!("mov rax, [rbp-{}]", var_offset));
                    self.emit_indent(&format!("cmp rax, [rbp-{}]", end_offset));
                    self.emit_indent(&format!("jge {}", end_label));

                    self.loop_stack.push((continue_label.clone(), end_label.clone()));
                    
                    for s in body {
                        self.generate_statement(s);
                    }
                    self.loop_stack.pop();

                    self.emit(&format!("{}:", continue_label));
                    
                    self.emit_indent(&format!("inc qword [rbp-{}]", var_offset));
                    self.emit_indent(&format!("jmp {}", start_label));
                    
                    self.emit(&format!("{}:", end_label));
                }
            }
            
            Statement::Repeat { count, body } => {
                let start_label = self.new_label("repeat_start");
                let continue_label = self.new_label("repeat_continue");
                let end_label = self.new_label("repeat_end");
                
                self.generate_expr(count);
                let counter_offset = self.alloc_var("_repeat_counter");
                self.emit_indent(&format!("mov [rbp-{}], rax", counter_offset));
                
                self.emit(&format!("{}:", start_label));
                
                self.emit_indent(&format!("cmp qword [rbp-{}], 0", counter_offset));
                self.emit_indent(&format!("jle {}", end_label));

                self.loop_stack.push((continue_label.clone(), end_label.clone()));
                
                for s in body {
                    self.generate_statement(s);
                }
                self.loop_stack.pop();

                self.emit(&format!("{}:", continue_label));
                
                self.emit_indent(&format!("dec qword [rbp-{}]", counter_offset));
                self.emit_indent(&format!("jmp {}", start_label));
                
                self.emit(&format!("{}:", end_label));
            }
            
            Statement::Allocate { name, size } => {
                self.generate_expr(size);
                self.emit_indent("HEAP_ALLOC rax");
                let offset = self.alloc_var(name);
                self.emit_indent(&format!("mov [rbp-{}], rax", offset));
            }
            
            Statement::Free { name } => {
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
                    self.emit_indent("HEAP_FREE rdi");
                }
            }
            
            Statement::Increment { name } => {
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("inc qword [rbp-{}]", offset));
                    self.emit_mirror_stack_var_to_global_if_needed(name, offset);
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    self.emit_indent(&format!("inc qword [rel {}]", label));
                }
            }
            
            Statement::Decrement { name } => {
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("dec qword [rbp-{}]", offset));
                    self.emit_mirror_stack_var_to_global_if_needed(name, offset);
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    self.emit_indent(&format!("dec qword [rel {}]", label));
                }
            }
            
            Statement::Break => {
                self.emit_indent("; break");
                if let Some((_, break_label)) = self.loop_stack.last() {
                    self.emit_indent(&format!("jmp {}", break_label));
                }
            }
            
            Statement::Exit { code } => {
                self.emit_indent("; exit program");
                self.generate_expr(code);
                self.emit_indent("mov rdi, rax  ; exit code");
                if self.uses_files || self.uses_buffers {
                    self.emit_indent("push rdi      ; save exit code");
                    self.emit_indent("call _cleanup_all");
                    self.emit_indent("pop rdi       ; restore exit code");
                }
                self.emit_indent("EXIT rdi");
            }
            
            Statement::Continue => {
                self.emit_indent("; continue");
                if let Some((continue_label, _)) = self.loop_stack.last() {
                    self.emit_indent(&format!("jmp {}", continue_label));
                }
            }
            
            Statement::Return { value } => {
                if let Some(v) = value {
                    self.generate_expr(v); // should leave return value in RAX
                }
                if self.in_function_codegen {
                    self.emit_indent("push rax  ; save return value");
                    self.emit_indent("call _dec_call_depth");
                    self.emit_indent("pop rax  ; restore return value");
                }
                self.emit_indent("FUNC_EPILOGUE");
            }
            
            Statement::FunctionCall { name, args } => {
                // Mark that we're using functions so funcs.asm gets included
                self.uses_funcs = true;
                self.emit_function_call(name, args);
            }
                        
            Statement::FunctionDef { name, params, body, .. } => {
                // Mark that we're using functions so funcs.asm gets included
                self.uses_funcs = true;
                
                let func_label = name.replace(' ', "_");

                // Track exported functions for shared library mode
                if self.shared_lib_mode {
                    self.exported_functions.push(func_label.clone());
                }

                // Save outer codegen state
                let saved_output = std::mem::take(&mut self.output);
                let saved_vars = std::mem::take(&mut self.variables);
                let saved_stack = self.stack_offset;
                let saved_loop_stack = std::mem::take(&mut self.loop_stack);
                let saved_in_function_codegen = self.in_function_codegen;

                // Fresh function-local state
                self.output = String::new();
                self.variables = std::collections::HashMap::new();
                self.stack_offset = 0;
                self.loop_stack = Vec::new();
                self.in_function_codegen = true;

                // ------------------------------------------------------------
                // PASS 1: Allocate stack slots for params, then generate body
                // into a temporary buffer to discover the true frame size.
                // ------------------------------------------------------------

                // Allocate param stack slots FIRST so offsets are stable.
                // Also register param types so they're known in function body.
                for (param_name, param_type) in params.iter() {
                    self.alloc_var(param_name);
                    let var_type = match param_type {
                        Type::Integer => VarType::Integer,
                        Type::Float => VarType::Float,
                        Type::String => VarType::String,
                        Type::Boolean => VarType::Boolean,
                        Type::List(_) => VarType::List,
                        Type::Buffer => VarType::Buffer,
                        _ => VarType::Unknown,
                    };
                    self.variable_types.insert(param_name.clone(), var_type);
                }

                // Generate body into a temp buffer (this will call alloc_var for locals too)
                let mut has_return = false;

                let saved_tmp_out = std::mem::take(&mut self.output);
                self.output = String::new();

                for stmt in body {
                    if matches!(stmt, Statement::Return { .. }) {
                        has_return = true;
                    }
                    self.generate_statement(stmt);
                }

                // If no explicit return, add a default epilogue
                if !has_return {
                    self.emit_indent("call _dec_call_depth");
                    self.emit_indent("FUNC_EPILOGUE");
                }

                let body_code = std::mem::take(&mut self.output);
                self.output = saved_tmp_out;

                // Now we KNOW the frame size needed (params + locals + temps)
                let frame_size = (self.stack_offset + 15) & !15;

                // ------------------------------------------------------------
                // PASS 2: Emit the real function with correct prologue + param stores,
                // then append the already-generated body code.
                // ------------------------------------------------------------

                self.emit(&format!("{}:", func_label));
                self.emit_indent(&format!("FUNC_PROLOGUE {}", frame_size));
                // Recursion depth guard - save param regs, check depth, restore
                let num_params = params.len().min(6);
                for i in 0..num_params {
                    self.emit_indent(&format!("push {}  ; save param reg", ["rdi", "rsi", "rdx", "rcx", "r8", "r9"][i]));
                }
                self.emit_indent("call _check_call_depth");
                for i in (0..num_params).rev() {
                    self.emit_indent(&format!("pop {}  ; restore param reg", ["rdi", "rsi", "rdx", "rcx", "r8", "r9"][i]));
                }

                // Store parameters after frame is allocated
                let param_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
                for (i, (param_name, _)) in params.iter().enumerate() {
                    if let Some(offset) = self.get_var(param_name) {
                        if i < param_regs.len() {
                            self.emit_indent(&format!("mov [rbp-{}], {}", offset, param_regs[i]));
                        } else {
                            // SysV x86_64: 7th arg is at [rbp+16], then +8 each.
                            // +8  = return address
                            // +0  = saved rbp
                            // so stack args start at +16
                            let stack_arg_off = 16 + (i - param_regs.len()) * 8;
                            self.emit_indent(&format!("mov rax, [rbp+{}]", stack_arg_off));
                            self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                        }
                    }
                }

                // Append the already-generated body
                self.output.push_str(&body_code);
                self.emit("");

                // Capture the finished function code
                let func_code = std::mem::take(&mut self.output);

                // Restore outer codegen state
                self.output = saved_output;
                self.variables = saved_vars;
                self.stack_offset = saved_stack;
                self.loop_stack = saved_loop_stack;
                self.in_function_codegen = saved_in_function_codegen;

                // Append to functions section
                self.functions_section.push_str(&format!("; Function: {}\n", name));
                self.functions_section.push_str(&func_code);
            }

            
            Statement::ForEach { variable, collection, body } => {
                let start_label = self.new_label("foreach_start");
                let continue_label = self.new_label("foreach_continue");
                let end_label = self.new_label("foreach_end");
                
                // Special handling for arguments lists
                if matches!(collection, Expr::ArgumentAll | Expr::ArgumentRaw) {
                    if matches!(collection, Expr::ArgumentAll) {
                        self.emit_indent("call _get_parsed_argc");
                    } else {
                        self.emit_indent("call _get_raw_argc");
                    }
                    let argc_var = self.alloc_var(&format!("{}_argc", variable));
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; arg count", argc_var));

                    // Initialize index to 0 (user-arg-relative)
                    let index_var = self.alloc_var(&format!("{}_idx", variable));
                    self.emit_indent(&format!("mov qword [rbp-{}], 0", index_var));
                    
                    // Allocate variable for current element
                    let elem_var = self.alloc_var(variable);
                    self.variables.insert(variable.clone(), elem_var);
                    self.variable_types.insert(variable.clone(), VarType::String);
                    
                    self.emit(&format!("{}:", start_label));
                    
                    // Check if index < count
                    self.emit_indent(&format!("mov rax, [rbp-{}]  ; index", index_var));
                    self.emit_indent(&format!("cmp rax, [rbp-{}]  ; compare with count", argc_var));
                    self.emit_indent(&format!("jge {}", end_label));
                    
                    // Get current argument pointer from selected view
                    self.emit_indent("mov rdi, rax");
                    if matches!(collection, Expr::ArgumentAll) {
                        self.emit_indent("call _get_parsed_arg");
                    } else {
                        self.emit_indent("call _get_raw_arg");
                    }
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; store in {}", elem_var, variable));
                    
                    // Generate body
                    self.loop_stack.push((continue_label.clone(), end_label.clone()));
                    for s in body {
                        self.generate_statement(s);
                    }
                    self.loop_stack.pop();

                    self.emit(&format!("{}:", continue_label));
                    
                    // Increment index
                    self.emit_indent(&format!("inc qword [rbp-{}]", index_var));
                    self.emit_indent(&format!("jmp {}", start_label));
                    
                    self.emit(&format!("{}:", end_label));
                    return;
                }
                
                // Determine element type from list
                let elem_type = if let Expr::Identifier(list_name) = collection {
                    // Get element type from list_element_types, not variable_types
                    self.list_element_types.get(list_name).cloned().unwrap_or(VarType::Unknown)
                } else if let Expr::ListLit { elements } = collection {
                    if let Some(first) = elements.first() {
                        match first {
                            Expr::StringLit(_) => VarType::String,
                            Expr::IntegerLit(_) => VarType::Integer,
                            Expr::BoolLit(_) => VarType::Boolean,
                            _ => VarType::Unknown,
                        }
                    } else {
                        VarType::Unknown
                    }
                } else {
                    VarType::Unknown
                };
                
                // Get list pointer
                // List structure: [capacity:8][length:8][elem_size:8][data...]
                self.generate_expr(collection);
                let list_ptr = self.alloc_var(&format!("{}_list", variable));
                self.emit_indent(&format!("mov [rbp-{}], rax  ; list pointer", list_ptr));
                
                // Get list length (at offset 8)
                self.emit_indent("mov rax, [rax + 8]  ; get length (offset 8)");
                let list_len = self.alloc_var(&format!("{}_len", variable));
                self.emit_indent(&format!("mov [rbp-{}], rax  ; list length", list_len));
                
                // Initialize index to 0
                let index_var = self.alloc_var(&format!("{}_idx", variable));
                self.emit_indent(&format!("mov qword [rbp-{}], 0  ; index", index_var));
                
                // Allocate variable for current element and track its type
                let elem_var = self.alloc_var(variable);
                self.variables.insert(variable.clone(), elem_var);
                self.variable_types.insert(variable.clone(), elem_type);
                
                self.emit(&format!("{}:", start_label));
                
                // Check if index < length
                self.emit_indent(&format!("mov rax, [rbp-{}]  ; index", index_var));
                self.emit_indent(&format!("cmp rax, [rbp-{}]  ; compare with length", list_len));
                self.emit_indent(&format!("jge {}", end_label));
                
                // Get current element: data starts at offset 24
                self.emit_indent(&format!("mov rbx, [rbp-{}]  ; list pointer", list_ptr));
                self.emit_indent("shl rax, 3  ; index * 8");
                self.emit_indent("add rax, 24  ; skip header (24 bytes)");
                self.emit_indent("add rbx, rax");
                self.emit_indent("mov rax, [rbx]  ; get element");
                self.emit_indent(&format!("mov [rbp-{}], rax  ; store in {}", elem_var, variable));
                
                // Generate body
                self.loop_stack.push((continue_label.clone(), end_label.clone()));
                for s in body {
                    self.generate_statement(s);
                }
                self.loop_stack.pop();

                self.emit(&format!("{}:", continue_label));
                
                // Increment index
                self.emit_indent(&format!("inc qword [rbp-{}]", index_var));
                self.emit_indent(&format!("jmp {}", start_label));
                
                self.emit(&format!("{}:", end_label));
            }
            
            // File I/O statements
            Statement::BufferDecl { name, size } => {
                // Reuse an existing slot for the same buffer name, exactly like
                // VarDecl reassignment. This ensures a buffer declared in both
                // branches of an if/otherwise pair shares a single stack slot,
                // so code after the branch reads the slot that was actually
                // written at runtime.
                let offset = if let Some(&existing) = self.variables.get(name) {
                    existing
                } else {
                    self.stack_offset += 8;
                    self.variables.insert(name.clone(), self.stack_offset);
                    self.stack_offset
                };
                self.variable_types.insert(name.clone(), VarType::Buffer);

                // Check if size is specified (non-zero)
                let is_sized = match size {
                    Expr::IntegerLit(0) => false,
                    Expr::IntegerLit(_) => true,
                    _ => true, // Any expression means sized
                };

                if is_sized {
                    // Fixed-size buffer (bounds checked, no auto-grow)
                    self.generate_expr(size);
                    self.emit_indent("mov rdi, rax  ; buffer size");
                    self.emit_indent("call _alloc_buffer_sized");
                } else {
                    // Dynamic buffer (auto-grows, tracked for cleanup)
                    self.emit_indent("call _alloc_buffer");
                }
                self.uses_buffers = true;
                self.emit_indent(&format!("mov [rbp-{}], rax  ; buffer struct pointer", offset));

                // Top-level/branch-declared buffers must be mirrored into BSS
                // so functions can read (and write) them via the global label.
                self.emit_mirror_stack_var_to_global_if_needed(name, offset);
            }
            
            Statement::ByteSet { buffer, index, value } => {
                let ok_label = self.new_label("bset_ok");
                let error_label = self.new_label("bset_err");
                let done_label = self.new_label("bset_done");
                let noupd_label = self.new_label("bset_noupd");

                self.emit_indent("; Set byte N of buffer to value (with bounds check)");
                // Get buffer pointer (local or global mirror)
                self.emit_load_named_var_addr(buffer);
                self.emit_indent("mov rbx, rax  ; buffer ptr");
                self.emit_indent("push rbx  ; save buffer pointer");
                // Get index
                self.generate_expr(index);
                self.emit_indent("mov rcx, rax  ; index in rcx (1-indexed)");
                self.emit_indent("pop rbx  ; buffer pointer in rbx");

                // Bounds check: index must be >= 1
                self.emit_indent("cmp rcx, 1");
                self.emit_indent(&format!("jl {}  ; index < 1 is error", error_label));
                self.emit_indent("mov rdx, [rbx]  ; get buffer capacity (offset 0)");
                self.emit_indent("cmp rcx, rdx");
                self.emit_indent(&format!("jle {}  ; index <= capacity is OK", ok_label));

                // Index beyond current capacity: dynamic buffers auto-grow,
                // fixed buffers are an error.
                self.emit_indent("mov rdx, [rbx + 16]  ; buffer flags");
                self.emit_indent("test rdx, 1  ; BUF_FLAG_FIXED");
                self.emit_indent(&format!("jnz {}  ; fixed buffer overflow", error_label));

                // Grow dynamic buffer so the 1-indexed position fits.
                self.emit_indent("push rcx  ; save index across grow call");
                self.emit_indent("mov rdi, rbx  ; buffer pointer");
                self.emit_indent("mov rsi, rcx  ; required capacity = index");
                self.emit_indent("call _grow_buffer");
                self.emit_indent("mov rbx, rax  ; new buffer pointer");
                if let Some(offset) = self.get_var(buffer) {
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; update buffer pointer", offset));
                }
                self.emit_indent("pop rcx  ; restore 1-indexed position");
                self.emit_indent(&format!("jmp {}  ; grown buffer now has space", ok_label));

                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent(&format!("jmp {}", done_label));

                // Success path: safe write
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("push rbx  ; save buffer pointer");
                self.emit_indent("push rcx  ; save 1-indexed position");
                // Get value
                self.generate_expr(value);
                self.emit_indent("mov rdx, rax  ; value in rdx");
                self.emit_indent("pop rcx  ; 1-indexed position in rcx");
                self.emit_indent("pop rbx  ; buffer pointer in rbx");
                // Update length = max(length, index) so reads see the written bytes
                self.emit_indent("cmp rcx, [rbx + 8]  ; compare index with current length");
                self.emit_indent(&format!("jle {}  ; skip if length already >= index", noupd_label));
                self.emit_indent("mov [rbx + 8], rcx  ; extend length to include this byte");
                self.emit(&format!("{}:", noupd_label));
                self.emit_indent("dec rcx  ; convert 1-indexed to 0-indexed");
                self.emit_indent("add rbx, 24  ; skip to buffer data area");
                self.emit_indent("mov [rbx + rcx], dl  ; write byte");

                self.emit(&format!("{}:", done_label));
            }
            
            Statement::ElementSet { list, index, value } => {
                let ok_label = self.new_label("eset_ok");
                let error_label = self.new_label("eset_err");
                let done_label = self.new_label("eset_done");

                self.emit_indent("; Set element N of list to value (with bounds check)");
                // Get list pointer (local or global mirror)
                self.emit_load_named_var_addr(list);
                self.emit_indent("mov rbx, rax  ; list ptr");
                self.emit_indent("push rbx  ; save list pointer");
                // Get index (1-indexed)
                self.generate_expr(index);
                self.emit_indent("mov rcx, rax  ; index in rcx (1-indexed)");
                self.emit_indent("pop rbx  ; list pointer in rbx");

                // Bounds check: index must be >= 1 and <= length
                self.emit_indent("cmp rcx, 1");
                self.emit_indent(&format!("jl {}  ; index < 1 is error", error_label));
                self.emit_indent("mov rdx, [rbx + 8]  ; get list length (offset 8)");
                self.emit_indent("cmp rcx, rdx");
                self.emit_indent(&format!("jle {}  ; index <= length is OK", ok_label));

                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent(&format!("jmp {}", done_label));

                // Success path: safe write
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("dec rcx  ; convert 1-indexed to 0-indexed");
                self.emit_indent("push rbx  ; save list pointer");
                self.emit_indent("push rcx  ; save index");
                // Get value
                self.generate_expr(value);
                self.emit_indent("mov r8, rax  ; value in r8");
                self.emit_indent("pop rcx  ; index in rcx");
                self.emit_indent("pop rbx  ; list pointer in rbx");
                // Get element size (at offset 16 in list structure)
                self.emit_indent("mov rdx, [rbx + 16]  ; element size");
                // Calculate offset
                self.emit_indent("imul rcx, rdx  ; index * element_size");
                self.emit_indent("add rcx, 24  ; data starts at offset 24");
                // Write element
                self.emit_indent("mov [rbx + rcx], r8  ; write element");

                self.emit(&format!("{}:", done_label));
            }
            
            Statement::ListAppend { list, value } => {
                if self.variable_types.get(list) == Some(&VarType::Buffer) {
                    let dst_local = self.get_var(list);
                    let dst_global = self.global_var_label(list).cloned();
                    if dst_local.is_some() || dst_global.is_some() {
                        if !self.emit_copy_expr_into_buffer_slot(value, false, dst_local, dst_global.as_deref()) {
                            self.generate_expr(value);
                            let fmt_spec = self.parse_format_spec(None);
                            if let Some(offset) = dst_local {
                                self.emit_append_runtime_value_to_buffer_slot(offset, self.infer_expr_type(value), fmt_spec);
                            } else if let Some(ref label) = dst_global {
                                self.emit_load_named_var_addr(list);
                                self.emit_indent("mov rdi, rax");
                                self.emit_append_runtime_value_to_buffer_ptr(self.infer_expr_type(value), fmt_spec);
                                self.emit_indent(&format!("mov [rel {}], rax", label));
                            }
                        }
                    }
                    return;
                }

                self.uses_lists = true;
                self.emit_indent("; Append value to list");
                
                // Track element type from appended value if not already set
                if !self.list_element_types.contains_key(list) {
                    let elem_type = match value {
                        Expr::StringLit(_) => VarType::String,
                        Expr::IntegerLit(_) => VarType::Integer,
                        Expr::FloatLit(_) => VarType::Float,
                        Expr::BoolLit(_) => VarType::Boolean,
                        Expr::Identifier(name) => {
                            // Buffer variables produce string elements when appended
                            match self.variable_types.get(name) {
                                Some(VarType::Buffer) => VarType::String,
                                Some(t) => t.clone(),
                                None => VarType::Unknown,
                            }
                        }
                        _ => VarType::Unknown,
                    };
                    if elem_type != VarType::Unknown {
                        self.list_element_types.insert(list.clone(), elem_type);
                    }
                }
                
                // Resolve list pointer (local slot or global mirror) and save it.
                let list_ptr_loaded = self.emit_load_named_var_addr(list);
                if list_ptr_loaded {
                    self.emit_indent("push rax  ; save list pointer");

                    // Check if the value is a buffer variable
                    let is_buffer_value = match value {
                        Expr::StringLit(name) | Expr::Identifier(name) => {
                            self.variable_types.get(name).map(|t| t == &VarType::Buffer).unwrap_or(false)
                        }
                        _ => false,
                    };

                    // Evaluate value to append
                    self.generate_expr(value);

                    if is_buffer_value {
                        // For buffer values, extract string data and duplicate it.
                        // Bounded by the buffer's own tracked length rather than
                        // scanning for NUL - see _strdup_bounded's comment for why
                        // (buffer content isn't reliably NUL-terminated at its
                        // logical end after a clear+shorter-rewrite).
                        self.uses_strings = true;
                        self.emit_indent("push rbx");
                        self.emit_indent("push r12");
                        self.emit_indent("mov rbx, rax  ; save buffer pointer");
                        self.emit_indent("mov rdi, rbx");
                        self.emit_indent("call _buffer_length");
                        self.emit_indent("mov r12, rax  ; save length");
                        self.emit_indent("mov rdi, rbx");
                        self.emit_indent("call _buffer_data  ; get data pointer");
                        self.emit_indent("mov rdi, rax  ; source string");
                        self.emit_indent("mov rsi, r12  ; max length");
                        self.emit_indent("call _strdup_bounded  ; duplicate string");
                        self.emit_indent("pop r12");
                        self.emit_indent("pop rbx");
                    }

                    self.emit_indent("push rax  ; save value to append");

                    // rdi = list pointer, rsi = value to append
                    self.emit_indent("pop rsi  ; value to append");
                    self.emit_indent("pop rdi  ; list ptr");
                    self.emit_indent("call _list_append");

                    // Store potentially new list pointer back to wherever it came from
                    if let Some(offset) = self.get_var(list) {
                        self.emit_indent(&format!("mov [rbp-{}], rax  ; store new list ptr", offset));
                    } else if let Some(label) = self.global_var_label(list).cloned() {
                        self.emit_indent(&format!("mov [rel {}], rax  ; store new list ptr", label));
                    }
                }
            }

            Statement::BufferCopy { source, destination } => {
                let dst_local = self.get_var(destination);
                let dst_global = self.global_var_label(destination).cloned();
                if dst_local.is_some() || dst_global.is_some() {
                    if !self.emit_copy_expr_into_buffer_slot(source, true, dst_local, dst_global.as_deref()) {
                        // Fallback for non-buffer source expressions.
                        // Load destination pointer into rdi, clear it, then append.
                        self.emit_load_named_var_addr(destination);
                        self.emit_indent("mov rdi, rax  ; destination buffer");
                        self.emit_indent("push rdi");
                        self.emit_indent("call _buffer_clear");
                        self.emit_indent("mov rdi, rax");
                        self.emit_indent("push rdi");
                        self.generate_expr(source);
                        let src_type = self.infer_expr_type(source);
                        let fmt_spec = self.parse_format_spec(None);
                        self.emit_append_runtime_value_to_buffer_ptr(src_type, fmt_spec);
                        self.emit_indent("pop rdi  ; original destination buffer pointer");
                        if let Some(offset) = dst_local {
                            self.emit_indent(&format!("mov [rbp-{}], rax  ; updated destination pointer", offset));
                        } else if let Some(ref label) = dst_global {
                            self.emit_indent(&format!("mov [rel {}], rax  ; updated destination pointer", label));
                        }
                    }
                }
            }

            Statement::BufferClear { name } => {
                self.uses_buffers = true;
                self.emit_indent("; Clear buffer contents");
                self.emit_load_named_var_addr(name);
                self.emit_indent("mov rdi, rax  ; buffer");
                self.emit_indent("call _buffer_clear");
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; buffer (unchanged pointer)", offset));
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    self.emit_indent(&format!("mov [rel {}], rax  ; buffer (unchanged pointer)", label));
                }
            }
            
            Statement::FileOpen { name, path, mode } => {
                self.uses_files = true;
                let path_is_fd = self.is_fd_path_expr(path);
                
                // Track if file is writable based on mode
                let is_writable = matches!(mode, FileMode::Writing | FileMode::Appending);
                self.file_writable.insert(name.clone(), is_writable);

                // Reuse the existing slot when the handle name is already
                // known, exactly like VarDecl reassignment. Two Opens of the
                // same name in an if/otherwise pair must share one slot -
                // separate slots meant code after the branch read whichever
                // slot the LAST-generated branch owned, which the branch
                // actually taken at runtime never wrote.
                let offset = if let Some(existing) = self.get_var(name) {
                    existing
                } else {
                    self.alloc_var(name)
                };

                if path_is_fd {
                    let fd_ok_label = self.new_label("fd_ok");
                    let fd_invalid_label = self.new_label("fd_invalid");
                    let fd_done_label = self.new_label("fd_done");

                    self.generate_expr(path);
                    self.emit_indent("; Treat numeric open path as file descriptor");
                    self.emit_indent("cmp rax, 0");
                    self.emit_indent(&format!("jl {}", fd_invalid_label));
                    self.emit_indent("mov rcx, 2147483647  ; i32::MAX");
                    self.emit_indent("cmp rax, rcx");
                    self.emit_indent(&format!("jle {}", fd_ok_label));
                    self.emit_indent(&format!("jmp {}", fd_invalid_label));

                    self.emit(&format!("{}:", fd_ok_label));
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; borrowed file descriptor", offset));
                    self.emit_indent("mov qword [rel _last_error], 0");
                    self.emit_indent(&format!("jmp {}", fd_done_label));

                    self.emit(&format!("{}:", fd_invalid_label));
                    self.emit_indent(&format!("mov qword [rbp-{}], -1  ; invalid fd", offset));
                    self.emit_indent("mov qword [rel _last_error], 22  ; EINVAL");

                    self.emit(&format!("{}:", fd_done_label));
                    self.emit_mirror_stack_var_to_global_if_needed(name, offset);
                    return;
                }

                // Generate path pointer for filesystem opens
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("lea rdi, [{}]", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("mov rdi, rax  ; path pointer");
                    }
                }
                
                // Open file with appropriate mode (path is in rdi)
                match mode {
                    FileMode::Reading => {
                        self.emit_indent("FILE_OPEN_READ rdi");
                    }
                    FileMode::Writing => {
                        self.emit_indent("FILE_OPEN_WRITE rdi");
                    }
                    FileMode::Appending => {
                        self.emit_indent("FILE_OPEN_APPEND rdi");
                    }
                }
                
                // Store file descriptor and register for tracking (only if valid)
                self.emit_indent(&format!("mov [rbp-{}], rax  ; file descriptor", offset));
                
                // Check for error (negative fd) and set _last_error
                let ok_label = self.new_label("file_ok");
                let done_label = self.new_label("file_done");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jns {}  ; jump if success (non-negative)", ok_label));
                
                // Error path: set _last_error
                self.emit_indent("neg rax  ; convert to positive errno");
                self.emit_indent("mov [rel _last_error], rax");
                self.emit_indent(&format!("jmp {}", done_label));
                
                // Success path: register fd for cleanup
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("mov qword [rel _last_error], 0  ; clear error");
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _register_fd  ; track for auto-cleanup");
                
                self.emit(&format!("{}:", done_label));
                self.emit_mirror_stack_var_to_global_if_needed(name, offset);
            }
            
            Statement::FileRead { source, buffer } => {
                // Get source fd
                let source_fd = if source == "stdin" {
                    "0".to_string()  // STDIN
                } else if let Some(offset) = self.get_var(source) {
                    format!("[rbp-{}]", offset)
                } else {
                    "0".to_string()
                };
                
                // Use dynamic read that auto-grows buffer (only if fd is valid)
                if let Some(buf_offset) = self.get_var(buffer) {
                    let skip_label = self.new_label("skip_fd");
                    self.emit_indent(&format!("mov rdi, {}", source_fd));
                    // Skip read if fd is invalid (negative)
                    self.emit_indent("test rdi, rdi");
                    self.emit_indent(&format!("js {}  ; skip if invalid fd", skip_label));
                    self.emit_indent(&format!("mov rsi, [rbp-{}]  ; buffer struct", buf_offset));
                    // Reset buffer length before reading (read replaces, not appends)
                    self.emit_indent("mov qword [rsi + 8], 0  ; reset buffer length");
                    self.emit_indent("call _read_into_buffer  ; auto-grows if needed");
                    // Update buffer pointer (may have changed if grown)
                    self.emit_indent(&format!("mov [rbp-{}], rsi  ; updated buffer ptr", buf_offset));
                    self.emit(&format!("{}:", skip_label));
                }
            }

            Statement::FileReadLine { source, buffer } => {
                // Get source fd
                let source_fd = if source == "stdin" {
                    "0".to_string()  // STDIN
                } else if let Some(offset) = self.get_var(source) {
                    format!("[rbp-{}]", offset)
                } else {
                    "0".to_string()
                };

                if let Some(buf_offset) = self.get_var(buffer) {
                    let skip_label = self.new_label("skip_fd");
                    self.emit_indent(&format!("mov rdi, {}", source_fd));
                    // Skip read if fd is invalid (negative)
                    self.emit_indent("test rdi, rdi");
                    self.emit_indent(&format!("js {}  ; skip if invalid fd", skip_label));
                    self.emit_indent(&format!("mov rsi, [rbp-{}]  ; buffer struct", buf_offset));
                    // Reset buffer length before reading (read replaces, not appends)
                    self.emit_indent("mov qword [rsi + 8], 0  ; reset buffer length");
                    self.emit_indent("call _read_line_into_buffer");
                    // Update buffer pointer (may have changed if grown)
                    self.emit_indent(&format!("mov [rbp-{}], rsi  ; updated buffer ptr", buf_offset));
                    self.emit(&format!("{}:", skip_label));
                }
            }

            Statement::FileSeekLine { file, line } => {
                self.uses_files = true;

                let file_fd = if let Some(offset) = self.get_var(file) {
                    format!("[rbp-{}]", offset)
                } else if let Some(label) = self.global_var_label(file).cloned() {
                    format!("[rel {}]", label)
                } else {
                    "0".to_string()
                };

                self.generate_expr(line);
                self.emit_indent("mov rsi, rax  ; target line (1-indexed)");
                self.emit_indent(&format!("mov rdi, {}", file_fd));
                self.emit_indent("call _seek_fd_line");
            }

            Statement::FileSeekByte { file, byte } => {
                self.uses_files = true;

                let file_fd = if let Some(offset) = self.get_var(file) {
                    format!("[rbp-{}]", offset)
                } else if let Some(label) = self.global_var_label(file).cloned() {
                    format!("[rel {}]", label)
                } else {
                    "0".to_string()
                };

                self.generate_expr(byte);
                self.emit_indent("mov rsi, rax  ; target byte (1-indexed)");
                self.emit_indent(&format!("mov rdi, {}", file_fd));
                self.emit_indent("call _seek_fd_byte");
            }
            
            Statement::FileWrite { file, value } => {
                // Get file fd
                let file_fd = if let Some(offset) = self.get_var(file) {
                    format!("[rbp-{}]", offset)
                } else if let Some(label) = self.global_var_label(file).cloned() {
                    format!("[rel {}]", label)
                } else {
                    "1".to_string()  // STDOUT as fallback
                };
                
                let skip_label = self.new_label("skip_fd");
                self.emit_indent(&format!("mov rdi, {}", file_fd));
                // Skip write if fd is invalid (negative)
                self.emit_indent("test rdi, rdi");
                self.emit_indent(&format!("js {}  ; skip if invalid fd", skip_label));
                
                match value {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("FILE_WRITE_STR rdi, {}", label));
                    }
                    Expr::Identifier(name) => {
                        if let Some(offset) = self.get_var(name) {
                            let var_type = self.variable_types.get(name).cloned();
                            self.emit_indent(&format!("mov rsi, [rbp-{}]", offset));
                            if matches!(var_type, Some(VarType::Buffer)) {
                                self.emit_indent("FILE_WRITE_BUF rdi, rsi");
                            } else {
                                self.emit_indent("FILE_WRITE_STR rdi, rsi");
                            }
                        } else if let Some(label) = self.global_var_label(name).cloned() {
                            let var_type = self.variable_types.get(name).cloned();
                            self.emit_indent(&format!("mov rsi, [rel {}]", label));
                            if matches!(var_type, Some(VarType::Buffer)) {
                                self.emit_indent("FILE_WRITE_BUF rdi, rsi");
                            } else {
                                self.emit_indent("FILE_WRITE_STR rdi, rsi");
                            }
                        }
                    }
                    Expr::TreatingAs { value: inner_val, match_value, replacement } => {
                        // Check if inner value is a buffer
                        let is_buffer = if let Expr::Identifier(ref name) = **inner_val {
                            self.variable_types.get(name) == Some(&VarType::Buffer)
                        } else {
                            false
                        };
                        
                        if is_buffer {
                            // For buffers, we need different write macros for match vs no-match
                            let skip_label = self.new_label("treating_skip");
                            let done_label = self.new_label("treating_done");
                            
                            self.emit_indent("push rdi");  // save fd
                            
                            // Generate buffer value
                            self.generate_expr(inner_val);
                            self.emit_indent("push rax  ; save buffer struct ptr");
                            
                            // Get the buffer's tracked length and data pointer.
                            // Use _mem_eq rather than _str_eq to avoid the stale-byte
                            // bug: the buffer's data area may not be NUL-terminated at
                            // its logical end after a clear+shorter-rewrite.
                            self.emit_indent("mov rdi, rax");
                            self.emit_indent("call _buffer_length");
                            self.emit_indent("mov rdx, rax  ; len1 = buf length");
                            self.emit_indent("mov rdi, [rsp]  ; reload buf struct ptr");
                            self.emit_indent("call _buffer_data");
                            self.emit_indent("mov rdi, rax  ; ptr1 = buf data");
                            self.generate_expr(match_value);
                            self.emit_indent("mov rsi, rax  ; ptr2 = match string");
                            self.emit_indent("push rdi      ; save ptr1 across str_len call");
                            self.emit_indent("push rsi      ; save ptr2");
                            self.emit_indent("push rdx      ; save len1");
                            self.emit_indent("mov rdi, rsi");
                            self.emit_indent("call _str_len");
                            self.emit_indent("mov rcx, rax  ; len2 = match string len");
                            self.emit_indent("pop rdx       ; restore len1");
                            self.emit_indent("pop rsi       ; restore ptr2");
                            self.emit_indent("pop rdi       ; restore ptr1");
                            self.emit_indent("call _mem_eq");
                            self.emit_indent("test rax, rax");
                            self.emit_indent(&format!("jz {}", skip_label));
                            
                            // Match: write replacement string
                            self.emit_indent("add rsp, 8  ; discard buffer ptr");
                            self.emit_indent("pop rdi  ; restore fd");
                            self.generate_expr(replacement);
                            self.emit_indent("FILE_WRITE_STR rdi, rax");
                            self.emit_indent(&format!("jmp {}", done_label));
                            
                            // No match: write original buffer
                            self.emit(&format!("{}:", skip_label));
                            self.emit_indent("pop rsi  ; restore buffer ptr");
                            self.emit_indent("pop rdi  ; restore fd");
                            self.emit_indent("FILE_WRITE_BUF rdi, rsi");
                            
                            self.emit(&format!("{}:", done_label));
                        } else {
                            // For non-buffers, use standard treating logic
                            self.emit_indent("push rdi");  // save fd
                            self.generate_expr(value);
                            self.emit_indent("mov rsi, rax");
                            self.emit_indent("pop rdi");   // restore fd
                            self.emit_indent("FILE_WRITE_STR rdi, rsi");
                        }
                    }
                    _ => {
                        // For other expressions, generate and write
                        self.emit_indent("push rdi");  // save fd
                        self.generate_expr(value);
                        self.emit_indent("pop rdi");   // restore fd
                        self.emit_indent("FILE_WRITE_STR rdi, rax");
                    }
                }
                self.emit(&format!("{}:", skip_label));
            }
            
            Statement::FileWriteNewline { file } => {
                let file_fd = if let Some(offset) = self.get_var(file) {
                    format!("[rbp-{}]", offset)
                } else {
                    "1".to_string()
                };
                let skip_label = self.new_label("skip_fd");
                self.emit_indent(&format!("mov rdi, {}", file_fd));
                // Skip write if fd is invalid (negative)
                self.emit_indent("test rdi, rdi");
                self.emit_indent(&format!("js {}  ; skip if invalid fd", skip_label));
                self.emit_indent("FILE_WRITE_NEWLINE rdi");
                self.emit(&format!("{}:", skip_label));
            }
            
            Statement::FileClose { file } => {
                if let Some(offset) = self.get_var(file) {
                    let skip_label = self.new_label("skip_fd");
                    self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
                    // Skip close if fd is invalid (negative)
                    self.emit_indent("test rdi, rdi");
                    self.emit_indent(&format!("js {}  ; skip if invalid fd", skip_label));
                    self.emit_indent("call _unregister_fd  ; remove from tracking");
                    self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
                    self.emit_indent("FILE_CLOSE rdi");
                    self.emit(&format!("{}:", skip_label));
                }
            }
            
            Statement::FileDelete { path } => {
                self.uses_files = true;
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("FILE_DELETE {}", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("FILE_DELETE rax");
                    }
                }
            }

            Statement::Rmdir { path } => {
                self.uses_files = true;
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("RMDIR {}", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("RMDIR rax");
                    }
                }
            }

            Statement::Mkdir { path } => {
                self.uses_files = true;
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("MKDIR {}", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("MKDIR rax");
                    }
                }
            }

            Statement::Chdir { path } => {
                self.uses_files = true;
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("CHDIR {}", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("CHDIR rax");
                    }
                }
            }

            Statement::Mount { source, target, fstype, options } => {
                self.uses_files = true;

                // Detect the "move"/"bind" pseudo-mount pattern used for
                // relocating already-mounted filesystems to a new root
                // (fstype "none" + options "move"/"bind"): for these, the
                // real mount(2) syscall wants a NULL filesystemtype and
                // NULL data, with the operation encoded entirely in flags.
                let is_none_fstype = matches!(fstype, Expr::StringLit(s) if s == "none");
                let move_flag = matches!(options, Some(Expr::StringLit(s)) if s == "move");
                let bind_flag = matches!(options, Some(Expr::StringLit(s)) if s == "bind");
                let flags: i64 = if is_none_fstype && move_flag {
                    8192 // MS_MOVE
                } else if is_none_fstype && bind_flag {
                    4096 // MS_BIND
                } else {
                    0
                };
                let suppress_fstype_and_data = is_none_fstype && (move_flag || bind_flag);

                // Park each evaluated argument on the stack so later
                // expressions (function calls, format strings) cannot
                // clobber earlier results, then pop into the syscall
                // registers in reverse order.
                self.generate_cstr_expr(source);
                self.emit_indent("push rax  ; park source");

                self.generate_cstr_expr(target);
                self.emit_indent("push rax  ; park target");

                // fstype (NULL for move/bind pseudo-mounts)
                if suppress_fstype_and_data {
                    self.emit_indent("xor rax, rax  ; fstype = NULL (move/bind)");
                } else {
                    self.generate_cstr_expr(fstype);
                }
                self.emit_indent("push rax  ; park fstype");

                // options/data (NULL for move/bind pseudo-mounts, or if omitted)
                if suppress_fstype_and_data {
                    self.emit_indent("xor rax, rax  ; data = NULL (move/bind)");
                } else {
                    match options {
                        None => self.emit_indent("xor rax, rax  ; data = NULL (no options given)"),
                        Some(expr) => self.generate_cstr_expr(expr),
                    }
                }
                self.emit_indent("push rax  ; park data (options)");

                // NOTE: raw `syscall` uses r10 for arg4, NOT rcx (rcx/r11
                // get clobbered by the syscall instruction itself) -
                // matches the convention already established by the
                // existing MMAP macro in this file.
                self.emit_indent("pop r8   ; data (options)");
                self.emit_indent("pop rdx  ; fstype");
                self.emit_indent("pop rsi  ; target");
                self.emit_indent("pop rdi  ; source");
                self.emit_indent(&format!("mov r10, {}  ; mount flags", flags));
                self.emit_indent("MOUNT");
            }

            Statement::Shutdown => {
                self.uses_files = true;
                self.emit_indent("REBOOT_CMD 0x4321FEDC  ; LINUX_REBOOT_CMD_POWER_OFF");
            }

            Statement::Reboot => {
                self.uses_files = true;
                self.emit_indent("REBOOT_CMD 0x01234567  ; LINUX_REBOOT_CMD_RESTART");
            }

            Statement::Halt => {
                self.uses_files = true;
                self.emit_indent("REBOOT_CMD 0xCDEF0123  ; LINUX_REBOOT_CMD_HALT");
            }

            Statement::Unmount { target, lazy } => {
                self.uses_files = true;
                self.generate_cstr_expr(target);
                self.emit_indent("mov rdi, rax  ; mount target");
                let flags = if *lazy { 2 } else { 0 }; // MNT_DETACH = 2
                self.emit_indent(&format!(
                    "mov rsi, {}  ; flags{}",
                    flags,
                    if *lazy { " (MNT_DETACH)" } else { "" }
                ));
                self.emit_indent("UMOUNT");
            }

            Statement::PivotRoot { new_root, put_old } => {
                self.uses_files = true;
                self.emit_syscall_args(&[(new_root, "rdi"), (put_old, "rsi")]);
                self.emit_indent("PIVOT_ROOT");
            }

            Statement::Execute { path, args } => {
                self.uses_files = true;

                // A list variable (or any non-literal list expression):
                // argv is built at runtime by _list_to_argv, which sizes the
                // allocation and bounds the copy from a single read of the
                // list's length - the array cannot be overrun.
                let elements: &[Expr] = match args {
                    Expr::ListLit { elements } => elements,
                    other => {
                        self.uses_lists = true;
                        self.generate_expr(other);
                        self.emit_indent("push rax  ; park list pointer");
                        match path {
                            Expr::StringLit(s) => {
                                let label = self.add_string(s);
                                self.emit_indent(&format!("lea rax, [{}]", label));
                            }
                            _ => self.generate_cstr_expr(path),
                        }
                        self.emit_indent("mov rsi, rax  ; path (becomes argv[0])");
                        self.emit_indent("pop rdi  ; list pointer");
                        self.emit_indent("call _list_to_argv");
                        self.emit_indent("mov rsi, rax  ; argv array pointer");
                        self.emit_indent("mov rdi, [rsi]  ; path = argv[0]");
                        self.emit_indent("mov rdx, [rel _envp]  ; inherit the real environment");
                        self.emit_indent("EXECVE");
                        return;
                    }
                };

                let slot_count = elements.len() + 2; // path + args + NULL terminator
                let total_size = slot_count * 8;

                // Allocate the argv array via mmap (same pattern as list
                // literals elsewhere in this file), but WITHOUT the normal
                // Vox-list header - execve needs a plain C-style array.
                self.emit_indent("; Build argv array for execve");
                self.emit_indent("mov rdi, 0  ; addr = NULL");
                self.emit_indent(&format!("mov rsi, {}  ; size", total_size));
                self.emit_indent("mov rdx, 3  ; PROT_READ | PROT_WRITE");
                self.emit_indent("mov r10, 0x22  ; MAP_PRIVATE | MAP_ANONYMOUS");
                self.emit_indent("mov r8, -1  ; fd = -1");
                self.emit_indent("mov r9, 0  ; offset = 0");
                self.emit_indent("mov rax, 9  ; sys_mmap");
                self.emit_indent("syscall");
                let mmap_ok = self.new_label("execve_argv_mmap_ok");
                self.emit_indent("cmp rax, -4096  ; raw mmap returns -errno in [-4095,-1]");
                self.emit_indent(&format!("jbe {}", mmap_ok));
                self.emit_indent("mov rdi, 1");
                self.emit_indent("mov rax, 60");
                self.emit_indent("syscall");
                self.emit(&format!("{}:", mmap_ok));
                self.emit_indent("push rax  ; save argv array pointer");

                // Slot 0: path (also argv[0] by convention)
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("mov rbx, {}", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("mov rbx, rax");
                    }
                }
                self.emit_indent("mov rax, [rsp]  ; peek argv array pointer");
                self.emit_indent("mov [rax], rbx  ; argv[0] = path");

                // Slots 1..n: the rest of the arguments
                for (i, elem) in elements.iter().enumerate() {
                    match elem {
                        Expr::StringLit(s) => {
                            let label = self.add_string(s);
                            self.emit_indent(&format!("mov rbx, {}", label));
                        }
                        _ => {
                            self.generate_cstr_expr(elem);
                            self.emit_indent("mov rbx, rax");
                        }
                    }
                    self.emit_indent("mov rax, [rsp]  ; peek argv array pointer");
                    self.emit_indent(&format!("mov [rax+{}], rbx  ; argv[{}]", (i + 1) * 8, i + 1));
                }

                // Final slot: NULL terminator
                self.emit_indent("pop rax  ; argv array pointer");
                self.emit_indent(&format!("mov qword [rax+{}], 0  ; argv NULL terminator", (elements.len() + 1) * 8));

                // path -> rdi (argv[0], reloaded from the array, not re-generated)
                self.emit_indent("mov rsi, rax  ; argv array pointer");
                self.emit_indent("mov rdi, [rsi]  ; path = argv[0]");
                self.emit_indent("mov rdx, [rel _envp]  ; inherit the real environment");
                self.emit_indent("EXECVE");
            }

            Statement::Symlink { target, linkpath } => {
                self.uses_files = true;
                self.emit_syscall_args(&[(target, "rdi"), (linkpath, "rsi")]);
                self.emit_indent("SYMLINK");
            }

            Statement::Mknod { path, node_type, major, minor } => {
                self.uses_files = true;

                // Path -> rdi
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("lea rdi, [{}]", label));
                    }
                    _ => {
                        self.generate_cstr_expr(path);
                        self.emit_indent("mov rdi, rax  ; path pointer");
                    }
                }
                self.emit_indent("push rdi  ; save path pointer");

                // Mode = S_IFCHR|S_IFBLK|S_IFIFO + 0666 permissions -> rsi
                // S_IFCHR = 0o020000 = 8192, S_IFBLK = 0o060000 = 24576,
                // S_IFIFO = 0o010000 = 4096, 0666 = 438
                let mode = match node_type {
                    DeviceNodeType::Character => 8192 + 438,
                    DeviceNodeType::Block => 24576 + 438,
                    DeviceNodeType::Fifo => 4096 + 438,
                };

                // dev = (major << 8) | minor -> rdx
                self.generate_expr(major);
                self.emit_indent("push rax  ; save major");
                self.generate_expr(minor);
                self.emit_indent("mov rcx, rax  ; minor");
                self.emit_indent("pop rax  ; major");
                self.emit_indent("shl rax, 8");
                self.emit_indent("or rax, rcx");
                self.emit_indent("mov rdx, rax  ; dev = (major << 8) | minor");

                self.emit_indent(&format!("mov rsi, {}  ; mode", mode));
                self.emit_indent("pop rdi  ; restore path pointer");
                self.emit_indent("MKNOD");
            }

            Statement::OnError { actions } => {
                // Check if last operation had an error
                let skip_label = self.new_label("skip_error");
                self.emit_indent("mov rax, [rel _last_error]");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jz {}  ; skip if no error", skip_label));
                
                // Execute all error actions
                for action in actions {
                    self.generate_statement(action);
                }
                
                // Clear the error
                self.emit_indent("mov qword [rel _last_error], 0");
                
                self.emit(&format!("{}:", skip_label));
            }
            
            Statement::BufferResize { name, new_size } => {
                if self.emit_load_named_var_addr(name) {
                    self.emit_indent("mov rdi, rax  ; buffer pointer");
                    self.generate_expr(new_size);
                    self.emit_indent("mov rsi, rax  ; new size");
                    self.emit_indent("call _realloc_buffer");
                    if let Some(offset) = self.get_var(name) {
                        self.emit_indent(&format!("mov [rbp-{}], rax  ; updated buffer pointer", offset));
                    } else if let Some(label) = self.global_var_label(name).cloned() {
                        self.emit_indent(&format!("mov [rel {}], rax  ; updated buffer pointer", label));
                    }
                }
            }
            
            Statement::LibraryDecl { name, version } => {
                // Library declaration - emit as comment for now
                // In the future, this metadata could be used for linking
                self.emit(&format!("; Library: {} version {}", name, version));
            }
            
            Statement::See { path, lib_name, lib_version } => {
                // See statement - emit as comment for now
                // The actual file inclusion is handled by the compiler frontend
                let lib_info = match (lib_name, lib_version) {
                    (Some(n), Some(v)) => format!(" (library: {} version {})", n, v),
                    (Some(n), None) => format!(" (library: {})", n),
                    _ => String::new(),
                };
                self.emit(&format!("; See: {}{}", path, lib_info));
            }
            
            // Time and Timer statements
            Statement::TimerDecl { name } => {
                self.uses_time = true;
                // Allocate the 8-byte name slot; the timer struct itself needs
                // TIMER_SIZE (56) bytes below it. Account for the full struct in
                // the frame size so later variables do not overlap the timer.
                let offset = self.alloc_var(name);
                self.variable_types.insert(name.clone(), VarType::Integer); // Track as integer for now
                self.stack_offset = std::cmp::max(self.stack_offset, offset + 48);
                self.emit_indent(&format!("; Timer declaration: {}", name));
                self.emit_indent(&format!("lea rax, [rbp - {}]", offset + 48)); // Point to timer area
                self.emit_indent("TIMER_INIT rax");
            }
            
            Statement::TimerStart { name } => {
                self.uses_time = true;
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("; Start timer: {}", name));
                    self.emit_indent(&format!("lea rax, [rbp - {}]", offset + 48));
                    self.emit_indent("TIMER_START rax");
                }
            }
            
            Statement::TimerStop { name } => {
                self.uses_time = true;
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("; Stop timer: {}", name));
                    self.emit_indent(&format!("lea rax, [rbp - {}]", offset + 48));
                    self.emit_indent("TIMER_STOP rax");
                }
            }
            
            Statement::Wait { duration, unit } => {
                self.uses_time = true;
                self.emit_indent("; Wait/Sleep");
                self.generate_expr(duration);
                match unit {
                    TimeUnit::Seconds => {
                        self.emit_indent("SLEEP_SECONDS rax");
                    }
                    TimeUnit::Milliseconds => {
                        self.emit_indent("SLEEP_MILLISECONDS rax");
                    }
                }
            }
            
            Statement::GetTime { into } => {
                self.uses_time = true;
                // Get current unix time and store in variable
                let offset = self.alloc_var(into);
                self.variable_types.insert(into.clone(), VarType::Integer);
                self.emit_indent(&format!("; Get current time into: {}", into));
                self.emit_indent("TIME_GET");
                self.emit_indent(&format!("mov [rbp - {}], rax", offset));
            }
        }
    }
    
    fn parse_format_spec(&self, fmt: Option<&str>) -> FormatSpec {
        match fmt {
            None => FormatSpec {
                width: None,
                zero_pad: false,
                base: IntegerBase::Decimal,
                precision: None,
            },
            Some(fmt_str) => {
                let mut spec = FormatSpec {
                    width: None,
                    zero_pad: false,
                    base: IntegerBase::Decimal,
                    precision: None,
                };
                
                // Check for precision format first (starts with '.')
                if fmt_str.starts_with('.') {
                    // Float precision format like .2, .4, etc.
                    if let Some(precision) = fmt_str.strip_prefix('.').and_then(|s| s.parse::<i32>().ok()) {
                        spec.precision = Some(precision);
                    }
                    return spec;
                }
                
                // Parse width and zero padding
                let mut remaining = fmt_str;
                let mut has_width = false;
                
                // Check if it starts with digit or '0' for width/padding
                if remaining.chars().next().map(|c| c.is_ascii_digit() || c == '0').unwrap_or(false) {
                    let zero_pad = remaining.starts_with('0');
                    let width_str = if zero_pad {
                        remaining.trim_start_matches('0')
                    } else {
                        remaining
                    };
                    
                    // Extract digits for width
                    let width_end = width_str.chars().take_while(|c| c.is_ascii_digit()).count();
                    if width_end > 0 {
                        let width_digits = &width_str[..width_end];
                        if let Ok(width) = width_digits.parse::<i32>() {
                            spec.width = Some(width);
                            spec.zero_pad = zero_pad;
                            has_width = true;
                            remaining = &fmt_str[if zero_pad { 1 + width_end } else { width_end }..];
                        }
                    }
                }
                
                // Parse base specifier from remaining characters
                if !remaining.is_empty() {
                    match remaining {
                        "x" => spec.base = IntegerBase::HexLower,
                        "X" => spec.base = IntegerBase::HexUpper,
                        "b" => spec.base = IntegerBase::Binary,
                        "o" => spec.base = IntegerBase::Octal,
                        _ => {
                            // If we parsed a width but no base, treat as decimal
                            if has_width {
                                spec.base = IntegerBase::Decimal;
                            }
                        }
                    }
                }
                
                spec
            }
        }
    }
    
    fn emit_formatted_value(&mut self, value_type: Option<VarType>, fmt: FormatSpec) {
        // Handle precision format for floats
        if let Some(precision) = fmt.precision {
            self.emit_indent("movq xmm0, rdi");
            self.emit_indent(&format!("mov rdi, {}", precision));
            self.emit_indent("call _print_float_precision");
            self.uses_floats = true;
            self.uses_format = true;
            return;
        }
        
        // If no specific format (default case), handle by type
        if fmt.width.is_none() && matches!(fmt.base, IntegerBase::Decimal) {
            match value_type {
                Some(VarType::Float) => {
                    self.emit_indent("movq xmm0, rdi");
                    self.emit_indent("PRINT_FLOAT");
                    self.uses_floats = true;
                }
                Some(VarType::Buffer) => {
                    // rdi must be the struct pointer (not data area) here.
                    // The fixed call sites guarantee this; it's documented on
                    // each one. Kept separate from VarType::String to make the
                    // contract explicit and catch any future callers that get
                    // it wrong (PRINT_BUF on a data pointer would print garbage).
                    self.emit_indent("PRINT_BUF rdi");
                }
                Some(VarType::String) => {
                    self.emit_indent("PRINT_CSTR rdi");
                }
                _ => {
                    self.emit_indent("PRINT_INT rdi");
                }
            }
            return;
        }
        
        // Handle integer formatting with width and base
        match fmt.base {
            IntegerBase::Decimal => {
                match (fmt.width, fmt.zero_pad) {
                    (Some(width), true) => {
                        self.emit_indent(&format!("PRINT_INT_ZEROPAD rdi, {}", width));
                    }
                    (Some(width), false) => {
                        self.emit_indent(&format!("PRINT_INT_PADDED rdi, {}", width));
                    }
                    _ => {
                        self.emit_indent("PRINT_INT rdi");
                    }
                }
                self.uses_format = true;
            }
            IntegerBase::HexLower => {
                if fmt.width.is_some() {
                    match (fmt.width, fmt.zero_pad) {
                        (Some(width), true) => {
                            self.emit_indent(&format!("PRINT_HEX_LOWER_ZEROPAD rdi, {}", width));
                        }
                        (Some(width), false) => {
                            self.emit_indent(&format!("PRINT_HEX_LOWER_PADDED rdi, {}", width));
                        }
                        _ => {
                            self.emit_indent("PRINT_HEX_LOWER rdi");
                        }
                    }
                } else {
                    self.emit_indent("PRINT_HEX_LOWER rdi");
                }
                self.uses_format = true;
            }
            IntegerBase::HexUpper => {
                if fmt.width.is_some() {
                    match (fmt.width, fmt.zero_pad) {
                        (Some(width), true) => {
                            self.emit_indent(&format!("PRINT_HEX_UPPER_ZEROPAD rdi, {}", width));
                        }
                        (Some(width), false) => {
                            self.emit_indent(&format!("PRINT_HEX_UPPER_PADDED rdi, {}", width));
                        }
                        _ => {
                            self.emit_indent("PRINT_HEX_UPPER rdi");
                        }
                    }
                } else {
                    self.emit_indent("PRINT_HEX_UPPER rdi");
                }
                self.uses_format = true;
            }
            IntegerBase::Binary => {
                if fmt.width.is_some() {
                    match (fmt.width, fmt.zero_pad) {
                        (Some(width), true) => {
                            self.emit_indent(&format!("PRINT_BINARY_ZEROPAD rdi, {}", width));
                        }
                        (Some(width), false) => {
                            self.emit_indent(&format!("PRINT_BINARY_PADDED rdi, {}", width));
                        }
                        _ => {
                            self.emit_indent("PRINT_BINARY rdi");
                        }
                    }
                } else {
                    self.emit_indent("PRINT_BINARY rdi");
                }
                self.uses_format = true;
            }
            IntegerBase::Octal => {
                if fmt.width.is_some() {
                    match (fmt.width, fmt.zero_pad) {
                        (Some(width), true) => {
                            self.emit_indent(&format!("PRINT_OCTAL_ZEROPAD rdi, {}", width));
                        }
                        (Some(width), false) => {
                            self.emit_indent(&format!("PRINT_OCTAL_PADDED rdi, {}", width));
                        }
                        _ => {
                            self.emit_indent("PRINT_OCTAL rdi");
                        }
                    }
                } else {
                    self.emit_indent("PRINT_OCTAL rdi");
                }
                self.uses_format = true;
            }
        }
    }
    
    fn generate_print(&mut self, value: &Expr, without_newline: bool) {
        self.uses_io = true;
        match value {
            Expr::FormatString { parts } => {
                // Print each part of the format string
                for part in parts {
                    match part {
                        FormatPart::Literal(s) => {
                            let label = self.add_string(s);
                            self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                        }
                        FormatPart::Variable { name, format } => {
                            let var_type: Option<VarType> = match self.resolve_format_variable(name) {
                                FormatPartValue::Loaded(t) => {
                                    self.emit_indent("mov rdi, rax");
                                    t
                                }
                                FormatPartValue::Literal(s) => {
                                    let label = self.add_string(&s);
                                    self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                                    continue;
                                }
                                FormatPartValue::Unknown => {
                                    let placeholder = format!("{{{}}}", name);
                                    let label = self.add_string(&placeholder);
                                    self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                                    continue;
                                }
                            };

                            // Parse format spec and emit formatted value.
                            // Buffer: use PRINT_BUF with the struct pointer (length-bounded,
                            // avoids the NUL-scan stale-byte bug). For all other types, rdi
                            // already holds the correct value/pointer.
                            if var_type == Some(VarType::Buffer) {
                                let fmt_spec = self.parse_format_spec(format.as_deref());
                                if fmt_spec.width.is_none() && matches!(fmt_spec.base, IntegerBase::Decimal) && fmt_spec.precision.is_none() {
                                    self.emit_indent("PRINT_BUF rdi");
                                } else {
                                    // Format spec: value is formatted as a number, so point
                                    // rdi at the data area so the formatter reads the string.
                                    self.emit_indent("add rdi, 24  ; buffer data area (header is 24 bytes)");
                                    self.emit_formatted_value(var_type, fmt_spec);
                                }
                            } else {
                                let fmt_spec = self.parse_format_spec(format.as_deref());
                                self.emit_formatted_value(var_type, fmt_spec);
                            }
                        }
                        FormatPart::Expression { expr, format } => {
                            let expr_type = self.infer_expr_type(expr);
                            let fmt_spec = self.parse_format_spec(format.as_deref());

                            if expr_type == Some(VarType::Buffer) {
                                // For buffer expressions: generate the struct pointer,
                                // not the data-area pointer - PRINT_BUF reads its own
                                // length from the struct, so it needs the base pointer.
                                self.generate_expr(expr);
                                self.emit_indent("mov rdi, rax");
                                if fmt_spec.width.is_none() && matches!(fmt_spec.base, IntegerBase::Decimal) && fmt_spec.precision.is_none() {
                                    self.emit_indent("PRINT_BUF rdi");
                                } else {
                                    // Format spec present: adjust to data area for
                                    // the NUL-scanned formatter.
                                    self.emit_indent("add rdi, 24  ; buffer data area");
                                    self.emit_formatted_value(expr_type, fmt_spec);
                                }
                            } else {
                                // Non-buffer: generate_cstr_expr adds +24 for buffer
                                // (irrelevant here), then falls through to normal path.
                                self.generate_cstr_expr(expr);
                                self.emit_indent("mov rdi, rax");
                                self.emit_formatted_value(expr_type, fmt_spec);
                            }
                        }
                    }
                }
                if !without_newline {
                    self.emit_indent("PRINT_NEWLINE");
                }
                return;
            }
            
            Expr::StringLit(s) => {
                // Check if this string literal is actually a variable reference
                if self.emit_load_named_var_into_rax(s) {
                    self.emit_indent("mov rdi, rax");
                    let var_type = self.variable_types.get(s).cloned();
                    match var_type {
                        Some(VarType::Buffer) => {
                            self.emit_indent("PRINT_BUF rdi");
                        }
                        Some(VarType::String) => {
                            self.emit_indent("PRINT_CSTR rdi");
                        }
                        Some(VarType::Float) => {
                            self.emit_indent("movq xmm0, rdi");
                            self.emit_indent("PRINT_FLOAT");
                            self.uses_floats = true;
                        }
                        _ => {
                            self.emit_indent("PRINT_INT rdi");
                        }
                    }
                } else {
                    if !self.emit_global_constant_format_fallback(s, None) {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                    }
                }
            }
            
            Expr::IntegerLit(n) => {
                self.emit_indent(&format!("mov rdi, {}", n));
                self.emit_indent("PRINT_INT rdi");
            }
            
            Expr::FloatLit(n) => {
                let label = self.add_float(*n);
                self.emit_indent(&format!("FLOAT_LOAD {}", label));
                self.emit_indent("PRINT_FLOAT");
                self.uses_floats = true;
            }
            
            Expr::Identifier(name) => {
                if self.emit_load_named_var_into_rax(name) {
                    self.emit_indent("mov rdi, rax");
                    let var_type = self.variable_types.get(name).cloned();
                    match var_type {
                        Some(VarType::Buffer) => {
                            // Dynamic buffer - PRINT_BUF reads length/data directly
                            // from the struct, no NUL-scan needed
                            self.emit_indent("PRINT_BUF rdi");
                        }
                        Some(VarType::String) => {
                            // Raw string pointer (from lists, etc.)
                            self.emit_indent("PRINT_CSTR rdi");
                        }
                        Some(VarType::Float) => {
                            self.emit_indent("movq xmm0, rdi");
                            self.emit_indent("PRINT_FLOAT");
                            self.uses_floats = true;
                        }
                        _ => {
                            self.emit_indent("PRINT_INT rdi");
                        }
                    }
                } else if name == "_iter" {
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("PRINT_INT rdi");
                }
            }
            
            Expr::ElementAccess { list, .. } => {
                // Get the list's element type for proper printing
                let elem_type = if let Expr::Identifier(name) = list.as_ref() {
                    self.list_element_types.get(name).cloned()
                } else {
                    None
                };
                
                self.generate_expr(value);
                self.emit_indent("mov rdi, rax");
                
                match elem_type {
                    Some(VarType::String) => {
                        self.emit_indent("PRINT_CSTR rdi");
                    }
                    Some(VarType::Float) => {
                        self.emit_indent("movq xmm0, rdi");
                        self.emit_indent("PRINT_FLOAT");
                        self.uses_floats = true;
                    }
                    _ => {
                        self.emit_indent("PRINT_INT rdi");
                    }
                }
            }
            
            _ => {
                let is_float = self.is_float_expr(value);
                let expr_type = self.infer_expr_type(value);
                self.generate_expr(value);
                if is_float {
                    self.emit_indent("movq xmm0, rax");
                    self.emit_indent("PRINT_FLOAT");
                    self.uses_floats = true;
                } else {
                    self.emit_indent("mov rdi, rax");
                    if matches!(expr_type, Some(VarType::String)) {
                        self.emit_indent("PRINT_CSTR rdi");
                    } else {
                        self.emit_indent("PRINT_INT rdi");
                    }
                }
            }
        }
        if !without_newline {
            self.emit_indent("PRINT_NEWLINE");
        }
    }
    
    /// Evaluate a sequence of syscall argument expressions safely.
    ///
    /// Each expression's result (in rax) is parked on the stack before the
    /// next expression is generated, then everything is popped into the
    /// target registers in reverse order. Loading argument registers
    /// directly between generate_expr calls is unsound: a later expression
    /// containing a function call, format string, or buffer operation can
    /// clobber any register already loaded (user functions only preserve
    /// rbp, and syscalls clobber rcx/r11).
    fn emit_syscall_args(&mut self, args: &[(&Expr, &'static str)]) {
        for (expr, _) in args {
            self.generate_cstr_expr(expr);
            self.emit_indent("push rax  ; park syscall arg");
        }
        for (_, reg) in args.iter().rev() {
            self.emit_indent(&format!("pop {}", reg));
        }
    }

    /// Evaluate an expression that will be handed to the kernel as a
    /// C-string (path, mount option, execve argument). Buffer variables
    /// evaluate to their struct pointer (capacity/length/flags header
    /// first), so adjust to the data area - the runtime maintains a
    /// trailing NUL at data[length], making buffer contents directly
    /// usable as a C string. Text variables and string literals already
    /// point at NUL-terminated bytes.
    fn generate_cstr_expr(&mut self, expr: &Expr) {
        self.generate_expr(expr);
        if self.infer_expr_type(expr) == Some(VarType::Buffer) {
            self.emit_indent("add rax, 24  ; buffer data area (header is 24 bytes, data is NUL-terminated)");
        }
    }

    /// True when comparing this expression with `==`/`!=` needs byte-content
    /// comparison (_str_eq) rather than a raw pointer `cmp`. Text variables,
    /// string literals, and buffers all qualify - two equal-content strings
    /// are essentially never the same address (add_string mints a fresh
    /// label per literal occurrence with no deduplication), so pointer
    /// comparison silently fails for the overwhelmingly common case of
    /// `some_variable is "literal"`.
    fn is_stringy_expr(&self, expr: &Expr) -> bool {
        matches!(self.infer_expr_type(expr), Some(VarType::String) | Some(VarType::Buffer))
    }

    fn generate_expr(&mut self, expr: &Expr) {
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
            
            Expr::StringLit(s) => {
                // Check if this string literal is actually a variable reference
                if self.emit_load_named_var_into_rax(s) {
                } else {
                    let label = self.add_string(s);
                    self.emit_indent(&format!("lea rax, [{}]", label));
                }
            }
            
            Expr::Identifier(name) => {
                if self.emit_load_named_var_into_rax(name) {
                }
            }
            
            Expr::BinaryOp { left, op, right } => {
                // Use has_float_operands for instruction selection (includes comparisons)
                let has_floats = self.has_float_operands(left) || self.has_float_operands(right);
                
                if has_floats {
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
                    && (self.is_stringy_expr(left) || self.is_stringy_expr(right))
                {
                    // Content comparison via _str_eq/_mem_eq - see emit_stringy_equality.
                    self.emit_stringy_equality(left, right);
                    if matches!(op, BinaryOperator::NotEqual) {
                        self.emit_indent("xor rax, 1  ; 1=equal -> 0=notequal");
                    }
                } else {
                    // Integer operations
                    self.uses_ints = true;
                    self.generate_expr(right);
                    self.emit_indent("push rax");
                    self.generate_expr(left);
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
                // List structure: [capacity:8][length:8][elem_size:8][data...]
                // Each element is 8 bytes, header is 24 bytes
                let capacity = std::cmp::max(elements.len(), 8); // minimum capacity 8
                let header_size = 24;
                let data_size = capacity * 8;
                let total_size = header_size + data_size;
                
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
                
                // Store elements (data starts at offset 24)
                for (i, elem) in elements.iter().enumerate() {
                    self.emit_indent("pop rbx  ; get list pointer");
                    self.emit_indent("push rbx ; save it back");
                    self.generate_expr(elem);
                    self.emit_indent("pop rbx  ; get list pointer");
                    self.emit_indent(&format!("mov [rbx+{}], rax", header_size + i * 8));
                    self.emit_indent("push rbx ; save list pointer");
                }
                
                self.emit_indent("pop rax  ; list pointer in rax");
            }
            
            // ListAccess: 0-indexed access (internal use)
            // MEMORY SAFETY: Always bounds-check before access
            // List structure: [capacity:8][length:8][elem_size:8][data...]
            Expr::ListAccess { list, index } => {
                let ok_label = self.new_label("list_ok");
                let error_label = self.new_label("list_err");
                let done_label = self.new_label("list_done");
                
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
                self.emit_indent(&format!("jmp {}", done_label));
                
                // Success path: safe access
                // List structure: [capacity:8][length:8][elem_size:8][data...]
                // Data starts at offset 24
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("mov rax, rcx");
                self.emit_indent("shl rax, 3  ; multiply by 8 (element size)");
                self.emit_indent("add rax, 24  ; skip header (24 bytes)");
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
                        // Buffer/List properties
                        ObjectProperty::Size => {
                            if var_type == VarType::Buffer {
                                self.emit_indent("mov rax, [rax + 8]  ; buffer length/size");
                            } else if var_type == VarType::List {
                                self.emit_indent("mov rax, [rax + 8]  ; list length at offset 8");
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
                            } else {
                                self.emit_indent("mov rax, [rax + 8]  ; get buffer size");
                            }
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setz al");
                            self.emit_indent("movzx rax, al  ; 1 if empty, 0 otherwise");
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
                            self.emit_indent("mov rbx, [rax + 8]  ; length (offset 8)");
                            self.emit_indent("test rbx, rbx");
                            self.emit_indent(&format!("jnz {}  ; non-empty list, safe to access", ok_label));
                            self.emit(&format!("{}:", error_label));
                            self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                            self.emit_indent("xor rax, rax  ; return 0 on error");
                            self.emit_indent(&format!("jmp {}", done_label));
                            self.emit(&format!("{}:", ok_label));
                            self.emit_indent("mov rax, [rax + 24]  ; first element (data at offset 24)");
                            self.emit(&format!("{}:", done_label));
                        }
                        ObjectProperty::Last => {
                            let ok_label = self.new_label("list_last_ok");
                            let error_label = self.new_label("list_last_err");
                            let done_label = self.new_label("list_last_done");
                            self.emit_indent("mov rbx, [rax + 8]  ; length (offset 8)");
                            self.emit_indent("test rbx, rbx");
                            self.emit_indent(&format!("jnz {}  ; non-empty list, safe to access", ok_label));
                            self.emit(&format!("{}:", error_label));
                            self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                            self.emit_indent("xor rax, rax  ; return 0 on error");
                            self.emit_indent(&format!("jmp {}", done_label));
                            self.emit(&format!("{}:", ok_label));
                            self.emit_indent("dec rbx             ; 0-indexed");
                            self.emit_indent("shl rbx, 3          ; * 8");
                            self.emit_indent("add rbx, 24         ; + header offset");
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

                // Allocate: size = capacity*8 + 24 (header)
                self.emit_indent("mov rax, r13");
                self.emit_indent("shl rax, 3");
                self.emit_indent("add rax, 24");
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
                self.emit_indent("mov [r14 + r15*8 + 24], rax");
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
                self.emit_indent("add rax, 24");
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
                self.emit_indent("mov [r14 + r15*8 + 24], rax");
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

            Expr::ReapChild { pid } => {
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
                self.emit_indent("; wait4() - reap a child, returns its pid (or -1 on error)");
                self.emit_indent("REAP_CHILD");
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
                                self.emit_indent("add rax, 24  ; buffer data area");
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
                        // decimal representation. Text/buffer values are already
                        // valid text pointers, so they are left unchanged.
                        let src_type = self.infer_expr_type(value);
                        if !matches!(src_type, Some(VarType::String) | Some(VarType::Buffer)) {
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
                                self.emit_indent(&format!("lea rsi, [{}]", false_label));
                                self.emit_indent(&format!("mov rdx, {}_len", false_label));
                                self.emit_indent(&format!("jmp {}", done_label));
                                self.emit(&format!("{}:", true_branch));
                                self.emit_indent(&format!("lea rsi, [{}]", true_label));
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
                            self.emit_indent("add rax, 24  ; buffer data area -> NUL-terminated C string");
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
                self.generate_expr(value);
                match unit {
                    TimeUnit::Seconds => {
                        // Value is already in seconds
                        self.emit_indent("; Duration in seconds");
                    }
                    TimeUnit::Milliseconds => {
                        // Multiply by 1000
                        self.emit_indent("; Duration in milliseconds");
                        self.emit_indent("imul rax, 1000");
                    }
                }
            }
            
            // Byte access: byte N of buffer (1-indexed)
            // Buffer structure: [capacity:8][length:8][data at offset 24]
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
                self.emit_indent("dec rcx  ; convert 1-indexed to 0-indexed");
                self.emit_indent("add rbx, 24  ; skip to buffer data area");
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
                self.emit_indent(&format!("jmp {}", done_label));
                
                // Success path: safe access
                // Data starts at offset 24, 1-indexed so element 1 is at offset 24
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("dec rcx  ; convert 1-indexed to 0-indexed");
                self.emit_indent("mov rax, rcx");
                self.emit_indent("shl rax, 3  ; index * 8");
                self.emit_indent("add rax, 24  ; skip header (24 bytes)");
                self.emit_indent("add rax, rbx");
                self.emit_indent("mov rax, [rax]  ; get element");
                
                self.emit(&format!("{}:", done_label));
            }
            
            // Format string in expression context (e.g. a text initializer
            // or a function argument): materialize it into a fresh dynamic
            // buffer and yield a pointer to the data area - a NUL-terminated
            // C string usable anywhere a text is. Previously this returned 0,
            // so `a text called "t" is "{buf}"` silently produced a NULL
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
                self.emit_indent("add rax, 24  ; buffer data area (header is 24 bytes)");
            }
        }
    }
    
    fn generate_condition(&mut self, condition: &Expr, false_label: &str) {
        match condition {
            Expr::PropertyCheck { value, property } => {
                self.generate_expr(value);
                match property {
                    Property::Even => {
                        self.emit_indent("test rax, 1");
                        self.emit_indent(&format!("jnz {}", false_label));
                    }
                    Property::Odd => {
                        self.emit_indent("test rax, 1");
                        self.emit_indent(&format!("jz {}", false_label));
                    }
                    Property::Zero => {
                        self.emit_indent("test rax, rax");
                        self.emit_indent(&format!("jnz {}", false_label));
                    }
                    Property::Positive => {
                        self.emit_indent("cmp rax, 0");
                        self.emit_indent(&format!("jle {}", false_label));
                    }
                    Property::Negative => {
                        self.emit_indent("cmp rax, 0");
                        self.emit_indent(&format!("jge {}", false_label));
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
                        self.emit_indent(&format!("jnz {}", false_label));
                    }
                }
            }

            Expr::FileAvailable { path } => {
                self.uses_files = true;
                self.generate_cstr_expr(path);
                self.emit_indent("FILE_AVAILABLE");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jz {}", false_label));
            }

            Expr::BinaryOp { left, op, right } => {
                match op {
                    BinaryOperator::And => {
                        self.generate_condition(left, false_label);
                        self.generate_condition(right, false_label);
                    }
                    BinaryOperator::Or => {
                        let true_label = self.new_label("or_true");
                        self.generate_expr(left);
                        self.emit_indent("test rax, rax");
                        self.emit_indent(&format!("jnz {}", true_label));
                        self.generate_condition(right, false_label);
                        self.emit(&format!("{}:", true_label));
                    }
                    BinaryOperator::Equal | BinaryOperator::NotEqual
                        if self.is_stringy_expr(left) || self.is_stringy_expr(right) =>
                    {
                        // Content comparison - see emit_stringy_equality for why
                        // _mem_eq is used when either side is a buffer.
                        self.emit_stringy_equality(left, right);
                        self.emit_indent("test rax, rax");
                        let jmp = if matches!(op, BinaryOperator::Equal) { "jz" } else { "jnz" };
                        self.emit_indent(&format!("{} {}  ; 1=equal", jmp, false_label));
                    }
                    BinaryOperator::Equal | BinaryOperator::NotEqual |
                    BinaryOperator::Greater | BinaryOperator::Less |
                    BinaryOperator::GreaterEqual | BinaryOperator::LessEqual => {
                        let is_float = self.is_float_expr(left) || self.is_float_expr(right);

                        if is_float {
                            // Float comparison using SSE2. Use the helper macros so that
                            // NaN/unordered results behave like Vox comparisons: ordered
                            // comparisons are false when either operand is NaN, and != is
                            // true for NaN. The macro leaves a 0/1 result in rax.
                            self.generate_expr(right);
                            self.emit_indent("push rax");
                            self.generate_expr(left);
                            self.emit_indent("movq xmm0, rax");       // left in xmm0
                            self.emit_indent("pop rax");
                            self.emit_indent("movq xmm1, rax");       // right in xmm1

                            let macro_name = match op {
                                BinaryOperator::Equal => "FLOAT_EQ",
                                BinaryOperator::NotEqual => "FLOAT_NE",
                                BinaryOperator::Greater => "FLOAT_GT",
                                BinaryOperator::Less => "FLOAT_LT",
                                BinaryOperator::GreaterEqual => "FLOAT_GE",
                                BinaryOperator::LessEqual => "FLOAT_LE",
                                _ => unreachable!(),
                            };
                            self.emit_indent(macro_name);
                            self.emit_indent("test rax, rax");
                            self.emit_indent(&format!("jz {}", false_label));
                        } else {
                            // Integer comparison
                            self.generate_expr(right);
                            self.emit_indent("push rax");
                            self.generate_expr(left);
                            self.emit_indent("pop rbx");
                            self.emit_indent("cmp rax, rbx");
                            
                            let jmp = match op {
                                BinaryOperator::Equal => "jne",
                                BinaryOperator::NotEqual => "je",
                                BinaryOperator::Greater => "jle",
                                BinaryOperator::Less => "jge",
                                BinaryOperator::GreaterEqual => "jl",
                                BinaryOperator::LessEqual => "jg",
                                _ => unreachable!(),
                            };
                            self.emit_indent(&format!("{} {}", jmp, false_label));
                        }
                    }
                    _ => {
                        self.generate_expr(condition);
                        self.emit_indent("test rax, rax");
                        self.emit_indent(&format!("jz {}", false_label));
                    }
                }
            }
            
            Expr::UnaryOp { op: UnaryOperator::Not, operand } => {
                let true_label = self.new_label("not_true");
                self.generate_condition(operand, &true_label);
                self.emit_indent(&format!("jmp {}", false_label));
                self.emit(&format!("{}:", true_label));
            }
            
            _ => {
                self.generate_expr(condition);
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jz {}", false_label));
            }
        }
    }
    
    fn infer_expr_type(&self, expr: &Expr) -> Option<VarType> {
        match expr {
            Expr::IntegerLit(_) => Some(VarType::Integer),
            Expr::FloatLit(_) => Some(VarType::Float),
            Expr::StringLit(s) => self.quoted_name_var_type(s).or(Some(VarType::String)),
            Expr::BoolLit(_) => Some(VarType::Integer), // Booleans are integers (0/1)
            Expr::ArgumentCount => Some(VarType::Integer),
            Expr::ArgumentAt { .. } | Expr::ArgumentName | Expr::ArgumentFirst
            | Expr::ArgumentSecond | Expr::ArgumentLast => Some(VarType::String),
            Expr::ArgumentEmpty | Expr::ArgumentHas { .. } => Some(VarType::Integer),
            Expr::EnvironmentVariable { .. } | Expr::EnvironmentVariableAt { .. }
            | Expr::EnvironmentVariableFirst | Expr::EnvironmentVariableLast => Some(VarType::String),
            Expr::EnvironmentVariableCount | Expr::EnvironmentVariableExists { .. }
            | Expr::EnvironmentVariableEmpty => Some(VarType::Integer),
            Expr::ArgumentAll | Expr::ArgumentRaw => Some(VarType::List),
            Expr::Identifier(name) => self.variable_types.get(name).cloned(),
            Expr::FunctionCall { name, .. } => self.function_return_types.get(name).cloned(),
            Expr::PropertyAccess { object, property } => {
                // For First/Last on lists, return the list's element type
                match property {
                    ObjectProperty::First | ObjectProperty::Last => {
                        if self.variable_types.get(object) == Some(&VarType::List) {
                            self.list_element_types.get(object).cloned()
                        } else {
                            Some(VarType::Integer)
                        }
                    }
                    ObjectProperty::Size | ObjectProperty::Capacity => Some(VarType::Integer),
                    _ => Some(VarType::Integer),
                }
            }
            Expr::ElementAccess { list, .. } => {
                // For element access, return the list's element type
                if let Expr::Identifier(name) = list.as_ref() {
                    self.list_element_types.get(name).cloned().or(Some(VarType::Integer))
                } else {
                    Some(VarType::Integer)
                }
            }
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

    fn is_fd_path_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::IntegerLit(_) => true,
            Expr::Identifier(name) => matches!(
                self.variable_types.get(name),
                Some(VarType::Integer)
            ),
            Expr::BinaryOp { .. }
            | Expr::UnaryOp { .. }
            | Expr::PropertyAccess { .. }
            | Expr::ByteAccess { .. }
            | Expr::ElementAccess { .. }
            | Expr::DurationCast { .. }
            | Expr::LastError
            | Expr::TreatingAs { .. } => self.infer_expr_type(expr) == Some(VarType::Integer),
            Expr::Cast { target_type, .. } => *target_type == Type::Integer,
            _ => false,
        }
    }
}
