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
    target_arch: String,
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
            target_arch: "x86_64".to_string(),
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
    
    fn is_float_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::FloatLit(_) => true,
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
    
    // Check if operands involve floats (for choosing comparison instructions)
    fn has_float_operands(&self, expr: &Expr) -> bool {
        match expr {
            Expr::FloatLit(_) => true,
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
    
    pub fn generate(&mut self, program: &Program) -> String {
        for stmt in &program.statements {
            self.generate_statement(stmt);
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
            if self.uses_buffers || self.uses_files {
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
            if program.uses_strings {
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
                    // Argument/environment expressions return string pointers
                    else if matches!(val, 
                        Expr::ArgumentAt { .. } | Expr::ArgumentName | Expr::ArgumentFirst | 
                        Expr::ArgumentSecond | Expr::ArgumentLast |
                        Expr::EnvironmentVariable { .. } | Expr::EnvironmentVariableAt { .. } |
                        Expr::EnvironmentVariableFirst | Expr::EnvironmentVariableLast
                    ) {
                        self.variable_types.insert(name.clone(), VarType::String);
                    }
                    
                    // Special handling for buffer initialization with string literal
                    if matches!(var_type, Some(Type::Buffer)) {
                        if let Expr::StringLit(s) = val {
                            // For buffer initialized with string, allocate and copy the string
                            let str_label = self.add_string(s);
                            let str_len = s.len();
                            // Allocate buffer with enough capacity (at least string length + 1)
                            let capacity = std::cmp::max(str_len + 1, 1024);
                            self.emit_indent(&format!("mov rdi, {}  ; buffer capacity", capacity));
                            self.emit_indent("call _alloc_buffer");
                            self.emit_indent(&format!("mov [rbp-{}], rax  ; store buffer pointer", offset));
                            // Copy string data into buffer data area (offset 24 = BUF_DATA)
                            self.emit_indent("lea rdi, [rax + 24]  ; dest = buffer data area");
                            self.emit_indent(&format!("lea rsi, [rel {}]  ; source string", str_label));
                            self.emit_indent(&format!("mov rcx, {}  ; string length", str_len));
                            self.emit_indent("rep movsb  ; copy bytes");
                            // Null-terminate the buffer
                            self.emit_indent("mov byte [rdi], 0");
                            // Update buffer length field (offset 8 = BUF_LENGTH)
                            self.emit_indent(&format!("mov rax, [rbp-{}]  ; reload buffer pointer", offset));
                            self.emit_indent(&format!("mov qword [rax + 8], {}  ; set buffer length", str_len));
                            self.uses_buffers = true;
                        } else {
                            // Non-string initializer for buffer - evaluate and store
                            self.generate_expr(val);
                            self.emit_indent(&format!("mov [rbp-{}], rax", offset));
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
            }
            
            Statement::Assignment { name, value } => {
                self.generate_expr(value);
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("mov [rbp-{}], rax", offset));
                } else {
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
                        self.emit(&format!("{}:", next_label));
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
                
                for s in body {
                    self.generate_statement(s);
                }
                
                self.emit_indent(&format!("jmp {}", start_label));
                self.emit(&format!("{}:", end_label));
            }
            
            Statement::ForRange { variable, range, body } => {
                let start_label = self.new_label("for_start");
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
                    
                    for s in body {
                        self.generate_statement(s);
                    }
                    
                    self.emit_indent(&format!("inc qword [rbp-{}]", var_offset));
                    self.emit_indent(&format!("jmp {}", start_label));
                    
                    self.emit(&format!("{}:", end_label));
                }
            }
            
            Statement::Repeat { count, body } => {
                let start_label = self.new_label("repeat_start");
                let end_label = self.new_label("repeat_end");
                
                self.generate_expr(count);
                let counter_offset = self.alloc_var("_repeat_counter");
                self.emit_indent(&format!("mov [rbp-{}], rax", counter_offset));
                
                self.emit(&format!("{}:", start_label));
                
                self.emit_indent(&format!("cmp qword [rbp-{}], 0", counter_offset));
                self.emit_indent(&format!("jle {}", end_label));
                
                for s in body {
                    self.generate_statement(s);
                }
                
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
                }
            }
            
            Statement::Decrement { name } => {
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("dec qword [rbp-{}]", offset));
                }
            }
            
            Statement::Break => {
                self.emit_indent("; break");
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
            }
            
            Statement::Return { value } => {
                if let Some(v) = value {
                    self.generate_expr(v); // should leave return value in RAX
                }
                self.emit_indent("FUNC_EPILOGUE");
            }
            
            Statement::FunctionCall { name, args } => {
                // Mark that we're using functions so funcs.asm gets included
                self.uses_funcs = true;
                
                for (i, arg) in args.iter().enumerate() {
                    self.generate_expr(arg);
                    let reg = match i {
                        0 => "rdi",
                        1 => "rsi",
                        2 => "rdx",
                        3 => "rcx",
                        4 => "r8",
                        5 => "r9",
                        _ => {
                            self.emit_indent("push rax");
                            continue;
                        }
                    };
                    self.emit_indent(&format!("mov {}, rax", reg));
                }
                let func_label = name.replace(' ', "_").replace('-', "_");
                self.emit_indent(&format!("call {}", func_label));
            }
                        
            Statement::FunctionDef { name, params, body, .. } => {
                // Mark that we're using functions so funcs.asm gets included
                self.uses_funcs = true;
                
                let func_label = name.replace(' ', "_").replace('-', "_");

                // Track exported functions for shared library mode
                if self.shared_lib_mode {
                    self.exported_functions.push(func_label.clone());
                }

                // Save outer codegen state
                let saved_output = std::mem::take(&mut self.output);
                let saved_vars = std::mem::take(&mut self.variables);
                let saved_stack = self.stack_offset;

                // Fresh function-local state
                self.output = String::new();
                self.variables = std::collections::HashMap::new(); // or whatever your type is
                self.stack_offset = 0;

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

                // Append to functions section
                self.functions_section.push_str(&format!("; Function: {}\n", name));
                self.functions_section.push_str(&func_code);
            }

            
            Statement::ForEach { variable, collection, body } => {
                let start_label = self.new_label("foreach_start");
                let end_label = self.new_label("foreach_end");
                
                // Special handling for ArgumentAll - iterate over argv[1..argc]
                if matches!(collection, Expr::ArgumentAll) {
                    // Get argc and store as loop limit
                    self.emit_indent("call _get_argc");
                    let argc_var = self.alloc_var(&format!("{}_argc", variable));
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; argc", argc_var));
                    
                    // Initialize index to 1 (skip program name)
                    let index_var = self.alloc_var(&format!("{}_idx", variable));
                    self.emit_indent(&format!("mov qword [rbp-{}], 1  ; start at argv[1]", index_var));
                    
                    // Allocate variable for current element
                    let elem_var = self.alloc_var(variable);
                    self.variables.insert(variable.clone(), elem_var);
                    self.variable_types.insert(variable.clone(), VarType::String);
                    
                    self.emit(&format!("{}:", start_label));
                    
                    // Check if index < argc
                    self.emit_indent(&format!("mov rax, [rbp-{}]  ; index", index_var));
                    self.emit_indent(&format!("cmp rax, [rbp-{}]  ; compare with argc", argc_var));
                    self.emit_indent(&format!("jge {}", end_label));
                    
                    // Get current argument: _get_arg(index)
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("call _get_arg");
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; store in {}", elem_var, variable));
                    
                    // Generate body
                    for s in body {
                        self.generate_statement(s);
                    }
                    
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
                self.generate_expr(collection);
                let list_ptr = self.alloc_var(&format!("{}_list", variable));
                self.emit_indent(&format!("mov [rbp-{}], rax  ; list pointer", list_ptr));
                
                // Get list length
                self.emit_indent("mov rax, [rax]  ; get length");
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
                
                // Get current element: list[index+1] (skip length field)
                self.emit_indent(&format!("mov rbx, [rbp-{}]  ; list pointer", list_ptr));
                self.emit_indent("inc rax  ; skip length field");
                self.emit_indent("shl rax, 3  ; multiply by 8");
                self.emit_indent("add rbx, rax");
                self.emit_indent("mov rax, [rbx]  ; get element");
                self.emit_indent(&format!("mov [rbp-{}], rax  ; store in {}", elem_var, variable));
                
                // Generate body
                for s in body {
                    self.generate_statement(s);
                }
                
                // Increment index
                self.emit_indent(&format!("inc qword [rbp-{}]", index_var));
                self.emit_indent(&format!("jmp {}", start_label));
                
                self.emit(&format!("{}:", end_label));
            }
            
            // File I/O statements
            Statement::BufferDecl { name, size } => {
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
                let offset = self.alloc_var(name);
                self.emit_indent(&format!("mov [rbp-{}], rax  ; buffer struct pointer", offset));
                self.variable_types.insert(name.clone(), VarType::Buffer);
            }
            
            Statement::ByteSet { buffer, index, value } => {
                self.emit_indent("; Set byte N of buffer to value");
                // Get buffer pointer into rdi for _buffer_data call
                if let Some(offset) = self.get_var(buffer) {
                    self.emit_indent(&format!("mov rdi, [rbp-{}]  ; buffer ptr", offset));
                }
                // Get the data pointer (skip buffer header)
                self.emit_indent("call _buffer_data");
                self.emit_indent("push rax  ; save data pointer");
                // Get index and convert to 0-indexed
                self.generate_expr(index);
                self.emit_indent("dec rax  ; 1-indexed to 0-indexed");
                self.emit_indent("push rax  ; save index");
                // Get value
                self.generate_expr(value);
                self.emit_indent("mov rdx, rax  ; value in rdx");
                self.emit_indent("pop rcx  ; index in rcx");
                self.emit_indent("pop rbx  ; data pointer in rbx");
                // Write byte
                self.emit_indent("mov [rbx + rcx], dl  ; write byte");
            }
            
            Statement::ElementSet { list, index, value } => {
                self.emit_indent("; Set element N of list to value");
                // Get list pointer
                if let Some(offset) = self.get_var(list) {
                    self.emit_indent(&format!("mov rbx, [rbp-{}]  ; list ptr", offset));
                }
                // Get index and convert to 0-indexed
                self.generate_expr(index);
                self.emit_indent("dec rax  ; 1-indexed to 0-indexed");
                self.emit_indent("mov rcx, rax  ; index in rcx");
                // Get element size (at offset 16 in list structure)
                self.emit_indent("mov rdx, [rbx + 16]  ; element size");
                // Calculate offset
                self.emit_indent("imul rcx, rdx  ; index * element_size");
                self.emit_indent("add rcx, 24  ; data starts at offset 24");
                // Get value
                self.generate_expr(value);
                // Write element
                self.emit_indent("mov [rbx + rcx], rax  ; write element");
            }
            
            Statement::FileOpen { name, path, mode } => {
                self.uses_files = true;
                // Generate path - either label or expression result
                let use_rdi = match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("lea rdi, [{}]", label));
                        true
                    }
                    _ => {
                        self.generate_expr(path);
                        self.emit_indent("mov rdi, rax  ; path pointer");
                        true
                    }
                };
                
                // Track if file is writable based on mode
                let is_writable = matches!(mode, FileMode::Writing | FileMode::Appending);
                self.file_writable.insert(name.clone(), is_writable);
                
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
                let _ = use_rdi;
                
                // Store file descriptor and register for tracking (only if valid)
                let offset = self.alloc_var(name);
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
                    self.emit_indent("call _read_into_buffer  ; auto-grows if needed");
                    // Update buffer pointer (may have changed if grown)
                    self.emit_indent(&format!("mov [rbp-{}], rsi  ; updated buffer ptr", buf_offset));
                    self.emit(&format!("{}:", skip_label));
                }
            }
            
            Statement::FileWrite { file, value } => {
                // Get file fd
                let file_fd = if let Some(offset) = self.get_var(file) {
                    format!("[rbp-{}]", offset)
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
                            self.emit_indent("push rax  ; save buffer ptr");
                            
                            // Compare buffer data with match value
                            self.emit_indent("add rax, 24  ; buffer data offset");
                            self.emit_indent("mov rdi, rax");
                            self.generate_expr(match_value);
                            self.emit_indent("mov rsi, rax");
                            self.emit_indent("call _str_eq");
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
                match path {
                    Expr::StringLit(s) => {
                        let label = self.add_string(s);
                        self.emit_indent(&format!("FILE_DELETE {}", label));
                    }
                    _ => {
                        self.generate_expr(path);
                        self.emit_indent("FILE_DELETE rax");
                    }
                }
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
                if let Some(offset) = self.get_var(name) {
                    self.generate_expr(new_size);
                    self.emit_indent("mov rsi, rax  ; new size");
                    self.emit_indent(&format!("mov rdi, [rbp-{}]  ; buffer pointer", offset));
                    self.emit_indent("call _realloc_buffer");
                    self.emit_indent(&format!("mov [rbp-{}], rax  ; updated buffer pointer", offset));
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
                // Allocate space for timer struct (56 bytes)
                let offset = self.alloc_var(name);
                self.variable_types.insert(name.clone(), VarType::Integer); // Track as integer for now
                self.emit_indent(&format!("; Timer declaration: {}", name));
                self.emit_indent("sub rsp, 56");  // TIMER_SIZE
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
                    if let Ok(precision) = fmt_str[1..].parse::<i32>() {
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
                Some(VarType::String) | Some(VarType::Buffer) => {
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
                            // Check for property access patterns first
                            let var_type: Option<VarType>;
                            
                            if name == "current time's hour" {
                                self.emit_indent("TIME_GET");
                                self.emit_indent("TIME_GET_HOUR rax");
                                self.emit_indent("mov rdi, rax");
                                self.uses_time = true;
                                var_type = Some(VarType::Integer);
                            } else if name == "current time's minute" {
                                self.emit_indent("TIME_GET");
                                self.emit_indent("TIME_GET_MINUTE rax");
                                self.emit_indent("mov rdi, rax");
                                self.uses_time = true;
                                var_type = Some(VarType::Integer);
                            } else if name == "current time's second" {
                                self.emit_indent("TIME_GET");
                                self.emit_indent("TIME_GET_SECOND rax");
                                self.emit_indent("mov rdi, rax");
                                self.uses_time = true;
                                var_type = Some(VarType::Integer);
                            } else if name == "arguments's count" || name == "argument's count" {
                                self.emit_indent("ARGS_COUNT");
                                self.emit_indent("mov rdi, rax");
                                var_type = Some(VarType::Integer);
                            } else if name == "arguments's name" || name == "argument's name" {
                                self.emit_indent("ARGS_NAME");
                                self.emit_indent("mov rdi, rax");
                                var_type = Some(VarType::String);
                            } else if name == "arguments's first" || name == "argument's first" {
                                self.emit_indent("ARGS_FIRST");
                                self.emit_indent("mov rdi, rax");
                                var_type = Some(VarType::String);
                            } else if name == "arguments's last" || name == "argument's last" {
                                self.emit_indent("ARGS_LAST");
                                self.emit_indent("mov rdi, rax");
                                var_type = Some(VarType::String);
                            } else if let Some(offset) = self.get_var(name) {
                                // Regular variable lookup
                                self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
                                var_type = self.variable_types.get(name).cloned();
                            } else {
                                // Unknown - print placeholder
                                let placeholder = format!("{{{}}}", name);
                                let label = self.add_string(&placeholder);
                                self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                                continue;
                            }
                            
                            let var_type = var_type;
                            
                            // Parse format spec and emit formatted value
                            let fmt_spec = self.parse_format_spec(format.as_deref());
                            self.emit_formatted_value(var_type, fmt_spec);
                        }
                        FormatPart::Expression { expr, format } => {
                            // Generate code for the expression, result will be in rax
                            self.generate_expr(expr);
                            self.emit_indent("mov rdi, rax");
                            
                            // Determine the type of the expression for formatting
                            let expr_type = self.infer_expr_type(expr);
                            
                            // Parse format spec and emit formatted value
                            let fmt_spec = self.parse_format_spec(format.as_deref());
                            self.emit_formatted_value(expr_type, fmt_spec);
                        }
                    }
                }
                if !without_newline {
                    self.emit_indent("PRINT_NEWLINE");
                }
                return;
            }
            
            Expr::StringLit(s) => {
                let label = self.add_string(s);
                self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
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
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
                    let var_type = self.variable_types.get(name).cloned();
                    match var_type {
                        Some(VarType::Buffer) => {
                            // Dynamic buffer - get data pointer (skip header)
                            self.emit_indent("call _buffer_data");
                            self.emit_indent("mov rdi, rax");
                            self.emit_indent("PRINT_CSTR rdi");
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
            
            _ => {
                let is_float = self.is_float_expr(value);
                self.generate_expr(value);
                if is_float {
                    self.emit_indent("movq xmm0, rax");
                    self.emit_indent("PRINT_FLOAT");
                    self.uses_floats = true;
                } else {
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("PRINT_INT rdi");
                }
            }
        }
        if !without_newline {
            self.emit_indent("PRINT_NEWLINE");
        }
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
                let label = self.add_string(s);
                self.emit_indent(&format!("lea rax, [{}]", label));
            }
            
            Expr::Identifier(name) => {
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
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
                        self.emit_indent("test rax, rax");
                        self.emit_indent("setz al");
                        self.emit_indent("movzx rax, al");
                    }
                }
            }
            
            Expr::Range { .. } => {}

            Expr::FunctionCall { name, args } => {
                let param_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

                // 1) Evaluate/push all args right-to-left (so arg0 ends up deepest)
                for arg in args.iter().rev() {
                    self.generate_expr(arg);
                    self.emit_indent("push rax");
                }

                // 2) Pop first 6 args into registers (arg0 -> rdi, arg1 -> rsi, ...)
                // After the pushes above, the stack top is arg0, so popping in increasing i works.
                let reg_count = args.len().min(param_regs.len());
                for i in 0..reg_count {
                    self.emit_indent(&format!("pop {}", param_regs[i]));
                }

                // 3) At this point, any remaining args (7th+) are still on the stack.
                // Count how many are left there:
                let stack_arg_count = args.len().saturating_sub(param_regs.len());
                let stack_arg_bytes = stack_arg_count * 8;

                // 4) Align stack before call.
                // In SysV, stack must be 16B-aligned *at the call instruction*.
                // We can do this by conditionally reserving 8 bytes if needed.
                // Since we don't know caller alignment here, we maintain an invariant:
                // - Our function prologue keeps alignment.
                // - Our pushes/pops here are the only changes.
                // If stack_arg_count is odd, we currently have an odd *8-byte* subtraction remaining
                // (because those stack args are still sitting on the stack), which flips alignment.
                let needs_pad = (stack_arg_count % 2) != 0;
                if needs_pad {
                    self.emit_indent("sub rsp, 8  ; align stack before call");
                }

                // 5) Call
                let func_label = name.replace(' ', "_").replace('-', "_");
                self.emit_indent(&format!("call {}", func_label));

                // 6) Clean up stack args + pad (caller cleanup in SysV)
                let mut cleanup = stack_arg_bytes as i32;
                if needs_pad {
                    cleanup += 8;
                }
                if cleanup > 0 {
                    self.emit_indent(&format!("add rsp, {}", cleanup));
                }

                // Return value already in rax
            }

            Expr::ListLit { elements } => {
                // Allocate memory for list: [length, elem0, elem1, ...]
                // Each element is 8 bytes
                let size = (elements.len() + 1) * 8;
                
                // Allocate on stack for simplicity (could use heap later)
                self.emit_indent(&format!("; List literal with {} elements", elements.len()));
                self.emit_indent(&format!("sub rsp, {}", size));
                self.emit_indent("mov rax, rsp");
                self.emit_indent("push rax  ; save list pointer");
                
                // Store length
                self.emit_indent(&format!("mov qword [rax], {}", elements.len()));
                
                // Store elements
                for (i, elem) in elements.iter().enumerate() {
                    self.emit_indent("pop rbx  ; get list pointer");
                    self.emit_indent("push rbx ; save it back");
                    self.generate_expr(elem);
                    self.emit_indent("pop rbx  ; get list pointer");
                    self.emit_indent(&format!("mov [rbx+{}], rax", (i + 1) * 8));
                    self.emit_indent("push rbx ; save list pointer");
                }
                
                self.emit_indent("pop rax  ; list pointer in rax");
            }
            
            // ListAccess: 0-indexed access (internal use)
            // MEMORY SAFETY: Always bounds-check before access
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
                self.emit_indent("mov rdx, [rbx]  ; get length");
                self.emit_indent("cmp rcx, rdx");
                self.emit_indent(&format!("jl {}  ; index < length is OK", ok_label));
                
                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent("xor rax, rax  ; return 0 on error");
                self.emit_indent(&format!("jmp {}", done_label));
                
                // Success path: safe access
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("mov rax, rcx");
                self.emit_indent("inc rax   ; skip length field");
                self.emit_indent("shl rax, 3  ; multiply by 8");
                self.emit_indent("add rax, rbx");
                self.emit_indent("mov rax, [rax]  ; get element");
                
                self.emit(&format!("{}:", done_label));
            }
            
            Expr::PropertyAccess { object, property } => {
                if let Some(offset) = self.get_var(object) {
                    let var_type = self.variable_types.get(object).cloned().unwrap_or(VarType::Unknown);
                    
                    match property {
                        // Buffer/List properties
                        ObjectProperty::Size => {
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            if var_type == VarType::Buffer {
                                self.emit_indent("mov rax, [rax + 8]  ; buffer length/size");
                            } else if var_type == VarType::List {
                                self.emit_indent("mov rax, [rax]  ; list length at offset 0");
                            } else {
                                // For files, call _file_size
                                self.emit_indent("mov rdi, rax");
                                self.emit_indent("call _file_size");
                            }
                        }
                        ObjectProperty::Capacity => {
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("mov rax, [rax]  ; buffer capacity");
                        }
                        ObjectProperty::Empty => {
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            if var_type == VarType::List {
                                self.emit_indent("mov rax, [rax]  ; get list length");
                            } else {
                                self.emit_indent("mov rax, [rax + 8]  ; get buffer size");
                            }
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setz al");
                            self.emit_indent("movzx rax, al  ; 1 if empty, 0 otherwise");
                        }
                        ObjectProperty::Full => {
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
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
                            self.emit_indent(&format!("mov rax, [rbp-{}]  ; fd", offset));
                        }
                        ObjectProperty::Modified => {
                            self.emit_indent(&format!("mov rdi, [rbp-{}]  ; fd", offset));
                            self.emit_indent("call _file_modified");
                        }
                        ObjectProperty::Accessed => {
                            self.emit_indent(&format!("mov rdi, [rbp-{}]  ; fd", offset));
                            self.emit_indent("call _file_accessed");
                        }
                        ObjectProperty::Permissions => {
                            self.emit_indent(&format!("mov rdi, [rbp-{}]  ; fd", offset));
                            self.emit_indent("call _file_permissions");
                        }
                        ObjectProperty::Readable => {
                            // Check if fd >= 0 (valid for reading)
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
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
                        ObjectProperty::First => {
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("mov rax, [rax + 8]  ; first element");
                        }
                        ObjectProperty::Last => {
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("mov rbx, [rax]      ; length");
                            self.emit_indent("shl rbx, 3          ; * 8");
                            self.emit_indent("add rax, rbx        ; offset to last");
                            self.emit_indent("mov rax, [rax]      ; last element");
                        }
                        
                        // Number properties
                        ObjectProperty::Absolute => {
                            let lbl = self.label_counter;
                            self.label_counter += 1;
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("test rax, rax");
                            self.emit_indent(&format!("jns .abs_done_{}", lbl));
                            self.emit_indent("neg rax");
                            self.emit(&format!(".abs_done_{}:", lbl));
                        }
                        ObjectProperty::Sign => {
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("test rax, rax");
                            self.emit_indent("mov rbx, 1");
                            self.emit_indent("mov rcx, -1");
                            self.emit_indent("cmovg rax, rbx  ; positive -> 1");
                            self.emit_indent("cmovl rax, rcx  ; negative -> -1");
                            self.emit_indent("cmovz rax, rax  ; zero -> 0 (already)");
                        }
                        ObjectProperty::Even => {
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("and rax, 1");
                            self.emit_indent("xor rax, 1  ; 1 if even, 0 if odd");
                        }
                        ObjectProperty::Odd => {
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("and rax, 1  ; 1 if odd, 0 if even");
                        }
                        ObjectProperty::Positive => {
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setg al");
                            self.emit_indent("movzx rax, al");
                        }
                        ObjectProperty::Negative => {
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setl al");
                            self.emit_indent("movzx rax, al");
                        }
                        ObjectProperty::Zero => {
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("test rax, rax");
                            self.emit_indent("setz al");
                            self.emit_indent("movzx rax, al");
                        }
                        
                        // Time properties (unix timestamp -> component extraction)
                        ObjectProperty::Hour => {
                            self.uses_time = true;
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("TIME_GET_HOUR rax");
                        }
                        ObjectProperty::Minute => {
                            self.uses_time = true;
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("TIME_GET_MINUTE rax");
                        }
                        ObjectProperty::Second => {
                            self.uses_time = true;
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("TIME_GET_SECOND rax");
                        }
                        ObjectProperty::Day => {
                            self.uses_time = true;
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("TIME_GET_DAY rax");
                        }
                        ObjectProperty::Month => {
                            self.uses_time = true;
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("TIME_GET_MONTH rax");
                        }
                        ObjectProperty::Year => {
                            self.uses_time = true;
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                            self.emit_indent("TIME_GET_YEAR rax");
                        }
                        ObjectProperty::Unix => {
                            // Unix timestamp is the raw value
                            self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                        }
                        
                        // Timer properties
                        ObjectProperty::Duration => {
                            self.uses_time = true;
                            self.emit_indent(&format!("; Timer duration"));
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset + 48));
                            self.emit_indent("TIMER_DURATION_SECONDS rax");
                        }
                        ObjectProperty::Elapsed => {
                            self.uses_time = true;
                            self.emit_indent(&format!("; Timer elapsed"));
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset + 48));
                            self.emit_indent("TIMER_ELAPSED_SECONDS rax");
                        }
                        ObjectProperty::StartTime => {
                            self.uses_time = true;
                            self.emit_indent(&format!("; Timer start time"));
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset + 48));
                            self.emit_indent("TIMER_START_TIME rax");
                        }
                        ObjectProperty::EndTime => {
                            self.uses_time = true;
                            self.emit_indent(&format!("; Timer end time"));
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset + 48));
                            self.emit_indent("TIMER_END_TIME rax");
                        }
                        ObjectProperty::Running => {
                            self.uses_time = true;
                            self.emit_indent(&format!("; Timer running status"));
                            self.emit_indent(&format!("lea rax, [rbp - {}]", offset + 48));
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
                self.emit_indent("call _get_argc");
            }
            
            Expr::ArgumentAt { index } => {
                self.generate_expr(index);
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _get_arg");
            }
            
            Expr::ArgumentName => {
                self.emit_indent("xor rdi, rdi  ; index 0 - program name");
                self.emit_indent("call _get_arg");
            }
            
            Expr::ArgumentFirst => {
                self.emit_indent("mov rdi, 1  ; index 1 - first user arg");
                self.emit_indent("call _get_arg");
            }
            
            Expr::ArgumentSecond => {
                self.emit_indent("mov rdi, 2  ; index 2 - second user arg");
                self.emit_indent("call _get_arg");
            }
            
            Expr::ArgumentLast => {
                self.emit_indent("call _get_argc");
                self.emit_indent("dec rax  ; last index = argc - 1");
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _get_arg");
            }
            
            Expr::ArgumentEmpty => {
                self.emit_indent("call _get_argc");
                self.emit_indent("cmp rax, 1");
                self.emit_indent("setle al  ; 1 if argc <= 1 (no user args)");
                self.emit_indent("movzx rax, al");
            }
            
            Expr::ArgumentAll => {
                // This is handled specially in ForEach codegen
                // If used elsewhere, we can't return a list directly
                self.emit_indent("; ArgumentAll - handled by ForEach");
            }
            
            Expr::TreatingAs { value, match_value, replacement } => {
                // Inline substitution: if value == match_value, use replacement
                let skip_label = self.new_label("treating_skip");
                let done_label = self.new_label("treating_done");
                
                // Check if value is a buffer variable
                let is_buffer = if let Expr::Identifier(ref name) = **value {
                    self.variable_types.get(name) == Some(&VarType::Buffer)
                } else {
                    false
                };
                
                // Evaluate the value
                self.generate_expr(value);
                self.emit_indent("push rax  ; save original value");
                
                // If buffer, get pointer to data (offset 24) for comparison
                if is_buffer {
                    self.emit_indent("add rax, 24  ; buffer data offset");
                }
                self.emit_indent("mov rdi, rax  ; comparison ptr in rdi");
                
                // Evaluate match_value
                self.generate_expr(match_value);
                self.emit_indent("mov rsi, rax  ; match value in rsi");
                
                // Compare strings
                self.emit_indent("call _str_eq");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jz {}", skip_label));
                
                // Match found - use replacement
                self.emit_indent("add rsp, 8  ; discard saved value");
                self.generate_expr(replacement);
                self.emit_indent(&format!("jmp {}", done_label));
                
                // No match - use original value
                self.emit(&format!("{}:", skip_label));
                self.emit_indent("pop rax  ; restore original value");
                
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
            
            // Type casting
            Expr::Cast { value, target_type } => {
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
                        }
                        // Other types stay as-is (already integer)
                    }
                    Type::Float => {
                        // Integer to float
                        if !self.is_float_expr(value) {
                            self.emit_indent("; Cast integer to float");
                            self.emit_indent("cvtsi2sd xmm0, rax");
                            // Keep the invariant that expressions leave their value in RAX.
                            // For floats, RAX holds the IEEE-754 bits.
                            self.emit_indent("XMM0_TO_RAX");
                            self.uses_floats = true;
                        }
                    }
                    Type::Boolean => {
                        // Convert to boolean (0 = false, non-zero = true)
                        self.emit_indent("; Cast to boolean");
                        self.emit_indent("test rax, rax");
                        self.emit_indent("setne al");
                        self.emit_indent("movzx rax, al");
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
            Expr::ByteAccess { buffer, index } => {
                self.emit_indent("; Byte access");
                // Get buffer pointer
                self.generate_expr(buffer);
                self.emit_indent("push rax");
                // Get index
                self.generate_expr(index);
                self.emit_indent("mov rcx, rax");  // index in rcx
                self.emit_indent("pop rbx");       // buffer ptr in rbx
                // Get data pointer (skip buffer header - BUF_DATA = 24)
                self.emit_indent("add rbx, 24  ; skip to buffer data area");
                // Convert 1-indexed to 0-indexed and read byte
                self.emit_indent("dec rcx");
                self.emit_indent("xor rax, rax");
                self.emit_indent("mov al, [rbx + rcx]");
            }
            
            // Element access: element N of list (1-indexed)
            // List structure: [length, elem0, elem1, ...] - all 8-byte values
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
                self.emit_indent("mov rdx, [rbx]  ; get length");
                self.emit_indent("cmp rcx, rdx");
                self.emit_indent(&format!("jle {}  ; index <= length is OK", ok_label));
                
                // Error path: out of bounds
                self.emit(&format!("{}:", error_label));
                self.emit_indent("mov qword [rel _last_error], 1  ; set error flag");
                self.emit_indent("xor rax, rax  ; return 0 on error");
                self.emit_indent(&format!("jmp {}", done_label));
                
                // Success path: safe access
                self.emit(&format!("{}:", ok_label));
                self.emit_indent("mov rax, rcx");
                self.emit_indent("shl rax, 3  ; index * 8");
                self.emit_indent("add rax, rbx");
                self.emit_indent("mov rax, [rax]  ; get element");
                
                self.emit(&format!("{}:", done_label));
            }
            
            // Format string - result is left in rax as a pointer (not used here, handled in generate_print)
            Expr::FormatString { .. } => {
                // Format strings are handled specially in generate_print
                // For expression context, just return 0
                self.emit_indent("xor rax, rax");
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
                        self.emit_indent("test rax, rax");
                        self.emit_indent(&format!("jnz {}", false_label));
                    }
                }
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
                    BinaryOperator::Equal | BinaryOperator::NotEqual |
                    BinaryOperator::Greater | BinaryOperator::Less |
                    BinaryOperator::GreaterEqual | BinaryOperator::LessEqual => {
                        let is_float = self.is_float_expr(left) || self.is_float_expr(right);
                        
                        if is_float {
                            // Float comparison using SSE2
                            self.generate_expr(right);
                            self.emit_indent("push rax");
                            self.generate_expr(left);
                            self.emit_indent("movq xmm0, rax");       // left in xmm0
                            self.emit_indent("pop rax");
                            self.emit_indent("movq xmm1, rax");       // right in xmm1
                            self.emit_indent("ucomisd xmm0, xmm1");
                            
                            let jmp = match op {
                                BinaryOperator::Equal => "jne",
                                BinaryOperator::NotEqual => "je",
                                BinaryOperator::Greater => "jbe",    // below or equal (unsigned)
                                BinaryOperator::Less => "jae",       // above or equal (unsigned)
                                BinaryOperator::GreaterEqual => "jb", // below (unsigned)
                                BinaryOperator::LessEqual => "ja",   // above (unsigned)
                                _ => unreachable!(),
                            };
                            self.emit_indent(&format!("{} {}", jmp, false_label));
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
            Expr::StringLit(_) => Some(VarType::String),
            Expr::BoolLit(_) => Some(VarType::Integer), // Booleans are integers (0/1)
            Expr::Identifier(name) => self.variable_types.get(name).cloned(),
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
            Expr::BinaryOp { left, op, right } => {
                // For binary operations, infer based on operator and operand types
                match op {
                    BinaryOperator::Add | BinaryOperator::Subtract | 
                    BinaryOperator::Multiply | BinaryOperator::Divide |
                    BinaryOperator::Modulo => {
                        // If either operand is float, result is float
                        if self.is_float_expr(left) || self.is_float_expr(right) {
                            Some(VarType::Float)
                        } else {
                            Some(VarType::Integer)
                        }
                    }
                    _ => Some(VarType::Integer), // Comparisons and logical ops result in integers
                }
            }
            Expr::UnaryOp { operand, .. } => self.infer_expr_type(operand),
            Expr::TreatingAs { value, .. } => self.infer_expr_type(value),
            _ => Some(VarType::Integer), // Default to integer for complex expressions
        }
    }
}
