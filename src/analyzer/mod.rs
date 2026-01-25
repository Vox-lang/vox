use crate::parser::ast::*;
use crate::errors::{find_similar_keyword, ENGLISH_KEYWORDS};
use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct Dependencies {
    pub uses_io: bool,
    pub uses_heap: bool,
    pub uses_strings: bool,
    pub uses_args: bool,
    pub uses_funcs: bool,
}

pub struct Analyzer {
    pub deps: Dependencies,
    pub variables: HashSet<String>,
    pub functions: HashSet<String>,
    pub used_identifiers: HashSet<String>,  // Track all identifiers seen
    pub errors: Vec<String>,
}

impl Analyzer {
    pub fn new() -> Self {
        Analyzer {
            deps: Dependencies::default(),
            variables: HashSet::new(),
            functions: HashSet::new(),
            used_identifiers: HashSet::new(),
            errors: Vec::new(),
        }
    }
    
    pub fn analyze(&mut self, program: &mut Program) {
        // First pass: collect all function definitions
        for stmt in &program.statements {
            if let Statement::FunctionDef { name, .. } = stmt {
                self.functions.insert(name.clone());
            }
        }
        
        // Second pass: analyze all statements
        for stmt in &program.statements {
            self.analyze_statement(stmt);
        }
        
        // Third pass: check for typos in unknown identifiers
        self.check_for_typos();
        
        program.uses_io = self.deps.uses_io;
        program.uses_heap = self.deps.uses_heap;
        program.uses_strings = self.deps.uses_strings;
        program.uses_args = self.deps.uses_args;
    }
    
    fn check_for_typos(&mut self) {
        // Find identifiers that aren't declared variables or functions
        let unknown: Vec<String> = self.used_identifiers
            .iter()
            .filter(|id| !self.variables.contains(*id) && !self.functions.contains(*id))
            .cloned()
            .collect();
        
        // Check if any look like keyword typos
        let mut typo_errors = Vec::new();
        for id in unknown {
            // Skip common internal identifiers
            if id.starts_with('_') || id == "stdin" || id == "stdout" || id == "stderr" {
                continue;
            }
            
            if let Some(suggestion) = find_similar_keyword(&id, ENGLISH_KEYWORDS) {
                typo_errors.push(format!(
                    "Unknown identifier '{}' - did you mean '{}'?",
                    id, suggestion
                ));
            }
        }
        
        // Prepend typo errors so they appear first
        typo_errors.append(&mut self.errors);
        self.errors = typo_errors;
    }
    
    fn track_identifier(&mut self, name: &str) {
        self.used_identifiers.insert(name.to_string());
    }
    
    fn analyze_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Print { value, .. } => {
                self.deps.uses_io = true;
                self.analyze_expr(value);
                
                if matches!(value, Expr::StringLit(_)) {
                    self.deps.uses_strings = true;
                }
            }
            
            Statement::VarDecl { name, value, .. } => {
                self.variables.insert(name.clone());
                if let Some(v) = value {
                    self.analyze_expr(v);
                }
            }
            
            Statement::Assignment { name, value } => {
                if !self.variables.contains(name) {
                    self.variables.insert(name.clone());
                }
                self.analyze_expr(value);
            }
            
            Statement::If { condition, then_block, else_if_blocks, else_block } => {
                self.analyze_expr(condition);
                for s in then_block {
                    self.analyze_statement(s);
                }
                for (cond, block) in else_if_blocks {
                    self.analyze_expr(cond);
                    for s in block {
                        self.analyze_statement(s);
                    }
                }
                if let Some(block) = else_block {
                    for s in block {
                        self.analyze_statement(s);
                    }
                }
            }
            
            Statement::While { condition, body } => {
                self.analyze_expr(condition);
                for s in body {
                    self.analyze_statement(s);
                }
            }
            
            Statement::ForRange { variable, range, body } => {
                self.variables.insert(variable.clone());
                self.analyze_expr(range);
                for s in body {
                    self.analyze_statement(s);
                }
            }
            
            Statement::ForEach { variable, collection, body } => {
                self.variables.insert(variable.clone());
                self.analyze_expr(collection);
                for s in body {
                    self.analyze_statement(s);
                }
            }
            
            Statement::Repeat { count, body } => {
                self.analyze_expr(count);
                for s in body {
                    self.analyze_statement(s);
                }
            }
            
            Statement::Return { value } => {
                if let Some(v) = value {
                    self.analyze_expr(v);
                }
            }
            
            Statement::Allocate { name, size } => {
                self.deps.uses_heap = true;
                self.variables.insert(name.clone());
                self.analyze_expr(size);
            }
            
            Statement::Free { name } => {
                self.deps.uses_heap = true;
                if !self.variables.contains(name) {
                    self.errors.push(format!("Freeing unknown variable: {}", name));
                }
            }
            
            Statement::FunctionCall { name, args } => {
                self.deps.uses_funcs = true; // Track that functions are used
                if !self.functions.contains(name) {
                    let mut err = format!("Unknown function: {}", name);
                    if let Some(suggestion) = find_similar_keyword(name, ENGLISH_KEYWORDS) {
                        err.push_str(&format!(" (did you mean '{}'?)", suggestion));
                    }
                    self.errors.push(err);
                }
                for arg in args {
                    self.analyze_expr(arg);
                }
            }
            
            Statement::FunctionDef { name, params, body, .. } => {
                self.functions.insert(name.clone());
                self.deps.uses_funcs = true; // Track that functions are used
                // Add function parameters to scope
                for (param_name, _) in params {
                    self.variables.insert(param_name.clone());
                }
                for s in body {
                    self.analyze_statement(s);
                }
                // Remove params after function (simple scoping)
                for (param_name, _) in params {
                    self.variables.remove(param_name);
                }
            }
            
            Statement::Increment { name } | Statement::Decrement { name } => {
                if !self.variables.contains(name) {
                    self.errors.push(format!("Unknown variable: {}", name));
                }
            }
            
            Statement::Break | Statement::Continue => {}
            
            // File I/O statements
            Statement::BufferDecl { name, size } => {
                self.variables.insert(name.clone());
                self.analyze_expr(size);
                self.deps.uses_heap = true;
            }
            
            Statement::ByteSet { buffer, index, value } => {
                self.track_identifier(buffer);
                self.analyze_expr(index);
                self.analyze_expr(value);
            }
            
            Statement::ElementSet { list, index, value } => {
                self.track_identifier(list);
                self.analyze_expr(index);
                self.analyze_expr(value);
            }
            
            Statement::ListAppend { list, value } => {
                self.track_identifier(list);
                self.analyze_expr(value);
            }
            
            Statement::FileOpen { name, path, .. } => {
                self.variables.insert(name.clone());
                self.analyze_expr(path);
                self.deps.uses_io = true;
            }
            
            Statement::FileRead { buffer, .. } => {
                if !self.variables.contains(buffer) {
                    self.errors.push(format!("Unknown buffer: {}", buffer));
                }
                self.deps.uses_io = true;
            }
            
            Statement::FileWrite { file, value } => {
                if !self.variables.contains(file) {
                    self.errors.push(format!("Unknown file: {}", file));
                }
                self.analyze_expr(value);
                self.deps.uses_io = true;
            }
            
            Statement::FileWriteNewline { file } => {
                if !self.variables.contains(file) {
                    self.errors.push(format!("Unknown file: {}", file));
                }
                self.deps.uses_io = true;
            }
            
            Statement::FileClose { file } => {
                if !self.variables.contains(file) {
                    self.errors.push(format!("Unknown file: {}", file));
                }
                self.deps.uses_io = true;
            }
            
            Statement::FileDelete { path } => {
                self.analyze_expr(path);
                self.deps.uses_io = true;
            }
            
            Statement::OnError { actions } => {
                for action in actions {
                    self.analyze_statement(action);
                }
            }
            
            Statement::BufferResize { name, new_size } => {
                if !self.variables.contains(name) {
                    self.errors.push(format!("Unknown buffer: {}", name));
                }
                self.analyze_expr(new_size);
                self.deps.uses_heap = true;
            }
            
            Statement::LibraryDecl { .. } => {
                // Library declarations are metadata, no analysis needed
            }
            
            Statement::See { .. } => {
                // See statements are handled at compile time
            }
            
            Statement::Exit { code } => {
                self.analyze_expr(code);
            }
            
            // Time and Timer statements
            Statement::TimerDecl { name } => {
                self.variables.insert(name.clone());
            }
            
            Statement::TimerStart { name } => {
                if !self.variables.contains(name) {
                    self.errors.push(format!("Unknown timer: {}", name));
                }
            }
            
            Statement::TimerStop { name } => {
                if !self.variables.contains(name) {
                    self.errors.push(format!("Unknown timer: {}", name));
                }
            }
            
            Statement::Wait { duration, .. } => {
                self.analyze_expr(duration);
            }
            
            Statement::GetTime { into } => {
                self.variables.insert(into.clone());
            }
        }
    }
    
    fn analyze_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::BinaryOp { left, op: _, right } => {
                self.analyze_expr(left);
                self.analyze_expr(right);
                
            }
            
            Expr::UnaryOp { operand, .. } => {
                self.analyze_expr(operand);
            }
            
            Expr::Range { start, end, .. } => {
                self.analyze_expr(start);
                self.analyze_expr(end);
            }
            
            Expr::PropertyCheck { value, .. } => {
                self.analyze_expr(value);
            }
            
            Expr::FunctionCall { name, args } => {
                self.deps.uses_funcs = true; // Track that functions are used
                if !self.functions.contains(name) {
                    let mut err = format!("Unknown function: {}", name);
                    if let Some(suggestion) = find_similar_keyword(name, ENGLISH_KEYWORDS) {
                        err.push_str(&format!(" (did you mean '{}'?)", suggestion));
                    }
                    self.errors.push(err);
                }
                for arg in args {
                    self.analyze_expr(arg);
                }
            }
            
            Expr::ListAccess { list, index } => {
                self.analyze_expr(list);
                self.analyze_expr(index);
            }
            
            Expr::ListLit { elements } => {
                self.deps.uses_heap = true;
                for elem in elements {
                    self.analyze_expr(elem);
                }
            }
            
            Expr::StringLit(_) => {
                self.deps.uses_strings = true;
            }
            
            Expr::FormatString { parts } => {
                self.deps.uses_strings = true;
                for part in parts {
                    match part {
                        FormatPart::Expression { expr, .. } => {
                            self.analyze_expr(expr);
                        }
                        FormatPart::Variable { name, .. } => {
                            self.track_identifier(name);
                            if !self.variables.contains(name) && name != "_iter" {
                                if find_similar_keyword(name, ENGLISH_KEYWORDS).is_none() {
                                    self.errors.push(format!("Unknown variable: {}", name));
                                }
                            }
                        }
                        FormatPart::Literal(_) => {}
                    }
                }
            }
            
            Expr::Identifier(name) => {
                self.track_identifier(name);
                if !self.variables.contains(name) && name != "_iter" {
                    // Don't report as unknown variable if it might be a keyword typo
                    // (that will be caught by check_for_typos)
                    if find_similar_keyword(name, ENGLISH_KEYWORDS).is_none() {
                        self.errors.push(format!("Unknown variable: {}", name));
                    }
                }
            }
            
            // Argument and environment variable expressions
            Expr::ArgumentCount | Expr::ArgumentName | Expr::ArgumentFirst | 
            Expr::ArgumentSecond | Expr::ArgumentLast | Expr::ArgumentEmpty |
            Expr::ArgumentAll => {
                self.deps.uses_args = true;
            }
            
            Expr::TreatingAs { value, match_value, replacement } => {
                self.analyze_expr(value);
                self.analyze_expr(match_value);
                self.analyze_expr(replacement);
            }
            
            Expr::ArgumentAt { index } => {
                self.deps.uses_args = true;
                self.analyze_expr(index);
            }
            
            Expr::EnvironmentVariable { name } => {
                self.deps.uses_args = true;
                self.analyze_expr(name);
            }
            
            Expr::EnvironmentVariableCount | Expr::EnvironmentVariableFirst |
            Expr::EnvironmentVariableLast | Expr::EnvironmentVariableEmpty => {
                self.deps.uses_args = true;
            }
            
            Expr::EnvironmentVariableAt { index } => {
                self.deps.uses_args = true;
                self.analyze_expr(index);
            }
            
            Expr::EnvironmentVariableExists { name } => {
                self.deps.uses_args = true;
                self.analyze_expr(name);
            }
            
            _ => {}
        }
    }
}

