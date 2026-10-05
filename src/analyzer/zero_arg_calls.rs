//! A call with no arguments written directly, as a name, is a call.
//!
//! LANGUAGE.md "Function Calls": "Calls with no arguments can be written
//! directly". The parser cannot tell `greeting` the call from `greeting` the
//! variable (a function may be defined below its first use, or come from a
//! library), so it produces `Expr::Identifier` for both. This pass settles
//! the question once, after every definition and import is known and before
//! anything is checked or generated: a name that is not a variable in its
//! scope and names a function declaring no parameters becomes
//! `Expr::FunctionCall` with no arguments. From here on every position that
//! takes a value sees the same shape it sees for a call written with `of`,
//! so the direct call means exactly what the call with arguments means
//! (docs/BUGS_FOUND.md #131).
//!
//! A variable of the same name shadows the function, as it always has. The
//! scope test is deliberately generous: a name declared anywhere at the top
//! level counts as a variable everywhere, and a name declared anywhere in a
//! function body (or as its parameter) counts as one throughout that body.
//! Such a name is left as it was written, for the analyzer and codegen to
//! resolve in declaration order exactly as before.

use super::Analyzer;
use crate::parser::ast::*;
use std::collections::HashSet;

impl Analyzer {
    pub(crate) fn resolve_zero_argument_calls(&mut self, program: &mut Program) {
        let mut top_level_names = HashSet::new();
        collect_declared_names(&program.statements, &mut top_level_names);

        // Function keys depend on the library identity in force at the
        // definition, so the walk tracks it the way the first pass does and
        // leaves the analyzer's own identity as it found it.
        let saved_library = self.current_library.clone();
        self.current_library = None;
        for stmt in program.statements.iter_mut() {
            if let Statement::LibraryDecl { name, version } = stmt {
                self.current_library = Some((name.clone(), version.clone()));
            }
            self.resolve_in_statement(stmt, &top_level_names);
        }
        self.current_library = saved_library;
    }

    fn resolve_in_block(&self, stmts: &mut [Statement], variables: &HashSet<String>) {
        for stmt in stmts.iter_mut() {
            self.resolve_in_statement(stmt, variables);
        }
    }

    fn resolve_in_statement(&self, stmt: &mut Statement, variables: &HashSet<String>) {
        match stmt {
            Statement::FunctionDef { params, body, .. } => {
                let mut in_scope = variables.clone();
                in_scope.extend(params.iter().map(|(name, _)| name.clone()));
                collect_declared_names(body, &mut in_scope);
                self.resolve_in_block(body, &in_scope);
            }
            Statement::Print { value, .. }
            | Statement::SetThingField { value, .. }
            | Statement::Assignment { value, .. }
            | Statement::ListAppend { value, .. }
            | Statement::FileWrite { value, .. } => self.resolve_in_expr(value, variables),
            Statement::VarDecl { value, .. } => {
                if let Some(value) = value {
                    self.resolve_in_expr(value, variables);
                }
            }
            Statement::FlagSchemaDecl { default, .. } => {
                if let Some(default) = default {
                    self.resolve_in_expr(default, variables);
                }
            }
            Statement::Return { value, .. } => {
                if let Some(value) = value {
                    self.resolve_in_expr(value, variables);
                }
            }
            Statement::If { condition, then_block, else_if_blocks, else_block } => {
                self.resolve_in_expr(condition, variables);
                self.resolve_in_block(then_block, variables);
                for (condition, block) in else_if_blocks.iter_mut() {
                    self.resolve_in_expr(condition, variables);
                    self.resolve_in_block(block, variables);
                }
                if let Some(block) = else_block {
                    self.resolve_in_block(block, variables);
                }
            }
            Statement::While { condition, body } => {
                self.resolve_in_expr(condition, variables);
                self.resolve_in_block(body, variables);
            }
            Statement::ForRange { range, body, .. } => {
                self.resolve_in_expr(range, variables);
                self.resolve_in_block(body, variables);
            }
            Statement::ForEach { collection, body, .. } => {
                self.resolve_in_expr(collection, variables);
                self.resolve_in_block(body, variables);
            }
            Statement::Repeat { count, body } => {
                self.resolve_in_expr(count, variables);
                self.resolve_in_block(body, variables);
            }
            Statement::OnError { actions } => self.resolve_in_block(actions, variables),
            Statement::Exit { code } => self.resolve_in_expr(code, variables),
            Statement::FunctionCall { args, .. } => {
                for arg in args.iter_mut() {
                    self.resolve_in_expr(arg, variables);
                }
            }
            Statement::Allocate { size, .. } | Statement::BufferDecl { size, .. } => {
                self.resolve_in_expr(size, variables)
            }
            Statement::ByteSet { index, value, .. } | Statement::ElementSet { index, value, .. } => {
                self.resolve_in_expr(index, variables);
                self.resolve_in_expr(value, variables);
            }
            Statement::MapSet { key, value, .. } => {
                self.resolve_in_expr(key, variables);
                self.resolve_in_expr(value, variables);
            }
            Statement::BufferCopy { source, .. } => self.resolve_in_expr(source, variables),
            Statement::FileOpen { path, .. } => self.resolve_in_expr(path, variables),
            Statement::FileSeekLine { line, .. } => self.resolve_in_expr(line, variables),
            Statement::FileSeekByte { byte, .. } => self.resolve_in_expr(byte, variables),
            Statement::FileDelete { path }
            | Statement::Rmdir { path }
            | Statement::Mkdir { path }
            | Statement::Chdir { path } => self.resolve_in_expr(path, variables),
            Statement::BufferResize { new_size, .. } => self.resolve_in_expr(new_size, variables),
            Statement::Wait { duration, .. } => self.resolve_in_expr(duration, variables),
            Statement::Symlink { target, linkpath } => {
                self.resolve_in_expr(target, variables);
                self.resolve_in_expr(linkpath, variables);
            }
            Statement::Mknod { path, major, minor, .. } => {
                self.resolve_in_expr(path, variables);
                self.resolve_in_expr(major, variables);
                self.resolve_in_expr(minor, variables);
            }
            Statement::Mount { source, target, fstype, options } => {
                self.resolve_in_expr(source, variables);
                self.resolve_in_expr(target, variables);
                self.resolve_in_expr(fstype, variables);
                if let Some(options) = options {
                    self.resolve_in_expr(options, variables);
                }
            }
            Statement::Unmount { target, .. } => self.resolve_in_expr(target, variables),
            Statement::PivotRoot { new_root, put_old } => {
                self.resolve_in_expr(new_root, variables);
                self.resolve_in_expr(put_old, variables);
            }
            Statement::Execute { path, args } => {
                self.resolve_in_expr(path, variables);
                self.resolve_in_expr(args, variables);
            }
            Statement::SendSignal { signal, target } => {
                self.resolve_in_expr(signal, variables);
                if let SignalTarget::Process(pid) | SignalTarget::ProcessGroup(pid) = target {
                    self.resolve_in_expr(pid, variables);
                }
            }
            Statement::ThingDecl(_)
            | Statement::ParseFlags
            | Statement::ValueRetype { .. }
            | Statement::Break
            | Statement::Continue
            | Statement::Free { .. }
            | Statement::Increment { .. }
            | Statement::Decrement { .. }
            | Statement::BufferClear { .. }
            | Statement::FileRead { .. }
            | Statement::FileReadLine { .. }
            | Statement::FileWriteNewline { .. }
            | Statement::FileClose { .. }
            | Statement::LibraryDecl { .. }
            | Statement::See { .. }
            | Statement::TimerDecl { .. }
            | Statement::TimerStart { .. }
            | Statement::TimerStop { .. }
            | Statement::GetTime { .. }
            | Statement::Shutdown
            | Statement::Reboot
            | Statement::Halt => {}
        }
    }

    fn names_zero_argument_call(&self, name: &str, variables: &HashSet<String>) -> bool {
        !variables.contains(name) && self.is_zero_arg_function(name)
    }

    fn resolve_in_expr(&self, expr: &mut Expr, variables: &HashSet<String>) {
        match expr {
            Expr::Identifier(name) => {
                if self.names_zero_argument_call(name, variables) {
                    *expr = Expr::FunctionCall { name: name.clone(), args: Vec::new() };
                }
            }
            Expr::FormatString { parts } => {
                for part in parts.iter_mut() {
                    match part {
                        FormatPart::Variable { name, format } => {
                            if self.names_zero_argument_call(name, variables) {
                                *part = FormatPart::Expression {
                                    expr: Box::new(Expr::FunctionCall {
                                        name: name.clone(),
                                        args: Vec::new(),
                                    }),
                                    format: format.take(),
                                };
                            }
                        }
                        FormatPart::Expression { expr, .. } => self.resolve_in_expr(expr, variables),
                        FormatPart::Literal(_) => {}
                    }
                }
            }
            Expr::BinaryOp { left, right, .. } => {
                self.resolve_in_expr(left, variables);
                self.resolve_in_expr(right, variables);
            }
            Expr::UnaryOp { operand, .. } => self.resolve_in_expr(operand, variables),
            Expr::Range { start, end, .. } => {
                self.resolve_in_expr(start, variables);
                self.resolve_in_expr(end, variables);
            }
            Expr::PropertyCheck { value, .. }
            | Expr::TypeCheck { value, .. }
            | Expr::Cast { value, .. }
            | Expr::DurationCast { value, .. }
            | Expr::ArgumentHas { value } => self.resolve_in_expr(value, variables),
            Expr::FunctionCall { args, .. } => {
                for arg in args.iter_mut() {
                    self.resolve_in_expr(arg, variables);
                }
            }
            Expr::ListLit { elements } => {
                for element in elements.iter_mut() {
                    self.resolve_in_expr(element, variables);
                }
            }
            Expr::MapLit { pairs } => {
                for (key, value) in pairs.iter_mut() {
                    self.resolve_in_expr(key, variables);
                    self.resolve_in_expr(value, variables);
                }
            }
            Expr::ListAccess { list, index } | Expr::ElementAccess { list, index } => {
                self.resolve_in_expr(list, variables);
                self.resolve_in_expr(index, variables);
            }
            Expr::ByteAccess { buffer, index } => {
                self.resolve_in_expr(buffer, variables);
                self.resolve_in_expr(index, variables);
            }
            Expr::MapAccess { key, .. } => self.resolve_in_expr(key, variables),
            Expr::ArgumentAt { index } | Expr::EnvironmentVariableAt { index } => {
                self.resolve_in_expr(index, variables)
            }
            Expr::TreatingAs { value, match_value, replacement } => {
                self.resolve_in_expr(value, variables);
                self.resolve_in_expr(match_value, variables);
                self.resolve_in_expr(replacement, variables);
            }
            Expr::EnvironmentVariable { name } | Expr::EnvironmentVariableExists { name } => {
                self.resolve_in_expr(name, variables)
            }
            Expr::ReapChild { pid, .. } => {
                if let Some(pid) = pid {
                    self.resolve_in_expr(pid, variables);
                }
            }
            Expr::FileAvailable { path } => self.resolve_in_expr(path, variables),
            Expr::IntegerLit(_)
            | Expr::FloatLit(_)
            | Expr::StringLit(_)
            | Expr::BoolLit(_)
            | Expr::NothingLit
            | Expr::PropertyAccess { .. }
            | Expr::ThingField { .. }
            | Expr::LastError
            | Expr::ArgumentCount
            | Expr::ArgumentName
            | Expr::ArgumentFirst
            | Expr::ArgumentSecond
            | Expr::ArgumentLast
            | Expr::ArgumentEmpty
            | Expr::ArgumentAll
            | Expr::ArgumentRaw
            | Expr::EnvironmentVariableCount
            | Expr::EnvironmentVariableFirst
            | Expr::EnvironmentVariableLast
            | Expr::EnvironmentVariableEmpty
            | Expr::CurrentTime
            | Expr::Fork
            | Expr::ReapedStatus => {}
        }
    }
}

/// Every name these statements can declare as a variable, at any depth of
/// nested blocks, but not inside a function definition (its body is its own
/// scope). Over-collecting is safe: it only leaves a name as written.
fn collect_declared_names(stmts: &[Statement], out: &mut HashSet<String>) {
    for stmt in stmts {
        match stmt {
            Statement::VarDecl { name, .. }
            | Statement::FlagSchemaDecl { name, .. }
            | Statement::Assignment { name, .. }
            | Statement::ValueRetype { name, .. }
            | Statement::Allocate { name, .. }
            | Statement::BufferDecl { name, .. }
            | Statement::FileOpen { name, .. }
            | Statement::TimerDecl { name } => {
                out.insert(name.clone());
            }
            Statement::GetTime { into } => {
                out.insert(into.clone());
            }
            Statement::ForRange { variable, body, .. } | Statement::ForEach { variable, body, .. } => {
                out.insert(variable.clone());
                collect_declared_names(body, out);
            }
            Statement::If { then_block, else_if_blocks, else_block, .. } => {
                collect_declared_names(then_block, out);
                for (_, block) in else_if_blocks {
                    collect_declared_names(block, out);
                }
                if let Some(block) = else_block {
                    collect_declared_names(block, out);
                }
            }
            Statement::While { body, .. } | Statement::Repeat { body, .. } => {
                collect_declared_names(body, out)
            }
            Statement::OnError { actions } => collect_declared_names(actions, out),
            _ => {}
        }
    }
}
