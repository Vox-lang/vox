use crate::parser::ast::*;
use crate::errors::{CompileError, SourceFile, SourceLocation, find_similar_keyword, ENGLISH_KEYWORDS};
use std::collections::{HashMap, HashSet};

const FD_MAX: i64 = 2_147_483_647;

#[derive(Debug, Default)]
pub struct Dependencies {
    pub uses_io: bool,
    pub uses_heap: bool,
    pub uses_strings: bool,
    pub uses_args: bool,
    pub uses_funcs: bool,
}

#[cfg(test)]
mod buffer_append_copy_analysis_tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;

    fn analyze_input(input: &str) -> Analyzer {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        let mut program = parser.parse().expect("input should parse");
        let mut analyzer = Analyzer::new().with_source("test.en", input);
        analyzer.analyze(&mut program);
        analyzer
    }

    #[test]
    fn append_requires_buffer_source_when_destination_is_buffer() {
        let input = r#"
            a buffer called "dst" is "hello".
            a number called "n" is 7.
            append n to dst.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Buffer append requires")),
            "expected buffer-append type error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn copy_requires_buffers_for_both_operands() {
        let input = r#"
            a buffer called "dst" is "hello".
            a number called "n" is 7.
            copy n to dst.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Copy source must be a buffer")),
            "expected copy-source type error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn clear_requires_buffer_operand() {
        let input = r#"
            a number called "n" is 7.
            clear n.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Clear target must be a buffer")),
            "expected clear-target type error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn append_allows_format_string_when_destination_is_buffer() {
        let input = r#"
            a number called "n" is 7.
            a buffer called "dst" is "".
            append "N={n:04}" to dst.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Buffer append requires")),
            "unexpected buffer-append error(s): {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn copy_allows_format_string_source() {
        let input = r#"
            a number called "n" is 7.
            a buffer called "dst" is "".
            copy "N={n:04}" to dst.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Copy source must be a buffer") && !e.message.contains("Copy source must be a buffer or format/literal text")),
            "unexpected copy-source error(s): {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn file_open_rejects_float_path_literal() {
        let input = r#"
            open a file for reading called source at 1.5.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Open path must be either a text path")),
            "expected open-path type error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn file_open_rejects_boolean_path_literal() {
        let input = r#"
            open a file for reading called source at true.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Open path must be either a text path")),
            "expected open-path type error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn file_open_rejects_fd_literal_out_of_range() {
        let input = r#"
            open a file for reading called source at -1.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("File descriptor out of range")),
            "expected fd-range error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn file_open_accepts_string_path_and_fd_literal() {
        let input = r#"
            open a file for reading called source at "./data.txt".
            open a file for writing called output at 1.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Open path must be either a text path") && !e.message.contains("File descriptor out of range")),
            "unexpected open-path errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn treating_rejects_mismatched_match_and_replacement_types() {
        let input = r#"
            print each filename from arguments's all treating "-" as 0.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Treating match and replacement must be the same type")),
            "expected treating type mismatch error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn treating_allows_same_type_substitution() {
        let input = r#"
            print each filename from arguments's all treating "-" as "/dev/stdin".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Treating match and replacement must be the same type")),
            "unexpected treating type mismatch error(s): {:?}",
            analyzer.errors
        );
    }
}

#[cfg(test)]
mod guard_env_tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;

    fn analyze_input(input: &str) -> Analyzer {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        let mut program = parser.parse().expect("input should parse");
        let mut analyzer = Analyzer::new().with_source("test.en", input);
        analyzer.analyze(&mut program);
        analyzer
    }

    #[test]
    fn variable_declared_under_same_guard_is_available_under_same_guard_later() {
        let input = r#"
            if "number lines" then,
                a number called "line number" is 1.

            if "number lines" then,
                Print "{line number:6}".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown variable: line number")),
            "unexpected unknown-variable errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn variable_declared_under_different_guard_is_not_available() {
        let input = r#"
            if "number lines" then,
                a number called "line number" is 1.

            if "verbose" then,
                Print "{line number:6}".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Unknown variable: line number")),
            "expected unknown-variable error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn guarded_variable_is_available_in_nested_while_for_repeat_blocks() {
        let input = r#"
            if "number lines" then,
                a number called "line number" is 1.

            if "number lines" then,
                while true,
                    for each item in arguments's all,
                        repeat 1 times,
                            Print "{line number:6}".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown variable: line number")),
            "unexpected unknown-variable errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn variable_declared_under_same_and_condition_is_available() {
        let input = r#"
            if "number lines" and "verbose" then,
                a number called "line number" is 1.

            if "number lines" and "verbose" then,
                Print "{line number:6}".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown variable: line number")),
            "unexpected unknown-variable errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn variable_declared_under_same_not_condition_is_available() {
        let input = r#"
            if not "number lines" then,
                a number called "line number" is 1.

            if not "number lines" then,
                Print "{line number:6}".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown variable: line number")),
            "unexpected unknown-variable errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn unknown_variable_inside_function_is_reported() {
        let input = r#"
            To "show",
                Print "{missing}".

            "show".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Unknown variable: missing")),
            "expected unknown-variable error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn top_level_global_variable_is_available_inside_function() {
        let input = r#"
            A text called "Program Version" is "0.1.3".

            To "show",
                Print "{Program Version}".

            "show".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown variable: Program Version")),
            "unexpected unknown-variable errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn function_local_variable_is_not_available_at_top_level() {
        let input = r#"
            To "make",
                a number called "temp" is 1.

            Print "{temp}".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Unknown variable: temp") || e.message.contains("Unknown identifier 'temp'")),
            "expected unknown-variable error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn branch_local_identifier_named_like_keyword_is_not_false_positive() {
        let input = r#"
            If arguments's count is greater than 1 then,
                a text called "arg1" is arguments's first,
                Print the arg1.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown identifier 'arg1'") && !e.message.contains("Unknown variable: arg1")),
            "unexpected arg1 errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn flag_schema_after_non_schema_code_is_allowed() {
        let input = r#"
            Print "hello".
            a flag called "verbose" is "-v" or "--verbose", it is a boolean.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer.errors.is_empty(),
            "expected no errors for schema after non-schema code, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn flag_schema_after_explicit_parse_is_rejected() {
        let input = r#"
            a flag called "verbose" is "-v" or "--verbose", it is a boolean.
            parse flags.
            a flag called "debug" is "-d" or "--debug", it is a boolean.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Cannot declare new flags after 'parse flags.'")),
            "expected post-parse schema error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn duplicate_parse_flags_statement_is_rejected() {
        let input = r#"
            a flag called "verbose" is "-v" or "--verbose", it is a boolean.
            parse flags.
            parse flags.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Duplicate 'parse flags.' statement")),
            "expected duplicate-parse error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn flag_usage_before_explicit_parse_is_rejected() {
        let input = r#"
            a flag called "verbose" is "-v" or "--verbose", it is a boolean.
            Print "{verbose}".
            parse flags.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Flag variable 'verbose' is used before flags are parsed")),
            "expected pre-parse usage error, got: {:?}",
            analyzer.errors
        );
    }
}

pub struct Analyzer {
    pub deps: Dependencies,
    pub variables: HashSet<String>,
    pub functions: HashSet<String>,
    pub used_identifiers: HashSet<String>,  // Track all identifiers seen
    typo_candidates: HashSet<String>,
    pub errors: Vec<CompileError>,
    source_file: Option<SourceFile>,
    guarded_scopes: HashMap<String, HashSet<String>>,
    symbol_error_counts: HashMap<String, usize>,
    active_guards: Vec<String>,
    block_depth: usize,
    global_variables: HashSet<String>,
    flag_variables: HashSet<String>,
    buffer_variables: HashSet<String>,
    list_variables: HashSet<String>,
}

#[derive(Clone, Default)]
struct AnalysisEnv {
    always: HashSet<String>,
    guarded: HashMap<String, HashSet<String>>,
}

impl Analyzer {
    pub fn new() -> Self {
        Analyzer {
            deps: Dependencies::default(),
            variables: HashSet::new(),
            functions: HashSet::new(),
            used_identifiers: HashSet::new(),
            typo_candidates: HashSet::new(),
            errors: Vec::new(),
            source_file: None,
            guarded_scopes: HashMap::new(),
            symbol_error_counts: HashMap::new(),
            active_guards: Vec::new(),
            block_depth: 0,
            global_variables: HashSet::new(),
            flag_variables: HashSet::new(),
            buffer_variables: HashSet::new(),
            list_variables: HashSet::new(),
        }
    }

    pub fn with_source(mut self, filename: &str, content: &str) -> Self {
        self.source_file = Some(SourceFile::new(filename, content));
        self
    }
    
    pub fn analyze(&mut self, program: &mut Program) {
        // First pass: collect function definitions, global declarations, and flag schemas.
        let mut explicit_parse_seen = false;

        for stmt in &program.statements {
            match stmt {
                Statement::FunctionDef { name, .. } => {
                    self.functions.insert(name.clone());
                }
                Statement::VarDecl { name, var_type, .. } => {
                    self.global_variables.insert(name.clone());
                    if let Some(Type::Buffer) = var_type {
                        self.buffer_variables.insert(name.clone());
                    }
                    if let Some(Type::List(_)) = var_type {
                        self.list_variables.insert(name.clone());
                    }
                }
                Statement::BufferDecl { name, .. } => {
                    self.global_variables.insert(name.clone());
                    self.buffer_variables.insert(name.clone());
                }
                Statement::Allocate { name, .. }
                | Statement::TimerDecl { name }
                | Statement::FileOpen { name, .. } => {
                    self.global_variables.insert(name.clone());
                }
                Statement::GetTime { into } => {
                    self.global_variables.insert(into.clone());
                }
                Statement::FlagSchemaDecl { name, .. } => {
                    self.flag_variables.insert(name.clone());
                    self.global_variables.insert(name.clone());
                    if explicit_parse_seen {
                        self.push_error(
                            "Cannot declare new flags after 'parse flags.'".to_string(),
                            Some(name),
                        );
                    }
                }
                Statement::ParseFlags => {
                    if explicit_parse_seen {
                        self.push_error("Duplicate 'parse flags.' statement".to_string(), None);
                    }
                    explicit_parse_seen = true;
                }
                _ => {}
            }
        }

        let parse_point = if explicit_parse_seen {
            program
                .statements
                .iter()
                .position(|s| matches!(s, Statement::ParseFlags))
                .map(|i| i + 1)
                .unwrap_or(0)
        } else {
            program
                .statements
                .iter()
                .rposition(|s| matches!(s, Statement::FlagSchemaDecl { .. }))
                .map(|i| i + 1)
                .unwrap_or(0)
        };

        for stmt in program.statements.iter().take(parse_point) {
            if matches!(stmt, Statement::FlagSchemaDecl { .. } | Statement::ParseFlags) {
                continue;
            }
            if let Some(flag_name) = self.statement_uses_flag(stmt) {
                self.push_error(
                    format!("Flag variable '{}' is used before flags are parsed", flag_name),
                    Some(&flag_name),
                );
            }
        }

        self.variables = self.global_variables.clone();
        
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
        let unknown: Vec<String> = self.typo_candidates.iter().cloned().collect();
        let mut typo_errors = Vec::new();

        for id in unknown {
            // Skip if this identifier already has an error
            if self.errors.iter().any(|e| e.message.contains(&id)) {
                continue;
            }

            // Skip common internal identifiers
            if id.starts_with('_') || id == "stdin" || id == "stdout" || id == "stderr" {
                continue;
            }
            
            if let Some(suggestion) = find_similar_keyword(&id, ENGLISH_KEYWORDS) {
                let mut err = CompileError::new(&format!("Unknown identifier '{}'", id))
                    .with_suggestion(&suggestion);
                if let Some(loc) = self.find_symbol_location(&id, 0) {
                    err = err.with_location(loc);
                }
                typo_errors.push(err);
            }
        }
        
        // Prepend typo errors so they appear first
        typo_errors.append(&mut self.errors);
        self.errors = typo_errors;
    }
    
    fn track_identifier(&mut self, name: &str) {
        self.used_identifiers.insert(name.to_string());
    }

    fn track_typo_candidate(&mut self, name: &str) {
        self.typo_candidates.insert(name.to_string());
    }

    fn expr_uses_flag(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Identifier(name) => {
                if self.flag_variables.contains(name) {
                    Some(name.clone())
                } else {
                    None
                }
            }
            Expr::FormatString { parts } => {
                for part in parts {
                    match part {
                        FormatPart::Variable { name, .. } => {
                            if self.flag_variables.contains(name) {
                                return Some(name.clone());
                            }
                        }
                        FormatPart::Expression { expr, .. } => {
                            if let Some(name) = self.expr_uses_flag(expr) {
                                return Some(name);
                            }
                        }
                        FormatPart::Literal(_) => {}
                    }
                }
                None
            }
            Expr::BinaryOp { left, right, .. } => self.expr_uses_flag(left).or_else(|| self.expr_uses_flag(right)),
            Expr::UnaryOp { operand, .. } => self.expr_uses_flag(operand),
            Expr::Range { start, end, .. } => self.expr_uses_flag(start).or_else(|| self.expr_uses_flag(end)),
            Expr::PropertyCheck { value, .. } => self.expr_uses_flag(value),
            Expr::FunctionCall { args, .. } => args.iter().find_map(|a| self.expr_uses_flag(a)),
            Expr::ListLit { elements } => elements.iter().find_map(|e| self.expr_uses_flag(e)),
            Expr::ListAccess { list, index } => self.expr_uses_flag(list).or_else(|| self.expr_uses_flag(index)),
            Expr::ByteAccess { buffer, index } => self.expr_uses_flag(buffer).or_else(|| self.expr_uses_flag(index)),
            Expr::ElementAccess { list, index } => self.expr_uses_flag(list).or_else(|| self.expr_uses_flag(index)),
            Expr::Cast { value, .. } => self.expr_uses_flag(value),
            Expr::DurationCast { value, .. } => self.expr_uses_flag(value),
            Expr::TreatingAs { value, match_value, replacement } => self
                .expr_uses_flag(value)
                .or_else(|| self.expr_uses_flag(match_value))
                .or_else(|| self.expr_uses_flag(replacement)),
            Expr::ArgumentAt { index } => self.expr_uses_flag(index),
            Expr::EnvironmentVariable { name } => self.expr_uses_flag(name),
            Expr::EnvironmentVariableAt { index } => self.expr_uses_flag(index),
            Expr::EnvironmentVariableExists { name } => self.expr_uses_flag(name),
            _ => None,
        }
    }

    fn statement_uses_flag(&self, stmt: &Statement) -> Option<String> {
        match stmt {
            Statement::Print { value, .. } => self.expr_uses_flag(value),
            Statement::VarDecl { value, .. } => value.as_ref().and_then(|v| self.expr_uses_flag(v)),
            Statement::Assignment { value, .. } => self.expr_uses_flag(value),
            Statement::If { condition, then_block, else_if_blocks, else_block } => {
                self.expr_uses_flag(condition)
                    .or_else(|| then_block.iter().find_map(|s| self.statement_uses_flag(s)))
                    .or_else(|| else_if_blocks.iter().find_map(|(c, b)| self.expr_uses_flag(c).or_else(|| b.iter().find_map(|s| self.statement_uses_flag(s)))))
                    .or_else(|| else_block.as_ref().and_then(|b| b.iter().find_map(|s| self.statement_uses_flag(s))))
            }
            Statement::While { condition, body } => self
                .expr_uses_flag(condition)
                .or_else(|| body.iter().find_map(|s| self.statement_uses_flag(s))),
            Statement::ForRange { range, body, .. } => self
                .expr_uses_flag(range)
                .or_else(|| body.iter().find_map(|s| self.statement_uses_flag(s))),
            Statement::ForEach { collection, body, .. } => self
                .expr_uses_flag(collection)
                .or_else(|| body.iter().find_map(|s| self.statement_uses_flag(s))),
            Statement::Repeat { count, body } => self
                .expr_uses_flag(count)
                .or_else(|| body.iter().find_map(|s| self.statement_uses_flag(s))),
            Statement::Return { value } => value.as_ref().and_then(|v| self.expr_uses_flag(v)),
            Statement::Exit { code } => self.expr_uses_flag(code),
            Statement::Allocate { size, .. } => self.expr_uses_flag(size),
            Statement::ByteSet { index, value, .. } => self.expr_uses_flag(index).or_else(|| self.expr_uses_flag(value)),
            Statement::ElementSet { index, value, .. } => self.expr_uses_flag(index).or_else(|| self.expr_uses_flag(value)),
            Statement::ListAppend { value, .. } => self.expr_uses_flag(value),
            Statement::FileOpen { path, .. } => self.expr_uses_flag(path),
            Statement::FileWrite { value, .. } => self.expr_uses_flag(value),
            Statement::OnError { actions } => actions.iter().find_map(|a| self.statement_uses_flag(a)),
            Statement::BufferResize { new_size, .. } => self.expr_uses_flag(new_size),
            Statement::FunctionCall { args, .. } => args.iter().find_map(|a| self.expr_uses_flag(a)),
            Statement::Wait { duration, .. } => self.expr_uses_flag(duration),
            _ => None,
        }
    }

    fn find_symbol_location(&self, symbol: &str, occurrence: usize) -> Option<SourceLocation> {
        let source = self.source_file.as_ref()?;
        let preferred_patterns = [
            format!("{{{}", symbol),
            format!("\"{}\"", symbol),
            symbol.to_string(),
        ];

        for pattern in preferred_patterns {
            let mut seen = 0usize;
            for (idx, line) in source.content.lines().enumerate() {
                if let Some(column) = line.find(&pattern) {
                    if seen == occurrence {
                        return Some(SourceLocation::new(
                            &source.filename,
                            idx + 1,
                            column + 1,
                            line,
                        ));
                    }
                    seen += 1;
                }
            }
        }

        None
    }

    fn push_error(&mut self, message: String, symbol: Option<&str>) {
        let mut err = CompileError::new(&message);
        if let Some(name) = symbol {
            let occurrence = *self.symbol_error_counts.get(name).unwrap_or(&0);
            if let Some(loc) = self.find_symbol_location(name, occurrence) {
                err = err.with_location(loc);
            }
            self.symbol_error_counts.insert(name.to_string(), occurrence + 1);
        }
        self.errors.push(err);
    }

    fn push_unknown_variable(&mut self, name: &str) {
        self.push_error(format!("Unknown variable: {}", name), Some(name));
    }

    fn current_env(&self) -> AnalysisEnv {
        AnalysisEnv {
            always: self.variables.clone(),
            guarded: self.guarded_scopes.clone(),
        }
    }

    fn apply_env(&mut self, env: &AnalysisEnv) {
        self.variables = env.always.clone();
        self.guarded_scopes = env.guarded.clone();
    }

    fn is_variable_available(&self, name: &str) -> bool {
        if self.variables.contains(name) {
            return true;
        }

        self.active_guards.iter().any(|guard| {
            self.guarded_scopes
                .get(guard)
                .map(|vars| vars.contains(name))
                .unwrap_or(false)
        })
    }

    fn declare_variable_in_current_scope(&mut self, name: &str) {
        if self.active_guards.is_empty() {
            self.variables.insert(name.to_string());
        } else {
            for guard in &self.active_guards {
                self.guarded_scopes
                    .entry(guard.clone())
                    .or_default()
                    .insert(name.to_string());
            }
        }
    }

    fn merge_continuing_envs(&self, envs: &[AnalysisEnv], fallback: &AnalysisEnv) -> AnalysisEnv {
        if envs.is_empty() {
            return fallback.clone();
        }

        let mut merged_always = envs[0].always.clone();
        for env in envs.iter().skip(1) {
            merged_always.retain(|name| env.always.contains(name));
        }

        let mut merged_guarded: HashMap<String, HashSet<String>> = HashMap::new();
        for env in envs {
            for (guard, vars) in &env.guarded {
                merged_guarded
                    .entry(guard.clone())
                    .or_default()
                    .extend(vars.iter().cloned());
            }
        }

        AnalysisEnv {
            always: merged_always,
            guarded: merged_guarded,
        }
    }

    fn simple_guard_key(condition: &Expr) -> Option<String> {
        match condition {
            Expr::Identifier(name) => Some(name.clone()),
            Expr::StringLit(name) => Some(name.clone()),
            Expr::UnaryOp { op: UnaryOperator::Not, operand } => {
                Self::simple_guard_key(operand).map(|k| format!("not ({})", k))
            }
            Expr::BinaryOp { left, op, right } => {
                let connector = match op {
                    BinaryOperator::And => "and",
                    BinaryOperator::Or => "or",
                    _ => return None,
                };
                let left_key = Self::simple_guard_key(left)?;
                let right_key = Self::simple_guard_key(right)?;
                Some(format!("({}) {} ({})", left_key, connector, right_key))
            }
            _ => None,
        }
    }

    fn maybe_activate_true_guard(&mut self, name: &str, var_type: &Option<Type>, value: &Option<Expr>) {
        if self.block_depth == 0 {
            return;
        }

        let is_bool_typed = var_type
            .as_ref()
            .map(|t| matches!(t, Type::Boolean))
            .unwrap_or(true);
        let is_true = matches!(value, Some(Expr::BoolLit(true)));

        if is_bool_typed && is_true {
            if !self.active_guards.iter().any(|g| g == name) {
                self.active_guards.push(name.to_string());
            }
            self.guarded_scopes
                .entry(name.to_string())
                .or_default()
                .insert(name.to_string());
        }
    }

    fn analyze_block_in_scope(&mut self, block: &[Statement], input_env: &AnalysisEnv, active_guard: Option<&str>) -> (AnalysisEnv, bool) {
        let saved_env = self.current_env();
        let saved_guards = self.active_guards.clone();
        let saved_block_depth = self.block_depth;
        self.apply_env(input_env);
        self.block_depth += 1;
        if let Some(guard) = active_guard {
            self.active_guards.push(guard.to_string());
        }

        let mut terminates = false;
        for stmt in block {
            self.analyze_statement(stmt);
            if self.statement_always_terminates(stmt) {
                terminates = true;
                break;
            }
        }
        let resulting_env = self.current_env();
        self.block_depth = saved_block_depth;
        self.active_guards = saved_guards;
        self.apply_env(&saved_env);
        (resulting_env, terminates)
    }

    fn block_always_terminates(&self, block: &[Statement]) -> bool {
        for stmt in block {
            if self.statement_always_terminates(stmt) {
                return true;
            }
        }
        false
    }

    fn is_buffer_variable(&self, name: &str) -> bool {
        self.buffer_variables.contains(name)
    }

    fn is_list_variable(&self, name: &str) -> bool {
        self.list_variables.contains(name)
    }

    fn expr_integer_literal_value(&self, expr: &Expr) -> Option<i64> {
        match expr {
            Expr::IntegerLit(v) => Some(*v),
            Expr::UnaryOp { op: UnaryOperator::Negate, operand } => {
                match operand.as_ref() {
                    Expr::IntegerLit(v) => Some(-*v),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn infer_simple_expr_type(&self, expr: &Expr) -> Option<Type> {
        match expr {
            Expr::IntegerLit(_) | Expr::LastError | Expr::ArgumentCount | Expr::EnvironmentVariableCount => Some(Type::Integer),
            Expr::FloatLit(_) => Some(Type::Float),
            Expr::StringLit(_) | Expr::FormatString { .. }
            | Expr::ArgumentName | Expr::ArgumentFirst | Expr::ArgumentSecond | Expr::ArgumentLast
            | Expr::ArgumentAt { .. } | Expr::EnvironmentVariable { .. }
            | Expr::EnvironmentVariableFirst | Expr::EnvironmentVariableLast
            | Expr::EnvironmentVariableAt { .. } => Some(Type::String),
            Expr::BoolLit(_) | Expr::ArgumentEmpty | Expr::EnvironmentVariableEmpty | Expr::EnvironmentVariableExists { .. }
            | Expr::PropertyCheck { .. } => Some(Type::Boolean),
            Expr::ListLit { .. } | Expr::ArgumentAll | Expr::ArgumentRaw => Some(Type::List(Box::new(Type::Unknown))),
            Expr::Identifier(name) => {
                if self.is_buffer_variable(name) {
                    Some(Type::Buffer)
                } else if self.is_list_variable(name) {
                    Some(Type::List(Box::new(Type::Unknown)))
                } else if self.flag_variables.contains(name) {
                    Some(Type::Boolean)
                } else {
                    None
                }
            }
            Expr::BinaryOp { op, left, right } => {
                match op {
                    BinaryOperator::Equal | BinaryOperator::NotEqual
                    | BinaryOperator::Greater | BinaryOperator::Less
                    | BinaryOperator::GreaterEqual | BinaryOperator::LessEqual
                    | BinaryOperator::And | BinaryOperator::Or => Some(Type::Boolean),
                    _ => {
                        let left_ty = self.infer_simple_expr_type(left);
                        let right_ty = self.infer_simple_expr_type(right);
                        if matches!(left_ty, Some(Type::Float)) || matches!(right_ty, Some(Type::Float)) {
                            Some(Type::Float)
                        } else if matches!(left_ty, Some(Type::Integer)) && matches!(right_ty, Some(Type::Integer)) {
                            Some(Type::Integer)
                        } else {
                            None
                        }
                    }
                }
            }
            Expr::UnaryOp { op, operand } => {
                match op {
                    UnaryOperator::Negate => self.infer_simple_expr_type(operand),
                    UnaryOperator::Not => Some(Type::Boolean),
                }
            }
            Expr::Cast { target_type, .. } => Some(target_type.clone()),
            Expr::DurationCast { .. } => Some(Type::Integer),
            Expr::TreatingAs { value, .. } => self.infer_simple_expr_type(value),
            _ => None,
        }
    }

    fn treating_types_compatible(&self, left: &Type, right: &Type) -> bool {
        match (left, right) {
            (Type::Integer, Type::Integer)
            | (Type::Float, Type::Float)
            | (Type::String, Type::String)
            | (Type::Boolean, Type::Boolean)
            | (Type::Buffer, Type::Buffer)
            | (Type::File, Type::File)
            | (Type::Time, Type::Time)
            | (Type::Timer, Type::Timer) => true,
            (Type::List(_), Type::List(_)) => true,
            _ => false,
        }
    }

    fn type_name(&self, ty: &Type) -> &'static str {
        match ty {
            Type::Integer => "number",
            Type::Float => "float",
            Type::String => "text",
            Type::Boolean => "boolean",
            Type::List(_) => "list",
            Type::Buffer => "buffer",
            Type::File => "file",
            Type::Time => "time",
            Type::Timer => "timer",
            Type::Void => "void",
            Type::Unknown => "unknown",
        }
    }

    fn validate_treating_expr(&mut self, value: &Expr, match_value: &Expr, replacement: &Expr) {
        if let (Some(match_ty), Some(replacement_ty)) = (
            self.infer_simple_expr_type(match_value),
            self.infer_simple_expr_type(replacement),
        ) {
            if !self.treating_types_compatible(&match_ty, &replacement_ty) {
                self.push_error(
                    format!(
                        "Treating match and replacement must be the same type (got {} vs {}).",
                        self.type_name(&match_ty),
                        self.type_name(&replacement_ty)
                    ),
                    None,
                );
            }
        }

        if let (Some(value_ty), Some(match_ty)) = (
            self.infer_simple_expr_type(value),
            self.infer_simple_expr_type(match_value),
        ) {
            if !self.treating_types_compatible(&value_ty, &match_ty) {
                self.push_error(
                    format!(
                        "Treating value and match must be the same type (got {} vs {}).",
                        self.type_name(&value_ty),
                        self.type_name(&match_ty)
                    ),
                    None,
                );
            }
        }
    }

    fn validate_file_open_path(&mut self, path: &Expr) {
        const OPEN_PATH_GUIDANCE: &str = "Open path must be either a text path like \"/path/to/file\" or a file descriptor number (0 = stdin, 1 = stdout, 2 = stderr).";

        if let Some(fd) = self.expr_integer_literal_value(path) {
            if fd < 0 || fd > FD_MAX {
                self.push_error(
                    format!(
                        "File descriptor out of range after 'at': {}. Valid range is 0..{} (0 = stdin).",
                        fd, FD_MAX
                    ),
                    None,
                );
            }
            return;
        }

        match path {
            Expr::StringLit(_) | Expr::FormatString { .. } => {}
            Expr::Identifier(name) => {
                if self.is_buffer_variable(name) || self.is_list_variable(name) {
                    self.push_error(OPEN_PATH_GUIDANCE.to_string(), Some(name));
                }
            }
            Expr::FloatLit(_)
            | Expr::BoolLit(_)
            | Expr::ListLit { .. }
            | Expr::Range { .. }
            | Expr::PropertyCheck { .. } => {
                self.push_error(OPEN_PATH_GUIDANCE.to_string(), None);
            }
            Expr::Cast { target_type, .. } => {
                if !matches!(target_type, Type::Integer | Type::String) {
                    self.push_error(OPEN_PATH_GUIDANCE.to_string(), None);
                }
            }
            _ => {}
        }
    }

    fn statement_always_terminates(&self, stmt: &Statement) -> bool {
        match stmt {
            Statement::Return { .. } | Statement::Exit { .. } => true,
            Statement::If { then_block, else_if_blocks, else_block, .. } => {
                if !self.block_always_terminates(then_block) {
                    return false;
                }
                for (_, block) in else_if_blocks {
                    if !self.block_always_terminates(block) {
                        return false;
                    }
                }
                if let Some(block) = else_block {
                    self.block_always_terminates(block)
                } else {
                    false
                }
            }
            _ => false,
        }
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
            
            Statement::VarDecl { name, var_type, value } => {
                self.declare_variable_in_current_scope(name);
                self.maybe_activate_true_guard(name, var_type, value);
                if let Some(v) = value {
                    self.analyze_expr(v);
                }
            }

            Statement::FlagSchemaDecl { name, default, .. } => {
                self.deps.uses_args = true;
                self.declare_variable_in_current_scope(name);
                if let Some(v) = default {
                    self.analyze_expr(v);
                }
            }

            Statement::ParseFlags => {
                self.deps.uses_args = true;
            }
            
            Statement::Assignment { name, value } => {
                if !self.is_variable_available(name) {
                    self.declare_variable_in_current_scope(name);
                }

                if matches!(value, Expr::FormatString { .. })
                    && self.is_variable_available(name)
                    && !self.is_buffer_variable(name)
                {
                    self.push_error(
                        format!("Format-string assignment requires a buffer destination: {}", name),
                        Some(name),
                    );
                }

                self.analyze_expr(value);
            }
            
            Statement::If { condition, then_block, else_if_blocks, else_block } => {
                self.analyze_expr(condition);

                // Branches are analyzed with the same incoming scope.
                // Declarations inside one branch do not become visible in sibling
                // branches. After the if-statement, only variables that are
                // definitely available on all continuing paths remain visible.
                let branch_env = self.current_env();
                let mut continuing_envs: Vec<AnalysisEnv> = Vec::new();

                let guard_key = Self::simple_guard_key(condition);
                let (then_env, then_terminates) = self.analyze_block_in_scope(
                    then_block,
                    &branch_env,
                    guard_key.as_deref(),
                );
                if !then_terminates {
                    continuing_envs.push(then_env);
                }

                for (cond, block) in else_if_blocks {
                    let saved_env = self.current_env();
                    self.apply_env(&branch_env);
                    self.analyze_expr(cond);
                    self.apply_env(&saved_env);
                    let (elif_env, elif_terminates) = self.analyze_block_in_scope(block, &branch_env, None);
                    if !elif_terminates {
                        continuing_envs.push(elif_env);
                    }
                }

                if let Some(block) = else_block {
                    let (else_env, else_terminates) = self.analyze_block_in_scope(block, &branch_env, None);
                    if !else_terminates {
                        continuing_envs.push(else_env);
                    }
                } else {
                    // No else means the original incoming scope can continue unchanged.
                    continuing_envs.push(branch_env.clone());
                }

                let merged_env = self.merge_continuing_envs(&continuing_envs, &branch_env);
                self.apply_env(&merged_env);
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
                if !self.is_variable_available(name) {
                    self.push_error(format!("Freeing unknown variable: {}", name), Some(name));
                }
            }
            
            Statement::FunctionCall { name, args } => {
                self.deps.uses_funcs = true; // Track that functions are used
                if !self.functions.contains(name) {
                    let mut err = format!("Unknown function: {}", name);
                    if let Some(suggestion) = find_similar_keyword(name, ENGLISH_KEYWORDS) {
                        err.push_str(&format!(" (did you mean '{}'?)", suggestion));
                    }
                    self.push_error(err, Some(name));
                }
                for arg in args {
                    self.analyze_expr(arg);
                }
            }
            
            Statement::FunctionDef { name, params, body, .. } => {
                self.functions.insert(name.clone());
                self.deps.uses_funcs = true; // Track that functions are used

                // Functions can access top-level globals, but locals declared inside
                // the function must not leak back into top-level scope.
                let saved_env = self.current_env();
                let saved_guards = self.active_guards.clone();
                let saved_block_depth = self.block_depth;
                self.variables = self.global_variables.clone();
                self.guarded_scopes.clear();
                self.active_guards.clear();
                self.block_depth = 0;

                // Add function parameters to function scope.
                for (param_name, _) in params {
                    self.variables.insert(param_name.clone());
                }
                for s in body {
                    self.analyze_statement(s);
                }

                self.block_depth = saved_block_depth;
                self.active_guards = saved_guards;
                self.apply_env(&saved_env);
            }
            
            Statement::Increment { name } | Statement::Decrement { name } => {
                if !self.is_variable_available(name) {
                    self.push_unknown_variable(name);
                }
            }
            
            Statement::Break | Statement::Continue => {}
            
            // File I/O statements
            Statement::BufferDecl { name, size } => {
                self.variables.insert(name.clone());
                self.buffer_variables.insert(name.clone());
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

                if self.is_buffer_variable(list) {
                    match value {
                        Expr::Identifier(source) => {
                            if !self.is_variable_available(source) {
                                self.push_error(format!("Unknown buffer: {}", source), Some(source));
                            } else if !self.is_buffer_variable(source) {
                                self.push_error(
                                    format!("Buffer append requires a buffer source: {}", source),
                                    Some(source),
                                );
                            }
                        }
                        Expr::StringLit(_) | Expr::FormatString { .. } => {
                            // Allowed: append text/format output into destination buffer.
                        }
                        _ => {
                            self.push_error(
                                "Buffer append requires a buffer source or format/literal text".to_string(),
                                Some(list),
                            );
                        }
                    }
                } else if self.is_list_variable(list) {
                    // Valid list append path.
                }
            }

            Statement::BufferCopy { source, destination } => {
                if let Expr::Identifier(source_name) = source {
                    self.track_identifier(source_name);
                }
                self.track_identifier(destination);

                self.analyze_expr(source);

                match source {
                    Expr::Identifier(source_name) => {
                        if !self.is_variable_available(source_name) {
                            self.push_error(format!("Unknown buffer: {}", source_name), Some(source_name));
                        } else if !self.is_buffer_variable(source_name) {
                            self.push_error(
                                format!("Copy source must be a buffer: {}", source_name),
                                Some(source_name),
                            );
                        }
                    }
                    Expr::StringLit(_) | Expr::FormatString { .. } => {
                        // Allowed: copy literal/format output into destination buffer.
                    }
                    _ => {
                        self.push_error(
                            "Copy source must be a buffer or format/literal text".to_string(),
                            Some(destination),
                        );
                    }
                }

                if !self.is_variable_available(destination) {
                    self.push_error(format!("Unknown buffer: {}", destination), Some(destination));
                } else if !self.is_buffer_variable(destination) {
                    self.push_error(
                        format!("Copy destination must be a buffer: {}", destination),
                        Some(destination),
                    );
                }
            }

            Statement::BufferClear { name } => {
                self.track_identifier(name);

                if !self.is_variable_available(name) {
                    self.push_error(format!("Unknown buffer: {}", name), Some(name));
                } else if !self.is_buffer_variable(name) {
                    self.push_error(
                        format!("Clear target must be a buffer: {}", name),
                        Some(name),
                    );
                }
            }
            
            Statement::FileOpen { name, path, .. } => {
                self.variables.insert(name.clone());
                self.analyze_expr(path);
                self.validate_file_open_path(path);
                self.deps.uses_io = true;
            }
            
            Statement::FileRead { buffer, .. } => {
                if !self.is_variable_available(buffer) {
                    self.push_error(format!("Unknown buffer: {}", buffer), Some(buffer));
                }
                self.deps.uses_io = true;
            }

            Statement::FileReadLine { buffer, .. } => {
                if !self.is_variable_available(buffer) {
                    self.push_error(format!("Unknown buffer: {}", buffer), Some(buffer));
                }
                self.deps.uses_io = true;
            }

            Statement::FileSeekLine { file, line } => {
                if !self.is_variable_available(file) {
                    self.push_error(format!("Unknown file: {}", file), Some(file));
                }
                self.analyze_expr(line);
                self.deps.uses_io = true;
            }

            Statement::FileSeekByte { file, byte } => {
                if !self.is_variable_available(file) {
                    self.push_error(format!("Unknown file: {}", file), Some(file));
                }
                self.analyze_expr(byte);
                self.deps.uses_io = true;
            }
            
            Statement::FileWrite { file, value } => {
                if !self.is_variable_available(file) {
                    self.push_error(format!("Unknown file: {}", file), Some(file));
                }
                self.analyze_expr(value);
                self.deps.uses_io = true;
            }
            
            Statement::FileWriteNewline { file } => {
                if !self.is_variable_available(file) {
                    self.push_error(format!("Unknown file: {}", file), Some(file));
                }
                self.deps.uses_io = true;
            }
            
            Statement::FileClose { file } => {
                if !self.is_variable_available(file) {
                    self.push_error(format!("Unknown file: {}", file), Some(file));
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
                if !self.is_variable_available(name) {
                    self.push_error(format!("Unknown buffer: {}", name), Some(name));
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
                if !self.is_variable_available(name) {
                    self.push_error(format!("Unknown timer: {}", name), Some(name));
                }
            }
            
            Statement::TimerStop { name } => {
                if !self.is_variable_available(name) {
                    self.push_error(format!("Unknown timer: {}", name), Some(name));
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
                    self.push_error(err, Some(name));
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
                            if !self.is_variable_available(name) && name != "_iter" {
                                if find_similar_keyword(name, ENGLISH_KEYWORDS).is_none() {
                                    self.push_unknown_variable(name);
                                } else {
                                    self.track_typo_candidate(name);
                                }
                            }
                        }
                        FormatPart::Literal(_) => {}
                    }
                }
            }
            
            Expr::Identifier(name) => {
                self.track_identifier(name);
                if !self.is_variable_available(name) && name != "_iter" {
                    // Don't report as unknown variable if it might be a keyword typo
                    // (that will be caught by check_for_typos)
                    if find_similar_keyword(name, ENGLISH_KEYWORDS).is_none() {
                        self.push_unknown_variable(name);
                    } else {
                        self.track_typo_candidate(name);
                    }
                }
            }
            
            // Argument and environment variable expressions
            Expr::ArgumentCount | Expr::ArgumentName | Expr::ArgumentFirst | 
            Expr::ArgumentSecond | Expr::ArgumentLast | Expr::ArgumentEmpty |
            Expr::ArgumentAll | Expr::ArgumentRaw => {
                self.deps.uses_args = true;
            }

            Expr::ArgumentHas { value } => {
                self.deps.uses_args = true;
                self.deps.uses_strings = true;
                self.analyze_expr(value);
            }
            
            Expr::TreatingAs { value, match_value, replacement } => {
                self.analyze_expr(value);
                self.analyze_expr(match_value);
                self.analyze_expr(replacement);
                self.validate_treating_expr(value, match_value, replacement);
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

