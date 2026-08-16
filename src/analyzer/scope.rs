use super::*;

impl Analyzer {
    pub(crate) fn check_for_typos(&mut self) {
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

    pub(crate) fn track_identifier(&mut self, name: &str) {
        self.used_identifiers.insert(name.to_string());
    }

    pub(crate) fn track_typo_candidate(&mut self, name: &str) {
        self.typo_candidates.insert(name.to_string());
    }

    pub(crate) fn find_pattern_location(
        &self,
        symbol: &str,
        patterns: &[String],
        occurrence: usize,
        exclude_line: Option<usize>,
        guard_against_called: bool,
    ) -> Option<SourceLocation> {
        let source = self.source_file.as_ref()?;
        for pattern in patterns {
            let Some(name_offset) = pattern.find(symbol) else {
                continue;
            };
            let mut seen = 0usize;
            for (idx, line) in source.content.lines().enumerate() {
                let line_no = idx + 1;
                if Some(line_no) == exclude_line {
                    continue;
                }
                let mut search_from = 0usize;
                while let Some(rel) = line[search_from..].find(pattern.as_str()) {
                    let pat_col = search_from + rel;
                    let name_col = pat_col + name_offset;
                    let name_end = name_col + symbol.len();
                    let left_ok = name_col == 0 || {
                        let prev = line.as_bytes()[name_col - 1];
                        !(prev.is_ascii_alphanumeric() || prev == b'_')
                    };
                    let right_ok = line
                        .as_bytes()
                        .get(name_end)
                        .map_or(true, |b| !(b.is_ascii_alphanumeric() || *b == b'_'));
                    let excluded_by_called = guard_against_called && line[..pat_col].ends_with("called ");
                    if left_ok && right_ok && !excluded_by_called {
                        if seen == occurrence {
                            return Some(SourceLocation::new(&source.filename, line_no, name_col + 1, line));
                        }
                        seen += 1;
                    }
                    search_from = pat_col + 1;
                }
            }
        }
        None
    }

    pub(crate) fn find_write_site_location(&self, symbol: &str, occurrence: usize) -> Option<SourceLocation> {
        let decl_line = self.declared_locations.get(symbol).map(|l| l.line);
        let write_patterns = [
            format!("Set {} to ", symbol),
            format!("the {} is ", symbol),
            format!("{} is ", symbol),
        ];
        self.find_pattern_location(symbol, &write_patterns, occurrence, decl_line, true)
            .or_else(|| self.find_symbol_location(symbol, occurrence))
    }

    pub(crate) fn find_bind_site_location(
        &self,
        symbol: &str,
        patterns: &[String],
        occurrence: usize,
        guard_against_called: bool,
    ) -> Option<SourceLocation> {
        let decl_line = self.declared_locations.get(symbol).map(|l| l.line);
        self.find_pattern_location(symbol, patterns, occurrence, decl_line, guard_against_called)
            .or_else(|| self.find_symbol_location(symbol, occurrence))
    }

    pub(crate) fn find_declaration_location(&self, name: &str) -> Option<SourceLocation> {
        let called_patterns = [format!("called {} is", name), format!("called {} ", name)];
        self.find_pattern_location(name, &called_patterns, 0, None, false)
            .or_else(|| {
                let bare_patterns = [format!("{} is ", name), format!("each {} ", name)];
                self.find_pattern_location(name, &bare_patterns, 0, None, false)
            })
            .or_else(|| self.find_symbol_location(name, 0))
    }

    pub(crate) fn find_symbol_location(&self, symbol: &str, occurrence: usize) -> Option<SourceLocation> {
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

    pub(crate) fn push_error(&mut self, message: String, symbol: Option<&str>) {
        self.push_error_with_hint(message, symbol, None);
    }

    pub(crate) fn push_error_with_hint(&mut self, message: String, symbol: Option<&str>, hint: Option<&str>) {
        let mut err = CompileError::new(&message);
        if let Some(name) = symbol {
            let occurrence = *self.symbol_error_counts.get(name).unwrap_or(&0);
            if let Some(loc) = self.find_symbol_location(name, occurrence) {
                err = err.with_location(loc);
            }
            self.symbol_error_counts.insert(name.to_string(), occurrence + 1);
        }
        if let Some(h) = hint {
            err = err.with_hint(h);
        }
        self.errors.push(err);
    }

    pub(crate) fn push_unknown_variable(&mut self, name: &str) {
        let hint = self.pending_blank_line_truncation.as_ref().and_then(|(func, params, loc)| {
            if params.iter().any(|p| p == name) {
                Some(format!(
                    "a blank line ended `{}`'s body early at line {} — a paragraph break closes all open clauses, including the enclosing function, so `{}` is no longer in scope here",
                    func, loc.line, name
                ))
            } else {
                None
            }
        });
        self.push_error_with_hint(format!("Unknown variable: {}", name), Some(name), hint.as_deref());
    }

    pub(crate) fn current_env(&self) -> AnalysisEnv {
        AnalysisEnv {
            always: self.variables.clone(),
            guarded: self.guarded_scopes.clone(),
        }
    }

    pub(crate) fn apply_env(&mut self, env: &AnalysisEnv) {
        self.variables = env.always.clone();
        self.guarded_scopes = env.guarded.clone();
    }

    pub(crate) fn is_variable_available(&self, name: &str) -> bool {
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

    pub(crate) fn declare_variable_in_current_scope(&mut self, name: &str) {
        if name.starts_with('_') {
            self.push_error(
                format!(
                    "Variable name '{}' starts with '_', which is reserved for \
                     the Vox runtime; choose a name without the leading underscore.",
                    name
                ),
                Some(name),
            );
        }
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

    pub(crate) fn merge_continuing_envs(&self, envs: &[AnalysisEnv], fallback: &AnalysisEnv) -> AnalysisEnv {
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

    pub(crate) fn simple_guard_key(condition: &Expr) -> Option<String> {
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

    pub(crate) fn maybe_activate_true_guard(&mut self, name: &str, var_type: &Option<Type>, value: &Option<Expr>) {
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

    pub(crate) fn analyze_block_in_scope(&mut self, block: &[Statement], input_env: &AnalysisEnv, active_guard: Option<&str>) -> (AnalysisEnv, bool) {
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

    pub(crate) fn block_always_terminates(&self, block: &[Statement]) -> bool {
        for stmt in block {
            if self.statement_always_terminates(stmt) {
                return true;
            }
        }
        false
    }

    pub(crate) fn is_buffer_variable(&self, name: &str) -> bool {
        self.buffer_variables.contains(name)
    }

    pub(crate) fn is_list_variable(&self, name: &str) -> bool {
        self.list_variables.contains(name)
    }

    pub(crate) fn is_map_variable(&self, name: &str) -> bool {
        self.map_variables.contains(name)
    }

    pub(crate) fn is_scalar_variable(&self, name: &str) -> bool {
        !self.is_buffer_variable(name)
            && !self.is_list_variable(name)
            && !self.is_map_variable(name)
            && !self.file_variables.contains(name)
            && !self.timer_variables.contains(name)
            && !self.allocated_variables.contains(name)
    }

    pub(crate) fn statement_always_terminates(&self, stmt: &Statement) -> bool {
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

}
