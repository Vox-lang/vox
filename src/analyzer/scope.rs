use super::*;
use crate::lexer::SourceRegion;

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

    /// Core of `find_symbol_location`/`find_write_site_location`/
    /// `find_bind_site_location`: search `patterns` in order, skipping
    /// any match that is not real code - a name mentioned in a `( … )`
    /// comment is not a use of it, and a text literal only counts for a
    /// pattern that asks for one (docs/BUGS_FOUND.md #46) - and skipping
    /// `exclude_line` (the declaration, when
    /// known) and requiring a left word boundary so a shorter name doesn't
    /// match as a suffix of a longer one (symbol "x", pattern "x is "
    /// matching inside "max is " - each pattern's own trailing space
    /// already enforces the right boundary). `guard_against_called`
    /// additionally excludes a match immediately preceded by "called " -
    /// the canonical declaration syntax `a <type> called X is <value>.`
    /// contains `X is ` right after it, so an "X is "-shaped pattern needs
    /// this guard as a second line of defence alongside `exclude_line`
    /// (which only covers the *recorded* declaration line, e.g. if a
    /// declaration and something else ever shared one line). A
    /// construct-specific pattern that legitimately targets "called X"
    /// itself (`FileOpen`'s own syntax) must pass `false` here so it does
    /// not exclude its own match.
    /// Search `patterns` (each expected to contain `symbol` as a
    /// substring) for the statement that binds/writes `symbol`, returning
    /// the location of `symbol` itself within the match - not the
    /// pattern's own start. That distinction matters: a pattern like
    /// `"Set {symbol} to "` has the symbol sitting *inside* it, offset by
    /// `len("Set ")`, so anchoring on the pattern's start would draw the
    /// caret under `Set` while claiming to point at the variable. Boundary
    /// checks (word boundary on both sides of `symbol`, and optionally
    /// "not immediately preceded by `called `") are applied around the
    /// symbol's own span for the same reason - a boundary check anchored on
    /// the pattern's start protects the wrong substring whenever the symbol
    /// isn't at offset 0.
    pub(crate) fn find_pattern_location(
        &self,
        symbol: &str,
        patterns: &[String],
        occurrence: usize,
        exclude_line: Option<usize>,
        guard_against_called: bool,
        hole_symbol: bool,
    ) -> Option<SourceLocation> {
        // Two passes. A hit in real code always beats one inside a text
        // literal, however much earlier the literal sits: `Print "hello".`
        // above `append hello to items.` is not where the unknown variable
        // is (docs/BUGS_FOUND.md #46). The second pass is for the name that
        // genuinely only ever appears inside a literal - interpolated as
        // `{name}`, or quoted - and it is the only pass a text-seeking
        // pattern can land in. A symbol that could never be a name in
        // code - the literal a format hole hands back as its "variable" -
        // has nothing for the first pass to find (docs/BUGS_FOUND.md #89).
        self.scan_patterns(symbol, patterns, occurrence, exclude_line, guard_against_called, false, hole_symbol)
            .or_else(|| {
                self.scan_patterns(symbol, patterns, occurrence, exclude_line, guard_against_called, true, hole_symbol)
            })
    }

    /// One pass of `find_pattern_location`, taking the first pattern that
    /// matches at all. `allow_text` opens the pass to matches sitting
    /// inside a text literal, and only to patterns that ask for one: a
    /// match inside a `( … )` comment is never a use of the name and is
    /// refused in both passes. A symbol that cannot be a name in code at
    /// all (`can_begin_a_name`) inverts that: for it, a match in code is
    /// the coincidence and the text literal is the real thing (#89).
    fn scan_patterns(
        &self,
        symbol: &str,
        patterns: &[String],
        occurrence: usize,
        exclude_line: Option<usize>,
        guard_against_called: bool,
        allow_text: bool,
        hole_symbol: bool,
    ) -> Option<SourceLocation> {
        let source = self.source_file.as_ref()?;
        // Could `symbol` be a bare name in code at all? A format hole
        // holding a literal - the manual's own rejected `{255:x}`
        // (LANGUAGE.md:3169), or `{3.14:.17}` - hands the analyzer the
        // literal's own text as the "variable" it could not find. No
        // occurrence of that text in real code is a use of it: it is some
        // unrelated number, and a legal `a float called f is 3.14.` three
        // lines above the hole was being marked as the mistake
        // (docs/BUGS_FOUND.md #89).
        // ...but only where the symbol REACHED us from a format hole. Every
        // other caller is looking for something genuinely written in code and
        // may legitimately be looking for a numeral: #78's buffer-size
        // diagnostic searches for the size as written, and refusing its code
        // match cost it its caret, note and help (docs/BUGS_FOUND.md #78 and
        // its corpus case 222).
        let names_code = !hole_symbol || can_begin_a_name(symbol);
        for pattern in patterns {
            let Some(name_offset) = pattern.find(symbol) else {
                continue;
            };
            // Whether this pattern is *asking* to land inside a text
            // literal. `{name` (interpolation) and `"name"` (the literal
            // itself) both put the symbol behind a delimiter the lexer
            // keeps inside a text token, so a hit there is the real thing.
            // A pattern that STARTS at the `:` of a `{name:SPEC}` clause
            // asks for one too, and by construction: a format spec exists
            // nowhere but inside a text literal, so a bare-count pattern
            // was refused in code, refused in the literal, and fell
            // through to the mention scan - which put the caret on the
            // first `8.2` anywhere in the file, a header comment included,
            // the exact miss #46 fixed for names (docs/BUGS_FOUND.md #85).
            // Every other pattern describes code, and a hit inside a
            // literal is then a coincidence.
            let reaches_into_text = {
                let before = &pattern[..name_offset];
                before.ends_with('{') || before.ends_with('"') || before.starts_with(':')
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
                    let region_ok = match source.region_of(line_no, name_col, name_end) {
                        SourceRegion::Code => names_code,
                        // The bare pattern reaches into a literal only for
                        // a symbol that has nowhere else to be, and then
                        // the literal is where the mistake was written -
                        // `{ 3.14 :.2}`, whose spacing no text-seeking
                        // pattern matches (#89).
                        SourceRegion::Text => allow_text && (reaches_into_text || !names_code),
                        SourceRegion::Comment => false,
                    };
                    if left_ok && right_ok && region_ok && !excluded_by_called {
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

    /// Like `find_symbol_location`, but for pointing at the specific
    /// statement that *writes* to `symbol` (`Set symbol to ...` / `symbol is
    /// ...` / `the symbol is ...`), not just any occurrence of the name.
    /// `find_symbol_location`'s own preference order (`{symbol` first, for
    /// format-string interpolation) is wrong here: a name that also appears
    /// in an unrelated `Print "{n}"` elsewhere in the file would anchor the
    /// type-lock error there instead of at the offending assignment.
    pub(crate) fn find_write_site_location(&self, symbol: &str, occurrence: usize) -> Option<SourceLocation> {
        let decl_line = self.declared_locations.get(symbol).map(|l| l.line);
        let write_patterns = [
            format!("Set {} to ", symbol),
            format!("the {} is ", symbol),
            format!("{} is ", symbol),
        ];
        self.find_pattern_location(symbol, &write_patterns, occurrence, decl_line, true, false)
            .or_else(|| self.find_symbol_location(symbol, occurrence))
    }

    /// Like `find_symbol_location`, but excludes `symbol`'s own declaration
    /// line. `find_symbol_location`'s first-occurrence search makes an
    /// "Unknown variable" error for a cross-condition use (declared only in
    /// an `if` branch, read after it) anchor on the declaration itself - the
    /// textually first place the name appears - instead of the read that
    /// actually failed (plan 318 §3, same class as the accepted #11
    /// finding). Falls back to `find_symbol_location` when there is no
    /// recorded declaration to exclude, or every occurrence found IS that
    /// declaration (a name reported unknown with no other occurrence at all -
    /// better to point at something than nothing).
    pub(crate) fn find_use_site_location(&self, symbol: &str, occurrence: usize) -> Option<SourceLocation> {
        let decl_line = self.declared_locations.get(symbol).map(|l| l.line);
        let patterns = [
            format!("{{{}", symbol),
            format!("\"{}\"", symbol),
            symbol.to_string(),
        ];
        self.find_pattern_location(symbol, &patterns, occurrence, decl_line, true, true)
            .or_else(|| self.find_symbol_location(symbol, occurrence))
    }

    /// Like `find_write_site_location`, for a statement that *binds* `name`
    /// through some construct-specific syntax rather than `is`/`to`
    /// (a for-range/for-each loop header, `open ... called X`, `Allocate N
    /// for X`). `patterns` are the construct's own syntax fragments
    /// (e.g. `"each {name} "`, `"called {name} "`); `guard_against_called`
    /// should be `false` when a pattern itself targets `"called X"`; a
    /// caller doing that must instead disambiguate the declaration via
    /// `exclude_line`.
    pub(crate) fn find_bind_site_location(
        &self,
        symbol: &str,
        patterns: &[String],
        occurrence: usize,
        guard_against_called: bool,
    ) -> Option<SourceLocation> {
        let decl_line = self.declared_locations.get(symbol).map(|l| l.line);
        self.find_pattern_location(symbol, patterns, occurrence, decl_line, guard_against_called, false)
            .or_else(|| self.find_symbol_location(symbol, occurrence))
    }

    /// Where `name` was declared, for `declared_locations`. Deliberately
    /// does NOT use `find_symbol_location`: that function prefers `{name`
    /// (format-string interpolation) as its first pattern, which is right
    /// for "where is this name used" but wrong here - a `Print "{src}"`
    /// anywhere in the file would outrank the actual `a text called src
    /// is ...` declaration, since interpolation is usually textually
    /// earlier or just as likely to hit occurrence 0.
    ///
    /// Every spelling that can bring a name into being is searched, and the
    /// EARLIEST of them in the file wins - `called NAME` (typed
    /// declarations, `Allocate`, `FileOpen`, ...), the loop header `each
    /// NAME`, and the three that name no type: `NAME is <value>.`, `the
    /// NAME is <value>.` and `Set NAME to <value>.`. Pattern order cannot
    /// decide it, because any of them may be the declaration and any of
    /// them may be a later write: `Set zoo to 5.` above `the zoo is "x".`
    /// declares on the first line, and the reverse order declares on the
    /// other. The `Set`/`Create` spellings were missing here altogether, so
    /// a name declared by `Set` had its declaration site reported as
    /// whichever later line rewrote it - which put the type-lock error's
    /// caret on the declaration and its "was declared at" note on the
    /// offending write, backwards (docs/BUGS_FOUND.md #95).
    ///
    /// A hit in real code still beats one inside a text literal however
    /// much earlier the literal sits, which is why the search runs as two
    /// whole passes (code, then text) rather than one pass per pattern -
    /// the same guarantee `find_pattern_location` gives a pattern group
    /// (docs/BUGS_FOUND.md #46).
    pub(crate) fn find_declaration_location(&self, name: &str) -> Option<SourceLocation> {
        let patterns = [
            format!("called {} is", name),
            format!("called {} ", name),
            format!("{} is ", name),
            format!("each {} ", name),
            format!("Set {} to ", name),
            format!("Create {} to ", name),
        ];
        let earliest = |allow_text: bool| {
            patterns
                .iter()
                .filter_map(|pattern| {
                    self.scan_patterns(
                        name,
                        std::slice::from_ref(pattern),
                        0,
                        None,
                        false,
                        allow_text,
                        false,
                    )
                })
                .min_by_key(|loc| (loc.line, loc.column))
        };
        earliest(false)
            .or_else(|| earliest(true))
            .or_else(|| self.find_symbol_location(name, 0))
    }

    /// Where `symbol` appears, for a diagnostic that has nothing but a
    /// name to go on. Prefers the interpolation form `{symbol` and the
    /// literal form `"symbol"` over the bare name, and goes through
    /// `find_pattern_location` so it inherits that scan's two guarantees:
    /// the match is a whole word (the symbol `n` no longer anchors on the
    /// `n` inside `print`, docs/BUGS_FOUND.md #55) and it sits in real
    /// code, never in a `( … )` comment and never inside a text literal
    /// the pattern did not ask for (#46).
    pub(crate) fn find_symbol_location(&self, symbol: &str, occurrence: usize) -> Option<SourceLocation> {
        self.find_pattern_location(symbol, &symbol_patterns(symbol), occurrence, None, false, false)
            .or_else(|| self.find_mention_location(symbol, occurrence))
    }

    /// Last resort for `find_symbol_location`: the pre-#46 scan - first
    /// textual occurrence of the name anywhere, comments and literals
    /// included. Only reached when the name occurs nowhere in code at all,
    /// where a caret on a comment is poor but an error with no `-->` line
    /// is worse; this file's standing policy is that pointing at something
    /// beats pointing at nothing.
    fn find_mention_location(&self, symbol: &str, occurrence: usize) -> Option<SourceLocation> {
        let source = self.source_file.as_ref()?;

        for pattern in symbol_patterns(symbol) {
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
        // Every "Unknown buffer/list/map/file/timer: X" in the statement arms
        // sits behind `if !self.is_variable_available(X)`, so an error pushed
        // about a symbol that is unavailable HERE but declared further down at
        // top level is always the same defect, whatever wording the arm chose:
        // the read is too early (docs/BUGS_FOUND.md #79). Answer it once, in
        // the words that name the construct and the way out, instead of
        // leaving each arm to call the name unknown. An error about a symbol
        // that IS available cannot reach this - `is_used_before_its_
        // declaration` requires unavailability - so no type-lock or
        // wrong-kind diagnostic is touched.
        if let Some(name) = symbol {
            if self.is_used_before_its_declaration(name) {
                self.push_used_before_declaration(name);
                return;
            }
        }
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

    /// Same as `push_error_with_hint`, but for a caller that already has a
    /// real `SourceLocation` in hand (from parser state, not a textual
    /// symbol search) - e.g. `Statement::Return`'s "only valid inside a
    /// function" error, which has no symbol name to search for and instead
    /// points at wherever the body-level Return or blank line closed the
    /// enclosing function early.
    pub(crate) fn push_error_with_hint_at(
        &mut self,
        message: String,
        location: Option<SourceLocation>,
        hint: Option<&str>,
    ) {
        let mut err = CompileError::new(&message);
        if let Some(loc) = location {
            err = err.with_location(loc);
        }
        if let Some(h) = hint {
            err = err.with_hint(h);
        }
        self.errors.push(err);
    }

    pub(crate) fn push_unknown_variable(&mut self, name: &str) {
        // "Unknown" is the wrong word for a name the pre-pass has already
        // proved exists: the read is too early, not misspelled, and the way
        // out is to move a line rather than to fix a typo
        // (docs/BUGS_FOUND.md #79).
        if self.is_used_before_its_declaration(name) {
            self.push_used_before_declaration(name);
            return;
        }
        let hint = self.pending_blank_line_truncation.as_ref().and_then(|(func, params, loc)| {
            if params.iter().any(|p| p == name) {
                Some(format!(
                    "a blank line ended `{}`'s body early at line {} — a paragraph break closes all open clauses, including the enclosing function, so `{}` is no longer in scope here",
                    func, loc.line, name
                ))
            } else {
                None
            }
        }).or_else(|| {
            // `declared_locations` records EVERY declaration this walk has
            // seen, including a some-branches-only one that didn't survive
            // the if/otherwise merge (LANGUAGE.md "Declarations in
            // Branches") - so its presence here, when nothing else
            // explains the error, means `name` isn't a typo: it exists,
            // just not on every path that reaches this read.
            self.declared_locations.get(name).map(|_| format!(
                "`{}` is declared only in some branches of an `if`/`otherwise`, so it is not in scope after it - declare it in every branch, or before the `if`",
                name
            ))
        });
        // Anchor on the actual failing read, not the (textually earlier)
        // declaration that happens to contain the same name (plan 318 §3).
        let occurrence = *self.symbol_error_counts.get(name).unwrap_or(&0);
        let location = self.find_use_site_location(name, occurrence);
        self.symbol_error_counts.insert(name.to_string(), occurrence + 1);
        self.push_error_with_hint_at(format!("Unknown variable: {}", name), location, hint.as_deref());
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

    /// Whether `name` is declared ANYWHERE in this program, ignoring where
    /// the walk has got to - the question "is this statement a declaration
    /// or a reassignment?" asks, and the only question that may ignore
    /// declaration order. `Set n to 5.` and `a text called n is "x".` both
    /// parse into the same statement whether `n` is brand-new or not, and
    /// which it is decides whether the type lock applies; that answer must
    /// not change just because the top-level walk now starts empty
    /// (docs/BUGS_FOUND.md #79). Every other caller wants
    /// `is_variable_available`, which answers for *here*.
    pub(crate) fn is_variable_declared_anywhere(&self, name: &str) -> bool {
        self.is_variable_available(name) || self.global_variables.contains(name)
    }

    /// Whether a read of `name` right here is a use of a top-level variable
    /// whose own declaration is further down the file. The whole-program
    /// pre-pass proved the name exists; this walk has not reached the
    /// declaration, and top-level statements run in order, so the storage
    /// still holds its zeroed .bss slot (docs/BUGS_FOUND.md #79).
    ///
    /// Never true inside a function body: a function runs when it is called,
    /// so a global declared further down IS in scope there, and LANGUAGE.md
    /// "Function Scope" says so. Never true of a flag either - a flag read
    /// before `parse flags.` has its own, more specific diagnostic.
    pub(crate) fn is_used_before_its_declaration(&self, name: &str) -> bool {
        !self.in_function_scope
            && self.global_variables.contains(name)
            && !self.flag_variables.contains_key(name)
            && !self.is_variable_available(name)
    }

    /// The diagnostic for `is_used_before_its_declaration`: name the
    /// construct, say where the declaration actually is, and give the way
    /// out. In #45/#62/#63's family - a program the compiler silently
    /// accepted and silently answered wrong - so it is an error, not a
    /// warning. The caret goes on the failing read, not on the declaration
    /// that happens to contain the same name (#46, plan 318 §3), which is
    /// what `find_use_site_location` exists for.
    pub(crate) fn push_used_before_declaration(&mut self, name: &str) {
        let occurrence = *self.symbol_error_counts.get(name).unwrap_or(&0);
        let location = self.find_use_site_location(name, occurrence);
        self.symbol_error_counts.insert(name.to_string(), occurrence + 1);

        let mut err = CompileError::new(&format!("'{}' is used before it is declared", name));
        if let Some(loc) = location {
            err = err.with_location(loc);
        }
        let where_declared = match self.declaration_line_of(name) {
            Some(line) => format!("'{}' is declared at line {}", name, line),
            None => format!("'{}' is declared further down this file", name),
        };
        err = err.with_note_line(&format!(
            "top-level statements run in the order they are written, and {}",
            where_declared
        ));
        err = err.with_help_line(&format!(
            "move the declaration of '{}' above this line; a function body may \
             read a global declared further down, top-level code may not",
            name
        ));
        self.errors.push(err);
    }

    /// Which line `name`'s declaration is on, for
    /// `push_used_before_declaration`'s `note:`. `declared_locations` is
    /// filled as the walk reaches each declaration, and this read happens
    /// BEFORE that, so the location has to be found in the source text.
    fn declaration_line_of(&self, name: &str) -> Option<usize> {
        self.find_declaration_location(name).map(|loc| loc.line)
    }

    pub(crate) fn declare_variable_in_current_scope(&mut self, name: &str) {
        // Register the name BEFORE complaining about it: this statement is
        // the declaration, so from here on the name is available, and an
        // error pushed while it still looks unavailable is read as a
        // use-before-declaration instead of what it is (docs/BUGS_FOUND.md
        // #79 - the reserved-underscore diagnostic used to come out as
        // "'_foo' is used before it is declared", pointing at the line after
        // its own declaration).
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

    /// The English name of a `for each` collection's kind when the analyzer
    /// can PROVE that kind cannot be walked as a list, a range, or a
    /// buffer's bytes; `None` otherwise.
    ///
    /// A loop expansion over anything but a buffer lowers to a list-header
    /// read - codegen takes the collection's value as a pointer and loads
    /// `[ptr + 8]` as the element count. Hand it a number and the number
    /// itself is dereferenced (segfault); hand it a map and its header is
    /// misread as a list's, so the loop runs a garbage number of iterations
    /// over garbage elements, silently (bug #49). A buffer is walked through
    /// its own byte-read path instead (docs/BUGS_FOUND.md #104), so it is no
    /// longer one of the kinds this rejects.
    ///
    /// This is deliberately a known-scalar rejection and NOT a
    /// list-whitelist: Vox is dynamically typed and this pass cannot see the
    /// shape of an untyped parameter, a `value`, a function result or a
    /// property read, all of which iterate correctly today. Only a name this
    /// pass has positively categorised as a scalar/map - or a literal
    /// scalar written straight into the clause - is refused.
    pub(crate) fn non_collection_kind(&self, collection: &Expr) -> Option<&'static str> {
        match collection {
            Expr::IntegerLit(_) => Some("number"),
            Expr::FloatLit(_) => Some("float"),
            Expr::BoolLit(_) => Some("boolean"),
            // `For each x from/in <expr>` rewrites a quoted name into an
            // `Identifier` while parsing, so a `StringLit` surviving to here
            // is a real text literal from a loop-expansion clause
            // (`print each part from "abc".`), never a variable reference.
            Expr::StringLit(_) | Expr::FormatString { .. } => Some("text"),
            // A map literal written straight into the clause is the same
            // defect as a map variable: its header is not a list's.
            Expr::MapLit { .. } => Some("map"),
            Expr::Identifier(name) => {
                // An undeclared name is already reported as an unknown
                // variable; a second error about its kind would only be
                // noise, and its kind is unknowable anyway.
                if !self.is_variable_available(name) {
                    return None;
                }
                // A buffer is walked byte-by-byte (docs/BUGS_FOUND.md
                // #104), the same standing a list or a range has here -
                // so it is never one of the refused kinds.
                if self.is_buffer_variable(name) {
                    return None;
                }
                if self.is_map_variable(name) {
                    return Some("map");
                }
                // A list, or a name whose runtime shape is chosen elsewhere,
                // keeps working untouched.
                if self.is_list_variable(name) || self.value_typed_names.contains(name) {
                    return None;
                }
                match self.scalar_types.get(name) {
                    Some(Type::Integer) => Some("number"),
                    Some(Type::Float) => Some("float"),
                    Some(Type::Boolean) => Some("boolean"),
                    Some(Type::String) => Some("text"),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Reject a `for each` collection `non_collection_kind` can prove is not
    /// one, naming the kind and - for a map - the accessor that does work.
    /// LANGUAGE.md's supported collections are a list, a range, and
    /// `arguments's all`; a map is iterated through `'s keys` or `'s values`.
    pub(crate) fn check_loop_collection(&mut self, variable: &str, collection: &Expr) {
        let Some(kind) = self.non_collection_kind(collection) else {
            return;
        };
        // `text` takes no article, exactly as `typed_phrase` spells it for
        // the type-lock diagnostics.
        let phrase = if kind == "text" {
            "text".to_string()
        } else {
            format!("a {}", kind)
        };
        // A literal has no name to quote back, so the message names the kind
        // that was written instead, and the error points at the loop variable
        // - the one name on that line the source search can find.
        let name = match collection {
            Expr::Identifier(name) => Some(name.clone()),
            _ => None,
        };
        let subject = name.clone().unwrap_or_else(|| phrase.clone());
        let symbol = name.clone().unwrap_or_else(|| variable.to_string());
        let hint = match (kind, &name) {
            ("map", Some(name)) => format!(
                "{} is a map - iterate `{}'s keys` or `{}'s values`",
                subject, name, name
            ),
            ("map", None) => "a map is iterated through its `'s keys` or `'s values`".to_string(),
            (_, Some(_)) => format!(
                "{} is {} - `each ... from` walks a list, a range, a buffer's bytes, or `arguments's all`",
                subject, phrase
            ),
            // The message already named the literal's kind; repeating it
            // here would say the same thing twice.
            (_, None) => "`each ... from` walks a list, a range, a buffer's bytes, or `arguments's all`".to_string(),
        };
        // Anchor at the loop clause's own use of the collection, not the
        // collection's declaration: `push_error_with_hint`'s bare symbol
        // search finds the textually FIRST mention of the name, which in a
        // large file is the declaration, hundreds of lines above the loop
        // that actually misuses it. `from {symbol}`/`in {symbol}` are this
        // statement's own syntax - `each ... from ...` and the older `For
        // each ... in ...,` both build this same AST node - so either lands
        // on the offending line even when the bare name recurs elsewhere
        // (docs/BUGS_FOUND.md #104). When the collection has no name of its
        // own, the loop variable is searched instead, and it sits BEFORE
        // `from`/`in`, not after.
        let bind_patterns: Vec<String> = if name.is_some() {
            vec![format!("from {}", symbol), format!("in {}", symbol)]
        } else {
            vec![format!("each {} from", symbol), format!("each {} in", symbol)]
        };
        let occurrence = *self.symbol_error_counts.get(&symbol).unwrap_or(&0);
        let location = self.find_bind_site_location(&symbol, &bind_patterns, occurrence, true);
        self.symbol_error_counts.insert(symbol.clone(), occurrence + 1);
        self.push_error_with_hint_at(
            format!("Loop collection must be a list: {}", subject),
            location,
            Some(&hint),
        );
    }

    /// A "scalar" variable holds a raw 64-bit value (a number, a boolean
    /// flag, or a unix timestamp) rather than a pointer or handle. Number
    /// and time properties read the raw slot, so applying them to a
    /// buffer/list/file/timer loads a pointer or fd and yields garbage.
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

/// Whether `symbol` could be a name in code, where the bare pattern
/// looks for one. The lexer begins a word on an alphabetic character or
/// `_` (`src/lexer/scan.rs`), so a symbol starting with anything else was
/// never lexed as a name: it is a literal the format parser handed back
/// as a hole's "variable", and it exists only inside the text literal it
/// was written in. The empty symbol is the unmatched-`{` sentinel of
/// docs/BUGS_FOUND.md #10 and answers `true` to keep its caret: its match
/// is zero-width, which `region_of` reports as code.
fn can_begin_a_name(symbol: &str) -> bool {
    match symbol.chars().next() {
        Some(first) => first.is_alphabetic() || first == '_',
        None => true,
    }
}

/// The patterns `find_symbol_location` looks for, in preference order: a
/// name interpolated into a text (`{name`), a name written as a text
/// literal (`"name"`), then the bare name. The first two only ever match
/// inside a literal, and `find_pattern_location` lets them do so only
/// after the bare name has failed to turn up anywhere in real code.
fn symbol_patterns(symbol: &str) -> [String; 3] {
    [
        format!("{{{}", symbol),
        format!("\"{}\"", symbol),
        symbol.to_string(),
    ]
}
