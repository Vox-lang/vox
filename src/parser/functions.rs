use super::*;

impl Parser {
    /// After a callee name (bare or quoted identifier) has been advanced past,
    /// parse a call connector (`of`/`with`/`on`, and `to` when `allow_to`)
    /// and its argument list into a `FunctionCall` (plan 270 G1). Returns
    /// `None` when the next token is not a call connector, so the caller falls
    /// through to other postfix forms (property access, a bare identifier) or,
    /// in append-value position, the `to` separator. `allow_to` is false
    /// there: `to` is the append separator and must not read as a connector.
    /// `of` is similarly reserved (via `suppress_of_connector`) while parsing
    /// an index in `element N of .../byte N of ...`, where `of` is that
    /// statement's own separator, not this primary's connector.
    pub(crate) fn parse_call_tail(&mut self, name: String, allow_to: bool) -> Result<Option<Expr>, Box<CompileError>> {
        let is_conn = match self.current() {
            Token::Of => !self.suppress_of_connector,
            Token::With | Token::On => true,
            Token::To => allow_to && !self.suppress_to_connector,
            _ => false,
        };
        if !is_conn {
            return Ok(None);
        }
        self.advance();
        self.skip_noise();
        let mut args = Vec::new();
        let mut first_arg = true;
        loop {
            // A function call is a primary and must bind tighter than the
            // additive operators (`add`/`subtract`): `'state pos' of state
            // add by` is `('state pos' of state) add by`, not `'state pos' of
            // (state add by)`. The FIRST argument is therefore parsed at the
            // `cast` level (below additive) so a trailing `add`/`subtract` is
            // left for the caller to apply to the call result, while an
            // argument's own `as a <type>` cast is still kept (`f of x as a
            // number`).
            //
            // Once an `and` marks this as a multi-argument call, the argument
            // boundary is explicit, so LATER arguments parse at the full
            // `parse_expression` level: `gcd of b and aa modulo b` keeps
            // `aa modulo b` as the second argument, and `walk of v and n
            // subtract 1` keeps `n subtract 1`. A boolean `and` inside one
            // argument must be braced (`f of {x and y}`), as before. This keeps
            // comparison parsing intact: `'some call' of x and y is false
            // and ...` still reads `f(x, y) is false and ...`.
            let arg = if first_arg {
                first_arg = false;
                self.parse_cast()?
            } else {
                self.parse_expression()?
            };
            args.push(arg);
            self.skip_noise();
            if *self.current() == Token::Comma {
                // Comma belongs to the enclosing sentence.
                break;
            }
            if *self.current() == Token::And {
                self.advance();
                self.skip_noise();
            } else {
                break;
            }
        }
        Ok(Some(Expr::FunctionCall { name, args }))
    }

    /// Parse a primary expression with `to` and/or `of` reserved for an
    /// enclosing statement grammar rather than available as this primary's
    /// own call connector. Use this wherever a value/index/bound is parsed
    /// immediately before code that then checks for a literal `to`/`of` of
    /// its own (a range bound's `to`, an index's `of`) - otherwise a bare
    /// identifier there greedily reads that following word as its call
    /// connector via `parse_call_tail`'s generic lookahead, leaving nothing
    /// for the enclosing check (plan 270 G1 regression). Restores the prior
    /// suppression state unconditionally, including on error, so a caller
    /// higher up the stack that also suppressed a connector is unaffected.
    pub(crate) fn parse_primary_reserving(&mut self, to: bool, of: bool) -> Result<Expr, Box<CompileError>> {
        let saved_to = self.suppress_to_connector;
        let saved_of = self.suppress_of_connector;
        if to {
            self.suppress_to_connector = true;
        }
        if of {
            self.suppress_of_connector = true;
        }
        let result = self.parse_primary();
        self.suppress_to_connector = saved_to;
        self.suppress_of_connector = saved_of;
        result
    }

    pub(crate) fn parse_library_decl(&mut self) -> Result<Statement, Box<CompileError>> {
        // Library 'name' version "1.0".
        // Plan 270 §6: the library *name* is an identifier (bare or quoted);
        // the *version* is a string literal (data, not a name).
        self.advance(); // consume 'library'
        self.skip_noise();

        // Record that this translation unit declares itself a library. A
        // library file has no top-level entry by design, so its last
        // function body legitimately runs to EOF — the BUGS_FOUND #5
        // "function still open at end of file" warning is suppressed for
        // the rest of this parse (see `parse_function_def`).
        self.saw_library_decl = true;

        // Get library name (a bare or quoted identifier, never a string).
        let name = self.parse_name()?;

        self.skip_noise();

        // Parse version — a string literal. `version` is a contextual word
        // (claimed here by lexeme); the `ver` alias still lexes to
        // `Token::Version`, so accept both.
        let is_version = *self.current() == Token::Version
            || matches!(self.current(), Token::Identifier(ref id) if id.to_lowercase() == "version");
        let version = if is_version {
            self.advance();
            self.skip_noise();
            match self.current().clone() {
                Token::StringLiteral(v) => { self.advance(); v }
                _ => return Err(self.err("Expected version string")),
            }
        } else {
            "1.0".to_string() // Default version
        };

        Ok(Statement::LibraryDecl { name, version })
    }

    pub(crate) fn parse_see(&mut self) -> Result<Statement, Box<CompileError>> {
        // Stage A5 retired the abandoned direct-`.so` syntax. The one library
        // import that survives is the canonical form:
        //   see '<lib>' version "<ver>" from "<path>.lib".
        // A bare `see "<path>.vox".` is a source include — spliced in by the
        // frontend before compilation, never part of the library system — and
        // is unchanged here. Every other `see` form is retired: it gets a
        // diagnostic showing the canonical form, not a bare parse error, so a
        // user who wrote a form that used to be documented learns what to
        // write instead.
        self.advance(); // consume 'see'
        self.skip_noise();

        let mut path = String::new();
        let mut lib_name: Option<String> = None;
        let mut lib_version: Option<String> = None;

        // Helper to get string or identifier value
        let get_name_or_string = |token: &Token| -> Option<String> {
            match token {
                Token::StringLiteral(s) => Some(s.clone()),
                Token::Identifier(s) => Some(s.clone()),
                _ => None,
            }
        };

        // Helper to get version (string, identifier, or number)
        let get_version = |token: &Token| -> Option<String> {
            match token {
                Token::StringLiteral(s) => Some(s.clone()),
                Token::Identifier(s) => Some(s.clone()),
                Token::IntegerLiteral(n) => Some(n.to_string()),
                _ => None,
            }
        };

        // First token is the library name (canonical form: a bare/quoted
        // identifier followed by `version`) or the path (a string literal —
        // the `see "<path>.vox"` source include). Plan 270 §S1.5: a string
        // literal where a *name* is expected is rejected with the teaching
        // diagnostic, so the old `see '<lib>' version ...` form now points
        // the user at `see '<lib>' version "..."`. Detect this *before*
        // advancing so the underline lands on the offending string.
        let first_tok = self.current().clone();
        if let Token::StringLiteral(s) = &first_tok {
            // Look ahead past noise (newlines) for `version`.
            let mut k = 1;
            while matches!(self.peek(k), Token::Newline) {
                k += 1;
            }
            if matches!(self.peek(k), Token::Version)
                || matches!(self.peek(k), Token::Identifier(ref id) if id.to_lowercase() == "version") {
                return Err(self.err_string_as_name(s));
            }
        }
        let first = get_name_or_string(&first_tok)
            .ok_or_else(|| self.err(
                "Missing path or library name after 'see'\n  \
                 Canonical form: see '<lib>' version \"<x.y>\" from \"<path>.lib\".\n  \
                 (A source include is: see \"<path>.vox\".)"
            ))?;
        self.advance();
        self.skip_noise();

        let is_version = *self.current() == Token::Version
            || matches!(self.current(), Token::Identifier(ref id) if id.to_lowercase() == "version");
        if is_version {
            // see '<lib>' version "<ver>" from "<path>.lib".
            // `first` is the library name (an identifier in canonical form).
            lib_name = Some(first);
            self.advance();
            self.skip_noise();

            lib_version = get_version(self.current());
            if lib_version.is_some() {
                self.advance();
                self.skip_noise();
            }

            if *self.current() == Token::From {
                self.advance();
                self.skip_noise();
                path = get_name_or_string(self.current()).unwrap_or_default();
                if !path.is_empty() {
                    self.advance();
                }
            }
        } else if *self.current() == Token::From || *self.current() == Token::For {
            // Retired `.so`-era forms: `see "<lib>" from "<path>"` (no version)
            // and `see "<path>" for "<lib>" version "<ver>"`. Both used to
            // compile; both now direct the writer to the canonical `.lib`
            // form rather than failing silently. The keyword is named so the
            // message echoes the shape the user actually wrote.
            let form = if *self.current() == Token::From { "from" } else { "for" };
            return Err(self.err(&format!(
                "The `see ... {} ...` form is no longer supported.\n  \
                 Canonical form: see '<lib>' version \"<x.y>\" from \"<path>.lib\".",
                form
            )));
        } else {
            // Simple `see "<path>"` — a .vox source include.
            path = first;
        }

        // A `.so` is a binary. The abandoned model imported it directly, which
        // compiled silently with the library call simply missing — the trap
        // that made the stale documentation hazardous rather than merely
        // untidy. It now errors, directing the user to the `.lib` interface
        // file that is the canonical way to consume a library. This catches a
        // bare `see "x.so"` and a `see 'lib' version "1" from "x.so"` alike.
        if path.ends_with(".so") {
            return Err(self.err(
                "see of a .so is not supported. A .so is a binary; consume it \
                 through its .lib interface file.\n  \
                 Canonical form: see '<lib>' version \"<x.y>\" from \"<path>.lib\"."
            ));
        }

        // A source include is read HERE, in the middle of this parse, rather
        // than spliced into the statement list afterwards. Everything the
        // parse decides from a name - whether `point` is a type noun, whether
        // `origin's x` is a field chain, whether a name is still free - it has
        // to decide while reading, so a definition that arrives after the
        // parse has finished arrives too late to be usable (plan 310 §3), and
        // every rule the parser enforces would hold only inside one file.
        // Reading the file where its `see` stands also keeps the
        // defined-earlier rule meaning what it says across the boundary.
        if path.ends_with(".vox") && self.at_top_level() {
            self.included_statements = self.inline_source_include(&path)?;
        }

        Ok(Statement::See { path, lib_name, lib_version })
    }

    /// Read a `see`n Vox source into this parse: its statements land where the
    /// `see` stands, and its definitions, declarations and manifests join the
    /// tables this parser is deciding against. Returns `None` when the file
    /// was already read into this compilation, which leaves the `see`
    /// statement in place exactly as a repeated include always has.
    fn inline_source_include(
        &mut self,
        path: &str,
    ) -> Result<Option<Vec<Statement>>, Box<CompileError>> {
        use std::path::{Path, PathBuf};

        let base = self
            .include_base
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let include_path = if path.starts_with("./") || path.starts_with("../") {
            base.join(path)
        } else if path.starts_with('/') {
            PathBuf::from(path)
        } else {
            // A bare name is a system library first, then a sibling file.
            let system_path = Path::new("/usr/share/vox/lib").join(path);
            if system_path.exists() {
                system_path
            } else {
                base.join(path)
            }
        };
        // `tests/./include/geometry.vox` and `tests/include/geometry.vox` name
        // the same file; only one of them is worth putting in a diagnostic.
        let display: PathBuf = include_path.components().collect();
        let canonical = include_path
            .canonicalize()
            .unwrap_or_else(|_| display.clone());

        if self.included_files.contains(&canonical) {
            return Ok(None);
        }

        let source = std::fs::read_to_string(&include_path).map_err(|e| {
            self.err(&format!(
                "Cannot read '{}', the file this `see` names: {}\n  \
                 A source include is resolved against the directory of the \
                 file that writes it.",
                display.display(),
                e
            ))
        })?;

        self.included_files.insert(canonical);
        self.included_paths.push(display.display().to_string());

        let mut lexer = Lexer::new(&source);
        let tokens = lexer.tokenize();
        let mut inner = Parser::new(tokens)
            .with_source(&display.display().to_string(), &source)
            // An included file is a collection of definitions with no
            // top-level entry of its own, so its last function body reaching
            // EOF is how such a file is written - not the swallowed-program
            // shape the warning is looking for.
            .with_shared_mode(true);
        inner.include_base = Some(
            include_path
                .parent()
                .filter(|dir| !dir.as_os_str().is_empty())
                .map(|dir| dir.to_path_buf())
                .unwrap_or_else(|| PathBuf::from(".")),
        );
        // One identifier space, one set of things, one set of files already
        // read: the seen file continues this parse rather than starting a
        // private one of its own.
        inner.claimed_names = std::mem::take(&mut self.claimed_names);
        inner.things = std::mem::take(&mut self.things);
        inner.thing_vars = std::mem::take(&mut self.thing_vars);
        inner.thing_returning_functions = std::mem::take(&mut self.thing_returning_functions);
        inner.function_first_parameters = std::mem::take(&mut self.function_first_parameters);
        inner.member_functions = std::mem::take(&mut self.member_functions);
        inner.included_files = std::mem::take(&mut self.included_files);

        let statements = inner.parse_statement_list();

        self.claimed_names = std::mem::take(&mut inner.claimed_names);
        self.things = std::mem::take(&mut inner.things);
        self.thing_vars = std::mem::take(&mut inner.thing_vars);
        self.thing_returning_functions = std::mem::take(&mut inner.thing_returning_functions);
        self.function_first_parameters = std::mem::take(&mut inner.function_first_parameters);
        self.member_functions = std::mem::take(&mut inner.member_functions);
        self.included_files = std::mem::take(&mut inner.included_files);
        self.included_paths.append(&mut inner.included_paths);
        self.warnings.append(&mut inner.warnings);

        Ok(Some(statements?))
    }

    pub(crate) fn parse_function_def(&mut self) -> Result<Statement, Box<CompileError>> {
        // Location of the `To` keyword, used by the "function still open at
        // end of file" warning (BUGS_FOUND #5) to point at the definition.
        let def_loc = self.current_location();
        let def_pos = self.pos;
        self.advance(); // consume 'To'
        self.skip_noise();

        // `To do the point's 'placed at', with ...` defines one of the members
        // point's manifest declares (plan 310 §4). The head is read here and
        // everything after it is an ordinary function definition, so a member
        // gets the whole parameter, body, and return grammar without a second
        // copy of any of it.
        let member = if self.member_definition_follows() {
            Some(self.parse_member_definition_head()?)
        } else {
            None
        };

        // Get function name: a bare or quoted identifier (plan 270). A string
        // literal here is rejected with the §S1.5 diagnostic.
        let name_pos = self.pos;
        let name = match &member {
            // Already read, and compiled under the name that keeps two
            // things' same-named members apart.
            Some(member) => member.internal.clone(),
            None => self.parse_name().or_else(|e| {
                // Distinguish "missing name entirely" from "used a string literal":
                // parse_name already gives the teaching diagnostic for a string;
                // for anything else (e.g. a keyword or `with`) produce the
                // syntax-hint message.
                if matches!(self.current(), Token::StringLiteral(_)) {
                    Err(e)
                } else {
                    Err(self.err(
                        "Missing function name after 'To'\n  \
                         Syntax: To 'function name' with parameters. Return a type, expression.\n  \
                         Example: To 'add' with a number called x and a number called y. Return a number, x add y."
                    ))
                }
            })?,
        };

        // A function name is a name in the one identifier space (plan 310 §4,
        // §10). A member is not: its name lives in its owner's member space,
        // under an internal name that keeps two things' same-named members
        // apart, and the manifest already checked it.
        if member.is_none() {
            self.claim_name(&name, NameKind::Function, name_pos)?;
        }

        self.skip_noise();

        // The comma before a member's parameter list, on the `Return a
        // number, total.` payload-comma precedent (plan 310 §4).
        if member.is_some() && *self.current() == Token::Comma {
            self.advance();
            self.skip_noise();
        }

        // Parse parameters: "with <name>" or "with a <type> called <name> and ..."
        let mut params = Vec::new();
        if *self.current() == Token::With || *self.current() == Token::Of {
            self.advance();
            self.skip_noise();
            
            loop {
                self.skip_noise();

                // A string literal is never a parameter name (plan 270 §S1.5).
                if let Token::StringLiteral(s) = self.current().clone() {
                    return Err(self.err_string_as_name(&s));
                }

                // Check for simple parameter: just an identifier
                if let Token::Identifier(n) = self.current().clone() {
                    // Simple parameter without type
                    let param_pos = self.pos;
                    self.advance();
                    self.claim_name(&n, NameKind::Variable, param_pos)?;
                    params.push((n, Type::Unknown));
                } else {
                    // Full syntax: "a <type> called <name>"
                    // Skip optional article before type
                    if matches!(self.current(), Token::A | Token::An) {
                        self.advance();
                        self.skip_noise();
                    }
                    
                    let param_type = match self.declaration_type_token() {
                        Some(t) => { self.advance(); t }
                        None => Type::Unknown,
                    };
                    
                    self.skip_noise();
                    if *self.current() == Token::Called {
                        self.advance();
                        self.skip_noise();
                    }
                    
                    // A parameter names a variable, so it claims the one
                    // identifier space too - a parameter called `point` would
                    // make the type name unreadable for the length of the
                    // body, which is the shadowing §4 refuses.
                    let param_pos = self.pos;
                    let param_name = self.parse_name()?;
                    self.claim_name(&param_name, NameKind::Variable, param_pos)?;

                    params.push((param_name, param_type));
                }
                
                self.skip_noise();
                if *self.current() == Token::And {
                    self.advance();
                    self.skip_noise();
                } else {
                    break;
                }
            }
        }
        
        // A thing parameter holds a thing inside this body, so `start's x`
        // has to read as a field chain from here on (plan 310 §3). Recorded
        // before the body is parsed, for the same reason a thing definition
        // is recorded before any use of its name.
        for (param_name, param_type) in &params {
            if let Type::Thing(thing) = param_type {
                self.thing_vars.insert(param_name.clone(), thing.clone());
            }
        }

        // A function taking a thing first joins that thing's member space, so
        // it is checked against what the type already owns before anything can
        // call it (plan 310 §4).
        self.reject_member_space_collision(&name, name_pos, params.first())?;

        // The first parameter is what the instance possessive fills (plan 310
        // §4), so it is recorded here - before the body - and a function may
        // therefore use the sugar on its own name.
        self.record_first_parameter(&name, params.first());

        // A member is recorded in the same place and for the same reason: its
        // first parameter is what decides whether a receiver can reach it.
        if let Some(member) = &member {
            self.record_member_function(member, params.first());
        }
        // The member rule reports against this body's own Return lines, so
        // the previous definition's must not be left in place.
        self.typed_returns.clear();

        self.skip_noise();
        // Period or comma after function signature are optional.
        if matches!(self.current(), Token::Period | Token::Comma) {
            self.advance();
            self.skip_noise();
        }
        
        // Parse return type: "Return a <type>, <body>"
        let mut return_type = Type::Void;
        let mut body = Vec::new();
        
        if *self.current() == Token::Return {
            let return_pos = self.pos;
            self.advance();
            self.skip_noise();

            // Check for return type declaration: "Return a number," or "Return number,"
            // Skip optional article
            if matches!(self.current(), Token::A | Token::An) {
                self.advance();
                self.skip_noise();
            }

            let mut declared_type = None;
            if let Some(t) = self.declaration_type_token() {
                self.advance();
                self.typed_returns.push((return_pos, t.clone()));
                return_type = t;
                declared_type = Some(return_type.clone());
                self.skip_noise();
                self.expect(&Token::Comma);
                self.skip_noise();
            }

            // Parse the return expression
            let expr = self.parse_condition()?;
            body.push(Statement::Return { value: Some(expr), declared_type });
        }

        // A top-level Return ends the function body. LANGUAGE.md states
        // that blank lines are optional and have no effect on program
        // execution, so a function whose body ends in `Return ... .` must
        // not keep consuming following sentences when the author omits the
        // separating blank line. Without this, the next top-level
        // statement was silently absorbed into the function body as dead
        // code (emitted after the epilogue `ret`), producing empty or
        // wrong output. Multi-statement bodies that do not end in a
        // top-level Return still terminate at the paragraph break below.
        let body_ended_at_return =
            matches!(body.last(), Some(Statement::Return { .. }));
        if body_ended_at_return {
            self.skip_noise();
            if matches!(self.current(), Token::Period | Token::Comma) {
                self.advance();
                self.skip_noise();
            }
        }

        // Continue parsing body until paragraph break. A function body never
        // contains another function definition or a Library declaration —
        // `Token::To` and `Token::Library` always begin a NEW top-level
        // construct, so they terminate the body just like a paragraph break.
        // Without this, a bodyless function (`To greet.` with no Return and
        // no separating blank line) silently absorbed the following `To f.`
        // as a *nested* FunctionDef: the nested function was still emitted (so
        // it appeared in `nm -D`) but was invisible to any walk of top-level
        // statements — notably the Stage A3 `.lib` signature collector, which
        // then dropped it from the table of contents while the `.so` still
        // exported it. Terminating on `To`/`Library` keeps the successor
        // top-level where it belongs.
        let mut body_ended_early: Option<SourceLocation> = None;
        // Set when the body terminated because a Gate B `Return` (a Return
        // that is not the function's first statement) closed it — distinct
        // from `body_ended_at_return` (inline first-statement Return) and
        // used to suppress the "still open at EOF" warning for a function
        // that legitimately ends in a Return with no trailing blank line.
        let mut ended_via_return = false;
        while !body_ended_at_return
            && !matches!(self.current(), Token::ParagraphBreak | Token::EOF | Token::To | Token::Library)
        {
            self.skip_noise();
            if matches!(self.current(), Token::Comma) {
                self.advance();
                self.skip_noise();
                continue;
            }
            if matches!(self.current(), Token::Period) {
                self.advance();
                self.skip_noise();
            }
            if matches!(self.current(), Token::ParagraphBreak | Token::EOF | Token::To | Token::Library) {
                if matches!(self.current(), Token::ParagraphBreak) {
                    body_ended_early = self.current_location();
                }
                break;
            }
            let stmt = self.parse_statement()?;
            let is_return = matches!(stmt, Statement::Return { .. });
            // Gate B: `Return` isn't the function's first statement, so its
            // type annotation (if any) was parsed by `parse_return` rather
            // than inline above. Feed it back into the function's declared
            // return type the same way the inline path above does, or a
            // `Return a number, ...` that isn't the first statement would
            // silently leave `return_type` at `Type::Void`.
            if let Statement::Return { declared_type: Some(ref t), .. } = stmt {
                return_type = t.clone();
            }
            body.push(stmt);

            // A top-level Return parsed as a body statement terminates the
            // body; consume its trailing period and stop.
            if is_return {
                ended_via_return = true;
                self.skip_noise();
                if matches!(self.current(), Token::Period | Token::Comma) {
                    self.advance();
                    self.skip_noise();
                }
                break;
            }

            self.skip_noise();
            if *self.current() == Token::Comma {
                self.advance();
                self.skip_noise();
            }
        }

        // BUGS_FOUND #5: a function definition whose body ran all the way to
        // end of file — no closing blank line, no Return, no following `To`/
        // `Library` — has no closing blank line, so everything after the
        // signature is read as part of the body. When the author meant the
        // trailing statements as top-level entry code, that code is silently
        // swallowed and the program typically does nothing (exit 0, no
        // output). A blank line is the ONLY thing that closes a function body
        // (LANGUAGE.md "The termination rule" rule 2), so warn the author
        // rather than compiling a do-nothing program.
        //
        // Suppressed when the unit declares itself a `Library` (or is built
        // `--shared`): a library file legitimately consists only of function
        // definitions with no top-level entry, so its last function body
        // ending at EOF is correct by construction, not an absorption.
        //
        // The parser cannot tell, from structure alone, whether the trailing
        // body statements were *intended* as the body (a function that is
        // simply last in the file) or as top-level entry code that got
        // swallowed. The message therefore states only the structural fact
        // (the body reached EOF with no closing blank line) and gives the
        // blank-line fix as *conditional* advice, so it stays truthful in
        // both shapes — it never asserts that statements were absorbed when
        // none were.
        let body_ended_at_eof = !body_ended_at_return
            && !ended_via_return
            && matches!(self.current(), Token::EOF);
        if body_ended_at_eof && !body.is_empty() && !self.shared_mode && !self.saw_library_decl {
            let mut warn = CompileError::new(&format!(
                "Function '{}' is still open at end of file: its body reached \
                 EOF with no closing blank line. A function body is closed by a \
                 blank line (paragraph break), not by EOF, so without one \
                 everything after the signature is read as part of the body. If \
                 statements after the body were meant to run at the top level, \
                 add a blank line after the function body to close it.",
                name
            ));
            if let Some(loc) = def_loc {
                warn = warn.with_location(loc);
            }
            self.warnings.push(warn.as_warning());
        }

        // Consume paragraph break
        if *self.current() == Token::ParagraphBreak {
            self.advance();
        }

        // Checked once the whole body is read, because a `Return` anywhere in
        // it is one of the lines the member rule is about (plan 310 §4).
        if let Some(member) = &member {
            self.reject_member_returning_another_type(member, def_pos)?;
        }

        self.record_thing_returning_function(&name, &return_type);

        Ok(Statement::FunctionDef {
            name,
            params,
            return_type,
            body,
            body_ended_early,
        })
    }

}
