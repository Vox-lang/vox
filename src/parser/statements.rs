use super::*;

impl Parser {
    /// True when the token after the current one (skipping newline noise)
    /// can be the name operand of a timer statement: `the` or an
    /// identifier. Decides whether a statement-initial `start`/`begin`/
    /// `stop`/`finish` is a timer statement or an ordinary call.
    pub(crate) fn timer_name_follows(&self) -> bool {
        let mut off = 1;
        while matches!(self.peek(off), Token::Newline) {
            off += 1;
        }
        matches!(self.peek(off), Token::The | Token::Identifier(_))
    }

    /// True when the token after the current one (skipping newline noise) is
    /// the identifier `signal` (case-insensitive). Decides whether a
    /// statement-initial `send` opens a `Send signal ...` statement or is an
    /// ordinary call, mirroring `timer_name_follows` for the timer words so a
    /// user-defined `send` function keeps working (the 0.3.7 precedent for
    /// `begin`/`stop`/`finish`).
    pub(crate) fn signal_keyword_follows(&self) -> bool {
        let mut off = 1;
        while matches!(self.peek(off), Token::Newline) {
            off += 1;
        }
        matches!(self.peek(off), Token::Identifier(ref s) if s.eq_ignore_ascii_case("signal"))
    }

    pub fn parse(&mut self) -> Result<Program, Box<CompileError>> {
        let statements = self.parse_statement_list()?;

        // The manifest is checked both ways (plan 310 §4, §10). "Nothing
        // defines it" is the half that can only be known here, once every
        // definition in the program has been read - which now means after the
        // `see`n files have been read too, so a member declared in one file
        // may be defined in another.
        self.reject_undefined_members()?;

        // `Program::new` derives the thing registry from the statement list
        // in definition (layout) order, so there is nothing to attach here -
        // and no construction path that can forget to. What it does derive is
        // checked against what the parse actually registered before the
        // program leaves the parser: two registries that can disagree in
        // silence are what let a thing be type-checked and then laid out as
        // nothing.
        let program = Program::new(statements);
        self.check_thing_registry(&program)?;
        Ok(program)
    }

    /// The top-level statement loop, without the whole-program checks that
    /// close a parse. A `see`n file is read through here rather than through
    /// `parse`, because those checks are about the program and a seen file is
    /// only part of one: a member its manifest declares may well be defined
    /// in the file that saw it.
    pub(crate) fn parse_statement_list(
        &mut self,
    ) -> Result<Vec<Statement>, Box<CompileError>> {
        // Every thing variable this file declares outside a function body is
        // registered before the first statement is read, so a function may
        // name a global declared below it (BUGS_FOUND #80). The walk still
        // registers each declaration as it reaches it; this only fills the
        // table in ahead of the walk.
        self.register_declared_thing_vars();

        let mut statements = Vec::new();

        while *self.current() != Token::EOF {
            self.skip_all_whitespace();
            if *self.current() == Token::EOF {
                break;
            }

            match self.parse_statement() {
                Ok(stmt) => {
                    // Function definitions handle their own period and paragraph break
                    let is_func_def = matches!(stmt, Statement::FunctionDef { .. });
                    // A `see "<path>.vox"` is not a statement in the program:
                    // it stands for the file's statements, which take its
                    // place here. `Some(empty)` still means "inlined" - a file
                    // may legitimately have nothing in it, and an already-seen
                    // file has nothing left to contribute.
                    match self.included_statements.take() {
                        Some(mut spliced) => statements.append(&mut spliced),
                        None => statements.push(stmt),
                    }

                    if !is_func_def {
                        self.skip_noise();
                        self.expect(&Token::Period);
                    }
                }
                Err(e) => return Err(e),
            }

            self.skip_all_whitespace();
        }

        Ok(statements)
    }

    /// Parse one statement, counting how deep it sits. Every block body - an
    /// `If` branch, a `While`/`For` body, a function body - reads its
    /// statements through here, so depth 1 is the top level and anything
    /// deeper is inside a block. `parse_thing_definition` is the one parser
    /// that asks (plan 310 §9); the count is kept here rather than at each
    /// block parser so a construct added later cannot forget to maintain it.
    pub(crate) fn parse_statement(&mut self) -> Result<Statement, Box<CompileError>> {
        self.statement_depth += 1;
        let parsed = self.dispatch_statement();
        self.statement_depth -= 1;
        parsed
    }

    /// True when the statement being parsed is a top-level one, written
    /// against the left margin rather than inside some block's body.
    pub(crate) fn at_top_level(&self) -> bool {
        self.statement_depth <= 1
    }

    fn dispatch_statement(&mut self) -> Result<Statement, Box<CompileError>> {
        self.skip_all_whitespace();

        let stmt = match self.current().clone() {
            Token::Print => self.parse_print(),
            Token::Set => self.parse_var_decl(),
            Token::Create => {
                // Disambiguate: "Create a directory" vs "Create symbolic link" vs variable creation
                let saved = self.pos;
                self.advance(); // consume 'create'
                self.skip_noise();

                // Skip optional "a"
                if *self.current() == Token::A {
                    self.advance();
                    self.skip_noise();
                }

                // Check for "directory" or "symbolic" or "device"
                if let Token::Identifier(ref id) = self.current() {
                    if id.eq_ignore_ascii_case("directory") {
                        self.pos = saved; // reset to parse with mkdir
                        return self.parse_mkdir();
                    } else if id.eq_ignore_ascii_case("symbolic") {
                        self.pos = saved; // reset to parse with symlink
                        return self.parse_symlink();
                    } else if id.eq_ignore_ascii_case("device") {
                        self.pos = saved; // reset to parse with mknod
                        return self.parse_mknod();
                    }
                }

                self.pos = saved; // reset to parse as var decl
                self.parse_var_decl()
            }
            Token::A | Token::An => self.parse_typed_var_decl(),
            Token::Parse => self.parse_parse_flags(),
            Token::The => self.parse_the_statement(),
            Token::If | Token::When => self.parse_if(),
            Token::While => self.parse_while(),
            Token::For => self.parse_for(),
            Token::Repeat => self.parse_repeat(),
            Token::Return => self.parse_return(),
            Token::Break => { self.advance(); Ok(Statement::Break) }
            Token::Continue => { self.advance(); Ok(Statement::Continue) }
            Token::Exit => self.parse_exit(),
            Token::Allocate => self.parse_allocate(),
            Token::Free => self.parse_free(),
            Token::Increment => self.parse_increment(),
            Token::Decrement => self.parse_decrement(),
            Token::To => self.parse_function_def(),
            // File I/O
            Token::Open => self.parse_file_open(),
            Token::Read => self.parse_file_read(),
            Token::Write => self.parse_file_write(),
            Token::Close => self.parse_file_close(),
            Token::Delete => {
                // Disambiguate: "Delete/Remove the file <path>" vs "Delete/Remove the directory <path>"
                let saved = self.pos;
                self.advance(); // consume 'delete'/'remove'
                self.skip_noise();

                if *self.current() == Token::The {
                    self.advance();
                    self.skip_noise();
                }

                if let Token::Identifier(ref id) = self.current() {
                    if id.eq_ignore_ascii_case("directory") {
                        self.pos = saved;
                        return self.parse_rmdir();
                    }
                }

                self.pos = saved;
                self.parse_file_delete()
            }
            Token::Seek => self.parse_file_seek(),
            Token::On => self.parse_on_error(),
            Token::Auto => self.parse_auto_error(),
            Token::Enable => self.parse_enable(),
            Token::Disable => self.parse_disable(),
            Token::Resize => self.parse_resize(),
            Token::Append => self.parse_append(),
            Token::Copy => self.parse_copy(),
            Token::Clear => self.parse_clear(),
            Token::Library => self.parse_library_decl(),
            Token::See => self.parse_see(),
            // Time and Timer statements
            Token::Wait | Token::Sleep => self.parse_wait(),
            Token::Get => self.parse_get(),
            // start/begin/stop/finish are contextual identifiers, not
            // reserved words: they open a timer statement only when a name
            // operand follows (`Start the t.`, `stop t.`). A bare `stop.`
            // or `begin of x` falls through to the ordinary call path, and
            // all four words stay usable as variable and function names.
            Token::Identifier(ref s)
                if (s == "start" || s == "begin") && self.timer_name_follows() =>
            {
                self.parse_timer_start()
            }
            Token::Identifier(ref s)
                if (s == "stop" || s == "finish") && self.timer_name_follows() =>
            {
                self.parse_timer_stop()
            }
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("change") => self.parse_chdir(),
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("mount") => self.parse_mount(),
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("unmount") || s.eq_ignore_ascii_case("umount") => self.parse_unmount(),
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("shutdown") || s.eq_ignore_ascii_case("poweroff") => {
                self.advance();
                Ok(Statement::Shutdown)
            }
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("reboot") || s.eq_ignore_ascii_case("restart") => {
                self.advance();
                Ok(Statement::Reboot)
            }
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("halt") => {
                self.advance();
                Ok(Statement::Halt)
            }
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("pivot") => self.parse_pivot_root(),
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("execute") => self.parse_execute(),
            Token::Identifier(ref s)
                if s.eq_ignore_ascii_case("send") && self.signal_keyword_follows() =>
            {
                self.parse_send_signal()
            }
            Token::Identifier(_) => self.parse_identifier_statement(),
            // A statement cannot start with a string literal: the old
            // `"get five".` / `"calc" of 3.` forms are gone (plan 270). A
            // string is data; a callee must be a bare or quoted identifier.
            Token::StringLiteral(s) => {
                let s = s.clone();
                Err(self.err_string_as_name(&s))
            }
            _ => Err(self.err_expected("a statement", self.current())),
        };

        // After parsing any statement, give it a chance to carry a `but if`/
        // `otherwise` conditional-sugar suffix.  This is the single central
        // hook that makes the *base* action generic; individual statement
        // parsers no longer need to repeat the suffix logic.  Loop-expansion
        // still handles its own `but if` because the suffix applies to the loop
        // action rather than the loop statement itself.
        //
        // `maybe_parse_conditional_suffix` restores parser position when no
        // suffix is present, and `suppress_conditional_suffix` keeps branch
        // bodies from consuming an outer chain's suffix.
        match stmt {
            Ok(base) => self.maybe_parse_conditional_suffix(base),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn parse_print(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        // `print` takes exactly one value. A loop expansion is that one
        // value: `print each X from Y`. Two or more `each` clauses would be
        // a grid, which is an arity error here, not a concatenation - the
        // one-value rule is what stops `print each x from A and each y from
        // B` being misread (plan 320 rule 4).
        if *self.current() == Token::Each {
            let clauses = self.parse_arg_clauses()?;
            if clauses.len() != 1 {
                return Err(self.one_slot_arity_error("print"));
            }
            // The first token was `each`, so the single clause is an
            // expansion. Match exhaustively so a fixed clause (unreachable
            // here, since `each` starts an expansion) still compiles cleanly.
            match &clauses[0] {
                ArgClause::Expansion((variable, collection, treating)) => {
                    let var_expr = Self::each_arg_expr(variable, treating);
                    let print_stmt = Statement::Print { value: var_expr, without_newline: false };
                    return self.wrap_in_loop_expansion(variable.clone(), collection.clone(), print_stmt);
                }
                ArgClause::Fixed(expr) => {
                    let print_stmt = Statement::Print { value: expr.clone(), without_newline: false };
                    return Ok(print_stmt);
                }
            }
        }

        // `print <func> of <args>`: the call's argument list may itself be a
        // grid of `each` clauses (`print pair of each x from A and each y
        // from B`), and `print` reports each result. Only entered when the
        // first argument is `each`; fixed-argument calls fall through to
        // `parse_expression`, which keeps the first-argument cast-level
        // binding (`print f of x add 1` is `f(x) add 1`, not `f(x add 1)`).
        if let Token::Identifier(func_name) = self.current().clone() {
            let saved_pos = self.pos;
            self.advance();
            self.skip_noise();

            if matches!(self.current(), Token::Of | Token::To | Token::With | Token::On) {
                self.advance();
                self.skip_noise();

                if *self.current() == Token::Each {
                    let clauses = self.parse_arg_clauses()?;
                    let (args, expansions) = Self::clauses_to_args_and_expansions(&clauses);
                    let func_call = Expr::FunctionCall { name: func_name, args };
                    let print_stmt = Statement::Print { value: func_call, without_newline: false };
                    return self.finish_grid(print_stmt, expansions);
                } else {
                    // Not a loop expansion, restore position and parse normally
                    self.pos = saved_pos;
                }
            } else {
                // Not a function call pattern, restore position
                self.pos = saved_pos;
            }
        }

        let value = self.parse_expression()?;
        
        // Check for "without newline" modifier
        self.skip_noise();
        let without_newline = if *self.current() == Token::Without {
            self.advance();
            self.skip_noise();
            // Expect "newline" after "without"
            if *self.current() == Token::Newline || 
               matches!(self.current(), Token::Identifier(s) if s.to_lowercase() == "newline") {
                self.advance();
                true
            } else {
                false
            }
        } else {
            false
        };
        
        Ok(Statement::Print { value, without_newline })
    }

    pub(crate) fn parse_return(&mut self) -> Result<Statement, Box<CompileError>> {
        // Where the `Return` itself sits, so a member definition handing back
        // the wrong thing can underline this line (plan 310 §4).
        let return_pos = self.pos;
        self.advance();
        self.skip_noise();

        if matches!(self.current(), Token::Period | Token::EOF | Token::Newline) {
            Ok(Statement::Return { value: None, declared_type: None })
        } else {
            // Handle "Return a type, expr." syntax (type declaration is optional)
            if matches!(self.current(), Token::A | Token::An) {
                self.advance();
                self.skip_noise();

                // Check if this is a type keyword followed by comma
                if let Some(declared_type) = self.declaration_type_token() {
                    self.advance();
                    self.skip_noise();

                    if *self.current() == Token::Comma {
                        self.advance();
                        self.skip_noise();
                        self.typed_returns
                            .push((return_pos, declared_type.clone()));
                        // Now parse the actual return expression. Use
                        // `parse_condition` (not `parse_expression`) so a typed
                        // return whose body is a comparison or boolean
                        // conjunction — `Return a boolean, A and B.` — parses
                        // the whole condition. `parse_expression` stops at
                        // `is`/`and`/`or`, which is why this only failed when
                        // the Return was NOT the function's first statement: the
                        // first-statement inline path in `parse_function_def`
                        // already uses `parse_condition`, so the two paths must
                        // agree.
                        let value = self.parse_condition()?;
                        return Ok(Statement::Return { value: Some(value), declared_type: Some(declared_type) });
                    }
                }
                // If not "a type,", backtrack isn't possible, so error
                return Err(self.err("Expected type after 'a' in return statement"));
            }

            // Match the inline first-statement path: parse the value as a
            // full condition so an untyped `Return A and B.` or `Return x is y.`
            // parses the same whether or not it is the first body statement.
            let value = self.parse_condition()?;
            Ok(Statement::Return { value: Some(value), declared_type: None })
        }
    }

    pub(crate) fn parse_exit(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume 'exit'
        self.skip_noise();
        
        // Allow optional 'with' keyword: "Exit with 1."
        if matches!(self.current(), Token::With) {
            self.advance();
            self.skip_noise();
        }
        
        // Parse exit code (default to 0 if not provided)
        let code = if matches!(self.current(), Token::Period | Token::EOF | Token::Newline) {
            Expr::IntegerLit(0)
        } else {
            self.parse_expression()?
        };
        
        Ok(Statement::Exit { code })
    }

    pub(crate) fn parse_allocate(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        let size = self.parse_primary()?;
        self.skip_noise();
        
        if *self.current() == Token::For {
            self.advance();
        }
        self.skip_noise();
        
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            _ => return Err(self.err("Expected variable name for allocation")),
        };
        
        Ok(Statement::Allocate { name, size })
    }

    pub(crate) fn parse_free(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        let name = self.parse_name()?;

        Ok(Statement::Free { name })
    }

    pub(crate) fn parse_increment(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();

        // Skip optional "the"
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }

        // `increment origin's x.` steps a field (plan 310 §3).
        if let Some((base, path, field_type)) = self.try_parse_thing_field_target()? {
            return Ok(Self::thing_field_step(
                base,
                path,
                &field_type,
                BinaryOperator::Add,
            ));
        }

        let name = self.parse_name()?;

        Ok(Statement::Increment { name })
    }

    pub(crate) fn parse_decrement(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();

        // Skip optional "the"
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }

        // `decrement cistern's 'litres drained'.` steps a field (plan 310 §3).
        if let Some((base, path, field_type)) = self.try_parse_thing_field_target()? {
            return Ok(Self::thing_field_step(
                base,
                path,
                &field_type,
                BinaryOperator::Subtract,
            ));
        }

        let name = self.parse_name()?;

        Ok(Statement::Decrement { name })
    }

    pub(crate) fn parse_identifier_statement(&mut self) -> Result<Statement, Box<CompileError>> {
        // `origin's 'shift east' on 2.` - the instance possessive stands where
        // an ordinary call statement stands (plan 310 §4). Tried first because
        // the write-target path below would otherwise report a call as a field
        // that does not exist; it rewinds and yields to that path for anything
        // that is not a call.
        if let Some(call) = self.try_parse_instance_call_statement()? {
            return Ok(call);
        }

        // `origin's y is origin's y add 1.` - a field is an lvalue in a bare
        // assignment too (plan 310 §3), so this is checked before the name is
        // read as a variable or a callee.
        if let Some((base, path, _)) = self.try_parse_thing_field_target()? {
            self.skip_noise();
            // `is`/`=` only, exactly like the bare assignment to a plain name
            // below - `to` is the `Set ... to ...` spelling's separator.
            if !matches!(self.current(), Token::Is | Token::Equals) {
                return Err(self.err_expected("'is' after a field of a thing", self.current()));
            }
            self.advance();
            self.skip_noise();
            let value = self.parse_expression()?;
            return Ok(Statement::SetThingField { base, path, value });
        }

        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            _ => return Err(self.err("Expected identifier")),
        };

        self.skip_noise();

        // Assignment: `name is value` / `name = value`.
        if matches!(self.current(), Token::Is | Token::Equals) {
            self.advance();
            self.skip_noise();
            // In-place retype of a `value` variable: `name is a number.`.
            // The same words in condition position (`If name is a number`)
            // still parse as a TypeCheck predicate because they go through
            // `parse_condition`, not this statement path.
            if let Some(target_type) = self.try_parse_scalar_type_noun_after_is() {
                return Ok(Statement::ValueRetype { name, target_type });
            }
            let value = self.parse_expression()?;
            if let Some(declaration) = self.thing_declaration_by_inference(&name, &value) {
                return Ok(declaration);
            }
            return Ok(Statement::Assignment { name, value });
        }

        // Call with arguments: `name of/with/to/on args ...` (plan 270 G1).
        // A bare or quoted identifier callee is accepted; a string literal
        // callee is rejected at the statement dispatch above. The argument
        // list is a sequence of clauses joined by `and`, each either a loop
        // expansion (`each X from Y`) or a fixed expression. The expansions
        // become nested loops - a Cartesian-product grid (plan 320).
        if matches!(self.current(), Token::Of | Token::To | Token::With | Token::On) {
            self.advance();
            self.skip_noise();

            let clauses = self.parse_arg_clauses()?;
            let (args, expansions) = Self::clauses_to_args_and_expansions(&clauses);
            // No expansion clauses: a plain fixed-argument call. It is not a
            // self-terminating statement, so leave the trailing period for
            // the caller - exactly as the old fixed-argument loop did.
            if expansions.is_empty() {
                return Ok(Statement::FunctionCall { name, args });
            }
            let call_stmt = Statement::FunctionCall { name, args };
            return self.finish_grid(call_stmt, expansions);
        }

        // A bare/quoted identifier immediately following the callee, with no
        // preposition between them, is not a genuine zero-argument call
        // (BUGS_FOUND #105): the writer meant to pass it as an argument and
        // dropped `of`/`to`/`with`/`on`. Left alone, this identifier falls
        // through to the statement-list loop, which finds no period where it
        // expects one and reads the identifier as an unrelated statement of
        // its own — the call then reports a wrong-arity error (0 seen) and
        // the identifier a second, unrelated one ("Unknown function"), with
        // neither naming the missing preposition. Caught here, at the token
        // that would have been misread, one diagnostic names the real cause
        // and the identifier is never parsed as anything else.
        if let Token::Identifier(next) = self.current().clone() {
            return Err(self.err(&format!(
                "'{}' follows the call with no preposition — arguments are \
                 introduced with 'of', 'to', 'with', or 'on'.",
                next
            )));
        }

        // Zero-argument call: `name.`
        Ok(Statement::FunctionCall {
            name,
            args: vec![],
        })
    }

    pub(crate) fn parse_wait(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume Wait/Sleep
        self.skip_noise();
        
        // Optional "for"
        self.expect(&Token::For);
        self.skip_noise();
        
        // Parse duration value
        let duration = self.parse_primary()?;
        self.skip_noise();
        
        // Parse unit: second(s), millisecond(s). `second` (singular) is a
        // contextual word — an ordinary identifier claimed here by lexeme
        // as the unit, so a variable named `second` coexists with the unit
        // (`Wait second seconds.` waits one second; `Set second to 1.` is
        // the variable). `seconds` (plural) stays a reserved token.
        let unit = match self.current() {
            Token::Seconds => {
                self.advance();
                ast::TimeUnit::Seconds
            }
            Token::Identifier(ref id) if id.to_lowercase() == "second" => {
                self.advance();
                ast::TimeUnit::Seconds
            }
            Token::Millisecond | Token::Milliseconds => {
                self.advance();
                ast::TimeUnit::Milliseconds
            }
            _ => return Err(self.err("Expected 'second', 'seconds', 'millisecond', or 'milliseconds' after duration")),
        };
        
        Ok(Statement::Wait { duration, unit })
    }

    pub(crate) fn parse_timer_start(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume the contextual start/begin identifier
        self.skip_noise();
        
        // Optional "the"
        self.expect(&Token::The);
        self.skip_noise();
        
        // Timer name (a bare or quoted identifier, never a string)
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
            _ => return Err(self.err("Expected timer name after 'start'")),
        };

        Ok(Statement::TimerStart { name })
    }

    pub(crate) fn parse_timer_stop(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume the contextual stop/finish identifier
        self.skip_noise();
        
        // Optional "the"
        self.expect(&Token::The);
        self.skip_noise();
        
        // Timer name (a bare or quoted identifier, never a string)
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
            _ => return Err(self.err("Expected timer name after 'stop'")),
        };

        Ok(Statement::TimerStop { name })
    }

    pub(crate) fn parse_get(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume Get
        self.skip_noise();
        
        // "Get current time into <name>"
        if *self.current() == Token::Current {
            self.advance();
            self.skip_noise();
            
            if *self.current() == Token::Time {
                self.advance();
                self.skip_noise();
                
                if *self.current() == Token::Into {
                    self.advance();
                    self.skip_noise();
                    
                    let name = match self.current().clone() {
                        Token::Identifier(n) => { self.advance(); n }
                        Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
                        _ => return Err(self.err("Expected variable name after 'into'")),
                    };

                    return Ok(Statement::GetTime { into: name });
                }
            }
        }
        
        Err(self.err("Expected 'current time into <name>' after 'get'"))
    }

}
