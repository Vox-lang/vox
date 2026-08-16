pub mod ast;

use crate::lexer::{Token, TokenInfo, Lexer};
use crate::errors::{CompileError, SourceLocation, SourceFile, find_similar_keyword, ENGLISH_KEYWORDS};
use ast::*;

// Type aliases for complex nested types
type TreatingClause = (Expr, Expr);
type LoopExpansion = (String, Expr, Option<TreatingClause>);
type PathInfo = Result<Expr, LoopExpansion>;

pub struct Parser {
    tokens: Vec<TokenInfo>,
    pos: usize,
    source_file: Option<SourceFile>,
    // True while parsing a sub-expression where `to`/`of` is reserved for an
    // enclosing statement's own grammar rather than available as this
    // sub-expression's call connector (plan 270 G1 made `to`/`of`/`with`
    // universal call connectors, which collides with older grammars that
    // already claim one of those words immediately after a value position:
    // the append separator `to`, a range bound's `to`, or an index's `of`).
    // Without this, e.g. the `id` in `append id of item to out` would
    // greedily read `to out` as its own call tail via the generic
    // `allow_to: true` path, leaving no `to` for the append statement
    // itself - see `parse_primary_reserving`.
    suppress_to_connector: bool,
    suppress_of_connector: bool,
    // True while parsing the body of one `but if`/`otherwise` branch.  The
    // branch is already inside the outer conditional-sugar chain, so any
    // `but if` suffix on the branch statement itself must be ignored; the
    // outer chain owns all of the conditions.  This keeps the branch parser
    // generic: it can hand any statement kind to the normal statement parser
    // and still not double-consume the chain.
    suppress_conditional_suffix: bool,
    // True when parsing a `--shared` library input. A library file is a
    // collection of function definitions and legitimately ends mid-body at
    // EOF (its last function has no trailing blank line), so the
    // "function still open at end of file" warning (BUGS_FOUND #5) is
    // suppressed in this mode — it only fires for an executable program,
    // where a function body that runs to EOF has almost certainly swallowed
    // the program's top-level entry code.
    shared_mode: bool,
    // True once a `Library <name> version "..."` declaration has been
    // parsed at the top level. A library file legitimately consists only
    // of function definitions with no top-level entry code, so its last
    // function body routinely runs to EOF with no closing blank line —
    // exactly the shape the BUGS_FOUND #5 "function still open at end of
    // file" warning misreads as "the program was swallowed". Like
    // `shared_mode`, this suppresses that warning, but it also covers the
    // case where a library file is compiled *without* `--shared` (e.g. the
    // `examples/` compile check in `test.sh`): a library with no
    // top-level entry is correct by construction, not a mistake.
    saw_library_decl: bool,
    // Non-fatal diagnostics collected during parsing (currently the #5
    // "function still open at end of file" warning). The driver prints
    // these after a successful parse; they never abort compilation.
    pub warnings: Vec<CompileError>,
}

#[cfg(test)]
mod buffer_copy_statement_tests;
#[cfg(test)]
mod file_line_read_and_seek_tests;
#[cfg(test)]
mod buffer_declaration_tests;
#[cfg(test)]
mod to_connector_tests;
#[cfg(test)]
mod possessive_property_unit_tests;
mod declarations;
mod io;
mod collections;

impl Parser {
    pub fn new(tokens: Vec<TokenInfo>) -> Self {
        Parser {
            tokens,
            pos: 0,
            source_file: None,
            suppress_to_connector: false,
            suppress_of_connector: false,
            suppress_conditional_suffix: false,
            shared_mode: false,
            saw_library_decl: false,
            warnings: Vec::new(),
        }
    }

    pub fn with_source(mut self, filename: &str, content: &str) -> Self {
        self.source_file = Some(SourceFile::new(filename, content));
        self
    }

    /// Mark this parse as a `--shared` library build, suppressing the
    /// "function still open at end of file" warning (legitimate for a
    /// library file whose last function has no trailing blank line).
    pub fn with_shared_mode(mut self, shared: bool) -> Self {
        self.shared_mode = shared;
        self
    }
    
    fn current(&self) -> &Token {
        self.tokens.get(self.pos).map(|t| &t.token).unwrap_or(&Token::EOF)
    }
    
    fn current_info(&self) -> Option<&TokenInfo> {
        self.tokens.get(self.pos)
    }
    
    fn current_location(&self) -> Option<SourceLocation> {
        if let (Some(info), Some(ref src)) = (self.current_info(), &self.source_file) {
            Some(src.make_location(info.line, info.column))
        } else {
            None
        }
    }

    /// Recover the identifier spelling the user actually wrote at the
    /// current token. The lexer canonicalises aliases (`length` →
    /// `Token::Size`, `ms` → `Token::Milliseconds`, …) so by the time
    /// `check_not_keyword` runs the original text is gone from the token;
    /// this reads it back from the source line so the diagnostic can name
    /// the word the user typed rather than the internal canonical keyword
    /// (BUGS_FOUND #6).
    fn current_lexeme(&self) -> Option<String> {
        let loc = self.current_location()?;
        let chars: Vec<char> = loc.line_content.chars().collect();
        let start = loc.column.saturating_sub(1);
        let mut iter = chars.into_iter().skip(start);
        let first = iter.next()?;
        if !(first.is_ascii_alphabetic() || first == '_') {
            return None;
        }
        let mut out = String::new();
        out.push(first);
        for c in iter {
            if c.is_ascii_alphanumeric() || c == '_' {
                out.push(c);
            } else {
                break;
            }
        }
        Some(out)
    }
    
    
    
    
    


    





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
    fn parse_call_tail(&mut self, name: String, allow_to: bool) -> Result<Option<Expr>, Box<CompileError>> {
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
    fn parse_primary_reserving(&mut self, to: bool, of: bool) -> Result<Expr, Box<CompileError>> {
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

    fn peek(&self, offset: usize) -> &Token {
        self.tokens.get(self.pos + offset).map(|t| &t.token).unwrap_or(&Token::EOF)
    }

    /// True when the token after the current one (skipping newline noise)
    /// can be the name operand of a timer statement: `the` or an
    /// identifier. Decides whether a statement-initial `start`/`begin`/
    /// `stop`/`finish` is a timer statement or an ordinary call.
    fn timer_name_follows(&self) -> bool {
        let mut off = 1;
        while matches!(self.peek(off), Token::Newline) {
            off += 1;
        }
        matches!(self.peek(off), Token::The | Token::Identifier(_))
    }
    
    fn advance(&mut self) -> Token {
        let tok = self.current().clone();
        self.pos += 1;
        tok
    }
    
    fn skip_noise(&mut self) {
        while matches!(self.current(), Token::Newline) {
            self.advance();
        }
    }
    
    fn skip_all_whitespace(&mut self) {
        while matches!(self.current(), Token::Newline | Token::ParagraphBreak) {
            self.advance();
        }
    }

    /// Consume a period only when it is the separator before an if-chain continuation
    /// (`but`, `else`, `otherwise`).
    fn consume_period_before_else_chain(&mut self) {
        if *self.current() != Token::Period {
            return;
        }

        let saved = self.pos;
        self.advance();
        self.skip_all_whitespace();

        if !matches!(self.current(), Token::But | Token::Else | Token::Otherwise) {
            self.pos = saved;
        }
    }
    
    #[allow(dead_code)]
    fn skip_newlines(&mut self) {
        while matches!(self.current(), Token::Newline | Token::ParagraphBreak) {
            self.advance();
        }
    }
    
    fn expect(&mut self, expected: &Token) -> bool {
        if self.current() == expected {
            self.advance();
            true
        } else {
            false
        }
    }
    
    pub fn parse(&mut self) -> Result<Program, Box<CompileError>> {
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
                    statements.push(stmt);
                    
                    if !is_func_def {
                        self.skip_noise();
                        self.expect(&Token::Period);
                    }
                }
                Err(e) => return Err(e),
            }
            
            self.skip_all_whitespace();
        }
        
        Ok(Program::new(statements))
    }
    
    fn parse_statement(&mut self) -> Result<Statement, Box<CompileError>> {
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

    
    fn parse_print(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        // Check for loop expansion: "print each X from Y [treating X as Y]"
        if let Some((variable, collection, treating)) = self.try_parse_each_from(false)? {
            // Create the variable expression, with optional treating substitution
            let var_expr = if let Some((match_val, replacement)) = treating {
                Expr::TreatingAs {
                    value: Box::new(Expr::Identifier(variable.clone())),
                    match_value: Box::new(match_val),
                    replacement: Box::new(replacement),
                }
            } else {
                Expr::Identifier(variable.clone())
            };
            let print_stmt = Statement::Print { value: var_expr, without_newline: false };
            return self.wrap_in_loop_expansion(variable, collection, print_stmt);
        }
        
        // Check for function call with loop expansion: "print func of each X from Y"
        // The callee is a bare or quoted identifier (plan 270). A string
        // literal here is data, not a callee; it is left for parse_expression
        // to handle as a value (and reject if followed by `of/with/to/on`).
        if let Token::Identifier(func_name) = self.current().clone() {
            let saved_pos = self.pos;
            self.advance();
            self.skip_noise();

            if matches!(self.current(), Token::Of | Token::To | Token::With | Token::On) {
                self.advance();
                self.skip_noise();

                // Check if next is "each" for loop expansion
                if let Some((variable, collection, treating)) = self.try_parse_each_from(false)? {
                    // Create function call with loop variable as argument
                    let arg_expr = if let Some((match_val, replacement)) = treating {
                        Expr::TreatingAs {
                            value: Box::new(Expr::Identifier(variable.clone())),
                            match_value: Box::new(match_val),
                            replacement: Box::new(replacement),
                        }
                    } else {
                        Expr::Identifier(variable.clone())
                    };
                    let func_call = Expr::FunctionCall {
                        name: func_name,
                        args: vec![arg_expr]
                    };
                    let print_stmt = Statement::Print { value: func_call, without_newline: false };
                    return self.wrap_in_loop_expansion(variable, collection, print_stmt);
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

    /// Detects an optional `, but if ...` / `but if ...` conditional-sugar
    /// suffix after a fully-parsed base statement and, if present, dispatches
    /// to `parse_conditional_suffix`.  If no `but if` follows, restores the
    /// parser position and returns `base` unchanged so outer constructs can
    /// consume the separator normally (e.g. a plain trailing comma belonging
    /// to an enclosing sentence-consuming construct).
    ///
    /// When `suppress_conditional_suffix` is set (while parsing a `but if`
    /// branch body), the suffix is ignored unconditionally so that the outer
    /// chain keeps ownership of every condition.
    fn maybe_parse_conditional_suffix(&mut self, base: Statement) -> Result<Statement, Box<CompileError>> {
        if self.suppress_conditional_suffix {
            return Ok(base);
        }

        let start_pos = self.pos;

        // The conditional continuation sugar is `but if ...` with an optional
        // leading comma. Consume the comma if present, but do not commit to it
        // until we see the `but if` that proves this is a suffix. A bare
        // `, if ... then, ...` is a nested `If` as the next item in an
        // enclosing comma-separated body, so we always restore `start_pos`
        // when `but if` is absent.
        if *self.current() == Token::Comma {
            self.advance();
            self.skip_noise();
        }

        if *self.current() == Token::But {
            self.advance();
            self.skip_noise();

            if *self.current() == Token::If {
                return self.parse_conditional_suffix(base);
            }
        }

        // Not a conditional continuation; restore parser position so
        // outer constructs can consume the separator normally.
        self.pos = start_pos;
        Ok(base)
    }

    /// Builds the nested `Statement::If` chain for `but if` conditional
    /// sugar. `base` is the already-parsed default statement (used as-is in
    /// the innermost `else`); each branch's own statement is parsed by
    /// `parse_conditional_branch` using the normal statement parser.
    fn parse_conditional_suffix(&mut self, base: Statement) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume 'if'
        self.skip_noise();

        let mut conditions = Vec::new();

        let cond = self.parse_condition()?;
        self.skip_noise();
        conditions.push((cond, self.parse_conditional_branch(&base)?));

        // Skip newlines before checking for continuation (allows multi-line but if)
        self.skip_noise();
        loop {
            // Check for continuation: comma, but, and — or a period that
            // belongs to a nested clause rather than closing the chain. Per
            // LANGUAGE.md termination rule 1, a period closes only the
            // innermost open clause; when the branch body opened its own
            // clause (e.g. `On error ...`), that period is *its* terminator,
            // not the chain's. Only treat the period as chain continuation
            // when it is immediately followed by `but` — a period with
            // nothing but blank-line/EOF/anything else after it still ends
            // the whole chain.
            if *self.current() == Token::Period {
                let saved = self.pos;
                self.advance();
                self.skip_noise();
                if *self.current() != Token::But {
                    self.pos = saved;
                    break;
                }
            } else if !matches!(self.current(), Token::But | Token::Comma | Token::And) {
                break;
            }

            // Remember if we started with comma (for ", but if" syntax)
            let started_with_comma = *self.current() == Token::Comma;
            self.advance();
            self.skip_noise();

            // After comma, we might have "but if" or just "if"
            if started_with_comma && *self.current() == Token::But {
                self.advance();
                self.skip_noise();
            }

            if *self.current() == Token::If {
                self.advance();
                self.skip_noise();
                let cond = self.parse_condition()?;
                self.skip_noise();
                conditions.push((cond, self.parse_conditional_branch(&base)?));
            } else if *self.current() == Token::Else || *self.current() == Token::Otherwise {
                self.advance();
                self.skip_noise();
                conditions.push((Expr::BoolLit(true), self.parse_conditional_branch(&base)?));
                break;
            } else {
                break;
            }
        }

        let mut result = base;

        for (cond, val) in conditions.into_iter().rev() {
            result = Statement::If {
                condition: cond,
                then_block: val,
                else_if_blocks: vec![],
                else_block: Some(vec![result]),
            };
        }

        Ok(result)
    }

    /// Parses one `but if`/`otherwise` branch's body.
    ///
    /// A branch body can be more than one action — `open a file ..., On
    /// error print ...` is the fallible-action-plus-handler shape (bug
    /// #14). We reuse `parse_block`'s comma-separated, on-error-aware body
    /// parser so a branch can hold its own trailing clause the same way an
    /// `If`/`otherwise if` branch does, with conditional-suffix parsing
    /// suppressed so that chained `but if`s stay owned by the outer
    /// `parse_conditional_suffix` loop. `parse_block` leaves a genuinely
    /// chain-ending terminator (period, paragraph break, EOF) for the
    /// caller — it does not consume it.
    ///
    /// The only special case is the terse `append <value>` form, where the
    /// branch may omit `to <name>` and inherit the base statement's target.
    /// That inheritance is handled here as a narrow fallback rather than a
    /// growing match over every statement kind.
    fn parse_conditional_branch(
        &mut self,
        base: &Statement,
    ) -> Result<Vec<Statement>, Box<CompileError>> {
        // The terse append form is the one place where a branch is allowed to
        // leave out a target and inherit it from the base.  `append <value>`
        // is not a valid standalone statement (the full grammar requires
        // `to <list>`), so it cannot be handed to the generic parser.
        if *self.current() == Token::Append {
            return Ok(vec![self.parse_terse_append_branch(base)?]);
        }

        // Every other branch body is parsed like an `If` branch, but with
        // conditional-suffix parsing disabled so that chained `but if`s are
        // owned by the outer `parse_conditional_suffix` loop.
        let saved = self.suppress_conditional_suffix;
        self.suppress_conditional_suffix = true;
        let result = self.parse_block();
        self.suppress_conditional_suffix = saved;
        result
    }

    /// Parses `append <value> [to <name>]` as a `but if`/`otherwise` branch.
    /// The target is optional when the base statement is an append whose
    /// target can be inherited; if the branch does name a target, it must
    /// match the base's.  If the base is not an append statement, an
    /// explicit target is required.
    fn parse_terse_append_branch(
        &mut self,
        base: &Statement,
    ) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume 'append'
        self.skip_noise();

        let mut value = self.parse_append_value_primary()?;
        value = self.parse_append_value_ops(value, 0)?;
        self.skip_noise();

        // Optional type predicate on the append value, e.g.
        // `append item is a number to flags`.
        if matches!(self.current(), Token::Is | Token::Are) {
            self.advance();
            self.skip_noise();
            let negated = *self.current() == Token::Not;
            if negated {
                self.advance();
                self.skip_noise();
            }
            if !matches!(self.current(), Token::A | Token::An) {
                return Err(self.err(
                    "Expected 'a'/'an' and a type noun after 'is' in append value"
                ));
            }
            let type_noun = self.parse_type_noun_after_article()?;
            let check = Expr::TypeCheck {
                value: Box::new(value),
                type_noun,
            };
            value = if negated {
                Expr::UnaryOp { op: UnaryOperator::Not, operand: Box::new(check) }
            } else {
                check
            };
        }

        self.skip_noise();

        // Resolve the target: inherit from the base if omitted, or check that
        // an explicit target matches the base's list/buffer.
        let list = if *self.current() == Token::To {
            self.advance();
            self.skip_noise();
            let target = match self.current().clone() {
                Token::Identifier(n) => { self.advance(); n }
                Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
                Token::The => {
                    self.advance();
                    self.skip_noise();
                    match self.current().clone() {
                        Token::Identifier(n) => { self.advance(); n }
                        Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
                        _ => return Err(self.err("Expected list name after 'the'")),
                    }
                }
                _ => return Err(self.err("Expected list name after 'to' in 'but if' branch")),
            };

            if let Statement::ListAppend { list: base_list, .. } = base {
                if target != *base_list {
                    return Err(self.err(&format!(
                        "'but if' append branch targets '{}', but the base statement targets '{}' — \
                         a conditional append branch cannot retarget to a different list/buffer",
                        target, base_list
                    )));
                }
                base_list.clone()
            } else {
                // The base is not an append, so the branch is fully explicit.
                target
            }
        } else if let Statement::ListAppend { list, .. } = base {
            // Terse form: no `to` on the branch, inherit from the base.
            list.clone()
        } else {
            return Err(self.err(
                "Expected 'to <list>' after value in 'but if' append branch"
            ));
        };

        Ok(Statement::ListAppend { list, value })
    }






    
    fn parse_if(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        let condition = self.parse_condition()?;
        self.skip_noise();
        
        self.expect(&Token::Then);
        self.expect(&Token::Comma);
        self.skip_noise();
        
        let then_block = self.parse_block()?;
        
        let mut else_if_blocks = Vec::new();
        let mut else_block = None;
        
        self.skip_noise();
        self.consume_period_before_else_chain();

        while matches!(self.current(), Token::But | Token::Else | Token::Otherwise) {
            self.advance();
            self.skip_noise();

            if *self.current() == Token::If || *self.current() == Token::When {
                self.advance();
                self.skip_noise();
                let cond = self.parse_condition()?;
                self.skip_noise();
                self.expect(&Token::Then);
                self.expect(&Token::Comma);
                self.skip_noise();
                let block = self.parse_block()?;
                else_if_blocks.push((cond, block));
                self.skip_noise();
                self.consume_period_before_else_chain();
            } else {
                self.expect(&Token::Comma);
                self.skip_noise();
                // Else block consumes the rest of the sentence (comma-separated
                // actions, ending at the first top-level period). A nested `If`
                // that owns its own trailing period is parsed as a single action.
                let block = self.parse_sentence_body()?;
                else_block = Some(block);
                break;
            }
        }

        // Standalone if-sentences own their trailing period.
        // This prevents outer sentence-consuming constructs (e.g., while/for)
        // from treating the inner if's period as their own terminator.
        if *self.current() == Token::Period {
            self.advance();
            self.skip_noise();
        }
        
        Ok(Statement::If {
            condition,
            then_block,
            else_if_blocks,
            else_block,
        })
    }
    
    fn parse_while(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        let condition = self.parse_condition()?;
        self.skip_noise();
        self.expect(&Token::Comma);
        self.skip_noise();
        
        // Parse body: comma continues actions, period ends this while statement.
        // Paragraph breaks are visual spacing and may appear after commas.
        let mut body = Vec::new();
        loop {
            if *self.current() == Token::EOF {
                break;
            }
            if !body.is_empty() && self.is_block_terminator() {
                break;
            }
            
            let stmt = self.parse_statement()?;
            body.push(stmt);
            self.skip_noise();
            
            // Consume separator and decide whether to continue
            if *self.current() == Token::Comma {
                // Comma continues to next action in same sentence
                self.advance();
                self.skip_noise();
                // Skip paragraph breaks after comma (visual spacing within sentence)
                while *self.current() == Token::ParagraphBreak {
                    self.advance();
                    self.skip_noise();
                }
            } else if *self.current() == Token::Period {
                self.advance();
                self.skip_noise();
                break;
            } else if *self.current() == Token::ParagraphBreak {
                break;
            } else if *self.current() == Token::EOF {
                break;
            }
        }
        
        Ok(Statement::While { condition, body })
    }
    
    /// Check if current token indicates end of a loop body inside a function
    /// Only Return truly ends a loop body - other statements can be part of the loop
    fn is_block_terminator(&self) -> bool {
        matches!(self.current(), Token::Return)
    }
    
    fn parse_for(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        if *self.current() != Token::Each {
            return Err(self.err(
                "Expected 'each' after 'for'\n  \
                 Syntax: For each <variable> from <start> to <end>, <action>.\n  \
                 Example: For each number from 1 to 10, print the number."
            ));
        }
        self.advance();
        self.skip_noise();
        
        let variable = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::Number => { self.advance(); "number".to_string() }
            Token::StringLiteral(s) => return Err(self.err_string_as_name(&s)),
            _ => return Err(self.err(
                "Missing loop variable after 'for each'\n  \
                 Syntax: For each <variable> from <start> to <end>, <action>.\n  \
                 Example: For each number from 1 to 10, print the number."
            )),
        };
        
        self.skip_noise();
        
        if *self.current() == Token::From || *self.current() == Token::Between {
            let inclusive = true;
            self.advance();
            self.skip_noise();

            let start = self.parse_primary_reserving(true, false)?;
            self.skip_noise();

            // Check if this is a range (has "to") or a collection iteration
            if *self.current() == Token::To || matches!(self.current(), Token::Identifier(s) if s == "to") {
                // Range: from X to Y
                self.advance(); // consume "to"
                self.skip_noise();
                
                let end = self.parse_primary()?;
                self.skip_noise();
                self.expect(&Token::Comma);
                self.skip_noise();
                
                // Parse body - terminated by period (single sentence loop body)
                let mut body = Vec::new();
                loop {
                    if matches!(self.current(), Token::EOF) {
                        break;
                    }
                    if !body.is_empty() && matches!(self.current(), Token::ParagraphBreak) {
                        break;
                    }
                    
                    let stmt = self.parse_statement()?;
                    body.push(stmt);
                    self.skip_noise();
                    
                    if *self.current() == Token::Comma {
                        // Comma continues to next action in same for loop
                        self.advance();
                        self.skip_noise();
                    } else if *self.current() == Token::Period {
                        // Period ends this for loop's body
                        self.advance();
                        self.skip_noise();
                        break;
                    } else if *self.current() == Token::ParagraphBreak {
                        break;
                    }
                }
                
                Ok(Statement::ForRange {
                    variable,
                    range: Expr::Range {
                        start: Box::new(start),
                        end: Box::new(end),
                        inclusive,
                    },
                    body,
                })
            } else {
                // Collection iteration: from <collection>
                // start is actually the collection
                let collection = match start {
                    Expr::StringLit(s) => Expr::Identifier(s),
                    other => other,
                };
                
                // Check for optional "treating X as Y" clause before the comma
                let treating = self.try_parse_treating()?;
                
                self.expect(&Token::Comma);
                self.skip_noise();
                
                // Parse body - terminated by period
                let mut body = Vec::new();
                loop {
                    if matches!(self.current(), Token::EOF) {
                        break;
                    }
                    if !body.is_empty() && matches!(self.current(), Token::ParagraphBreak) {
                        break;
                    }
                    
                    let stmt = self.parse_statement()?;
                    body.push(stmt);
                    self.skip_noise();
                    
                    if *self.current() == Token::Comma {
                        self.advance();
                        self.skip_noise();
                    } else if *self.current() == Token::Period {
                        self.advance();
                        self.skip_noise();
                        break;
                    } else if *self.current() == Token::ParagraphBreak {
                        break;
                    }
                }
                
                // If treating clause present, wrap variable references in body
                let body = if let Some((match_val, replacement)) = treating {
                    self.apply_treating_to_body(body, &variable, match_val, replacement)
                } else {
                    body
                };
                
                Ok(Statement::ForEach {
                    variable,
                    collection,
                    body,
                })
            }
        } else if *self.current() == Token::In {
            self.advance();
            self.skip_noise();
            
            // Parse collection - convert StringLit to Identifier (quoted var names)
            let collection = match self.parse_expression()? {
                Expr::StringLit(s) => Expr::Identifier(s),
                other => other,
            };
            self.skip_noise();
            self.expect(&Token::Comma);
            self.skip_noise();
            
            // Parse body - terminated by period (single sentence loop body)
            let mut body = Vec::new();
            loop {
                if matches!(self.current(), Token::EOF) {
                    break;
                }
                if !body.is_empty() && matches!(self.current(), Token::ParagraphBreak) {
                    break;
                }
                
                let stmt = self.parse_statement()?;
                body.push(stmt);
                self.skip_noise();
                
                if *self.current() == Token::Comma {
                    // Comma continues to next action in same for loop
                    self.advance();
                    self.skip_noise();
                } else if *self.current() == Token::Period {
                    // Period ends this for loop's body
                    self.advance();
                    self.skip_noise();
                    break;
                } else if *self.current() == Token::ParagraphBreak {
                    break;
                }
            }
            
            Ok(Statement::ForEach {
                variable,
                collection,
                body,
            })
        } else {
            Err(self.err("Expected 'from', 'between', or 'in' after for each"))
        }
    }
    
    fn parse_repeat(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        let count = self.parse_primary()?;
        self.skip_noise();
        self.expect(&Token::Times);
        self.skip_noise();
        self.expect(&Token::Comma);
        self.skip_noise();
        
        // Parse body - terminated by period followed by major keyword or paragraph break
        let mut body = Vec::new();
        loop {
            if matches!(self.current(), Token::ParagraphBreak | Token::EOF) {
                break;
            }
            if !body.is_empty() && self.is_block_terminator() {
                break;
            }
            
            let stmt = self.parse_statement()?;
            body.push(stmt);
            self.skip_noise();
            
            if matches!(self.current(), Token::Period) {
                self.advance();
                self.skip_noise();
                if self.is_block_terminator() || matches!(self.current(), Token::ParagraphBreak | Token::EOF) {
                    break;
                }
            }
        }
        
        Ok(Statement::Repeat { count, body })
    }


    fn parse_return(&mut self) -> Result<Statement, Box<CompileError>> {
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
    
    fn parse_exit(&mut self) -> Result<Statement, Box<CompileError>> {
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
    
    fn parse_allocate(&mut self) -> Result<Statement, Box<CompileError>> {
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
    
    fn parse_free(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        let name = self.parse_name()?;

        Ok(Statement::Free { name })
    }

    fn parse_increment(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();

        // Skip optional "the"
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }

        let name = self.parse_name()?;

        Ok(Statement::Increment { name })
    }

    fn parse_decrement(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();

        // Skip optional "the"
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }

        let name = self.parse_name()?;

        Ok(Statement::Decrement { name })
    }
    
    // File I/O parsing functions
    
    
    /// Try to parse optional "treating X as Y" clause.
    /// Returns Some((match_value, replacement)) if found, None otherwise.
    fn try_parse_treating(&mut self) -> Result<Option<TreatingClause>, Box<CompileError>> {
        if *self.current() != Token::Treating {
            return Ok(None);
        }
        self.advance();
        self.skip_noise();
        
        // Parse match value (simple scalar expressions)
        let match_value = match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); self.string_value_expr(s) }
            Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
            Token::IntegerLiteral(n) => { self.advance(); Expr::IntegerLit(n) }
            Token::FloatLiteral(n) => { self.advance(); Expr::FloatLit(n) }
            Token::True => { self.advance(); Expr::BoolLit(true) }
            Token::False => { self.advance(); Expr::BoolLit(false) }
            _ => return Err(self.err(
                "Missing match value after 'treating'\n  \
                 Syntax: treating <match> as <replacement>\n  \
                 Example: treating \"-\" as \"/dev/stdin\""
            )),
        };
        self.skip_noise();
        
        // Expect "as"
        let has_as = if *self.current() == Token::As {
            self.advance();
            self.skip_noise();
            true
        } else if let Token::Identifier(s) = self.current() {
            if s.to_lowercase() == "as" {
                self.advance();
                self.skip_noise();
                true
            } else {
                false
            }
        } else {
            false
        };
        
        if !has_as {
            return Err(self.err(&format!(
                "Missing 'as' after 'treating {:?}'\n  \
                 Syntax: treating <match> as <replacement>\n  \
                 Example: treating \"-\" as \"/dev/stdin\"",
                match_value
            )));
        }
        
        // Parse replacement (simple scalar expressions)
        let replacement = match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); self.string_value_expr(s) }
            Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
            Token::IntegerLiteral(n) => { self.advance(); Expr::IntegerLit(n) }
            Token::FloatLiteral(n) => { self.advance(); Expr::FloatLit(n) }
            Token::True => { self.advance(); Expr::BoolLit(true) }
            Token::False => { self.advance(); Expr::BoolLit(false) }
            _ => return Err(self.err(
                "Missing replacement value after 'as'\n  \
                 Syntax: treating <match> as <replacement>\n  \
                 Example: treating \"-\" as \"/dev/stdin\" (or treating \"-\" as 0 for fd stdin)"
            )),
        };
        self.skip_noise();
        
        Ok(Some((match_value, replacement)))
    }
    
    /// Apply treating substitution to all references of a variable in a statement body.
    /// Wraps Identifier references to the variable with TreatingAs expressions.
    fn apply_treating_to_body(&self, body: Vec<Statement>, variable: &str, match_val: Expr, replacement: Expr) -> Vec<Statement> {
        body.into_iter().map(|stmt| {
            self.apply_treating_to_statement(stmt, variable, &match_val, &replacement)
        }).collect()
    }
    
    fn apply_treating_to_statement(&self, stmt: Statement, variable: &str, match_val: &Expr, replacement: &Expr) -> Statement {
        match stmt {
            Statement::Print { value, without_newline } => {
                Statement::Print {
                    value: self.apply_treating_to_expr(value, variable, match_val, replacement),
                    without_newline,
                }
            }
            Statement::If { condition, then_block, else_if_blocks, else_block } => {
                Statement::If {
                    condition: self.apply_treating_to_expr(condition, variable, match_val, replacement),
                    then_block: self.apply_treating_to_body(then_block, variable, match_val.clone(), replacement.clone()),
                    else_if_blocks: else_if_blocks.into_iter().map(|(cond, block)| {
                        (self.apply_treating_to_expr(cond, variable, match_val, replacement),
                         self.apply_treating_to_body(block, variable, match_val.clone(), replacement.clone()))
                    }).collect(),
                    else_block: else_block.map(|b| self.apply_treating_to_body(b, variable, match_val.clone(), replacement.clone())),
                }
            }
            Statement::Assignment { name, value } => {
                Statement::Assignment {
                    name,
                    value: self.apply_treating_to_expr(value, variable, match_val, replacement),
                }
            }
            Statement::FunctionCall { name, args } => {
                Statement::FunctionCall {
                    name,
                    args: args.into_iter().map(|a| self.apply_treating_to_expr(a, variable, match_val, replacement)).collect(),
                }
            }
            Statement::FileWrite { file, value } => {
                Statement::FileWrite {
                    file,
                    value: self.apply_treating_to_expr(value, variable, match_val, replacement),
                }
            }
            other => other,
        }
    }
    
    fn apply_treating_to_expr(&self, expr: Expr, variable: &str, match_val: &Expr, replacement: &Expr) -> Expr {
        match expr {
            Expr::Identifier(ref name) if name == variable => {
                Expr::TreatingAs {
                    value: Box::new(expr),
                    match_value: Box::new(match_val.clone()),
                    replacement: Box::new(replacement.clone()),
                }
            }
            Expr::FormatString { parts } => {
                Expr::FormatString {
                    parts: parts.into_iter().map(|part| {
                        match part {
                            FormatPart::Expression { expr, format } => {
                                FormatPart::Expression {
                                    expr: Box::new(self.apply_treating_to_expr(*expr, variable, match_val, replacement)),
                                    format,
                                }
                            }
                            FormatPart::Variable { name, format } if name == variable => {
                                FormatPart::Expression {
                                    expr: Box::new(Expr::TreatingAs {
                                        value: Box::new(Expr::Identifier(name)),
                                        match_value: Box::new(match_val.clone()),
                                        replacement: Box::new(replacement.clone()),
                                    }),
                                    format,
                                }
                            }
                            other => other,
                        }
                    }).collect()
                }
            }
            Expr::BinaryOp { left, op, right } => {
                Expr::BinaryOp {
                    left: Box::new(self.apply_treating_to_expr(*left, variable, match_val, replacement)),
                    op,
                    right: Box::new(self.apply_treating_to_expr(*right, variable, match_val, replacement)),
                }
            }
            other => other,
        }
    }
    
    /// Try to parse "each <variable> from <collection> [treating X as Y]" pattern.
    /// Returns Some((variable, collection, optional_treating)) if found.
    /// This is the universal loop expansion syntax that works with any action.
    /// Parse `each <var> from <collection>`. When `expect_trailing_to` is set
    /// (the append statement), a `to <dest>` clause follows the collection, so
    /// a range source (`from 1 to 5 to rl`, two `to`s) must be told apart from
    /// a list source (`from source to dest`, one `to`).
    fn try_parse_each_from(&mut self, expect_trailing_to: bool) -> Result<Option<LoopExpansion>, Box<CompileError>> {
        if *self.current() != Token::Each {
            return Ok(None);
        }
        
        self.advance(); // consume 'each'
        self.skip_noise();
        
        // Get loop variable name
        let variable = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::Number => { self.advance(); "number".to_string() }
            Token::StringLiteral(s) => return Err(self.err_string_as_name(&s)),
            _ => return Err(self.err(
                "Missing loop variable after 'each'\n  \
                 Syntax: each <variable> from <collection>\n  \
                 Example: each filename from arguments's all"
            )),
        };
        
        self.skip_noise();
        
        // Expect "from"
        if *self.current() != Token::From {
            return Err(self.err(&format!(
                "Missing 'from' after 'each {}'\n  \
                 Syntax: each {} from <collection>\n  \
                 Example: each {} from arguments's all",
                variable, variable, variable
            )));
        }
        self.advance();
        self.skip_noise();
        
        // Get collection to iterate over - could be a range (1 to 15) or a collection expression
        // First parse a primary/simple expression. `to` is reserved here
        // (not available as a nested call connector) because the very next
        // check is for a literal `to` marking either a range bound or, in
        // append-each position, the append separator itself.
        let first = self.parse_primary_reserving(true, false)?;
        self.skip_noise();

        // Check if this is a range: <start> to <end>
        // But only if first is a simple value (number/identifier), not a list or other collection
        let is_list_or_collection = matches!(first, Expr::ListLit { .. } | Expr::PropertyAccess { .. });
        let collection = if *self.current() == Token::To && !is_list_or_collection {
            if expect_trailing_to {
                // Range source (`from 1 to 5 to rl`) vs list source
                // (`from source to dest`): parse the would-be range end
                // speculatively and keep the range only when a second `to`
                // follows. Otherwise the first `to` is the caller's
                // separator - rewind and leave it for the caller. `to` stays
                // reserved for `end` too, so it can't eat the second `to`
                // this disambiguation depends on.
                let saved = self.pos;
                self.advance();
                self.skip_noise();
                let end = self.parse_primary_reserving(true, false)?;
                self.skip_noise();
                if *self.current() == Token::To {
                    Expr::Range {
                        start: Box::new(first),
                        end: Box::new(end),
                        inclusive: true,
                    }
                } else {
                    self.pos = saved;
                    first
                }
            } else {
                self.advance();
                self.skip_noise();
                let end = self.parse_primary_reserving(true, false)?;
                self.skip_noise();
                Expr::Range {
                    start: Box::new(first),
                    end: Box::new(end),
                    inclusive: true,
                }
            }
        } else {
            // Not a range - could be a more complex expression, but we already have first
            // Check if there are binary operators to continue parsing
            first
        };
        self.skip_noise();
        
        // Check for optional "treating X as Y" clause
        let treating = self.try_parse_treating()?;
        
        Ok(Some((variable, collection, treating)))
    }
    
    /// Wrap a statement in a ForEach loop with the given variable and collection.
    /// Parses any additional comma-separated statements as part of the loop body.
    /// Supports "but if" conditional branching for any action in the loop.
    fn wrap_in_loop_expansion(&mut self, variable: String, collection: Expr, base_stmt: Statement) -> Result<Statement, Box<CompileError>> {
        let mut body = vec![base_stmt];

        // Check for comma to parse additional body statements or "but if" conditionals
        if *self.current() == Token::Comma {
            self.advance();
            self.skip_noise();

            // Check for "but if" conditional branching (wraps the base statement
            // in a conditional chain, regardless of what kind of statement it is).
            if *self.current() == Token::But {
                self.advance();
                self.skip_noise();

                if *self.current() == Token::If {
                    let base_stmt = body.pop().unwrap();
                    let conditional_stmt = self.parse_conditional_suffix(base_stmt)?;
                    body.push(conditional_stmt);
                } else {
                    return Err(self.err("Expected 'if' after 'but'"));
                }
            } else {
                // Parse remaining statements in the sentence
                loop {
                    if matches!(self.current(), Token::EOF) {
                        break;
                    }
                    if *self.current() == Token::ParagraphBreak {
                        self.advance();
                        self.skip_noise();
                        continue;
                    }
                    if *self.current() == Token::Period {
                        break;
                    }
                    
                    let stmt = self.parse_statement()?;
                    body.push(stmt);
                    self.skip_noise();
                    
                    if *self.current() == Token::Comma {
                        self.advance();
                        self.skip_noise();
                        // Paragraph breaks are visual spacing and may appear after commas.
                        while *self.current() == Token::ParagraphBreak {
                            self.advance();
                            self.skip_noise();
                        }
                    } else if *self.current() == Token::ParagraphBreak {
                        self.advance();
                        self.skip_noise();
                    }
                }
            }
        }
        
        // Consume period if present
        if *self.current() == Token::Period {
            self.advance();
            self.skip_noise();
        }
        
        // Use ForRange for range collections, ForEach otherwise
        match collection {
            Expr::Range { .. } => Ok(Statement::ForRange {
                variable,
                range: collection,
                body,
            }),
            _ => Ok(Statement::ForEach {
                variable,
                collection,
                body,
            }),
        }
    }
    

    
    
    







    // Filesystem operations parsing





    fn parse_on_error(&mut self) -> Result<Statement, Box<CompileError>> {
        // "On error <action>, <action>, <action>." - consumes full sentence
        self.advance(); // consume 'on'
        self.skip_noise();
        
        if *self.current() != Token::Error {
            return Err(self.err(
                "Expected 'error' after 'on'\n  \
                 Syntax: On error <action>.\n  \
                 Example: On error print \"Something went wrong\", exit 1."
            ));
        }
        self.advance();
        self.skip_noise();
        
        // Parse comma-separated actions until end of sentence
        let actions = self.parse_sentence_body()?;
        
        if actions.is_empty() {
            return Err(self.err(
                "Missing action after 'on error'\n  \
                 Syntax: On error <action>.\n  \
                 Example: On error print \"Read failed\", exit 1."
            ));
        }
        
        Ok(Statement::OnError { actions })
    }
    
    fn parse_auto_error(&mut self) -> Result<Statement, Box<CompileError>> {
        // Feature deferred - auto error catching not yet implemented
        Err(self.err(
            "'auto error catching' is not yet implemented.\n  \
             Use 'on error <action>.' for manual error handling instead."
        ))
    }
    
    fn parse_enable(&mut self) -> Result<Statement, Box<CompileError>> {
        // Feature deferred - enable error catching not yet implemented
        Err(self.err(
            "'enable error catching' is not yet implemented.\n  \
             Use 'on error <action>.' for manual error handling instead."
        ))
    }
    
    fn parse_disable(&mut self) -> Result<Statement, Box<CompileError>> {
        // Feature deferred - disable error catching not yet implemented
        Err(self.err(
            "'disable error catching' is not yet implemented.\n  \
             Use 'on error <action>.' for manual error handling instead."
        ))
    }
    
    




    
    fn parse_library_decl(&mut self) -> Result<Statement, Box<CompileError>> {
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

        // Parse version — a string literal.
        let version = if *self.current() == Token::Version {
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
    
    fn parse_see(&mut self) -> Result<Statement, Box<CompileError>> {
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
            if matches!(self.peek(k), Token::Version) {
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

        if *self.current() == Token::Version {
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

        Ok(Statement::See { path, lib_name, lib_version })
    }
    

    fn parse_identifier_statement(&mut self) -> Result<Statement, Box<CompileError>> {
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
            return Ok(Statement::Assignment { name, value });
        }

        // Call with arguments: `name of/with/to/on args ...` (plan 270 G1).
        // A bare or quoted identifier callee is accepted; a string literal
        // callee is rejected at the statement dispatch above.
        if matches!(self.current(), Token::Of | Token::To | Token::With | Token::On) {
            self.advance();
            self.skip_noise();

            // Loop-expansion: `name of each X from Y [treating X as Y]`.
            if let Some((variable, collection, treating)) = self.try_parse_each_from(false)? {
                let arg_expr = if let Some((match_val, replacement)) = treating {
                    Expr::TreatingAs {
                        value: Box::new(Expr::Identifier(variable.clone())),
                        match_value: Box::new(match_val),
                        replacement: Box::new(replacement),
                    }
                } else {
                    Expr::Identifier(variable.clone())
                };
                let call_stmt = Statement::FunctionCall {
                    name: name.clone(),
                    args: vec![arg_expr],
                };
                return self.wrap_in_loop_expansion(variable, collection, call_stmt);
            }

            let mut args = Vec::new();
            loop {
                let arg = self.parse_expression()?;
                args.push(arg);

                self.skip_noise();
                if *self.current() == Token::And {
                    self.advance();
                    self.skip_noise();
                } else {
                    break;
                }
            }
            return Ok(Statement::FunctionCall { name, args });
        }

        // Zero-argument call: `name.`
        Ok(Statement::FunctionCall {
            name,
            args: vec![],
        })
    }
    
    fn parse_function_def(&mut self) -> Result<Statement, Box<CompileError>> {
        // Location of the `To` keyword, used by the "function still open at
        // end of file" warning (BUGS_FOUND #5) to point at the definition.
        let def_loc = self.current_location();
        self.advance(); // consume 'To'
        self.skip_noise();
        
        // Get function name: a bare or quoted identifier (plan 270). A string
        // literal here is rejected with the §S1.5 diagnostic.
        let name = self.parse_name().or_else(|e| {
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
        })?;
        
        self.skip_noise();
        
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
                    self.advance();
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
                    
                    let param_name = self.parse_name()?;

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
        
        Ok(Statement::FunctionDef {
            name,
            params,
            return_type,
            body,
            body_ended_early,
        })
    }

    /// Parse the body of an `If`/`otherwise if` branch.
    ///
    /// A branch body is a comma-separated sequence of statements. Each statement
    /// may itself be a nested construct (e.g. another `If`) that owns its own
    /// trailing period. The body ends when we reach a top-level else-chain
    /// keyword (`But`, `Else`, `Otherwise`), `EOF`, or a paragraph break. A
    /// trailing comma immediately before the boundary is allowed.
    fn parse_block(&mut self) -> Result<Vec<Statement>, Box<CompileError>> {
        let mut statements = Vec::new();

        loop {
            // The next token starts the enclosing `If`'s else-chain, or we
            // have reached the end of the input.
            if matches!(
                self.current(),
                Token::But | Token::Else | Token::Otherwise | Token::EOF
            ) {
                break;
            }

            let stmt = self.parse_statement()?;
            let is_on_error = matches!(stmt, Statement::OnError { .. });
            // A self-terminating nested construct (If/While/For) consumes its
            // own trailing period; see the note below for why we track this.
            let is_self_terminated = matches!(
                stmt,
                Statement::If { .. } | Statement::While { .. }
                    | Statement::ForRange { .. } | Statement::ForEach { .. }
            );
            statements.push(stmt);

            self.skip_noise();

            // `On error` can chain directly into the next action without an
            // intervening comma or period.
            if is_on_error {
                if matches!(
                    self.current(),
                    Token::But
                        | Token::Else
                        | Token::Otherwise
                        | Token::EOF
                        | Token::Period
                        | Token::ParagraphBreak
                ) {
                    break;
                }
                continue;
            }

            // A self-terminating nested construct — `If`, `While`, `For each`,
            // `For ... to` — owns and consumes its own trailing period (see
            // `parse_if`'s final period consume, and the body loops in
            // `parse_while`/`parse_for`). When such a construct is an action in
            // a comma-separated branch, the next action therefore follows with
            // NO comma separator: the nested construct's period already served
            // as the separator. Without this, a complete nested `If ... then,
            // X.` followed by another action in the same branch would orphan
            // that action (and every later one), closing the enclosing
            // statement early. Only continue when the next token genuinely
            // starts another action; boundaries (else-chain, period, comma,
            // paragraph, EOF) are handled by the loop top or the arms below.
            if is_self_terminated && !matches!(
                self.current(),
                Token::Comma
                    | Token::Period
                    | Token::ParagraphBreak
                    | Token::EOF
                    | Token::But
                    | Token::Else
                    | Token::Otherwise
            ) {
                continue;
            }

            // A comma continues the body, a period ends the current statement
            // and therefore the body (the period is left for the caller so
            // standalone `if` sentences can own their own terminator).
            if *self.current() == Token::Comma {
                self.advance();
                self.skip_all_whitespace();

                // Trailing comma right before the else-chain boundary.
                if matches!(
                    self.current(),
                    Token::But | Token::Else | Token::Otherwise | Token::EOF | Token::ParagraphBreak
                ) {
                    break;
                }

                continue;
            }

            // Period, paragraph break, EOF, or an unexpected token ends the
            // body. Leave the terminator for the caller.
            break;
        }

        Ok(statements)
    }
    
    /// Parse comma-separated statements until end of sentence (period).
    /// This is the standard pattern for action-consuming constructs like:
    /// - on error <action>, <action>, <action>.
    /// - while <cond>, <action>, <action>.
    /// - for each X, <action>, <action>.
    ///
    /// The loop also stops at the start of an enclosing `If` else-chain so a
    /// trailing comma before `But`/`Else`/`Otherwise` does not swallow the
    /// boundary token.
    fn parse_sentence_body(&mut self) -> Result<Vec<Statement>, Box<CompileError>> {
        let mut statements = Vec::new();

        loop {
            // Stop at end of sentence markers or at an enclosing if-chain.
            if matches!(
                self.current(),
                Token::Period | Token::EOF | Token::ParagraphBreak
                    | Token::But | Token::Else | Token::Otherwise
            ) {
                break;
            }

            let stmt = self.parse_statement()?;
            statements.push(stmt);
            self.skip_noise();

            // Comma continues to next action, period ends. A comma immediately
            // followed by an if-chain boundary ends the sentence here.
            if *self.current() == Token::Comma {
                self.advance();
                self.skip_noise();

                if matches!(
                    self.current(),
                    Token::But | Token::Else | Token::Otherwise | Token::EOF | Token::ParagraphBreak
                ) {
                    break;
                }
            } else {
                break;
            }
        }

        // Consume the period if present
        if *self.current() == Token::Period {
            self.advance();
            self.skip_noise();
        }

        Ok(statements)
    }
    
    fn parse_condition(&mut self) -> Result<Expr, Box<CompileError>> {
        self.parse_or_expr()
    }
    
    fn parse_or_expr(&mut self) -> Result<Expr, Box<CompileError>> {
        let mut left = self.parse_and_expr()?;
        
        while *self.current() == Token::Or {
            self.advance();
            self.skip_noise();
            let right = self.parse_and_expr()?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op: BinaryOperator::Or,
                right: Box::new(right),
            };
        }
        
        Ok(left)
    }
    
    fn parse_and_expr(&mut self) -> Result<Expr, Box<CompileError>> {
        let mut left = self.parse_comparison()?;
        
        while *self.current() == Token::And {
            self.advance();
            self.skip_noise();
            let right = self.parse_comparison()?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op: BinaryOperator::And,
                right: Box::new(right),
            };
        }
        
        Ok(left)
    }
    
    /// Look ahead to check if "are" token appears within the next few tokens
    /// Used to determine if we should try parsing the multi-subject "x, y, z are" pattern
    fn has_are_ahead(&self) -> bool {
        for i in 1..20 {
            match self.peek(i) {
                Token::Are => return true,
                Token::Period | Token::EOF | Token::ParagraphBreak => return false,
                Token::Is => return false, // "is" means single subject, not multi
                _ => continue,
            }
        }
        false
    }
    

    fn parse_comparison(&mut self) -> Result<Expr, Box<CompileError>> {
        let left = self.parse_expression()?;
        self.skip_noise();
        
        // Check for "subject1, subject2, and subject3 are predicate" pattern
        // Only enter this pattern if we can see "are" coming up ahead
        if *self.current() == Token::Comma && self.has_are_ahead() {
            // Collect subjects for potential "are" pattern
            let mut subjects = vec![left.clone()];
            
            while *self.current() == Token::Comma {
                self.advance();
                self.skip_noise();
                
                // Check for "and" before last subject
                if *self.current() == Token::And {
                    self.advance();
                    self.skip_noise();
                }
                
                // Check if next is "are" - means we're done with subjects
                if *self.current() == Token::Are {
                    break;
                }
                
                let subject = self.parse_primary()?;
                subjects.push(subject);
                self.skip_noise();
            }
            
            // If we have "are" after collecting subjects, expand to ANDed conditions
            if *self.current() == Token::Are && subjects.len() > 1 {
                self.advance();
                self.skip_noise();
                
                let negated = *self.current() == Token::Not;
                if negated {
                    self.advance();
                    self.skip_noise();
                }
                
                // Parse the predicate (e.g., "true", "false", property, or value)
                let predicate = self.parse_primary()?;
                
                // Build ANDed conditions: subject1 is predicate AND subject2 is predicate ...
                let mut result: Option<Expr> = None;
                for subject in subjects {
                    let comparison = if negated {
                        Expr::BinaryOp {
                            left: Box::new(subject),
                            op: BinaryOperator::NotEqual,
                            right: Box::new(predicate.clone()),
                        }
                    } else {
                        Expr::BinaryOp {
                            left: Box::new(subject),
                            op: BinaryOperator::Equal,
                            right: Box::new(predicate.clone()),
                        }
                    };
                    
                    result = Some(match result {
                        None => comparison,
                        Some(left) => Expr::BinaryOp {
                            left: Box::new(left),
                            op: BinaryOperator::And,
                            right: Box::new(comparison),
                        },
                    });
                }
                
                return Ok(result.unwrap());
            }
            
            // Not an "are" pattern, return left as-is (shouldn't normally happen)
            return Ok(left);
        }
        
        if *self.current() == Token::Is || *self.current() == Token::Are {
            self.advance();
            self.skip_noise();
            
            let negated = *self.current() == Token::Not;
            if negated {
                self.advance();
                self.skip_noise();
            }
            
            let property = match self.current() {
                Token::Even => Some(Property::Even),
                Token::Odd => Some(Property::Odd),
                Token::Positive => Some(Property::Positive),
                Token::Negative => Some(Property::Negative),
                Token::Zero => Some(Property::Zero),
                Token::Empty => Some(Property::Empty),
                Token::Identifier(ref id) if id.eq_ignore_ascii_case("available") => {
                    // Handle "path is available" as a file availability check
                    self.advance();
                    let check = Expr::FileAvailable {
                        path: Box::new(left),
                    };
                    return if negated {
                        Ok(Expr::UnaryOp {
                            op: UnaryOperator::Not,
                            operand: Box::new(check),
                        })
                    } else {
                        Ok(check)
                    };
                }
                _ => None,
            };
            
            if let Some(prop) = property {
                self.advance();
                let check = Expr::PropertyCheck {
                    value: Box::new(left),
                    property: prop,
                };
                return if negated {
                    Ok(Expr::UnaryOp {
                        op: UnaryOperator::Not,
                        operand: Box::new(check),
                    })
                } else {
                    Ok(check)
                };
            }

            // "is a <type-noun>" / "is an <type-noun>" — runtime type
            // predicate (stage 1c). The article disambiguates this from a
            // bare `is <expr>` equality; `a`/`an` are keywords, never a valid
            // expression primary, so there is no ambiguity with equality.
            // Negation (`is not a text`) reuses the `negated` flag above and
            // wraps in `UnaryOp { Not, .. }`, exactly like `is not empty`.
            // Type-noun tokens map to `Type` the same way the Cast parser
            // does (see `parse_postfix`, ~line 4571).
            if matches!(self.current(), Token::A | Token::An) {
                let type_noun = self.parse_type_noun_after_article()?;
                let check = Expr::TypeCheck {
                    value: Box::new(left),
                    type_noun,
                };
                return if negated {
                    Ok(Expr::UnaryOp {
                        op: UnaryOperator::Not,
                        operand: Box::new(check),
                    })
                } else {
                    Ok(check)
                };
            }

            if *self.current() == Token::Greater || *self.current() == Token::Less {
                let is_greater = *self.current() == Token::Greater;
                self.advance();
                self.skip_noise();
                self.expect(&Token::Than);
                self.skip_noise();
                
                let mut is_equal = false;
                if *self.current() == Token::Or {
                    self.advance();
                    self.skip_noise();
                    self.expect(&Token::Equal);
                    self.expect(&Token::Equals);
                    self.expect(&Token::To);
                    self.skip_noise();
                    is_equal = true;
                }
                
                let right = self.parse_expression()?;
                let op = match (is_greater, is_equal, negated) {
                    (true, false, false) => BinaryOperator::Greater,
                    (true, true, false) => BinaryOperator::GreaterEqual,
                    (false, false, false) => BinaryOperator::Less,
                    (false, true, false) => BinaryOperator::LessEqual,
                    (true, false, true) => BinaryOperator::LessEqual,
                    (true, true, true) => BinaryOperator::Less,
                    (false, false, true) => BinaryOperator::GreaterEqual,
                    (false, true, true) => BinaryOperator::Greater,
                };
                
                return Ok(Expr::BinaryOp {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                });
            }
            
            // Handle "is equal to" / "is equals" explicitly
            if *self.current() == Token::Equals || *self.current() == Token::Equal {
                self.advance();
                self.skip_noise();
                // Skip optional "to"
                if *self.current() == Token::To {
                    self.advance();
                    self.skip_noise();
                }
                
                let right = self.parse_expression()?;
                let op = if negated {
                    BinaryOperator::NotEqual
                } else {
                    BinaryOperator::Equal
                };
                
                return Ok(Expr::BinaryOp {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                });
            }
            
            let right = self.parse_expression()?;
            let op = if negated {
                BinaryOperator::NotEqual
            } else {
                BinaryOperator::Equal
            };
            
            return Ok(Expr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            });
        }
        
        Ok(left)
    }
    
    fn parse_expression(&mut self) -> Result<Expr, Box<CompileError>> {
        // Type casts (`as a <type>`) are parsed by `parse_cast`, which sits
        // below the arithmetic levels (additive/multiplicative/bitwise). This
        // makes a cast bind TIGHTER than arithmetic, so it applies to the
        // expression immediately to its left - matching natural English, where
        // "X as a number" modifies X itself. To cast a whole arithmetic
        // expression, brace it: `{a add b} as a number`. See LANGUAGE.md.
        self.parse_additive()
    }

    /// Parse a primary expression followed by zero or more type casts.
    /// Sits between `parse_primary` (postfix) and `parse_bitwise` (the
    /// tightest binary level), so a cast applies to a single primary and
    /// binds tighter than every arithmetic/bitwise operator.
    fn parse_cast(&mut self) -> Result<Expr, Box<CompileError>> {
        let mut expr = self.parse_primary()?;

        loop {
            // Check for type casting with 'as' keyword
            self.skip_noise();
            if *self.current() != Token::As {
                break;
            }
            self.advance();
            self.skip_noise();

            // Optional 'a'/'an' before type
            if matches!(self.current(), Token::A | Token::An) {
                self.advance();
                self.skip_noise();
            }

            // Optional radix word before 'number': hex/binary/octal, or 'base N'
            let mut radix: u32 = 10;
            if let Token::Identifier(ref id) = self.current() {
                if id.eq_ignore_ascii_case("hex") || id.eq_ignore_ascii_case("hexadecimal") {
                    radix = 16;
                    self.advance();
                    self.skip_noise();
                } else if id.eq_ignore_ascii_case("octal") {
                    radix = 8;
                    self.advance();
                    self.skip_noise();
                } else if id.eq_ignore_ascii_case("binary") {
                    radix = 2;
                    self.advance();
                    self.skip_noise();
                } else if id.eq_ignore_ascii_case("base") {
                    self.advance();
                    self.skip_noise();
                    // Accept "base16"/"base 16" (fused word or separate number)
                    match self.current().clone() {
                        Token::IntegerLiteral(n) => {
                            radix = n as u32;
                            self.advance();
                            self.skip_noise();
                        }
                        Token::Identifier(ref fused) => {
                            // e.g. "base16", "base8", "base2" as one token
                            if let Ok(n) = fused.parse::<u32>() {
                                radix = n;
                                self.advance();
                                self.skip_noise();
                            } else {
                                return Err(self.err(&format!(
                                    "Expected a number after 'base', got '{}'", fused
                                )));
                            }
                        }
                        _ => return Err(self.err("Expected a number after 'base' (e.g. 'base 16')")),
                    }
                    if !(2..=36).contains(&radix) {
                        return Err(self.err("Only base 2 through base 36 are supported"));
                    }
                } else if id.len() > 4 && id[..4].eq_ignore_ascii_case("base") && id[4..].chars().all(|c| c.is_ascii_digit()) {
                    // Fused form as ONE token: "base16", "base8", "base2"
                    radix = id[4..].parse().unwrap_or(10);
                    if !(2..=36).contains(&radix) {
                        return Err(self.err("Only base 2 through base 36 are supported"));
                    }
                    self.advance();
                    self.skip_noise();
                }
            }

            // Parse target type
            let target_type = match self.current() {
                Token::Number | Token::Int => { self.advance(); Type::Integer }
                Token::Text => { self.advance(); Type::String }
                Token::Boolean => { self.advance(); Type::Boolean }
                Token::Float => { self.advance(); Type::Float }
                _ => return Err(self.err("Expected type after 'as'")),
            };

            expr = Expr::Cast {
                value: Box::new(expr),
                target_type,
                radix,
            };
        }

        Ok(expr)
    }
    
    fn parse_additive(&mut self) -> Result<Expr, Box<CompileError>> {
        let mut left = self.parse_multiplicative()?;
        
        loop {
            self.skip_noise();
            let op = match self.current() {
                Token::Add => Some(BinaryOperator::Add),
                Token::Subtract => Some(BinaryOperator::Subtract),
                _ => None,
            };
            
            if let Some(operator) = op {
                self.advance();
                self.skip_noise();
                let right = self.parse_multiplicative()?;
                left = Expr::BinaryOp {
                    left: Box::new(left),
                    op: operator,
                    right: Box::new(right),
                };
            } else {
                break;
            }
        }
        
        Ok(left)
    }
    
    fn parse_multiplicative(&mut self) -> Result<Expr, Box<CompileError>> {
        let mut left = self.parse_bitwise()?;
        
        loop {
            self.skip_noise();
            let op = match self.current() {
                Token::Multiply => Some(BinaryOperator::Multiply),
                Token::Divide => Some(BinaryOperator::Divide),
                Token::Modulo => Some(BinaryOperator::Modulo),
                _ => None,
            };
            
            if let Some(operator) = op {
                self.advance();
                self.skip_noise();
                let right = self.parse_bitwise()?;
                left = Expr::BinaryOp {
                    left: Box::new(left),
                    op: operator,
                    right: Box::new(right),
                };
            } else {
                break;
            }
        }
        
        Ok(left)
    }
    
    fn parse_bitwise(&mut self) -> Result<Expr, Box<CompileError>> {
        let mut left = self.parse_cast()?;

        loop {
            self.skip_noise();
            let op = match self.current() {
                Token::BitAnd => Some(BinaryOperator::BitAnd),
                Token::BitOr => Some(BinaryOperator::BitOr),
                Token::BitXor => Some(BinaryOperator::BitXor),
                Token::BitShiftLeft => Some(BinaryOperator::ShiftLeft),
                Token::BitShiftRight => Some(BinaryOperator::ShiftRight),
                _ => None,
            };

            if let Some(operator) = op {
                self.advance();
                self.skip_noise();
                let right = self.parse_cast()?;
                left = Expr::BinaryOp {
                    left: Box::new(left),
                    op: operator,
                    right: Box::new(right),
                };
            } else {
                break;
            }
        }
        
        Ok(left)
    }
    
    /// Turn a string literal in VALUE position into either a FormatString
    /// expression (when it contains {variable}/{expression} parts) or a
    /// plain StringLit. Every parser site that reads a string literal as a
    /// value (print/write payloads, buffer sources, paths, treating
    /// clauses, function arguments) must go through this helper - sites
    /// that read a string literal as a NAME (variable and file-handle
    /// names) must not. Hand-rolling this check per statement is how
    /// `write "{x}" to f` shipped writing the braces literally.
    fn string_value_expr(&self, s: String) -> Expr {
        // Any brace - escaped ({{ }}) or a real placeholder ({x}) - means we
        // must run the format parser. A leading "{{" used to short-circuit
        // this, leaving the braces in the literal verbatim. Now we always
        // parse: real placeholders become FormatString, and an all-Literal
        // result (pure escapes like "{{x}}" -> "{x}") is collapsed back into a
        // plain StringLit so the escapes take effect. An unpaired "{" yields
        // an empty-name Variable, which still triggers the codegen error -
        // preserving the "Unknown variable" diagnostic for `Append "{" to out`.
        if s.contains('{') || s.contains('}') {
            let parts = self.parse_format_string(&s);
            if parts
                .iter()
                .any(|p| matches!(p, FormatPart::Variable { .. } | FormatPart::Expression { .. }))
            {
                return Expr::FormatString { parts };
            }
            let collapsed: String = parts
                .iter()
                .filter_map(|p| match p {
                    FormatPart::Literal(t) => Some(t.as_str()),
                    _ => None,
                })
                .collect();
            return Expr::StringLit(if collapsed.is_empty() { s } else { collapsed });
        }
        Expr::StringLit(s)
    }

    fn parse_format_string(&self, s: &str) -> Vec<FormatPart> {
        let mut parts = Vec::new();
        let mut current_literal = String::new();
        let mut chars = s.chars().peekable();
        
        while let Some(ch) = chars.next() {
            if ch == '{' {
                // Check for escaped brace {{
                if chars.peek() == Some(&'{') {
                    chars.next();
                    current_literal.push('{');
                    continue;
                }
                
                // Save any accumulated literal
                if !current_literal.is_empty() {
                    parts.push(FormatPart::Literal(current_literal.clone()));
                    current_literal.clear();
                }
                
                // Parse content until closing brace
                let mut placeholder_content = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '}' {
                        chars.next();
                        break;
                    }
                    placeholder_content.push(c);
                    chars.next();
                }
                
                // Split on first : to separate variable/expression from format spec
                // The format spec is preserved exactly as written, with no interpretation
                let (content, format) = if let Some(colon_pos) = placeholder_content.find(':') {
                    let content = placeholder_content[..colon_pos].trim().to_string();
                    // Preserve format spec verbatim - no trimming, no interpretation
                    let format = placeholder_content[colon_pos + 1..].to_string();
                    (content, Some(format))
                } else {
                    (placeholder_content.trim().to_string(), None)
                };
                
                // Determine if content is an expression or a simple variable name
                // The format spec (if any) is attached verbatim without any parsing
                if let Some(expr) = self.try_parse_expression(&content) {
                    parts.push(FormatPart::Expression { 
                        expr: Box::new(expr), 
                        format 
                    });
                } else {
                    parts.push(FormatPart::Variable { 
                        name: content, 
                        format 
                    });
                }
            } else if ch == '}' {
                // Check for escaped brace }}
                if chars.peek() == Some(&'}') {
                    chars.next();
                    current_literal.push('}');
                } else {
                    current_literal.push(ch);
                }
            } else {
                current_literal.push(ch);
            }
        }
        
        // Add any remaining literal
        if !current_literal.is_empty() {
            parts.push(FormatPart::Literal(current_literal));
        }
        
        parts
    }
    
    fn try_parse_expression(&self, content: &str) -> Option<Expr> {
        // Simple heuristic: if it contains spaces, it might be an expression
        // Single identifiers are likely just variable names
        if !content.contains(' ') || content.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None;
        }
        
        // Try to parse as an English expression (including comparisons)
        let mut lexer = Lexer::new(content);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        // Use parse_and_expr to handle comparisons like "0 is equal to 0"
        match parser.parse_and_expr() {
            Ok(expr) => {
                // Check if we consumed all tokens (successful parse)
                if *parser.current() == Token::EOF {
                    Some(expr)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
    
    fn parse_primary(&mut self) -> Result<Expr, Box<CompileError>> {
        self.skip_noise();
        
        match self.current().clone() {
            Token::Not => {
                self.advance();
                self.skip_noise();
                let operand = self.parse_primary()?;
                Ok(Expr::UnaryOp {
                    op: UnaryOperator::Not,
                    operand: Box::new(operand),
                })
            }
            Token::Minus => {
                self.advance();
                self.skip_noise();
                let operand = self.parse_primary()?;
                Ok(Expr::UnaryOp {
                    op: UnaryOperator::Negate,
                    operand: Box::new(operand),
                })
            }
            Token::OpenBrace => {
                self.advance();
                self.skip_noise();
                // An explicit `{...}` group is fully self-delimiting - the
                // closing brace unambiguously ends it, so any `to`/`of`
                // reserved by an *enclosing* construct (e.g. `byte X of
                // buffer` reserving `of` via `parse_primary_reserving`) has
                // nothing left to protect once we're inside the braces.
                // Save/clear/restore here, mirroring the shape
                // `parse_primary_reserving` uses, so a nested call like
                // `byte {ci of 1 and 2} of buf` can use its own `of` (plan
                // 281).
                let saved_to = self.suppress_to_connector;
                let saved_of = self.suppress_of_connector;
                self.suppress_to_connector = false;
                self.suppress_of_connector = false;
                let result = (|| -> Result<Expr, Box<CompileError>> {
                    // Disambiguate a map literal from a grouping {expr}:
                    //   {}                -> empty map
                    //   {k: v, ...}       -> map literal (a colon follows the
                    //                        first expression)
                    //   {expr}            -> grouping (existing behaviour)
                    // Parse the first expression, then branch on whether a colon
                    // follows. This lets a non-text key (e.g. {1: "x"}) reach the
                    // analyzer's "Map keys must be text" check rather than being
                    // rejected as a malformed grouping. (stage 1e2)
                    if *self.current() == Token::CloseBrace {
                        self.advance();
                        return Ok(Expr::MapLit { pairs: vec![] });
                    }
                    let first = self.parse_expression()?;
                    self.skip_noise();
                    if *self.current() == Token::Colon {
                        let mut pairs = Vec::new();
                        self.advance(); // consume colon
                        self.skip_noise();
                        let first_value = self.parse_expression()?;
                        pairs.push((first, first_value));
                        loop {
                            self.skip_noise();
                            if *self.current() != Token::Comma {
                                break;
                            }
                            self.advance();
                            self.skip_noise();
                            // tolerate a trailing comma before the close brace
                            if *self.current() == Token::CloseBrace {
                                break;
                            }
                            let key = self.parse_expression()?;
                            self.skip_noise();
                            self.expect(&Token::Colon);
                            self.skip_noise();
                            let value = self.parse_expression()?;
                            pairs.push((key, value));
                        }
                        self.expect(&Token::CloseBrace);
                        return Ok(Expr::MapLit { pairs });
                    }
                    // grouping
                    self.expect(&Token::CloseBrace);
                    Ok(first)
                })();
                self.suppress_to_connector = saved_to;
                self.suppress_of_connector = saved_of;
                result
            }
            Token::Byte => {
                // byte N of buffer
                self.advance();
                self.skip_noise();
                let index = self.parse_primary_reserving(false, true)?;
                self.skip_noise();
                if *self.current() != Token::Of {
                    return Err(self.err("Expected 'of' after byte index"));
                }
                self.advance();
                self.skip_noise();
                let buffer = self.parse_primary()?;
                Ok(Expr::ByteAccess {
                    buffer: Box::new(buffer),
                    index: Box::new(index),
                })
            }
            Token::Element => {
                // element N of list
                self.advance();
                self.skip_noise();
                let index = self.parse_primary_reserving(false, true)?;
                self.skip_noise();
                if *self.current() != Token::Of {
                    return Err(self.err("Expected 'of' after element index"));
                }
                self.advance();
                self.skip_noise();
                // The list operand is usually a name, but a list *literal*
                // (`element 2 of [1, 2, 3]`) is also legal, so this can't use
                // `parse_name()`. A bare string literal here is neither: it
                // is the plan 270 §S1.5 trap (`element 1 of "items"` reading
                // as a name in old syntax) and, left unrejected, silently
                // resolves to a degenerate ElementAccess instead of a
                // compile error. A format string is unambiguous data and
                // stays allowed, same as elsewhere.
                let list_loc = self.current_location();
                let list_string_lit = match self.current().clone() {
                    Token::StringLiteral(s) => Some(s),
                    _ => None,
                };
                let list = self.parse_primary()?;
                if let (Some(s), Expr::StringLit(_)) = (list_string_lit, &list) {
                    let mut err = CompileError::new("expected a name, found a string literal");
                    if let Some(loc) = list_loc {
                        err = err.with_location(loc);
                    }
                    let span = s.chars().count() + 2;
                    err = err
                        .with_underline_note(span, "strings are data; names are bare or 'single-quoted'")
                        .with_help_line(&Self::suggest_name_form(&s));
                    return Err(Box::new(err));
                }
                Ok(Expr::ElementAccess {
                    list: Box::new(list),
                    index: Box::new(index),
                })
            }
            Token::IntegerLiteral(n) => {
                self.advance();
                Ok(Expr::IntegerLit(n))
            }
            Token::FloatLiteral(n) => {
                self.advance();
                Ok(Expr::FloatLit(n))
            }
            Token::StringLiteral(s) => {
                let s_owned = s.clone();
                self.advance();
                self.skip_noise();

                // A format string is always data.
                if let expr @ Expr::FormatString { .. } = self.string_value_expr(s_owned.clone()) {
                    return Ok(expr);
                }

                // Plan 270: a string literal is data, never a callee or an
                // object name. The old `"f" of args`, `"x"'s prop`, and
                // `"x"'s "key"` overloads are rejected with the §S1.5
                // diagnostic. (Map key access on a *real* identifier —
                // `person's "name"` — is handled in the Identifier arm below,
                // where the string literal is the key, not the object.)
                if matches!(self.current(), Token::Of | Token::To | Token::With | Token::On | Token::Apostrophe) {
                    return Err(self.err_string_as_name(&s_owned));
                }

                Ok(self.string_value_expr(s_owned))
            }
            Token::True => {
                self.advance();
                Ok(Expr::BoolLit(true))
            }
            Token::False => {
                self.advance();
                Ok(Expr::BoolLit(false))
            }
            // The nothing/null literal (stage 1e3, tag 6). `nothing`/`null`/
            // `nil` all lex to `Token::Nothing`. As a bare primary it yields
            // `NothingLit`; in `x is nothing` it falls through
            // `parse_comparison` (the property/article/greater-less/equals
            // guards all skip `Nothing`) to the bare-`is` equality arm,
            // building `BinaryOp{Equal|NotEqual, x, NothingLit}`.
            Token::Nothing => {
                self.advance();
                Ok(Expr::NothingLit)
            }
            // Handle "current time" expression
            Token::Current => {
                self.advance();
                self.skip_noise();
                
                if *self.current() == Token::Time {
                    self.advance();
                    self.skip_noise();
                    
                    // Check for property access: "current time's hour"
                    if *self.current() == Token::Apostrophe {
                        self.advance();
                        if let Token::Identifier(s) = self.current().clone() {
                            if s.to_lowercase() == "s" {
                                self.advance();
                                self.skip_noise();
                                
                                let property = match self.current() {
                                    Token::Hour => ObjectProperty::Hour,
                                    Token::Minute => ObjectProperty::Minute,
                                    Token::Second => ObjectProperty::Second,
                                    Token::Day => ObjectProperty::Day,
                                    Token::Month => ObjectProperty::Month,
                                    Token::Year => ObjectProperty::Year,
                                    Token::Unix => ObjectProperty::Unix,
                                    _ => return Err(self.err_expected("time property (hour, minute, second, day, month, year)", self.current())),
                                };
                                self.advance();
                                
                                // Return property access on current time
                                return Ok(Expr::PropertyAccess {
                                    object: "_current_time".to_string(),
                                    property,
                                });
                            }
                        }
                    }
                    
                    Ok(Expr::CurrentTime)
                } else {
                    Err(self.err("Expected 'time' after 'current'"))
                }
            }
            // Handle arguments's and environment's property access directly from tokens
            Token::Arguments | Token::Argument => {
                self.advance();
                self.skip_noise();

                // arguments has <value>
                if let Token::Identifier(ref id) = self.current() {
                    if id.to_lowercase() == "has" {
                        self.advance();
                        self.skip_noise();
                        let value = self.parse_expression()?;
                        return Ok(Expr::ArgumentHas {
                            value: Box::new(value),
                        });
                    }
                }
                
                if *self.current() == Token::Apostrophe {
                    self.advance();
                    if let Token::Identifier(s) = self.current().clone() {
                        if s.to_lowercase() == "s" {
                            self.advance();
                            self.skip_noise();
                            
                            return match self.current() {
                                Token::Count => { self.advance(); Ok(Expr::ArgumentCount) }
                                Token::Identifier(ref id) if id.to_lowercase() == "name" => { 
                                    self.advance(); Ok(Expr::ArgumentName) 
                                }
                                Token::First => { self.advance(); Ok(Expr::ArgumentFirst) }
                                Token::Second => { self.advance(); Ok(Expr::ArgumentSecond) }
                                Token::Identifier(ref id) if id.to_lowercase() == "second" => { 
                                    self.advance(); Ok(Expr::ArgumentSecond) 
                                }
                                Token::Last => { self.advance(); Ok(Expr::ArgumentLast) }
                                Token::Empty => { self.advance(); Ok(Expr::ArgumentEmpty) }
                                Token::All => { self.advance(); Ok(Expr::ArgumentAll) }
                                Token::Raw => { self.advance(); Ok(Expr::ArgumentRaw) }
                                _ => Err(self.err_expected("arguments property (count, first, last, empty, all, raw)", self.current())),
                            };
                        }
                    }
                }
                Err(self.err("Expected 's after 'arguments'"))
            }
            
            Token::Environment => {
                self.advance();
                self.skip_noise();
                
                if *self.current() == Token::Apostrophe {
                    self.advance();
                    if let Token::Identifier(s) = self.current().clone() {
                        if s.to_lowercase() == "s" {
                            self.advance();
                            self.skip_noise();
                            
                            return match self.current() {
                                Token::Count => { self.advance(); Ok(Expr::EnvironmentVariableCount) }
                                Token::First => { self.advance(); Ok(Expr::EnvironmentVariableFirst) }
                                Token::Last => { self.advance(); Ok(Expr::EnvironmentVariableLast) }
                                Token::Empty => { self.advance(); Ok(Expr::EnvironmentVariableEmpty) }
                                Token::StringLiteral(env_name) => {
                                    let env_name = env_name.clone();
                                    self.advance();
                                    Ok(Expr::EnvironmentVariable { name: Box::new(Expr::StringLit(env_name)) })
                                }
                                _ => Err(self.err_expected("environment property", self.current())),
                            };
                        }
                    }
                }
                Err(self.err("Expected 's after 'environment'"))
            }
            
            Token::Identifier(ref id) if id.eq_ignore_ascii_case("fork") => {
                self.advance();
                self.skip_noise();
                // Optional trailing "the process" for readability
                if *self.current() == Token::The {
                    self.advance();
                    self.skip_noise();
                    if let Token::Identifier(ref w2) = self.current() {
                        if w2.eq_ignore_ascii_case("process") {
                            self.advance();
                        }
                    }
                }
                Ok(Expr::Fork)
            }

            Token::Identifier(ref id) if id.eq_ignore_ascii_case("reap") => {
                self.advance();
                self.skip_noise();

                // "reap any child process" -> pid = None (wait for any child)
                if let Token::Identifier(ref w) = self.current() {
                    if w.eq_ignore_ascii_case("any") {
                        self.advance();
                        self.skip_noise();
                        // Optional trailing "child process"/"child"/"process"
                        while let Token::Identifier(ref w2) = self.current() {
                            if w2.eq_ignore_ascii_case("child") || w2.eq_ignore_ascii_case("process") {
                                self.advance();
                                self.skip_noise();
                            } else {
                                break;
                            }
                        }
                        return Ok(Expr::ReapChild { pid: None });
                    }
                }

                // "reap process <pid>" / "reap child <pid>" -> pid = Some(expr)
                if let Token::Identifier(ref w) = self.current() {
                    if w.eq_ignore_ascii_case("process") || w.eq_ignore_ascii_case("child") {
                        self.advance();
                        self.skip_noise();
                    }
                }
                let pid = self.parse_primary()?;
                Ok(Expr::ReapChild { pid: Some(Box::new(pid)) })
            }

            Token::Identifier(name) => {
                self.advance();
                self.skip_noise();

                // Call with arguments: `name of/with/to/on args` (plan 270 G1).
                // A bare or quoted identifier is the callee; this is the
                // expression-level counterpart of the statement-level call.
                if let Some(call) = self.parse_call_tail(name.clone(), true)? {
                    return Ok(call);
                }

                // Check for property access: identifier's property
                if *self.current() == Token::Apostrophe {
                    self.advance();
                    // Expect 's' followed by property name
                    if let Token::Identifier(s) = self.current().clone() {
                        if s.to_lowercase() == "s" {
                            self.advance();
                            self.skip_noise();
                            
                            // Special handling for arguments's and environment's
                            let name_lower = name.to_lowercase();
                            if name_lower == "arguments" || name_lower == "args" {
                                return match self.current() {
                                    Token::Count => { self.advance(); Ok(Expr::ArgumentCount) }
                                    Token::Identifier(ref id) if id.to_lowercase() == "name" => { 
                                        self.advance(); Ok(Expr::ArgumentName) 
                                    }
                                    Token::First => { self.advance(); Ok(Expr::ArgumentFirst) }
                                    Token::Second => { self.advance(); Ok(Expr::ArgumentSecond) }
                                    Token::Identifier(ref id) if id.to_lowercase() == "second" => { 
                                        self.advance(); Ok(Expr::ArgumentSecond) 
                                    }
                                    Token::Last => { self.advance(); Ok(Expr::ArgumentLast) }
                                    Token::Empty => { self.advance(); Ok(Expr::ArgumentEmpty) }
                                    Token::All => { self.advance(); Ok(Expr::ArgumentAll) }
                                    Token::Raw => { self.advance(); Ok(Expr::ArgumentRaw) }
                                    _ => Err(self.err_expected("arguments property (count, first, last, empty, all, raw)", self.current())),
                                };
                            }
                            
                            if name_lower == "environment" || name_lower == "env" {
                                return match self.current() {
                                    Token::Count => { self.advance(); Ok(Expr::EnvironmentVariableCount) }
                                    Token::First => { self.advance(); Ok(Expr::EnvironmentVariableFirst) }
                                    Token::Last => { self.advance(); Ok(Expr::EnvironmentVariableLast) }
                                    Token::Empty => { self.advance(); Ok(Expr::EnvironmentVariableEmpty) }
                                    Token::StringLiteral(env_name) => {
                                        let env_name = env_name.clone();
                                        self.advance();
                                        Ok(Expr::EnvironmentVariable { name: Box::new(Expr::StringLit(env_name)) })
                                    }
                                    _ => Err(self.err_expected("environment property", self.current())),
                                };
                            }
                            
                            // Check if user meant 'arguments' or 'environment' but made a typo
                            // If so, the property they're accessing might be valid for that object
                            let is_arguments_property = matches!(self.current(), 
                                Token::Count | Token::First | Token::Last | Token::Empty | Token::All);
                            let is_env_property = matches!(self.current(),
                                Token::Count | Token::First | Token::Last | Token::Empty);
                            
                            if is_arguments_property {
                                if let Some(suggestion) = find_similar_keyword(&name, &["arguments", "args"]) {
                                    return Err(self.err(&format!(
                                        "Unknown identifier '{}' - did you mean '{}'?",
                                        name, suggestion
                                    )));
                                }
                            }
                            if is_env_property {
                                if let Some(suggestion) = find_similar_keyword(&name, &["environment", "env"]) {
                                    return Err(self.err(&format!(
                                        "Unknown identifier '{}' - did you mean '{}'?",
                                        name, suggestion
                                    )));
                                }
                            }
                            
                            // Map key access: person's "name" (text-literal key).
                            // Keys are text in stage 1e2; a quoted key with
                            // `{...}` interpolation materializes a fresh text
                            // (so `m's "key{i}"` builds a dynamic key). An
                            // unquoted identifier here is a property name.
                            if let Token::StringLiteral(k) = self.current().clone() {
                                self.advance();
                                self.skip_noise();
                                return Ok(Expr::MapAccess {
                                    map: name,
                                    key: Box::new(self.string_value_expr(k)),
                                });
                            }

                            // Parse property name for other objects
                            let property = match self.current() {
                                // Buffer properties
                                Token::Size => ObjectProperty::Size,
                                Token::Capacity => ObjectProperty::Capacity,
                                Token::Empty => ObjectProperty::Empty,
                                Token::Full => ObjectProperty::Full,

                                // File properties
                                Token::Descriptor => ObjectProperty::Descriptor,
                                Token::Modified => ObjectProperty::Modified,
                                Token::Accessed => ObjectProperty::Accessed,
                                Token::Permissions => ObjectProperty::Permissions,
                                Token::Readable => ObjectProperty::Readable,
                                Token::Writable => ObjectProperty::Writable,

                                // List properties
                                Token::First => ObjectProperty::First,
                                Token::Last => ObjectProperty::Last,

                                // Map properties
                                Token::Keys => ObjectProperty::Keys,
                                Token::Values => ObjectProperty::Values,

                                // Number properties
                                Token::Absolute => ObjectProperty::Absolute,
                                Token::Sign => ObjectProperty::Sign,
                                Token::Even => ObjectProperty::Even,
                                Token::Odd => ObjectProperty::Odd,
                                Token::Positive => ObjectProperty::Positive,
                                Token::Negative => ObjectProperty::Negative,
                                Token::Zero => ObjectProperty::Zero,

                                // Time properties
                                Token::Hour => ObjectProperty::Hour,
                                Token::Minute => ObjectProperty::Minute,
                                Token::Second => ObjectProperty::Second,
                                Token::Day => ObjectProperty::Day,
                                Token::Month => ObjectProperty::Month,
                                Token::Year => ObjectProperty::Year,
                                Token::Unix => ObjectProperty::Unix,

                                // Timer properties
                                Token::Duration => ObjectProperty::Duration,
                                Token::Elapsed => ObjectProperty::Elapsed,
                                Token::Identifier(ref id) if id.to_lowercase() == "start" => ObjectProperty::StartTime,
                                Token::Identifier(ref id) if id.to_lowercase() == "end" => ObjectProperty::EndTime,
                                Token::Running => ObjectProperty::Running,
                                Token::Identifier(ref id) if id.to_lowercase() == "type" => ObjectProperty::Type,

                                _ => return Err(self.err_expected("property name", self.current())),
                            };
                            self.advance();

                            // `start time` / `end time`: `time` is a reserved
                            // word and lexes as Token::Time, so it can never
                            // match a property name above - consume it when it
                            // directly follows `start`/`end`.
                            if matches!(property, ObjectProperty::StartTime | ObjectProperty::EndTime) {
                                self.skip_noise();
                                if *self.current() == Token::Time {
                                    self.advance();
                                }
                            }

                            // Timer duration/elapsed may be followed by a unit,
                            // e.g. "t's duration in seconds". This matches the
                            // handling already present for quoted variable and
                            // "the ..." property-access forms.
                            if matches!(property, ObjectProperty::Duration | ObjectProperty::Elapsed) {
                                self.skip_noise();
                                if *self.current() == Token::In {
                                    self.advance();
                                    self.skip_noise();
                                }
                                if matches!(self.current(), Token::Seconds | Token::Second | Token::Milliseconds | Token::Millisecond) {
                                    let unit = match self.current() {
                                        Token::Seconds | Token::Second => {
                                            self.advance();
                                            ast::TimeUnit::Seconds
                                        }
                                        Token::Milliseconds | Token::Millisecond => {
                                            self.advance();
                                            ast::TimeUnit::Milliseconds
                                        }
                                        _ => unreachable!(),
                                    };
                                    return Ok(Expr::DurationCast {
                                        value: Box::new(Expr::PropertyAccess { object: name, property }),
                                        unit,
                                    });
                                }
                            }

                            return Ok(Expr::PropertyAccess {
                                object: name,
                                property,
                            });
                        }
                    }
                }
                
                Ok(Expr::Identifier(name))
            }
            Token::OpenBracket => {
                self.advance();
                self.skip_noise();
                
                let mut elements = Vec::new();
                
                // Empty list
                if *self.current() == Token::CloseBracket {
                    self.advance();
                    return Ok(Expr::ListLit { elements });
                }
                
                // Parse first element
                elements.push(self.parse_expression()?);
                self.skip_noise();
                
                // Parse remaining elements
                while *self.current() == Token::Comma {
                    self.advance();
                    self.skip_noise();
                    elements.push(self.parse_expression()?);
                    self.skip_noise();
                }
                
                self.expect(&Token::CloseBracket);
                Ok(Expr::ListLit { elements })
            }
            Token::All => {
                self.advance();
                self.skip_noise();
                self.expect(&Token::The);
                self.skip_noise();
                self.expect(&Token::Number);
                self.skip_noise();
                
                if *self.current() == Token::From || *self.current() == Token::Between {
                    let inclusive = *self.current() == Token::Between;
                    self.advance();
                    self.skip_noise();
                    
                    let start = self.parse_primary_reserving(true, false)?;
                    self.skip_noise();
                    self.expect(&Token::To);
                    self.expect(&Token::And);
                    self.skip_noise();

                    let end = self.parse_primary()?;
                    
                    Ok(Expr::Range {
                        start: Box::new(start),
                        end: Box::new(end),
                        inclusive,
                    })
                } else {
                    Err(self.err("Expected 'from' or 'between' after 'all the numbers'"))
                }
            }
            Token::Number => {
                self.advance();
                Ok(Expr::Identifier("_iter".to_string()))
            }
            Token::The => {
                self.advance(); // consume 'the'
                self.skip_noise();
                // "the x" or "the number called x" -> variable reference
                match self.current().clone() {
                    // "the argument count" or "the argument at N"
                    Token::Argument => {
                        self.advance();
                        self.skip_noise();
                        
                        if *self.current() == Token::Count {
                            self.advance();
                            Ok(Expr::ArgumentCount)
                        } else if *self.current() == Token::On { // "at" maps to Token::On
                            self.advance();
                            self.skip_noise();
                            let index = self.parse_expression()?;
                            Ok(Expr::ArgumentAt { index: Box::new(index) })
                        } else {
                            Err(self.err("Expected 'count' or 'at' after 'the argument'"))
                        }
                    }
                    // "the environment variable ..." 
                    Token::Environment => {
                        self.advance();
                        self.skip_noise();
                        
                        // Skip optional "variable"
                        if *self.current() == Token::Variable {
                            self.advance();
                            self.skip_noise();
                        }
                        
                        // "the environment variable count"
                        if *self.current() == Token::Count {
                            self.advance();
                            Ok(Expr::EnvironmentVariableCount)
                        }
                        // "the environment variable at N"
                        else if *self.current() == Token::On { // "at" maps to Token::On
                            self.advance();
                            self.skip_noise();
                            let index = self.parse_expression()?;
                            Ok(Expr::EnvironmentVariableAt { index: Box::new(index) })
                        }
                        // "the environment variable "NAME"" or "the environment variable exists"
                        else {
                            let name = self.parse_primary()?;
                            self.skip_noise();
                            
                            // Check for "exists" after the name
                            if *self.current() == Token::Exists {
                                self.advance();
                                Ok(Expr::EnvironmentVariableExists { name: Box::new(name) })
                            } else {
                                Ok(Expr::EnvironmentVariable { name: Box::new(name) })
                            }
                        }
                    }
                    Token::Identifier(name) => {
                        self.advance();
                        self.skip_noise();
                        
                        // Check for property access: "the now's hour"
                        if *self.current() == Token::Apostrophe {
                            self.advance();
                            if let Token::Identifier(prop_s) = self.current().clone() {
                                if prop_s.to_lowercase() == "s" {
                                    self.advance();
                                    self.skip_noise();
                                    
                                    let property = match self.current() {
                                        // Time properties
                                        Token::Hour => ObjectProperty::Hour,
                                        Token::Minute => ObjectProperty::Minute,
                                        Token::Second => ObjectProperty::Second,
                                        Token::Day => ObjectProperty::Day,
                                        Token::Month => ObjectProperty::Month,
                                        Token::Year => ObjectProperty::Year,
                                        Token::Unix => ObjectProperty::Unix,
                                        // Timer properties
                                        Token::Duration => ObjectProperty::Duration,
                                        Token::Elapsed => ObjectProperty::Elapsed,
                                        Token::Running => ObjectProperty::Running,
                                        // Other properties
                                        Token::Size => ObjectProperty::Size,
                                        Token::Capacity => ObjectProperty::Capacity,
                                        Token::Empty => ObjectProperty::Empty,
                                        Token::Full => ObjectProperty::Full,
                                        // Handle single-quoted multi-word property names and 'start'
                                        Token::Identifier(ref prop_name) => {
                                            match prop_name.to_lowercase().as_str() {
                                                "start" => ObjectProperty::StartTime,
                                                // bare `end` - site 2 (unquoted
                                                // name) has always had this arm;
                                                // the quoted and `the ...` paths
                                                // dropped it
                                                "end" => ObjectProperty::EndTime,
                                                "start time" => ObjectProperty::StartTime,
                                                "end time" => ObjectProperty::EndTime,
                                                "duration" => ObjectProperty::Duration,
                                                "elapsed" => ObjectProperty::Elapsed,
                                                "running" => ObjectProperty::Running,
                                                _ => return Err(self.err_expected("property name", self.current())),
                                            }
                                        }
                                        _ => return Err(self.err_expected("property name", self.current())),
                                    };
                                    self.advance();

                                    // `start time` / `end time`: `time` is a
                                    // reserved word and lexes as Token::Time,
                                    // so it can never match a property name
                                    // above - consume it when it directly
                                    // follows `start`/`end`.
                                    if matches!(property, ObjectProperty::StartTime | ObjectProperty::EndTime) {
                                        self.skip_noise();
                                        if *self.current() == Token::Time {
                                            self.advance();
                                        }
                                    }

                                    // Timer duration/elapsed may be followed by
                                    // a unit, e.g. "the t's elapsed seconds" or
                                    // "the t's duration in seconds". This
                                    // matches the handling already present for
                                    // the quoted-variable possessive form
                                    // (`t's duration in seconds` without a
                                    // leading `the`) - without it, a two-word
                                    // `<property> <unit>` phrase here left
                                    // `seconds` unconsumed, so the statement
                                    // ended early and the top-level loop then
                                    // choked trying to parse `seconds` as its
                                    // own statement.
                                    if matches!(property, ObjectProperty::Duration | ObjectProperty::Elapsed) {
                                        self.skip_noise();
                                        if *self.current() == Token::In {
                                            self.advance();
                                            self.skip_noise();
                                        }
                                        if matches!(self.current(), Token::Seconds | Token::Second | Token::Milliseconds | Token::Millisecond) {
                                            let unit = match self.current() {
                                                Token::Seconds | Token::Second => {
                                                    self.advance();
                                                    ast::TimeUnit::Seconds
                                                }
                                                Token::Milliseconds | Token::Millisecond => {
                                                    self.advance();
                                                    ast::TimeUnit::Milliseconds
                                                }
                                                _ => unreachable!(),
                                            };
                                            return Ok(Expr::DurationCast {
                                                value: Box::new(Expr::PropertyAccess { object: name, property }),
                                                unit,
                                            });
                                        }
                                    }

                                    return Ok(Expr::PropertyAccess { object: name, property });
                                }
                            }
                            return Err(self.err("Expected 's after apostrophe for property access"));
                        }

                        Ok(Expr::Identifier(name))
                    }
                    // Plan 270 §S1.5: a string literal cannot be an object name.
                    // `the "job timer"'s duration` -> write `the 'job timer''s
                    // duration` (a quoted identifier). Reject before advancing so
                    // the underline lands on the offending string.
                    Token::StringLiteral(name) => Err(self.err_string_as_name(&name)),
                    Token::Number | Token::Text | Token::Boolean => {
                        self.advance(); // consume type
                        self.skip_noise();

                        // "the number called x" -> variable reference
                        // "the number" alone -> loop iterator reference
                        if *self.current() == Token::Called {
                            self.advance();
                            self.skip_noise();
                            match self.current().clone() {
                                Token::StringLiteral(name) => Err(self.err_string_as_name(&name)),
                                Token::Identifier(name) => {
                                    self.advance();
                                    Ok(Expr::Identifier(name))
                                }
                                _ => Err(self.err("Expected variable name after 'called'")),
                            }
                        } else {
                            // "the number" without "called" refers to loop iterator
                            Ok(Expr::Identifier("_iter".to_string()))
                        }
                    }
                    _ => Err(self.err_expected("identifier after 'the'", self.current())),
                }
            }
            Token::A | Token::An => {
                // Check if this is an article before a type, or just the letter "a"/"an" as identifier
                let is_article = self.current().clone();
                self.advance();
                self.skip_noise();
                
                // If followed by a type keyword, treat as article and parse the type expression
                if matches!(self.current(), Token::Number | Token::Text | Token::Boolean | Token::List) {
                    self.parse_primary()
                } else {
                    // Otherwise, treat "a" or "an" as an identifier
                    let name = if matches!(is_article, Token::A) { "a" } else { "an" };
                    Ok(Expr::Identifier(name.to_string()))
                }
            }
            _ => Err(self.err_expected("a statement", self.current())),
        }
    }
    
    // ========================================================================
    // Time and Timer parsing
    // ========================================================================
    
    fn parse_wait(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume Wait/Sleep
        self.skip_noise();
        
        // Optional "for"
        self.expect(&Token::For);
        self.skip_noise();
        
        // Parse duration value
        let duration = self.parse_primary()?;
        self.skip_noise();
        
        // Parse unit: second(s), millisecond(s)
        let unit = match self.current() {
            Token::Second | Token::Seconds => {
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
    
    fn parse_timer_start(&mut self) -> Result<Statement, Box<CompileError>> {
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
    
    fn parse_timer_stop(&mut self) -> Result<Statement, Box<CompileError>> {
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
    
    fn parse_get(&mut self) -> Result<Statement, Box<CompileError>> {
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



