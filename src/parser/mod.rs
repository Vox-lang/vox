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
mod functions;
mod control_flow;

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
    
    
    
    
    
    
    
    

    
    
    







    // Filesystem operations parsing





    
    
    
    
    




    
    
    

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



