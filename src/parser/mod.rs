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
    // Every thing defined so far, by name (plan 310). Populated as the
    // parse walks the file, which is enough for a single pass because a
    // thing must be defined before any use of its name - a field type
    // naming a later thing is an unknown type, not a forward reference.
    things: std::collections::HashMap<String, ast::ThingDef>,
    // Which thing each declared variable holds, by variable name (plan 310
    // §3). This is what lets `origin's x` parse as a field chain rather than
    // an object property: the possessive's meaning depends on what the base
    // is, and only a declaration says so.
    //
    // Deliberately flat and never popped, like the parser's other tables: it
    // answers "is this name a thing variable" for the shape of the parse, and
    // scope is the analyzer's job (a use outside the declaring scope is its
    // "Unknown variable"). The same "declared before used" rule that makes
    // one pass enough for definitions applies to declarations too.
    thing_vars: std::collections::HashMap<String, String>,
    // Which thing each function returns, for the functions that return one
    // (plan 310 §2). `The after is nudged of before.` declares `after` from
    // the call's return type, and the parser is where that has to be known:
    // `after's x` only reads as a field chain if the parse already knows
    // what `after` holds. Populated as each `To` definition is parsed, so
    // the same "defined before used" rule that governs thing definitions
    // governs inference from a call.
    thing_returning_functions: std::collections::HashMap<String, String>,
    // The declared type of each function's FIRST parameter, for the functions
    // that take one (plan 310 §4). This is what the instance possessive
    // resolves against: `origin's magnitude` is a call only if `magnitude`
    // takes a point first, and the parser is where that has to be known,
    // because the answer decides whether the possessive is a field chain or a
    // call tail with arguments still to read. Populated as each `To`
    // definition's signature is parsed - before its body, so a function may
    // use the sugar on itself - which is the same "defined before used" rule
    // that governs thing definitions.
    function_first_parameters: std::collections::HashMap<String, Type>,
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
#[cfg(test)]
mod thing_definition_tests;
mod declarations;
mod io;
mod collections;
mod functions;
mod control_flow;
mod expressions;
mod statements;
mod things;

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
            things: std::collections::HashMap::new(),
            thing_vars: std::collections::HashMap::new(),
            thing_returning_functions: std::collections::HashMap::new(),
            function_first_parameters: std::collections::HashMap::new(),
        }
    }

    pub fn with_source(mut self, filename: &str, content: &str) -> Self {
        self.source_file = Some(SourceFile::new(filename, content));
        self
    }

    /// Hand this parser the thing definitions and thing variables another
    /// parser has already seen. A format string's `{...}` placeholder is
    /// parsed by a fresh sub-parser (`try_parse_expression`), which without
    /// this knows no things at all - so `"{origin's x}"` would fail to parse
    /// as an expression and fall back to a literal `{origin's x}` placeholder.
    /// §3 lists interpolation as one of the places a field must work, and the
    /// instance possessive stands wherever a field does (§4) - which is why
    /// the first-parameter table travels too: without it `"{origin's
    /// magnitude}"` would read as an unknown member of point.
    pub(crate) fn with_things_of(mut self, outer: &Parser) -> Self {
        self.things = outer.things.clone();
        self.thing_vars = outer.thing_vars.clone();
        self.thing_returning_functions = outer.thing_returning_functions.clone();
        self.function_first_parameters = outer.function_first_parameters.clone();
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

}

