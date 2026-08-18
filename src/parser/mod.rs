pub mod ast;

use crate::lexer::{Token, TokenInfo, Lexer};
use crate::errors::{CompileError, SourceLocation, SourceFile, find_similar_keyword, ENGLISH_KEYWORDS};
use ast::*;

// Type aliases for complex nested types
type TreatingClause = (Expr, Expr);
type LoopExpansion = (String, Expr, Option<TreatingClause>);
type PathInfo = Result<Expr, LoopExpansion>;

/// Which kind of declaration took a name. Plan 310 §4 settles that these
/// three share ONE space: Vox's possessive puts a type and a variable in the
/// same grammatical position, so `the point's` only reads one way if nothing
/// else in the program is called `point`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum NameKind {
    Thing,
    Variable,
    Function,
}

impl NameKind {
    /// The word the diagnostic uses for this kind of declaration.
    fn noun(self) -> &'static str {
        match self {
            NameKind::Thing => "thing",
            NameKind::Variable => "variable",
            NameKind::Function => "function",
        }
    }
}

/// One name in the identifier space, and where it was claimed - so the
/// second declaration into it can name the first (plan 310 §10). The file is
/// carried because a `see` splices another file into the same space, and a
/// line number alone would then name a line in a file the reader is not
/// looking at.
pub(crate) struct NameClaim {
    kind: NameKind,
    line: usize,
    /// Token index of the name, for the caret - only meaningful when `file`
    /// is the file being parsed, since another file's tokens are a different
    /// stream.
    pos: usize,
    file: Option<String>,
}

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
    // Every declared member whose `To do the <thing>'s <name>` definition has
    // been read, keyed by (thing, member) (plan 310 §4). Two things may
    // declare the same member name, so the owner is half the key - which is
    // also what the internal name it records keeps apart.
    member_functions: std::collections::HashMap<(String, String), things::MemberFunction>,
    // The one identifier space (plan 310 §4, §10). Every declaration form -
    // a thing definition, a variable declaration in any of its spellings, a
    // function definition, a parameter, a loop variable - claims its name
    // here through `claim_name`, and that one operation is where the
    // collision rule lives. Enforcing it at each spelling instead is how five
    // of the six spellings came to be unguarded: a rule written at a call
    // site is a rule the next call site has to remember.
    //
    // It doubles as the caret table the two whole-program checks need
    // ("declares X but nothing defines it", and the registry assertion),
    // which is why the token index is kept alongside.
    claimed_names: std::collections::HashMap<String, NameClaim>,
    // How deep the statement being parsed sits: 1 while the top-level loop
    // is reading a statement, 2 or more anywhere inside a block - an `If`
    // branch, a loop body, a function body. A thing is defined at the top
    // level like a function is (plan 310 §3, §9: layout is compile-time and
    // global, and a definition must precede every use of its name), so
    // `parse_thing_definition` needs to know where it stands. Every block
    // body reaches its statements through `parse_statement`, which is the
    // one door this is counted at.
    statement_depth: usize,
    // The directory a `see "./x.vox"` resolves against: the directory of the
    // file being parsed. Set from the source filename, or given directly by
    // a caller that displays a file under a different name than it reads it
    // from (the compile_fail harness).
    include_base: Option<std::path::PathBuf>,
    // Canonical paths already spliced into this compilation, so a diamond or
    // a circular `see` splices each file once. Seeded with the file being
    // parsed, so a file cannot see itself.
    included_files: std::collections::HashSet<std::path::PathBuf>,
    // Every source file this parse read through a `see`, in the order it read
    // them, for the driver's `-v` listing.
    pub included_paths: Vec<String>,
    // The statements a `see "<path>.vox"` just spliced in, waiting for the
    // top-level loop to put them where the `see` stood. `None` means the
    // statement is an ordinary one; `Some` (even empty) means it was a source
    // include and the `See` statement itself is not part of the program.
    included_statements: Option<Vec<Statement>>,
    // Every `Return` in the definition being parsed that declared a type,
    // as (token index, declared type). The member rule is about the Return
    // LINES (plan 310 §4), not about the one type the function ends up
    // carrying: a body whose only Return sits inside an `If` declares its
    // type there, and that line is what a member handing back the wrong thing
    // must be reported against. Cleared at the start of each definition.
    typed_returns: Vec<(usize, Type)>,
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
            member_functions: std::collections::HashMap::new(),
            claimed_names: std::collections::HashMap::new(),
            statement_depth: 0,
            typed_returns: Vec::new(),
            include_base: None,
            included_files: std::collections::HashSet::new(),
            included_paths: Vec::new(),
            included_statements: None,
        }
    }

    pub fn with_source(mut self, filename: &str, content: &str) -> Self {
        // A `see "./x.vox"` resolves against the directory of the file that
        // wrote it, and this is where the parse learns what that is. Seeding
        // the already-included set with this file is what stops a file that
        // sees itself from recursing.
        let path = std::path::PathBuf::from(filename);
        self.include_base = Some(
            path.parent()
                .filter(|dir| !dir.as_os_str().is_empty())
                .map(|dir| dir.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from(".")),
        );
        self.included_files
            .insert(path.canonicalize().unwrap_or(path));
        self.source_file = Some(SourceFile::new(filename, content));
        self
    }

    /// Resolve this parse's `see` paths against `dir` rather than against the
    /// directory of the name the source is displayed under. Only the
    /// compile_fail harness needs the two to differ: its `.err` fixtures pin
    /// the bare file name in the rendered error, while the cases themselves
    /// live in `tests/compile_fail`.
    #[cfg(test)]
    pub(crate) fn with_include_base(mut self, dir: &std::path::Path) -> Self {
        self.include_base = Some(dir.to_path_buf());
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
        // A declared member stands wherever a function does, so
        // `"{origin's 'shifted north'}"` has to resolve here too (§4).
        self.member_functions = outer.member_functions.clone();
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
    /// current token. The lexer canonicalises aliases (`ms` →
    /// `Token::Milliseconds`, `message` → `Token::Text`, …) so by the time
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

    /// Like `expect`, but matches an ordinary identifier by its lexeme
    /// (case-insensitive). Used for contextual words that are no longer
    /// reserved tokens (`size`, …): the parser claims them in a fixed
    /// grammatical position by the word itself, not a token kind.
    fn expect_lexeme(&mut self, lexeme: &str) -> bool {
        if matches!(self.current(), Token::Identifier(ref id) if id.to_lowercase() == lexeme) {
            self.advance();
            true
        } else {
            false
        }
    }

}

