//! migrate-identifiers — plan 270, stage S4.
//!
//! Rewrites a `.vox` file from the old double-quoted-identifier syntax to the
//! canonical syntax defined in `docs/plans/270_identifier_syntax.md`:
//!
//!   * `"..."` that is a string literal  -> untouched
//!   * an identifier written `"X"`      -> `X` when bare-legal, else `'X'`
//!
//! The codemod is exact, not heuristic. Every double-quoted token is classified
//! by grammar position (the S4 rewrite table) and, for positions the table does
//! not list, by whether `X` names something declared in the same compilation
//! unit — mirroring the compiler's own resolution of a quoted name to a
//! variable (codegen: `emit_load_named_var_into_rax`). A quoted name that the
//! old compiler resolved to a variable must become an identifier; a quoted name
//! that was always a string stays a string.
//!
//! Whitespace — comments, blank lines, indentation — is preserved byte for
//! byte. Paragraph breaks are semantic in Vox (they terminate function bodies),
//! so the tool never reflows. It is idempotent: running it twice equals once,
//! and a file already in canonical form comes out byte-identical.
//!
//! No external crates (same constraint as the compiler). The tokenizer is
//! hand-rolled because the S1 compiler will reject double-quoted identifiers, so
//! this tool cannot depend on the compiler's parser.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

// ---------------------------------------------------------------------------
// Reserved keywords. A bare word is a valid identifier only if it is NOT one of
// these. This is the set of words the lexer's `read_word` maps to a keyword
// token (not `Token::Identifier`) — NOT the `string_is_keyword` set. The
// difference matters: a name like `append` is allowed by `string_is_keyword`
// (so `a buffer called "append"` parses) but bare `append` lexes as the
// `Append` keyword, so it must be written `'append'`. Sorted for binary search.
// ---------------------------------------------------------------------------
/// The exact set of words the lexer's `read_word` (src/lexer/mod.rs:726-886)
/// maps to a keyword token rather than `Token::Identifier`. Sorted for binary
/// search. Excludes the three Identifier-mapped spellings (`flags`, `it`,
/// `start`), the apostrophe keywords (unreachable as bare words), and the
/// `bit-*` hyphenated forms (a hyphen is never bare-legal anyway). A bare word
/// is a valid identifier only if it is NOT in this set.
const RESERVED: &[&str] = &[
    "a", "abs", "absolute", "accessed", "add", "all", "allocate", "an", "and",
    "append", "appending", "are", "arg", "args", "argument", "arguments",
    "array", "as", "assign", "at", "auto", "automatic", "begin", "between",
    "bigger", "bool", "boolean", "break", "buffer", "but", "byte", "bytes",
    "called", "capacity", "clear", "close", "closed", "collection", "continue",
    "copy", "count", "create", "current", "day", "days", "deallocate", "decimal",
    "decrement", "default", "define", "delay", "delete", "descriptor",
    "dictionary", "disable", "disabled", "display", "divide", "duration",
    "each", "elapsed", "element", "else", "empty", "enable", "enabled", "env",
    "environment", "equal", "equals", "error", "even", "exist", "exists", "exit",
    "false", "fd", "fetch", "fewer", "file", "finish", "first", "flag", "float",
    "for", "free", "from", "full", "get", "give", "greater", "grow", "hour",
    "hours", "if", "import", "in", "include", "increment", "input", "inside",
    "int", "integer", "into", "is", "keys", "larger", "last", "length", "less",
    "lib", "library", "list", "make", "map", "message", "millisecond",
    "milliseconds", "minus", "minute", "minutes", "mod", "modified", "modulo",
    "month", "months", "more", "ms", "multiply", "named", "negative", "nil",
    "no", "not", "nothing", "null", "number", "numbers", "odd", "of", "on",
    "open", "opened", "or", "otherwise", "param", "parameter", "parameters",
    "params", "parse", "pause", "permissions", "perms", "plus", "positive",
    "print", "prints", "push", "quit", "raw", "read", "readable", "reading",
    "real", "reallocate", "release", "remainder", "remove", "repeat", "require",
    "required", "resize", "retrieve", "return", "returns", "running", "second",
    "seconds", "see", "seek", "set", "show", "shrink", "sign", "size", "skip",
    "sleep", "smaller", "standard", "starting", "stop", "stopwatch", "store",
    "string", "subtract", "terminate", "text", "than", "the", "then", "time",
    "timer", "times", "timestamp", "to", "treat", "treating", "true", "unix",
    "unixtime", "up", "values", "var", "variable", "ver", "version", "wait",
    "when", "while", "with", "within", "without", "writable", "write", "writing",
    "year", "years", "yes", "zero",
];

fn is_reserved(lower: &str) -> bool {
    RESERVED.binary_search(&lower).is_ok()
}

/// Words that can be the `<type>` in `a <type> called "<name>"` — a name
/// declaration. The two English `called` grammars are distinguished by what
/// immediately precedes `called`:
///
///   * `a <type> called "<name>"` — a type keyword precedes `called`; the quoted
///     token is a variable/parameter name (rewrite to an identifier).
///   * `Create a directory called "<path>"` / `Create a device node called
///     "<path>"` — a non-type noun (`directory`, `node`) precedes `called`;
///     `called` introduces a filesystem path, which is data (leave the string).
///
/// Keying off the grammatical shape (type keyword before `called` ⇒ name)
/// generalises to statement kinds the corpus has not hit yet, instead of
/// special-casing each filesystem verb. Derived from the lexer's type tokens
/// (src/lexer/mod.rs:786-883) plus `value` (a pseudo-type handled specially in
/// parse_typed_var_decl) and `reading`/`writing` (file-handle declarations:
/// `open a file for reading called "src"`). None of these is a path noun.
const TYPE_KWS: &[&str] = &[
    "number", "numbers", "float", "decimal", "real", "int", "integer",
    "text", "string", "message", "boolean", "bool", "list", "array",
    "collection", "map", "dictionary", "buffer", "file", "bytes", "timer",
    "stopwatch", "byte", "flag", "value", "reading", "writing",
];

/// A name is bare-legal when it matches `^[A-Za-z_][A-Za-z0-9_]*$` and is not a
/// reserved keyword. (Spec §"The rule": single-word identifiers are ASCII.)
fn is_bare_legal(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }
    !is_reserved(&name.to_ascii_lowercase())
}

/// The canonical spelling of an identifier content.
enum Form {
    Bare(String),
    Quoted(String),
    /// Needs quoting but contains `'` or a newline, or is a single character
    /// that would collide with a character literal (`'X'`).
    Unrepresentable,
}

fn canonical(content: &str) -> Form {
    if is_bare_legal(content) {
        return Form::Bare(content.to_string());
    }
    // Needs the quoted form `'…'`: requires two or more characters (one char is
    // a character literal) and no inner quote or newline.
    if content.contains('\'') || content.contains('\n') {
        return Form::Unrepresentable;
    }
    if content.chars().count() < 2 {
        return Form::Unrepresentable;
    }
    Form::Quoted(content.to_string())
}

// ---------------------------------------------------------------------------
// Tokenizer.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Word,
    DStr,
    SStr,
    CharLit,
    Apostrophe,
    Number,
    Punct,
    Newline,
    Para,
}

struct Tok {
    start: usize,
    end: usize,
    kind: Kind,
    /// For Word: the raw text. For DStr/SStr: the unescaped content. Else empty.
    text: String,
}

impl Tok {
    fn is_nl(&self) -> bool {
        matches!(self.kind, Kind::Newline | Kind::Para)
    }
    /// Lowercased word text if this is a Word, else None.
    fn word_lower(&self) -> Option<&str> {
        if self.kind == Kind::Word {
            Some(&self.text)
        } else {
            None
        }
    }
}

struct Tokenizer<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Tokenizer<'a> {
    fn new(src: &'a str) -> Self {
        Tokenizer {
            src,
            bytes: src.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self, off: usize) -> Option<char> {
        self.src[self.pos..].chars().nth(off)
    }

    fn skip_comment(&mut self) {
        // self.pos is on '('. Consume until the matching ')', nesting tracked.
        let mut depth: i32 = 0;
        while self.pos < self.bytes.len() {
            let c = self.src[self.pos..].chars().next().unwrap();
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
                self.pos += c.len_utf8();
                if depth == 0 {
                    return;
                }
                continue;
            }
            self.pos += c.len_utf8();
        }
        // Unterminated comment: consumed to EOF.
    }

    fn read_word(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.src[self.pos..].chars().next() {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        self.src[start..self.pos].to_string()
    }

    fn read_dstring(&mut self) -> String {
        // self.pos is on the opening '"'. Consume it.
        self.pos += 1;
        let mut content = String::new();
        while self.pos < self.bytes.len() {
            let c = self.src[self.pos..].chars().next().unwrap();
            if c == '"' {
                self.pos += 1;
                break;
            } else if c == '\\' {
                self.pos += 1;
                if self.pos < self.bytes.len() {
                    let e = self.src[self.pos..].chars().next().unwrap();
                    content.push(match e {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        '\\' => '\\',
                        '"' => '"',
                        other => other,
                    });
                    self.pos += e.len_utf8();
                }
            } else {
                content.push(c);
                self.pos += c.len_utf8();
            }
        }
        content
    }

    /// Is the `'` at self.pos a character literal `'X'` / `'\X'`?
    fn is_char_literal(&self) -> bool {
        // After the quote: either `\` + escaped + close, or one char + close.
        let mut it = self.src[self.pos + 1..].chars();
        match it.next() {
            Some('\\') => {
                it.next(); // the escaped char
                it.next() == Some('\'')
            }
            Some(c) => {
                // consume that one char, then expect a closing quote
                let after = self.pos + 1 + c.len_utf8();
                self.src[after..].chars().next() == Some('\'')
            }
            None => false,
        }
    }

    /// Is the `'` at self.pos a single-quoted identifier `'multi word'`
    /// (and not the possessive `'s`)? Mirrors lexer semantics.
    fn is_single_quoted_identifier(&self) -> bool {
        let rest = &self.src[self.pos + 1..];
        let it = rest.chars();
        // Possessive: 's / 'S followed by whitespace, '.', ',', ''', or end.
        if let Some(first) = it.clone().next() {
            if first == 's' || first == 'S' {
                let after_s = self.pos + 1 + first.len_utf8();
                let second = self.src[after_s..].chars().next();
                match second {
                    Some(c) if c.is_whitespace() || c == '.' || c == ',' || c == '\'' => {
                        return false;
                    }
                    None => return false,
                    _ => {}
                }
            }
        }
        // Scan to a closing quote before a newline; content must be non-empty.
        let mut count = 0usize;
        for c in it {
            if c == '\'' {
                return count > 0;
            } else if c == '\n' {
                return false;
            }
            count += 1;
        }
        false
    }

    fn read_single_quoted(&mut self) -> String {
        // self.pos on opening '. Consume it, read to closing '.
        self.pos += 1;
        let mut content = String::new();
        while self.pos < self.bytes.len() {
            let c = self.src[self.pos..].chars().next().unwrap();
            if c == '\'' {
                self.pos += 1;
                break;
            } else if c == '\\' {
                self.pos += 1;
                if self.pos < self.bytes.len() {
                    let e = self.src[self.pos..].chars().next().unwrap();
                    content.push(match e {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        '\\' => '\\',
                        '\'' => '\'',
                        other => other,
                    });
                    self.pos += e.len_utf8();
                }
            } else {
                content.push(c);
                self.pos += c.len_utf8();
            }
        }
        content
    }

    fn read_number(&mut self) {
        // self.pos on a digit. Hex/binary prefixes, decimals, exponents. A '.'
        // is consumed only when followed by a digit (so `5.` stays `5` + Period).
        let n = self.bytes.len();
        if self.src[self.pos..].starts_with("0x") || self.src[self.pos..].starts_with("0X") {
            self.pos += 2;
            while let Some(c) = self.src[self.pos..].chars().next() {
                if c.is_ascii_hexdigit() || c == '_' {
                    self.pos += c.len_utf8();
                } else {
                    break;
                }
            }
            return;
        }
        if self.src[self.pos..].starts_with("0b") || self.src[self.pos..].starts_with("0B") {
            self.pos += 2;
            while let Some(c) = self.src[self.pos..].chars().next() {
                if c == '0' || c == '1' || c == '_' {
                    self.pos += c.len_utf8();
                } else {
                    break;
                }
            }
            return;
        }
        // decimal integer/float
        while let Some(c) = self.src[self.pos..].chars().next() {
            if c.is_ascii_digit() || c == '_' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        if self.peek(0) == Some('.') {
            if let Some(d) = self.peek(1) {
                if d.is_ascii_digit() {
                    self.pos += 1; // consume '.'
                    while let Some(c) = self.src[self.pos..].chars().next() {
                        if c.is_ascii_digit() || c == '_' {
                            self.pos += c.len_utf8();
                        } else {
                            break;
                        }
                    }
                }
            }
        }
        let _ = n;
        if matches!(self.peek(0), Some('e') | Some('E')) {
            let save = self.pos;
            self.pos += 1;
            if matches!(self.peek(0), Some('+') | Some('-')) {
                self.pos += 1;
            }
            if self.peek(0).map(|c| c.is_ascii_digit()).unwrap_or(false) {
                while let Some(c) = self.src[self.pos..].chars().next() {
                    if c.is_ascii_digit() || c == '_' {
                        self.pos += c.len_utf8();
                    } else {
                        break;
                    }
                }
            } else {
                self.pos = save; // not an exponent; back up
            }
        }
    }

    fn read_newline(&mut self) -> Kind {
        // self.pos on '\n'. Consume it and trailing horizontal whitespace, then
        // decide Newline vs ParagraphBreak (one or more blank lines).
        self.pos += 1;
        while matches!(self.peek(0), Some(' ') | Some('\t') | Some('\r')) {
            self.pos += 1;
        }
        // A following newline (after only whitespace) makes this a paragraph
        // break. Consume all consecutive blank lines into the one Para token so
        // the span is byte-exact.
        if self.peek(0) == Some('\n') {
            while self.peek(0) == Some('\n') {
                self.pos += 1;
                while matches!(self.peek(0), Some(' ') | Some('\t') | Some('\r')) {
                    self.pos += 1;
                }
            }
            Kind::Para
        } else {
            Kind::Newline
        }
    }

    fn tokenize(mut self) -> Vec<Tok> {
        let mut toks = Vec::new();
        while self.pos < self.bytes.len() {
            let start = self.pos;
            let c = self.src[self.pos..].chars().next().unwrap();
            match c {
                '(' => {
                    self.skip_comment();
                    continue; // comment is a gap, no token
                }
                ')' => {
                    self.pos += 1; // stray ')' is a gap
                    continue;
                }
                '\n' => {
                    let kind = self.read_newline();
                    toks.push(Tok {
                        start,
                        end: self.pos,
                        kind,
                        text: String::new(),
                    });
                }
                ' ' | '\t' | '\r' => {
                    self.pos += 1; // horizontal whitespace is a gap
                    continue;
                }
                '"' => {
                    let content = self.read_dstring();
                    toks.push(Tok {
                        start,
                        end: self.pos,
                        kind: Kind::DStr,
                        text: content,
                    });
                }
                '\'' => {
                    if self.is_char_literal() {
                        // consume the whole literal through the closing quote
                        let mut it = self.src[self.pos..].chars();
                        it.next(); // opening '
                        let first = it.next();
                        if first == Some('\\') {
                            it.next(); // escaped char
                        }
                        // consume until closing '
                        for c in self.src[self.pos + 1..].chars() {
                            self.pos += c.len_utf8();
                            if c == '\'' {
                                break;
                            }
                        }
                        let _ = first;
                        toks.push(Tok {
                            start,
                            end: self.pos,
                            kind: Kind::CharLit,
                            text: String::new(),
                        });
                    } else if self.is_single_quoted_identifier() {
                        let content = self.read_single_quoted();
                        toks.push(Tok {
                            start,
                            end: self.pos,
                            kind: Kind::SStr,
                            text: content,
                        });
                    } else {
                        self.pos += 1; // just the apostrophe (possessive)
                        toks.push(Tok {
                            start,
                            end: self.pos,
                            kind: Kind::Apostrophe,
                            text: String::new(),
                        });
                    }
                }
                c if c.is_ascii_digit() => {
                    self.read_number();
                    toks.push(Tok {
                        start,
                        end: self.pos,
                        kind: Kind::Number,
                        text: String::new(),
                    });
                }
                c if c.is_alphabetic() || c == '_' => {
                    let word = self.read_word();
                    toks.push(Tok {
                        start,
                        end: self.pos,
                        kind: Kind::Word,
                        text: word,
                    });
                }
                _ => {
                    self.pos += c.len_utf8();
                    toks.push(Tok {
                        start,
                        end: self.pos,
                        kind: Kind::Punct,
                        text: String::new(),
                    });
                }
            }
        }
        toks
    }
}

// ---------------------------------------------------------------------------
// Index helpers computed from the token stream.
// ---------------------------------------------------------------------------

fn build_indexes(toks: &[Tok]) -> (Vec<Option<usize>>, Vec<Option<usize>>, Vec<bool>) {
    let n = toks.len();
    let mut sig_prev = vec![None; n];
    let mut sig_next = vec![None; n];
    let mut line_start = vec![false; n];
    let mut last_sig: Option<usize> = None;
    for i in 0..n {
        line_start[i] = i == 0 || toks[i - 1].is_nl();
        if !toks[i].is_nl() {
            sig_prev[i] = last_sig;
            last_sig = Some(i);
        }
    }
    let mut next_sig: Option<usize> = None;
    for i in (0..n).rev() {
        if !toks[i].is_nl() {
            sig_next[i] = next_sig;
            next_sig = Some(i);
        }
    }
    (sig_prev, sig_next, line_start)
}

/// Set membership test against a few word spellings (case-insensitive).
fn word_in(toks: &[Tok], idx: Option<usize>, set: &[&str]) -> bool {
    match idx {
        Some(i) => match toks[i].word_lower() {
            Some(w) => set.iter().any(|s| s.eq_ignore_ascii_case(w)),
            None => false,
        },
        None => false,
    }
}

/// The lowercased word of the significant token two steps before `i` — i.e. the
/// word immediately before this token's own predecessor. Used to tell the two
/// `called` grammars apart: for `called "<X>"`, `prev` is `called` itself and
/// `prev_prev` is the `<type>` (name declaration) or the path noun (`directory`,
/// `node` — a filesystem path). Returns `None` when there is no such token or it
/// is not a word.
fn prev_prev_word<'a>(toks: &'a [Tok], sig_prev: &[Option<usize>], i: usize) -> Option<&'a str> {
    let prev = sig_prev[i]?;
    let pp = sig_prev[prev]?;
    toks[pp].word_lower()
}

// ---------------------------------------------------------------------------
// Pass 1: collect declared names.
//   functions  — names introduced by `To "X"` at line start (callable anywhere).
//   globals    — top-level (outside any function body) names from `called "X"`
//               and `For/Print each <bare>`.
// Function-local names are tracked incrementally in pass 2.
// ---------------------------------------------------------------------------

fn in_function_walk(toks: &[Tok], line_start: &[bool]) -> Vec<bool> {
    // in_func[i] = token i is inside a function header or body. The `To` word
    // itself is the entry; the blank line (Para) that ends the body is outside.
    let n = toks.len();
    let mut in_func = vec![false; n];
    let mut active = false;
    for i in 0..n {
        let entering = !active
            && toks[i].kind == Kind::Word
            && line_start[i]
            && {
                let w = toks[i].text.to_ascii_lowercase();
                w == "to" || w == "up"
            };
        if entering {
            active = true;
            in_func[i] = true; // the To header counts as in-function
            continue;
        }
        if active {
            if toks[i].kind == Kind::Para {
                in_func[i] = false; // the terminating blank line is outside
                active = false;
            } else {
                in_func[i] = true;
            }
        } else {
            in_func[i] = false;
        }
    }
    in_func
}

struct Names {
    functions: BTreeSet<String>,
    globals: BTreeSet<String>,
}

fn collect_names(toks: &[Tok], sig_prev: &[Option<usize>], in_func: &[bool]) -> Names {
    let mut functions = BTreeSet::new();
    let mut globals = BTreeSet::new();
    for i in 0..toks.len() {
        if toks[i].kind != Kind::DStr {
            continue;
        }
        // `To "X"` at line start -> function name.
        if let Some(p) = sig_prev[i] {
            if toks[p].kind == Kind::Word {
                let w = toks[p].text.to_ascii_lowercase();
                if (w == "to" || w == "up") && line_start_idx(toks, p) {
                    functions.insert(toks[i].text.clone());
                }
            }
        }
        // `called "X"` (declared name): global if at top level. Only count the
        // name-declaration grammar (`a <type> called "X"`); the filesystem-path
        // grammar (`Create a directory called "<path>"`) introduces data, not a
        // variable, so it must not be registered as a declared name.
        if word_in(toks, sig_prev[i], &["called", "named"])
            && !in_func[i]
            && word_in_opt(prev_prev_word(toks, sig_prev, i), TYPE_KWS)
        {
            globals.insert(toks[i].text.clone());
        }
    }
    // `For/Print each <bare>` -> loop var. Top-level ones are globals.
    for i in 0..toks.len() {
        if toks[i].kind == Kind::Word && toks[i].text.eq_ignore_ascii_case("each") {
            if let Some(n) = sig_next_of(toks, i) {
                if toks[n].kind == Kind::Word && !in_func[i] {
                    globals.insert(toks[n].text.clone());
                }
            }
        }
    }
    Names { functions, globals }
}

fn line_start_idx(toks: &[Tok], i: usize) -> bool {
    i == 0 || toks[i - 1].is_nl()
}

fn sig_next_of(toks: &[Tok], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while j < toks.len() {
        if !toks[j].is_nl() {
            return Some(j);
        }
        j += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Classification + migration.
// ---------------------------------------------------------------------------

/// What to do with a double-quoted token.
enum Decision {
    /// Replace the `"..."` span with this text.
    Rewrite(String),
    /// Leave the `"..."` as-is. `data` true = a known data position (no flag);
    /// `data` false = an unlisted position (flag if it names a declared thing).
    Leave { data: bool },
    /// A name in a must-rewrite position that cannot be represented canonically
    /// — a reserved single-character name (`a`, which is the article keyword and
    /// cannot be bare, while `'a'` is a character literal) or a name containing
    /// `'`. The `"..."` is left as-is and recorded as a failure: the name needs
    /// hand-renaming in the corpus, since the new syntax has no spelling for it.
    Failed,
}

struct Migration {
    out: String,
    /// (line, original, replacement) for each rewritten token, for reporting.
    rewrites: Vec<(usize, String, String)>,
    /// Left as a string but its content names a declared thing — may be a
    /// variable reference the spec leaves as a string. Review by hand.
    flags: Vec<(usize, String)>,
    /// Could not represent the name canonically (e.g. contains `'`).
    failures: Vec<(usize, String)>,
}

fn migrate(src: &str) -> Migration {
    let toks = Tokenizer::new(src).tokenize();
    let (sig_prev, sig_next, line_start) = build_indexes(&toks);
    let in_func = in_function_walk(&toks, &line_start);
    let names = collect_names(&toks, &sig_prev, &in_func);

    // Pre-load the always-in-scope names (functions and globals are visible
    // throughout — functions are hoisted, top-level vars get BSS).
    let mut base_scope: BTreeSet<String> = BTreeSet::new();
    for n in &names.functions {
        base_scope.insert(n.clone());
    }
    for n in &names.globals {
        base_scope.insert(n.clone());
    }

    let mut out = String::with_capacity(src.len());
    let mut pos = 0usize;
    let mut rewrites = Vec::new();
    let mut flags = Vec::new();
    let mut failures = Vec::new();

    // Pass 2: walk left-to-right, maintaining function-local scope incrementally
    // (decl-before-use within a function). `func_locals` holds locals of the
    // current function declared so far.
    let mut in_function = false;
    let mut func_locals: BTreeSet<String> = BTreeSet::new();

    // `start` and `end` map to Token::Identifier in the lexer but still head a
    // timer statement (`Start the "t"` / `End the "t"`), so match by text.
    let timer_kws = ["start", "stop", "begin", "end", "finish"];
    // Words the lexer maps to Token::Print (the `print` family). `say`/`output`
    // are NOT keywords — a leading `say`/`output` is an ordinary identifier, so
    // a quoted name after them falls through to the general rule, not a
    // must-not.
    let print_kws = ["print", "prints", "display", "show"];
    let see_kws = ["see", "import", "include", "require"];
    // The call operator `with` (Token::With). Only `with` itself — there is no
    // `using`/`given`/`taking` call operator in the grammar.
    let with_kws = ["with"];
    let to_kws = ["to", "up"];
    let data_guard = ["write", "append", "copy"];
    // Words that, when they follow `with` (or `at … with`), mark the string
    // before `with` as a filesystem-statement data argument rather than a call
    // operand: `Mount "x" at "y" with type/options/size`, `Execute "p" with
    // arguments`, `Pivot root to "p" with old root`. None is a call expression,
    // so the callee `with` rule must not fire on them.
    let with_data_kws = ["type", "options", "size", "arguments", "old"];

    for i in 0..toks.len() {
        let tok = &toks[i];

        // Function-body scope tracking (must run before classifying this token
        // so the DStr sees locals declared earlier in the same function).
        if tok.kind == Kind::DStr {
            let prev = sig_prev[i];
            // Entering a function: the To-rule DStr (prev is line-start `to`).
            let entering = word_in(&toks, prev, &to_kws)
                && prev.map(|p| line_start[p]).unwrap_or(false);
            if entering {
                in_function = true;
                func_locals.clear();
            }
        }

        if tok.kind != Kind::DStr {
            // `For/Print each <bare>`: loop var is the word after `each`.
            if tok.kind == Kind::Word && tok.text.eq_ignore_ascii_case("each") {
                if let Some(n) = sig_next[i] {
                    if toks[n].kind == Kind::Word && in_function {
                        func_locals.insert(toks[n].text.clone());
                    }
                }
            }
            // Normalise a single-quoted identifier `'word'` whose content is
            // bare-legal to the bare form. The canonical spelling of a
            // single-word identifier is bare; `'word'` is valid but
            // non-canonical. Multi-word `'multi word'` stays (already canonical).
            // A char literal `'X'` is a different token kind and is untouched.
            if tok.kind == Kind::SStr && is_bare_legal(&tok.text) {
                let line = line_number(src, tok.start);
                out.push_str(&src[pos..tok.start]);
                out.push_str(&tok.text);
                rewrites.push((line, format!("'{}'", tok.text), tok.text.clone()));
                pos = tok.end;
                continue;
            }
            // Emit gap + token verbatim, advance pos.
            out.push_str(&src[pos..tok.end]);
            pos = tok.end;
            // Paragraph break ends a function body.
            if tok.kind == Kind::Para && in_function {
                in_function = false;
                func_locals.clear();
            }
            continue;
        }

        // --- Classify a double-quoted token. ---
        let content = &tok.text;
        let prev = sig_prev[i];
        let next = sig_next[i];
        let prev_w = toks_word(&toks, prev);
        let next_w = toks_word(&toks, next);

        // Effective in-scope set at this point.
        let in_scope = |c: &str| -> bool {
            if base_scope.contains(c) {
                return true;
            }
            if in_function && func_locals.contains(c) {
                return true;
            }
            // Case-insensitive name match (Vox names are case-insensitive).
            base_scope
                .iter()
                .any(|n| n.eq_ignore_ascii_case(c))
                || (in_function
                    && func_locals.iter().any(|n| n.eq_ignore_ascii_case(c)))
        };

        let mut decision: Decision = Decision::Leave { data: false };

        // 1. Format string — data, never an identifier.
        if content.contains('{') {
            decision = Decision::Leave { data: true };
        }
        // 2. Flag alias (`"-v"`, `"--verbose"`).
        else if content.starts_with('-') {
            decision = Decision::Leave { data: true };
        }
        // 3. Map key after a possessive (`person's "name"`, `'multi word's "k"`).
        else if prev_w.map(|w| w == "s").unwrap_or(false) {
            if let Some(pp) = prev.and_then(|p| sig_prev[p]) {
                if matches!(toks[pp].kind, Kind::Apostrophe | Kind::SStr) {
                    decision = Decision::Leave { data: true };
                }
            }
        } else {
            // `from "X"` introduces a path or source (`see … from "path"`,
            // `Create symbolic link from "A" to "B"`), never a callee. Check it
            // before the callee rule so the symlink `from "A" to "B"` is not
            // misread as a `to`-callee (`"A" to "B"`).
            if word_in(&toks, prev, &["from"]) {
                decision = Decision::Leave { data: true };
            }
            // 4. Listed rewrite positions (always identifiers).
            //    called "X" / named "X" — but only the name-declaration grammar
            //    (`a <type> called "X"`). The filesystem-path grammar (`Create a
            //    directory called "<path>"`, `Create a device node called "<path>"`)
            //    reuses the word `called` to introduce a path; a type keyword
            //    immediately precedes `called` for a name, a path noun for a path.
            else if word_in(&toks, prev, &["called", "named"]) {
                if word_in_opt(prev_prev_word(&toks, &sig_prev, i), TYPE_KWS) {
                    decision = decide(content);
                } else {
                    decision = Decision::Leave { data: true };
                }
            }
            //    To "X"  (function def, `to` at line start)
            else if word_in(&toks, prev, &to_kws)
                && prev.map(|p| line_start[p]).unwrap_or(false)
            {
                decision = decide(content);
            }
            //    Library "X"  (name -> identifier; version after is left by #5)
            else if word_in(&toks, prev, &["library", "lib"]) {
                decision = decide(content);
            }
            //    see "X" version "V"  (X is the lib name; V, path are data)
            else if word_in(&toks, prev, &see_kws) && word_in(&toks, next, &["version", "ver"]) {
                decision = decide(content);
            }
            //    Start/Stop/Begin/End/Finish [the] "X"  (timer name)
            else if is_timer(&toks, prev, prev_w, &line_start, &timer_kws) {
                decision = decide(content);
            }
            //    "X" of/with/on/to  (callee — the left operand)
            else if let Some(d) = callee(
                content,
                prev_w,
                next_w,
                next,
                &sig_next,
                &toks,
                &with_kws,
                &to_kws,
                &data_guard,
                &with_data_kws,
            ) {
                decision = d;
            }
            // 5. Must-not (known data positions).
            else if word_in(&toks, prev, &["version", "ver"]) {
                decision = Decision::Leave { data: true };
            } else if word_in(&toks, prev, &see_kws) {
                decision = Decision::Leave { data: true }; // see "path.vox"
            } else if word_in(&toks, prev, &print_kws) {
                decision = Decision::Leave { data: true }; // print "string"
            } else {
                // 6. General rule (unlisted position): mirror the compiler's
                //    resolution of a quoted name to a variable — rewrite iff X
                //    names something in scope, else it was always a string.
                if in_scope(content) {
                    decision = decide(content);
                } else {
                    decision = Decision::Leave { data: false };
                }
            }
        }

        // Apply the decision, copying the gap before this token verbatim.
        out.push_str(&src[pos..tok.start]);
        let line = line_number(src, tok.start);
        match &decision {
            Decision::Rewrite(repl) => {
                out.push_str(repl);
                rewrites.push((line, format!("\"{}\"", content), repl.clone()));
            }
            Decision::Leave { data } => {
                out.push_str(&src[tok.start..tok.end]); // keep `"..."`
                if !data && in_scope(content) && is_name_like(content) {
                    flags.push((line, content.clone()));
                }
            }
            Decision::Failed => {
                // The name cannot be written canonically; leave the `"..."` and
                // record it so the migration worker knows to hand-rename it.
                out.push_str(&src[tok.start..tok.end]);
                failures.push((line, content.clone()));
            }
        }
        pos = tok.end;

        // If this DStr was a `called "X"` inside a function, register the local
        // for subsequent scope.
        if in_function && word_in(&toks, prev, &["called", "named"]) {
            func_locals.insert(content.clone());
        }
    }
    // Trailing gap (bytes after the last token).
    out.push_str(&src[pos..]);

    Migration {
        out,
        rewrites,
        flags,
        failures,
    }
}

fn toks_word<'a>(toks: &'a [Tok], idx: Option<usize>) -> Option<&'a str> {
    idx.and_then(|i| toks[i].word_lower()).map(|w| w)
}

fn is_timer(
    toks: &[Tok],
    prev: Option<usize>,
    prev_w: Option<&str>,
    line_start: &[bool],
    timer_kws: &[&str],
) -> bool {
    // `Stop the "X"`: prev is "the", prev-prev is a timer keyword at line start.
    if prev_w == Some("the") {
        if let Some(p) = prev {
            if let Some(pp) = sig_prev_at(toks, p) {
                if let Some(w) = toks[pp].word_lower() {
                    if timer_kws.iter().any(|k| k.eq_ignore_ascii_case(w)) && line_start[pp] {
                        return true;
                    }
                }
            }
        }
    }
    // `Stop "X"`: prev is a timer keyword at line start.
    if let Some(w) = prev_w {
        if timer_kws.iter().any(|k| k.eq_ignore_ascii_case(w)) {
            if let Some(p) = prev {
                if line_start[p] {
                    return true;
                }
            }
        }
    }
    false
}

fn sig_prev_at(toks: &[Tok], i: usize) -> Option<usize> {
    let mut j = i;
    loop {
        if j == 0 {
            return None;
        }
        j -= 1;
        if !toks[j].is_nl() {
            return Some(j);
        }
    }
}

fn callee(
    content: &str,
    prev_w: Option<&str>,
    next_w: Option<&str>,
    next: Option<usize>,
    sig_next: &[Option<usize>],
    toks: &[Tok],
    with_kws: &[&str],
    to_kws: &[&str],
    data_guard: &[&str],
    with_data_kws: &[&str],
) -> Option<Decision> {
    // `of` — no false-positive form in the corpus.
    if next_w == Some("of") {
        return Some(decide(content));
    }
    // `on` (not `at` — `at` is the Mount/Open separator, never a callee here).
    if next_w == Some("on") {
        return Some(decide(content));
    }
    // `with` — but `Mount "dst" with type/options/size`, `Execute "p" with
    // arguments`, and `Pivot root to "p" with old root` are statement grammar,
    // not call expressions: the word after `with` marks the string as data.
    if word_in_opt(next_w, with_kws) {
        if let Some(ni) = next {
            if let Some(nn) = sig_next[ni] {
                if word_in(toks, Some(nn), with_data_kws) {
                    return Some(Decision::Leave { data: true });
                }
            }
        }
        return Some(decide(content));
    }
    // `to` — but `Write/Append/Copy "data" to` is data.
    if word_in_opt(next_w, to_kws) {
        if word_in_opt(prev_w, data_guard) {
            return Some(Decision::Leave { data: true });
        }
        return Some(decide(content));
    }
    None
}

fn word_in_opt(w: Option<&str>, set: &[&str]) -> bool {
    match w {
        Some(s) => set.iter().any(|k| k.eq_ignore_ascii_case(s)),
        None => false,
    }
}

/// Classify name content into a Rewrite decision, or `Failed` when it cannot be
/// represented canonically (a reserved single-char name like `a`, or a name
/// containing `'`). The caller leaves a `Failed` name as the original `"..."`.
fn decide(content: &str) -> Decision {
    match canonical(content) {
        Form::Bare(s) => Decision::Rewrite(s),
        Form::Quoted(s) => Decision::Rewrite(format!("'{}'", s)),
        Form::Unrepresentable => Decision::Failed,
    }
}

/// A string that looks like a bare-or-multi-word name (no path/version/flag
/// characters). Used to decide whether a left-as-string token is worth flagging.
fn is_name_like(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ' ')
}

fn line_number(src: &str, byte: usize) -> usize {
    src[..byte].matches('\n').count() + 1
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn run_file(path: &PathBuf, in_place: bool) -> bool {
    // returns true if the file had a HARD failure (unrepresentable / IO error)
    let src = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path.display(), e);
            return true;
        }
    };
    let m = migrate(&src);
    let failed = !m.failures.is_empty();
    let nrew = m.rewrites.len();
    let nflag = m.flags.len();
    if nrew == 0 && nflag == 0 && !failed {
        println!("{}: unchanged", path.display());
    } else {
        println!(
            "{}: {} rewrite(s), {} flag(s){}",
            path.display(),
            nrew,
            nflag,
            if failed { ", FAILED" } else { "" }
        );
    }
    for (line, orig, repl) in &m.rewrites {
        println!("  L{}: {} -> {}", line, orig, repl);
    }
    for (line, content) in &m.flags {
        println!(
            "  L{}: REVIEW \"{}\" left as string but names a declared thing (spec may omit this position)",
            line, content
        );
    }
    for (line, content) in &m.failures {
        let why = if content.contains('\'') || content.contains('\n') {
            "contains ' or newline"
        } else {
            // No bare form (reserved keyword) and no quoted form (one char would
            // collide with a character literal) — e.g. the single-letter name `a`,
            // which is the article keyword. Rename it in the corpus.
            "reserved single-char name (bare is a keyword, 'x' is a char literal)"
        };
        println!(
            "  L{}: FAILED \"{}\" cannot be represented canonically ({}) — rename this name",
            line, content, why
        );
    }
    if in_place && !failed {
        if m.out != src {
            if let Err(e) = fs::write(path, &m.out) {
                eprintln!("error: cannot write {}: {}", path.display(), e);
                return true;
            }
        }
    }
    failed
}

fn usage() {
    eprintln!(
        "usage: migrate-identifiers [--in-place] [--dry-run] <file...>\n\
         --dry-run (default): report only, do not write\n\
         --in-place: rewrite files in place"
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        return ExitCode::from(2);
    }
    let mut in_place = false;
    let mut dry = false;
    let mut files: Vec<PathBuf> = Vec::new();
    for a in &args {
        match a.as_str() {
            "--in-place" => in_place = true,
            "--dry-run" => dry = true,
            "-h" | "--help" => {
                usage();
                return ExitCode::from(0);
            }
            other if other.starts_with("--") => {
                eprintln!("unknown option: {}", other);
                usage();
                return ExitCode::from(2);
            }
            _ => files.push(PathBuf::from(a)),
        }
    }
    if dry && in_place {
        eprintln!("--in-place and --dry-run are mutually exclusive");
        return ExitCode::from(2);
    }
    if files.is_empty() {
        eprintln!("no input files");
        return ExitCode::from(2);
    }
    let _ = dry; // default is dry-run; --in-place opts in
    let mut any_failed = false;
    for f in &files {
        if run_file(f, in_place) {
            any_failed = true;
        }
    }
    if any_failed {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrote(src: &str) -> String {
        migrate(src).out
    }

    fn count_rewrites(src: &str) -> usize {
        migrate(src).rewrites.len()
    }

    fn assert_unchanged(src: &str) {
        assert_eq!(migrate(src).out, src, "input should be unchanged");
        assert_eq!(
            count_rewrites(src),
            0,
            "canonical input must produce zero rewrites"
        );
    }

    // --- called ------------------------------------------------------------
    #[test]
    fn called_bare() {
        assert_eq!(rewrote("a number called \"total\" is 5.\n"), "a number called total is 5.\n");
    }
    #[test]
    fn called_quoted() {
        assert_eq!(
            rewrote("a number called \"total items\" is 5.\n"),
            "a number called 'total items' is 5.\n"
        );
    }
    #[test]
    fn called_reserved_becomes_quoted() {
        // "append" is allowed as a name but bare `append` lexes as a keyword.
        assert_eq!(
            rewrote("a buffer called \"append\" is \"x\".\n"),
            "a buffer called 'append' is \"x\".\n"
        );
    }
    #[test]
    fn called_type_keyword_becomes_quoted() {
        // `real` maps to Token::Float — bare `real` would not be an identifier.
        assert_eq!(
            rewrote("a number called \"real\" is 5.\n"),
            "a number called 'real' is 5.\n"
        );
    }

    // --- To -----------------------------------------------------------------
    #[test]
    fn to_function_def_bare() {
        assert_eq!(rewrote("To \"f\".\n  Return a number, 1.\n"), "To f.\n  Return a number, 1.\n");
    }
    #[test]
    fn to_function_def_quoted() {
        assert_eq!(
            rewrote("To \"add up\" with a number called \"x\".\n  Return a number, x.\n"),
            "To 'add up' with a number called x.\n  Return a number, x.\n"
        );
    }

    // --- callee of/with/on/to ---------------------------------------------
    #[test]
    fn callee_of() {
        assert_eq!(rewrote("print \"add up\" of 3 and 4.\n"), "print 'add up' of 3 and 4.\n");
    }
    #[test]
    fn callee_with() {
        assert_eq!(rewrote("print \"add up\" with var1 and var2.\n"), "print 'add up' with var1 and var2.\n");
    }
    #[test]
    fn callee_on() {
        assert_eq!(rewrote("a number called \"s\" is \"factorial\" on 5.\n"),
            "a number called s is factorial on 5.\n");
    }
    #[test]
    fn callee_to_set_flag() {
        // `Set "flag" to true` — the flag name is the callee (left of `to`).
        // `verbose` is not a reserved word, so the canonical form is bare.
        assert_eq!(
            rewrote("a flag called \"verbose\" is true.\nset \"verbose\" to false.\n"),
            "a flag called verbose is true.\nset verbose to false.\n"
        );
    }

    // --- must-not: Write/Append/Copy data ----------------------------------
    #[test]
    fn write_data_not_rewritten() {
        assert_unchanged("Write \"Hello World\" to output.\n");
    }
    #[test]
    fn append_data_not_rewritten() {
        assert_unchanged("append \"hello\" to staged_output.\n");
    }
    #[test]
    fn copy_format_not_rewritten() {
        assert_unchanged("copy \"Y={n}\" to buf.\n");
    }

    // --- must-not: Mount with type/options ---------------------------------
    #[test]
    fn mount_paths_not_rewritten() {
        assert_unchanged("Mount \"proc\" at \"/proc\" with type \"proc\".\n");
        assert_unchanged("Mount \"src\" at \"/dst\" with type \"none\" with options \"bind\".\n");
    }

    // --- Library -----------------------------------------------------------
    #[test]
    fn library_name_rewritten_version_left() {
        assert_eq!(
            rewrote("Library \"math kit\" version \"1.0\".\n"),
            "Library 'math kit' version \"1.0\".\n"
        );
    }

    // --- see ----------------------------------------------------------------
    #[test]
    fn see_version_name_rewritten() {
        assert_eq!(
            rewrote("see \"mathkit\" version \"1.0\" from \"./libmathkit.lib\".\n"),
            "see mathkit version \"1.0\" from \"./libmathkit.lib\".\n"
        );
    }
    #[test]
    fn see_path_unchanged() {
        assert_unchanged("see \"./include/math_helpers.vox\".\n");
    }

    // --- timer --------------------------------------------------------------
    #[test]
    fn timer_start_the() {
        assert_eq!(
            rewrote("a timer called \"job timer\" is 0.\nStart the \"job timer\".\nStop the \"job timer\".\n"),
            "a timer called 'job timer' is 0.\nStart the 'job timer'.\nStop the 'job timer'.\n"
        );
    }
    #[test]
    fn timer_stop_no_the() {
        assert_eq!(rewrote("Stop \"t\".\n"), "Stop t.\n");
    }

    // --- must-not: map keys -------------------------------------------------
    #[test]
    fn map_key_unchanged() {
        assert_unchanged("print person's \"name\".\n");
        assert_unchanged("set person's \"age\" to 37.\n");
    }
    #[test]
    fn map_key_quoted_var_possessive_unchanged() {
        assert_unchanged("print \"job timer\"'s elapsed.\n");
    }

    // --- must-not: flag aliases --------------------------------------------
    #[test]
    fn flag_aliases_unchanged() {
        assert_eq!(
            // the flag name is rewritten (called, bare — not reserved), the
            // aliases stay strings
            rewrote("a flag called \"verbose\" is \"-v\" or \"--verbose\".\n"),
            "a flag called verbose is \"-v\" or \"--verbose\".\n"
        );
    }

    // --- must-not: print strings -------------------------------------------
    #[test]
    fn print_string_unchanged() {
        assert_unchanged("print \"hello world\".\n");
        assert_unchanged("Print \"DONE\".\n");
    }
    #[test]
    fn print_format_unchanged() {
        assert_unchanged("Print \"{x} is {y}\".\n");
    }

    // --- must-not: versions -------------------------------------------------
    #[test]
    fn version_unchanged() {
        assert_unchanged("Library math version \"1.0.3\".\n");
    }

    // --- G4 / general rule --------------------------------------------------
    #[test]
    fn g4_is_function_call() {
        // `is "get five"` where "get five" is a function -> zero-arg call.
        assert_eq!(
            rewrote("To \"get five\".\n  Return a number, 5.\na number called x is \"get five\".\n"),
            "To 'get five'.\n  Return a number, 5.\na number called x is 'get five'.\n"
        );
    }
    #[test]
    fn g4_is_string_left() {
        // "hello" is not declared -> always a string.
        assert_unchanged("a text called shape is \"rectangle\".\n");
        assert_unchanged("If linebuf is \"reboot\" then, print \"MATCH\".\n");
    }

    // --- bare-boolean (spec omission handled by general rule) --------------
    #[test]
    fn if_flag_rewritten() {
        assert_eq!(
            rewrote(
                "a flag called \"wants help\" is \"--help\".\nIf \"wants help\" then,\n  print \"hi\".\n"
            ),
            "a flag called 'wants help' is \"--help\".\nIf 'wants help' then,\n  print \"hi\".\n"
        );
    }

    // --- argument-position variable reference (spec omission) --------------
    #[test]
    fn argument_var_ref_rewritten() {
        // `with "source"` where source is a declared file -> bare variable.
        assert_eq!(
            rewrote(
                "To \"read the file\" with a file called \"source\".\n  Return a buffer, source.\n\
                 a buffer called \"out\" is \"read the file\" with \"source\".\n"
            ),
            "To 'read the file' with a file called source.\n  Return a buffer, source.\n\
             a buffer called out is 'read the file' with source.\n"
        );
    }
    #[test]
    fn argument_string_left() {
        // "world" is not declared -> the string "world" stays.
        assert_eq!(
            rewrote("To \"greet\" with a text called \"n\".\n  print n.\nprint \"greet\" of \"world\".\n"),
            "To greet with a text called n.\n  print n.\nprint greet of \"world\".\n"
        );
    }

    // --- whitespace / paragraph breaks preserved ---------------------------
    #[test]
    fn blank_lines_preserved() {
        let src = "To \"f\".\n  print 1.\n\na number called x is 5.\n";
        assert_eq!(rewrote(src), "To f.\n  print 1.\n\na number called x is 5.\n");
        // The blank line (paragraph break) must survive byte-identically.
        assert!(rewrote(src).contains("\n\na number"));
    }
    #[test]
    fn indentation_preserved() {
        let src = "To \"f\".\n    a number called \"x\" is 5.\n    print x.\n";
        assert_eq!(
            rewrote(src),
            "To f.\n    a number called x is 5.\n    print x.\n"
        );
    }
    #[test]
    fn comments_preserved() {
        // `greet` is not reserved, so the function name rewrites to bare. The
        // `(…)` comment — including the decoy `To "fake"` — is skipped whole.
        let src = "(a comment with \"quotes\" and To \"fake\")\nTo \"greet\".\n  print 1.\n";
        assert_eq!(rewrote(src), "(a comment with \"quotes\" and To \"fake\")\nTo greet.\n  print 1.\n");
    }

    // --- idempotency --------------------------------------------------------
    #[test]
    fn idempotent_on_old_syntax() {
        let src = "a number called \"total items\" is \"f\" of 3.\nTo \"f\" with a number called \"x\".\n  Return a number, x.\n";
        let once = rewrote(src);
        let twice = rewrote(&once);
        assert_eq!(once, twice, "running twice must equal once");
    }
    #[test]
    fn idempotent_on_mixed() {
        let src = "Library \"math kit\" version \"1.0\".\nsee \"mk\" version \"2\" from \"./p.lib\".\nprint \"msg {x}\".\n";
        let once = rewrote(src);
        assert_eq!(rewrote(&once), once);
    }

    // --- canonical file byte-identical -------------------------------------
    #[test]
    fn canonical_file_unchanged() {
        // Already-canonical syntax: bare names, 'multi word' identifiers,
        // strings stay strings, possessives canonical.
        let src = "a number called total is 5.\n\
                   a number called 'total items' is 9.\n\
                   To 'add up' with a number called x.\n  Return a number, x.\n\
                   print 'add up' of 3 and 4.\n\
                   Library 'math kit' version \"1.0\".\n\
                   print person's \"name\".\n\
                   print \"hello\".\n";
        assert_unchanged(src);
    }
    #[test]
    fn canonical_quoted_single_word_normalised() {
        // A single-word quoted identifier ('total') is legal but non-canonical;
        // the codemod normalises it to bare. (Not byte-identical, but idempotent
        // afterwards — covered by idempotent_on_old_syntax.)
        assert_eq!(rewrote("a number called 'total' is 5.\n"), "a number called total is 5.\n");
    }

    // --- failure: unrepresentable name -------------------------------------
    #[test]
    fn unrepresentable_apostrophe_left_and_failed() {
        // A name containing an apostrophe cannot be written `'...`. The token
        // is left as a string and reported as a failure.
        let m = migrate("a text called \"o'brien\" is \"x\".\n");
        assert!(m.out.contains("\"o'brien\""), "left as-is");
        // the string value is still present (a separate DStr, untouched)
        assert!(m.out.contains("\"x\""));
        assert_eq!(m.failures.len(), 1, "failure recorded for the called name");
        assert_eq!(m.failures[0].1, "o'brien");
    }

    // --- scoping: function-local name does not leak ------------------------
    #[test]
    fn function_local_does_not_leak() {
        // "padded" is local to "measure"; outside it is a string, not a var.
        let src = "To \"measure\" with a text called \"word\".\n  a buffer called \"padded\" is \" {word}\\n\".\n  Return a buffer, padded.\n\nprint \"padded\".\n";
        let out = rewrote(src);
        // Inside the function: padded -> bare. Outside: "padded" is a print string -> unchanged.
        assert!(out.contains("a buffer called padded is"));
        assert!(out.contains("print \"padded\"."));
    }

    // --- regression: char literal vs single-char name ----------------------
    #[test]
    fn char_literal_unchanged() {
        assert_unchanged("a number called c is 'A' as a number.\n");
    }

    // =======================================================================
    // Filesystem paths: `called` introduces a PATH, not a name.
    //
    // `Create a directory called "<path>"` reuses the word `called` to introduce
    // a filesystem path (data). The name-declaration form `a <type> called
    // "<name>"` always has a type keyword immediately before `called`; the
    // filesystem form has a non-type noun (`directory`, `node`). The shape rule
    // (type keyword before `called` => name, else => path) tells them apart.
    // =======================================================================
    #[test]
    fn mkdir_create_path_unchanged() {
        assert_unchanged("Create a directory called \"/tmp/vox_test_mkdir\".\n");
        assert_unchanged(
            "Create a directory called \"/tmp/vox_test_mkdir\".\nOn error print \"mkdir failed\", exit 1.\n",
        );
    }
    #[test]
    fn rmdir_remove_path_unchanged() {
        assert_unchanged("Remove the directory called \"/tmp/vox_test_mkdir\".\n");
    }
    #[test]
    fn rmdir_delete_path_unchanged() {
        // `Delete the directory "<path>"` does not use `called` at all.
        assert_unchanged("Delete the directory \"/tmp/vox_test_mkdir\".\n");
    }
    #[test]
    fn mknod_device_node_path_unchanged() {
        assert_unchanged(
            "Create a device node called \"/dev/null\" with type \"c\" major 1 minor 3.\n",
        );
    }
    #[test]
    fn chdir_path_unchanged() {
        assert_unchanged("Change directory to \"/newroot\".\n");
    }

    // --- symlink: `from "<path>" to "<path>"` is data, not a callee --------
    // The `from` path must not be misread as a `to`-callee (`"A" to "B"`).
    #[test]
    fn symlink_paths_unchanged() {
        assert_unchanged("Create symbolic link from \"/proc/self/fd\" to \"/dev/fd\".\n");
    }
    #[test]
    fn symlink_error_path_unchanged() {
        assert_unchanged(
            "Create symbolic link from \"/tmp\" to \"/tmp/vox_nonexistent_dir_12345/bad_link\".\nOn error print \"symlink error detected as expected\".\n",
        );
    }

    // --- execve: `Execute "<path>" with arguments` is data ----------------
    // The path must not be misread as a `with`-callee (`"X" with args`).
    #[test]
    fn execve_path_and_literal_args_unchanged() {
        assert_unchanged("Execute \"/bin/echo\" with arguments [\"hello\", \"world\"].\n");
    }
    #[test]
    fn execve_no_args_path_unchanged() {
        assert_unchanged("Execute \"/bin/sh\".\n");
    }

    // --- pivot_root: `Pivot root to "<path>" with old root "<path>"` -------
    // The path after `to` must not be misread as a `with`-callee.
    #[test]
    fn pivot_root_paths_unchanged() {
        assert_unchanged("Pivot root to \"/newroot\" with old root \"/newroot/oldroot\".\n");
    }

    // --- genuine names still rewrite in files that also contain paths ------
    #[test]
    fn names_rewrite_alongside_paths() {
        // `linktarget`/`linkname` are `text called` names -> bare; every path
        // (`is "/tmp/..."`, `directory called "/tmp/..."`, `from … to …`,
        // `Execute … with arguments […]`) stays a string.
        let src = "a text called \"linktarget\" is \"/tmp/a\".\n\
                   a text called \"linkname\" is \"/tmp/b\".\n\
                   Create a directory called \"/tmp/d\".\n\
                   Create symbolic link from \"/tmp/a\" to \"/tmp/b\".\n\
                   Execute \"/bin/echo\" with arguments [\"x\"].\n";
        let out = rewrote(src);
        assert!(out.contains("a text called linktarget is \"/tmp/a\"."));
        assert!(out.contains("a text called linkname is \"/tmp/b\"."));
        assert!(out.contains("Create a directory called \"/tmp/d\"."));
        assert!(out.contains("Create symbolic link from \"/tmp/a\" to \"/tmp/b\"."));
        assert!(out.contains("Execute \"/bin/echo\" with arguments [\"x\"]."));
        assert_eq!(count_rewrites(src), 2, "only the two called names rewrite");
    }
    #[test]
    fn execve_list_var_name_rewrites_path_stays() {
        let src = "a list called \"echoargs\" is [\"from\", \"a\", \"list\", \"variable\"].\n\
                   Execute \"/bin/echo\" with arguments echoargs.\n";
        let out = rewrote(src);
        assert!(out.contains("a list called echoargs is [\"from\", \"a\", \"list\", \"variable\"]."));
        assert!(out.contains("Execute \"/bin/echo\" with arguments echoargs."));
        assert_eq!(count_rewrites(src), 1, "only the list name rewrites");
    }

    // --- idempotency / byte-identity on filesystem-statement input ---------
    #[test]
    fn filesystem_paths_canonical_and_idempotent() {
        let src = "Create a directory called \"/tmp/d\".\n\
                   Create symbolic link from \"/tmp/a\" to \"/tmp/b\".\n\
                   Execute \"/bin/echo\" with arguments [\"x\"].\n\
                   Pivot root to \"/newroot\" with old root \"/newroot/oldroot\".\n";
        let once = rewrote(src);
        assert_eq!(once, src, "paths stay; canonical input is byte-identical");
        assert_eq!(rewrote(&once), once, "running twice equals once");
    }
    #[test]
    fn idempotent_on_mixed_paths_and_names() {
        let src = "a text called \"src\" is \"/tmp/a\".\n\
                   Create a directory called \"/tmp/d\".\n\
                   Execute \"/bin/echo\" with arguments [\"x\"].\n";
        let once = rewrote(src);
        assert_eq!(rewrote(&once), once);
    }

    // =======================================================================
    // Single-char reserved name `a`: a SEPARATE root cause from the path bug.
    //
    // `a` is the article keyword. Bare `called a` does not parse (the compiler
    // rejects the keyword as a name), and `'a'` is a character literal, not a
    // quoted identifier. So a name `a` has no canonical spelling at all — it is
    // unrepresentable, not merely "should be bare". The codemod leaves it as
    // `"a"` and reports a failure so the corpus renames it (e.g. `aa`). This is
    // distinct from the path bug, which is a classification error, not a
    // representability limit. (Verified: `vox` rejects `To "gcd" with a number
    // called a` with "Missing parameter name"; `called 'a'` with the same.)
    // =======================================================================
    #[test]
    fn called_single_char_reserved_is_failure() {
        let src = "To \"gcd\" with a number called \"a\" and a number called \"b\".\n  Return a number, a.\n";
        let m = migrate(src);
        assert!(m.out.contains("To gcd"), "function name rewrites");
        assert!(m.out.contains("called b"), "\"b\" rewrites to bare");
        assert!(m.out.contains("called \"a\""), "\"a\" left as-is (unrepresentable)");
        assert_eq!(m.failures.len(), 1, "exactly one failure (the name `a`)");
        assert_eq!(m.failures[0].1, "a");
    }
    #[test]
    fn to_single_char_reserved_function_name_is_failure() {
        let src = "To \"a\". Return a number, 1.\n";
        let m = migrate(src);
        assert!(m.out.contains("To \"a\"."), "\"a\" function name left as-is");
        assert_eq!(m.failures.len(), 1);
        assert_eq!(m.failures[0].1, "a");
    }
}