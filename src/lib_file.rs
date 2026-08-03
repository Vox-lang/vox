//! Stage A4: parse a `.lib` interface file and resolve a `see` against it.
//!
//! A `.lib` is lexed with the SAME `Lexer` as Vox source — quoting and
//! escaping rules cannot drift — but parsed by this dedicated parser, not the
//! full Vox parser. That is deliberate (plan 230, "The `.lib` format"): a
//! `.lib` must be structurally incapable of carrying executable statements,
//! so this grammar accepts only `Library`/`Location`/`Table of Contents`
//! lines and `To` entries. Anything else is a parse error here, not a
//! post-hoc rejection.
//!
//! Newlines are significant: one ToC entry is exactly one line, however long
//! (the emitter never wraps), so the parser treats a newline as ending the
//! entry. Several `Library` blocks may appear in one file, each with its own
//! `Location`; parsing runs to EOF and a `Library` line starts a new block.
//!
//! The `.lib` is trusted for TYPES and the `.so` is the authority on
//! EXISTENCE: after parsing, every mangled ToC name is verified against the
//! `.so`'s `.dynsym` (`elf.rs`). Types that survived a rebuild differ only
//! when the author edited the `.lib` by hand — the stale-`.lib` case — and
//! that is exactly the diagnostic this module exists to produce.

use std::path::{Path, PathBuf};

use crate::codegen::{mangle_library_symbol, LibFunction};
use crate::lexer::{Lexer, Token, TokenInfo};
use crate::parser::ast::Type;

/// One `Library` block as parsed from a `.lib`: the identity, the `Location`
/// string exactly as written (resolution against the `.lib`'s directory and
/// `--lib-path` happens later), and the table-of-contents signatures.
#[derive(Debug, Clone, PartialEq)]
pub struct LibFileBlock {
    pub lib: String,
    pub version: String,
    pub location: String,
    pub funcs: Vec<LibFunction>,
}

/// One imported function after resolution: the ToC signature plus the mangled
/// `<lib>_<ver>_<func>` symbol it must resolve to in the `.so`. The analyzer
/// keys these by authored `name` for call checking; the codegen keys its
/// signature tables by `mangled` and emits `extern mangled`.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedFunction {
    pub lib: String,
    pub version: String,
    pub name: String,
    pub mangled: String,
    pub params: Vec<(String, Type)>,
    pub return_type: Type,
}

/// The result of resolving one `see "<lib>" version "<ver>" from "<path>".`:
/// the verified signatures and the `.so` to put on the link line.
#[derive(Debug, Clone)]
pub struct ResolvedImport {
    pub lib: String,
    pub version: String,
    pub functions: Vec<ImportedFunction>,
    /// The `.so` path as discovered (the `Location` resolved against the
    /// `.lib`'s directory or a `--lib-path` directory).
    pub so_path: PathBuf,
}

// ---------------------------------------------------------------------------
// The .lib parser
// ---------------------------------------------------------------------------

struct LibParser {
    tokens: Vec<TokenInfo>,
    pos: usize,
}

impl LibParser {
    fn new(text: &str) -> Self {
        let mut lexer = Lexer::new(text);
        LibParser {
            tokens: lexer.tokenize(),
            pos: 0,
        }
    }

    fn current(&self) -> &Token {
        match self.tokens.get(self.pos) {
            Some(t) => &t.token,
            None => &Token::EOF,
        }
    }

    fn advance(&mut self) {
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
    }

    /// 1-based line of the current token, for parse errors — the lexer keeps
    /// positions even though the Vox parser discards them.
    fn line(&self) -> usize {
        self.tokens.get(self.pos).map(|t| t.line).unwrap_or(0)
    }

    fn err(&self, msg: String) -> String {
        format!("line {}: {}", self.line(), msg)
    }

    /// Skip the whitespace tokens that carry no structure here. Newlines
    /// BETWEEN entries are skipped by the callers; inside an entry a newline
    /// is significant (one entry per line), so this only skips blank space.
    fn skip_blank_lines(&mut self) {
        while matches!(self.current(), Token::Newline | Token::ParagraphBreak) {
            self.advance();
        }
    }

    fn expect_period(&mut self, what: &str) -> Result<(), String> {
        if *self.current() == Token::Period {
            self.advance();
            Ok(())
        } else {
            Err(self.err(format!("expected '.' at the end of the {}", what)))
        }
    }

    /// A quoted (or bare single-word) string operand: library names, versions,
    /// paths, and parameter names are all quoted in the emitted format, but a
    /// bare identifier is accepted anywhere one appears.
    fn take_name(&mut self, what: &str) -> Result<String, String> {
        match self.current().clone() {
            Token::StringLiteral(s) => {
                self.advance();
                Ok(s)
            }
            Token::Identifier(s) => {
                self.advance();
                Ok(s)
            }
            _ => Err(self.err(format!("expected {} here, found {:?}", what, self.current()))),
        }
    }

    /// Case-insensitive identifier word (`Location`, `Table`, `Contents`,
    /// `returning`), which the Vox lexer leaves as plain identifiers because
    /// they are not language keywords.
    fn at_word(&self, word: &str) -> bool {
        matches!(self.current(), Token::Identifier(n) if n.eq_ignore_ascii_case(word))
    }

    fn expect_word(&mut self, word: &str, context: &str) -> Result<(), String> {
        if self.at_word(word) {
            self.advance();
            Ok(())
        } else {
            Err(self.err(format!(
                "expected '{}' in {}, found {:?}",
                word,
                context,
                self.current()
            )))
        }
    }

    /// The signature type vocabulary. Parameter positions additionally accept
    /// the composite/collection nouns the A3 emitter can write (`buffer`,
    /// `list`, `map`) so the file the compiler emits always re-parses —
    /// parameter types are trusted straight from the file either way.
    /// Return positions accept exactly the normative five (`number`, `text`,
    /// `boolean`, `file`, `value`); anything else is an error naming the
    /// unsupported type.
    fn take_type(&mut self, position: &'static str) -> Result<Type, String> {
        let ty = match self.current() {
            Token::Number => Some(Type::Integer),
            Token::Text => Some(Type::String),
            Token::Boolean => Some(Type::Boolean),
            Token::File => Some(Type::File),
            Token::Identifier(n) if n.eq_ignore_ascii_case("value") => Some(Type::Value),
            Token::Buffer if position == "parameter" => Some(Type::Buffer),
            Token::List if position == "parameter" => Some(Type::List(Box::new(Type::Unknown))),
            Token::Map if position == "parameter" => Some(Type::Map(Box::new(Type::Unknown))),
            _ => None,
        };
        match ty {
            Some(t) => {
                self.advance();
                Ok(t)
            }
            None => {
                let found = match self.current() {
                    Token::Identifier(n) => format!("'{}'", n),
                    Token::Buffer => "'buffer'".to_string(),
                    Token::List => "'list'".to_string(),
                    Token::Map => "'map'".to_string(),
                    other => format!("{:?}", other),
                };
                let allowed = if position == "return" {
                    "number, text, boolean, file, value"
                } else {
                    "number, text, boolean, file, buffer, list, map, value"
                };
                Err(self.err(format!(
                    "unsupported type {} in a {} position — a .lib states types \
                     as one of: {}",
                    found, position, allowed
                )))
            }
        }
    }

    /// One table-of-contents entry, which is exactly one physical line:
    /// `To "name" [with a <type> called "p" and ...] [, returning a <type>].`
    /// After the closing period the next token MUST end the line — the
    /// emitter never wraps entries, so a wrapped hand edit is a parse error
    /// here rather than a silently mis-split entry.
    /// The shared diagnostic for a table-of-contents entry split across lines
    /// (or continued onto the next), since the emitter never wraps and the
    /// parser is entitled to treat a newline as ending the entry.
    fn wrap_err(&self, name: &str) -> String {
        self.err(format!(
            "the entry for \"{}\" does not fit on one line — a \
             table-of-contents entry is exactly one line and never wraps",
            name
        ))
    }

    fn parse_toc_entry(&mut self) -> Result<LibFunction, String> {
        self.advance(); // consume 'To'
        let name = self.take_name("a function name after 'To'")?;

        let mut params: Vec<(String, Type)> = Vec::new();
        let mut return_type = Type::Void;

        if *self.current() == Token::With {
            self.advance();
            loop {
                if matches!(self.current(), Token::A | Token::An) {
                    self.advance();
                }
                let ptype = self.take_type("parameter")?;
                if *self.current() == Token::Called {
                    self.advance();
                } else {
                    return Err(self.err(format!(
                        "expected 'called' after the parameter type in the entry for \"{}\"",
                        name
                    )));
                }
                let pname = self.take_name("a parameter name after 'called'")?;
                params.push((pname, ptype));
                if *self.current() == Token::And {
                    self.advance();
                } else {
                    break;
                }
            }
        }

        if *self.current() == Token::Comma {
            self.advance();
            // A newline right after the comma is a hand-wrapped entry: the
            // format's one-entry-per-line rule names that better than a bare
            // "expected 'returning'" would.
            if matches!(self.current(), Token::Newline | Token::ParagraphBreak) {
                return Err(self.wrap_err(&name));
            }
            self.expect_word("returning", "a table-of-contents entry")?;
            if matches!(self.current(), Token::A | Token::An) {
                self.advance();
            }
            return_type = self.take_type("return")?;
        } else if self.at_word("returning") {
            return Err(self.err(format!(
                "the entry for \"{}\" has 'returning' without the comma that \
                 introduces it — a .lib entry reads 'To \"name\" ..., returning a <type>.'",
                name
            )));
        }

        // One entry per line, however long: the entry ends at its period on
        // the same line, and the next token must be the end of the line (or
        // of the file). A newline BEFORE the period is a hand-wrapped entry;
        // anything after the period on the same line is trailing junk.
        if *self.current() == Token::Period {
            self.advance();
        } else if matches!(self.current(), Token::Newline | Token::ParagraphBreak) {
            return Err(self.wrap_err(&name));
        } else {
            return Err(self.err(format!(
                "expected '.' at the end of the entry for \"{}\", found {:?}",
                name,
                self.current()
            )));
        }
        if !matches!(
            self.current(),
            Token::Newline | Token::ParagraphBreak | Token::EOF
        ) {
            return Err(self.err(format!(
                "the entry for \"{}\" does not end at its period — a \
                 table-of-contents entry is exactly one line; nothing may \
                 follow the '.' on that line",
                name
            )));
        }

        Ok(LibFunction {
            name,
            params,
            return_type,
        })
    }

    /// One `Library` block: identity line, `Location` line, `Table of
    /// Contents:` header, then entries until the next `Library` or EOF.
    fn parse_block(&mut self) -> Result<LibFileBlock, String> {
        self.advance(); // consume 'Library'
        let lib = self.take_name("a library name after 'Library'")?;
        if *self.current() == Token::Version {
            self.advance();
        } else {
            return Err(self.err(format!(
                "library \"{}\" has no version — a .lib block reads \
                 'Library \"<name>\" version \"<x.y>\".'",
                lib
            )));
        }
        let version = self.take_name("a version string")?;
        self.expect_period("Library line")?;

        self.skip_blank_lines();
        self.expect_word("location", "a Library block")?;
        let location = self.take_name("a path after 'Location'")?;
        self.expect_period("Location line")?;

        self.skip_blank_lines();
        self.expect_word("table", "a Library block")?;
        if *self.current() == Token::Of {
            self.advance();
        } else {
            return Err("expected 'of' in the 'Table of Contents:' header".to_string());
        }
        self.expect_word("contents", "the 'Table of Contents:' header")?;
        if *self.current() == Token::Colon {
            self.advance();
        } else {
            return Err("the 'Table of Contents' header must end with ':'".to_string());
        }

        let mut funcs = Vec::new();
        loop {
            self.skip_blank_lines();
            match self.current() {
                Token::To => funcs.push(self.parse_toc_entry()?),
                Token::Library | Token::EOF => break,
                other => {
                    return Err(self.err(format!(
                        "unexpected {:?} in the table of contents for library \
                         \"{}\" — entries are 'To \"name\" ... .' lines only; \
                         a .lib file cannot carry executable statements",
                        other, lib
                    )));
                }
            }
        }

        Ok(LibFileBlock {
            lib,
            version,
            location,
            funcs,
        })
    }

    fn parse_file(&mut self) -> Result<Vec<LibFileBlock>, String> {
        let mut blocks = Vec::new();
        loop {
            self.skip_blank_lines();
            match self.current() {
                Token::EOF => break,
                Token::Library => blocks.push(self.parse_block()?),
                other => {
                    return Err(self.err(format!(
                        "unexpected {:?} at the top level of a .lib file — a \
                         .lib contains only 'Library \"<name>\" version \
                         \"<x.y>\".' blocks",
                        other
                    )));
                }
            }
        }
        Ok(blocks)
    }
}

/// Parse `.lib` interface text into its blocks. Errors describe what was
/// found and where in format terms (the lexer keeps no line numbers); the
/// caller prefixes the file path.
pub fn parse_lib_text(text: &str) -> Result<Vec<LibFileBlock>, String> {
    let mut p = LibParser::new(text);
    p.parse_file()
}

// ---------------------------------------------------------------------------
// Resolving a `see` against a .lib + .so
// ---------------------------------------------------------------------------

/// Strip redundant `.` components for display in diagnostics. `Path::join`
/// leaves a `.` base joined with a `./`-prefixed relative as `././x`, which
/// reads badly in error text — a user staring at a failure is exactly who
/// reads carefully. This rebuilds the path from its components, dropping
/// every `CurDir` (`.`); `..`, the leading `/` and the final component are
/// preserved, so the result names the same file without the cosmetic noise.
/// The stored path is unchanged — only the message is prettified — so the
/// link line's `parent()`/`canonicalize()` still see the path they expect.
fn normalise_display(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        if let Component::CurDir = c {
            continue;
        }
        out.push(c.as_os_str());
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// Find `name` relative to `first_dir`, then each `--lib-path` directory.
/// Returns the first existing candidate; `tried` collects every candidate
/// for the not-found diagnostic.
fn search_paths(name: &str, first_dir: &Path, lib_paths: &[String]) -> (Option<PathBuf>, Vec<PathBuf>) {
    let mut tried = Vec::new();
    for c in std::iter::once(first_dir.join(name))
        .chain(lib_paths.iter().map(|p| Path::new(p).join(name)))
    {
        tried.push(c.clone());
        if c.exists() {
            return (Some(c), tried);
        }
    }
    (None, tried)
}

/// Resolve the `.lib` named by a `see` statement: relative to the source file
/// first, then each `--lib-path` directory. Absolute paths are honoured.
/// The not-found error names every path tried and mentions `--lib-path`.
fn resolve_lib_file(path: &str, source_dir: &Path, lib_paths: &[String]) -> Result<PathBuf, String> {
    let p = Path::new(path);
    if p.is_absolute() {
        if p.exists() {
            return Ok(p.to_path_buf());
        }
        return Err(format!(
            "the library interface file '{}' does not exist.\n\
             The path is absolute; no search locations apply.",
            path
        ));
    }
    let (found, tried) = search_paths(path, source_dir, lib_paths);
    found.ok_or_else(|| {
        let tried_list = tried
            .iter()
            .map(|t| format!("  {}", normalise_display(t).display()))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "could not find the library interface file '{}'.\nPaths tried:\n{}\n\
             Use --lib-path <dir> to add directories to this search.",
            path, tried_list
        )
    })
}

/// Resolve a block's `Location`: relative to the `.lib` itself first, then
/// each `--lib-path` directory; absolute paths are honoured (the emitter
/// never generates them). The not-found error names the resolved path, not
/// the raw one.
fn resolve_location(location: &str, lib_dir: &Path, lib_paths: &[String]) -> Result<PathBuf, String> {
    let p = Path::new(location);
    if p.is_absolute() {
        if p.exists() {
            return Ok(p.to_path_buf());
        }
        return Err(format!(
            "the .so at Location '{}' does not exist (absolute path).",
            location
        ));
    }
    let (found, _) = search_paths(location, lib_dir, lib_paths);
    found.ok_or_else(|| {
        // The diagnostic names the resolved path — where the loader would
        // have looked relative to the .lib — not the raw Location string.
        let resolved = lib_dir.join(location);
        format!(
            "the .so named by Location \"{}\" does not exist at the resolved \
             path '{}'.\nThe library binary belongs beside the .lib that \
             describes it (or in a directory given by --lib-path).",
            location,
            normalise_display(&resolved).display()
        )
    })
}

/// Resolve one canonical `see "<lib>" version "<ver>" from "<path>.lib".`
/// against the filesystem: find and parse the `.lib`, select the block
/// matching name AND version, resolve its `Location`, and verify every
/// mangled ToC symbol against the `.so`'s `.dynsym`.
///
/// Every failure has its own message naming the file and what was expected —
/// the diagnostics are half the deliverable (plan 230 stage A4):
/// missing `.lib` (paths tried, `--lib-path` exists); no such library (which
/// libraries the file DOES contain); version mismatch (the versions it
/// offers); missing `.so` (the resolved path); symbol absent from `.dynsym`
/// (the stale-`.lib` case, naming the symbol).
pub fn resolve_see_import(
    lib_name: &str,
    lib_version: &str,
    path: &str,
    source_dir: &Path,
    lib_paths: &[String],
) -> Result<ResolvedImport, String> {
    let lib_path = resolve_lib_file(path, source_dir, lib_paths)?;
    let text = std::fs::read_to_string(&lib_path)
        .map_err(|e| format!("could not read '{}': {}", normalise_display(&lib_path).display(), e))?;
    let blocks = parse_lib_text(&text)
        .map_err(|e| format!("could not parse '{}': {}", normalise_display(&lib_path).display(), e))?;

    let matching_name: Vec<&LibFileBlock> = blocks.iter().filter(|b| b.lib == lib_name).collect();
    if matching_name.is_empty() {
        let have = blocks
            .iter()
            .map(|b| format!("\"{}\" version \"{}\"", b.lib, b.version))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "'{}' has no library named \"{}\".\nIt declares: {}.",
            normalise_display(&lib_path).display(),
            lib_name,
            if have.is_empty() { "nothing — the file has no Library blocks".to_string() } else { have }
        ));
    }
    let block = match matching_name.iter().find(|b| b.version == lib_version) {
        Some(b) => *b,
        None => {
            let versions = matching_name
                .iter()
                .map(|b| format!("\"{}\"", b.version))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "'{}' has library \"{}\" but not version \"{}\".\n\
                 The available versions are: {}.",
                normalise_display(&lib_path).display(),
                lib_name,
                lib_version,
                versions
            ));
        }
    };

    let lib_dir = lib_path.parent().unwrap_or(Path::new("."));
    let so_path = resolve_location(&block.location, lib_dir, lib_paths)?;

    // The .lib is trusted for types, the .so is the authority on existence:
    // every mangled name the ToC promises must be a defined dynamic symbol.
    // A miss is the stale-.lib case: the library was rebuilt with different
    // exports (or the .lib was hand-edited) and the pair now disagree.
    let dynsym = crate::elf::defined_dynamic_symbols(&so_path)
        .map_err(|e| format!("checking the library binary: {}", e))?;
    let mut functions = Vec::new();
    for f in &block.funcs {
        let mangled = mangle_library_symbol(&block.lib, &block.version, &f.name);
        if !dynsym.iter().any(|s| s == &mangled) {
            return Err(format!(
                "the .lib entry 'To \"{}\" ...' promises the symbol '{}', but \
                 '{}' does not export it (not in .dynsym).\n\
                 The .lib is stale: it does not match the library binary. \
                 Rebuild the library with `vox --shared` to regenerate the pair.",
                f.name,
                mangled,
                normalise_display(&so_path).display()
            ));
        }
        functions.push(ImportedFunction {
            lib: block.lib.clone(),
            version: block.version.clone(),
            name: f.name.clone(),
            mangled,
            params: f.params.clone(),
            return_type: f.return_type.clone(),
        });
    }

    Ok(ResolvedImport {
        lib: block.lib.clone(),
        version: block.version.clone(),
        functions,
        so_path,
    })
}

/// Resolve every `see ... from "*.lib"` in a parsed program (there may be
/// several). Statements naming `.vox` sources (inlined by `process_includes`)
/// and `.so` paths (retired by stage A5) are not this stage's business and
/// are skipped here.
///
/// A .lib `see` without name and version is rejected: the canonical form is
/// the only one, and a `.lib` containing several blocks cannot be selected
/// without them. The error shows the canonical form.
pub fn resolve_program_imports(
    program: &crate::parser::ast::Program,
    source_dir: &Path,
    lib_paths: &[String],
) -> Result<Vec<ResolvedImport>, String> {
    use crate::parser::ast::Statement;
    let mut resolved: Vec<ResolvedImport> = Vec::new();
    for stmt in &program.statements {
        let (path, lib_name, lib_version) = match stmt {
            Statement::See {
                path,
                lib_name,
                lib_version,
            } if path.ends_with(".lib") => (path, lib_name, lib_version),
            _ => continue,
        };
        let (name, version) = match (lib_name, lib_version) {
            (Some(n), Some(v)) => (n.as_str(), v.as_str()),
            _ => {
                return Err(format!(
                    "see \"{}\": a .lib import must name the library and its \
                     version, so the right block can be selected.\n\
                     Canonical form: see \"<lib>\" version \"<x.y>\" from \"<path>.lib\".",
                    path
                ));
            }
        };
        let import = resolve_see_import(name, version, path, source_dir, lib_paths)?;
        // Re-seeing the same <lib,version> resolves identically (same .lib,
        // same block); keep the first so the import tables stay duplicate-free.
        if !resolved
            .iter()
            .any(|r: &ResolvedImport| r.lib == import.lib && r.version == import.version)
        {
            resolved.push(import);
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_BLOCKS: &str = "Library \"mathkit\" version \"1.0\".\n\
Location \"./libmathkit.so\".\n\
\n\
Table of Contents:\n\
    To \"add two numbers\" with a number called \"a\" and a number called \"b\", returning a number.\n\
    To \"greet\".\n\
\n\
Library \"flags\" version \"0.1\".\n\
Location \"./libflags.so\".\n\
\n\
Table of Contents:\n\
    To \"hasflag\" with a number called \"n\", returning a number.\n";

    #[test]
    fn parses_two_blocks_with_their_own_locations() {
        let blocks = parse_lib_text(TWO_BLOCKS).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].lib, "mathkit");
        assert_eq!(blocks[0].version, "1.0");
        assert_eq!(blocks[0].location, "./libmathkit.so");
        assert_eq!(blocks[0].funcs.len(), 2);
        assert_eq!(blocks[0].funcs[0].name, "add two numbers");
        assert_eq!(
            blocks[0].funcs[0].params,
            vec![
                ("a".to_string(), Type::Integer),
                ("b".to_string(), Type::Integer)
            ]
        );
        assert_eq!(blocks[0].funcs[0].return_type, Type::Integer);
        // No `returning` clause -> returns nothing.
        assert_eq!(blocks[0].funcs[1].name, "greet");
        assert!(blocks[0].funcs[1].params.is_empty());
        assert_eq!(blocks[0].funcs[1].return_type, Type::Void);
        assert_eq!(blocks[1].lib, "flags");
        assert_eq!(blocks[1].location, "./libflags.so");
        assert_eq!(blocks[1].funcs[0].params.len(), 1);
    }

    #[test]
    fn round_trips_the_a3_emitter_output() {
        // The exact text A3 renders for libmath.vox (test.sh pins it); the
        // round trip is the stage contract — the parser consumes what the
        // emitter writes. `makebuf` has no return clause.
        let text = "Library \"mathkit\" version \"1.0\".\n\
Location \"./libmath.so\".\n\
\n\
Table of Contents:\n\
    To \"add two numbers\" with a number called \"n\", returning a number.\n\
    To \"greet\".\n\
    To \"makebuf\".\n";
        let blocks = parse_lib_text(text).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].funcs.len(), 3);
        assert_eq!(blocks[0].funcs[2].return_type, Type::Void);
    }

    #[test]
    fn value_and_collection_nouns_parse() {
        let text = "Library \"dyn\" version \"1.0\".\n\
Location \"./libdyn.so\".\n\
\n\
Table of Contents:\n\
    To \"echo\" with a value called \"v\", returning a value.\n\
    To \"stash\" with a buffer called \"b\" and a list called \"l\" and a map called \"m\".\n";
        let blocks = parse_lib_text(text).unwrap();
        assert_eq!(blocks[0].funcs[0].return_type, Type::Value);
        assert_eq!(blocks[0].funcs[0].params[0].1, Type::Value);
        assert_eq!(blocks[0].funcs[1].params[0].1, Type::Buffer);
        assert!(matches!(blocks[0].funcs[1].params[1].1, Type::List(_)));
        assert!(matches!(blocks[0].funcs[1].params[2].1, Type::Map(_)));
    }

    #[test]
    fn returning_with_no_params_parses() {
        let text = "Library \"n\" version \"1.0\".\n\
Location \"./n.so\".\n\
\n\
Table of Contents:\n\
    To \"makebuf\", returning a number.\n";
        let blocks = parse_lib_text(text).unwrap();
        assert_eq!(blocks[0].funcs[0].return_type, Type::Integer);
        assert!(blocks[0].funcs[0].params.is_empty());
    }

    #[test]
    fn unsupported_return_type_is_named() {
        let text = "Library \"n\" version \"1.0\".\n\
Location \"./n.so\".\n\
\n\
Table of Contents:\n\
    To \"f\", returning a buffer.\n";
        let err = parse_lib_text(text).unwrap_err();
        assert!(err.contains("unsupported type"), "got: {}", err);
        assert!(err.contains("'buffer'"), "got: {}", err);
    }

    #[test]
    fn executable_statements_are_rejected_structurally() {
        let text = "Library \"n\" version \"1.0\".\n\
Location \"./n.so\".\n\
\n\
Table of Contents:\n\
    To \"f\".\n\
    Print \"surprise\".\n";
        let err = parse_lib_text(text).unwrap_err();
        assert!(
            err.contains("cannot carry executable statements"),
            "got: {}",
            err
        );
    }

    #[test]
    fn a_wrapped_entry_is_an_error() {
        let text = "Library \"n\" version \"1.0\".\n\
Location \"./n.so\".\n\
\n\
Table of Contents:\n\
    To \"f\" with a number called \"a\",\n\
    and a number called \"b\", returning a number.\n";
        let err = parse_lib_text(text).unwrap_err();
        assert!(err.contains("one line"), "got: {}", err);
    }

    #[test]
    fn mangled_names_follow_the_a1_rule() {
        let blocks = parse_lib_text(TWO_BLOCKS).unwrap();
        assert_eq!(
            mangle_library_symbol(
                &blocks[0].lib,
                &blocks[0].version,
                &blocks[0].funcs[0].name
            ),
            "mathkit_1_0_add_two_numbers"
        );
        assert_eq!(
            mangle_library_symbol(&blocks[1].lib, &blocks[1].version, "hasflag"),
            "flags_0_1_hasflag"
        );
    }
}
