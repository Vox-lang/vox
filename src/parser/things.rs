//! User-defined thing definitions (plan 310 §1).
//!
//! ```text
//! A thing called point has
//!   a function called 'from polar',
//!   a number called x is 0,
//!   a number called y is 0.
//! ```
//!
//! A definition declares a *type*, never a variable: it allocates nothing
//! and emits no code. The construct is closed by the ordinary termination
//! rules (a period after the last entry, or a paragraph break), and entries
//! are comma-separated the same way a sentence's multiple actions are.
//!
//! `thing` is deliberately NOT a lexer keyword - it stays an ordinary
//! identifier everywhere else (`a number called thing is 42.`), so this
//! construct is recognised by sentence shape alone. That is the same
//! contextual treatment `start`/`begin`/`stop`/`finish` get in
//! `src/parser/statements.rs`.

use super::*;
use std::collections::hash_map::Entry;

/// A type's name as Vox spells it, for a diagnostic about a field's type.
/// The analyzer has its own richer `type_name`; this is the parser-side
/// vocabulary, which only ever needs to name a field's declared type.
fn type_noun_of(field_type: &Type) -> String {
    match field_type {
        Type::Integer => "number".to_string(),
        Type::Float => "float".to_string(),
        Type::String => "text".to_string(),
        Type::Boolean => "boolean".to_string(),
        Type::Buffer => "buffer".to_string(),
        Type::List(_) => "list".to_string(),
        Type::Map(_) => "map".to_string(),
        Type::File => "file".to_string(),
        Type::Time => "time".to_string(),
        Type::Timer => "timer".to_string(),
        Type::Value => "value".to_string(),
        Type::Thing(name) => name.clone(),
        Type::Void | Type::Unknown => "value".to_string(),
    }
}

/// What a possessive on a thing-typed base turned out to name (plan 310 §3,
/// §4). The two readings are decided as the possessive is consumed, because
/// which one it is decides what follows it: a field may be gone through with
/// another `'s`, while a call reads an argument list instead.
pub(crate) enum Possessive {
    /// A field, reached by walking `path` from the base: `origin's x`,
    /// `route's leg's start's x`. `field_type` is what sits at the end.
    Field { path: Vec<String>, field_type: Type },
    /// The instance sugar, already rewritten into the call it means, with the
    /// receiver as its first argument.
    Call(Expr),
}

/// A declared member whose `To do the <thing>'s <name>` definition has been
/// read (plan 310 §4). Recorded as the definition's signature is parsed, so
/// the two call forms can ask about it while the rest of the file is read.
#[derive(Clone)]
pub(crate) struct MemberFunction {
    /// The internal name the definition is compiled under - see
    /// `member_function_name`.
    pub(crate) internal: String,
    /// True when the definition's first parameter is the owner, which is what
    /// decides whether the instance possessive reaches it as well as the type
    /// possessive. A maker (first parameter not the owner) is reachable only
    /// as `a point's <name>`.
    pub(crate) takes_owner_first: bool,
    /// The line of its `To do` sentence, for the second-definition error.
    pub(crate) line: usize,
}

/// What a member definition's head named: `To do the point's 'placed at'`.
pub(crate) struct MemberDefinition {
    /// The thing that declares the member.
    pub(crate) thing: String,
    /// The member's name as the manifest spells it.
    pub(crate) member: String,
    /// The name the definition compiles under.
    pub(crate) internal: String,
    /// The line the `To do` sentence sits on.
    pub(crate) line: usize,
}

/// The internal name a member definition is compiled under: the owner and the
/// member, spelled the way Vox writes the possessive. `point`'s `'placed at'`
/// and `'grid square'`'s `'placed at'` are therefore two different functions
/// all the way down to the symbol table, where `mangle_symbol` turns each into
/// its own label (`point_s_placed_at`, `grid_square_s_placed_at`). Nothing
/// downstream of the parser needs to know a member from an ordinary function -
/// what the analyzer and codegen get is the call the author could have written
/// by hand, which is what keeps mangling a naming rule rather than a second
/// dispatch mechanism.
pub(crate) fn member_function_name(thing: &str, member: &str) -> String {
    format!("{}'s {}", thing, member)
}

/// Whether a possessive in this position may resolve to the instance sugar.
/// A write target names storage and a call is not storage, so `Set origin's
/// magnitude to 3.` has no second reading to fall back on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PossessivePosition {
    /// An expression: a field first, then the sugar (plan 310 §4).
    Value,
    /// The left of a write: a field, and nothing else.
    WriteTarget,
}

impl Parser {
    /// True when the current token opens a thing-definition construct:
    /// the contextual keyword `thing` followed by `called`. Call with the
    /// article (`a`/`an`) already consumed.
    ///
    /// Matching on `called` alone - rather than looking further ahead for
    /// `has` - is what lets the reserved wrong shapes (`... called X is
    /// ...`, `... called X.`) reach their own targeted diagnostics in
    /// `parse_thing_definition` instead of falling through to a generic
    /// parse failure. `a thing called <name>` is reserved in every version
    /// (plan 310 §10), so nothing legitimate is captured by the wider net.
    pub(crate) fn thing_definition_follows(&self) -> bool {
        if !matches!(self.current(), Token::Identifier(w) if w.eq_ignore_ascii_case("thing")) {
            return false;
        }
        let mut off = 1;
        while matches!(self.peek(off), Token::Newline) {
            off += 1;
        }
        matches!(self.peek(off), Token::Called)
    }

    /// The `Create a thing called X` diagnostic (plan 310 §10). A thing is
    /// defined, not created as a variable - this shape is never valid Vox,
    /// so it names the canonical form rather than erroring generically.
    /// Call with the article already consumed and `thing_definition_follows`
    /// true.
    pub(crate) fn err_thing_created_as_variable(&mut self) -> Box<CompileError> {
        let name = self.peek_defined_thing_name();
        self.err(&format!(
            "A thing is defined, not created as a variable\n  \
             Canonical form: A thing called {} has <fields>.",
            name
        ))
    }

    /// The name a definition construct is about, read without disturbing the
    /// parser position - every caller is about to abort, but a diagnostic
    /// that silently consumed tokens would be a trap for the next person to
    /// reuse one. Call at the contextual `thing` keyword.
    ///
    /// A name the lexer has folded into a keyword token (`reading`, `size`,
    /// and their aliases) no longer carries its spelling, so it is read back
    /// from the source line the way `check_not_keyword` does, and handed back
    /// **quoted**: `A thing called 'reading' has ...` is how a reserved word
    /// names a thing, and it compiles. Echoing it bare would spell a
    /// canonical form that is refused the moment the author writes it, and
    /// `<name>` told them nothing about their own word.
    fn peek_defined_thing_name(&mut self) -> String {
        let saved = self.pos;
        self.advance(); // `thing`
        self.skip_noise();
        self.advance(); // `called`
        self.skip_noise();
        let name = match self.current().clone() {
            Token::Identifier(n) | Token::StringLiteral(n) => n,
            keyword => match (keyword.as_keyword(), self.current_lexeme()) {
                (Some(_), Some(typed)) => format!("'{}'", typed),
                // Whatever follows `called` is not a name at all; a
                // placeholder is honest where inventing one would misreport
                // what was written.
                _ => "<name>".to_string(),
            },
        };
        self.pos = saved;
        name
    }

    /// The definition-inside-a-block diagnostic (plan 310 §3, §9). A thing is
    /// defined at the top level, like a function: its layout is fixed when the
    /// program is compiled and every use of its name reads that one layout, so
    /// a definition written inside a block has no scope of its own to mean
    /// anything in. Rejecting it also keeps the parser's own table of things
    /// and `Program.things` describing the same set - a definition nested in a
    /// block used to register the type while never reaching the registry
    /// codegen reads, which laid the thing out as 0 bytes and put a parameter
    /// of it at frame offset 0, the saved base pointer.
    fn err_thing_defined_inside_a_block(&mut self) -> Box<CompileError> {
        let name = self.peek_defined_thing_name();
        self.err(&format!(
            "A thing is defined at the top level, like a function\n  \
             Canonical form: A thing called {} has <fields>.\n  \
             Move the definition above the block it is written in: a thing's \
             layout is fixed for the whole program, so a definition inside an \
             'If', a loop, or a function body has no scope to belong to.",
            name
        ))
    }

    /// Parse a whole definition construct, starting at the contextual
    /// `thing` keyword (the article is already consumed). Registers the
    /// `ThingDef` so later definitions can nest it, and returns the
    /// statement that carries it into the program.
    pub(crate) fn parse_thing_definition(&mut self) -> Result<Statement, Box<CompileError>> {
        // A definition is a top-level statement, like a function definition.
        // Anywhere else it is refused at its own site rather than parsed into
        // a block's body, where `Program::new`'s flat scan of the top level
        // would never find it.
        if !self.at_top_level() {
            return Err(self.err_thing_defined_inside_a_block());
        }

        let line = self.current_info().map(|t| t.line).unwrap_or(0);

        self.advance(); // `thing`
        self.skip_noise();
        if !self.expect(&Token::Called) {
            // Unreachable via `thing_definition_follows`, but the parser
            // never assumes a guard held.
            return Err(self.err_expected("'called' after 'thing'", self.current()));
        }
        self.skip_noise();

        let name_pos = self.pos;
        let name = self.parse_name()?;
        // The definition is a claim on the one identifier space like any
        // other, in both directions: a name a variable or a function already
        // took is refused here just as this name is refused to them later.
        self.claim_name(&name, NameKind::Thing, name_pos)?;
        self.skip_noise();

        // `has` opens the entry list. The two reserved near-misses get their
        // own messages (plan 310 §10) before the generic expectation fires.
        match self.current().clone() {
            Token::Identifier(w) if w.eq_ignore_ascii_case("has") => {
                self.advance();
            }
            Token::Is | Token::Equals => {
                return Err(self.err(&format!(
                    "'is' declares a variable; a thing definition uses 'has'\n  \
                     Canonical form: A thing called {} has <fields>.",
                    name
                )));
            }
            Token::Period | Token::EOF | Token::ParagraphBreak => {
                return Err(self.err_thing_needs_a_field(&name, false));
            }
            other => {
                return Err(self.err(&format!(
                    "Expected 'has' after 'a thing called {}', got {:?}\n  \
                     Canonical form: A thing called {} has <fields>.",
                    name, other, name
                )));
            }
        }

        let (fields, members) = self.parse_thing_entries(&name)?;
        // "v1 requires at least one field" (plan 310 §10) counts *data*
        // fields: function members take no storage (§4), so a definition
        // listing only members would describe a zero-byte thing. Rejecting
        // that is the reversible choice - a later version can allow it
        // without invalidating any program written today.
        if fields.is_empty() {
            return Err(self.err_thing_needs_a_field(&name, !members.is_empty()));
        }

        let def = ThingDef { name: name.clone(), fields, members, line };
        // Every declared member returns its owner (plan 310 §4), so the
        // manifest alone says what a call to one yields - which is what lets
        // `The pin is a point's 'placed at' with 1 and 0.` declare `pin`
        // from a definition further down the file. The promise is collected
        // on twice: `reject_member_returning_another_type` at each
        // definition, and `reject_undefined_members` for a member with none.
        for member in &def.members {
            self.thing_returning_functions
                .insert(member_function_name(&name, member), name.clone());
        }
        self.things.insert(name, def.clone());
        Ok(Statement::ThingDecl(def))
    }

    /// Prove that the parser's table of things and the program's registry
    /// name the same set, and refuse to hand back a program where they do
    /// not. The two are filled by different walks - the parser records a
    /// definition as it reads it, `Program::new` derives the registry from a
    /// flat scan of the top-level statements - and everything downstream
    /// trusts them to agree: the parse type-checks a declaration against
    /// `self.things`, while layout, offsets and the cycle check all read
    /// `Program.things`. When a definition nested in a block registered the
    /// type without reaching the registry, a program that parsed cleanly was
    /// laid out against a registry missing the thing, so its size came back
    /// as 0 and a parameter of it took frame offset 0 - the saved base
    /// pointer. Rejecting the nested definition is the fix; this is what
    /// keeps it fixed if a construct that can hold a statement is added
    /// later.
    pub(crate) fn check_thing_registry(
        &mut self,
        program: &Program,
    ) -> Result<(), Box<CompileError>> {
        let mut missing: Vec<&String> = self
            .things
            .keys()
            .filter(|name| !program.things.iter().any(|def| &&def.name == name))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        // A HashMap hands its keys back in whatever order it likes; sorting
        // makes the report the same on every run.
        missing.sort();
        let names = missing
            .iter()
            .map(|name| format!("'{}'", name))
            .collect::<Vec<_>>()
            .join(", ");
        // Point at the first definition that went missing, so the caret lands
        // on a thing rather than at end of file.
        if let Some(name_pos) = self.thing_name_position(missing[0]) {
            self.pos = name_pos;
        }
        Err(self.err(&format!(
            "Compiler bug: {} parsed as a thing but is missing from the \
             program's registry\n  \
             The parse type-checked against a set of things that layout and \
             code generation cannot see, so this program will not be \
             compiled.\n  \
             Please report this file to the Vox maintainers.",
            names
        )))
    }

    /// Take `name` for `kind`, or refuse because something already has it.
    /// This is the whole of the one-identifier-space rule (plan 310 §4, §10):
    /// every declaration form goes through here, so a form added later
    /// inherits the rule instead of having to remember it. The rule used to
    /// be written at one spelling - `a <thing> called <thatname>` - and the
    /// five other spellings that reach the same collision all compiled.
    ///
    /// A type name is exclusive: nothing else may take a name a thing has,
    /// and a thing may not take a name already in use. Two variables, or a
    /// variable and a function, keep the behaviour they have always had - a
    /// local shadowing an outer name is how every existing Vox program is
    /// written (tests/339), and widening the rule to those is a separate
    /// language decision, not part of this feature. What the spec settles is
    /// the half the possessive needs: `the point's` reads one way only if
    /// `point` names exactly one thing in the program.
    ///
    /// `name_pos` is the token index of the name, so the caret lands on the
    /// second declaration - the one that is being refused - and the message
    /// names the first.
    pub(crate) fn claim_name(
        &mut self,
        name: &str,
        kind: NameKind,
        name_pos: usize,
    ) -> Result<(), Box<CompileError>> {
        let line = self.tokens.get(name_pos).map(|info| info.line).unwrap_or(0);
        let file = self.source_file.as_ref().map(|src| src.filename.clone());

        if let Some(previous) = self.claimed_names.get(name) {
            if previous.kind == NameKind::Thing || kind == NameKind::Thing {
                let previous_kind = previous.kind.noun();
                let previous_line = previous.line;
                // A `see` splices another file into the same identifier
                // space, so the line the message names may be in a file the
                // reader is not looking at. Name it when it differs.
                let elsewhere = match (&previous.file, &file) {
                    (Some(claimed_in), Some(reading)) if claimed_in != reading => {
                        format!(" of {}", claimed_in)
                    }
                    _ => String::new(),
                };
                // Rewind so the underline lands on the name rather than on
                // whatever follows it. The parse is aborting anyway.
                self.pos = name_pos;
                return Err(self.err(&format!(
                    "'{}' is already defined as a {} on line {}{}\n  \
                     Type names, variable names, and function names share one \
                     identifier space; the first definition wins.",
                    name, previous_kind, previous_line, elsewhere
                )));
            }
            // First claim stands: a second variable or function of the same
            // name is not this rule's business.
            return Ok(());
        }

        self.claimed_names.insert(
            name.to_string(),
            NameClaim { kind, line, pos: name_pos, file },
        );
        Ok(())
    }

    /// "line 6", or "line 6 of tests/include/geometry.vox" when the thing was
    /// defined in a file this one saw. A `see` splices another file into the
    /// same program, so a bare line number would send the reader to the wrong
    /// file's line 6.
    pub(crate) fn where_thing_was_defined(&self, thing: &str, line: usize) -> String {
        let elsewhere = match (
            self.claimed_names.get(thing).and_then(|claim| claim.file.as_ref()),
            self.source_file.as_ref().map(|src| &src.filename),
        ) {
            (Some(claimed_in), Some(reading)) if claimed_in != reading => {
                format!(" of {}", claimed_in)
            }
            _ => String::new(),
        };
        format!("line {}{}", line, elsewhere)
    }

    /// Where a thing's name was written, for the two checks that can only run
    /// once the whole program has been read and still want their caret on the
    /// type. `None` when the definition came from a `see`n file, whose token
    /// indices belong to a different stream than this parser's.
    fn thing_name_position(&self, name: &str) -> Option<usize> {
        let claim = self.claimed_names.get(name)?;
        let reading = self.source_file.as_ref().map(|src| &src.filename);
        (claim.kind == NameKind::Thing && claim.file.as_ref() == reading).then_some(claim.pos)
    }

    /// The no-data-field diagnostic, shared by `A thing called X.` (no `has`
    /// at all), `A thing called X has.` (a `has` with nothing after it), and
    /// a definition listing only function members - all three describe a
    /// thing with nothing in it. `declared_members` adds the line that
    /// explains why a manifest entry did not count.
    fn err_thing_needs_a_field(&self, name: &str, declared_members: bool) -> Box<CompileError> {
        let members_note = if declared_members {
            "\n  `a function called <name>` declares callable API, not storage."
        } else {
            ""
        };
        self.err(&format!(
            "A thing needs at least one field\n  \
             Canonical form: A thing called {} has\n    \
             a number called x is 0,\n    \
             a number called y is 0.{}",
            name, members_note
        ))
    }

    /// The comma-separated entry list. Each entry is a data field
    /// (`a <type> called <name> [is <literal>]`) or a manifest function
    /// declaration (`a function called <name>`). Stops at the construct's
    /// termination - a period, a paragraph break, or end of file - leaving
    /// the terminator for the caller, exactly as every other statement
    /// parser does.
    fn parse_thing_entries(
        &mut self,
        thing_name: &str,
    ) -> Result<(Vec<FieldDef>, Vec<String>), Box<CompileError>> {
        let mut fields: Vec<FieldDef> = Vec::new();
        let mut members: Vec<String> = Vec::new();
        // Every name this thing owns, mapped to what declared it, so the
        // second use of a name errors at its own site (plan 310 §4).
        let mut claimed: std::collections::HashMap<String, &'static str> =
            std::collections::HashMap::new();

        loop {
            self.skip_noise();
            if self.at_thing_terminator() {
                break;
            }

            if !matches!(self.current(), Token::A | Token::An) {
                return Err(self.err(&format!(
                    "Expected 'a' or 'an' to open an entry of thing '{}', got {:?}\n  \
                     Entries read `a <type> called <name>` or `a function called <name>`.",
                    thing_name,
                    self.current()
                )));
            }
            self.advance();
            self.skip_noise();

            let (entry_name, entry_name_pos, kind) = if self.function_member_follows() {
                self.advance(); // `function`
                self.skip_noise();
                self.advance(); // `called`
                self.skip_noise();
                let name_pos = self.pos;
                let member = self.parse_name()?;
                (member, name_pos, "function member")
            } else {
                let field_type = self.parse_field_type(thing_name)?;
                self.skip_noise();
                if !self.expect(&Token::Called) {
                    return Err(self.err(&format!(
                        "Expected 'called' after the field type in thing '{}', got {:?}\n  \
                         Entries read `a <type> called <name>`.",
                        thing_name,
                        self.current()
                    )));
                }
                self.skip_noise();
                let name_pos = self.pos;
                let field_name = self.parse_name()?;
                self.skip_noise();

                let default = if matches!(self.current(), Token::Is | Token::Equals) {
                    self.advance();
                    self.skip_noise();
                    Some(self.parse_field_default(thing_name, &field_name)?)
                } else {
                    None
                };

                fields.push(FieldDef {
                    name: field_name.clone(),
                    field_type,
                    default,
                });
                (field_name, name_pos, "field")
            };

            match claimed.entry(entry_name.clone()) {
                Entry::Occupied(previous) => {
                    let first_kind = *previous.get();
                    // Rewind to the offending name so the underline lands on
                    // it rather than on the end of the entry; the parse is
                    // aborting anyway.
                    self.pos = entry_name_pos;
                    return Err(self.err(&format!(
                        "Thing '{}' already has a {} called '{}'\n  \
                         Each thing owns one member space: its fields and its \
                         declared function members cannot share a name.",
                        thing_name, first_kind, entry_name
                    )));
                }
                Entry::Vacant(slot) => {
                    slot.insert(kind);
                }
            }
            if kind == "function member" {
                members.push(entry_name);
            }

            self.skip_noise();
            if *self.current() == Token::Comma {
                self.advance();
                continue;
            }
            if self.at_thing_terminator() {
                break;
            }
            return Err(self.err(&format!(
                "Expected ',' before the next entry of thing '{}' or '.' to end the \
                 definition, got {:?}",
                thing_name,
                self.current()
            )));
        }

        Ok((fields, members))
    }

    /// The construct's termination: a period closes it (rule 1), a blank
    /// line closes it (rule 2), and end of file ends everything.
    fn at_thing_terminator(&self) -> bool {
        matches!(
            self.current(),
            Token::Period | Token::EOF | Token::ParagraphBreak
        )
    }

    /// True when the entry being read is a manifest function declaration
    /// (`a function called <name>`). `function` is not a lexer keyword
    /// either, so this is another shape check: only `function` immediately
    /// before `called` declares a member, leaving `function` usable as an
    /// ordinary field name elsewhere.
    fn function_member_follows(&self) -> bool {
        if !matches!(self.current(), Token::Identifier(w) if w.eq_ignore_ascii_case("function")) {
            return false;
        }
        let mut off = 1;
        while matches!(self.peek(off), Token::Newline) {
            off += 1;
        }
        matches!(self.peek(off), Token::Called)
    }

    /// A field's declared type: any builtin type noun, or the name of a
    /// thing defined earlier in the program (plan 310 §6 - things nest to
    /// any depth, and "defined earlier" is what keeps the single parse pass
    /// enough to resolve them).
    fn parse_field_type(&mut self, thing_name: &str) -> Result<Type, Box<CompileError>> {
        if let Some(builtin) = self.try_parse_type_noun() {
            return Ok(builtin);
        }
        if let Token::Identifier(word) = self.current().clone() {
            if self.things.contains_key(&word) {
                self.advance();
                return Ok(Type::Thing(word));
            }
            // A field naming the thing being defined closes a cycle (plan 310
            // §6, §10): a thing's fields are stored inline, so its size would
            // include its own, and it has none. This is the only cycle Vox
            // source can express - a longer chain needs a field naming a thing
            // defined later, which is an unknown type here, and the registry
            // does not yet hold this definition (it is registered once its
            // entries parse), so the name would otherwise report as unknown.
            if word == thing_name {
                return Err(self.err(&format!(
                    "A thing cannot contain itself: {} contains {}\n  \
                     A thing's fields are stored inline, so this definition has \
                     no finite size.\n  \
                     A field may name any thing defined before this one.",
                    thing_name, word
                )));
            }
            let mut err = *self.err(&format!(
                "Unknown field type '{}' in thing '{}'\n  \
                 A field's type is a builtin type noun or a thing defined \
                 earlier in the program.",
                word, thing_name
            ));
            let known: Vec<&str> = self.things.keys().map(|k| k.as_str()).collect();
            if let Some(near) = find_similar_keyword(&word, &known) {
                err = err.with_suggestion(&near);
            }
            return Err(Box::new(err));
        }
        Err(self.err_expected("a field type", self.current()))
    }

    /// The literal after a field's `is`. Defaults are literals by
    /// specification (plan 310 §1) - a field with no default takes its
    /// type's zero value, and anything computed belongs in a maker - so an
    /// expression here is rejected with a message that says which field.
    fn parse_field_default(
        &mut self,
        thing_name: &str,
        field_name: &str,
    ) -> Result<Expr, Box<CompileError>> {
        // A leading `-` belongs to the literal it negates; folding it in
        // here keeps `default` a literal rather than a UnaryOp tree that
        // every consumer would have to evaluate.
        let negated = *self.current() == Token::Minus;
        if negated {
            self.advance();
            self.skip_noise();
        }

        // BUGS_FOUND #22: `-9223372036854775808` (i64::MIN) is the one
        // magnitude that only exists as a negated literal - see the matching
        // comment in expressions.rs's `parse_primary`. Any other overflowing
        // literal here is a compile error, named and bounded, same as
        // everywhere else a literal is consumed.
        if let Token::IntegerLiteralOverflow(raw) = self.current().clone() {
            if negated && raw == "9223372036854775808" {
                // fall through to the advance()/return below via `literal`
            } else {
                return Err(self.integer_literal_overflow_error(&raw));
            }
        }

        let literal = match self.current().clone() {
            Token::IntegerLiteral(n) => Some(Expr::IntegerLit(if negated { -n } else { n })),
            Token::IntegerLiteralOverflow(_) => Some(Expr::IntegerLit(i64::MIN)),
            Token::FloatLiteral(f) => Some(Expr::FloatLit(if negated { -f } else { f })),
            Token::StringLiteral(s) if !negated => Some(Expr::StringLit(s)),
            Token::True if !negated => Some(Expr::BoolLit(true)),
            Token::False if !negated => Some(Expr::BoolLit(false)),
            Token::Nothing if !negated => Some(Expr::NothingLit),
            _ => None,
        };

        let expr = match literal {
            Some(expr) => {
                self.advance();
                expr
            }
            None => return Err(self.err_field_default_not_literal(thing_name, field_name)),
        };

        // A literal that does not end the entry means an expression was
        // written (`is 1 add 2`). Catching it here gives the same "defaults
        // are literals" message as `is other` rather than a confusing
        // complaint about the missing comma.
        self.skip_noise();
        if !self.at_thing_terminator() && *self.current() != Token::Comma {
            return Err(self.err_field_default_not_literal(thing_name, field_name));
        }

        Ok(expr)
    }

    // ---------------------------------------------------------------------
    // Declarations read ahead of the walk (BUGS_FOUND #80)
    // ---------------------------------------------------------------------

    /// The token at `at`, for the scans that read the stream directly rather
    /// than through the cursor.
    fn token_at(&self, at: usize) -> &Token {
        self.tokens.get(at).map(|info| &info.token).unwrap_or(&Token::EOF)
    }

    /// The index of the first token from `at` that is not a newline - the
    /// same "noise between two words of one construct" the cursor skips.
    fn past_newlines(&self, at: usize) -> usize {
        let mut i = at;
        while matches!(self.token_at(i), Token::Newline) {
            i += 1;
        }
        i
    }

    /// Register every `a <thing> called <name>` declaration this token stream
    /// makes outside a function body, before the first statement is parsed.
    ///
    /// `thing_vars` is what decides whether `origin's x` reads as a field
    /// chain, and it used to be filled as declarations were *parsed*, in
    /// source order. A global thing declared BELOW a function was therefore
    /// invisible inside it, and the possessive failed as "Expected property
    /// name" with the caret on the field - a message about the one token that
    /// was not the problem (BUGS_FOUND #80). LANGUAGE.md attaches no ordering
    /// condition to a top-level variable: "variables declared at top level are
    /// global and can be used inside functions". The ordering rule it does
    /// state is about a thing DEFINITION, and that one still holds - a
    /// definition is skipped over here, not registered.
    ///
    /// The set this walks is the set `collect_thing_vars` walks: the top level
    /// and the blocks written at it, never a function body's parameters or
    /// locals, which are registered when that body is parsed and belong to it.
    /// Keeping the parser's table the same shape as the analyzer's and
    /// codegen's is the point - three tables describing different sets are
    /// three answers waiting to disagree.
    pub(crate) fn register_declared_thing_vars(&mut self) {
        // Seeded with the definitions already parsed, which is how a `see`n
        // file's things reach a declaration written in the file that saw it.
        // Names are added as the scan passes each definition, so a
        // declaration still only reads a type noun defined above it - the
        // same rule `try_parse_thing_type_noun` applies during the walk.
        let mut defined: std::collections::HashSet<String> =
            self.things.keys().cloned().collect();

        let mut at = 0;
        let mut opens_statement = true;
        while at < self.tokens.len() {
            match self.token_at(at).clone() {
                Token::Newline => at += 1,
                Token::Period | Token::Comma | Token::ParagraphBreak => {
                    opens_statement = true;
                    at += 1;
                }
                // A function's signature and body are not the top level: its
                // parameters and its locals are registered when the body is
                // parsed, in the scope they belong to.
                Token::To if opens_statement => {
                    at = self.end_of_function(at);
                    opens_statement = true;
                }
                // A definition's entries are fields, not variables: the
                // `a leg called outbound` inside `A thing called route has`
                // declares a field of route and nothing named `outbound`.
                Token::Identifier(ref word)
                    if word.eq_ignore_ascii_case("thing")
                        && matches!(self.token_at(self.past_newlines(at + 1)), Token::Called) =>
                {
                    if let Token::Identifier(defined_name) =
                        self.token_at(self.past_newlines(self.past_newlines(at + 1) + 1)).clone()
                    {
                        defined.insert(defined_name);
                    }
                    at = self.end_of_thing_definition(at);
                    opens_statement = true;
                }
                Token::Identifier(ref word) if defined.contains(word) => {
                    let called = self.past_newlines(at + 1);
                    if !matches!(self.token_at(called), Token::Called) {
                        opens_statement = false;
                        at += 1;
                        continue;
                    }
                    let name_at = self.past_newlines(called + 1);
                    if let Token::Identifier(name) = self.token_at(name_at).clone() {
                        // First declaration wins. The walk that follows
                        // overwrites each entry as it reaches it, so a name
                        // declared twice still reads as whichever declaration
                        // stands above the use - which is what the walk alone
                        // gave before this existed.
                        self.thing_vars.entry(name).or_insert_with(|| word.clone());
                    }
                    opens_statement = false;
                    at = name_at + 1;
                }
                _ => {
                    opens_statement = false;
                    at += 1;
                }
            }
        }
    }

    /// One past the last token of the function definition opening at `at` (a
    /// `To` in statement position). Read by the same three rules
    /// `parse_function_def` closes a body with: the signature ends at its
    /// period, a body whose first statement is a `Return` is that one
    /// sentence, and any other body runs to the paragraph break - or to the
    /// `To`/`Library` that opens the next top-level construct.
    fn end_of_function(&self, at: usize) -> usize {
        let mut i = at + 1;
        while !matches!(
            self.token_at(i),
            Token::Period | Token::ParagraphBreak | Token::EOF
        ) {
            i += 1;
        }
        if matches!(self.token_at(i), Token::Period) {
            i += 1;
        }

        // `To 'answer'. Return a number, 3.` - the inline Return closes the
        // body, so what follows it is top-level again even with no blank line.
        let head = self.past_newlines(i);
        if matches!(self.token_at(head), Token::Return) {
            let mut end = head;
            while !matches!(
                self.token_at(end),
                Token::Period | Token::ParagraphBreak | Token::EOF
            ) {
                end += 1;
            }
            return if matches!(self.token_at(end), Token::Period) { end + 1 } else { end };
        }

        let mut opens_statement = true;
        loop {
            match self.token_at(i) {
                Token::EOF | Token::ParagraphBreak => return i,
                Token::To | Token::Library if opens_statement => return i,
                Token::Period | Token::Comma => {
                    opens_statement = true;
                    i += 1;
                }
                Token::Newline => i += 1,
                _ => {
                    opens_statement = false;
                    i += 1;
                }
            }
        }
    }

    /// One past the last token of the thing definition opening at `at` (the
    /// contextual `thing` keyword). A definition is closed by the ordinary
    /// termination rules - a period after the last entry, or a paragraph
    /// break - which is what `at_thing_terminator` reads.
    fn end_of_thing_definition(&self, at: usize) -> usize {
        let mut i = at;
        while !matches!(
            self.token_at(i),
            Token::Period | Token::ParagraphBreak | Token::EOF
        ) {
            i += 1;
        }
        if matches!(self.token_at(i), Token::Period) { i + 1 } else { i }
    }

    // ---------------------------------------------------------------------
    // Declaration position (plan 310 §1, §6, §10)
    // ---------------------------------------------------------------------

    /// A defined thing's name used as a type noun: `a point called origin.`.
    /// Consumes the name and returns `Type::Thing` only when `called` follows,
    /// the same guard `try_parse_type_noun` puts on `value` - so a thing name
    /// stays an ordinary identifier in every other position (a call, a
    /// variable read), and nothing is consumed when this returns None.
    pub(crate) fn try_parse_thing_type_noun(&mut self) -> Option<Type> {
        let Token::Identifier(word) = self.current().clone() else {
            return None;
        };
        if !self.things.contains_key(&word) {
            return None;
        }
        let mut off = 1;
        while matches!(self.peek(off), Token::Newline) {
            off += 1;
        }
        if !matches!(self.peek(off), Token::Called) {
            return None;
        }
        self.advance();
        Some(Type::Thing(word))
    }

    /// Close a `a <thing> called <name>` declaration, with the name already
    /// parsed and already claimed in the one identifier space by the caller -
    /// `claim_name` runs for every declaration whatever its type, so this
    /// path no longer keeps its own copy of the rule in step. Keeping it here
    /// is how the rule came to hold for `a point called point.` and for none
    /// of the five other spellings that reach the same collision.
    pub(crate) fn finish_thing_declaration(
        &mut self,
        thing: String,
        name: String,
    ) -> Result<Statement, Box<CompileError>> {
        // An initialiser copies the whole thing into the storage this
        // declaration reserves (plan 310 §5). The separator set is the one
        // every other typed declaration takes, so `a point called moved is
        // origin.` and `Create a point called moved to origin.` read alike.
        self.skip_noise();
        let value = if matches!(self.current(), Token::Is | Token::Equals | Token::To) {
            self.advance();
            self.skip_noise();
            Some(self.parse_expression()?)
        } else {
            None
        };

        // Registered after the initialiser is parsed: the variable does not
        // exist while its own initialiser is being read, so `a point called
        // origin is origin.` is an unknown variable rather than a chain.
        self.thing_vars.insert(name.clone(), thing.clone());
        Ok(Statement::VarDecl {
            name,
            var_type: Some(Type::Thing(thing)),
            value,
        })
    }

    // ---------------------------------------------------------------------
    // Field access (plan 310 §3)
    // ---------------------------------------------------------------------

    /// Which thing a declared variable holds, if it holds one.
    pub(crate) fn thing_of_variable(&self, name: &str) -> Option<String> {
        self.thing_vars.get(name).cloned()
    }

    /// Record the thing a function returns, so a later `The <name> is
    /// <call>.` can declare its target from the call (plan 310 §2).
    pub(crate) fn record_thing_returning_function(&mut self, name: &str, return_type: &Type) {
        if let Type::Thing(thing) = return_type {
            self.thing_returning_functions
                .insert(name.to_string(), thing.clone());
        }
    }

    /// The thing an expression yields whole, if it yields one: a thing
    /// variable's own name, a chain ending on a nested thing, or a call to a
    /// function that returns a thing.
    fn thing_yielded_by(&self, value: &Expr) -> Option<String> {
        match value {
            Expr::Identifier(name) => self.thing_of_variable(name),
            Expr::ThingField { base, path } => {
                let mut current = self.thing_of_variable(base)?;
                for step in path {
                    let field = self.things.get(&current)?.fields.iter().find(|f| f.name == *step)?;
                    match &field.field_type {
                        Type::Thing(inner) => current = inner.clone(),
                        // A chain through a scalar cannot be built by
                        // `parse_thing_field_chain`, which stops at one.
                        _ => return None,
                    }
                }
                Some(current)
            }
            Expr::FunctionCall { name, .. } => self.thing_returning_functions.get(name).cloned(),
            _ => None,
        }
    }

    /// `The after is nudged of before.` - a name not yet holding a thing,
    /// assigned a whole thing, is declared by that assignment with its type
    /// inferred from the expression (plan 310 §2). Returns the declaration
    /// that spelling means, or None when the statement is an ordinary
    /// assignment: a name that already holds a thing has storage, so the
    /// same words are a copy into it (§5).
    ///
    /// "Not yet holding a thing" is this parser's own left-to-right reading,
    /// which is what §2's "previously unseen" means for a single pass. It is
    /// the same rule that governs a thing definition and a thing variable:
    /// a name is a thing from its declaration onwards. A function written
    /// ABOVE a main-line thing declaration therefore does not see it - it
    /// cannot name that thing's fields either, which is the louder half of
    /// the same limitation.
    pub(crate) fn thing_declaration_by_inference(
        &mut self,
        name: &str,
        value: &Expr,
    ) -> Option<Statement> {
        if self.thing_vars.contains_key(name) {
            return None;
        }
        let thing = self.thing_yielded_by(value)?;
        self.thing_vars.insert(name.to_string(), thing.clone());
        Some(Statement::VarDecl {
            name: name.to_string(),
            var_type: Some(Type::Thing(thing)),
            value: Some(value.clone()),
        })
    }

    /// True when the tokens at the cursor open a possessive (`'s`).
    pub(crate) fn possessive_follows(&self) -> bool {
        self.possessive_follows_from(0)
    }

    /// The same question asked `off` tokens ahead, for the lookaheads that
    /// have to see past a name they have not consumed yet: `a point's` and
    /// `To do the point's` both read the possessive without moving.
    fn possessive_follows_from(&self, mut off: usize) -> bool {
        while matches!(self.peek(off), Token::Newline) {
            off += 1;
        }
        if !matches!(self.peek(off), Token::Apostrophe) {
            return false;
        }
        off += 1;
        while matches!(self.peek(off), Token::Newline) {
            off += 1;
        }
        matches!(self.peek(off), Token::Identifier(s) if s.eq_ignore_ascii_case("s"))
    }

    /// Consume a possessive (`'s`) the caller has already confirmed with
    /// `possessive_follows`.
    fn consume_possessive(&mut self) {
        self.skip_noise();
        self.advance(); // the apostrophe
        self.skip_noise();
        self.advance(); // the `s`
        self.skip_noise();
    }

    /// Plan 310 §4: each type owns ONE member space - its fields, its declared
    /// function members, and every function whose first parameter is that
    /// type. The second definition of a name in that space is refused at its
    /// own site rather than shadowed, the same refuse-the-ambiguity posture
    /// the `send`/`begin`/`stop` lookaheads take.
    ///
    /// The function is always the second definition: a thing's name is a type
    /// noun only after its definition, so a parameter naming a thing puts that
    /// definition above this one. That is why this check lives here and needs
    /// no second pass - and why the diagnostic can point *back* at a line it
    /// has already read.
    ///
    /// The caret is rewound onto the function's own name, so the error is
    /// reported where the ambiguity was introduced; the parse is aborting
    /// anyway.
    pub(crate) fn reject_member_space_collision(
        &mut self,
        name: &str,
        name_pos: usize,
        first: Option<&(String, Type)>,
    ) -> Result<(), Box<CompileError>> {
        let Some((_, Type::Thing(thing))) = first else {
            return Ok(());
        };
        let Some(def) = self.things.get(thing) else {
            return Ok(());
        };
        let claimed = if def.fields.iter().any(|f| f.name == name) {
            "field"
        } else if def.members.iter().any(|member| member == name) {
            "declared function member"
        } else {
            return Ok(());
        };
        let defined_line = def.line;
        let thing = thing.clone();
        let defined_on = self.where_thing_was_defined(&thing, defined_line);

        self.pos = name_pos;
        Err(self.err(&format!(
            "{} already has a {} called '{}', so a function taking a {} cannot \
             be called '{}' too\n  \
             {} is defined on {}. A type owns one member space: its \
             fields, its declared function members, and every function whose \
             first parameter is that type (plan 310 §4).\n  \
             Rename one of the two - Vox refuses the ambiguity rather than \
             choosing between them.",
            thing, claimed, name, thing, name, thing, defined_on
        )))
    }

    /// Record what a function takes first, so the instance possessive can ask
    /// (plan 310 §4). A function with no parameters at all can never be
    /// reached through a receiver, so it is simply absent from the table.
    pub(crate) fn record_first_parameter(
        &mut self,
        name: &str,
        first: Option<&(String, Type)>,
    ) {
        if let Some((_, first_type)) = first {
            self.function_first_parameters
                .insert(name.to_string(), first_type.clone());
        }
    }

    /// True when `function` takes `thing` as its first parameter - the one
    /// condition the instance possessive resolves against (plan 310 §4).
    /// Membership needs no declaration: any function with the right first
    /// parameter is reachable this way, manifest-declared or not.
    fn first_parameter_is(&self, function: &str, thing: &str) -> bool {
        matches!(
            self.function_first_parameters.get(function),
            Some(Type::Thing(first)) if first == thing
        )
    }

    /// Every function a possessive on `thing` can reach, for the diagnostic
    /// that says what the thing does have. Sorted by name, because the table
    /// behind it is a hash map and an unsorted list would print in a
    /// different order on every run.
    fn functions_taking(&self, thing: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .function_first_parameters
            .iter()
            .filter(|(_, first)| matches!(first, Type::Thing(first) if first == thing))
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        names
    }

    /// A thing's field names in layout order, for a diagnostic.
    fn field_names_of(&self, thing: &str) -> Vec<String> {
        self.things
            .get(thing)
            .map(|def| def.fields.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default()
    }

    /// Parse `'s <member>` repeatedly, from a base variable holding `thing`.
    /// Call with the base name consumed and `possessive_follows` true.
    ///
    /// Each step is checked against the registry as it is consumed, so an
    /// unknown member is reported at its own token and the chain only
    /// continues while the field it just read is itself a thing - which is
    /// what makes `route's leg's start's x` a single compile-time walk of
    /// definitions rather than a guess about depth.
    ///
    /// A step that is not a field is the instance possessive (plan 310 §4):
    /// if a function takes this thing first, the whole possessive is that
    /// call, with everything read so far as its first argument. The rewrite
    /// happens here, so nothing downstream ever sees the sugar - what the
    /// analyzer and codegen get is the ordinary call the author could have
    /// written by hand.
    fn parse_thing_possessive(
        &mut self,
        base: &str,
        thing: &str,
        position: PossessivePosition,
    ) -> Result<Possessive, Box<CompileError>> {
        let mut current = thing.to_string();
        let mut path: Vec<String> = Vec::new();

        loop {
            self.consume_possessive();

            let member_pos = self.pos;
            let member = match self.current().clone() {
                Token::Identifier(member) => {
                    self.advance();
                    member
                }
                // A reserved word can never be a field or a function name:
                // both go through `parse_name`, which rejects them.
                other => {
                    return Err(self.err_expected(
                        &format!("a member of thing '{}'", current),
                        &other,
                    ))
                }
            };

            let field_type = match self.things.get(&current) {
                Some(def) => def
                    .fields
                    .iter()
                    .find(|f| f.name == member)
                    .map(|f| f.field_type.clone()),
                // The declaration is known (it is what named this type) but
                // the definition has not been read yet: the thing is defined
                // BELOW this use. That ordering rule is real - LANGUAGE.md
                // states that every use stands after the definition it names -
                // so this is a rejection, and the message says which line to
                // move (BUGS_FOUND #80, diagnostic in #46's family).
                None => {
                    self.pos = member_pos;
                    return Err(self.err(&format!(
                        "Thing '{}' is defined below this line\n  \
                         A thing is defined at the top level, like a function, \
                         and every use of its name stands after the \
                         definition.\n  \
                         Move the definition of '{}' above this line.",
                        current, current
                    )));
                }
            };

            let Some(field_type) = field_type else {
                // A field always wins, so reaching here means there is none.
                // The second reading is the sugar; a write target has no
                // second reading, because a call is not storage.
                //
                // A declared member is asked about before the global
                // functions, because the two cannot collide - a function
                // taking a point first cannot be called what point's manifest
                // already lists (`reject_member_space_collision`), so this
                // order decides nothing that is ever contested.
                if position == PossessivePosition::Value {
                    if let Some(function) = self.instance_member_of(&current, &member) {
                        let receiver = Self::receiver_of(base, &path);
                        return Ok(Possessive::Call(
                            self.parse_instance_call(function, receiver)?,
                        ));
                    }
                    if self.first_parameter_is(&member, &current) {
                        let receiver = Self::receiver_of(base, &path);
                        return Ok(Possessive::Call(self.parse_instance_call(member, receiver)?));
                    }
                }
                self.pos = member_pos;
                return Err(self.err_unknown_member(&current, &member, position));
            };
            path.push(member);

            match &field_type {
                Type::Thing(inner) => {
                    current = inner.clone();
                    if self.possessive_follows() {
                        continue;
                    }
                    // The chain ends on a nested thing, which names the whole
                    // thing: a copy source, a copy target, or an argument
                    // (plan 310 §5). Whether *this* position accepts a whole
                    // thing is the analyzer's call, so the chain is handed
                    // back as written rather than judged here.
                    return Ok(Possessive::Field { path, field_type });
                }
                scalar => {
                    if self.possessive_follows() {
                        self.pos = member_pos;
                        return Err(self.err(&format!(
                            "'{}' holds a {}, so nothing can be read out of it\n  \
                             Only a field that holds a thing can be gone through \
                             with another possessive.",
                            Self::render_chain(base, &path),
                            type_noun_of(scalar)
                        )));
                    }
                    let scalar = scalar.clone();
                    return Ok(Possessive::Field {
                        path,
                        field_type: scalar,
                    });
                }
            }
        }
    }

    /// What the receiver of an instance call is: the base variable itself, or
    /// the field chain read so far when the possessive went through a field
    /// that holds a thing (`the line's end's 'magnitude squared'`).
    fn receiver_of(base: &str, path: &[String]) -> Expr {
        if path.is_empty() {
            Expr::Identifier(base.to_string())
        } else {
            Expr::ThingField {
                base: base.to_string(),
                path: path.to_vec(),
            }
        }
    }

    /// Finish an instance call: the receiver fills the first parameter, and
    /// any remaining arguments follow the ordinary call preposition, read by
    /// the ordinary call-tail parser (plan 310 §4). `origin's 'scaled by' on
    /// 3` and `'scaled by' of origin and 3` therefore build the same call -
    /// there is no second argument grammar to keep in step.
    fn parse_instance_call(
        &mut self,
        function: String,
        receiver: Expr,
    ) -> Result<Expr, Box<CompileError>> {
        let mut args = vec![receiver];
        if let Some(Expr::FunctionCall { args: rest, .. }) =
            self.parse_call_tail(function.clone(), true)?
        {
            args.extend(rest);
        }
        Ok(Expr::FunctionCall {
            name: function,
            args,
        })
    }

    /// A possessive naming nothing the thing has. Says what it does have:
    /// its fields, and - where the sugar could have fired - the functions
    /// that take it first.
    fn err_unknown_member(
        &self,
        thing: &str,
        member: &str,
        position: PossessivePosition,
    ) -> Box<CompileError> {
        let fields = self.field_names_of(thing);
        let functions = self.functions_taking(thing);
        let declared = self.declared_members_of(thing);

        // A name the manifest lists is not "no such member" - it is a member
        // this possessive cannot reach, and saying which is the difference
        // between a correction and a wild goose chase.
        if declared.iter().any(|name| name == member) {
            return self.err_member_out_of_reach(thing, member, position);
        }

        let message = match position {
            PossessivePosition::WriteTarget if self.first_parameter_is(member, thing) => format!(
                "'{}' is a function taking a {}, not a field of it\n  \
                 A call is not storage, so nothing can be written to it.\n  \
                 {}'s fields are: {}",
                member,
                thing,
                thing,
                fields.join(", ")
            ),
            PossessivePosition::WriteTarget => format!(
                "Thing '{}' has no field '{}'\n  \
                 Only a field can be written; its fields are: {}",
                thing,
                member,
                fields.join(", ")
            ),
            PossessivePosition::Value => format!(
                "Thing '{}' has no member '{}'\n  \
                 A possessive reads one of the thing's fields, or calls a \
                 function whose first parameter is a {} (plan 310 §4).\n  \
                 {}'s fields are: {}{}\n  \
                 {}",
                thing,
                member,
                thing,
                thing,
                fields.join(", "),
                if declared.is_empty() {
                    String::new()
                } else {
                    format!("\n  {} declares: {}", thing, declared.join(", "))
                },
                // "above this line" is the whole truth: a function is
                // reachable through a receiver from its definition onwards,
                // the same rule that governs a thing and a thing variable.
                // Saying only "no function takes a point first" would be a
                // lie about a program that defines one further down.
                if functions.is_empty() {
                    format!(
                        "no function above this line takes a {} as its first parameter",
                        thing
                    )
                } else {
                    format!(
                        "functions above this line taking a {} first: {}",
                        thing,
                        functions.join(", ")
                    )
                }
            ),
        };

        let mut err = *self.err(&message);
        // Offer every part of the member space as near misses, so a
        // misspelled function or declared member is corrected as readily as
        // a field.
        let mut candidates: Vec<&str> = fields.iter().map(|f| f.as_str()).collect();
        if position == PossessivePosition::Value {
            candidates.extend(functions.iter().map(|f| f.as_str()));
            candidates.extend(declared.iter().map(|m| m.as_str()));
        }
        if let Some(near) = find_similar_keyword(member, &candidates) {
            err = err.with_suggestion(&near);
        }
        Box::new(err)
    }

    /// `origin's leg's start` - the chain as written, for a diagnostic.
    fn render_chain(base: &str, path: &[String]) -> String {
        let mut out = base.to_string();
        for step in path {
            out.push_str("'s ");
            out.push_str(step);
        }
        out
    }

    /// A possessive in expression position: `origin's x` reads a field,
    /// `origin's magnitude` calls a function taking a point (plan 310 §4).
    pub(crate) fn parse_thing_possessive_expr(
        &mut self,
        base: String,
        thing: &str,
    ) -> Result<Expr, Box<CompileError>> {
        match self.parse_thing_possessive(&base, thing, PossessivePosition::Value)? {
            Possessive::Field { path, .. } => Ok(Expr::ThingField { base, path }),
            Possessive::Call(call) => Ok(call),
        }
    }

    /// If the cursor sits on `<thing variable>'s <field>...`, consume the
    /// whole chain and return the write target plus the type it holds.
    /// Returns None with the position unchanged when it does not, so every
    /// caller can try this before its own grammar.
    pub(crate) fn try_parse_thing_field_target(
        &mut self,
    ) -> Result<Option<(String, Vec<String>, Type)>, Box<CompileError>> {
        let Token::Identifier(name) = self.current().clone() else {
            return Ok(None);
        };
        let Some(thing) = self.thing_of_variable(&name) else {
            return Ok(None);
        };
        let saved = self.pos;
        self.advance();
        if !self.possessive_follows() {
            self.pos = saved;
            return Ok(None);
        }
        match self.parse_thing_possessive(&name, &thing, PossessivePosition::WriteTarget)? {
            Possessive::Field { path, field_type } => Ok(Some((name, path, field_type))),
            // `WriteTarget` never resolves the sugar, so a call cannot come
            // back from it.
            Possessive::Call(_) => unreachable!("a write target resolves to a field or errors"),
        }
    }

    /// `origin's 'shift east' on 2.` as a whole statement - the same sugar in
    /// the position an ordinary call already occupies, for a function called
    /// to do something rather than to produce a value.
    ///
    /// A bare statement is the one place BOTH readings of a possessive are
    /// grammatical - a write (`origin's y is 4.`) and a call - so this reads
    /// it in value position, where both are allowed, and hands back anything
    /// that turns out to be a write. What follows decides: a field, or an `is`
    /// after the possessive, means a write, and the caller's write-target path
    /// re-reads it and reports it in those terms, with its caret on the member
    /// and its message about storage. An error is NOT handed back, because in
    /// value position it already names both halves of the member space, which
    /// is exactly what a statement position needs to offer.
    pub(crate) fn try_parse_instance_call_statement(
        &mut self,
    ) -> Result<Option<Statement>, Box<CompileError>> {
        let Token::Identifier(name) = self.current().clone() else {
            return Ok(None);
        };
        let Some(thing) = self.thing_of_variable(&name) else {
            return Ok(None);
        };
        let saved = self.pos;
        self.advance();
        if !self.possessive_follows() {
            self.pos = saved;
            return Ok(None);
        }
        let possessive = self.parse_thing_possessive(&name, &thing, PossessivePosition::Value)?;
        let Possessive::Call(Expr::FunctionCall { name, args }) = possessive else {
            // A field, or - `parse_instance_call` builds nothing else - a
            // shape that cannot occur. Either way this is not a call.
            self.pos = saved;
            return Ok(None);
        };

        self.skip_noise();
        if matches!(self.current(), Token::Is | Token::Equals) {
            self.pos = saved;
            return Ok(None);
        }
        Ok(Some(Statement::FunctionCall { name, args }))
    }

    /// `increment origin's x.` / `decrement ...`. The target is an offset, not
    /// a name, so `Statement::Increment` (which carries a name) cannot hold
    /// it; the step is desugared into the field write it means. The step
    /// literal follows the field's own type so a float field stays a float.
    pub(crate) fn thing_field_step(
        base: String,
        path: Vec<String>,
        field_type: &Type,
        op: BinaryOperator,
    ) -> Statement {
        let one = if matches!(field_type, Type::Float) {
            Expr::FloatLit(1.0)
        } else {
            Expr::IntegerLit(1)
        };
        Statement::SetThingField {
            base: base.clone(),
            path: path.clone(),
            value: Expr::BinaryOp {
                left: Box::new(Expr::ThingField { base, path }),
                op,
                right: Box::new(one),
            },
        }
    }

    // ---------------------------------------------------------------------
    // Manifest members (plan 310 §4)
    // ---------------------------------------------------------------------

    /// True when a `To` opens a member definition: `To do the point's 'placed
    /// at', with ...`. Call with `To` already consumed.
    ///
    /// `do` does not become a keyword: only the whole shape `do the <name>'s`
    /// opens the construct, so a function called `do` keeps working - the
    /// contextual treatment `send`, `thing`, and the timer words all get. The
    /// `<name>` is not required to be a defined thing here, so a definition
    /// naming a type that does not exist reaches the message about the
    /// missing type rather than falling out of this guard into a generic
    /// complaint about `the`.
    pub(crate) fn member_definition_follows(&self) -> bool {
        if !matches!(self.current(), Token::Identifier(w) if w.eq_ignore_ascii_case("do")) {
            return false;
        }
        let mut off = 1;
        while matches!(self.peek(off), Token::Newline) {
            off += 1;
        }
        if !matches!(self.peek(off), Token::The) {
            return false;
        }
        off += 1;
        while matches!(self.peek(off), Token::Newline) {
            off += 1;
        }
        if !matches!(self.peek(off), Token::Identifier(_)) {
            return false;
        }
        self.possessive_follows_from(off + 1)
    }

    /// Read `do the <thing>'s <member>` and check it against the manifest,
    /// leaving the cursor on whatever follows the member's name (the payload
    /// comma before the parameter list, or the end of the signature). Call
    /// with `member_definition_follows` true.
    pub(crate) fn parse_member_definition_head(
        &mut self,
    ) -> Result<MemberDefinition, Box<CompileError>> {
        let line = self.current_info().map(|t| t.line).unwrap_or(0);
        self.advance(); // `do`
        self.skip_noise();
        self.advance(); // `the`
        self.skip_noise();

        let thing_pos = self.pos;
        let thing = self.parse_name()?;
        if !self.things.contains_key(&thing) {
            self.pos = thing_pos;
            return Err(self.err_no_such_thing(
                &thing,
                "`To do the <thing>'s <name>` defines one of the members a thing \
                 declares, so the thing's own definition comes first.",
            ));
        }
        self.consume_possessive();

        let member_pos = self.pos;
        let member = self.parse_member_name(
            &thing,
            &format!("To do the {}'s <name>, with <parameters>.", thing),
        )?;

        // Both halves of the manifest check (plan 310 §10). This is the half
        // that reports at the definition; the other - a declared member
        // nothing defines - can only be known once the whole file is read,
        // and reports at the type.
        if !self.declared_members_of(&thing).iter().any(|m| *m == member) {
            self.pos = member_pos;
            return Err(self.err_member_not_declared(&thing, &member));
        }

        if let Some(previous) = self.member_functions.get(&(thing.clone(), member.clone())) {
            let previous_line = previous.line;
            self.pos = member_pos;
            return Err(self.err(&format!(
                "{}'s '{}' is already defined on line {}\n  \
                 The manifest declares a member once and one `To do` defines it \
                 once; a second definition has no way to be called.",
                thing, member, previous_line
            )));
        }

        Ok(MemberDefinition {
            internal: member_function_name(&thing, &member),
            thing,
            member,
            line,
        })
    }

    /// Record a member definition once its signature is read - before its
    /// body, so a member may use its own thing's possessives inside itself,
    /// the same order `record_first_parameter` is written in.
    pub(crate) fn record_member_function(
        &mut self,
        member: &MemberDefinition,
        first: Option<&(String, Type)>,
    ) {
        let takes_owner_first =
            matches!(first, Some((_, Type::Thing(first))) if *first == member.thing);
        self.member_functions.insert(
            (member.thing.clone(), member.member.clone()),
            MemberFunction {
                internal: member.internal.clone(),
                takes_owner_first,
                line: member.line,
            },
        );
    }

    /// Plan 310 §4: every declared member returns its owner, which is what
    /// gives the manifest a crisp meaning - it lists the functions that
    /// produce or transform the thing. A function computing something else
    /// from a thing belongs in the global namespace, where the instance
    /// possessive still reaches it.
    ///
    /// The caret lands on the `Return` that hands back the wrong type, and
    /// the message names the `To do` line, so both lines of the disagreement
    /// are in the report.
    ///
    /// Every Return LINE is checked, rather than the one type the function
    /// ends up carrying: a body whose only Return sits inside an `If` leaves
    /// that type off the signature, and rejecting it for handing back nothing
    /// would be a report about a line the author did not write.
    pub(crate) fn reject_member_returning_another_type(
        &mut self,
        member: &MemberDefinition,
        definition_pos: usize,
    ) -> Result<(), Box<CompileError>> {
        let wrong = self
            .typed_returns
            .iter()
            .find(|(_, returned)| !matches!(returned, Type::Thing(name) if *name == member.thing))
            .map(|(pos, returned)| (*pos, returned.clone()));

        let (caret, handed_back) = match wrong {
            Some((pos, returned)) => (
                pos,
                format!(
                    "the Return on line {} hands back a {}",
                    self.tokens.get(pos).map(|t| t.line).unwrap_or(0),
                    type_noun_of(&returned)
                ),
            ),
            // Every Return that declares a type declares the right one.
            None if !self.typed_returns.is_empty() => return Ok(()),
            // None at all: there is no second line to point at, so the caret
            // stays on the definition that promised one.
            None => (
                definition_pos,
                format!(
                    "nothing in it declares a `Return a {}, <value>.`",
                    member.thing
                ),
            ),
        };
        self.pos = caret;
        Err(self.err(&format!(
            "A declared member returns its own thing: {}'s '{}' must return a {}\n  \
             The definition on line {} makes '{}' a member of {}, and {}.\n  \
             A function that computes something else from a {} is an ordinary \
             function - it needs no manifest entry, and the instance possessive \
             still reaches it (plan 310 §4).",
            member.thing,
            member.member,
            member.thing,
            member.line,
            member.member,
            member.thing,
            handed_back,
            member.thing
        )))
    }

    /// The other half of the manifest check (plan 310 §10), run once the
    /// whole file is read because that is the earliest a definition can be
    /// known to be absent. Reports at the type, whose line is where the
    /// promise was made, and stops at the first unmet one - every later
    /// report would be about the same missing half of the same construct.
    pub(crate) fn reject_undefined_members(&mut self) -> Result<(), Box<CompileError>> {
        // The registry is a hash map, so it is sorted into definition order
        // first: a program with two unmet declarations must report the same
        // one on every run.
        let mut defs: Vec<&ThingDef> = self.things.values().collect();
        defs.sort_by_key(|def| def.line);
        let unmet = defs.iter().find_map(|def| {
            def.members
                .iter()
                .find(|member| {
                    !self
                        .member_functions
                        .contains_key(&(def.name.clone(), (*member).clone()))
                })
                .map(|member| (def.name.clone(), member.clone(), def.line))
        });

        let Some((thing, member, line)) = unmet else {
            return Ok(());
        };
        let defined_on = self.where_thing_was_defined(&thing, line);
        // The caret goes on the type whose promise is unmet - unless the
        // definition came from a `see`n file, whose token indices belong to a
        // different stream. There the message names the file and the line,
        // and no caret is drawn: one pointing at a line of the wrong file
        // reads as a claim about that line.
        let in_this_file = self.thing_name_position(&thing);
        if let Some(pos) = in_this_file {
            self.pos = pos;
        }
        let report = if in_this_file.is_some() {
            |parser: &Self, message: &str| parser.err(message)
        } else {
            |_: &Self, message: &str| Box::new(CompileError::new(message))
        };
        Err(report(self, &format!(
            "{} declares '{}' but nothing defines it\n  \
             The definition on {} lists '{}' as part of {}'s callable API, \
             so somewhere the program has to write it:\n    \
             To do the {}'s {}, with <parameters>.\n      \
             ...\n      \
             Return a {}, <value>.\n  \
             A name that is not this type's own API is an ordinary function and \
             needs no manifest entry (plan 310 §4).",
            thing,
            member,
            defined_on,
            member,
            thing,
            thing,
            crate::codegen::format_lib_name(&member),
            thing
        )))
    }

    /// True when the cursor opens a type possessive: `a point's 'placed at'`.
    /// One token of lookahead separates it from a declaration - the `'s`
    /// against the `called` of `a point called origin` (plan 310 §4).
    ///
    /// The name is not required to be a defined thing, for the same reason
    /// `member_definition_follows` does not require it: nothing else in Vox
    /// spells `a <name>'s`, so capturing the whole shape is what lets the
    /// unknown type be reported as one.
    pub(crate) fn type_possessive_follows(&self) -> bool {
        if !matches!(self.current(), Token::A | Token::An) {
            return false;
        }
        let mut off = 1;
        while matches!(self.peek(off), Token::Newline) {
            off += 1;
        }
        if !matches!(self.peek(off), Token::Identifier(_)) {
            return false;
        }
        self.possessive_follows_from(off + 1)
    }

    /// `a point's 'placed at' with 3 and 4` - the call form that names the
    /// type rather than a receiver (plan 310 §4). It reaches every member the
    /// manifest declares, and it is the ONLY way to reach a maker, whose
    /// first parameter is not the thing and so cannot be filled by one.
    ///
    /// Resolution is from the manifest, not from the definitions read so far,
    /// so a call may stand above the `To do` that defines it: the declaration
    /// is the promise, and `reject_undefined_members` is what collects on it.
    pub(crate) fn parse_type_possessive_call(&mut self) -> Result<Expr, Box<CompileError>> {
        self.advance(); // the article
        self.skip_noise();

        let thing_pos = self.pos;
        let thing = self.parse_name()?;
        if !self.things.contains_key(&thing) {
            self.pos = thing_pos;
            return Err(self.err_no_such_thing(
                &thing,
                "`a <thing>'s <name>` calls a member a thing declares. To read a \
                 field or call through a receiver, name the variable: `origin's x`.",
            ));
        }
        self.consume_possessive();

        let member_pos = self.pos;
        let member = self.parse_member_name(
            &thing,
            &format!("a {}'s <name> with <arguments>", thing),
        )?;
        if !self.declared_members_of(&thing).iter().any(|m| *m == member) {
            self.pos = member_pos;
            return Err(self.err_member_not_declared(&thing, &member));
        }

        // The arguments follow the ordinary call preposition, read by the
        // ordinary call-tail parser, so this form shares its argument grammar
        // with every other call rather than keeping a second one in step.
        let name = member_function_name(&thing, &member);
        let mut args = Vec::new();
        if let Some(Expr::FunctionCall { args: rest, .. }) =
            self.parse_call_tail(name.clone(), true)?
        {
            args = rest;
        }
        Ok(Expr::FunctionCall { name, args })
    }

    /// The member name after a `<thing>'s`, with the canonical form named
    /// when what follows is not a name at all. `To do the point's.` is an
    /// unfinished sentence, and "expected a name" alone would not say which
    /// sentence it is. A quoted or string-literal name keeps `parse_name`'s
    /// own teaching diagnostic.
    fn parse_member_name(
        &mut self,
        thing: &str,
        canonical: &str,
    ) -> Result<String, Box<CompileError>> {
        if matches!(
            self.current(),
            Token::Identifier(_) | Token::StringLiteral(_)
        ) {
            return self.parse_name();
        }
        Err(self.err(&format!(
            "Expected the name of one of {}'s members, got {:?}\n  \
             Canonical form: {}",
            thing,
            self.current(),
            canonical
        )))
    }

    /// The internal name of a declared member the instance possessive can
    /// reach: one whose definition has been read and takes its own thing
    /// first. A maker is absent, because a receiver cannot fill a parameter
    /// that is not the thing.
    fn instance_member_of(&self, thing: &str, member: &str) -> Option<String> {
        let defined = self
            .member_functions
            .get(&(thing.to_string(), member.to_string()))?;
        defined
            .takes_owner_first
            .then(|| defined.internal.clone())
    }

    /// A thing's declared function members, in manifest order.
    fn declared_members_of(&self, thing: &str) -> Vec<String> {
        self.things
            .get(thing)
            .map(|def| def.members.clone())
            .unwrap_or_default()
    }

    /// A possessive naming a member the manifest DOES declare, in a position
    /// that cannot reach it. Which position it is decides the reason, and
    /// each reason has a different thing to write instead.
    fn err_member_out_of_reach(
        &self,
        thing: &str,
        member: &str,
        position: PossessivePosition,
    ) -> Box<CompileError> {
        if position == PossessivePosition::WriteTarget {
            return self.err(&format!(
                "'{}' is a function member {} declares, not a field of it\n  \
                 A call is not storage, so nothing can be written to it.\n  \
                 {}'s fields are: {}",
                member,
                thing,
                thing,
                self.field_names_of(thing).join(", ")
            ));
        }
        let reason = if self.member_functions.contains_key(&(thing.to_string(), member.to_string()))
        {
            format!(
                "'{}' is a maker: its first parameter is not a {}, so a receiver \
                 has nothing to fill",
                member, thing
            )
        } else {
            // The definition may well be further down the file. A receiver
            // resolves against what has been read, so this is a limit of
            // where the call sits, not a claim that the member is missing.
            format!(
                "'{}' has no definition above this line, so what its first \
                 parameter takes is not known here",
                member
            )
        };
        self.err(&format!(
            "{} declares '{}', but a receiver cannot reach it here\n  \
             {}.\n  \
             Name the type instead: `a {}'s {} with <arguments>` (plan 310 §4).",
            thing,
            member,
            reason,
            thing,
            crate::codegen::format_lib_name(member)
        ))
    }

    /// A possessive or a definition naming a type nothing defines. `context`
    /// is the one sentence that differs between the two forms.
    fn err_no_such_thing(&self, name: &str, context: &str) -> Box<CompileError> {
        let mut known: Vec<&str> = self.things.keys().map(|k| k.as_str()).collect();
        known.sort();
        let mut err = *self.err(&format!(
            "No thing called '{}' is defined above this line\n  \
             {}\n  \
             {}",
            name,
            context,
            if known.is_empty() {
                "This program defines no things.".to_string()
            } else {
                format!("Things defined above this line: {}", known.join(", "))
            }
        ));
        if let Some(near) = find_similar_keyword(name, &known) {
            err = err.with_suggestion(&near);
        }
        Box::new(err)
    }

    /// The manifest check reported at a definition or a call (plan 310 §10):
    /// a member the type does not declare. Membership is declared in the
    /// type, so the fix is to add the entry - which the message spells.
    fn err_member_not_declared(&self, thing: &str, member: &str) -> Box<CompileError> {
        // A field is the one name that must not be answered with "add `a
        // function called <name>`": the type owns one member space, so
        // following that advice would collide with the field it already has.
        if self.field_names_of(thing).iter().any(|f| f == member) {
            return self.err(&format!(
                "'{}' is a field of {}, not one of its declared function members\n  \
                 A type owns one member space, so a field and a function member \
                 cannot share a name (plan 310 §4).\n  \
                 A field is read from a variable holding a {}: `origin's {}`.",
                member, thing, thing, member
            ));
        }

        let declared = self.declared_members_of(thing);
        let mut err = *self.err(&format!(
            "{} does not declare {} - add `a function called {}` to the type\n  \
             Membership is declared in the thing's definition, which lists its \
             whole callable API in one place (plan 310 §4).\n  \
             {}",
            thing,
            crate::codegen::format_lib_name(member),
            crate::codegen::format_lib_name(member),
            if declared.is_empty() {
                format!("{} declares no function members.", thing)
            } else {
                format!("{} declares: {}", thing, declared.join(", "))
            }
        ));
        let candidates: Vec<&str> = declared.iter().map(|m| m.as_str()).collect();
        if let Some(near) = find_similar_keyword(member, &candidates) {
            err = err.with_suggestion(&near);
        }
        Box::new(err)
    }

    fn err_field_default_not_literal(
        &self,
        thing_name: &str,
        field_name: &str,
    ) -> Box<CompileError> {
        self.err(&format!(
            "A field default must be a literal\n  \
             Field '{}' of thing '{}': write `is 0`, `is 1.5`, `is true`, or \
             `is \"text\"`.\n  \
             Anything computed belongs in a function that returns the thing.",
            field_name, thing_name
        ))
    }
}
