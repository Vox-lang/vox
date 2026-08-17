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
        // Peek the name so the message can echo it, without disturbing the
        // parser position - the caller is about to abort anyway, but a
        // diagnostic that silently consumed tokens would be a trap for the
        // next person to reuse this helper.
        let saved = self.pos;
        self.advance(); // `thing`
        self.skip_noise();
        self.advance(); // `called`
        self.skip_noise();
        let name = match self.current().clone() {
            Token::Identifier(n) | Token::StringLiteral(n) => n,
            // Whatever follows `called` is not a name at all; a placeholder
            // is honest where inventing one would misreport what was
            // written.
            _ => "<name>".to_string(),
        };
        self.pos = saved;
        self.err(&format!(
            "A thing is defined, not created as a variable\n  \
             Canonical form: A thing called {} has <fields>.",
            name
        ))
    }

    /// Parse a whole definition construct, starting at the contextual
    /// `thing` keyword (the article is already consumed). Registers the
    /// `ThingDef` so later definitions can nest it, and returns the
    /// statement that carries it into the program.
    pub(crate) fn parse_thing_definition(&mut self) -> Result<Statement, Box<CompileError>> {
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
        if let Some(previous) = self.things.get(&name) {
            let previous_line = previous.line;
            // Rewind so the underline lands on the duplicate name rather
            // than on whatever follows it. The parse is aborting anyway.
            self.pos = name_pos;
            return Err(self.err(&format!(
                "'{}' is already defined as a thing on line {}\n  \
                 Type names, variable names, and function names share one \
                 identifier space; the first definition wins.",
                name, previous_line
            )));
        }
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
        self.things.insert(name, def.clone());
        Ok(Statement::ThingDecl(def))
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

        let literal = match self.current().clone() {
            Token::IntegerLiteral(n) => Some(Expr::IntegerLit(if negated { -n } else { n })),
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
    /// parsed. `name_pos` is the token index of that name, so a rejected
    /// declaration underlines the name rather than what follows it.
    pub(crate) fn finish_thing_declaration(
        &mut self,
        thing: String,
        name: String,
        name_pos: usize,
    ) -> Result<Statement, Box<CompileError>> {
        // One identifier space, first-come-first-serve (plan 310 §10): the
        // definition claimed this name already, so `a point called point.`
        // cannot also mean a variable.
        if let Some(previous) = self.things.get(&name) {
            let previous_line = previous.line;
            self.pos = name_pos;
            return Err(self.err(&format!(
                "'{}' is already defined as a thing on line {}\n  \
                 Type names, variable names, and function names share one \
                 identifier space; the first definition wins.",
                name, previous_line
            )));
        }

        self.skip_noise();
        if matches!(self.current(), Token::Is | Token::Equals | Token::To) {
            return Err(self.err(&format!(
                "Copying a whole thing is not supported yet (plan 310 §5)\n  \
                 A declaration with an initialiser copies the whole value, \
                 which lands with copy semantics.\n  \
                 For now write `a {} called {}.` and set its fields.",
                thing, name
            )));
        }

        self.thing_vars.insert(name.clone(), thing.clone());
        Ok(Statement::VarDecl {
            name,
            var_type: Some(Type::Thing(thing)),
            value: None,
        })
    }

    // ---------------------------------------------------------------------
    // Field access (plan 310 §3)
    // ---------------------------------------------------------------------

    /// Which thing a declared variable holds, if it holds one.
    pub(crate) fn thing_of_variable(&self, name: &str) -> Option<String> {
        self.thing_vars.get(name).cloned()
    }

    /// True when the tokens at the cursor open a possessive (`'s`).
    pub(crate) fn possessive_follows(&self) -> bool {
        let mut off = 0;
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

    /// Parse `'s <field>` repeatedly, from a base variable holding `thing`,
    /// and return the field names in order together with the type stored at
    /// the end of the chain. Call with the base name consumed and
    /// `possessive_follows` true.
    ///
    /// Each step is checked against the registry as it is consumed, so an
    /// unknown field is reported at its own token and the chain only
    /// continues while the field it just read is itself a thing - which is
    /// what makes `route's leg's start's x` a single compile-time walk of
    /// definitions rather than a guess about depth.
    fn parse_thing_field_chain(
        &mut self,
        base: &str,
        thing: &str,
    ) -> Result<(Vec<String>, Type), Box<CompileError>> {
        let mut current = thing.to_string();
        let mut path: Vec<String> = Vec::new();

        loop {
            self.skip_noise();
            self.advance(); // the apostrophe
            self.skip_noise();
            self.advance(); // the `s`
            self.skip_noise();

            let field_pos = self.pos;
            let field = match self.current().clone() {
                Token::Identifier(field) => {
                    self.advance();
                    field
                }
                // A reserved word can never be a field name: a definition's
                // field names go through `parse_name`, which rejects them.
                other => {
                    return Err(self.err_expected(
                        &format!("a field of thing '{}'", current),
                        &other,
                    ))
                }
            };

            let Some(def) = self.things.get(&current) else {
                // Unreachable: a `Type::Thing` payload is only ever written
                // for a name already in the registry.
                return Err(self.err(&format!("Unknown thing '{}'", current)));
            };
            let Some(found) = def.fields.iter().find(|f| f.name == field) else {
                let known: Vec<String> = def.fields.iter().map(|f| f.name.clone()).collect();
                self.pos = field_pos;
                return Err(self.err_unknown_field(&current, &field, &known));
            };
            let field_type = found.field_type.clone();
            path.push(field);

            match &field_type {
                Type::Thing(inner) => {
                    current = inner.clone();
                    if self.possessive_follows() {
                        continue;
                    }
                    // Ending on a nested thing means reading the whole thing:
                    // copying (§5) or printing (§7), both later tasks. Reading
                    // its first eight bytes instead would be silently wrong.
                    self.pos = field_pos;
                    let known: Vec<String> = self
                        .things
                        .get(&current)
                        .map(|def| def.fields.iter().map(|f| f.name.clone()).collect())
                        .unwrap_or_default();
                    return Err(self.err(&format!(
                        "'{}' holds a whole {}, not a value\n  \
                         A field chain must end on a field that holds a value; \
                         reading a whole thing lands with copy semantics (plan \
                         310 §5) and printing (§7).\n  \
                         {}'s fields are: {}",
                        Self::render_chain(base, &path),
                        current,
                        current,
                        known.join(", ")
                    )));
                }
                scalar => {
                    if self.possessive_follows() {
                        self.pos = field_pos;
                        return Err(self.err(&format!(
                            "'{}' holds a {}, so nothing can be read out of it\n  \
                             Only a field that holds a thing can be gone through \
                             with another possessive.",
                            Self::render_chain(base, &path),
                            type_noun_of(scalar)
                        )));
                    }
                    return Ok((path, scalar.clone()));
                }
            }
        }
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

    pub(crate) fn err_unknown_field(
        &self,
        thing: &str,
        field: &str,
        known: &[String],
    ) -> Box<CompileError> {
        let mut err = *self.err(&format!(
            "Thing '{}' has no field '{}'\n  \
             A thing's fields are its whole member space: its fields are: {}",
            thing,
            field,
            known.join(", ")
        ));
        let candidates: Vec<&str> = known.iter().map(|k| k.as_str()).collect();
        if let Some(near) = find_similar_keyword(field, &candidates) {
            err = err.with_suggestion(&near);
        }
        Box::new(err)
    }

    /// A field read in expression position: `origin's x`.
    pub(crate) fn parse_thing_field_expr(
        &mut self,
        base: String,
        thing: &str,
    ) -> Result<Expr, Box<CompileError>> {
        let (path, _) = self.parse_thing_field_chain(&base, thing)?;
        Ok(Expr::ThingField { base, path })
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
        let (path, field_type) = self.parse_thing_field_chain(&name, &thing)?;
        Ok(Some((name, path, field_type)))
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
