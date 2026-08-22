//! BUGS_FOUND #62/#63 - a result that does not exist, used as a value.
//!
//! Two spellings, one rule. A `.lib` entry with no `, returning` clause and
//! a `To` with no `Return` at all are both functions that return nothing.
//! LANGUAGE.md:4963-4965 says the first outright - "No `returning` clause
//! means the function returns nothing" - and the Functions section never
//! gives the second a result to read: `To ping. Print "pong".` is a
//! definition (LANGUAGE.md:684-686), `ping.` is a call (LANGUAGE.md:772-777),
//! and "Calling as Statement" (LANGUAGE.md:779-785) is the position a call
//! with no result belongs in. Nothing in either section hands a value back
//! from a function that never returns one.
//!
//! Before this, both compiled in value position with no diagnostic at all
//! and the caller read whatever the call left behind: `a number called n is
//! greet.` and `print ping.` both answered `1`, a leftover in the return
//! register wearing the type of the slot it landed in. That is exactly the
//! shape LANGUAGE.md:656-660 names as the thing the 0.3.0 identifier/literal
//! split was written to kill - "a wrong answer that looks like data. No
//! error, no warning". There is no result here to infer a type for and no
//! honest value to substitute, so the use site is refused; calling either
//! one as a statement is untouched and stays the way to run it.
//!
//! Both halves are one check on `Type::Void`, resolved the way a call
//! resolves - a local definition first, then a single unambiguous import -
//! so a local function shadowing a void import is judged on its own body.
//!
//! Sibling: BUGS_FOUND #45 is the other half of `Type::Void`, a function
//! that DOES hand a value back but never declared its type. The two sets
//! partition the same flag: #45's is `Void` with a value-returning `Return`
//! somewhere in the body, this one is `Void` with none at all. A function
//! whose branches return DIFFERENT declared types also lands in #45's half,
//! never this one - it returns a value, it just has no single type to
//! promise (src/parser/functions.rs, BUGS_FOUND #43) - so nothing here can
//! refuse a call that really does answer with something.

use crate::errors::SourceLocation;
use crate::parser::ast::*;
use super::Analyzer;

/// True when `body` hands a value back to its caller - a `Return <expr>` at
/// any depth. Nested returns count: a function's only `Return` may sit
/// inside an `If` (BUGS_FOUND #43), and such a function still answers with a
/// value. A bare `Return.` carries no value and so does not count, which is
/// the point: it ends the call, it does not answer it.
fn body_returns_a_value(body: &[Statement]) -> bool {
    body.iter().any(statement_returns_a_value)
}

fn statement_returns_a_value(stmt: &Statement) -> bool {
    match stmt {
        Statement::Return { value: Some(_), .. } => true,
        Statement::If { then_block, else_if_blocks, else_block, .. } => {
            body_returns_a_value(then_block)
                || else_if_blocks.iter().any(|(_, blk)| body_returns_a_value(blk))
                || else_block.as_ref().is_some_and(|blk| body_returns_a_value(blk))
        }
        Statement::While { body, .. }
        | Statement::ForRange { body, .. }
        | Statement::ForEach { body, .. }
        | Statement::Repeat { body, .. } => body_returns_a_value(body),
        _ => false,
    }
}

/// Which way a name turned out to return nothing. The two differ only in
/// what the author has to change, so that is all this decides.
#[derive(Clone, Copy)]
enum VoidResult {
    /// A `To` in this program with no `Return` anywhere in its body (#63).
    Procedure,
    /// An imported `.lib` entry with no `, returning` clause (#62).
    LibraryEntry,
}

impl Analyzer {
    /// Record `key` as a function that returns nothing: it declared no return
    /// type AND never hands a value back. Called from the signature pre-pass,
    /// so a call written above the definition is judged the same as one below
    /// it.
    pub(crate) fn record_procedure(
        &mut self,
        key: String,
        return_type: &Type,
        body: &[Statement],
    ) {
        if *return_type == Type::Void && !body_returns_a_value(body) {
            self.procedures.insert(key);
        }
    }

    /// How `name` returns nothing, and `None` when it returns something (or
    /// is not a function at all). Resolution follows the call-site rule in
    /// `check_function_call`: a local definition shadows a same-named import,
    /// and two imports exporting one name are ambiguous - that ambiguity has
    /// its own diagnostic, so it is left alone here rather than reported
    /// twice.
    fn void_result_of(&self, name: &str) -> Option<VoidResult> {
        if self.functions.contains(&self.func_key(name)) {
            return self
                .procedures
                .contains(&self.func_key(name))
                .then_some(VoidResult::Procedure);
        }
        match self.imported_providers(name).as_slice() {
            [only] if only.return_type == Type::Void => Some(VoidResult::LibraryEntry),
            _ => None,
        }
    }

    /// Refuse a call to `name` in a position that reads its result. Every
    /// rejection site is one call to this, and a site that only RUNS the call
    /// - `Statement::FunctionCall`, the whole-statement form - never reaches
    /// it.
    pub(crate) fn reject_void_call_result(&mut self, name: &str) {
        let Some(kind) = self.void_result_of(name) else {
            return;
        };
        let (message, hint) = match kind {
            VoidResult::Procedure => (
                format!(
                    "'{}' returns nothing, so its result cannot be used as a value here\n  \
                     A `To` with no `Return` hands nothing back (LANGUAGE.md \
                     \"Functions\"), and this position reads a value - so what lands \
                     here is whatever the call left in the return register, not an \
                     answer.",
                    name
                ),
                format!(
                    "give '{}' a `Return a <type>, <expression>.`, or call '{}' as a \
                     statement instead of using its result",
                    name, name
                ),
            ),
            VoidResult::LibraryEntry => (
                format!(
                    "'{}' has no declared return type in its .lib entry, so its result \
                     cannot be used as a value here\n  \
                     A `.lib` entry with no `, returning` clause is a function that \
                     returns nothing (LANGUAGE.md:4963-4965), and consuming a library \
                     type-checks its calls like any other function's \
                     (LANGUAGE.md:4990) - so what lands here is whatever the call left \
                     in the return register, not an answer.",
                    name
                ),
                format!(
                    "add `, returning a <type>` to {}'s .lib entry, or call '{}' as a \
                     statement instead of using its result",
                    name, name
                ),
            ),
        };
        match self.use_site_location(name) {
            Some(loc) => self.push_error_with_hint_at(message, Some(loc), Some(&hint)),
            None => self.push_error_with_hint(message, Some(name), Some(&hint)),
        }
    }

    /// The use, not the definition. The ordinary symbol search takes the
    /// first textual hit for the name, which for a function defined in this
    /// file is its own `To` line - the caret would land on the definition the
    /// author is being told to change rather than on the read that is wrong.
    /// Excluding that line puts it back on the use. The occurrence counter is
    /// the one `push_error_with_hint` keeps, so a second misuse of the same
    /// name gets its own caret instead of a second copy of the first one.
    fn use_site_location(&mut self, name: &str) -> Option<SourceLocation> {
        let definition_line = self.definition_line(name);
        // `{name` leads the list because of bug #46's region rule: a match
        // sitting inside a text literal is refused unless the pattern asked
        // for one, and a call CAN legitimately sit inside a literal —
        // `Print "shouted {shout of 3}".` is a call in a format hole. Only a
        // pattern whose prefix ends `{` (or `"`) reaches in there. It never
        // wins for an ordinary call: the code-only first pass cannot match a
        // pattern that exists only inside a literal, so a plain `shout of 3`
        // in code still anchors on the code hit. Without it the search found
        // nothing, fell back to the unfiltered symbol scan, and landed on the
        // first textual `shout` on the line — inside the word `shouted`.
        let patterns = [
            format!("{{{}", name),
            format!("'{}'", name),
            name.to_string(),
        ];
        let occurrence = *self.symbol_error_counts.get(name).unwrap_or(&0);
        let found = self.find_pattern_location(name, &patterns, occurrence, definition_line, false);
        self.symbol_error_counts.insert(name.to_string(), occurrence + 1);
        found
    }

    /// The line `name` is defined on: the first `To 'name'`/`To name` in the
    /// source. `None` for an imported name (its definition is in another
    /// program entirely) and when there is no source to scan, which just
    /// leaves the caret to the ordinary search.
    fn definition_line(&self, name: &str) -> Option<usize> {
        let source = self.source_file.as_ref()?;
        let quoted = format!("To '{}'", name);
        let bare = format!("To {}", name);
        source
            .content
            .lines()
            .position(|line| {
                let trimmed = line.trim_start();
                trimmed.starts_with(&quoted)
                    || (trimmed.starts_with(&bare)
                        && trimmed[bare.len()..]
                            .chars()
                            .next()
                            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_'))
            })
            .map(|index| index + 1)
    }
}
