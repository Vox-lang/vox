//! BUGS_FOUND #45 - a function with no declared return type, read where
//! nothing supplies one.
//!
//! `To 'opaque label'. Return "hi".` returns a text, but the definition
//! never says so. A caller that lands the result in a declared variable is
//! fine - the declaration supplies the type - but a caller that reads it
//! straight into an untyped position has nothing to read it as, and the
//! compiler falls back on a conservative "it is a number" guess. The text
//! then prints as the rodata address of its bytes: a wrong answer that
//! looks like data, stable across runs, with no diagnostic.
//!
//! LANGUAGE.md:649-660 names that exact shape - "a function pointer,
//! printed as a number, silently. No error, no warning; the program runs
//! and gives a wrong answer that looks like data" - as the thing the 0.3.0
//! identifier/literal split was written to kill. Guessing and staying
//! silent is the one option the language's own stated philosophy rules
//! out, and this pass cannot prove the type (the body may return a text on
//! one path and a number on another, or call something opaque itself). So
//! the untyped read is refused, and the diagnostic names both ways out -
//! the same shape as `push_whole_thing_not_interpolable`, which refuses a
//! construct codegen cannot render rather than rendering it wrongly.
//!
//! Everything here is keyed off ONE set, `untyped_result_functions`, filled
//! in the signature pre-pass. The rejection sites are the positions that
//! store or render a value with no declared type of their own; a position
//! that does supply a type (a declared variable, a declared parameter, a
//! comparison against a typed operand) is left exactly as it was.

use crate::parser::ast::*;
use crate::errors::SourceLocation;
use super::Analyzer;

/// True when `body` hands a value back to its caller - a `Return <expr>`
/// at any depth. Nested returns count: bug #43 established that a function's
/// only `Return` can sit inside an `If`, and such a function still returns a
/// value to read. A function with no value-returning `Return` at all is a
/// different shape (it returns nothing, and reading its result is a separate
/// question), so it is deliberately not collected here.
pub(crate) fn body_returns_a_value(body: &[Statement]) -> bool {
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

/// The position a call's result landed in, for the second line of the
/// diagnostic. Each one is a slot that carries no declared type of its own.
#[derive(Clone, Copy)]
pub(crate) enum UntypedPosition {
    Print,
    Interpolation,
    ListAppend,
    ListElement,
    MapValue,
    DynamicValue,
}

impl UntypedPosition {
    fn describe(self) -> &'static str {
        match self {
            UntypedPosition::Print => "a print writes whatever type it is told the value has",
            UntypedPosition::Interpolation => {
                "an interpolation renders whatever type it is told the value has"
            }
            UntypedPosition::ListAppend | UntypedPosition::ListElement => {
                "a list slot is tagged with the type proven at the write"
            }
            UntypedPosition::MapValue => "a map value is tagged with the type proven at the write",
            UntypedPosition::DynamicValue => {
                "a `value` carries a runtime tag, which is set from the type proven at the write"
            }
        }
    }
}

impl Analyzer {
    /// Record `name` as a function whose result has no type for a caller to
    /// read: it returns a value, and the definition declared no return type.
    /// Called from the signature pre-pass, so a call above the definition is
    /// judged the same as a call below it.
    pub(crate) fn record_untyped_result_function(
        &mut self,
        key: String,
        return_type: &Type,
        body: &[Statement],
    ) {
        if *return_type == Type::Void && body_returns_a_value(body) {
            self.untyped_result_functions.insert(key);
        }
    }

    /// The callee's name when `expr` reads the result of a call whose return
    /// type was never declared, and `None` for everything else - a declared
    /// return, a procedure, an imported function (its `.lib` records a
    /// declared return type or nothing at all, and there is no body here to
    /// tell the two apart), or an expression that is not a call.
    ///
    /// A bare or single-quoted name that resolves to a zero-argument function
    /// is a call too (plan 270 G4), so it is read the same way - but only
    /// when no variable of that name is in scope, since a variable shadows it.
    pub(crate) fn untyped_call_result(&self, expr: &Expr) -> Option<String> {
        let name = match expr {
            Expr::FunctionCall { name, .. } => name,
            Expr::Identifier(name) if !self.is_variable_available(name) => name,
            _ => return None,
        };
        if self.untyped_result_functions.contains(&self.func_key(name)) {
            Some(name.clone())
        } else {
            None
        }
    }

    /// Reject `expr` when it reads an undeclared return type into a slot that
    /// supplies no type of its own. Every rejection site is one call to this.
    pub(crate) fn reject_untyped_call_result(&mut self, expr: &Expr, position: UntypedPosition) {
        let Some(name) = self.untyped_call_result(expr) else {
            return;
        };
        let message = format!(
            "'{}' has no declared return type, so its result is read as a number here\n  \
             A call's result carries a type only where its definition declares one \
             (LANGUAGE.md \"Functions\"), and {} - so a text comes back as the address \
             of its bytes rather than as text.\n  \
             Declare it (`Return a text, \"hi\".`), or assign it to a declared variable \
             first (`a text called saved is '{}'.`) and read that.",
            name,
            position.describe(),
            name
        );
        let location = self.find_call_site_location(&name);
        match location {
            Some(loc) => self.push_error_with_hint_at(message, Some(loc), None),
            None => self.push_error(message, Some(&name)),
        }
    }

    /// The call, not the definition. `find_symbol_location` takes the first
    /// textual hit for the name, which for a function is always its own `To`
    /// line - so the caret would land on the definition the author is being
    /// told to change rather than on the read that is wrong. Excluding the
    /// definition line puts it back on the call.
    ///
    /// Two steps, because bug #46 taught `find_pattern_location` to refuse a
    /// match sitting inside a text literal unless the pattern asked for one
    /// (`{name`, `"name"`). That rule is right for an unknown variable, but a
    /// call CAN legitimately sit inside a literal - `"got {'opaque label'}"`
    /// is an interpolated call, and the quoted-name spelling puts a `'`
    /// between the `{` and the name, so no pattern of ours can ask for it.
    /// Rather than widen #46's rule, the interpolated case falls through to a
    /// plain scan that skips the definition line, which is the only thing the
    /// unfiltered `find_symbol_location` fallback gets wrong here.
    fn find_call_site_location(&self, name: &str) -> Option<SourceLocation> {
        let definition_line = self.function_definition_line(name);
        let patterns = [format!("'{}'", name), name.to_string()];
        self.find_pattern_location(name, &patterns, 0, definition_line, false, false)
            .or_else(|| self.find_interpolated_call_location(name, definition_line))
    }

    /// A plain first-hit scan for `name`, skipping `definition_line`. No
    /// region filtering: the caller has already tried the filtered search, so
    /// what is left is a call written inside a format string.
    fn find_interpolated_call_location(
        &self,
        name: &str,
        definition_line: Option<usize>,
    ) -> Option<SourceLocation> {
        let source = self.source_file.as_ref()?;
        for (index, line) in source.content.lines().enumerate() {
            let line_no = index + 1;
            if Some(line_no) == definition_line {
                continue;
            }
            if let Some(column) = line.find(name) {
                return Some(SourceLocation::new(&source.filename, line_no, column + 1, line));
            }
        }
        None
    }

    /// The line `name` is defined on: the first `To 'name'`/`To name` in the
    /// source. `None` when there is no source to scan (a unit test builds the
    /// AST directly), which just leaves the caret to the ordinary search.
    fn function_definition_line(&self, name: &str) -> Option<usize> {
        let source = self.source_file.as_ref()?;
        let quoted = format!("To '{}'", name);
        let bare = format!("To {}", name);
        source.content.lines().position(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with(&quoted)
                || (trimmed.starts_with(&bare)
                    && trimmed[bare.len()..]
                        .chars()
                        .next()
                        .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_'))
        }).map(|index| index + 1)
    }
}
