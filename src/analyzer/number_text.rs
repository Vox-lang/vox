//! Which texts are numbers (LANGUAGE.md "Casting Rules"), for the cast of a
//! text literal that the compiler can judge before the program runs.
//!
//! A text is a number exactly when the whole text could be written as a
//! number literal in Vox source, with one `-` allowed before it. The literal
//! is read by the lexer's own reader (`read_number_literal`), so the two can
//! never disagree; the run-time reader (`_read_number_text` and
//! `_read_float_text` in coreasm) follows the same rule:
//!
//! - `as a number` takes the whole number, or the whole part of a decimal
//!   with a fractional part (the fraction is dropped, as a float cast to a
//!   number drops it), and it must fit in a number;
//! - `as a float` takes any number literal; a whole number must fit in a
//!   number, as it must in source;
//! - a radix cast (`as a hex number`, `as a base 7 number`) takes an
//!   optional `-`, then only digits of its base, after the base's own
//!   prefix when it has one (`0x` for 16, `0o` for 8, `0b` for 2).

use super::*;
use crate::lexer::number_literal::{read_number_literal, NumberLiteral};

/// The magnitude a number may have: one more for a negative number, whose
/// smallest value is -9223372036854775808.
fn fits_in_a_number(magnitude: Option<u64>, negative: bool) -> bool {
    let limit = if negative { 1u64 << 63 } else { i64::MAX as u64 };
    magnitude.is_some_and(|m| m <= limit)
}

/// Why `text` is not a number to a cast into `target` (a number or a float)
/// in `radix` (0 when the cast names no base), or `None` when it is one.
pub(crate) fn number_text_problem(text: &str, target: &Type, radix: u32) -> Option<&'static str> {
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    let negative = unsigned.len() != text.len();
    if radix != 0 && *target == Type::Integer {
        return radix_text_problem(unsigned, negative, radix);
    }
    let mut chars = unsigned.chars();
    let Some(first) = chars.next() else {
        return Some(if negative { "no digit follows its '-'" } else { "it is empty" });
    };
    if !first.is_ascii_digit() {
        return Some("it does not begin with a digit");
    }
    let mut rest = chars.peekable();
    let read = read_number_literal(first, &mut rest);
    if read.literal == NumberLiteral::BarePrefix {
        return Some("no digit of its base follows its prefix");
    }
    if rest.peek().is_some() {
        return Some("the text goes on after the number");
    }
    let whole = match read.literal {
        NumberLiteral::Whole(magnitude) => magnitude,
        NumberLiteral::Fraction { .. } if *target == Type::Float => return None,
        NumberLiteral::Fraction { whole, .. } => whole,
        NumberLiteral::BarePrefix => None,
    };
    (!fits_in_a_number(whole, negative)).then_some("it is too large for a number")
}

/// A radix cast: the digits of `radix`, after its own prefix if it has one.
fn radix_text_problem(unsigned: &str, negative: bool, radix: u32) -> Option<&'static str> {
    let own_prefix = match radix {
        16 => ["0x", "0X"].as_slice(),
        8 => ["0o", "0O"].as_slice(),
        2 => ["0b", "0B"].as_slice(),
        _ => [].as_slice(),
    };
    let digits = own_prefix
        .iter()
        .find_map(|prefix| unsigned.strip_prefix(prefix))
        .unwrap_or(unsigned);
    if digits.is_empty() {
        return Some("it has no digit of its base");
    }
    let mut magnitude = Some(0u64);
    for ch in digits.chars() {
        let Some(digit) = ch.to_digit(radix) else {
            return Some("it holds a character that is not a digit of its base");
        };
        magnitude = magnitude
            .and_then(|m| m.checked_mul(radix as u64))
            .and_then(|m| m.checked_add(digit as u64));
    }
    (!fits_in_a_number(magnitude, negative)).then_some("it is too large for a number")
}

impl Analyzer {
    /// The text a literal cast reads, when the value is a text literal rather
    /// than a quoted name that refers to a variable.
    fn literal_cast_text<'a>(&self, value: &'a Expr) -> Option<&'a str> {
        let Expr::StringLit(text) = value else {
            return None;
        };
        let names_a_variable = self.scalar_types.contains_key(text)
            || self.value_typed_names.contains(text.as_str())
            || self.named_value_type(text).is_some();
        (!names_a_variable).then_some(text.as_str())
    }

    /// Why `value as <target>` can never succeed, when `value` is a text
    /// literal the compiler can read for itself: the program would only
    /// raise the error flag every time it ran.
    pub(crate) fn literal_cast_problem(
        &self,
        value: &Expr,
        target: &Type,
        radix: u32,
    ) -> Option<&'static str> {
        let text = self.literal_cast_text(value)?;
        match target {
            Type::Integer | Type::Float => number_text_problem(text, target, radix),
            _ => None,
        }
    }

    /// `"hello" as a number.`: a compile error, because the text is known
    /// now and is not a number. A text known only at run time is read then,
    /// and a failure raises the error flag instead (codegen's cast marker).
    pub(crate) fn check_literal_cast(&mut self, value: &Expr, target: &Type, radix: u32) {
        let Some(problem) = self.literal_cast_problem(value, target, radix) else {
            return;
        };
        let Some(text) = self.literal_cast_text(value) else {
            return;
        };
        let target_phrase = match (target, radix) {
            (Type::Integer, 16) => "a hex number".to_string(),
            (Type::Integer, 8) => "an octal number".to_string(),
            (Type::Integer, 2) => "a binary number".to_string(),
            (Type::Integer, 0) => "a number".to_string(),
            (Type::Integer, base) => format!("a base {} number", base),
            _ => self.typed_phrase(target),
        };
        let shape = match (target, radix) {
            (Type::Integer, 16) => "a hex number is written as an optional '-' and hex digits, after an optional 0x, like \"ff\" or \"-0x1F\"".to_string(),
            (Type::Integer, 8) => "an octal number is written as an optional '-' and octal digits, after an optional 0o, like \"17\" or \"0o17\"".to_string(),
            (Type::Integer, 2) => "a binary number is written as an optional '-' and binary digits, after an optional 0b, like \"101\" or \"0b101\"".to_string(),
            (Type::Integer, base) if base != 0 => format!("a base {} number is written as an optional '-' and digits of base {}", base, base),
            _ => "a number is written as it would be in Vox source, after an optional '-': digits with an optional fractional part, like \"42\" or \"2.5\", or a whole number after 0x, 0b or 0o, like \"0x1F\"".to_string(),
        };
        let message = format!(
            "cannot cast \"{}\" to {}: {}\n  {}",
            text, target_phrase, problem, shape
        );
        let pattern = format!("\"{}\" as", text);
        let occurrence = *self.symbol_error_counts.get(&pattern).unwrap_or(&0);
        self.symbol_error_counts.insert(pattern.clone(), occurrence + 1);
        let mut err = CompileError::new(&message);
        if let Some(loc) = self.find_text_location(&pattern, occurrence) {
            err = err.with_location(loc);
        }
        self.errors.push(err);
    }

    /// The `occurrence`th place `pattern` is written in the source file.
    fn find_text_location(&self, pattern: &str, occurrence: usize) -> Option<SourceLocation> {
        let source = self.source_file.as_ref()?;
        source
            .content
            .lines()
            .enumerate()
            .flat_map(|(index, line)| {
                line.match_indices(pattern)
                    .map(move |(column, _)| (index, column, line))
            })
            .nth(occurrence)
            .map(|(index, column, line)| {
                SourceLocation::new(&source.filename, index + 1, column + 1, line)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;

    fn errors_for(input: &str) -> Vec<CompileError> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        let mut program = parser.parse().expect("input should parse");
        let mut analyzer = Analyzer::new().with_source("test.vox", input);
        analyzer.analyze(&mut program);
        analyzer.errors
    }

    /// Every line of every diagnostic, so a test can say what is NOT offered.
    fn everything_said(errors: &[CompileError]) -> String {
        errors
            .iter()
            .map(|e| {
                format!(
                    "{}\n{}\n{}",
                    e.message,
                    e.note_line.clone().unwrap_or_default(),
                    e.help_line.clone().unwrap_or_default()
                )
            })
            .collect()
    }

    #[test]
    fn no_diagnostic_suggests_casting_a_text_that_is_not_a_number() {
        for input in [
            "a number called n is 5.\nn is \"abc\".\n",
            "a number called n is \"get five\".\n",
            "a float called ratio is \"abc\".\n",
            "A thing called point has\n  a number called x is 0.\na point called origin.\nSet origin's x to \"hello\".\n",
        ] {
            let errors = errors_for(input);
            assert!(!errors.is_empty(), "expected a refusal for {:?}", input);
            let said = everything_said(&errors);
            assert!(
                !said.contains("\" as a"),
                "a cast that is itself refused was offered for {:?}:\n{}",
                input,
                said
            );
        }
    }

    #[test]
    fn a_diagnostic_still_suggests_casting_a_text_that_is_a_number() {
        let said = everything_said(&errors_for("a number called n is 5.\nn is \"42\".\n"));
        assert!(said.contains("n is \"42\" as a number."), "{}", said);
        let said = everything_said(&errors_for(
            "A thing called point has\n  a number called x is 0.\na point called origin.\nSet origin's x to \"42\".\n",
        ));
        assert!(said.contains("Set origin's x to \"42\" as a number."), "{}", said);
    }

    fn is_a_number(text: &str) -> bool {
        number_text_problem(text, &Type::Integer, 0).is_none()
    }

    fn is_a_float(text: &str) -> bool {
        number_text_problem(text, &Type::Float, 0).is_none()
    }

    fn is_a_number_in(text: &str, radix: u32) -> bool {
        number_text_problem(text, &Type::Integer, radix).is_none()
    }

    #[test]
    fn a_text_is_a_number_when_the_whole_text_is_a_number_literal() {
        for text in [
            "42", "-7", "0234", "007", "-0", "4.8", "-2.5", "-0x345A", "0o234", "0b101", "0X1f",
            "-9223372036854775808", "9223372036854775807", "9223372036854775807.9",
        ] {
            assert!(is_a_number(text), "{:?} should be a number", text);
            assert!(is_a_float(text), "{:?} should be a float", text);
        }
        for text in [
            "12 apples", "1.5x", "", "-", "0x", "0o8", "0b2", "--1", "1-", "7 ", " 7", "+7", "1e5",
            "3.", ".5", "1.2.3", "0x1.5", "hello",
        ] {
            assert!(!is_a_number(text), "{:?} should not be a number", text);
            assert!(!is_a_float(text), "{:?} should not be a float", text);
        }
    }

    #[test]
    fn a_whole_number_must_fit_and_a_fraction_only_its_whole_part_for_a_number() {
        assert!(!is_a_number("9223372036854775808"));
        assert!(!is_a_float("9223372036854775808"));
        assert!(!is_a_number("-9223372036854775809"));
        assert!(!is_a_number("0x8000000000000000"));
        assert!(is_a_number("-0x8000000000000000"));
        assert!(!is_a_number("99999999999999999999.5"));
        assert!(is_a_float("99999999999999999999.5"));
    }

    #[test]
    fn a_radix_cast_takes_only_digits_of_its_base_after_its_own_prefix() {
        assert!(is_a_number_in("ff", 16));
        assert!(is_a_number_in("FF", 16));
        assert!(is_a_number_in("0x1F", 16));
        assert!(is_a_number_in("-0x1F", 16));
        assert!(is_a_number_in("0b1", 16)); // b and 1 are hex digits
        assert!(is_a_number_in("0o17", 8));
        assert!(is_a_number_in("0b101", 2));
        assert!(is_a_number_in("z9a", 36));
        assert!(is_a_number_in("0234", 10));
        assert!(!is_a_number_in("0x1F", 10));
        assert!(!is_a_number_in("0x", 16));
        assert!(!is_a_number_in("12g5", 16));
        assert!(!is_a_number_in("zz", 16));
        assert!(!is_a_number_in("2", 2));
        assert!(!is_a_number_in("0o8", 8));
        assert!(!is_a_number_in("1.5", 16));
        assert!(!is_a_number_in("+1", 16));
        assert!(!is_a_number_in("", 7));
    }
}
