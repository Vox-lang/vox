//! A number as Vox source writes it (LANGUAGE.md "Literals"), read in one
//! place: by the lexer for a literal in the source, and by the analyzer for
//! a text literal cast to a number, which is a number exactly when the whole
//! text could have been written as a number literal (LANGUAGE.md "Casting
//! Rules").
//!
//! A number literal is decimal digits with an optional fractional part
//! (`42`, `4.8`), or a whole number after a `0x`, `0b` or `0o` prefix
//! (`0x345A`, `0b101`, `0o234`). A leading zero means nothing: `0234` is
//! 234. The sign is not part of the literal: source writes `-` before it,
//! and a cast reads one `-` before it.

use std::iter::Peekable;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NumberLiteral {
    /// A whole number, as its magnitude, or `None` when the magnitude does
    /// not fit in 64 bits.
    Whole(Option<u64>),
    /// A decimal with a fractional part, and the magnitude of its whole
    /// part (`None` when that does not fit in 64 bits).
    Fraction { value: f64, whole: Option<u64> },
    /// `0x`, `0b` or `0o` with no digit of its base after it.
    BarePrefix,
}

pub(crate) struct ReadNumber {
    pub(crate) literal: NumberLiteral,
    /// Exactly the characters read, a prefix included.
    pub(crate) spelling: String,
}

/// The base a `0x`, `0b` or `0o` prefix names, from the letter after the 0.
fn prefix_base(letter: char) -> Option<u32> {
    match letter {
        'x' | 'X' => Some(16),
        'b' | 'B' => Some(2),
        'o' | 'O' => Some(8),
        _ => None,
    }
}

/// Reads the number literal that opens with the digit `first`, taking from
/// `rest` every character that belongs to it and leaving the rest there.
pub(crate) fn read_number_literal<I>(first: char, rest: &mut Peekable<I>) -> ReadNumber
where
    I: Iterator<Item = char> + Clone,
{
    let mut spelling = String::from(first);
    let take_digits = |rest: &mut Peekable<I>, spelling: &mut String, base: u32, magnitude: Option<u64>| {
        let mut magnitude = magnitude;
        let mut digits = 0;
        while let Some(digit) = rest.peek().and_then(|ch| ch.to_digit(base)) {
            magnitude = magnitude
                .and_then(|m| m.checked_mul(base as u64))
                .and_then(|m| m.checked_add(digit as u64));
            spelling.push(rest.next().unwrap_or_default());
            digits += 1;
        }
        (magnitude, digits)
    };

    if first == '0' {
        if let Some(base) = rest.peek().copied().and_then(prefix_base) {
            spelling.push(rest.next().unwrap_or_default());
            let (magnitude, digits) = take_digits(rest, &mut spelling, base, Some(0));
            let literal = if digits == 0 {
                NumberLiteral::BarePrefix
            } else {
                NumberLiteral::Whole(magnitude)
            };
            return ReadNumber { literal, spelling };
        }
    }

    let first_digit = first.to_digit(10).map(u64::from);
    let (whole, _) = take_digits(rest, &mut spelling, 10, first_digit);

    // A '.' is a decimal point only with a digit after it; otherwise it
    // ends the sentence.
    let mut ahead = rest.clone();
    let point_then_digit =
        ahead.next() == Some('.') && ahead.next().is_some_and(|ch| ch.is_ascii_digit());
    if !point_then_digit {
        return ReadNumber { literal: NumberLiteral::Whole(whole), spelling };
    }
    spelling.push(rest.next().unwrap_or_default());
    take_digits(rest, &mut spelling, 10, Some(0));
    // A decimal too large for a float reads as infinity here (BUGS_FOUND #22
    // records the hole).
    let value = spelling.parse().unwrap_or(0.0);
    ReadNumber { literal: NumberLiteral::Fraction { value, whole }, spelling }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> (NumberLiteral, String, String) {
        let mut chars = text.chars();
        let first = chars.next().expect("a digit");
        let mut rest = chars.peekable();
        let read = read_number_literal(first, &mut rest);
        (read.literal, read.spelling, rest.collect())
    }

    #[test]
    fn decimals_hex_binary_and_octal_are_read_to_their_last_digit() {
        assert_eq!(read("0234"), (NumberLiteral::Whole(Some(234)), "0234".into(), "".into()));
        assert_eq!(read("0x345A."), (NumberLiteral::Whole(Some(0x345A)), "0x345A".into(), ".".into()));
        assert_eq!(read("0b101"), (NumberLiteral::Whole(Some(5)), "0b101".into(), "".into()));
        assert_eq!(read("0o234"), (NumberLiteral::Whole(Some(156)), "0o234".into(), "".into()));
        assert_eq!(read("0o8"), (NumberLiteral::BarePrefix, "0o".into(), "8".into()));
        assert_eq!(read("0b2"), (NumberLiteral::BarePrefix, "0b".into(), "2".into()));
        assert_eq!(read("12 apples").2, " apples");
        assert_eq!(read("1e5").2, "e5");
    }

    #[test]
    fn a_point_is_a_decimal_point_only_with_a_digit_after_it() {
        assert_eq!(
            read("4.8"),
            (NumberLiteral::Fraction { value: 4.8, whole: Some(4) }, "4.8".into(), "".into())
        );
        assert_eq!(read("3."), (NumberLiteral::Whole(Some(3)), "3".into(), ".".into()));
        assert_eq!(read("1.2.3").2, ".3");
    }

    #[test]
    fn a_magnitude_past_64_bits_is_kept_as_too_large() {
        assert_eq!(read("18446744073709551615").0, NumberLiteral::Whole(Some(u64::MAX)));
        assert_eq!(read("18446744073709551616").0, NumberLiteral::Whole(None));
        assert_eq!(read("0x10000000000000000").0, NumberLiteral::Whole(None));
    }
}
