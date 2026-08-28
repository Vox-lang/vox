use std::iter::Peekable;
use std::str::Chars;

mod tokens;
pub use tokens::Token;
// Only `#[cfg(test)]` code consumes this re-export today (BUGS_FOUND
// #106's keyword-table tests), same as `string_is_keyword` itself.
#[allow(unused_imports)]
pub use tokens::RESERVED_ALIASES;
mod scan;
mod regions;
pub use regions::{classify_lines, SourceRegion};


#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub token: Token,
    pub line: usize,
    pub column: usize,
}

pub struct Lexer<'a> {
    input: Peekable<Chars<'a>>,
    line: usize,
    column: usize,
    /// The second half of a contraction. `isn't` means `is not` - one word
    /// but two tokens - so `read_word` returns the head and leaves the tail
    /// here for `tokenize` to push. `None` for every other word.
    pending: Option<Token>,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Lexer {
            input: input.chars().peekable(),
            line: 1,
            column: 1,
            pending: None,
        }
    }
    
    fn advance(&mut self) -> Option<char> {
        let ch = self.input.next();
        if let Some(c) = ch {
            if c == '\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
        }
        ch
    }
    
    fn peek(&mut self) -> Option<&char> {
        self.input.peek()
    }

}

#[cfg(test)]
mod tests;

