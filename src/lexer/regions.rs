use super::Lexer;

/// What the lexer makes of a byte of source: code it turns into tokens,
/// the inside of a `( … )` comment it skips wholesale, or the inside of a
/// text literal it keeps as one token's content.
///
/// A diagnostic that locates a symbol by searching the raw source text
/// (`Analyzer::find_pattern_location`) needs this distinction. A name
/// written in a comment is not a use of that name, and a caret that lands
/// on it sends the reader to a line where nothing is wrong
/// (docs/BUGS_FOUND.md #46).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SourceRegion {
    Code,
    Comment,
    Text,
}

/// Classify every byte of `content` the way `Lexer::tokenize` reads it:
/// one row per line of `content.lines()`, each row indexed by byte offset
/// within that line. A character that takes several bytes fills as many
/// entries, so an offset from `str::find` lands on the right one.
///
/// This mirrors the lexer rather than approximating it: comments nest and
/// span lines, a quote inside a comment opens nothing (`skip_comment`
/// counts parentheses and reads nothing else), a parenthesis inside a text
/// literal or a character literal opens nothing either, and an unclosed
/// comment or literal runs to end of file exactly as the lexer lets it.
pub fn classify_lines(content: &str) -> Vec<Vec<SourceRegion>> {
    let chars: Vec<(usize, char)> = content.char_indices().collect();
    let mut rows: Vec<Vec<SourceRegion>> = Vec::new();
    let mut row: Vec<SourceRegion> = Vec::new();
    let mut comment_depth = 0usize;
    let mut in_text = false;
    let mut index = 0usize;

    while index < chars.len() {
        let (_, ch) = chars[index];

        if ch == '\n' {
            rows.push(std::mem::take(&mut row));
            index += 1;
            continue;
        }

        if comment_depth > 0 {
            match ch {
                '(' => comment_depth += 1,
                ')' => comment_depth -= 1,
                _ => {}
            }
            mark(&mut row, SourceRegion::Comment, ch);
            index += 1;
            continue;
        }

        if in_text {
            // `read_string`: a backslash escapes whatever follows it
            // (a quote included), and an unescaped quote ends the literal.
            mark(&mut row, SourceRegion::Text, ch);
            index += 1;
            if ch == '\\' {
                if let Some(&(_, escaped)) = chars.get(index) {
                    if escaped != '\n' {
                        mark(&mut row, SourceRegion::Text, escaped);
                        index += 1;
                    }
                }
            } else if ch == '"' {
                in_text = false;
            }
            continue;
        }

        match ch {
            '(' => {
                comment_depth = 1;
                mark(&mut row, SourceRegion::Comment, ch);
                index += 1;
            }
            '"' => {
                in_text = true;
                mark(&mut row, SourceRegion::Text, ch);
                index += 1;
            }
            '\'' => index = skip_single_quoted(content, &chars, index, &mut row),
            _ => {
                mark(&mut row, SourceRegion::Code, ch);
                index += 1;
            }
        }
    }

    if !row.is_empty() {
        rows.push(row);
    }
    rows
}

fn mark(row: &mut Vec<SourceRegion>, region: SourceRegion, ch: char) {
    for _ in 0..ch.len_utf8() {
        row.push(region);
    }
}

/// Mirror the lexer's `'` dispatch: a character literal (`'A'`, `'\n'`), a
/// single-quoted identifier (`'my count'`), or a bare possessive
/// apostrophe. The lexer's own lookahead decides which, so this asks it
/// rather than guessing — and the answer matters beyond tidiness, because
/// a `(` inside `'…'` opens no comment: the lexer never offers it one.
/// A quoted identifier's content is a name, so it is classified as code;
/// a character literal's is not.
fn skip_single_quoted(
    content: &str,
    chars: &[(usize, char)],
    quote: usize,
    row: &mut Vec<SourceRegion>,
) -> usize {
    let after_quote = chars
        .get(quote + 1)
        .map(|&(offset, _)| offset)
        .unwrap_or(content.len());
    let probe = Lexer::new(&content[after_quote..]);
    let mut index = quote + 1;

    if probe.is_char_literal() {
        // `read_char_literal`: one character, or a backslash and the
        // character it escapes, then the closing quote.
        mark(row, SourceRegion::Text, '\'');
        if let Some(&(_, ch)) = chars.get(index) {
            mark(row, SourceRegion::Text, ch);
            index += 1;
            if ch == '\\' {
                if let Some(&(_, escaped)) = chars.get(index) {
                    mark(row, SourceRegion::Text, escaped);
                    index += 1;
                }
            }
        }
        if let Some(&(_, '\'')) = chars.get(index) {
            mark(row, SourceRegion::Text, '\'');
            index += 1;
        }
    } else if probe.is_single_quoted_identifier() {
        mark(row, SourceRegion::Code, '\'');
        while let Some(&(_, ch)) = chars.get(index) {
            if ch == '\n' {
                break;
            }
            mark(row, SourceRegion::Code, ch);
            index += 1;
            if ch == '\'' {
                break;
            }
        }
    } else {
        mark(row, SourceRegion::Code, '\'');
    }

    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Token;

    fn regions_of(content: &str) -> Vec<Vec<SourceRegion>> {
        classify_lines(content)
    }

    fn kind_at(content: &str, line: usize, column: usize) -> SourceRegion {
        regions_of(content)[line - 1][column - 1]
    }

    #[test]
    fn rows_line_up_with_str_lines() {
        for content in [
            "",
            "one",
            "one\n",
            "one\ntwo",
            "one\n\ntwo",
            "one\n\n",
            "one\r\ntwo\r\n",
        ] {
            let rows = regions_of(content);
            assert_eq!(
                rows.len(),
                content.lines().count(),
                "row count for {:?}",
                content
            );
        }
    }

    #[test]
    fn a_comment_is_a_comment_parentheses_and_all() {
        let content = "(mentions hello here)\nappend hello to items.\n";
        assert_eq!(kind_at(content, 1, 1), SourceRegion::Comment);
        assert_eq!(kind_at(content, 1, 11), SourceRegion::Comment);
        assert_eq!(kind_at(content, 1, 21), SourceRegion::Comment);
        assert_eq!(kind_at(content, 2, 8), SourceRegion::Code);
    }

    #[test]
    fn comments_nest_and_span_lines() {
        let content = "(outer (inner) still\nopen) code.\n";
        assert_eq!(kind_at(content, 1, 9), SourceRegion::Comment);
        assert_eq!(kind_at(content, 2, 1), SourceRegion::Comment);
        assert_eq!(kind_at(content, 2, 5), SourceRegion::Comment);
        assert_eq!(kind_at(content, 2, 7), SourceRegion::Code);
    }

    #[test]
    fn a_quote_inside_a_comment_opens_nothing() {
        let content = "(a \" quote)\ncode.\n";
        assert_eq!(kind_at(content, 2, 1), SourceRegion::Code);
    }

    #[test]
    fn a_parenthesis_inside_a_text_literal_opens_nothing() {
        let content = "Print \"a ( paren\".\ncode.\n";
        assert_eq!(kind_at(content, 1, 10), SourceRegion::Text);
        assert_eq!(kind_at(content, 1, 18), SourceRegion::Code);
        assert_eq!(kind_at(content, 2, 1), SourceRegion::Code);
    }

    #[test]
    fn an_escaped_quote_does_not_end_the_literal() {
        let content = "Print \"say \\\" more\". code.\n";
        let quoted = content.find("more").expect("literal content");
        assert_eq!(kind_at(content, 1, quoted + 1), SourceRegion::Text);
        let after = content.find("code").expect("code after");
        assert_eq!(kind_at(content, 1, after + 1), SourceRegion::Code);
    }

    #[test]
    fn a_quoted_identifier_is_code_and_swallows_its_parentheses() {
        let content = "a number called 'my (count)' is 1.\ncode.\n";
        let name = content.find("my (count)").expect("quoted name");
        assert_eq!(kind_at(content, 1, name + 1), SourceRegion::Code);
        assert_eq!(kind_at(content, 1, 33), SourceRegion::Code);
        assert_eq!(kind_at(content, 2, 1), SourceRegion::Code);
    }

    #[test]
    fn a_character_literal_holding_a_parenthesis_opens_no_comment() {
        let content = "a number called open is '('.\ncode.\n";
        assert_eq!(kind_at(content, 2, 1), SourceRegion::Code);
    }

    #[test]
    fn a_possessive_apostrophe_stays_code() {
        let content = "Print scores's count.\n";
        assert_eq!(kind_at(content, 1, 14), SourceRegion::Code);
        assert_eq!(kind_at(content, 1, 17), SourceRegion::Code);
    }

    #[test]
    fn an_unclosed_comment_runs_to_end_of_file() {
        let content = "(unclosed\nhello\n";
        assert_eq!(kind_at(content, 2, 1), SourceRegion::Comment);
    }

    /// The classifier is a second reading of the lexer's own comment and
    /// literal rules, so it is pinned against the lexer itself: every
    /// token the lexer emits must start on a byte the classifier calls
    /// code or a literal. If the two ever disagree about where a comment
    /// ends, a diagnostic caret starts lying again.
    #[test]
    fn no_token_the_lexer_emits_starts_inside_a_comment() {
        let content = concat!(
            "(a header (with nesting) that mentions hello)\n",
            "a list called items is [].\n",
            "a number called 'my (count)' is 1.\n",
            "a number called open is '('.\n",
            "Print \"a ( paren and a \\\" quote\".\n",
            "Print \"count is {my (count)}\". (trailing note)\n",
            "append hello to items.\n",
        );
        let rows = classify_lines(content);
        for info in Lexer::new(content).tokenize() {
            if matches!(
                info.token,
                Token::EOF | Token::Newline | Token::ParagraphBreak
            ) {
                continue;
            }
            let region = rows[info.line - 1].get(info.column - 1).copied();
            assert_ne!(
                region,
                Some(SourceRegion::Comment),
                "token {:?} at {}:{} starts inside what the classifier calls a comment",
                info.token,
                info.line,
                info.column
            );
        }
    }

    #[test]
    fn a_multi_byte_character_fills_its_own_bytes() {
        let content = "Print \"é\". hello.\n";
        let hello = content.find("hello").expect("code after");
        assert_eq!(kind_at(content, 1, hello + 1), SourceRegion::Code);
    }
}
