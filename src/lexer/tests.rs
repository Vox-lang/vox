    use super::*;

    fn tokens_of(input: &str) -> Vec<Token> {
        let mut lexer = Lexer::new(input);
        lexer
            .tokenize()
            .into_iter()
            .map(|t| t.token)
            .filter(|t| *t != Token::EOF)
            .collect()
    }

    #[test]
    fn single_char_between_single_quotes_is_a_character_literal() {
        // Plan 270 §"The rule" item 3: exactly one character between single
        // quotes is a character literal, not a one-character identifier —
        // this is why single-character quoted identifiers do not exist.
        assert_eq!(tokens_of("'A'"), vec![Token::IntegerLiteral(65)]);
    }

    #[test]
    fn possessive_single_apostrophe_form_lexes_identifier_then_s() {
        // Plan 270 §5: `'name's` reads as the quoted identifier plus the
        // possessive marker, not `Unknown function: s`. `length` is the
        // reserved size/length property keyword (`Token::Size`), matching
        // the plan's own canonical example (`'total items's length`).
        assert_eq!(
            tokens_of("'my nums's length"),
            vec![
                Token::Identifier("my nums".to_string()),
                Token::Apostrophe,
                Token::Identifier("s".to_string()),
                Token::Size,
            ]
        );
    }

    #[test]
    fn possessive_doubled_apostrophe_form_lexes_identically() {
        // Plan 270 §5: `'name''s` is the pre-existing doubled-apostrophe
        // path and must produce the exact same token stream as the new
        // single-apostrophe possessive form, so the parser needs no new path.
        assert_eq!(
            tokens_of("'my nums''s length"),
            tokens_of("'my nums's length")
        );
    }

    #[test]
    fn underscore_prefix_is_preserved_in_identifier() {
        // Regression 1: `_str_eq` must lex as a single identifier with the
        // leading underscore intact, not as the bare name `str_eq`.
        assert_eq!(
            tokens_of("_str_eq"),
            vec![Token::Identifier("_str_eq".to_string())]
        );
        // Mid-word underscores continue to work.
        assert_eq!(
            tokens_of("my_helper"),
            vec![Token::Identifier("my_helper".to_string())]
        );
    }

