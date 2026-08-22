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
        // possessive marker, not `Unknown function: s`. `length` is a
        // contextual word (a synonym of `size` in the possessive dispatch
        // only), so it lexes as an ordinary identifier, matching the
        // plan's own canonical example (`'total items's length`).
        assert_eq!(
            tokens_of("'my nums's length"),
            vec![
                Token::Identifier("my nums".to_string()),
                Token::Apostrophe,
                Token::Identifier("s".to_string()),
                Token::Identifier("length".to_string()),
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


    #[test]
    fn isnt_lexes_as_is_then_not() {
        // BUGS_FOUND #84: `isn't` is a documented spelling of `not`
        // (LANGUAGE.md, Logical Operators) that `read_word` could never
        // build - it stopped dead at the apostrophe, so the keyword-table
        // entry was unreachable. It means `is not`, so it must lex as the
        // two tokens `parse_comparison` reads, not as a single `Not`:
        // `v1 not v2` does not parse and never did.
        assert_eq!(tokens_of("v1 isn't v2"), tokens_of("v1 is not v2"));
        assert_eq!(
            tokens_of("v1 isn't v2"),
            vec![
                Token::Identifier("v1".to_string()),
                Token::Is,
                Token::Not,
                Token::Identifier("v2".to_string()),
            ]
        );
    }

    #[test]
    fn arent_lexes_as_are_then_not() {
        // BUGS_FOUND #84: the other documented contraction, on the same
        // rule. `has_are_ahead` looks for `Token::Are`, so the multi-subject
        // comparison sees `aren't` exactly where it sees `are not`.
        assert_eq!(tokens_of("p aren't false"), tokens_of("p are not false"));
    }

    #[test]
    fn contractions_are_case_insensitive_like_every_other_keyword() {
        // BUGS_FOUND #84: the keyword table lowercases the word before
        // matching, and the contraction rule matches its stem and its `t`
        // the same way.
        assert_eq!(tokens_of("v1 ISN'T v2"), tokens_of("v1 isn't v2"));
        assert_eq!(tokens_of("p AREN'T false"), tokens_of("p aren't false"));
    }

    #[test]
    fn possessive_on_it_and_they_survives_the_contraction_rule() {
        // BUGS_FOUND #84: `it's` and `they're` sat in the keyword table as
        // spellings of `is` and `are`. Waking them would have swallowed the
        // possessive on a variable called `it` or `they` - `print it's
        // length.` prints a length - so they were removed instead. The
        // contraction rule must leave both apostrophes to the `'` arm.
        assert_eq!(
            tokens_of("it's length"),
            vec![
                Token::Identifier("it".to_string()),
                Token::Apostrophe,
                Token::Identifier("s".to_string()),
                Token::Identifier("length".to_string()),
            ]
        );
        assert_eq!(
            tokens_of("they's length"),
            vec![
                Token::Identifier("they".to_string()),
                Token::Apostrophe,
                Token::Identifier("s".to_string()),
                Token::Identifier("length".to_string()),
            ]
        );
    }

    #[test]
    fn a_contraction_stem_is_still_an_ordinary_name() {
        // BUGS_FOUND #84: the rule fires only on the whole contraction
        // followed by a character that cannot continue a word. `isn` and
        // `aren` stay ordinary names, possessive included, and a word that
        // merely starts like a contraction is left exactly as it was.
        assert_eq!(
            tokens_of("isn's length"),
            vec![
                Token::Identifier("isn".to_string()),
                Token::Apostrophe,
                Token::Identifier("s".to_string()),
                Token::Identifier("length".to_string()),
            ]
        );
        assert_eq!(
            tokens_of("aren"),
            vec![Token::Identifier("aren".to_string())]
        );
        // `isn'ts` is not the contraction, so nothing is consumed for it.
        assert_eq!(
            tokens_of("isn'ts"),
            vec![
                Token::Identifier("isn".to_string()),
                Token::Apostrophe,
                Token::Identifier("ts".to_string()),
            ]
        );
    }

    #[test]
    fn both_halves_of_a_contraction_report_its_own_column() {
        // BUGS_FOUND #84: one word, two tokens. A caret under either half
        // has to land on the word the author actually wrote, so both carry
        // the contraction's line and column.
        let mut lexer = Lexer::new("If v1 isn't v2");
        let tokens = lexer.tokenize();
        let is = tokens.iter().find(|t| t.token == Token::Is).unwrap();
        let not = tokens.iter().find(|t| t.token == Token::Not).unwrap();
        assert_eq!((is.line, is.column), (1, 7));
        assert_eq!((not.line, not.column), (1, 7));
    }
