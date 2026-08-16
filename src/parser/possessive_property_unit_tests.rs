    use super::*;
    use crate::lexer::Lexer;

    fn parse_input(input: &str) -> Result<Program, Box<CompileError>> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        parser.parse()
    }

    /// `the <quoted name>'s elapsed seconds` - a quoted (multi-word)
    /// identifier's possessive followed by `elapsed`/`duration` plus a unit
    /// word. Before this fix the `the X's Y` parse path returned right after
    /// the property token, leaving `seconds` unconsumed: the statement ended
    /// early and the top-level loop then failed trying to parse `seconds` as
    /// its own statement.
    #[test]
    fn the_quoted_possessive_elapsed_seconds_parses() {
        let input = "Print the 'job timer''s elapsed seconds.";
        let result = parse_input(input).expect("elapsed seconds after 'the ...'s' should parse");
        assert_eq!(result.statements.len(), 1);
        match &result.statements[0] {
            Statement::Print {
                value: Expr::DurationCast { value, unit },
                ..
            } => {
                assert!(matches!(
                    value.as_ref(),
                    Expr::PropertyAccess { object, property: ObjectProperty::Elapsed }
                    if object == "job timer"
                ));
                assert!(matches!(unit, ast::TimeUnit::Seconds));
            }
            other => panic!("Expected Print of a DurationCast, got {:?}", other),
        }
    }

    /// The `duration in seconds` phrasing (with the optional `in`) must keep
    /// working through the same `the X's Y` path.
    #[test]
    fn the_quoted_possessive_duration_in_seconds_parses() {
        let input = "Print the 'job timer''s duration in seconds.";
        let result = parse_input(input).expect("duration in seconds after 'the ...'s' should parse");
        match &result.statements[0] {
            Statement::Print {
                value: Expr::DurationCast { value, unit },
                ..
            } => {
                assert!(matches!(
                    value.as_ref(),
                    Expr::PropertyAccess { property: ObjectProperty::Duration, .. }
                ));
                assert!(matches!(unit, ast::TimeUnit::Seconds));
            }
            other => panic!("Expected Print of a DurationCast, got {:?}", other),
        }
    }

    /// A single-word property after the same `the X's Y` possessive form
    /// (no unit suffix) must be unaffected by the fix.
    #[test]
    fn the_quoted_possessive_single_word_property_still_parses() {
        let input = "Print the 'job timer''s 'start time'.";
        let result = parse_input(input).expect("single-word property should still parse");
        match &result.statements[0] {
            Statement::Print {
                value: Expr::PropertyAccess { object, property: ObjectProperty::StartTime },
                ..
            } => {
                assert_eq!(object, "job timer");
            }
            other => panic!("Expected Print of a PropertyAccess, got {:?}", other),
        }
    }
