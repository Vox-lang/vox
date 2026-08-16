    use super::*;
    use crate::lexer::Lexer;

    fn parse_input(input: &str) -> Result<Program, Box<CompileError>> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        parser.parse()
    }

    #[test]
    fn test_parse_copy_statement() {
        let input = r#"copy source to destination."#;
        let result = parse_input(input).expect("copy statement should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::BufferCopy { source, destination } => {
                assert!(matches!(source, Expr::Identifier(s) if s == "source"));
                assert_eq!(destination, "destination");
            }
            other => panic!("Expected BufferCopy, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_the_buffer_assignment_format_string() {
        let input = r#"
            a buffer called out is "".
            the buffer out is "line {n:06}".
        "#;
        let result = parse_input(input).expect("the buffer assignment should parse");
        assert_eq!(result.statements.len(), 2);
        match &result.statements[1] {
            Statement::Assignment { name, value } => {
                assert_eq!(name, "out");
                assert!(matches!(value, Expr::FormatString { .. }));
            }
            other => panic!("Expected Assignment, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_copy_statement_with_optional_articles() {
        let input = r#"copy the source to the destination."#;
        let result = parse_input(input).expect("copy statement with articles should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::BufferCopy { source, destination } => {
                assert!(matches!(source, Expr::Identifier(s) if s == "source"));
                assert_eq!(destination, "destination");
            }
            other => panic!("Expected BufferCopy, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_copy_format_string_source() {
        let input = r#"copy "line {n:06}" to destination."#;
        let result = parse_input(input).expect("copy format string should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::BufferCopy { source, destination } => {
                assert!(matches!(source, Expr::FormatString { .. }));
                assert_eq!(destination, "destination");
            }
            other => panic!("Expected BufferCopy, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_clear_statement() {
        let input = r#"clear destination."#;
        let result = parse_input(input).expect("clear statement should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::BufferClear { name } => {
                assert_eq!(name, "destination");
            }
            other => panic!("Expected BufferClear, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_clear_statement_with_optional_article() {
        let input = r#"clear the destination."#;
        let result = parse_input(input).expect("clear statement with article should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::BufferClear { name } => {
                assert_eq!(name, "destination");
            }
            other => panic!("Expected BufferClear, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_append_to_quoted_name() {
        let input = r#"append "hello" to 'staged output'."#;
        let result = parse_input(input).expect("append to quoted destination should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::ListAppend { list, value } => {
                assert_eq!(list, "staged output");
                assert!(matches!(value, Expr::StringLit(s) if s == "hello"));
            }
            other => panic!("Expected ListAppend, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_copy_to_quoted_destination() {
        let input = r#"copy source to 'staged output'."#;
        let result = parse_input(input).expect("copy to quoted destination should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::BufferCopy { source, destination } => {
                assert!(matches!(source, Expr::Identifier(s) if s == "source"));
                assert_eq!(destination, "staged output");
            }
            other => panic!("Expected BufferCopy, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_clear_quoted_name() {
        let input = r#"clear 'staged output'."#;
        let result = parse_input(input).expect("clear quoted destination should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::BufferClear { name } => {
                assert_eq!(name, "staged output");
            }
            other => panic!("Expected BufferClear, got {:?}", other),
        }
    }
