    use super::*;
    use crate::lexer::Lexer;

    fn parse_input(input: &str) -> Result<Program, Box<CompileError>> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        parser.parse()
    }

    #[test]
    fn test_buffer_with_string_initializer() {
        let input = r#"a buffer called byte_buf is "Hello"."#;
        let result = parse_input(input);
        assert!(result.is_ok());
        let program = result.unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::VarDecl { name, var_type, value } => {
                assert_eq!(name, "byte_buf");
                assert_eq!(var_type, &Some(Type::Buffer));
                assert!(matches!(value, Some(Expr::StringLit(_))));
            }
            _ => panic!("Expected VarDecl for buffer with initializer"),
        }
    }

    #[test]
    fn test_buffer_with_size_clause() {
        let input = r#"a buffer called log is 2048 bytes."#;
        let result = parse_input(input);
        assert!(result.is_ok());
        let program = result.unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::BufferDecl { name, size } => {
                assert_eq!(name, "log");
                assert!(matches!(size, Expr::IntegerLit(2048)));
            }
            _ => panic!("Expected BufferDecl for buffer with size"),
        }
    }

    #[test]
    fn test_buffer_with_size_in_size_suffix() {
        let input = r#"a buffer called buf is 1024 bytes in size."#;
        let result = parse_input(input);
        assert!(result.is_ok());
        let program = result.unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::BufferDecl { name, size } => {
                assert_eq!(name, "buf");
                assert!(matches!(size, Expr::IntegerLit(1024)));
            }
            _ => panic!("Expected BufferDecl for buffer with size in size"),
        }
    }

    #[test]
    fn test_buffer_non_numeric_size_error() {
        let input = r#"a buffer called bad is "Hello" bytes."#;
        let result = parse_input(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("numeric literal"));
    }

    #[test]
    fn test_buffer_negative_size_error() {
        let input = r#"a buffer called bad is -100 bytes."#;
        let result = parse_input(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("positive integer"));
    }

    #[test]
    fn test_buffer_zero_size_error() {
        let input = r#"a buffer called bad is 0 bytes."#;
        let result = parse_input(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("positive integer"));
    }

    #[test]
    fn test_buffer_excessive_size_error() {
        let input = r#"a buffer called huge is 9999999999999 bytes."#;
        let result = parse_input(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_buffer_with_variable_size() {
        let input = r#"a buffer called dynamic is config_size bytes."#;
        let result = parse_input(input);
        assert!(result.is_ok());
        let program = result.unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::BufferDecl { name, size } => {
                assert_eq!(name, "dynamic");
                assert!(matches!(size, Expr::Identifier(_)));
            }
            _ => panic!("Expected BufferDecl for buffer with variable size"),
        }
    }

    #[test]
    fn test_buffer_with_numeric_initializer() {
        // Without "bytes" keyword, this should be an initializer, not a size
        let input = r#"a buffer called data is 42."#;
        let result = parse_input(input);
        assert!(result.is_ok());
        let program = result.unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::VarDecl { name, var_type, value } => {
                assert_eq!(name, "data");
                assert_eq!(var_type, &Some(Type::Buffer));
                assert!(matches!(value, Some(Expr::IntegerLit(42))));
            }
            _ => panic!("Expected VarDecl for buffer with numeric initializer"),
        }
    }

    #[test]
    fn test_buffer_without_initializer_warning() {
        let input = r#"a buffer called empty_buf."#;
        let result = parse_input(input);
        assert!(result.is_ok());
        let program = result.unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::BufferDecl { name, size } => {
                assert_eq!(name, "empty_buf");
                assert!(matches!(size, Expr::IntegerLit(0)));
            }
            _ => panic!("Expected BufferDecl for uninitialized buffer"),
        }
        // Note: Warning should be emitted to stderr during parsing
    }
