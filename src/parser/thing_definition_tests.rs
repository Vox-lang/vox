    //! Unit coverage for the thing registry (plan 310 §1).
    //!
    //! The integration test can only observe that a definition *parses* -
    //! nothing consumes the registry until declarations land - so the shape
    //! later tasks depend on (field order, field types, defaults, the
    //! manifest split, `Program.things`) is pinned here instead.

    use super::*;
    use crate::lexer::Lexer;

    fn parse_input(input: &str) -> Result<Program, Box<CompileError>> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        parser.parse()
    }

    fn parse_err(input: &str) -> String {
        parse_input(input)
            .err()
            .unwrap_or_else(|| panic!("expected {:?} to be rejected", input))
            .to_string()
    }

    fn only_thing(program: &Program) -> &ThingDef {
        assert_eq!(
            program.things.len(),
            1,
            "expected exactly one thing, got {:?}",
            program.things
        );
        &program.things[0]
    }

    /// Data fields land in definition order (which is layout order), with
    /// their declared type and their literal default.
    #[test]
    fn fields_keep_definition_order_types_and_defaults() {
        let program = parse_input(
            "A thing called point has\n  a number called x is 0,\n  a float called y.\n",
        )
        .expect("a definition should parse");

        let def = only_thing(&program);
        assert_eq!(def.name, "point");
        assert_eq!(def.line, 1);
        assert!(def.members.is_empty());

        let names: Vec<&str> = def.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["x", "y"]);
        assert_eq!(def.fields[0].field_type, Type::Integer);
        assert!(matches!(def.fields[0].default, Some(Expr::IntegerLit(0))));
        assert_eq!(def.fields[1].field_type, Type::Float);
        // No `is` clause: the field takes its type's zero value, which is
        // the layout's business, not a default expression.
        assert!(def.fields[1].default.is_none());
    }

    /// A manifest entry declares callable API, not storage: it must never
    /// reach `fields`, or every offset after it would be wrong.
    #[test]
    fn function_members_are_declared_without_taking_storage() {
        let program = parse_input(
            "A thing called point has\n  \
             a function called 'from polar',\n  \
             a number called x is 0.\n",
        )
        .expect("a manifest entry should parse");

        let def = only_thing(&program);
        assert_eq!(def.members, vec!["from polar".to_string()]);
        assert_eq!(def.fields.len(), 1);
        assert_eq!(def.fields[0].name, "x");
    }

    /// A field may name a thing defined earlier, to any depth (plan 310 §6).
    #[test]
    fn a_field_may_name_an_earlier_thing() {
        let program = parse_input(
            "A thing called point has\n  a number called x is 0.\n\n\
             A thing called segment has\n  a point called start,\n  a point called end.\n",
        )
        .expect("a nested thing field should parse");

        assert_eq!(program.things.len(), 2);
        let segment = &program.things[1];
        assert_eq!(segment.name, "segment");
        assert_eq!(
            segment.fields[0].field_type,
            Type::Thing("point".to_string())
        );
        assert_eq!(
            segment.fields[1].field_type,
            Type::Thing("point".to_string())
        );
    }

    /// Definitions precede use, so a field naming a *later* thing is an
    /// unknown type rather than a forward reference the single pass would
    /// have to resolve.
    #[test]
    fn a_field_may_not_name_a_later_thing() {
        let err = parse_err(
            "A thing called segment has\n  a point called start.\n\n\
             A thing called point has\n  a number called x is 0.\n",
        );
        assert!(
            err.contains("Unknown field type 'point'"),
            "unexpected error: {}",
            err
        );
    }

    /// Both the thing's name and a field's name go through `parse_name`, so
    /// both accept a quoted multi-word identifier.
    #[test]
    fn names_may_be_quoted_and_multi_word() {
        let program = parse_input(
            "A thing called 'bounding box' has\n  a number called 'top left x' is 1.\n",
        )
        .expect("quoted multi-word names should parse");

        let def = only_thing(&program);
        assert_eq!(def.name, "bounding box");
        assert_eq!(def.fields[0].name, "top left x");
    }

    /// A definition declares a type and nothing else - it must not also
    /// introduce a variable, or the one identifier space would already be
    /// occupied by its own definition.
    #[test]
    fn a_definition_emits_only_a_thing_decl() {
        let program = parse_input("A thing called point has\n  a number called x is 0.\n")
            .expect("a definition should parse");
        assert_eq!(program.statements.len(), 1);
        assert!(matches!(program.statements[0], Statement::ThingDecl(_)));
    }

    /// `thing` is contextual, not reserved: outside `a thing called X has`
    /// it is an ordinary identifier, in every position a name can appear.
    #[test]
    fn thing_stays_an_ordinary_identifier() {
        let program = parse_input("a number called thing is 42.\nPrint thing.\nthing is 7.\n")
            .expect("`thing` should still be usable as a variable name");
        assert!(program.things.is_empty());
        assert!(matches!(
            &program.statements[0],
            Statement::VarDecl { name, .. } if name == "thing"
        ));
        assert!(matches!(
            &program.statements[2],
            Statement::Assignment { name, .. } if name == "thing"
        ));
    }

    /// The lookahead keys on `called`, not on the whole `... has` shape, so
    /// the reserved near-misses reach their own diagnostics.
    #[test]
    fn reserved_wrong_shapes_get_targeted_diagnostics() {
        assert!(parse_err("Create a thing called point.\n")
            .contains("A thing is defined, not created as a variable"));
        assert!(parse_err("A thing called point is 5.\n")
            .contains("'is' declares a variable; a thing definition uses 'has'"));
        assert!(parse_err("A thing called point has.\n").contains("at least one field"));
        assert!(parse_err("A thing called point.\n").contains("at least one field"));
    }
