#[cfg(test)]
mod tests {
    use crate::analyzer::Analyzer;
    use crate::lexer::Lexer;
    use crate::parser::Parser;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn compile_to_error(vox_path: &Path) -> Result<(), String> {
        let source_name = vox_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown_case");
        let source = fs::read_to_string(vox_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", vox_path.display(), e));

        let mut lexer = Lexer::new(&source);
        let tokens = lexer.tokenize();

        let mut parser = Parser::new(tokens).with_source(source_name, &source);
        let mut program = match parser.parse() {
            Ok(p) => p,
            Err(err) => return Err(err.to_string()),
        };

        // A `.shared` sidecar marks a case that must be analyzed as a
        // `--shared` compile (top-level executable statements are rejected
        // only in that mode). The marker is a zero-byte file named
        // `<case>.shared` next to the `.vox`.
        let shared = vox_path.with_extension("shared").exists();
        let mut analyzer = Analyzer::new()
            .with_source(source_name, &source)
            .with_shared_mode(shared);
        analyzer.analyze(&mut program);

        if analyzer.errors.is_empty() {
            Ok(())
        } else {
            let joined = analyzer
                .errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            Err(joined)
        }
    }

    fn collect_cases(root: &Path) -> Vec<PathBuf> {
        let mut cases = Vec::new();
        let entries = fs::read_dir(root).expect("compile_fail directory should exist");

        for entry in entries {
            let entry = entry.expect("directory entry should be readable");
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("vox") {
                cases.push(path);
            }
        }

        cases.sort();
        cases
    }

    #[test]
    fn compile_fail_corpus_reports_errors() {
        let root = Path::new("tests/compile_fail");
        let cases = collect_cases(root);
        assert!(
            !cases.is_empty(),
            "compile_fail corpus is empty; add at least one failing case"
        );

        for vox_path in cases {
            let case_name = vox_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown_case");

            let err_path = vox_path.with_extension("err");
            let expected = fs::read_to_string(&err_path)
                .unwrap_or_else(|e| panic!("missing .err for {}: {}", case_name, e));
            let expected = expected.trim();
            assert!(
                !expected.is_empty(),
                ".err for {} must contain an expected error substring",
                case_name
            );

            match compile_to_error(&vox_path) {
                Ok(()) => panic!("{} unexpectedly compiled successfully", case_name),
                Err(actual) => {
                    assert!(
                        actual.contains(expected),
                        "{} failed with unexpected error.\nExpected substring: {:?}\nActual:\n{}",
                        case_name,
                        expected,
                        actual
                    );
                }
            }
        }
    }
}
