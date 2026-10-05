// LANGUAGE.md, Type Immutability: a type-lock error's help line shows "the
// exact cast that would fix it, when there is one (a text that is not a
// number has none)". The compile_fail corpus matches each `.err` line as a
// substring, so it can show that a help line is there but never that the
// cast half of it is gone. These tests compile the corpus programs and
// assert both halves: a text that is not a number gets no "convert it
// explicitly" suggestion and no `... as a number` for its literal, and the
// same program with a numeric text still gets the cast.
//
// Each test reads its program straight from tests/compile_fail and swaps
// one literal, so the program under test stays the one the corpus pins.

use std::fs;
use std::process::{Command, Stdio};

fn work_dir(tag: &str) -> std::path::PathBuf {
    let work = std::env::temp_dir().join(format!("vox-no-cast-help-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");
    work
}

// The CLI colours its labels, so strip every ANSI escape (ESC '[' ... a
// letter) before matching any text.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn compile_stderr(work: &std::path::Path, source: &str) -> (bool, String) {
    let src_path = work.join("prog.vox");
    fs::write(&src_path, source).expect("write prog.vox");
    let bin = work.join("prog");

    let output = Command::new(env!("CARGO_BIN_EXE_vox"))
        .env("VOX_CORE_PATH", concat!(env!("CARGO_MANIFEST_DIR"), "/coreasm"))
        .arg(&src_path)
        .arg("-o")
        .arg(&bin)
        .current_dir(work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    (output.status.success(), strip_ansi(&String::from_utf8_lossy(&output.stderr)))
}

// The corpus program with its one `from` literal replaced by `to`.
fn with_literal(program: &str, from: &str, to: &str) -> String {
    assert_eq!(
        program.matches(from).count(),
        1,
        "expected {} exactly once in the program:\n{}",
        from,
        program
    );
    program.replacen(from, to, 1)
}

// `program` writes the text `word` into a variable of type `noun`, and
// `headline` is the error it must still get. The help line must offer no
// cast for `word`, and the same program with `numeric` in its place must
// offer exactly that cast.
fn check(tag: &str, program: &str, word: &str, numeric: &str, noun: &str, headline: &str) {
    let work = work_dir(tag);

    let (ok, stderr) = compile_stderr(&work, program);
    assert!(!ok, "writing {} into a {} must still be rejected", word, noun);
    assert!(
        stderr.contains(headline),
        "expected the type-lock error {:?}; got:\n{}",
        headline,
        stderr
    );
    assert!(
        !stderr.contains("convert it explicitly"),
        "{} is not a {}, so there is no cast to suggest; got:\n{}",
        word,
        noun,
        stderr
    );
    let cast = format!("{} as a {}", word, noun);
    assert!(
        !stderr.contains(&cast),
        "the help must not suggest `{}`; got:\n{}",
        cast,
        stderr
    );

    let (ok, stderr) = compile_stderr(&work, &with_literal(program, word, numeric));
    assert!(!ok, "writing {} into a {} must still be rejected", numeric, noun);
    let cast = format!("{} as a {}", numeric, noun);
    assert!(
        stderr.contains("convert it explicitly") && stderr.contains(&cast),
        "{} is a {}, so the help must suggest `{}`; got:\n{}",
        numeric,
        noun,
        cast,
        stderr
    );

    fs::remove_dir_all(&work).ok();
}

#[test]
fn text_that_is_not_a_number_declared_as_a_number_gets_no_cast_help() {
    check(
        "146",
        include_str!("compile_fail/146_text_into_number_declaration.vox"),
        "\"get five\"",
        "\"5\"",
        "number",
        "cannot initialise 'x', which is a number, with text",
    );
}

#[test]
fn text_that_is_not_a_number_declared_as_a_float_gets_no_cast_help() {
    check(
        "148",
        include_str!("compile_fail/148_text_into_float_declaration.vox"),
        "\"abc\"",
        "\"3.14\"",
        "float",
        "cannot initialise 'ratio', which is a float, with text",
    );
}

#[test]
fn text_that_is_not_a_number_created_as_a_number_gets_no_cast_help() {
    check(
        "154",
        include_str!("compile_fail/154_text_into_number_via_create_declaration.vox"),
        "\"five\"",
        "\"5\"",
        "number",
        "cannot initialise 'n', which is a number, with text",
    );
}

#[test]
fn text_that_is_not_a_number_assigned_to_a_number_gets_no_cast_help() {
    let program = include_str!("compile_fail/073_type_lock_caret_points_at_write_site.vox");
    check(
        "073",
        &with_literal(program, "\"12\"", "\"abc\""),
        "\"abc\"",
        "\"12\"",
        "number",
        "cannot assign text to 'n', which is a number",
    );
}

#[test]
fn text_that_is_not_a_number_set_on_an_untyped_number_gets_no_cast_help() {
    let program = include_str!("compile_fail/255_untyped_declaration_rewritten_with_another_type.vox");
    check(
        "255",
        &with_literal(program, "\"7\"", "\"text now\""),
        "\"text now\"",
        "\"7\"",
        "number",
        "cannot assign text to 'zoo', which is a number",
    );
}

#[test]
fn text_that_is_not_a_number_written_with_the_form_gets_no_cast_help() {
    let program = include_str!("compile_fail/256_set_declared_name_rewritten_by_the_form.vox");
    check(
        "256",
        &with_literal(program, "\"7\"", "\"text now\""),
        "\"text now\"",
        "\"7\"",
        "number",
        "cannot assign text to 'zoo', which is a number",
    );
}

#[test]
fn text_that_is_not_a_number_set_after_the_form_declares_gets_no_cast_help() {
    let program = include_str!("compile_fail/257_untyped_declaration_rewritten_by_set.vox");
    check(
        "257",
        &with_literal(program, "\"7\"", "\"text now\""),
        "\"text now\"",
        "\"7\"",
        "number",
        "cannot assign text to 'zoo', which is a number",
    );
}

#[test]
fn text_that_is_not_a_number_set_on_a_typed_number_gets_no_cast_help() {
    let program = include_str!("compile_fail/258_declared_name_rewritten_by_set.vox");
    check(
        "258",
        &with_literal(program, "\"7\"", "\"text now\""),
        "\"text now\"",
        "\"7\"",
        "number",
        "cannot assign text to 'zoo', which is a number",
    );
}
