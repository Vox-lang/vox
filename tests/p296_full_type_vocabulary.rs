// Plan 296 — regression matrix: every expressible Vox type (`Type::Void`
// and `Type::Unknown` excluded by design — see
// docs/plans/296_lib_collection_types.md) must work as an ordinary
// function's PARAMETER type and its declared RETURN type, via both parsers
// that accept `Return a <type>,`: the inline path in `parse_function_def`
// (Return as the function's literal first statement) and Gate B's
// `parse_return` (any later statement). The two used to disagree — Gate B
// took only number/text/boolean while the inline path separately took
// file/value and the parameter path separately took buffer/list/map — this
// plan unified them onto one shared vocabulary table specifically so a
// future narrowing of any one of the three fails a test here instead of
// shipping silently.

use std::fs;
use std::process::{Command, Stdio};

fn work_dir(tag: &str) -> std::path::PathBuf {
    let work = std::env::temp_dir().join(format!("vox-p296-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");
    work
}

fn compile_ok(tag: &str, source: &str) {
    let work = work_dir(tag);
    fs::write(work.join("prog.vox"), source).expect("write prog.vox");
    let vox = env!("CARGO_BIN_EXE_vox");
    let bin = work.join("prog");
    let output = Command::new(vox)
        .arg(work.join("prog.vox"))
        .arg("-o")
        .arg(&bin)
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");
    assert!(
        output.status.success(),
        "case {}: compile should succeed; stderr:\n{}",
        tag,
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(&work).ok();
}

fn compile_err(tag: &str, source: &str) -> String {
    let work = work_dir(tag);
    fs::write(work.join("prog.vox"), source).expect("write prog.vox");
    let vox = env!("CARGO_BIN_EXE_vox");
    let bin = work.join("prog");
    let output = Command::new(vox)
        .arg(work.join("prog.vox"))
        .arg("-o")
        .arg(&bin)
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");
    assert!(
        !output.status.success(),
        "case {}: compile should fail, but it succeeded",
        tag
    );
    fs::remove_dir_all(&work).ok();
    String::from_utf8_lossy(&output.stderr).to_string()
}

const TYPES: &[&str] = &[
    "number", "float", "text", "boolean", "list", "map", "buffer", "file", "time", "timer", "value",
];

/// What a `Return a <type>,` case stands on: whatever must be declared
/// above the function, and the operand itself. The vocabulary under test is
/// the parser's, and the parser never looks at the operand - which is why a
/// bare `1` used to serve all eleven types. A buffer return is judged by
/// the analyzer as well (bug #53: a non-buffer source leaves an address the
/// caller reads as a buffer struct, and reading a text literal's characters
/// as a buffer header segfaults), so the buffer case stands on a real
/// buffer.
///
/// Bug #65 widened that from the buffer alone to every type the analyzer
/// can prove: a `Return a <type>,` whose operand is provably some other
/// type is now refused, because the caller reads the result as the declared
/// type and `Return a text, 1.` handed it the literal `1` to dereference.
/// So each of those types now stands on an operand of its own kind, exactly
/// as the buffer already did. `number`, `float`, `file`, `time`, `timer`
/// and `value` keep the bare `1` - a number and a float are one family
/// under the designer's ruling, and the rest are handles and the dynamic
/// type, all of which #65 deliberately leaves alone - so a narrowing on any
/// of them still fails here.
fn return_operand(ty: &str) -> (&'static str, &'static str) {
    match ty {
        "text" => ("", "\"ok\""),
        "boolean" => ("", "true"),
        "list" => ("a list called source is [1].\n\n", "source"),
        "map" => ("a map called source is {\"only\": 1}.\n\n", "source"),
        "buffer" => ("a buffer called source is \"ok\".\n\n", "source"),
        _ => ("", "1"),
    }
}

#[test]
fn return_inline_path_accepts_every_type() {
    // Return as the function's literal first (and only) statement.
    for ty in TYPES {
        let (prelude, operand) = return_operand(ty);
        let src = format!(
            "{}To 'give it'. Return a {}, {}.\n\nPrint \"ok\".\n",
            prelude, ty, operand
        );
        compile_ok(&format!("inline-{}", ty), &src);
    }
}

#[test]
fn return_gate_b_path_accepts_every_type() {
    // A preceding statement forces Gate B (`parse_return`) instead of the
    // inline first-statement path.
    for ty in TYPES {
        let (prelude, operand) = return_operand(ty);
        // The local `x` is what forces Gate B; what is returned is the
        // correctly-typed operand from `return_operand`, since bug #65
        // refuses a Return whose operand is provably the wrong type.
        let src = format!(
            "{}To 'give it'.\n  a number called x is 1.\n  Return a {}, {}.\n\nPrint \"ok\".\n",
            prelude, ty, operand
        );
        compile_ok(&format!("gateb-{}", ty), &src);
    }
}

#[test]
fn parameter_type_accepts_every_type() {
    for ty in TYPES {
        let src = format!(
            "To 'give it' with a {} called x. Return a number, 1.\n\nPrint \"ok\".\n",
            ty
        );
        compile_ok(&format!("param-{}", ty), &src);
    }
}

#[test]
fn return_still_rejects_a_nonexistent_type_on_both_paths() {
    // Void/Unknown stay unspellable (plan 296's judgment call), and a
    // flatly bogus noun stays an error — widening the accepted vocabulary
    // must not mean accepting anything.
    let inline_err = compile_err(
        "inline-bogus",
        "To 'give it'. Return a bogus_type, 1.\n\nPrint \"ok\".\n",
    );
    assert!(
        !inline_err.is_empty(),
        "inline path: a nonexistent type must still produce a diagnostic"
    );

    let gateb_err = compile_err(
        "gateb-bogus",
        "To 'give it'.\n  a number called x is 1.\n  Return a bogus_type, x.\n\nPrint \"ok\".\n",
    );
    assert!(
        !gateb_err.is_empty(),
        "Gate B path: a nonexistent type must still produce a diagnostic"
    );
}
