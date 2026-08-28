// BUGS_FOUND #103 — a thing field whose type is rejected used to ALSO fire
// the default-mismatch template ("is a text, but its default is a text" —
// both slots the same word, since `default_matches_field_type` has no arm
// for an unsupported type and always answers false). The garbled message
// preceded the real one. `tests/compile_fail/273_*` pins the surviving
// message's text and location via substring match, which cannot prove the
// garbled sibling is GONE; this test spawns the compiler and asserts the
// "but its default is" template is absent, so exactly one error survives.

use std::fs;
use std::process::{Command, Stdio};

fn work_dir(tag: &str) -> std::path::PathBuf {
    let work = std::env::temp_dir().join(format!("vox-bugs103-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");
    work
}

// `CompileError`'s `Display` wraps "error" and its trailing colon on
// opposite sides of a reset code (`{RED}error{RESET}: `), so the literal
// text "error:" never appears contiguously in real output - a plain
// substring count of it is silently always zero. Strip every ANSI escape
// (ESC '[' ... a letter) before counting or matching anything positional.
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

#[test]
fn rejected_field_type_reports_exactly_one_error() {
    let work = work_dir("single-error");
    let (ok, stderr) = compile_stderr(
        &work,
        "A thing called 'file report' has\n  \
           a text called filename is \"\",\n  \
           a number called lines is 0.\n",
    );

    assert!(!ok, "a thing with a text field must still be rejected");
    assert_eq!(
        stderr.matches("error:").count(),
        1,
        "expected exactly one error, got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("which a thing cannot hold yet"),
        "the surviving error must be the field-type rejection; got:\n{}",
        stderr
    );
    assert!(
        !stderr.contains("but its default is"),
        "the garbled default-mismatch template must not fire when the field's \
         type was already rejected; got:\n{}",
        stderr
    );

    fs::remove_dir_all(&work).ok();
}

#[test]
fn mismatched_default_on_a_supported_type_still_errors() {
    let work = work_dir("supported-mismatch");
    let (ok, stderr) = compile_stderr(
        &work,
        "A thing called 'file report' has\n  \
           a number called n is \"x\".\n",
    );

    assert!(!ok, "a mismatched default on a supported type must still be rejected");
    assert_eq!(
        stderr.matches("error:").count(),
        1,
        "expected exactly one error, got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("Field 'n' of thing 'file report' is a number, but its default is a text"),
        "expected the default-mismatch message; got:\n{}",
        stderr
    );

    fs::remove_dir_all(&work).ok();
}
