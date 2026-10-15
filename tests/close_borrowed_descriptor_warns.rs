// A handle opened with a numeric `at` borrows that descriptor (LANGUAGE.md
// "Opening Files"), and `Close` on it closes the descriptor itself
// (LANGUAGE.md "Closing Files"). That is the right thing to do when the
// program is done with the descriptor, so it stays legal; the compiler
// warns at the Close so that closing standard output or standard error by
// accident is always seen.
//
// These tests pin both halves: the warning (non-fatal, naming the handle,
// the descriptor, and the Close's own line), and the unchanged behaviour of
// the compiled program. They also pin where it stays quiet: a handle opened
// by a path, and a file parameter, whose descriptor the compiler cannot
// know.

use std::fs;
use std::process::{Command, Output, Stdio};

fn work_dir(tag: &str) -> std::path::PathBuf {
    let work = std::env::temp_dir().join(format!("vox-borrowed-close-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");
    work
}

/// Compile `source` as prog.vox in a fresh directory; returns the compile
/// output and the directory, which holds the binary `prog` on success.
fn compile(tag: &str, source: &str) -> (Output, std::path::PathBuf) {
    let work = work_dir(tag);
    let src_path = work.join("prog.vox");
    fs::write(&src_path, source).expect("write prog.vox");
    let compile = Command::new(env!("CARGO_BIN_EXE_vox"))
        .arg(&src_path)
        .arg("-o")
        .arg(work.join("prog"))
        .current_dir(&work)
        .env("VOX_CORE_PATH", concat!(env!("CARGO_MANIFEST_DIR"), "/coreasm"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");
    assert!(
        compile.status.success(),
        "the program must still compile (a warning, not an error); stderr:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    (compile, work)
}

#[test]
fn closing_standard_input_warns_and_the_program_runs_as_written() {
    let (compile, work) = compile(
        "stdin",
        "Open a file for reading called keyboard at 0.\nClose keyboard.\nPrint \"still running\".\n",
    );
    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        stderr.contains("warning")
            && stderr.contains(
                "closing 'keyboard' closes borrowed descriptor 0 (standard input) for the rest of the program"
            ),
        "expected the borrowed-descriptor warning naming 'keyboard' and descriptor 0; got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("prog.vox:2:7"),
        "the warning must point at the Close, line 2; got:\n{}",
        stderr
    );

    let run = Command::new(work.join("prog")).stdin(Stdio::null()).output().expect("run prog");
    assert!(run.status.success(), "the program must exit cleanly");
    assert_eq!(String::from_utf8_lossy(&run.stdout), "still running\n");
    fs::remove_dir_all(&work).ok();
}

#[test]
fn closing_standard_output_closes_it_for_the_rest_of_the_program() {
    let (compile, work) = compile(
        "stdout",
        "Open a file for writing called screen at 1.\nWrite \"before\\n\" to screen.\nclose the screen.\nPrint \"after\".\n",
    );
    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        stderr.contains("closing 'screen' closes borrowed descriptor 1 (standard output) for the rest of the program")
            && stderr.contains("prog.vox:3:11"),
        "expected the warning for 'screen' at the Close on line 3; got:\n{}",
        stderr
    );

    // The Close really closes descriptor 1: the Print after it writes nothing.
    let run = Command::new(work.join("prog")).stdin(Stdio::null()).output().expect("run prog");
    assert!(run.status.success(), "the program must exit cleanly");
    assert_eq!(String::from_utf8_lossy(&run.stdout), "before\n");
    fs::remove_dir_all(&work).ok();
}

#[test]
fn a_descriptor_held_in_a_number_is_named_by_its_handle() {
    let (compile, work) = compile(
        "variable",
        "a number called channel is 2.\nOpen a file for writing called errors at channel.\nClose errors.\n",
    );
    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        stderr.contains("closing 'errors' closes the borrowed descriptor it was opened at for the rest of the program"),
        "expected the warning for a descriptor held in a number; got:\n{}",
        stderr
    );
    fs::remove_dir_all(&work).ok();
}

#[test]
fn a_handle_borrowed_on_only_one_path_says_so() {
    let (compile, work) = compile(
        "branch",
        "A text called 'output file' is \"\".\n\
         If 'output file' is empty then,\n  Open a file for writing called output at 1.\n\
         Otherwise,\n  Open a file for writing called output at 'output file'.\n\n\
         Close output.\n",
    );
    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        stderr.contains(
            "closing 'output' closes borrowed descriptor 1 (standard output) for the rest of the program \
             when 'output' was opened at that number"
        ),
        "expected the conditional warning for 'output'; got:\n{}",
        stderr
    );
    fs::remove_dir_all(&work).ok();
}

#[test]
fn closing_a_path_handle_or_a_file_parameter_does_not_warn() {
    let (compile, work) = compile(
        "quiet",
        "Open a file for reading called source at 0.\n\
         Open a file for writing called log at \"log.txt\".\nClose log.\n\n\
         To 'finish' with a file called source.\n    Close source.\n\n\
         'finish' with source.\n\
         Open a file for writing called screen at 1.\n\
         Open a file for writing called screen at \"screen.txt\".\nClose screen.\n",
    );
    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        !stderr.contains("borrowed descriptor"),
        "a path handle, a reopened handle and a file parameter must not warn; got:\n{}",
        stderr
    );
    fs::remove_dir_all(&work).ok();
}
