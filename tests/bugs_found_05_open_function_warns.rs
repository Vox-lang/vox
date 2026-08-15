// BUGS_FOUND #5 — a function definition whose body runs to end of file
// (no closing blank line) silently absorbs every following top-level
// statement into the body. The function is then never called, so the
// program does nothing (exit 0, no output) with no diagnostic.
//
// The behaviour is NOT changed: a blank line is the only thing that
// closes a function body (LANGUAGE.md "The termination rule" rule 2),
// so the absorbed program still compiles to a do-nothing binary. What
// changed is that the compiler now WARNS the author, pointing at the
// function definition, instead of staying silent. This test locks in
// both halves: the warning is emitted (and names the function), the
// program still compiles (exit 0), and the binary still produces no
// output (the damage is diagnosed, not "fixed" — fixing it would break
// the language's termination rule).
//
// Two guards on the warning are also locked in here:
//   * a `Library <name> version "..."` file never triggers it — a library
//     legitimately consists only of function definitions with no
//     top-level entry, even when compiled *without* `--shared` (the
//     `examples/` compile check does exactly that);
//   * the message never claims statements were "absorbed" — the parser
//     cannot tell a function that is simply last in the file (its body
//     is the whole trailing text) from one that swallowed top-level
//     entry code, so the message states only the structural fact and
//     gives the blank-line fix as conditional advice.

use std::fs;
use std::process::{Command, Stdio};

fn work_dir(tag: &str) -> std::path::PathBuf {
    let work = std::env::temp_dir().join(format!("vox-bugs05-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");
    work
}

// The minimal damage repro: `ping` absorbs `Print "after"` and is never
// called, so nothing runs.
const DAMAGE_SRC: &str = "To ping.\n  Print \"pong\".\nPrint \"after\".\n";

#[test]
fn open_function_at_eof_warns_and_compiles_to_nothing() {
    let work = work_dir("damage");
    let src_path = work.join("prog.vox");
    fs::write(&src_path, DAMAGE_SRC).expect("write prog.vox");
    let bin = work.join("prog");

    let compile = Command::new(env!("CARGO_BIN_EXE_vox"))
        .arg(&src_path)
        .arg("-o")
        .arg(&bin)
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    // The warning is non-fatal: the program still compiles (exit 0).
    assert!(
        compile.status.success(),
        "a function open at EOF must still compile (warning, not error); stderr:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        stderr.contains("warning"),
        "expected a warning on stderr; got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("still open at end of file"),
        "warning must say the function is still open at end of file; got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("'ping'"),
        "warning must name the offending function 'ping'; got:\n{}",
        stderr
    );

    // The behaviour is unchanged: the absorbed program runs and produces
    // no output (ping is never called, "after" was swallowed into the body).
    let run = Command::new(&bin)
        .stdin(Stdio::null())
        .output()
        .expect("run compiled binary");
    assert!(
        run.status.success(),
        "do-nothing program should exit cleanly"
    );
    assert!(
        run.stdout.is_empty(),
        "absorbed program must produce no output; got stdout:\n{}",
        String::from_utf8_lossy(&run.stdout)
    );

    fs::remove_dir_all(&work).ok();
}

#[test]
fn function_ending_in_return_at_eof_does_not_warn() {
    // A function that legitimately ends in a `Return` at EOF (no trailing
    // blank line) is a proper function, not an absorption: the Return
    // closes the body. It must NOT trigger the warning.
    let work = work_dir("return");
    let src_path = work.join("prog.vox");
    fs::write(
        &src_path,
        "To 'give it'.\n  a number called x is 1.\n  Return a number, x.\n",
    )
    .expect("write prog.vox");
    let bin = work.join("prog");

    let compile = Command::new(env!("CARGO_BIN_EXE_vox"))
        .arg(&src_path)
        .arg("-o")
        .arg(&bin)
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(
        compile.status.success(),
        "Return-ended function must compile; stderr:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        !stderr.contains("still open at end of file"),
        "a function ending in Return at EOF must not warn; got:\n{}",
        stderr
    );

    fs::remove_dir_all(&work).ok();
}

#[test]
fn shared_library_open_function_at_eof_does_not_warn() {
    // A `--shared` library file legitimately ends mid-body at EOF (its
    // last function has no trailing blank line). The warning is suppressed
    // in shared mode — it only fires for an executable program.
    let work = work_dir("shared");
    let src_path = work.join("lib.vox");
    fs::write(
        &src_path,
        "Library m version \"1.0\".\n\nTo greet.\n  Print \"hi\".\n",
    )
    .expect("write lib.vox");
    let so = work.join("libm.so");

    let compile = Command::new(env!("CARGO_BIN_EXE_vox"))
        .arg(&src_path)
        .arg("--shared")
        .arg("-o")
        .arg(&so)
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(
        compile.status.success(),
        "shared lib must build; stderr:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        !stderr.contains("still open at end of file"),
        "a --shared library ending in a function at EOF must not warn; got:\n{}",
        stderr
    );

    fs::remove_dir_all(&work).ok();
}

#[test]
fn library_file_compiled_as_executable_does_not_warn() {
    // A `Library <name> version "..."` file legitimately consists only of
    // function definitions with no top-level entry, so its last function
    // body routinely runs to EOF with no closing blank line. The warning
    // must be suppressed for it even when it is compiled *without*
    // `--shared` — the `examples/` compile check in `test.sh` does exactly
    // that. (The `--shared` path is covered by the test above; this one
    // guards the non-shared, declare-`Library` path.)
    let work = work_dir("libexec");
    let src_path = work.join("lib.vox");
    fs::write(
        &src_path,
        "Library m version \"1.0\".\n\nTo greet.\n  Print \"hi\".\n",
    )
    .expect("write lib.vox");
    let bin = work.join("lib");

    let compile = Command::new(env!("CARGO_BIN_EXE_vox"))
        .arg(&src_path)
        .arg("-o")
        .arg(&bin)
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(
        compile.status.success(),
        "library file must compile without --shared; stderr:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        !stderr.contains("still open at end of file"),
        "a Library file compiled as an executable must not warn about its \
         last function ending at EOF; got:\n{}",
        stderr
    );

    fs::remove_dir_all(&work).ok();
}

#[test]
fn last_function_at_eof_makes_no_absorption_claim() {
    // A function that is simply the last thing in the file — its body is
    // the whole trailing text, nothing was swallowed — is structurally
    // indistinguishable in the parser from a function that absorbed
    // top-level entry code (both: body runs to EOF, no closing blank
    // line). The warning may still fire, but its message must NOT assert
    // that statements were "absorbed", because for this shape none were.
    // It must state the structural fact and offer the blank-line fix only
    // as conditional advice.
    let work = work_dir("barelast");
    let src_path = work.join("prog.vox");
    fs::write(&src_path, "To greet.\n  Print \"hi\".\n").expect("write prog.vox");
    let bin = work.join("prog");

    let compile = Command::new(env!("CARGO_BIN_EXE_vox"))
        .arg(&src_path)
        .arg("-o")
        .arg(&bin)
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(
        compile.status.success(),
        "bare last-function file must compile (warning, not error); stderr:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        !stderr.contains("absorb"),
        "a function that is simply last in the file must not be told its \
         statements were absorbed; got:\n{}",
        stderr
    );
    // The blank-line fix must still be offered (as conditional advice),
    // and the function must still be named.
    assert!(
        stderr.contains("blank line"),
        "the warning must still offer the blank-line fix; got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("'greet'"),
        "the warning must still name the function; got:\n{}",
        stderr
    );

    fs::remove_dir_all(&work).ok();
}