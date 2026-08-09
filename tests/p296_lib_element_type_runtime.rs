// Plan 296 — genuine end-to-end runtime verification for list element
// typing across the `.lib` boundary.
//
// The codegen-level matrix tests (`plan_296_list_element_type_matrix_*` in
// `src/codegen/mod.rs`) check the `.lib`'s declared/emitted TYPE and TEXT
// only — they never compile a real consumer, link it, and run the binary.
// That gap is exactly how the returned-list-LITERAL shape shipped broken:
// the `.lib` correctly said `returning a list of text`, but the consumer
// still printed raw pointers, because a bare zero-argument call in
// expression position (`a list called got is 'tokens'.`, no `of`/`with`
// connector) parses as `Expr::Identifier`, not `Expr::FunctionCall`, and
// the first cut of the consumer-side element-type propagation only
// recognized the latter shape. These tests compile a real library `.so` +
// `.lib`, compile a SEPARATE consumer program against it, run the
// resulting binary, and assert on real stdout — metadata assertions alone
// already proved insufficient to catch this.

use std::fs;
use std::process::{Command, Stdio};

fn work_dir(tag: &str) -> std::path::PathBuf {
    let work = std::env::temp_dir().join(format!("vox-p296-rt-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");
    work
}

fn run(cmd: &mut Command) -> std::process::Output {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn process")
}

/// Build `lib_source` as a `--shared` library in `work`. The `.so`/`.lib`
/// pair is always named `liblibrary.{so,lib}`; the `Library '<name>'
/// version` INSIDE the source is what a `see` statement actually matches
/// against, so callers are free to vary that per case.
fn build_library(work: &std::path::Path, lib_source: &str) {
    fs::write(work.join("lib.vox"), lib_source).expect("write lib.vox");
    let vox = env!("CARGO_BIN_EXE_vox");
    let output = run(Command::new(vox)
        .arg(work.join("lib.vox"))
        .arg("--shared")
        .arg("-o")
        .arg(work.join("liblibrary.so"))
        .current_dir(work));
    assert!(
        output.status.success(),
        "library build failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        work.join("liblibrary.lib").exists(),
        "expected liblibrary.lib to be emitted beside liblibrary.so"
    );
}

/// Compile `consumer_source` (which `see`s the `.lib` built above) and run
/// the resulting binary, returning its stdout.
fn build_and_run_consumer(work: &std::path::Path, consumer_source: &str) -> String {
    fs::write(work.join("consumer.vox"), consumer_source).expect("write consumer.vox");
    let vox = env!("CARGO_BIN_EXE_vox");
    let bin = work.join("consumer");
    let output = run(Command::new(vox)
        .arg(work.join("consumer.vox"))
        .arg("-o")
        .arg(&bin)
        .current_dir(work));
    assert!(
        output.status.success(),
        "consumer compile failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let run_output = run(&mut Command::new(&bin));
    assert!(
        run_output.status.success(),
        "consumer run failed; stderr:\n{}",
        String::from_utf8_lossy(&run_output.stderr)
    );
    String::from_utf8_lossy(&run_output.stdout).to_string()
}

#[test]
fn returned_list_built_via_append_prints_real_elements() {
    // Case A from the owner's review: a library-local list is built with
    // Append (a parameter forwarded in, plus a literal) and returned by
    // name via an explicit `of` call. This shape already worked before
    // this fix; pinned here so it can't silently regress.
    let work = work_dir("append-return");
    build_library(
        &work,
        "Library appendkit version \"1.0\".\n\n\
         To 'collect it' with a text called s.\n  \
         a list called out is [].\n  \
         Append s to out.\n  \
         Append \"extra\" to out.\n  \
         Return a list, out.\n",
    );
    let stdout = build_and_run_consumer(
        &work,
        "see appendkit version \"1.0\" from \"./liblibrary.lib\".\n\n\
         a list called got is 'collect it' of \"hello\".\n\
         Print \"count={got's length}\".\n\
         For each t from got, print \"got=[{t}]\".\n",
    );
    assert_eq!(stdout, "count=2\ngot=[hello]\ngot=[extra]\n");
    fs::remove_dir_all(&work).ok();
}

#[test]
fn returned_list_literal_via_zero_arg_call_prints_real_elements() {
    // Case B from the owner's review — the shape that shipped broken. The
    // returned list is a literal, and the consumer calls the zero-argument
    // function with no `of`/`with` connector: `a list called got is
    // 'tokens'.`. That parses as `Expr::Identifier`, not
    // `Expr::FunctionCall` (plan 270 G4's zero-arg-call ambiguity), which
    // the first cut of the return-side element-type propagation didn't
    // account for.
    let work = work_dir("literal-return");
    build_library(
        &work,
        "Library litkit version \"1.0\".\n\n\
         To tokens.\n  Return a list, [\"alpha\", \"beta\", \"gamma\"].\n",
    );
    let stdout = build_and_run_consumer(
        &work,
        "see litkit version \"1.0\" from \"./liblibrary.lib\".\n\n\
         a list called got is 'tokens'.\n\
         Print \"count={got's length}\".\n\
         For each t from got, print \"got=[{t}]\".\n",
    );
    assert_eq!(stdout, "count=3\ngot=[alpha]\ngot=[beta]\ngot=[gamma]\n");
    fs::remove_dir_all(&work).ok();
}

#[test]
fn list_parameter_out_arg_prints_real_elements() {
    // The plan's own verified repro (the parameter/out-arg shape), as a
    // genuine runtime check alongside the two return-shape tests above —
    // closing the same "metadata-only test gives false confidence" gap for
    // every shape this plan touches, not just the one that broke.
    let work = work_dir("param-outarg");
    build_library(
        &work,
        "Library paramkit version \"1.0\".\n\n\
         To 'split into' with a text called s and a list called out.\n  \
         Append s to out.\n  \
         Append \"second\" to out.\n",
    );
    let stdout = build_and_run_consumer(
        &work,
        "see paramkit version \"1.0\" from \"./liblibrary.lib\".\n\n\
         a list called toks is [].\n\
         'split into' with \"hello\" and toks.\n\
         Print \"count={toks's length}\".\n\
         For each t from toks, print \"tok=[{t}]\".\n",
    );
    assert_eq!(stdout, "count=2\ntok=[hello]\ntok=[second]\n");
    fs::remove_dir_all(&work).ok();
}
