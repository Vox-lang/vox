// Track A1+A2+A3 — global store-back single-source refactor.
//
// The six Vox fixtures in tests/300_*.vox exercise the new
// `emit_store_back_after_realloc` helper: a global container is mutated
// inside a function (where `self.variables` is reset and the variable is
// resolved through its global BSS mirror), and a second function observes the
// updated pointer/contents. Each fixture has a matching .expected file and is
// also run by ./test.sh, so the same assertions cover both the Rust test
// harness and the shell driver.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

const FIXTURES: &[&str] = &[
    "300_global_byte_grow_in_function",
    "301_global_map_grow_in_function",
    "302_global_list_grow_in_function",
    "303_global_bufread_in_function",
    "304_global_bufreadline_in_function",
    "305_global_bufresize_in_function",
];

fn run_vox_fixture(name: &str) -> String {
    let vox = env!("CARGO_BIN_EXE_vox");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("tests").join(format!("{}.vox", name));
    let expected = root.join("tests").join(format!("{}.expected", name));

    assert!(src.exists(), "missing fixture: {}", src.display());
    assert!(expected.exists(), "missing expected: {}", expected.display());

    let work = std::env::temp_dir().join(format!("vox-p302-{}-{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");

    let bin = work.join("prog");
    let compile = Command::new(vox)
        .env("VOX_CORE_PATH", concat!(env!("CARGO_MANIFEST_DIR"), "/coreasm"))
        .arg(&src)
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
        "{}: compile failed:\n{}",
        name,
        String::from_utf8_lossy(&compile.stderr)
    );

    let run = Command::new(&bin)
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run compiled binary");
    assert!(
        run.status.success(),
        "{}: program exited with {:?}\nstderr:\n{}",
        name,
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );

    let output = String::from_utf8_lossy(&run.stdout).into_owned();
    let expected_text = fs::read_to_string(&expected).expect("read expected file");
    assert_eq!(
        output, expected_text,
        "{}: output mismatch",
        name
    );

    let _ = fs::remove_dir_all(&work);
    output
}

#[test]
fn global_byte_grow_in_function() {
    run_vox_fixture(FIXTURES[0]);
}

#[test]
fn global_map_grow_in_function() {
    run_vox_fixture(FIXTURES[1]);
}

#[test]
fn global_list_grow_in_function() {
    run_vox_fixture(FIXTURES[2]);
}

#[test]
fn global_bufread_in_function() {
    run_vox_fixture(FIXTURES[3]);
}

#[test]
fn global_bufreadline_in_function() {
    run_vox_fixture(FIXTURES[4]);
}

#[test]
fn global_bufresize_in_function() {
    run_vox_fixture(FIXTURES[5]);
}
