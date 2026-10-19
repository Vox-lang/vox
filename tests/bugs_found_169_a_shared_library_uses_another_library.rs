// docs/BUGS_FOUND.md #169: a library built with `--shared` can `see` another
// library's `.lib` and call it, as a program can.
//
// A call from one `.so` into another goes through the procedure linkage
// table: the callee lives in a different object, so the call has no fixed
// distance to it, and the link refused the direct form ("relocation
// R_X86_64_PC32 ... recompile with -fPIC"). These tests build a real inner
// library, an outer library that calls it, and a program that calls the
// outer one, and check the outer library needs the inner one and exports only
// its own function.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const INNER: &str = "Library 'inner' version \"0.1\".\n\n\
                     To 'inner answer'.\n  \
                     Return a number, 41.\n";

const OUTER: &str = "Library 'outer' version \"0.1\".\n\
                     see 'inner' version \"0.1\" from \"libinner.lib\".\n\n\
                     To 'outer answer'.\n  \
                     Return a number, 'inner answer' add 1.\n\n\
                     To 'outer greeting' with a text called name.\n  \
                     Print \"hello, {name}\".\n  \
                     Return a number, 'inner answer'.\n";

const PROGRAM: &str = "see 'outer' version \"0.1\" from \"libouter.lib\".\n\n\
                       Print 'outer answer'.\n\
                       a number called greeted is 'outer greeting' of \"inner\".\n\
                       Print greeted.\n";

fn work_dir(tag: &str) -> PathBuf {
    let work = std::env::temp_dir().join(format!("vox-169-{}-{}", tag, std::process::id()));
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

/// Compile `source` with the built compiler, passing `extra` flags, into `out`.
fn vox_build(work: &Path, source: &str, name: &str, extra: &[&str], out: &str) {
    fs::write(work.join(name), source).expect("write source");
    let output = run(Command::new(env!("CARGO_BIN_EXE_vox"))
        .arg(work.join(name))
        .args(extra)
        .arg("-o")
        .arg(work.join(out))
        .env("VOX_CORE_PATH", concat!(env!("CARGO_MANIFEST_DIR"), "/coreasm"))
        .current_dir(work));
    assert!(
        output.status.success(),
        "vox build of {} failed; stderr:\n{}",
        name,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_shared_library_calls_a_library_it_sees_and_a_program_calls_both() {
    let work = work_dir("chain");
    vox_build(&work, INNER, "inner.vox", &["--shared"], "libinner.so");
    vox_build(&work, OUTER, "outer.vox", &["--shared"], "libouter.so");
    vox_build(&work, PROGRAM, "program.vox", &[], "program");

    let ran = run(&mut Command::new(work.join("program")));
    assert!(ran.status.success(), "program exited {:?}", ran.status);
    assert_eq!(String::from_utf8_lossy(&ran.stdout), "42\nhello, inner\n41\n");
    fs::remove_dir_all(&work).ok();
}

#[test]
fn the_outer_library_needs_the_inner_one_and_exports_only_its_own_functions() {
    let work = work_dir("exports");
    vox_build(&work, INNER, "inner.vox", &["--shared"], "libinner.so");
    vox_build(&work, OUTER, "outer.vox", &["--shared"], "libouter.so");

    let dynamic = match Command::new("readelf").arg("-d").arg(work.join("libouter.so")).output() {
        Ok(output) => output,
        Err(why) => {
            eprintln!("skipped: readelf is not available ({})", why);
            fs::remove_dir_all(&work).ok();
            return;
        }
    };
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(
        dynamic.lines().any(|line| line.contains("(NEEDED)") && line.contains("[libinner.so]")),
        "libouter.so does not need libinner.so:\n{}",
        dynamic
    );

    let symbols = run(Command::new("nm").arg("-D").arg("--defined-only").arg(work.join("libouter.so")));
    let mut exported: Vec<String> = String::from_utf8_lossy(&symbols.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().last().map(str::to_string))
        .collect();
    exported.sort();
    assert_eq!(exported, ["outer_0_1_outer_answer", "outer_0_1_outer_greeting"]);
    fs::remove_dir_all(&work).ok();
}
