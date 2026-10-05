// docs/BUGS_FOUND.md #146: everything `vox` builds says its stack is not
// executable.
//
// An object assembled by NASM has no `.note.GNU-stack` section unless the
// source declares one, and `ld` reads its absence as "this object may need an
// executable stack". The output then carries no GNU_STACK program header, so a
// C host that links a Vox `.so` runs with an executable stack, and glibc 2.43
// refuses to `dlopen` the library at all ("cannot enable executable stack as
// shared object requires"). These tests build a real library and a real
// executable with the compiler binary and check both the headers and a C host.
//
// `readelf` ships with binutils, which `vox` itself requires to link; if it is
// missing anyway, the header test says so and skips. `gcc` is the C toolchain
// the suite's C-interop test already requires, so the `dlopen` test treats it
// the same way and fails loudly without it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const LIBRARY: &str = "Library 'stack check' version \"1.0\".\n\n\
                       To 'add two' with a number called x.\n  \
                       Return a number, x add 2.\n";

const PROGRAM: &str = "Print \"hello\".\n";

fn work_dir(tag: &str) -> PathBuf {
    let work = std::env::temp_dir().join(format!("vox-146-{}-{}", tag, std::process::id()));
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

/// The GNU_STACK line of `readelf -lW`, or None when the header is missing.
/// Returns Err when readelf itself cannot be run.
fn gnu_stack_line(file: &Path) -> Result<Option<String>, String> {
    let output = Command::new("readelf")
        .arg("-lW")
        .arg(file)
        .output()
        .map_err(|e| e.to_string())?;
    assert!(output.status.success(), "readelf -lW {} failed", file.display());
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.trim_start().starts_with("GNU_STACK"))
        .map(|line| line.to_string()))
}

#[test]
fn a_library_and_an_executable_both_carry_a_stack_header_that_is_read_write_only() {
    let work = work_dir("headers");
    vox_build(&work, LIBRARY, "stack_check.vox", &["--shared"], "libstackcheck.so");
    vox_build(&work, PROGRAM, "hello.vox", &[], "hello");

    for built in ["libstackcheck.so", "hello"] {
        let line = match gnu_stack_line(&work.join(built)) {
            Ok(line) => line,
            Err(why) => {
                eprintln!("skipped: readelf is not available ({})", why);
                fs::remove_dir_all(&work).ok();
                return;
            }
        };
        let line = line.unwrap_or_else(|| panic!("{} has no GNU_STACK header", built));
        // The flags column is the second-to-last field: `RW` here, `RWE` for an
        // executable stack.
        let fields: Vec<&str> = line.split_whitespace().collect();
        let flags = fields[fields.len() - 2];
        assert_eq!(flags, "RW", "{} asks for stack flags {}: {}", built, flags, line);
    }
    fs::remove_dir_all(&work).ok();
}

#[test]
fn a_c_host_can_dlopen_a_vox_library_and_call_it() {
    let work = work_dir("dlopen");
    vox_build(&work, LIBRARY, "stack_check.vox", &["--shared"], "libstackcheck.so");

    let host = "#include <dlfcn.h>\n\
                #include <stdio.h>\n\
                int main(int argc, char **argv) {\n\
                    (void)argc;\n\
                    void *library = dlopen(argv[1], RTLD_NOW);\n\
                    if (!library) { printf(\"dlopen failed: %s\\n\", dlerror()); return 1; }\n\
                    long (*add_two)(long) = (long (*)(long))dlsym(library, \"stack_check_1_0_add_two\");\n\
                    if (!add_two) { printf(\"dlsym failed: %s\\n\", dlerror()); return 2; }\n\
                    printf(\"%ld\\n\", add_two(40));\n\
                    return dlclose(library);\n\
                }\n";
    fs::write(work.join("host.c"), host).expect("write host.c");
    let compiled = run(Command::new("gcc")
        .args(["-Wall", "-Wextra", "-Werror", "-std=c11", "host.c", "-ldl", "-o", "host"])
        .current_dir(&work));
    assert!(
        compiled.status.success(),
        "gcc build of the host failed; stderr:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let ran = run(Command::new(work.join("host")).arg(work.join("libstackcheck.so")));
    assert_eq!(String::from_utf8_lossy(&ran.stdout), "42\n");
    assert!(ran.status.success(), "host exited {:?}", ran.status);
    fs::remove_dir_all(&work).ok();
}
