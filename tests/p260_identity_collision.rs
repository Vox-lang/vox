// Plan 260 (F1) — the duplicate-identity check must compare mangled identities.
//
// `mangle_library_symbol` sanitises every character outside `[A-Za-z0-9_]` to
// `_`, so two *different* library names (`a-b` and `a_b`) or two *different*
// version strings (`1.0` and `1_0`) fold to the same symbol prefix. The driver's
// duplicate-identity check used to compare the raw strings and so missed the
// clash, falling through to a raw NASM "label inconsistently redefined" error
// that named an internal `<stem>.asm` temp file. The check now compares what
// the identities become and rejects the collision with a diagnostic naming
// both files, both raw identities, and the colliding prefix.
//
// These drive the built `vox` binary so they share the toolchain the rest of
// the suite already requires; a missing toolchain fails the build loudly.

use std::fs;
use std::process::{Command, Stdio};

/// Render a library name as a canonical vox identifier: bare when it is
/// bare-legal (`[A-Za-z_][A-Za-z0-9_]*`), else single-quoted. A single
/// bare-legal character must stay bare — quoting it (`'x'`) would lex as a
/// one-character *character literal*, not an identifier (plan 270 §"The
/// rule" item 3).
fn vox_name(name: &str) -> String {
    let is_bare_legal = matches!(name.chars().next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if is_bare_legal {
        name.to_string()
    } else {
        format!("'{}'", name)
    }
}

/// One `<lib, version>` collision case: write the two sources, run the shared
/// build, and assert it fails with the vox diagnostic — never a NASM error.
fn assert_collision_rejected(name_a: &str, ver_a: &str, name_b: &str, ver_b: &str) {
    let work = std::env::temp_dir().join(format!(
        "vox-p260-id-{}-{}",
        std::process::id(),
        name_a.replace('-', "_")
    ));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");

    let src_a = format!(
        "Library {} version \"{}\".\n\nTo greet with a number called n.\n  Return a number, n add 1.\n",
        vox_name(name_a), ver_a
    );
    let src_b = format!(
        "Library {} version \"{}\".\n\nTo greet with a number called n.\n  Return a number, n add 2.\n",
        vox_name(name_b), ver_b
    );
    fs::write(work.join("a.vox"), src_a).expect("write a.vox");
    fs::write(work.join("b.vox"), src_b).expect("write b.vox");

    let vox = env!("CARGO_BIN_EXE_vox");
    let output = Command::new(vox)
        .arg(work.join("a.vox"))
        .arg(work.join("b.vox"))
        .arg("--shared")
        .arg("-o")
        .arg(work.join("lib.so"))
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(
        !output.status.success(),
        "expected the build to be rejected, but it succeeded; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);

    // The vox diagnostic must fire and must name both raw identities (so the
    // author sees why the distinct-looking names are the same to the linker).
    assert!(
        stderr.contains("Duplicate library identity"),
        "missing 'Duplicate library identity' diagnostic; stderr:\n{}",
        stderr
    );
    assert!(
        stderr.contains("mangle to the symbol prefix"),
        "missing the mangled-prefix explanation; stderr:\n{}",
        stderr
    );
    assert!(
        stderr.contains(name_a) && stderr.contains(name_b),
        "diagnostic must name both raw library identities '{}' and '{}'; stderr:\n{}",
        name_a,
        name_b,
        stderr
    );

    // And it must NOT be the raw NASM error the old code fell through to.
    assert!(
        !stderr.contains("NASM assembly failed"),
        "fell through to a raw NASM error instead of the vox diagnostic; stderr:\n{}",
        stderr
    );
    assert!(
        !stderr.contains("inconsistently redefined"),
        "fell through to a NASM label-redefinition error; stderr:\n{}",
        stderr
    );

    let _ = fs::remove_dir_all(&work);
}

// Library names collide after sanitisation: `a-b` and `a_b` both mangle to
// `a_b`.
#[test]
fn colliding_library_names_rejected_with_diagnostic() {
    assert_collision_rejected("a-b", "1.0", "a_b", "1.0");
}

// Version strings collide after sanitisation: `1.0` and `1_0` both mangle to
// `1_0` under the same library name.
#[test]
fn colliding_versions_rejected_with_diagnostic() {
    assert_collision_rejected("x", "1.0", "x", "1_0");
}

// The exact-duplicate case (the same identity twice) keeps the original
// diagnostic's shape — widening the trigger, not rewriting the message.
#[test]
fn exact_duplicate_keeps_original_message_shape() {
    let work = std::env::temp_dir().join(format!("vox-p260-dup-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");

    let src = "Library x version \"1.0\".\n\nTo f with a number called n.\n  Return a number, n add 1.\n";
    fs::write(work.join("one.vox"), src).expect("write one.vox");
    fs::write(work.join("two.vox"), src).expect("write two.vox");

    let vox = env!("CARGO_BIN_EXE_vox");
    let output = Command::new(vox)
        .arg(work.join("one.vox"))
        .arg(work.join("two.vox"))
        .arg("--shared")
        .arg("-o")
        .arg(work.join("lib.so"))
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(!output.status.success(), "expected rejection");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The original message named a single Library/version both files declare.
    assert!(
        stderr.contains("both declare Library x version \"1.0\""),
        "exact-duplicate case lost the original message shape; stderr:\n{}",
        stderr
    );

    let _ = fs::remove_dir_all(&work);
}

// Control: two identities that stay distinct after mangling still build.
// Confirms the wider trigger did not make the check reject valid pairs.
#[test]
fn distinct_identities_still_build() {
    let work = std::env::temp_dir().join(format!("vox-p260-ok-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");

    fs::write(
        work.join("a.vox"),
        "Library alpha version \"1.0\".\n\nTo f.\n  Return 1.\n",
    )
    .expect("write a.vox");
    fs::write(
        work.join("b.vox"),
        "Library beta version \"1.0\".\n\nTo g.\n  Return 2.\n",
    )
    .expect("write b.vox");

    let vox = env!("CARGO_BIN_EXE_vox");
    let output = Command::new(vox)
        .arg(work.join("a.vox"))
        .arg(work.join("b.vox"))
        .arg("--shared")
        .arg("-o")
        .arg(work.join("lib.so"))
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(
        output.status.success(),
        "distinct identities should build; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(work.join("lib.so").exists(), "lib.so was not produced");

    let _ = fs::remove_dir_all(&work);
}