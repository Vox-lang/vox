// docs/BUGS_FOUND.md #174: when the system has no more memory to give, a Vox
// program stops with "Error: out of memory" on standard error and exit code 1.
// It never writes through a block it was not given, so it never segfaults.
//
// Every allocation path in the runtime is driven past a 10 MB address-space
// cap (`prlimit --as`): buffers, lists, maps, texts and format strings, at the
// top level and inside a function. `Resize` keeps its own contract (the error
// flag, the buffer as it was), which tests/320_realloc_failure.vox holds. Each program prints "started" first, so a
// program that fails to compile or to start cannot pass by accident. Core dumps
// are capped to one byte (`--core=1:1`), the setting a piped core pattern
// honours, so a regression crashes quietly. `prlimit` ships with util-linux; a
// box without it fails these tests loudly rather than skipping them.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// The cap each program runs under, in bytes of address space.
const ADDRESS_SPACE: &str = "--as=10000000";

fn work_dir(tag: &str) -> PathBuf {
    let work = std::env::temp_dir().join(format!("vox-174-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");
    work
}

/// Build `source`, run it under the cap, and check it stopped the way the
/// ruling says: "started" on standard output, the message on standard error,
/// exit code 1.
fn runs_out_of_memory(tag: &str, source: &str) {
    let work = work_dir(tag);
    let source_path = work.join(format!("{}.vox", tag));
    fs::write(&source_path, source).expect("write source");
    let program = work.join(tag);
    let built = Command::new(env!("CARGO_BIN_EXE_vox"))
        .arg(&source_path)
        .arg("-o")
        .arg(&program)
        .env("VOX_CORE_PATH", concat!(env!("CARGO_MANIFEST_DIR"), "/coreasm"))
        .current_dir(&work)
        .stdin(Stdio::null())
        .output()
        .expect("spawn vox");
    assert!(
        built.status.success(),
        "{}: vox build failed; stderr:\n{}",
        tag,
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = Command::new("prlimit")
        .arg(ADDRESS_SPACE)
        .arg("--core=1:1")
        .arg("--")
        .arg(&program)
        .current_dir(&work)
        .stdin(Stdio::null())
        .output()
        .expect("spawn prlimit (util-linux)");
    let stdout = String::from_utf8_lossy(&ran.stdout);
    let stderr = String::from_utf8_lossy(&ran.stderr);
    assert_eq!(stdout, "started\n", "{}: standard output", tag);
    assert_eq!(stderr, "Error: out of memory\n", "{}: standard error", tag);
    assert_eq!(ran.status.code(), Some(1), "{}: exit status {:?}", tag, ran.status);
    fs::remove_dir_all(&work).ok();
}

/// A growing buffer appended to at the top level.
#[test]
fn buffer_append_stops_with_out_of_memory() {
    runs_out_of_memory(
        "buffer_append",
        "a buffer called heap.
Print \"started\".
a number called rounds is 0.
While rounds is less than 200000,
    append \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\" to heap,
    increment rounds.
Print \"never reached\".
",
    );
}

/// A buffer parameter grown inside a function.
#[test]
fn buffer_in_function_stops_with_out_of_memory() {
    runs_out_of_memory(
        "buffer_in_function",
        "To 'fill the heap' with a buffer called heap.
    a number called rounds is 0.
    While rounds is less than 200000,
        append \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\" to heap,
        increment rounds.

a buffer called heap.
Print \"started\".
'fill the heap' of heap.
Print \"never reached\".
",
    );
}

/// A list growing at the top level.
#[test]
fn list_append_stops_with_out_of_memory() {
    runs_out_of_memory(
        "list_append",
        "a list called tally is [].
Print \"started\".
a number called rounds is 0.
While rounds is less than 10000000,
    append rounds to tally,
    increment rounds.
Print \"never reached\".
",
    );
}

/// A list parameter growing inside a function.
#[test]
fn list_in_function_stops_with_out_of_memory() {
    runs_out_of_memory(
        "list_in_function",
        "To 'count without end' with a list called tally.
    a number called rounds is 0.
    While rounds is less than 10000000,
        append rounds to tally,
        increment rounds.

a list called tally is [].
Print \"started\".
'count without end' of tally.
Print \"never reached\".
",
    );
}

/// A list copied into another list, over and over.
#[test]
fn list_copies_stops_with_out_of_memory() {
    runs_out_of_memory(
        "list_copies",
        "a list called tally is [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].
a list called shelf is [].
Print \"started\".
a number called rounds is 0.
While rounds is less than 10000000,
    append tally to shelf,
    increment rounds.
Print \"never reached\".
",
    );
}

/// A map growing by a key per round.
#[test]
fn map_insert_stops_with_out_of_memory() {
    runs_out_of_memory(
        "map_insert",
        "a map called ledger is {}.
Print \"started\".
a number called rounds is 0.
While rounds is less than 10000000,
    Set ledger's \"{rounds}\" to rounds,
    increment rounds.
Print \"never reached\".
",
    );
}

/// A map copied into a list, over and over.
#[test]
fn map_copies_stops_with_out_of_memory() {
    runs_out_of_memory(
        "map_copies",
        "a map called entry is {\"name\": \"Ada\", \"age\": 36}.
a list called shelf is [].
Print \"started\".
a number called rounds is 0.
While rounds is less than 10000000,
    append entry to shelf,
    increment rounds.
Print \"never reached\".
",
    );
}

/// The keys of a map, made into a fresh list each round.
#[test]
fn map_keys_stops_with_out_of_memory() {
    runs_out_of_memory(
        "map_keys",
        "a map called entry is {\"name\": \"Ada\", \"age\": 36}.
a list called shelf is [].
Print \"started\".
a number called rounds is 0.
While rounds is less than 10000000,
    append entry's keys to shelf,
    increment rounds.
Print \"never reached\".
",
    );
}

/// A format string made into a text each round.
#[test]
fn texts_in_a_list_stops_with_out_of_memory() {
    runs_out_of_memory(
        "texts_in_a_list",
        "a list called words is [].
Print \"started\".
a number called rounds is 0.
While rounds is less than 10000000,
    a text called word is \"word {rounds}\",
    append word to words,
    increment rounds.
Print \"never reached\".
",
    );
}

/// A buffer copied out as a text each round.
#[test]
fn buffer_texts_stops_with_out_of_memory() {
    runs_out_of_memory(
        "buffer_texts",
        "a buffer called line is \"a line of text\".
a list called copies is [].
Print \"started\".
a number called rounds is 0.
While rounds is less than 10000000,
    append {line as text} to copies,
    increment rounds.
Print \"never reached\".
",
    );
}

/// A fixed buffer whose size is decided as the program runs.
#[test]
fn sized_at_run_time_stops_with_out_of_memory() {
    runs_out_of_memory(
        "sized_at_run_time",
        "a number called size is 1073741824.
Print \"started\".
a buffer called big is size bytes in size.
Print \"never reached\".
",
    );
}
