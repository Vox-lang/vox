# Issues found during the voxos `cat` optimisation audit (2026-08-10)

Compiler: vox v0.3.4, target x86_64. Every item below was reproduced
empirically on Linux 7.1.6 (Fedora 44); minimal repros are inlined where the
behaviour is surprising. Ordered by how hard they bit.

## 1. Buffer data area is cache-line misaligned (+24) — ~3.7× read slowdown

`BUF_DATA` is 24 (`coreasm/x86_64/resource.asm:14`), so every buffer's data
area starts at `mmap + 24`. `read(2)` into that destination makes the kernel's
`copy_to_user` split every cache line. Measured with an isolated C harness
(identical 128KB read loop over a 135MB page-cached file, warm buffer):

- destination `mmap + 0`: **61 ms**
- destination `mmap + 24`: **222 ms** (3.7×)

This is the single reason optimised vox `cat` (84 ms) still trails GNU cat
(30 ms) on large files; syscall counts are already comparable.

**Fix:** pad the header to 64 bytes. The offset is hardcoded in more places
than the define:

- `resource.asm` — `BUF_DATA` define and arithmetic on it
- `file.asm:294-295` (`FILE_WRITE_BUF`: `[rsi + 8]`, `add rsi, 24`)
- `io.asm:48-49` (same pattern)
- `src/codegen/mod.rs` — literal `24`s at e.g. 3882, 4015, 4086, 5335, 5381
- `list.asm` / `map.asm` share the same 24-byte header layout (their `+ 24`
  sites are separate structures; decide whether to pad those too)

Introduce one shared constant and emit it from codegen rather than literals.

## 2. Global variables inside functions: three different behaviours

A top-level declaration creates BOTH a `gvar_N` and a shadow stack slot in
main's frame, and access forms disagree about which one they touch:

| Access | From main | From a function |
|---|---|---|
| read | stale shadow `[rbp-N]` | `gvar_N` (correct) |
| `set X to Y` | both (init) / shadow | **phantom local — write lost** |
| `increment X` | `gvar_N` | `gvar_N` (correct) |

Repro:

```
a number called counter is 0.

To poke.
  increment the counter.

poke.
Print "{counter}".        (prints 0 — top-level read uses the stale shadow)
```

and the `set` variant is lost entirely (`set 'flag' to true` inside a function
writes `[rbp-8]` of the *function's* frame — visible in `--emit-asm`).
Consequence: a flag written in a function and read at top level silently never
fires; programs "work" only when both sides happen to pick the gvar. voxos
`cat` now uses a number + `increment`, tested only inside functions, as the
workaround.

**Fix:** resolve every named global to `gvar_N` in all contexts; drop the
shadow slot.

## 3. `Read from <file> into <global buffer>` inside a function reads 0 bytes

Top-level reads into a global buffer work; function-local buffers work; but a
function reading into a global buffer silently returns 0 bytes (no error
flag). Likely the same root cause as issue 2 (the buffer pointer is loaded
from/stored to the wrong slot). Workaround: function-local buffers only.

## 4. Nested `if` via comma inside a top-level `If` body mis-parses

```
If cond then,
  Print "a",
  if cond then,
    Print "inner".
  Print "b".
```

errors with `Expected 'print' in 'but if' branch`. Worse, in a larger program
the same shape compiled *silently*, closing the outer `If` early so the
following statements (an `Exit 0.` in cat's case) ran unconditionally at top
level. Nested `if` inside `While` bodies and inside function bodies parses
correctly — only the top-level `If` body path is affected. The silent variant
is the dangerous one.

## 5. `_grow_buffer` mmap failure check is wrong (`resource.asm:897`)

After the mmap syscall it tests `cmp rax, -1`, but raw mmap returns `-errno`
(−12 for ENOMEM, never −1). An allocation failure is treated as success and
the "buffer" pointer is written through → SIGSEGV under memory pressure.
`_alloc_buffer` (line ~652) has the correct `cmp rax, -4096; ja .failed`
check; `_grow_buffer` needs the same. Also: the doubling loop
(`.double_loop: shl rax, 1; cmp rax, r13; jl`) never terminates if capacity is
ever 0.

## 6. `_realloc_buffer` doesn't null-check `_alloc_buffer_sized` (`resource.asm:1697`)

`_alloc_buffer_sized` documents "0 on failure"; `_realloc_buffer` does
`call _alloc_buffer_sized; mov rbx, rax` and proceeds straight to
`rep movsb` into `rbx + BUF_DATA` — a write through address 24 on failure.

## 7. `FILE_WRITE_BUF` / `FILE_WRITE_STR` are single unchecked write(2)s (`file.asm:284`)

No partial-write loop and no `_last_error` signalling, so:

- a write interrupted after a signal handler (none installed today, so latent)
  or a single write >2GB (Linux caps at ~2^31−4096) silently truncates;
- ENOSPC / EPIPE / EBADF are invisible to `On error` — a vox program cannot
  detect a failed write at all. GNU cat reports these and exits 1.

**Fix:** loop until all bytes written; set `_last_error` on error.

## 8. Fixed-buffer exact-fill probe loses one byte on pipes (`resource.asm:~1075`)

When a read exactly fills a fixed buffer, `_read_into_buffer` reads 1 probe
byte to distinguish "exact fit" from "truncation", then seeks back. On a pipe
the seek-back fails and the byte is gone (acknowledged in the asm comment).
Any vox program that chunk-reads a pipe through a fixed buffer corrupts data
if a burst ever fills the buffer. voxos `cat` dodges this by giving fixed
buffers only to sources with `fstat` size > 0.

**Fix idea:** probe only when the fd is seekable (one `lseek(fd, 0, SEEK_CUR)`
test, or fstat mode check); on unseekable fds report "unknown, treat exact
fit as success" instead of eating a byte. Better still, see the "read up to N
bytes" item in the optimisation notes.

## 9. Misleading warning for dynamic buffer declarations

`Warning: Buffer "chunk" declared without size or initializer. This creates a
zero-capacity buffer which may not be useful. Consider: a buffer called
'chunk' is 1024 bytes.` — both claims mislead: dynamic buffers start at 4096
capacity (`INITIAL_BUF_CAP`, `resource.asm:20`) and grow without bound, and
the suggested "fix" creates a *fixed* buffer with different (truncating)
semantics. A bare dynamic buffer is often exactly what's wanted; the warning
trains users away from the safe default.

## Stale `_last_error` (observation, not yet a confirmed bug)

The truncation probe sets `_last_error` on every full chunk and nothing clears
it until the next successful `Open`. Any future statement with an `On error`
that doesn't itself set/clear the flag could inherit a stale error from an
unrelated earlier operation. Consider clearing `_last_error` at the start of
every error-capable operation so `On error` is always statement-local.
