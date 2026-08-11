# Runtime optimisation opportunities (from the voxos `cat` audit, 2026-08-10)

Ideas for making *every* vox program faster without touching its source,
roughly ordered by measured or expected payoff. Numbers come from a 135MB
page-cached file on Fedora 44 / x86_64 (Linux 7.1.6).

## 1. Pad the buffer header 24 → 64 bytes (measured 3.7× on bulk reads)

Covered as issue 1 in `ISSUES_FOUND_OPTIMIZING_CAT.md`. The single biggest
lever: it closes the remaining gap between optimised vox `cat` (84 ms) and GNU
cat (30 ms). Everything below is smaller.

## 2. `Read line` should scan blocks, not consume bytes

`_read_line_into_buffer` (`resource.asm:203`) already has an 8KB readahead
slot, but consumes it one byte per iteration (~6-8 instructions/byte:
load, compare to `\n`, bounds check, store, three counter updates). The
original line-based `cat` moved 135MB in 2.3s ≈ 60MB/s — that loop is why.

**Fix:** scan the readahead block for `\n` (SSE2 `pcmpeqb`/`pmovmskb`, or
even `repne scasb`), then copy the whole span into the destination with
`rep movsb`. Expect an order of magnitude on line-heavy workloads.
Raising `READAHEAD_BUF_SIZE` (currently 8192, `resource.asm:8`) to 64KB is a
cheap companion win once the scan is vectorised.

## 3. Pre-size reads from regular files (removes growth copies and re-reads)

`Read from` into a dynamic buffer grows by doubling from 4096, copying the
accumulated data on every growth (`_grow_buffer`: mmap new, `rep movsb`,
munmap old). Slurping an N-byte file costs ~log2(N/4096) mmap/munmap cycles
and ~2N bytes of extra copying.

**Fix:** when the destination is empty and the fd is a regular file, `fstat`
once inside `_read_into_buffer` and grow directly to `st_size + 1` before the
first read. voxos `cat` did this manually (via `source's size` + `resize`) for
a large win; the runtime could do it for every program. Guard: fall back to
doubling when `st_size` is 0 (pipes, /proc) or the file grows mid-read.

## 4. Use `mremap` for buffer growth instead of mmap+copy+munmap

`_grow_buffer` and `_realloc_buffer` allocate fresh, `rep movsb` the old
contents, then munmap. Linux `mremap(old, oldsz, newsz, MREMAP_MAYMOVE)`
does the same job by remapping pages — zero bytes copied, one syscall instead
of two plus a copy. Growth of large buffers becomes ~free; also shrinks the
munmap cost seen in profiles (54 ms of the old slurp design's 620 ms was
munmap of a 135MB buffer).

## 5. `FILE_WRITE_STR` computes strlen with a byte loop (`file.asm:~256`)

Every string write walks the string a byte at a time to find the NUL before
the syscall. Texts created from literals/format strings could carry their
length (they're runtime-allocated already); failing that, a `pcmpeqb`-based
strlen. Matters for print-heavy programs.

## 6. Make the exact-fill probe seekability-aware (and cheaper)

Per full fixed-buffer chunk the runtime spends two extra syscalls
(`read(fd,·,1)` + `lseek(-1)`) and taints `_last_error`. For seekable fds a
single `fstat` at open time (cache `st_mode`/`st_size` in the file table)
lets the runtime know "position < size ⇒ more data" without any probe; for
unseekable fds it avoids the byte-loss bug (issue 8). This also makes a
bounded chunk loop the natural constant-memory idiom.

## 7. Language-level: a bounded, pipe-safe read

`Read from` on a regular file always slurps to EOF (memory = file size);
fixed buffers are the only bounded read and carry the probe caveats. A
first-class `Read up to N bytes from source into buf.` (single read(2), no
probe, appends ≤ N bytes, 0 at EOF) would let programs stream any source at
constant memory with no sharp edges — it's the primitive `cat`, `cp`,
checksummers and servers all want.

## 8. `MAP_POPULATE` for large known-size allocations

When pre-sizing a buffer to a known file size (item 3), passing
`MAP_POPULATE` to mmap avoids taking ~one soft page fault per 4KB during the
subsequent read; the fault storm was measurable (fresh 135MB buffer: reads at
1.4GB/s vs dd's 5.6GB/s into a warm buffer — part misalignment, part
faulting). For the streaming path (small warm buffer) this is irrelevant.

## Non-issues checked along the way

- Syscall structure is already good: optimised `cat` moves 135MB in 136
  syscalls total; GNU cat uses ~1030. No dispatch overhead worth chasing.
- `rep movsb` on this ERMS-era hardware is fine for the copies that remain;
  alignment (item 1) dominates, not the instruction choice.
- Static linking + tiny binary makes process startup ~0.5 ms cheaper than
  GNU cat's dynamic startup — vox `cat` *beats* GNU cat below ~1MB because
  of it. Worth preserving.
