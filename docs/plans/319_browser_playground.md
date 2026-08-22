# 319 — The browser playground

**Status:** staged by TheJostler (2026-08-18). **Queued behind the
benchmarking tool** — that repo comes first; this plan exists so the
design survives until then. Not started.

> **2026-08-18, later the same day: the domain arrived, and the scope
> grew.** TheJostler bought **`vox-lang.dev`** (canonical) and
> **`voxlang.dev`** (already redirecting to it), which gives the
> playground a real home instead of a Pages subdomain — and raised a
> larger question this plan does not cover: a proper language *site*
> with tutorials and a language reference, plus an **AI-facing way to
> serve the language rules** (an API and/or an MCP server) so that
> assistants writing Vox can consult the real grammar instead of
> guessing at it.
>
> That is at least four separable pieces — the site, the tutorials, this
> playground, and the rules service — with very different shapes
> (static generation, writing, systems engineering, a service contract).
> Writing one spec across all four would produce something too vague to
> build. **Shelved deliberately for a later brainstorm**, undecided at
> the point it was shelved: whether they are one phased site in one repo
> or separate projects sharing a domain. The argument for one repo is
> that the docs, the language reference, and whatever the rules service
> serves are *the same content*, and splitting them means maintaining
> the language rules in two places.
>
> What this plan should absorb when it is next opened: the site is
> hosted at `vox-lang.dev` (custom domain, canonical URL, `.dev` is
> HSTS-preloaded so HTTPS-only from day one), the playground lives under
> a path on it rather than standing alone, and `voxlang.dev` redirects.

**What it is:** a static website — `Vox-lang/vox-playground` — where the
Vox compiler runs in the visitor's browser as WASM and the programs it
produces execute there too. Zero install, zero server, and the screen no
other language can show: **English on the left, the real x86_64 assembly
it becomes in the middle, the program's output on the right.**

## Why Vox is unusually suited to this

1. **The compiler is plain Rust** — it builds for wasm32 with
   `wasm-bindgen` almost as-is. The only surgery: it shells out to
   `nasm`/`ld` via `Command::new`; put that behind a trait and the
   browser build stops at emitted assembly. Plan 312's embedded coreasm
   means the browser compiler is already self-contained — that fix
   accidentally did half this plan's work.
2. **Vox binaries are the easiest possible emulation payload**: ~15KB,
   static, libc-free, speaking exactly the small documented syscall set
   coreasm defines. No Linux VM needed — an x86_64 CPU emulator plus
   **~25 syscalls implemented in JavaScript** is the whole OS:
   `write` → xterm.js, `open`/`read`/`close` → an in-memory virtual FS,
   `clock_gettime` → performance.now(), `nanosleep` → a scheduler yield.
3. **Sandboxing is free.** Visitor code runs in the visitor's browser,
   inside an emulator, inside the WASM sandbox. Unlike the Rust/Go
   playgrounds there is no server executing strangers' code and no
   server bill: static hosting (GitHub Pages), same CI/ruleset standards
   as the other repos.

## Rulings made at staging (TheJostler, 2026-08-18)

- **No Vox→WASM compiler backend.** It is the "proper-looking" answer
  and the wrong one: most of Vox's showcase is syscalls WASM does not
  have, and it is ten times the work for a worse demo. The playground
  emulates x86_64; the compiler's one true backend stays NASM.
- **Queued behind the benchmarking tool.** The playground is the
  highest-leverage adoption artifact, but the queue order stands.

## Architecture

| Piece | Choice | Notes |
|---|---|---|
| Compiler | vox (Rust) → WASM, `wasm-bindgen` | `Command::new` behind a trait; `--emit-asm` path only in-browser |
| Assembler | nasm via Emscripten | known-good; C codebase |
| Linker | minimal ELF64 writer | one object, zero external symbols — deliberately small |
| CPU | Unicorn.js or Blink-in-WASM | evaluate both; Blink (~200KB, usermode x86_64-linux) is the likelier fit |
| Syscalls | ~25 in TypeScript | the coreasm syscall inventory is the spec; enumerate it at build start |
| Editor | Monaco + the vox-vscode TextMate grammar | grammar reuses directly |
| Terminal | xterm.js | |
| Hosting | GitHub Pages, static | vox-lang standards: CI, ruleset, signed commits |

## Staged delivery

- **v0 (days):** compiler-in-WASM + editor + assembly pane. No
  execution. "See what your English becomes" — already shareable, and
  ships the two hard toolchain proofs (Rust→WASM build, trait seam).
- **v1 (the real work, ~1–2 weeks of worker time):** emulator + syscall
  layer → programs run; the three-pane screen; examples (`cat.vox`,
  `pi.vox`, `delivery.vox`) as one-click loads.
- **v2:** virtual FS surfaced in the UI for the file examples; canned
  multi-file `see` support; share-by-URL (program encoded in the
  fragment, nothing server-side).

## Honest limits, stated on the site itself

`fork`, `execve`, `mount`, signals, and the supervisor demo need real
process semantics a usermode emulator does not offer. v1 detects those
statements and prints a friendly note: *"this one needs a real kernel —
`dnf install vox`"* — which is an honest limitation and a decent
conversion funnel in one line. Do not fake them.

## Prerequisites when work starts

1. The benchmarking tool exists (queue ruling above).
2. The `Command::new` trait seam lands in the compiler as its own small
   reviewed PR — it benefits tests independently and de-risks the rest.
3. An enumerated syscall inventory generated from coreasm, checked
   against `grep syscall coreasm/x86_64/*.asm`, committed as the
   playground's conformance spec.
