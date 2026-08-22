# Security Policy

## Supported versions

Vox is pre-1.0 and moves quickly. **Only the most recent release
receives fixes** — there is no long-term-support line, and a patch
release supersedes the one before it entirely.

| Version | Supported |
| ------- | --------- |
| 0.4.x (latest patch) | :white_check_mark: |
| Any earlier release | :x: — upgrade first |

If you are on an older version, please reproduce against the latest
release before reporting: the bug may already be fixed, and today's
fixes are usually days old rather than months.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting**, which is enabled on
this repository: go to the [Security
tab](https://github.com/Vox-lang/vox/security) and choose *Report a
vulnerability*. That keeps the report private until a fix exists.

If you cannot use GitHub, email **security@vox-lang.dev**. For anything
that is not a vulnerability, **info@vox-lang.dev** is the general
address.

**Please do not open a public issue for a suspected vulnerability.**
Ordinary bugs — crashes on invalid input, wrong output, compiler errors
that are merely unhelpful — are welcome as public issues, and are not
vulnerabilities. See the scope section below.

**What to expect.** Vox is maintained by one person, so the honest
answer is best-effort rather than a service-level agreement: an
acknowledgement within a few days, and an assessment of whether the
report is in scope soon after. If it is accepted, you will be told when
the fix lands and in which release. If it is declined, you will be told
why, in enough detail to disagree with. Credit in the release notes is
offered by default and withheld on request.

## What counts as a vulnerability

Vox's central claim is that a compiled program is memory-safe without a
garbage collector or a runtime: bounds are checked inline, resources are
tracked at compile time, and failure surfaces through error flags rather
than memory corruption. Security reports are the ones that put a hole in
that claim.

**In scope:**

- **A generated program violating the safety guarantees** — reading or
  writing outside a buffer's bounds without the documented error-flag
  behaviour, a use-after-free, or any memory corruption reachable from
  ordinary Vox source. This is the most serious class.
- **The compiler mishandling untrusted source** — compiling a `.vox`
  file should never give that file's author code execution on the
  compiling machine, write files outside the expected outputs, or
  exfiltrate anything.
- **Path or argument handling that escapes its intended directory** in
  the compiler or in the tooling it ships.
- **Anything wrong with the published artifacts** — a crates.io, Copr,
  or Nix build that does not correspond to the tagged source.

**Not vulnerabilities**, though still worth reporting as ordinary issues:

- Compiler crashes, internal errors, or hangs on malformed input. These
  are bugs, and there is a whole fuzzer devoted to finding them
  ([vox-fuzz](https://github.com/Vox-lang/vox-fuzz)) — they are filed
  publicly in [docs/BUGS_FOUND.md](docs/BUGS_FOUND.md).
- A Vox program doing something dangerous that its author asked for.
  Vox exposes real syscalls — `Execute`, `mount`, `Send signal`,
  `Shutdown` — and a program that uses them is working as documented.
  The compiler is not a sandbox and does not claim to be.
- Missing hardening that Vox has never claimed (ASLR-friendly PIE
  output, stack canaries, and similar). These are reasonable feature
  requests, not vulnerabilities.

## How we look for these ourselves

Memory-safety defects in this project are found and fixed in public.
[vox-fuzz](https://github.com/Vox-lang/vox-fuzz) generates random valid
Vox programs, compiles them, and supervises the resulting binaries to
catch any that die by signal, hang, or make the compiler itself fall
over. Every finding it has produced is recorded in
[docs/BUGS_FOUND.md](docs/BUGS_FOUND.md) with a minimal reproduction and
the release that fixed it — including several genuine memory-safety
bugs, each with regression tests standing guard.

If you find one it missed, that is exactly the report worth sending.
