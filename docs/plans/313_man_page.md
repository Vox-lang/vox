# 313 — `man vox`

**Status:** staged by TheJostler (2026-08-18). Not started. Deliberately
**not** part of 0.4.2 — that patch is the cargo-install fix and should
stay small.

**Dependencies:** none.

## Why

`vox --help` lists flags and nothing else. A user who installs from Copr
or Nix has no `man vox`, which for a systems compiler is a conspicuous
absence — it is the first thing anyone reaching for an unfamiliar
compiler tries, and its absence reads as unfinished.

Everything the page needs already exists and is verified: `--help` for
the synopsis, `docs/INSTALL.md` for the coreasm resolution order,
LANGUAGE.md for the language itself, and the 0.4.x changelog for the
process and things vocabulary. The work is selection and shaping, not
research.

## What to write

A single `man/vox.1` in **mdoc** or **man** macros — pick one and say
which; groff `man` macros are the lower-risk choice since every
`man` implementation handles them.

Sections, in the conventional order:

- **NAME** — `vox — compile English sentences to native x86_64`
- **SYNOPSIS** — `vox <source.vox> [options]`
- **DESCRIPTION** — what Vox is in three or four sentences: a compiler
  from a constrained English grammar directly to NASM, no libc, no
  garbage collector, no resident runtime. Say what it is *not*, since
  that is what surprises people.
- **OPTIONS** — every flag from `--help`, each with a sentence of
  substance rather than a restatement of its name. `--emit-asm`,
  `--keep-asm`, `--run`, `--shared`, `--link`, `--lib-path`,
  `--target`, `-o`, `-v`, `-h`, `-V`. Generate the list from `--help`
  and check nothing is missing or stale.
- **ENVIRONMENT** — `VOX_CORE_PATH` (and the deprecated
  `EC_CORE_PATH`), with the resolution order and the shadowing warning
  from `docs/INSTALL.md`. This is the single most useful thing the page
  can carry: it is the trap this project has hit repeatedly.
- **FILES** — `/usr/share/vox/coreasm`, the XDG config,
  `~/.cache/vox/<version>/coreasm` (the embedded fallback from plan
  312), `/usr/include/vox/*.lib` and `/usr/lib64/lib*.so` for
  libraries.
- **EXAMPLES** — three or four, each of which must compile: hello
  world; `--emit-asm`; building a shared library and linking against it
  with `--link`/`--lib-path`.
- **EXIT STATUS** — what vox returns on success and on failure.
- **SEE ALSO** — `nasm(1)`, `ld(1)`, and the project URLs.
- **AUTHOR / BUGS** — Josjuar Lister; the GitHub issues URL.

## Constraints

- **Every example must compile**, checked against the built compiler
  before commit — the same iron rule the LANGUAGE.md chapter follows,
  and this project has shipped six defective snippets by skipping it.
- The page must not duplicate LANGUAGE.md. It documents the *program*,
  not the language; point at LANGUAGE.md for grammar.
- No claim about behaviour that has not been run. In particular do not
  describe the coreasm search order from memory — read
  `find_core_path` in `src/main.rs`, which has six steps, not the three
  an older plan claimed.

## Packaging

- `Makefile`: install `man/vox.1` to `$(PREFIX)/share/man/man1/`,
  gzipped or not per distro convention (rpm compresses automatically).
- `vox.spec`: add the man page to `%files` as
  `%{_mandir}/man1/vox.1*`.
- `flake.nix`: install it into `$out/share/man/man1` so `man vox` works
  under Nix.
- The 7z release archive should carry it too.

## Verification

1. `man ./man/vox.1` renders with no groff warnings
   (`groff -man -Tutf8 man/vox.1 >/dev/null` reports nothing).
2. Every example in the page compiles and runs.
3. Flags in the page exactly match `vox --help` — no extras, none
   missing.
4. After `make install`, `man vox` finds it.
5. `rpmbuild` includes it and `rpm -ql` shows it under `%{_mandir}`.
