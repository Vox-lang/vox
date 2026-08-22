# Contributing to Vox

Vox is pre-1.0, maintained by one person part-time. Thank you
for reading this before opening something; it saves both of us time.

## Reporting a bug

A report that gets fixed has three things:

1. **The smallest `.vox` file that reproduces it.** Strip anything not
   needed to trigger the bug. `docs/BUGS_FOUND.md` in this repo shows
   the format we use internally: a minimal standalone snippet, what it
   does, what it should do.
2. **The compiler version** (`vox --version`), since only the latest
   patch release is supported (see `SECURITY.md`).
3. **Expected output versus actual output**, stated separately, not
   implied.

Suspected security issues (a generated program corrupting memory, or
the compiler doing something to your machine beyond compiling) go
through GitHub's private vulnerability reporting or security@vox-lang.dev,
per `SECURITY.md`, not a public issue.

## Proposing a language change

Read `LANGUAGE.md` first, and `docs/STYLE.md` for the read-aloud test:
if a line would not sound like something a person would say out loud,
that is usually the whole objection. Most proposals turn out to already
be expressible in the current grammar. The default answer to a new
keyword or new syntax is "no, and here is how to write it today"; that
is not a brush-off, it is the language staying small on purpose. A
proposal is more likely to land if it shows the construct it would
replace and explains why that construct reads worse.

## AI-assisted contributions

AI-assisted contributions are welcome. Two rules make that workable:

- **You are responsible for every line you submit**, whether you typed
  it or an assistant did. "The AI wrote it" is not a defense for a bug,
  an unreadable name, or code that violates `docs/STYLE.md`.
- **State whether and how AI was used in the PR description.** A short
  line is enough: which tool, for what part.

A PR that is unreviewed AI output with no compiling test attached will
be closed, not debated. This project is not anti-AI: a large share of
this compiler's own commits are AI-assisted, credited as such in the
commit history, and that will keep being true. The bar is the same for
every contributor, human-typed or not: it compiles, it is tested, and
you can explain why it is correct.

## Licence

Vox is GPL-3.0-or-later. By submitting a contribution you license it
under the same terms; the project does not require copyright
assignment and does not ask you to sign anything away. This does not
change if the project is ever sold or the trademark changes hands.

## Good first issue

There is no curated backlog yet. For now, "good first issue" means: a
report that already has a minimal `.vox` reproduction attached, so the
fix is scoped before anyone starts. Ask in Discussions if you want
something to work on and none is open.

## Response time

Expect an acknowledgment within a few
days and a real answer soon after, the same promise `SECURITY.md`
makes for vulnerability reports. Silence past a couple of weeks means
ping it again, not that you were ignored on purpose.

## Conduct

Be someone the maintainer wants to keep talking to; disagreement about
the language is fine, disrespect is not.
