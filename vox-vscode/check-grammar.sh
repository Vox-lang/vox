#!/usr/bin/env bash
#
# check-grammar.sh — catch drift between the Vox lexer's keywords and the
# VS Code grammar's highlighted keywords.
#
# The extension's grammar (syntaxes/vox.tmLanguage.json) is hand-maintained
# while the lexer (src/lexer/mod.rs) is the source of truth for what the
# language treats as a keyword. They drift apart silently because nothing
# compares them. This script does.
#
# It reports the keywords the lexer recognises that the grammar does NOT
# highlight, and exits non-zero when that set is non-empty so it can be wired
# into CI. It also prints, for information, the reverse drift: words the
# grammar highlights that the lexer does not know at all (stale grammar).
#
# Design notes (read these before "fixing" the script):
#
#   * No new dependencies. POSIX shell + Python 3, which the repo already
#     uses. The extension must stay installable from the repo with no
#     toolchain, so no node, no npm, no third-party JSON library.
#
#   * The grammar is parsed as JSON (json.load), not with a regex over the
#     file. A regex over the raw text under-counts badly: the keyword
#     patterns are wrapped in (?i:...) and \b...\b, which defeat naive
#     alternation matching. JSON parsing gives the pattern strings; the
#     keyword literals are then pulled out of those patterns by walking the
#     parenthesised groups, not by grepping the file.
#
#   * A lexer keyword is counted as "covered" if the grammar highlights the
#     canonical form OR any of its aliases. The lexer has two spelling tables
#     (string_is_keyword and read_word) that disagree with each other in
#     places; both are merged with the canonical names from as_keyword so a
#     keyword is never reported missing just because the grammar used an alias
#     the canonical form maps to.
#
#   * A small allow-list of articles/particles is excluded from the required
#     set (see ALLOW below). These are real lexer tokens but highlighting them
#     as keywords would be visual noise in prose-like Vox source. The list is
#     explicit and commented so a reader can see it is a judgement, not an
#     omission.
#
# Usage:  ./vox-vscode/check-grammar.sh
# Exit:   0 if the grammar is not behind the lexer, 1 if it is.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEXER="${SCRIPT_DIR}/../src/lexer/mod.rs"
GRAMMAR="${SCRIPT_DIR}/syntaxes/vox.tmLanguage.json"

if [ ! -f "$LEXER" ]; then
    echo "check-grammar: lexer not found at $LEXER" >&2
    exit 2
fi
if [ ! -f "$GRAMMAR" ]; then
    echo "check-grammar: grammar not found at $GRAMMAR" >&2
    exit 2
fi

exec python3 - "$LEXER" "$GRAMMAR" <<'PYEOF'
import json, re, sys
from collections import defaultdict

lexer_path, grammar_path = sys.argv[1], sys.argv[2]

# ---------------------------------------------------------------------------
# Lexer side: build canonical keyword -> set of spellings.
# ---------------------------------------------------------------------------

src = open(lexer_path, encoding="utf-8").read()

def func_body(text, name):
    """Return the brace-delimited body of `fn <name>(...)`, skipping
    double-quoted strings while counting braces so braces inside string
    literals cannot throw off the match."""
    sig = "fn " + name + "("
    start = text.index(sig)
    bi = text.index("{", start)
    depth = 0
    i = bi
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return text[bi + 1:i]
        i += 1
    raise SystemExit("check-grammar: could not isolate body of " + name)

# Canonical keyword names: every `Token::Variant => Some("canonical")` in
# as_keyword. This is the authoritative set of keyword tokens the lexer
# actually emits (string_is_keyword is a separate, partly stale helper and is
# NOT used to define the required set).
ak_body = func_body(src, "as_keyword")
variant_to_canon = {}
canon = set()
for m in re.finditer(r'Token::(\w+)\s*=>\s*Some\("([^"]+)"\)', ak_body):
    v, c = m.group(1), m.group(2)
    variant_to_canon[v] = c
    canon.add(c)

canon_to_spellings = defaultdict(set)  # canonical -> {spellings}

# Spellings from string_is_keyword: `"sp" | ... => Some("canonical")`.
sik_body = func_body(src, "string_is_keyword")
arm_re = re.compile(r'((?:"[^"]+"\s*(?:\|\s*)?)+)\s*=>\s*Some\("([^"]+)"\)')
for m in arm_re.finditer(sik_body):
    left, c = m.group(1), m.group(2)
    for s in re.findall(r'"([^"]+)"', left):
        canon_to_spellings[c].add(s.lower())

# Spellings from read_word (the real tokenizer): `"sp" | ... => Token::Variant`.
# Arms whose target is Token::Identifier(...) are NOT keywords and are skipped.
rw_body = func_body(src, "read_word")
arm_rw = re.compile(r'((?:"[^"]+"\s*(?:\|\s*)?)+)\s*=>\s*Token::(\w+)')
for m in arm_rw.finditer(rw_body):
    left, variant = m.group(1), m.group(2)
    if variant == "Identifier":
        continue
    c = variant_to_canon.get(variant)
    if c is None:
        continue  # not a keyword token (e.g. a literal)
    for s in re.findall(r'"([^"]+)"', left):
        canon_to_spellings[c].add(s.lower())

# The canonical form itself is always a valid spelling of its keyword.
for c in canon:
    canon_to_spellings[c].add(c)

# ---------------------------------------------------------------------------
# Allow-list: articles / particles that are real lexer tokens but would be
# noise if highlighted. Keep this list small and deliberate; adding a word
# here means "we never require the grammar to highlight it". This is a
# judgement, not an omission — if the grammar chooses to highlight one of
# these (the current grammar does, via the "articles" pattern), that is fine;
# the checker simply does not enforce it.
# ---------------------------------------------------------------------------

ALLOW = {
    "a",      # indefinite article
    "an",     # indefinite article
    "the",    # definite article
    "of",     # genitive / function-call particle
    "with",   # function-parameter introducer
    "called", # naming particle
}

# --------------------------------------------------------------------------- ---------------------------------------------------------------------------
# Grammar side: collect every literal keyword a pattern highlights.
# ---------------------------------------------------------------------------

grammar = json.load(open(grammar_path, encoding="utf-8"))
grammar_words = set()
WORD = re.compile(r'[A-Za-z][A-Za-z-]*')

def collect_from_pattern(pat):
    """Walk a regex string and collect literal words from parenthesised
    groups that are pure `word|word|...` alternations. Handles `(?i:...)`
    flag groups and nested groups by recursion. Escaped characters and
    bracket character classes are skipped so they never yield words."""
    i = 0
    n = len(pat)
    while i < n:
        c = pat[i]
        if c == '\\' and i + 1 < n:
            i += 2
            continue
        if c == '[':
            # skip a character class (handle leading ^ and nested ] as first)
            i += 1
            if i < n and pat[i] == '^':
                i += 1
            if i < n and pat[i] == ']':
                i += 1
            while i < n and pat[i] != ']':
                if pat[i] == '\\' and i + 1 < n:
                    i += 2
                else:
                    i += 1
            i += 1
            continue
        if c == '(':
            # find the matching close, skipping escapes, char classes, nested
            depth = 1
            j = i + 1
            inner_start = j
            # strip leading (?...): flag groups like (?i:...) or (?=...)
            if j < n and pat[j] == '?':
                k = j + 1
                while k < n and pat[k] not in ':)':
                    k += 1
                if k < n and pat[k] == ':':
                    inner_start = k + 1
                    j = inner_start
                # else: a bare flag group like (?i) — inner stays after '?'
            jj = j
            while jj < n and depth > 0:
                cc = pat[jj]
                if cc == '\\' and jj + 1 < n:
                    jj += 2
                    continue
                if cc == '[':
                    jj += 1
                    if jj < n and pat[jj] == '^':
                        jj += 1
                    if jj < n and pat[jj] == ']':
                        jj += 1
                    while jj < n and pat[jj] != ']':
                        if pat[jj] == '\\' and jj + 1 < n:
                            jj += 2
                        else:
                            jj += 1
                    jj += 1
                    continue
                if cc == '(':
                    depth += 1
                elif cc == ')':
                    depth -= 1
                    if depth == 0:
                        break
                jj += 1
            inner = pat[inner_start:jj]
            alts = inner.split('|')
            if alts and all(WORD.fullmatch(a) is not None for a in alts):
                for a in alts:
                    grammar_words.add(a.lower())
            else:
                collect_from_pattern(inner)  # nested groups
            i = jj + 1
            continue
        i += 1

def walk(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("match", "begin", "end") and isinstance(v, str):
                collect_from_pattern(v)
            else:
                walk(v)
    elif isinstance(obj, list):
        for x in obj:
            walk(x)

walk(grammar)

# --------------------------------------------------------------------------- ---------------------------------------------------------------------------
# Compare.
# ---------------------------------------------------------------------------

covered = {c for c in canon if (canon_to_spellings[c] & grammar_words)}
missing = sorted(canon - covered - ALLOW)

all_spellings = set()
for sps in canon_to_spellings.values():
    all_spellings |= sps
extras = sorted(grammar_words - all_spellings - ALLOW)

print("vox grammar drift check")
print("  lexer keywords:    %d" % len(canon))
print("  grammar keywords:  %d" % len(grammar_words))
print("  covered:           %d" % len(canon - set(missing) - ALLOW))
print("  missing:            %d" % len(missing))
print("  grammar-only:       %d" % len(extras))

if missing:
    print("")
    print("MISSING — lexer keywords the grammar does not highlight:")
    for kw in missing:
        spellings = sorted(canon_to_spellings[kw])
        if spellings == [kw]:
            print("  " + kw)
        else:
            print("  " + kw + "  (spellings: " + ", ".join(spellings) + ")")

if extras:
    print("")
    print("GRAMMAR-ONLY — highlighted by the grammar but not a lexer keyword")
    print("(informational; may be stale grammar, does not fail this check):")
    for kw in extras:
        print("  " + kw)

if missing:
    sys.exit(1)
sys.exit(0)
PYEOF