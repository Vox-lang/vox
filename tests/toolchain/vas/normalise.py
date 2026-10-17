#!/usr/bin/env python3
"""Normalise preprocessed NASM source, so that the expansion vas writes and
the one `nasm -E` writes can be compared line for line.

Both sides go through the same steps:

  - %line markers, comments and blank lines are dropped;
  - nasm's bracketed forms of its primitive directives are written plainly,
    so [section .text] reads section .text, as vas writes it;
  - nasm's expansion of align, [sectalign N] followed by
    times (((N) - (($-$$) % (N))) % (N)) nop, is written back as align N;
  - a label at the start of a line is put on a line of its own;
  - outside quotes, every run of spaces becomes one space, and no space is
    kept next to punctuation;
  - hexadecimal digits are written in lower case;
  - macro-local labels, ..@<number>.name, are numbered again in the order
    they first appear, since vas and nasm count their expansions apart.

Usage:
  normalise.py FILE                 print FILE normalised
  normalise.py --compare NASM VAS   compare two files once normalised; on a
                                    difference, print the first one and
                                    exit 1
"""

import re
import sys

QUOTED = re.compile(r"('[^']*'|\"[^\"]*\"|`(?:[^`\\]|\\.)*`)")
PRIMITIVE = re.compile(r"^\[\s*(section|segment|global|extern|default|sectalign)\s+(.*?)\s*\]$", re.I)
LABEL = re.compile(r"^([A-Za-z_.?@$][\w.?@$#~]*)\s*:(.*)$")
HEX = re.compile(r"\b0[xX][0-9a-fA-F_]+\b")
LOCAL_LABEL = re.compile(r"\.\.@(\d+)\.")
WORD_CHARACTER = re.compile(r"[\w.$@?#~%]")


def strip_comment(text):
    quote = None
    for position, character in enumerate(text):
        if quote:
            if character == quote:
                quote = None
        elif character in "'\"`":
            quote = character
        elif character == ";":
            return text[:position]
    return text


def tidy_spacing(text):
    """Collapse spaces and drop those next to punctuation, outside quotes."""
    pieces = QUOTED.split(text)
    for index in range(0, len(pieces), 2):
        piece = re.sub(r"\s+", " ", pieces[index])
        piece = HEX.sub(lambda match: match.group(0).lower(), piece)
        kept = []
        for position, character in enumerate(piece):
            if character == " ":
                before = piece[position - 1] if position > 0 else ""
                after = piece[position + 1] if position + 1 < len(piece) else ""
                if not (before and after and WORD_CHARACTER.match(before) and WORD_CHARACTER.match(after)):
                    continue
            kept.append(character)
        pieces[index] = "".join(kept)
    return "".join(pieces).strip()


def statements(path):
    """The statements of a file, one per line, before renumbering."""
    with open(path, errors="replace") as handle:
        rows = handle.read().splitlines()
    result = []
    for row in rows:
        if row.lstrip().startswith("%line"):
            continue
        text = strip_comment(row).strip()
        if not text:
            continue
        primitive = PRIMITIVE.match(text)
        if primitive:
            text = primitive.group(1).lower() + " " + primitive.group(2)
        while True:
            label = LABEL.match(text)
            if not label or text.startswith("["):
                break
            result.append(label.group(1) + ":")
            text = label.group(2).strip()
        if text:
            result.append(tidy_spacing(text))
    return result


def fold_align(lines):
    """nasm writes align N as a sectalign and a times ... nop; fold them back."""
    folded = []
    position = 0
    while position < len(lines):
        line = lines[position]
        match = re.match(r"^sectalign (\S+)$", line)
        if match and position + 1 < len(lines):
            boundary = match.group(1)
            padding = "times(((%s)-(($-$$)%%(%s)))%%(%s))nop" % (boundary, boundary, boundary)
            if lines[position + 1].replace(" ", "") == padding:
                folded.append("align " + boundary)
                position += 2
                continue
        folded.append(line)
        position += 1
    return folded


def renumber(lines):
    numbers = {}

    def replace(match):
        number = numbers.setdefault(match.group(1), str(len(numbers) + 1))
        return "..@" + number + "."
    result = []
    for line in lines:
        pieces = QUOTED.split(line)
        for index in range(0, len(pieces), 2):
            pieces[index] = LOCAL_LABEL.sub(replace, pieces[index])
        result.append("".join(pieces))
    return result


def normalise(path):
    return renumber(fold_align(statements(path)))


def main(arguments):
    if len(arguments) == 1:
        sys.stdout.write("".join(line + "\n" for line in normalise(arguments[0])))
        return 0
    if len(arguments) == 3 and arguments[0] == "--compare":
        nasm, vas = normalise(arguments[1]), normalise(arguments[2])
        for number, (nasm_line, vas_line) in enumerate(zip(nasm, vas), 1):
            if nasm_line != vas_line:
                print("first difference at normalised line %d:\n    nasm: %s\n    vas:  %s" % (number, nasm_line, vas_line))
                return 1
        if len(nasm) != len(vas):
            longer, name = (nasm, "nasm") if len(nasm) > len(vas) else (vas, "vas")
            print("first difference at normalised line %d: only %s goes on, with: %s"
                  % (min(len(nasm), len(vas)) + 1, name, longer[min(len(nasm), len(vas))]))
            return 1
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
