#!/usr/bin/env python3
"""Derive the instruction shapes of the assembly corpus.

For every file in tests/corpus/MANIFEST this runs `nasm -E` with coreasm on
the include path, so %include and the coreasm macros expand, classifies every
instruction as a mnemonic plus an operand shape, counts the directives, and
lists every NASM feature the corpus uses outside the subset the assembler is
meant to accept. For each shape it also assembles one example line with nasm
to record the bytes an encoder has to produce. It writes:

  tests/toolchain/SHAPES.md   the tables, for reading
  tests/toolchain/shapes.tsv  one row per shape with its bytes: the skeleton
                              of the encoder's test table

Usage:
  python3 tests/toolchain/shapes.py

Environment:
  VOX_CORE_PATH  the coreasm directory (default: this repository's coreasm)

Regenerate after the corpus changes (tests/toolchain/corpus.sh).
"""

import collections
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORPUS = os.path.join(ROOT, "tests", "corpus")
OUTPUT = os.path.join(ROOT, "tests", "toolchain")
CORE = os.path.abspath(os.environ.get("VOX_CORE_PATH", os.path.join(ROOT, "coreasm")))
# The emitted %include lines name coreasm/<arch>/<file>.asm, so nasm searches
# the directory above coreasm, as the compiler's own -I does.
INCLUDE = os.path.dirname(CORE)

# Where a line is placed when it is assembled on its own: code starts at the
# usual load address, and its labels sit at a fixed address a megabyte away,
# far enough that a jump to one needs rel32, so the bytes are deterministic.
ORIGIN = 0x401000
FAR_LABEL = 0x500000

# ----------------------------------------------------------------------------
# The fixed vocabulary
# ----------------------------------------------------------------------------

GPR64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] + ["r%d" % n for n in range(8, 16)]
GPR32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"] + ["r%dd" % n for n in range(8, 16)]
GPR16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"] + ["r%dw" % n for n in range(8, 16)]
GPR8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "ah", "ch", "dh", "bh"] + \
       ["r%db" % n for n in range(8, 16)] + ["r%dl" % n for n in range(8, 16)]

REGISTER_CLASS = {}
REGISTER_BITS = {}
for names, register_class, bits in ((GPR64, "r64", 64), (GPR32, "r32", 32), (GPR16, "r16", 16), (GPR8, "r8", 8)):
    for name in names:
        REGISTER_CLASS[name] = register_class
        REGISTER_BITS[name] = bits
for number in range(32):
    REGISTER_CLASS["xmm%d" % number] = "xmm"
    REGISTER_BITS["xmm%d" % number] = 128
    REGISTER_CLASS["ymm%d" % number] = "ymm"
    REGISTER_BITS["ymm%d" % number] = 256
for number in range(8):
    REGISTER_CLASS["st%d" % number] = "st"
    REGISTER_CLASS["mm%d" % number] = "mm"
REGISTER_CLASS["st"] = "st"
for name in ("cs", "ds", "es", "fs", "gs", "ss"):
    REGISTER_CLASS[name] = "sreg"

EXTENDED = {name for name in REGISTER_CLASS if re.match(r"r(8|9|1[0-5])[dwbl]?$", name)} | \
           {"xmm%d" % n for n in range(8, 16)}
UNIFORM_BYTE = {"spl", "bpl", "sil", "dil"}
HIGH_BYTE = {"ah", "ch", "dh", "bh"}
ACCUMULATOR = {"al", "ax", "eax", "rax"}

SIZE_WORDS = {"byte": 8, "word": 16, "dword": 32, "qword": 64, "tword": 80, "oword": 128, "yword": 256}
JUMP_QUALIFIERS = {"short", "near", "far", "strict"}

CONDITIONS = ["a", "ae", "b", "be", "c", "e", "g", "ge", "l", "le", "na", "nae", "nb", "nbe", "nc", "ne",
              "ng", "nge", "nl", "nle", "no", "np", "ns", "nz", "o", "p", "pe", "po", "s", "z"]
JUMPS = {"j" + condition for condition in CONDITIONS} | \
        {"jmp", "call", "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne", "loopz", "loopnz"}
SHIFTS = {"shl", "shr", "sal", "sar", "rol", "ror", "rcl", "rcr", "shld", "shrd"}
ACCUMULATOR_FORMS = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp", "test"}
PREFIXES = {"rep", "repe", "repz", "repne", "repnz", "lock"}

DATA_UNITS = {"db": 1, "dw": 2, "dd": 4, "dq": 8, "dt": 10, "do": 16, "dy": 32, "dz": 64}
RESERVE_UNITS = {"resb": 1, "resw": 2, "resd": 4, "resq": 8, "rest": 10, "reso": 16, "resy": 32, "resz": 64}
PRIMITIVES = {"section", "segment", "global", "extern", "default", "bits", "absolute", "common", "static",
              "cpu", "warning", "list", "required", "map", "float", "org", "sectalign"}

IDENTIFIER = r"[A-Za-z_.?@$][\w.?@$#~]*"

# ----------------------------------------------------------------------------
# Expressions
# ----------------------------------------------------------------------------

TOKEN = re.compile(r"""\s*(?:
     (?P<number>0[xX][0-9a-fA-F_]+|0[bB][01_]+(?![\w])|0[oOqQ][0-7_]+|[0-9][0-9a-fA-F_]*[hH](?![\w])
               |[01][01_]*[bByY](?![\w])|[0-7][0-7_]*[qQoO](?![\w])|[0-9][0-9_]*[dDtT]?(?![\w.]))
    |(?P<string>'[^']*'|"[^"]*"|`(?:[^`\\]|\\.)*`)
    |(?P<name>\$\$|[A-Za-z_.?@$][\w.?@$#~]*|\$)
    |(?P<operator><<|>>|//|%%|[-+*/%&|^~!(),:])
)""", re.X)


class Unresolved(Exception):
    """The expression names a symbol whose value is only known at link time."""


class Address:
    """A place in a section: a label, or `$`. The offset is None when the
    place follows an instruction, whose size this script does not compute."""

    def __init__(self, section, offset):
        self.section = section
        self.offset = offset


def tokenize(text):
    tokens = []
    position = 0
    text = text.rstrip()
    while position < len(text):
        match = TOKEN.match(text, position)
        if not match or match.end() == position:
            raise ValueError("cannot read %r" % text[position:])
        kind = match.lastgroup
        tokens.append((kind, match.group(kind)))
        position = match.end()
    return tokens


def number_value(spelling):
    text = spelling.replace("_", "").lower()
    if text.startswith("0x"):
        return int(text[2:], 16)
    if text.startswith("0b"):
        return int(text[2:], 2)
    if text.startswith("0o") or text.startswith("0q"):
        return int(text[2:], 8)
    if text.endswith("h"):
        return int(text[:-1], 16)
    if text[-1] in "by":
        return int(text[:-1], 2)
    if text[-1] in "qo":
        return int(text[:-1], 8)
    if text[-1] in "dt":
        return int(text[:-1])
    return int(text)


def string_bytes(spelling):
    quote, body = spelling[0], spelling[1:-1]
    if quote != "`":
        return body.encode("latin-1", "replace")
    escapes = {"n": 10, "t": 9, "r": 13, "0": 0, "\\": 92, "`": 96, "'": 39, '"': 34, "e": 27, "a": 7, "b": 8}
    result = bytearray()
    position = 0
    while position < len(body):
        if body[position] == "\\" and position + 1 < len(body):
            result.append(escapes.get(body[position + 1], ord(body[position + 1])))
            position += 2
        else:
            result.append(ord(body[position]))
            position += 1
    return bytes(result)


class Evaluator:
    """Evaluates NASM's integer expressions over the constants and labels one
    corpus file defines, as far as they can be known without encoding."""

    LEVELS = [{"|"}, {"^"}, {"&"}, {"<<", ">>"}, {"+", "-"}, {"*", "/", "//", "%", "%%"}]

    def __init__(self, symbols, here):
        self.symbols = symbols
        self.here = here

    def evaluate(self, tokens):
        self.tokens = tokens
        self.position = 0
        value = self.binary(0)
        if self.position != len(self.tokens):
            raise ValueError("unexpected %r" % (self.tokens[self.position][1],))
        return value

    def peek(self):
        return self.tokens[self.position][1] if self.position < len(self.tokens) else None

    def binary(self, level):
        if level == len(self.LEVELS):
            return self.unary()
        value = self.binary(level + 1)
        while self.peek() in self.LEVELS[level]:
            operator = self.tokens[self.position][1]
            self.position += 1
            value = combine(operator, value, self.binary(level + 1))
        return value

    def unary(self):
        operator = self.peek()
        if operator in ("-", "+", "~", "!"):
            self.position += 1
            value = self.unary()
            if isinstance(value, Address):
                raise Unresolved()
            return {"-": -value, "+": value, "~": ~value, "!": int(not value)}[operator]
        return self.primary()

    def primary(self):
        if self.position >= len(self.tokens):
            raise ValueError("expression ends early")
        kind, text = self.tokens[self.position]
        self.position += 1
        if text == "(":
            value = self.binary(0)
            if self.peek() != ")":
                raise ValueError("missing )")
            self.position += 1
            return value
        if kind == "number":
            return number_value(text)
        if kind == "string":
            return int.from_bytes(string_bytes(text), "little")
        if kind == "name":
            if text == "$":
                return self.here
            if text == "$$":
                return Address(self.here.section, 0)
            if text in self.symbols:
                return self.symbols[text]
            raise Unresolved()
        raise ValueError("unexpected %r" % text)


def combine(operator, left, right):
    if isinstance(left, Address) or isinstance(right, Address):
        if operator == "-" and isinstance(left, Address) and isinstance(right, Address):
            if left.section == right.section and left.offset is not None and right.offset is not None:
                return left.offset - right.offset
            raise Unresolved()
        if operator in ("+", "-") and isinstance(left, Address) and isinstance(right, int):
            offset = None if left.offset is None else left.offset + (right if operator == "+" else -right)
            return Address(left.section, offset)
        if operator == "+" and isinstance(left, int) and isinstance(right, Address):
            return Address(right.section, None if right.offset is None else right.offset + left)
        raise Unresolved()
    if operator == "+":
        return left + right
    if operator == "-":
        return left - right
    if operator == "*":
        return left * right
    if operator in ("/", "//"):
        return int(left / right) if right else 0
    if operator in ("%", "%%"):
        return (abs(left) % abs(right)) * (1 if left >= 0 else -1) if right else 0
    if operator == "<<":
        return left << right
    if operator == ">>":
        return left >> right
    if operator == "&":
        return left & right
    if operator == "|":
        return left | right
    return left ^ right


def split_top_level(text, separator=","):
    """Split on a separator outside quotes, brackets and parentheses."""
    parts, depth, quote, current = [], 0, None, []
    for character in text:
        if quote:
            current.append(character)
            if character == quote:
                quote = None
            continue
        if character in "'\"`":
            quote = character
        elif character in "([":
            depth += 1
        elif character in ")]":
            depth -= 1
        elif character == separator and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(character)
    if "".join(current).strip() or parts:
        parts.append("".join(current).strip())
    return parts


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

# ----------------------------------------------------------------------------
# Reading the preprocessed corpus
# ----------------------------------------------------------------------------


class Line:
    """One statement of preprocessed assembly, with where it came from."""

    def __init__(self, corpus_file, source, text):
        self.corpus_file = corpus_file
        self.source = source
        self.text = text
        self.label = None
        self.kind = None          # "instruction", "directive" or None
        self.word = None          # the mnemonic, or the directive's name
        self.arguments = ""
        self.repeated = False     # carries a `times` prefix
        self.section = None


def relative_source(path):
    path = os.path.abspath(path)
    for base in (CORPUS, INCLUDE):
        if path.startswith(base + os.sep):
            return os.path.relpath(path, base)
    return os.path.basename(path)


def read_line_markers(output, corpus_file):
    """Yield (source, text) for each line of `nasm -E` output, following its
    %line markers back to the file and line each statement came from."""
    current_file, current_line, step = corpus_file, 1, 1
    for raw in output.splitlines():
        marker = re.match(r"%line\s+(\d+)(?:\+(\d+))?\s*(.*)$", raw)
        if marker:
            current_line = int(marker.group(1))
            step = int(marker.group(2)) if marker.group(2) is not None else 1
            if marker.group(3):
                current_file = relative_source(marker.group(3).strip())
            continue
        yield "%s:%d" % (current_file, current_line), raw
        current_line += step


def split_times(arguments):
    """Split `times <count> <statement>` into the count and the statement."""
    pieces, depth, current = [], 0, []
    for character in arguments.strip():
        if character in "([":
            depth += 1
        elif character in ")]":
            depth -= 1
        if character.isspace() and depth == 0:
            if current:
                pieces.append("".join(current))
                current = []
            continue
        current.append(character)
    if current:
        pieces.append("".join(current))
    count = []
    for index, piece in enumerate(pieces):
        operator_before = count and re.search(r"[-+*/%&|^~(<>]$", count[-1])
        if count and re.match(r"[A-Za-z_]\w*$", piece) and not operator_before and not re.match(r"[-+*/%&|^~)]", piece):
            return " ".join(count), " ".join(pieces[index:])
        count.append(piece)
    return " ".join(count), ""


def parse_statement(line, text, known_words):
    text = text.strip()
    if not text:
        return
    label = re.match(r"(%s)\s*:(?!:)\s*" % IDENTIFIER, text)
    if label and not re.match(r"\[", text):
        line.label = label.group(1)
        text = text[label.end():]
    else:
        bare = re.match(r"(%s)\s+(\w+)\b" % IDENTIFIER, text)
        if bare and bare.group(2).lower() in set(DATA_UNITS) | set(RESERVE_UNITS) | {"equ", "times"} \
                and bare.group(1).lower() not in known_words:
            line.label = bare.group(1)
            text = text[len(bare.group(1)):].strip()
    if not text:
        return
    primitive = re.match(r"\[\s*(\w+)\b\s*(.*?)\s*\]$", text)
    if primitive and primitive.group(1).lower() in PRIMITIVES:
        line.kind, line.word, line.arguments = "directive", primitive.group(1).lower(), primitive.group(2)
        if line.word == "segment":
            line.word = "section"
        return
    word, _, rest = text.partition(" ")
    word_lower = word.lower()
    if word_lower == "times":
        count, statement = split_times(rest)
        line.repeated = True
        line.times_count = count
        parse_statement(line, statement, known_words)
        return
    if word_lower in DATA_UNITS or word_lower in RESERVE_UNITS or word_lower in ("equ", "incbin", "align", "alignb") \
            or word_lower in PRIMITIVES:
        line.kind, line.word, line.arguments = "directive", word_lower, rest.strip()
        return
    if word_lower in PREFIXES:
        prefixed, _, rest = rest.strip().partition(" ")
        word_lower = (word_lower + " " + prefixed.lower()).strip()
    line.kind, line.word, line.arguments = "instruction", word_lower, rest.strip()


def preprocess(entry):
    command = ["nasm", "-E", "-f", "elf64"]
    if entry["kind"] == "library":
        command.append("-DPIC")
    command += ["-I" + INCLUDE + os.sep, os.path.join(CORPUS, entry["file"])]
    with tempfile.TemporaryDirectory() as scratch:
        # nasm searches the current directory first, so run it somewhere
        # that holds no coreasm/ of its own.
        result = subprocess.run(command, cwd=scratch, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit("shapes: nasm -E failed on %s:\n%s" % (entry["file"], result.stderr))
    return result.stdout


def read_corpus_file(entry):
    """Parse one preprocessed corpus file into Lines, and resolve the labels
    and `equ` constants that can be known without encoding instructions."""
    output = preprocess(entry)
    lines = []
    for source, raw in read_line_markers(output, entry["file"]):
        text = strip_comment(raw)
        if not text.strip():
            continue
        line = Line(entry["file"], source, " ".join(text.split()))
        lines.append(line)
    known_words = set()
    for line in lines:
        parse_statement(line, line.text, known_words)

    symbols, offsets = {}, collections.defaultdict(int)
    section, scope = ".text", ""
    for line in lines:
        line.section = section
        here = Address(section, offsets[section])
        if line.label:
            name = line.label
            if name.startswith(".") and not name.startswith(".."):
                name = scope + name
            elif not name.startswith(".."):
                scope = name
            line.qualified_label = name
            if line.word != "equ":
                symbols[name] = here
        if line.kind == "directive" and line.word == "section":
            section = line.arguments.split()[0] if line.arguments else ".text"
            line.section = section
            continue
        if line.kind == "directive" and line.word == "equ" and line.label:
            try:
                symbols[line.qualified_label] = Evaluator(symbols, here).evaluate(tokenize(line.arguments))
            except (Unresolved, ValueError):
                pass
            continue
        size = None
        try:
            size = statement_size(line, symbols, here)
        except (Unresolved, ValueError, ZeroDivisionError):
            size = None
        if size is None or offsets[section] is None:
            offsets[section] = None
        else:
            offsets[section] += size
    for line in lines:
        line.symbols = symbols
    return lines, output


def statement_size(line, symbols, here):
    if line.kind == "instruction":
        # `align` pads a data section with `times ... nop`, so the one
        # instruction whose size matters for data offsets is nop.
        if line.word == "nop" and not line.arguments:
            count = Evaluator(symbols, here).evaluate(tokenize(line.times_count)) if line.repeated else 1
            return count
        return None
    if line.kind != "directive":
        return 0
    if line.word in DATA_UNITS:
        unit = DATA_UNITS[line.word]
        total = 0
        for item in split_top_level(line.arguments):
            if re.match(r"^(['\"`]).*\1$", item):
                length = len(string_bytes(item))
                total += max(unit, -(-length // unit) * unit)
            else:
                total += unit
        size = total
    elif line.word in RESERVE_UNITS:
        size = RESERVE_UNITS[line.word] * Evaluator(symbols, here).evaluate(tokenize(line.arguments))
    elif line.word in PRIMITIVES:
        return 0
    else:
        return None
    if line.repeated:
        size *= Evaluator(symbols, here).evaluate(tokenize(line.times_count))
    return size

# ----------------------------------------------------------------------------
# Classifying instructions
# ----------------------------------------------------------------------------


class Operand:
    def __init__(self, text):
        self.text = text
        self.shape = None
        self.register = None
        self.size = None           # bits, from a register or a size word
        self.memory = None         # dict of base, index, scale, displacement form
        self.value = None          # an immediate's value, when it is a number
        self.symbolic = False      # names a label


def resolve(expression, symbols):
    """The integer value of an expression (its text or its tokens), or None
    when it names a label or cannot be read."""
    try:
        tokens = tokenize(expression) if isinstance(expression, str) else expression
        value = Evaluator(symbols, Address(None, None)).evaluate(tokens)
    except (Unresolved, ValueError, ZeroDivisionError, TypeError):
        return None
    return value if isinstance(value, int) else None


def immediate_shape(value, size):
    if size == 8:
        return "imm8"
    if -128 <= value <= 127:
        return "imm8"
    if size == 16:
        return "imm16"
    if -2 ** 31 <= value < 2 ** 31:
        return "imm32"
    if 0 <= value < 2 ** 32:
        return "imm32u"
    return "imm64"


def classify_memory(operand, inner, symbols):
    tokens = tokenize(inner)
    relative = absolute = False
    while tokens and tokens[0][0] == "name" and tokens[0][1].lower() in ("rel", "abs"):
        relative = relative or tokens[0][1].lower() == "rel"
        absolute = absolute or tokens[0][1].lower() == "abs"
        tokens = tokens[1:]
    segment = None
    if len(tokens) > 1 and tokens[1][1] == ":" and tokens[0][1].lower() in REGISTER_CLASS:
        segment = tokens[0][1].lower()
        tokens = tokens[2:]
    terms, current, sign, depth = [], [], "+", 0
    for kind, text in tokens:
        if text == "(":
            depth += 1
        elif text == ")":
            depth -= 1
        if depth == 0 and text in ("+", "-") and current and (current[-1][0] in ("number", "name", "string") or current[-1][1] == ")"):
            terms.append((sign, current))
            current, sign = [], text
            continue
        if depth == 0 and text in ("+", "-") and not current:
            sign = "-" if (sign == "-") != (text == "-") else "+"
            continue
        current.append((kind, text))
    if current:
        terms.append((sign, current))
    base = index = None
    scale = 1
    displacement = []
    for sign, term in terms:
        names = [text.lower() for kind, text in term]
        if len(term) == 1 and names[0] in REGISTER_CLASS and sign == "+":
            if base is None:
                base = names[0]
            else:
                index = names[0]
            continue
        if len(term) == 3 and term[1][1] == "*":
            if names[0] in REGISTER_CLASS:
                index, scale = names[0], number_value(term[2][1]) if term[2][0] == "number" else 1
                continue
            if names[2] in REGISTER_CLASS:
                index, scale = names[2], number_value(term[0][1]) if term[0][0] == "number" else 1
                continue
        displacement.append((sign, term))
    numeric, symbolic = 0, False
    for sign, term in displacement:
        value = resolve(term, symbols)
        if value is None:
            symbolic = True
        else:
            numeric += value if sign == "+" else -value
    if symbolic:
        form = "label+disp" if numeric else "label"
    elif not displacement or numeric == 0:
        form = None
    elif -128 <= numeric <= 127 and (base or index):
        form = "disp8"
    else:
        form = "disp32"
    parts = []
    if relative:
        parts.append("rel")
    if base:
        parts.append("reg")
    if index:
        parts.append("reg*scale")
    if form:
        parts.append(form)
    shape = "[" + ("rel " + "+".join(parts[1:]) if relative else "+".join(parts)) + "]"
    if segment:
        shape = segment + ":" + shape
    operand.memory = {"base": base, "index": index, "scale": scale, "form": form, "relative": relative,
                      "absolute": absolute, "symbolic": symbolic, "segment": segment, "displacement": numeric}
    operand.symbolic = symbolic
    return shape


def classify_operand(text, mnemonic, symbols):
    operand = Operand(text)
    words = text.split()
    size_word, qualifier = None, None
    while len(words) > 1 and words[0].lower() in set(SIZE_WORDS) | JUMP_QUALIFIERS:
        if words[0].lower() in SIZE_WORDS:
            size_word = words[0].lower()
        else:
            qualifier = words[0].lower()
        words = words[1:]
    body = " ".join(words)
    lower = body.lower()
    if size_word:
        operand.size = SIZE_WORDS[size_word]
    if body.startswith("[") and body.endswith("]") or re.match(r"\w+:\[", body):
        inner = body[body.index("[") + 1:-1]
        prefix = body[:body.index("[")]
        shape = classify_memory(operand, (prefix.rstrip(":") + ":" if prefix else "") + inner, symbols)
        operand.shape = (size_word + " " if size_word else "") + shape
        return operand
    if lower in REGISTER_CLASS:
        operand.register = lower
        operand.size = REGISTER_BITS.get(lower)
        operand.shape = REGISTER_CLASS[lower]
        return operand
    if mnemonic in JUMPS:
        operand.symbolic = True
        operand.shape = (qualifier + " " if qualifier else "") + "label"
        return operand
    value = resolve(body, symbols)
    if value is None:
        operand.symbolic = True
        operand.shape = "imm(label)"
    else:
        operand.value = value
        operand.shape = "imm"
    if size_word:
        operand.shape = size_word + " " + operand.shape
    return operand


class Instruction:
    def __init__(self, line, mnemonic, operands):
        self.line = line
        self.mnemonic = mnemonic
        self.operands = operands
        self.shape = ", ".join(operand.shape for operand in operands)


def classify_instruction(line):
    mnemonic = line.word
    operands = [classify_operand(text, mnemonic.split()[-1], line.symbols) for text in split_top_level(line.arguments)] \
        if line.arguments else []
    operation_size = next((operand.size for operand in operands if operand.size), None)
    for position, operand in enumerate(operands):
        if operand.value is not None:
            if mnemonic in SHIFTS and operand.value == 1 and position == len(operands) - 1:
                width = "1"
            else:
                width = immediate_shape(operand.value, operation_size)
            operand.shape = operand.shape.replace("imm", width, 1)
    # Name the register where the encoding depends on which one it is.
    for position, operand in enumerate(operands):
        name = operand.register
        if not name:
            continue
        if mnemonic in SHIFTS and name == "cl" and position == len(operands) - 1:
            operand.shape = "cl"
        elif mnemonic in ACCUMULATOR_FORMS and position == 0 and name in ACCUMULATOR and len(operands) == 2 \
                and "imm" in operands[1].shape:
            if mnemonic == "test" or name == "al" or not operands[1].shape.endswith("imm8"):
                operand.shape = name
        elif mnemonic == "xchg" and name in ACCUMULATOR - {"al"} and len(operands) == 2 \
                and all(other.register for other in operands):
            operand.shape = name
    return Instruction(line, mnemonic, operands)


def encoding_cases(instruction):
    """The encoding traps this instruction exercises, by name."""
    cases = []
    registers = [operand.register for operand in instruction.operands if operand.register]
    memory = [operand.memory for operand in instruction.operands if operand.memory]
    for found in memory:
        registers += [name for name in (found["base"], found["index"]) if name]
    if any(name in EXTENDED for name in registers):
        cases.append("a register r8 to r15 (REX.R, REX.X or REX.B)")
    if any(name in UNIFORM_BYTE for name in registers):
        cases.append("spl, bpl, sil or dil (a REX prefix with no other bit set)")
    if any(name in HIGH_BYTE for name in registers):
        cases.append("ah, ch, dh or bh (no REX prefix allowed)")
    # The operand-size prefix follows the operation's size; a zero- or
    # sign-extending move takes its 16-bit source without one.
    sized = instruction.operands[:1] if instruction.mnemonic in ("movzx", "movsx", "movsxd") \
        else instruction.operands
    if any(operand.size == 16 and (operand.register or operand.memory) for operand in sized):
        cases.append("a 16-bit operand (0x66 prefix)")
    for found in memory:
        if found["base"] in ("rsp", "r12", "esp", "r12d"):
            cases.append("memory based on rsp or r12 (needs a SIB byte)")
        if found["base"] in ("rbp", "r13", "ebp", "r13d") and found["form"] is None:
            cases.append("memory [rbp] or [r13] with no displacement (needs disp8 0)")
        if found["index"]:
            cases.append("memory with an index register (SIB byte)")
        if any(name and REGISTER_CLASS.get(name) == "r32" for name in (found["base"], found["index"])):
            cases.append("a 32-bit address register (0x67 prefix)")
        if found["relative"]:
            cases.append("RIP-relative memory [rel label]")
        if not found["base"] and not found["index"] and not found["relative"]:
            cases.append("absolute memory [label] (SIB with no base, disp32)")
        if found["form"] == "disp8":
            cases.append("an 8-bit displacement")
        if found["form"] == "disp32":
            cases.append("a 32-bit displacement")
        if found["segment"]:
            cases.append("a segment override")
    sizes = [operand.size for operand in instruction.operands if operand.size]
    for operand in instruction.operands:
        if operand.shape.endswith("imm8") and sizes and max(sizes) > 8 and instruction.mnemonic != "mov":
            cases.append("an imm8 sign-extended into a wider operation")
        if operand.shape.endswith("imm64"):
            cases.append("a full 64-bit immediate")
    if instruction.mnemonic in JUMPS and any(operand.shape.endswith("label") for operand in instruction.operands):
        cases.append("a jump or call to a label (rel32 in vas)")
    if instruction.mnemonic.split()[0] in PREFIXES:
        cases.append("a %s prefix" % instruction.mnemonic.split()[0])
    return cases

# ----------------------------------------------------------------------------
# Assembling one line
# ----------------------------------------------------------------------------


def substitute(text, symbols, replacement):
    """Rewrite an instruction's operands with each label replaced, and each
    constant replaced by its value."""
    def replace(match):
        name = match.group(0)
        lower = name.lower()
        if lower in REGISTER_CLASS or lower in SIZE_WORDS or lower in JUMP_QUALIFIERS or lower in ("rel", "abs"):
            return name
        if name in ("$", "$$"):
            return name
        value = symbols.get(name)
        if isinstance(value, int):
            return str(value)
        return replacement(name)
    pieces = re.split(r"('[^']*'|\"[^\"]*\"|`(?:[^`\\]|\\.)*`)", text)
    for index in range(0, len(pieces), 2):
        pieces[index] = re.sub(r"(?<![\w.?@$#~])" + IDENTIFIER, replace, pieces[index])
    return "".join(pieces)


def hex_bytes(data):
    return " ".join("%02x" % byte for byte in data)


def assemble_bin(statement, labels, scratch, near=False):
    """Assemble one line with `nasm -f bin` at ORIGIN. Its labels sit at the
    fixed address FAR_LABEL (eight bytes apart), in a section that takes no
    room in the output; or, with near set, straight after the line."""
    source = os.path.join(scratch, "line.asm")
    binary = os.path.join(scratch, "line.bin")
    with open(source, "w") as handle:
        handle.write("bits 64\norg 0x%x\nsection .text\n%s\n" % (ORIGIN, statement))
        if near:
            handle.write("".join("%s:\n" % label for label in labels))
        elif labels:
            handle.write("section far nobits vstart=0x%x\n" % FAR_LABEL)
            handle.write("".join("%s: resb 8\n" % label for label in labels))
    result = subprocess.run(["nasm", "-f", "bin", "-o", binary, source], cwd=scratch, capture_output=True, text=True)
    if result.returncode != 0:
        return None, first_message(result.stderr)
    with open(binary, "rb") as handle:
        return handle.read(), first_message(result.stderr)


def assemble_object(statement, labels, scratch):
    """Assemble the line into an ELF object with its labels defined as real
    symbols, and read the bytes from nasm's listing. A relocated field is
    shown in brackets, as zeros: the linker fills it in."""
    source = os.path.join(scratch, "object.asm")
    listing = os.path.join(scratch, "object.lst")
    with open(source, "w") as handle:
        handle.write("bits 64\nsection .text\n%s\nsection .data\n" % statement)
        for label in labels:
            handle.write("%s: dq 0\n" % label)
    result = subprocess.run(["nasm", "-f", "elf64", "-l", listing, "-o", os.path.join(scratch, "object.o"), source],
                            cwd=scratch, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    fields = []
    with open(listing) as handle:
        for row in handle:
            match = re.match(r"\s*(\d+)\s+[0-9A-F]{8}\s+(\S+)", row)
            if match and match.group(1) == "3":
                fields.append(match.group(2).rstrip("-"))
    text = "".join(fields)
    rendered, position = [], 0
    while position < len(text):
        character = text[position]
        if character in "[(":
            close = text.index("]" if character == "[" else ")", position)
            inner = text[position + 1:close]
            rendered.append("[" + " ".join(inner[i:i + 2].lower() for i in range(0, len(inner), 2)) + "]")
            position = close + 1
        else:
            rendered.append(text[position:position + 2].lower())
            position += 2
    return " ".join(rendered)


def first_message(stderr):
    for row in stderr.splitlines():
        message = re.sub(r"^\S+:\d+:\s*", "", row).strip()
        if message:
            return message
    return ""


def assemble_shape(instruction, scratch):
    """The bytes nasm assembles the example line to, the object-file bytes
    when the line names a label, and the flags worth an encoder's attention."""
    line = instruction.line
    flags = []
    labels = []

    def rename(name):
        if name not in labels:
            labels.append(name)
        return "L%d" % labels.index(name)
    statement = "%s %s" % (instruction.mnemonic, substitute(line.arguments, line.symbols, rename))
    placed = ["L%d" % number for number in range(len(labels))]
    data, warning = assemble_bin(statement, placed, scratch)
    if data is None:
        return "-", "-", ["nasm -f bin refused the line: %s" % warning]
    if warning:
        flags.append("nasm warns: %s" % warning)
    object_bytes = "-"
    if placed and instruction.mnemonic in JUMPS:
        near_data, _ = assemble_bin(statement, placed, scratch, near=True)
        if near_data is not None and len(near_data) < len(data):
            flags.append("rel8: nasm encodes a target in reach as %s; vas always encodes rel32"
                         % hex_bytes(near_data))
    elif placed:
        object_bytes = assemble_object(statement, placed, scratch) or "-"
        if object_bytes != "-" and len(object_bytes.replace("[", "").replace("]", "").split()) != len(data):
            flags.append("object form: in an object file nasm encodes the symbol at full width (object_bytes), "
                         "longer than in -f bin")
    first = data[1] if data[0] in range(0x40, 0x50) and len(data) > 1 else data[0]
    operands = instruction.operands
    if instruction.mnemonic == "mov" and len(operands) == 2 and operands[0].shape == "r64" \
            and operands[1].value is not None and 0xB8 <= first <= 0xBF and len(data) <= 6:
        flags.append("nasm encodes this 64-bit mov as a 32-bit mov (no REX.W), which zero-extends")
    if any(operand.shape in ACCUMULATOR for operand in operands) and instruction.mnemonic in ACCUMULATOR_FORMS:
        flags.append("accumulator short form")
    if instruction.mnemonic == "xchg" and any(operand.shape in ACCUMULATOR for operand in operands):
        flags.append("accumulator short form (90+r)")
    if instruction.mnemonic in SHIFTS and operands and operands[-1].shape == "1":
        flags.append("shift-by-one form (D0/D1)")
    return hex_bytes(data), object_bytes, flags

# ----------------------------------------------------------------------------
# The raw source: features outside the accepted subset
# ----------------------------------------------------------------------------

# What the assembler brief accepts. Everything else found is listed as a
# decision to make.
ACCEPTED = {
    "%include", "%macro", "%endmacro", "%%local label", "macro parameter (%1, %2, ...)",
    "section .data", "section .text", "section .bss", "section .note.GNU-stack noalloc noexec nowrite progbits",
    "global", "db", "dw", "dd", "dq", "resb", "resq", "equ",
    "label name:", "local label .name:",
    "decimal constant", "hexadecimal constant 0x...", "binary constant 0b...", "character constant",
    "string constant in quotes", "size word byte", "size word dword", "size word qword", "rel",
    "operator +", "operator -", "operator *", "parentheses", "$ (current address)", "$$ (section start)",
}


def includes_of(path):
    found = []
    with open(path, errors="replace") as handle:
        for row in handle:
            match = re.match(r"\s*%include\s+[\"'<]([^\"'>]+)[\"'>]", row)
            if match:
                name = match.group(1)
                for base in (os.path.dirname(path), INCLUDE):
                    candidate = os.path.join(base, name)
                    if os.path.isfile(candidate):
                        found.append(os.path.abspath(candidate))
                        break
    return found


def raw_features(path):
    """Yield (feature, line number) for every NASM feature on every line."""
    with open(path, errors="replace") as handle:
        rows = handle.read().splitlines()
    for number, row in enumerate(rows, 1):
        code = strip_comment(row).strip()
        if not code:
            continue
        strings = re.findall(r"'[^']*'|\"[^\"]*\"|`(?:[^`\\]|\\.)*`", code)
        for spelling in strings:
            if spelling.startswith("`"):
                yield "backquoted string with escapes", number
        bare = re.sub(r"'[^']*'|\"[^\"]*\"|`(?:[^`\\]|\\.)*`", " S ", code)
        first = bare.split()[0] if bare.split() else ""
        directive = re.match(r"%[a-zA-Z]+", first)
        if directive and not first.startswith("%%"):
            name = directive.group(0).lower()
            yield name, number
            if name in ("%define", "%xdefine", "%assign"):
                # The body of a definition is assembled wherever it is
                # used, so its constants and operators count too.
                body = bare.split(None, 2)
                bare = body[2] if len(body) > 2 else ""
                code = bare
            elif name in ("%undef", "%ifdef", "%ifndef", "%macro", "%include", "%error", "%warning"):
                continue
        if re.search(r"%%\w", bare):
            yield "%%local label", number
        if re.search(r"%[1-9]\d*", bare):
            yield "macro parameter (%1, %2, ...)", number
        if re.search(r"%0\b", bare):
            yield "%0 (parameter count)", number
        if "%+" in bare:
            yield "%+ (token pasting)", number
        if re.search(r"%\{", bare):
            yield "%{...} (brace parameter)", number
        if re.search(r"%\$", bare):
            yield "%$ (context-local name)", number
        if re.search(r"__\??\w+\??__", bare):
            yield "standard macro %s" % re.search(r"__\??\w+\??__", bare).group(0), number
        statement = bare
        label = re.match(r"\s*((?:%%)?\w[\w.?@$#~]*|\.[\w.?@$#~]+)\s*:", statement)
        if label:
            if label.group(1).startswith("%%"):
                pass
            elif label.group(1).startswith("."):
                yield "local label .name:", number
            else:
                yield "label name:", number
            statement = statement[label.end():]
        words = statement.split()
        if not words:
            continue
        head = words[0].lower()
        if len(words) > 1 and not label and words[1].lower() in set(DATA_UNITS) | set(RESERVE_UNITS) | {"equ"} \
                and not head.startswith("%"):
            yield "label without a colon", number
            words = words[1:]
            head = words[0].lower()
        if head in ("section", "segment"):
            attributes = " ".join(words[1:])
            yield "section " + attributes, number
        elif head in ("global", "extern", "common", "static", "align", "alignb", "times", "incbin", "struc",
                      "endstruc", "istruc", "iend", "at", "org", "cpu", "absolute"):
            yield head, number
        elif head in ("default", "bits"):
            yield head + " " + " ".join(words[1:2]), number
        elif head in DATA_UNITS or head in RESERVE_UNITS or head == "equ":
            yield head, number
        if strings and not head.startswith("%"):
            if head in DATA_UNITS:
                yield "string constant in quotes", number
            else:
                yield "character constant", number
        operands = re.sub(r"%%\w[\w.]*|%[0-9]+|%[a-zA-Z]+|%\+|%\$+\w*", " X ", statement)
        operands = re.sub(r"(?<![\w.?@$#~])%s" % IDENTIFIER, lambda match: " " + match.group(0) + " ", operands)
        for operator, name in (("<<", "operator << (shift left)"), (">>", "operator >> (shift right)"),
                               ("//", "operator // (signed divide)")):
            if operator in operands:
                yield name, number
                operands = operands.replace(operator, " ")
        for character, name in (("|", "operator | (or)"), ("&", "operator & (and)"), ("^", "operator ^ (xor)"),
                                ("~", "operator ~ (not)"), ("!", "operator ! (logical not)"),
                                ("/", "operator / (divide)"), ("%", "operator % (modulo)"),
                                ("+", "operator +"), ("*", "operator *")):
            if character in operands:
                yield name, number
        if re.search(r"[\w)\]]\s*-", operands):
            yield "operator -", number
        if "(" in operands:
            yield "parentheses", number
        if "$$" in operands:
            yield "$$ (section start)", number
        if re.search(r"(?<![\w$])\$(?![\w$])", operands):
            yield "$ (current address)", number
        lowered = operands.lower()
        for word in re.findall(r"[a-z_][\w]*", lowered):
            if word in SIZE_WORDS:
                yield "size word " + word, number
            elif word in ("rel", "abs", "wrt", "seg", "strict", "short", "near", "far"):
                yield word, number
            elif re.match(r"xmm\d+$", word):
                yield "SSE register (xmm)", number
            elif re.match(r"ymm\d+$", word):
                yield "AVX register (ymm)", number
            elif re.match(r"st\d$", word):
                yield "x87 register (st)", number
            elif re.match(r"mm\d$", word):
                yield "MMX register (mm)", number
        if re.search(r"\b[cdefgs]s\s*:", lowered):
            yield "segment override", number
        for token in re.findall(r"(?<![\w.$])[0-9][\w.]*", operands):
            lower = token.lower()
            if re.match(r"0x[0-9a-f_]+$", lower):
                yield "hexadecimal constant 0x...", number
            elif re.match(r"[0-9][0-9a-f_]*h$", lower):
                yield "hexadecimal constant ...h", number
            elif re.match(r"0b[01_]+$", lower):
                yield "binary constant 0b...", number
            elif re.match(r"[01_]+[by]$", lower):
                yield "binary constant ...b", number
            elif re.match(r"0[oq][0-7_]+$", lower) or re.match(r"[0-7_]+[oq]$", lower):
                yield "octal constant", number
            elif re.match(r"\d[\d_]*\.\d*(e[+-]?\d+)?$", lower) or re.match(r"\d+e[+-]?\d+$", lower):
                yield "floating-point constant", number
            elif re.match(r"\d[\d_]*$", lower):
                yield "decimal constant", number
        if re.search(r"(?<![\w.$])(__float\w+__|__Infinity__|__NaN__|__QNaN__|__SNaN__)", operands):
            yield "floating-point constant", number
        if re.search(r"(^|\s|,)\?(\s|,|$)", operands):
            yield "? (uninitialised data)", number

# ----------------------------------------------------------------------------
# Writing the tables
# ----------------------------------------------------------------------------


def markdown_cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def code_cell(text):
    if text in ("", "-"):
        return text
    return "`" + str(text).replace("`", "'").replace("|", "\\|") + "`"


def read_manifest():
    entries, compiler = [], "unknown"
    with open(os.path.join(CORPUS, "MANIFEST")) as handle:
        for row in handle:
            row = row.rstrip("\n")
            if row.startswith("# compiler:"):
                compiler = row.split(":", 1)[1].strip()
            if not row or row.startswith("#"):
                continue
            file, kind, source, needs = row.split("\t")
            entries.append({"file": file, "kind": kind, "source": source, "needs": needs})
    return entries, compiler


def jump_widths(entry, scratch):
    """Count the label jumps nasm encodes as rel8 when it assembles the whole
    corpus file, from its listing."""
    command = ["nasm", "-f", "elf64"]
    if entry["kind"] == "library":
        command.append("-DPIC")
    listing = os.path.join(scratch, "corpus.lst")
    command += ["-I" + INCLUDE + os.sep, "-l", listing, "-o", os.path.join(scratch, "corpus.o"),
                os.path.join(CORPUS, entry["file"])]
    subprocess.run(command, cwd=scratch, capture_output=True, check=True)
    short = total = 0
    with open(listing, errors="replace") as handle:
        for row in handle:
            match = re.match(r"\s*\d+\s+[0-9A-F]{8}\s+([0-9A-F\[\]()]+)(-?)\s+(?:<\d+>\s*)?(.*)$", row)
            if not match:
                continue
            statement = strip_comment(match.group(3)).strip()
            statement = re.sub(r"^%s\s*:\s*" % IDENTIFIER, "", statement)
            words = statement.split(None, 1)
            if len(words) != 2 or words[0].lower() not in JUMPS or words[0].lower() == "call":
                continue
            target = words[1].strip().lower()
            if target.startswith("[") or target in REGISTER_CLASS or "word" in target:
                continue
            total += 1
            if len(match.group(1)) == 4 and not match.group(2):
                short += 1
    return short, total


def main():
    entries, compiler = read_manifest()
    if not entries:
        sys.exit("shapes: the corpus manifest lists no files")

    shapes = collections.OrderedDict()
    shape_files = collections.defaultdict(set)
    directives = collections.OrderedDict()
    directive_files = collections.defaultdict(set)
    cases = collections.OrderedDict()
    instruction_count = 0
    source_lines = preprocessed_lines = 0

    for entry in entries:
        with open(os.path.join(CORPUS, entry["file"])) as handle:
            source_lines += sum(1 for _ in handle)
        lines, output = read_corpus_file(entry)
        preprocessed_lines += output.count("\n")
        for line in lines:
            if line.kind == "directive" or line.repeated:
                if line.repeated:
                    key = "times"
                    directives.setdefault(key, [0, line])[0] += 1
                    directive_files[key].add(entry["file"])
                if line.kind == "directive":
                    key = line.word
                    if key == "section":
                        key = "section " + line.arguments
                    elif key in ("default", "bits"):
                        key = key + " " + line.arguments
                    directives.setdefault(key, [0, line])[0] += 1
                    directive_files[key].add(entry["file"])
            if line.kind != "instruction":
                continue
            try:
                instruction = classify_instruction(line)
            except ValueError as error:
                sys.exit("shapes: cannot classify %s (%s): %s" % (line.source, line.text, error))
            instruction_count += 1
            key = (instruction.mnemonic, instruction.shape)
            if key not in shapes:
                shapes[key] = [0, instruction]
            shapes[key][0] += 1
            shape_files[key].add(entry["file"])
            for case in encoding_cases(instruction):
                cases.setdefault(case, [0, line])[0] += 1

    # The raw source, before preprocessing: every corpus file and every
    # coreasm file it reaches through %include.
    reached = collections.OrderedDict()
    for entry in entries:
        path = os.path.join(CORPUS, entry["file"])
        pending = [path]
        while pending:
            current = pending.pop(0)
            reached.setdefault(current, set()).add(entry["file"])
            for included in includes_of(current):
                if entry["file"] not in reached.get(included, set()):
                    pending.append(included)
    features = collections.OrderedDict()
    feature_files = collections.defaultdict(set)
    for path, corpus_files in reached.items():
        for feature, number in raw_features(path):
            if feature not in features:
                features[feature] = [0, "%s:%d" % (relative_source(path), number)]
            features[feature][0] += 1
            feature_files[feature] |= corpus_files

    coreasm_uses_times = any("times" in [f for f, _ in raw_features(path)] for path in reached
                             if path.startswith(CORE))

    # Operand forms outside the accepted list, from the classified shapes.
    accepted_memory = {"[reg]", "[reg+disp8]", "[reg+disp32]", "[label]", "[rel label]"}
    operand_forms = collections.OrderedDict()
    for (mnemonic, shape), (count, instruction) in shapes.items():
        for operand in instruction.operands:
            form = operand.shape.split(" ", 1)[1] if operand.shape.split(" ", 1)[0] in SIZE_WORDS else operand.shape
            outside = None
            if operand.memory and form not in accepted_memory:
                outside = "memory operand %s" % form
            elif operand.register and REGISTER_CLASS[operand.register] not in ("r64", "r32", "r16", "r8"):
                outside = "register class %s" % REGISTER_CLASS[operand.register]
            if outside:
                record = operand_forms.setdefault(outside, [0, instruction, set()])
                record[0] += count
                record[2] |= shape_files[(mnemonic, shape)]

    jumps_short = jumps_total = 0
    files_with_short = 0
    rows = []
    with tempfile.TemporaryDirectory() as scratch:
        for entry in entries:
            short, total = jump_widths(entry, scratch)
            jumps_short += short
            jumps_total += total
            files_with_short += 1 if short else 0
        for (mnemonic, shape), (count, instruction) in sorted(shapes.items()):
            data, object_bytes, flags = assemble_shape(instruction, scratch)
            rows.append({"mnemonic": mnemonic, "shape": shape, "count": count,
                         "files": len(shape_files[(mnemonic, shape)]),
                         "example": "%s %s" % (mnemonic, instruction.line.arguments) if instruction.line.arguments
                         else mnemonic,
                         "source": instruction.line.source, "bytes": data, "object": object_bytes,
                         "flags": "; ".join(flags)})

    with open(os.path.join(OUTPUT, "shapes.tsv"), "w") as handle:
        handle.write("mnemonic\toperands\tcount\tfiles\texample\tsource\tbytes\tobject_bytes\tflags\n")
        for row in rows:
            handle.write("\t".join(str(row[key]) if row[key] != "" else "-" for key in
                                   ("mnemonic", "shape", "count", "files", "example", "source", "bytes", "object",
                                    "flags")) + "\n")

    outside_rows = []
    for feature, (count, example) in features.items():
        # The brief accepts `times` only if coreasm uses it directly.
        accepted = feature in ACCEPTED or (feature == "times" and coreasm_uses_times)
        if not accepted:
            outside_rows.append((feature, count, len(feature_files[feature]), example))
    outside_rows.sort(key=lambda row: (-row[2], -row[1], row[0]))

    mnemonics = sorted({mnemonic for mnemonic, _ in shapes})
    write_markdown(entries, compiler, rows, directives, directive_files, outside_rows, operand_forms, cases,
                   instruction_count, mnemonics, source_lines, preprocessed_lines, jumps_short, jumps_total,
                   files_with_short, features)
    print("shapes: %d corpus files, %d instructions, %d mnemonics, %d shapes, %d features outside the subset, "
          "%d operand forms outside it" % (len(entries), instruction_count, len(mnemonics), len(rows),
                                           len(outside_rows), len(operand_forms)))


def write_markdown(entries, compiler, rows, directives, directive_files, outside_rows, operand_forms, cases,
                   instruction_count, mnemonics, source_lines, preprocessed_lines, jumps_short, jumps_total,
                   files_with_short, features):
    out = []
    write = out.append
    write("# Instruction shapes of the assembly corpus")
    write("")
    write("Written by `tests/toolchain/shapes.py` from the %d files in `tests/corpus/` (compiler: %s)."
          % (len(entries), compiler))
    write("Do not edit by hand: regenerate it whenever the corpus changes. The same rows, with their bytes,")
    write("are in `shapes.tsv` beside this file, the skeleton of the encoder's test table.")
    write("")
    write("## How it is derived")
    write("")
    write("Each corpus file is preprocessed with `nasm -E -f elf64` (and `-DPIC` for a library, as the")
    write("compiler does for `--shared`), with coreasm on the include path, so `%include` and every coreasm")
    write("macro is expanded. Every instruction is then classified as a mnemonic and an operand shape:")
    write("")
    write("- `r64`, `r32`, `r16`, `r8`: a general register. A register is named instead (`rax`, `al`, `cl`)")
    write("  where the encoding depends on which one it is: the shift count `cl`, the accumulator with an")
    write("  immediate where nasm uses the short accumulator form, and `xchg` with the accumulator.")
    write("- `xmm`, `st`, `mm`: SSE, x87 and MMX registers.")
    write("- `imm8`, `imm16`, `imm32`, `imm32u`, `imm64`: an immediate, by the smallest width that holds its")
    write("  value (`imm32u` holds it only as an unsigned 32-bit number). `equ` constants are evaluated where")
    write("  their value is known without encoding. `imm(label)` is an immediate that names a symbol. `1` is a")
    write("  shift by one, which has its own opcode.")
    write("- Memory: `[reg]`, `[reg+disp8]`, `[reg+disp32]`, `[reg+reg*scale+...]`, `[label]`, `[rel label]` and")
    write("  `[reg+label]`, prefixed by its size word when the line has one.")
    write("- `label`: the target of a jump or call.")
    write("")
    write("Counts are occurrences in the preprocessed corpus, so a coreasm line counts once for every corpus")
    write("file that includes it; *Files* is how many corpus files use the shape. Each shape's example line is")
    write("assembled on its own with `nasm -f bin` at `org 0x%x`, every constant replaced by its value and"
          % ORIGIN)
    write("every label placed at the fixed address `0x%x` (far enough that a jump to it needs rel32): that"
          % FAR_LABEL)
    write("is *Bytes*. A jump is assembled a second time with its target just after it, to see whether nasm")
    write("picks rel8. A line that names a symbol is also assembled into an ELF object with the symbol")
    write("defined, and the listing's bytes are *Object bytes*, a relocated field in brackets: that is the form")
    write("in a linked program.")
    write("")
    write("## Summary")
    write("")
    write("- %d corpus files: %d lines of compiler output, %d lines after preprocessing."
          % (len(entries), source_lines, preprocessed_lines))
    write("- %d instructions, %d distinct mnemonics, %d distinct mnemonic-and-shape pairs."
          % (instruction_count, len(mnemonics), len(rows)))
    write("- %d NASM syntax features and %d operand forms outside the accepted subset (the next section)."
          % (len(outside_rows), len(operand_forms)))
    write("- Jump widths: assembling the whole corpus, nasm encodes %d of %d jumps to a label as rel8, in %d"
          % (jumps_short, jumps_total, files_with_short))
    write("  of %d files. vas encodes every jump as rel32, so those files' bytes will differ from nasm's in"
          % len(entries))
    write("  the whole-program comparison, and are compared by running them instead.")
    write("")
    write("## Decisions: NASM features outside the accepted subset")
    write("")
    write("The assembler brief accepts a fixed subset of NASM and refuses everything else by name. These are")
    write("the features the corpus uses that the subset does not list. Each one needs a decision: add it to the")
    write("subset, or change the compiler or coreasm so the corpus stops using it.")
    write("")
    write("Syntax features are counted in the raw source the assembler reads: the corpus files and every")
    write("coreasm file they include, each coreasm file once. *Files* is how many corpus files reach the feature.")
    write("")
    write("| Feature | Occurrences | Files | First seen |")
    write("|---|---:|---:|---|")
    for feature, count, files, example in outside_rows:
        write("| %s | %d | %d | %s |" % (code_cell(feature), count, files, markdown_cell(example)))
    write("")
    write("Operand forms the subset does not list, counted in the preprocessed corpus:")
    write("")
    write("| Operand form | Occurrences | Files | Example | Source |")
    write("|---|---:|---:|---|---|")
    for form, (count, instruction, files) in operand_forms.items():
        example = "%s %s" % (instruction.mnemonic, instruction.line.arguments)
        write("| %s | %d | %d | %s | %s |" % (markdown_cell(form), count, len(files), code_cell(example),
                                              markdown_cell(instruction.line.source)))
    write("")
    write("Features of the subset the corpus does use, for reference: %s."
          % ", ".join(code_cell(feature) for feature in sorted(features) if feature in ACCEPTED))
    write("")
    write("## Instruction shapes")
    write("")
    write("*Flags* mark what an encoder has to match: `rel8` where nasm would pick a short jump for a target in")
    write("reach (vas always encodes rel32), the object form of a symbol operand, nasm's 32-bit encoding of a")
    write("64-bit `mov` of a small immediate, the accumulator and shift-by-one short forms, and any warning nasm")
    write("printed for the line.")
    write("")
    write("| Mnemonic | Operands | Count | Files | Example | Source | Bytes | Object bytes | Flags |")
    write("|---|---|---:|---:|---|---|---|---|---|")
    for row in rows:
        write("| %s | %s | %d | %d | %s | %s | %s | %s | %s |" % (
            code_cell(row["mnemonic"]), code_cell(row["shape"]) if row["shape"] else "", row["count"], row["files"],
            code_cell(row["example"]), markdown_cell(row["source"]), code_cell(row["bytes"]),
            code_cell(row["object"]), markdown_cell(row["flags"])))
    write("")
    write("## Directives")
    write("")
    write("Counted in the preprocessed corpus, where nasm has already rewritten `section`, `global` and")
    write("`extern` as their bracketed primitive forms and `align` as `times ... nop`.")
    write("")
    write("| Directive | Count | Files | Example | Source |")
    write("|---|---:|---:|---|---|")
    for key in sorted(directives):
        count, line = directives[key]
        write("| %s | %d | %d | %s | %s |" % (code_cell(key), count, len(directive_files[key]), code_cell(line.text),
                                             markdown_cell(line.source)))
    write("")
    write("## Encoding cases")
    write("")
    write("The encoding details the brief names as traps, with how often the corpus meets each one. Every case")
    write("here needs a focused encoder test.")
    write("")
    write("| Case | Count | Example | Source |")
    write("|---|---:|---|---|")
    for case in sorted(cases):
        count, line = cases[case]
        write("| %s | %d | %s | %s |" % (markdown_cell(case), count, code_cell(line.text), markdown_cell(line.source)))
    write("")
    with open(os.path.join(OUTPUT, "SHAPES.md"), "w") as handle:
        handle.write("\n".join(out))


if __name__ == "__main__":
    main()
