#!/usr/bin/env python3
"""The vas structure check: compare the operands the vas front end parses
with the ones tests/toolchain/shapes.py reads from `nasm -E`, instruction by
instruction, for every corpus file vas expands.

For each instruction, the mnemonic must agree, and so must every operand:
a register by name; a memory operand by its size word, base, index, scale,
whether it is relative to the instruction pointer, and its displacement;
an immediate or a jump target by its size word and value. Where vas has
worked out a value, shapes.py must have the same one. Where vas leaves a
value to the encoder, because it depends on a label, shapes.py may still
know it, since it measures data to place labels in data sections; those
are counted, and are what the encoder resolves.

Usage:
  structure_check.py <records program> <shapes.py> <corpus directory> <coreasm directory>

The records program is tests/toolchain/vas/records.vox, built.
"""

import importlib.util
import os
import subprocess
import sys
import tempfile


def refused_files():
    """The files vas refuses, by design: they hold constructs only a shared
    build writes. They are listed, each with its message, in
    refused_corpus_files.tsv beside this script, which expand_check.sh reads
    to check the refusals themselves."""
    listing = os.path.join(os.path.dirname(os.path.abspath(__file__)), "refused_corpus_files.tsv")
    with open(listing) as handle:
        return {row.split("\t", 1)[0] for row in handle if row.strip() and not row.startswith("#")}


REFUSED = refused_files()

MASK = (1 << 64) - 1


def signed(value):
    value &= MASK
    return value - (1 << 64) if value >> 63 else value


def size_word_of(operand, shapes):
    first = operand.shape.split(" ", 1)[0]
    return first if first in shapes.SIZE_WORDS else "-"


def nasm_signature(operand, shapes):
    """An operand as shapes.py read it, in the form records.vox writes."""
    if operand.register and not operand.memory:
        return "reg " + operand.register
    if operand.memory:
        found = operand.memory
        index = found["index"] or ""
        displacement = "?" if found["symbolic"] else str(signed(found["displacement"]))
        return "mem %s base=%s index=%s scale=%s rel=%d disp=%s" % (
            size_word_of(operand, shapes), found["base"] or "", index,
            found["scale"] if index else 0, 1 if found["relative"] else 0, displacement)
    value = "?" if operand.value is None else str(signed(operand.value))
    return "imm %s %s" % (size_word_of(operand, shapes), value)


def agrees(vas, nasm):
    """Does vas's operand agree with nasm's? Answers (agrees, left to the
    encoder): vas may leave a value unknown that shapes.py knows."""
    if vas == nasm:
        return True, False
    vas_words, nasm_words = vas.split(" "), nasm.split(" ")
    if len(vas_words) != len(nasm_words) or vas_words[0] != nasm_words[0]:
        return False, False
    if vas_words[:-1] != nasm_words[:-1]:
        return False, False
    if vas_words[-1] in ("?", "disp=?"):
        return True, True
    return False, False


def main(arguments):
    if len(arguments) != 4:
        sys.stderr.write(__doc__)
        return 2
    records, shapes_path, corpus, core = arguments
    os.environ["VOX_CORE_PATH"] = core
    specification = importlib.util.spec_from_file_location("shapes", shapes_path)
    shapes = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(shapes)
    shapes.CORPUS = os.path.abspath(corpus)
    shapes.CORE = os.path.abspath(core)
    shapes.INCLUDE = os.path.dirname(shapes.CORE)

    entries, _ = shapes.read_manifest()
    compared = left_to_encoder = files = 0
    failures = []
    with tempfile.TemporaryDirectory() as scratch:
        for entry in entries:
            if entry["file"] in REFUSED:
                continue
            files += 1
            lines, _ = shapes.read_corpus_file(entry)
            # nasm writes align N as a times ... nop over $ and $$; vas keeps
            # it as one align record, which records.vox does not list.
            nasm = [shapes.classify_instruction(line) for line in lines if line.kind == "instruction"
                    and not (line.repeated and line.word == "nop" and "$$" in line.times_count)]
            dump = os.path.join(scratch, "records.tsv")
            command = [records, os.path.join(shapes.CORPUS, entry["file"]), core, dump]
            if entry["kind"] == "library":
                command.append("PIC")
            result = subprocess.run(command, cwd=scratch, capture_output=True, text=True)
            if result.returncode != 0:
                failures.append("%s: records failed: %s" % (entry["file"], result.stderr.strip()[:200]))
                continue
            with open(dump) as handle:
                vas = [row.rstrip("\n").split("\t") for row in handle if row.strip()]
            if len(vas) != len(nasm):
                failures.append("%s: vas parsed %d instructions, nasm -E has %d" % (entry["file"], len(vas), len(nasm)))
                continue
            for parsed, instruction in zip(vas, nasm):
                compared += 1
                where, mnemonic, operands = parsed[0], parsed[1], parsed[2:]
                expected = [nasm_signature(operand, shapes) for operand in instruction.operands]
                problem = None
                if mnemonic != instruction.mnemonic:
                    problem = "mnemonic %s, nasm has %s" % (mnemonic, instruction.mnemonic)
                elif len(operands) != len(expected):
                    problem = "%d operands, nasm has %d" % (len(operands), len(expected))
                else:
                    for mine, theirs in zip(operands, expected):
                        same, left = agrees(mine, theirs)
                        if not same:
                            problem = "operand %r, nasm has %r" % (mine, theirs)
                            break
                        left_to_encoder += 1 if left else 0
                if problem:
                    failures.append("%s: %s (%s %s): %s" % (entry["file"], where, instruction.mnemonic,
                                                          instruction.line.arguments, problem))
    if failures:
        print("structure check: %d of %d instructions differ:" % (len(failures), compared))
        for failure in failures[:25]:
            print("  " + failure)
        if len(failures) > 25:
            print("  ... and %d more" % (len(failures) - 25))
        return 1
    print("structure check: all %d instructions in %d files parse as nasm reads them; "
          "%d operand values are left to the encoder" % (compared, files, left_to_encoder))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
