# Vox style — writing code that reads

Vox's whole premise is that a program is a readable English document. A
name that would be fine in C — `i`, `tns`, `buf` — breaks that premise,
because it turns a sentence back into code. This guide is the house
style, derived from the reference programs in `examples/`: **`cat.vox`,
`pi.vox`, and `controller.vox` are the models.** When this document and
those files disagree, the files win.

## The test

**Read the whole line aloud. Does it sound like something a person would
say?** That is the entire standard; everything below is a consequence.

```vox
While steps is less than 500000,          (a person could say this)
While i is less than n,                   (nobody says this)

If 'wants help' then,                     (says itself)
If h then,                                (says nothing)
```

## Names are the thing's true name

The rule is **not** "long names." It is: the name must be what the thing
is actually called. Length is irrelevant; truthfulness is everything.

**Good, and short** — because these are the real names:

```vox
a float pi is 3.0.                        (pi IS its name)
a number called x is 0.                   (x IS a coordinate's name)
```

**Bad at any length** — placeholders, abbreviations, and mangles:

| Avoid | Why | Instead |
|---|---|---|
| `i`, `j`, `n`, `t` | placeholders, not names | `steps`, `attempt`, `'line number'` |
| `tns`, `buf`, `src`, `cfg` | abbreviations of real words | `timeout`, `content`, `source`, `settings` |
| `SafetyGate2`, `temp2` | a number instead of a distinction | name what makes the second one different |
| `flag1`, `data`, `thing` | says nothing about the role | `'wants version'`, `'staged output'` |

If two names need numbering, they have two different jobs — name the
jobs. If a name needs an abbreviation, Vox's quoted multi-word names
remove the excuse.

## Use quoted multi-word names freely

This is Vox's best naming feature and the examples lean on it:

```vox
A flag called 'we are numbering lines' is "--number" or "-n", it is a boolean.
a boolean called 'failed to open a file' is false.
A number called 'Line Number' is 1.
To 'read the file' with a file called source.
```

Note what `'we are numbering lines'` buys: `if 'we are numbering lines'
then,` needs no comment, no comparison, and no second reading.

## Booleans read as conditions

Name a boolean so the `if` line is a sentence — a claim that is true or
false, not a noun:

```vox
If 'wants help' then,                     (good)
If 'failed to open a file' then,          (good)
If help_flag is true then,                (weaker: noun, plus a redundant test)
```

`controller.vox` shows the pattern at its plainest: `door_open`,
`lift_moving`, `lift_full` — each reads as a statement of fact in the
condition.

## Function names read at the call site

A function's name is chosen for how the *call* reads, not the
definition. Vox's prepositions (`of`, `on`, `with`, `to`) are part of
the name's grammar:

```vox
'read the file' with source              (reads)
Print magnitude of origin.               (reads)
Print 'exit code of' of status.          (reads)
calc(s, 2)                               (not Vox, and not English)
```

## Loop variables name the item

The `each` form makes this natural — name the element, never the index:

```vox
Open a file called source for reading at each filename from arguments's all.
process of each finding from findings.
```

## Comments say why, not what

`pi.vox` is the model: the code says what, the comments say why it is
shaped that way.

```vox
(The denominator starts at two and grows by two each step)
a float denominator is 2.0.

(We alternate between adding and subtracting)
a float direction is 1.0.
```

A comment restating the line (`(add one to i)`) is noise. A comment
naming the intent, the source of an algorithm, or a non-obvious
constraint earns its place.

## Structure

- Group with blank lines **only at top level between complete
  constructs** — never inside a loop or conditional body, where a blank
  line silently closes the construct (see LANGUAGE.md, The termination
  rule).
- Prefer a named intermediate over a dense expression when the name adds
  meaning: `pi.vox` names `Ist`, `IInd`, `IIIrd` and `product` rather
  than nesting one long formula.
- Let messages be complete sentences: `"{Program}: {filename}: No such
  file or directory"` beats `"err: ENOENT"`.

## Scope of this guide

- **All new Vox** — examples, tests, `lib/`, and tooling written in Vox
  (vox-fuzz, the benchmarking tool) — follows this guide.
- **Rust inside the compiler** follows ordinary Rust conventions, but
  the anti-abbreviation spirit still applies: no `tns`, no `cfg2`.
- **The existing test suite predates this guide** and is full of `b`,
  `n`, `x`, `v`, `buf`. Those tests are not required to be rewritten;
  they are compiler-mechanics fixtures, and churning 600 files carries
  more risk than value. New tests follow the guide. Whether to retrofit
  any of them is the project owner's call, not a worker's.
