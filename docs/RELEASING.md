# Releasing

## Release notes
Every `## [x.y.z]` entry in CHANGELOG.md opens with one headline sentence on its own
paragraph, before any `###` section: the single most interesting user-visible change,
written for a stranger. A new keyword or capability beats a fix; a fix beats a
diagnostic; a diagnostic beats docs. Plain words, present tense, under 140 characters,
no em dash, no issue numbers, no code marks it cannot survive without (a keyword in
backticks is fine). The headlined change is ideally also the first bullet of the first
section.

The website's feed takes this paragraph's first sentence verbatim as the summary, and
the Mastodon announcement posts it as its second line — the headline IS the
announcement.

Example (0.4.14, had the rule existed):

> A new `Free` statement releases a buffer's memory the moment you are done with it.
