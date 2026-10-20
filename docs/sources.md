# Where the facts in this repository come from

Every list of allowed values in this tool is a claim about the Sigma
specification, and a wrong one produces false positives on correct content. The
modifier allowlist was wrong the first time, written from memory, which is
recorded in [false-positives.md](false-positives.md). This file is what makes
the second version checkable.

## The specification

| what | source | pinned at |
| --- | --- | --- |
| Field modifiers | `SigmaHQ/sigma-specification`, `specification/sigma-appendix-modifiers.md` | `ba9251aa834b11a70dbf80836b453dba99c5159e` |
| Rule fields, levels, statuses | `SigmaHQ/sigma-specification`, `specification/sigma-rules-specification.md`, version 2.1.0 | same commit |

The modifier set in `src/drg/checks/modifiers.py` is grouped exactly as the
appendix groups it, so the two can be read side by side:

- Generic: `all`, `startswith`, `endswith`, `contains`, `exists`, `cased`, `neq`
- String: `windash`
- Regular expression: `re`, with sub-modifiers `i`, `m`, `s`
- Encoding: `base64`, `base64offset`, `utf16le`, `utf16be`, `utf16`, `wide`
- Numeric: `lt`, `lte`, `gt`, `gte`
- Time: `minute`, `hour`, `day`, `week`, `month`, `year`
- Network: `cidr`
- Specific: `expand`, `fieldref`

Two things worth noting from the transcription. The regular expression flags are
sub-modifiers rather than modifiers, so they are valid only directly after
`re`, and the check enforces that. And `gzip`, which I had assumed was a
modifier, is not in the specification at all.

A pipeline that defines its own modifier is normal, and the check takes an
`extra_modifiers` option rather than requiring a fork.

## The rule corpus

| what | source | pinned at |
| --- | --- | --- |
| 3,799 rules | `SigmaHQ/sigma` | `e3f466211866e92553d8389d621ed13cfed5523d` |

Not vendored. `tools/fetch_corpus.py` holds the pin and reproduces the exact
tree; `.gitignore` keeps it out of the repository. Copying 3,799 third party
YAML files in would bury this project's own code in the language bar, put
somebody else's content in every diff, and make the corpus something that has
to be updated by hand.

Rules are read from `rules`, `rules-emerging-threats`, `rules-threat-hunting`,
`rules-compliance`, `rules-placeholder` and `rules-dfir`, which is every rule
directory the project publishes.

## Keeping the numbers and the corpus together

The pin moves only in a commit that also updates `docs/metrics.json`. That
keeps the firing rates in [checks.md](checks.md) and the corpus they were
measured against from drifting apart, which is the usual way a published
benchmark becomes a historical artefact that still reads as current.

`docs/metrics.json` records the corpus commit alongside every number, so any
figure in this repository can be traced to the tree it came from.

## What is not sourced from anywhere

The default severity of each check. Those were set from measured firing rates
on the corpus above, and the reasoning is in [checks.md](checks.md). They are a
judgement about what a team will tolerate on day one, not a fact about Sigma,
and a team is expected to change them.
