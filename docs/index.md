# detection rule gate

Fails a detection-as-code pull request when a Sigma rule is unmapped, unbounded
or missing the context an analyst needs at 03:00.

Detection content gets reviewed by people reading YAML in a diff. Application
code gets a linter. This is the linter.

## Start here

- [Checks](checks.md) is every check, its default severity and how often it
  fires on a pinned corpus of 3,799 real Sigma rules. Generated from the
  registry, so it cannot drift from the code.
- [False positives](false-positives.md) is the part no benchmark can do. Three
  of the original check designs flagged correct Sigma, and the only way to find
  out was to read every finding one rule at a time. All three are written up
  with the per rule reasoning.
- [Limitations](limitations.md) is what this deliberately does not do, each
  with the condition that would trigger building it.
- [Sources](sources.md) is where every allowed value comes from, pinned to a
  commit. The modifier allowlist was wrong the first time because it was
  written from memory.

## The design position in one paragraph

A gate is only useful if it stays turned on. Every default severity here was set
from how often the check fires on a real corpus rather than from how serious
the finding sounds, because a check that fails the build on a quarter of a
team's existing rules gets removed in its first week. A suppression requires a
written reason, so the gate cannot be silenced quietly one rule at a time. And
when a check turns out to flag correct content, that is published rather than
patched out, because the failure rate of a check is the number that decides
whether anyone trusts it.

## Install

```bash
pip install detection-rule-gate
drg check rules
```

Or as a GitHub Action, or a pre-commit hook. The
[readme](https://github.com/__GITHUB_USERNAME__/detection-rule-gate#install)
has all three.
