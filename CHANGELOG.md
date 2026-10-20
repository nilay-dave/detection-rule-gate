# Changelog

Kept by hand, in the format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
following [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A new check, or a check that starts firing where it did not before, is a minor
version at least. Something that fails a build which previously passed is not a
patch release however small the diff.

## [Unreleased]

## [0.1.0]

First release.

### Added

- Ten checks over Sigma rules, each with its default severity set from the rate
  it fires at on a pinned public corpus of 3,799 rules rather than from how
  serious the finding sounds.
- Two structural findings that no policy can downgrade: a file that does not
  parse, and a file that parses and is not a Sigma rule.
- A YAML loader that keeps the source position of every value, so a finding
  lands on a line rather than on a file, and that records a repeated mapping
  key instead of letting the parser discard it in silence.
- A condition parser, so a wildcard inside a negated filter is told apart from
  a wildcard that broadens a rule.
- Three output formats: text, GitHub annotations with a job summary, and SARIF
  2.1.0 for the security tab.
- A policy file, with an unknown check id as an error rather than a silent
  no-op, and per rule suppressions that require a written reason.
- A baseline, so the gate can be adopted on a corpus that already has findings.
- A composite GitHub Action and a pre-commit hook.

### Measured

- 3,799 rules in 1.594s, 2,383 rules per second, 85.4 MiB peak.
- 1,439 findings, of which 1,419 come from the two checks that default to a
  warning for exactly that reason.
- Six of the ten checks report nothing on the public corpus, which is correct:
  SigmaHQ validates its own content in CI.

### Known limitations

Multi document rule collections, correlation rules, field name validation,
changed files only, and autofix. Each with the condition that would trigger
building it, in `docs/limitations.md`.
