# detection-rule-gate

[![CI](https://github.com/__GITHUB_USERNAME__/detection-rule-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/__GITHUB_USERNAME__/detection-rule-gate/actions/workflows/ci.yml)
[![coverage](https://img.shields.io/endpoint?url=https://__GITHUB_USERNAME__.github.io/detection-rule-gate/badges/coverage.json)](https://__GITHUB_USERNAME__.github.io/detection-rule-gate/)
[![checks](https://img.shields.io/endpoint?url=https://__GITHUB_USERNAME__.github.io/detection-rule-gate/badges/checks.json)](docs/checks.md)
[![PyPI](https://img.shields.io/pypi/v/detection-rule-gate)](https://pypi.org/project/detection-rule-gate/)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![licence](https://img.shields.io/badge/licence-MIT-green)](LICENSE)

Fails a detection-as-code pull request when a Sigma rule is unmapped, unbounded
or missing the context an analyst needs at 03:00.

Detection content gets reviewed by people reading YAML in a diff. Application
code gets a linter. This is the linter.

## Install

As a GitHub Action:

```yaml
- uses: actions/checkout@v4
- uses: __GITHUB_USERNAME__/detection-rule-gate@v0.1.0
  with:
    paths: rules
```

As a pre-commit hook:

```yaml
repos:
  - repo: https://github.com/__GITHUB_USERNAME__/detection-rule-gate
    rev: v0.1.0
    hooks:
      - id: detection-rule-gate
```

Or directly:

```bash
pip install detection-rule-gate
drg check rules
```

## What it reports

```
rules/windows/proc_creation_win_susp_dump.yml
     14  error   unknown-field-modifier  'TargetFilename|endwith' uses an unknown modifier 'endwith'
     16  warning missing-falsepositives  level high rule whose only falsepositives entry is 'Unknown'

1 rule in 1 file: 2 findings (1 error, 1 warning)
failing on: error
```

Inside Actions it emits annotations on the diff. With `--format sarif` the
findings land in the GitHub security tab, where each one gets a page, a history
and a dismissal with a recorded reason.

## The ten checks

Full list with reasoning in [docs/checks.md](docs/checks.md).
`drg explain <check>` prints the same thing in the terminal.

| check | default | fires on the public corpus |
| --- | --- | --- |
| `unknown-field-modifier` | error | <!--number:checks.unknown-field-modifier.fired-->0<!--/number--> |
| `condition-undefined-selection` | error | <!--number:checks.condition-undefined-selection.fired-->0<!--/number--> |
| `condition-unparseable` | error | <!--number:checks.condition-unparseable.fired-->0<!--/number--> |
| `duplicate-yaml-key` | error | <!--number:checks.duplicate-yaml-key.fired-->0<!--/number--> |
| `duplicate-rule-id` | error | <!--number:checks.duplicate-rule-id.fired-->0<!--/number--> |
| `missing-rule-id` | error | <!--number:checks.missing-rule-id.fired-->0<!--/number--> |
| `missing-falsepositives` | warning | <!--number:checks.missing-falsepositives.fired-->949<!--/number--> |
| `attack-technique-missing` | warning | <!--number:checks.attack-technique-missing.fired-->470<!--/number--> |
| `broad-logsource` | warning | <!--number:checks.broad-logsource.fired-->19<!--/number--> |
| `unbounded-selection` | warning | <!--number:checks.unbounded-selection.fired-->1<!--/number--> |

Measured over <!--number:rules_loaded-->3799<!--/number--> rules from the public
SigmaHQ corpus at a pinned commit, in
<!--number:seconds_median-->1.594<!--/number-->s
(<!--number:rules_per_second-->2383.1<!--/number--> rules/s,
<!--number:peak_memory_mib-->85.4<!--/number--> MiB peak). `make bench`
reproduces every number here; `docs/metrics.json` holds them with the corpus
commit, and CI fails if the README drifts from it.

## Three things worth knowing before you turn this on

**Every default severity was set from the firing rate, not from how bad the
finding sounds.** `missing-falsepositives` fires on 25% of the public corpus. It
is still a warning by default, because a gate that fails the build on a quarter
of a team's existing rules gets removed in its first week.

**Six of the ten checks report nothing on the public corpus.** That is correct:
SigmaHQ validates its own content in CI, so anything published has already had
these caught. They are for the fork you maintain, where rules get copied as
starting points, identifiers get left behind and nobody runs SigmaHQ's CI.

**Three of the original checks were wrong, and flagged correct Sigma.** The
wildcard check raised 9 findings and 8 were valid content: `field: '*'` is how
Sigma says *this field is present*. The write up is in
[docs/false-positives.md](docs/false-positives.md), with the reasoning for each
rule and what the checks do now. An 89% false positive rate is not a check that
needs tuning; it is a check that teaches a team which flag turns the gate off.

## Adopting it on a corpus that already has findings

```bash
drg baseline rules            # record what is already wrong
drg check rules --baseline .drg-baseline.json
```

New findings fail. Recorded ones are reported as a count, and the output says
how many have since been fixed so the baseline can shrink. An entry carries a
count rather than a flag, so a second copy of a baselined finding is still new.

## Configuring it

`.detection-rule-gate.yml`, discovered by walking up from the target. This
repository's own is the worked example.

```yaml
fail_on: error

checks:
  missing-falsepositives: error      # a severity, or off
  attack-technique-missing:
    severity: warning
  unknown-field-modifier:
    options:
      extra_modifiers: [lookup]      # your pipeline's own

exclude:
  - 'deprecated/**'
```

An unknown check id is an error, not a silent no-op. A setting that applies to
nothing is a check you believe is configured until the day you look.

To silence one finding on one rule, in the rule file:

```yaml
# drg:ignore unbounded-selection reason: allowlist detection, breadth is the design
```

The reason is not optional. A suppression without one is itself a finding, and
so is a suppression naming a check that does not exist.

## Two dependencies

`pyyaml` and `pydantic`. The command line uses `argparse` rather than the Typer
the rest of this portfolio uses, because this installs on every pull request and
Typer brings seven more packages and 15MB for argument parsing the standard
library does. [ADR-001](docs/adr/adr-001-dependency-budget.md) has the
measurement, and the part of it I refused to publish because it turned out to be
noise.

## What it does not do

Field name validation, multi document rule collections, correlation rules,
autofix, changed-files-only. Each with the thing that would trigger building it
in [docs/limitations.md](docs/limitations.md).

It also does not convert rules. A rule that passes every check here can still
fail in `sigma convert`, which is pySigma's job. Run both; this one is the
cheaper to run on every commit.

## Development

```bash
make install
make verify      # everything CI runs, in the same order
make corpus      # fetch the public corpus at the pinned commit
make bench       # regenerate docs/metrics.json
```

## Licence

MIT. The rule corpus it is measured against is SigmaHQ's, under the Detection
Rule Licence, and is fetched rather than vendored.
