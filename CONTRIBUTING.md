# Contributing

## Running everything CI runs

```bash
make install
make verify
```

`verify` runs the same checks as CI, in the same order. A verify that is a
subset of CI is a verify that lies.

## Adding a check

Five things, and the fourth is the one that gets skipped.

**1. Write it in its own module under `src/drg/checks/`** and register it with
`@rule_check` or `@corpus_check`. Import the module in
`src/drg/checks/__init__.py`; registration happens on import and the list is
explicit rather than discovered, because a check that silently fails to
register is a check that silently stops gating.

**2. Write the rationale as if someone's pull request has just been blocked by
it.** The question they have is not what the rule is, it is why anyone enforces
it. That text goes into `drg explain`, into the SARIF help text, into the job
summary and into `docs/checks.md`, so it is written once.

**3. Add two fixtures, not one.** One rule in `tests/fixtures/violations/` that
raises it, and the negative case that must not raise it, in
`tests/fixtures/clean/` or as a unit test. Every check here that needed
redesigning needed it because the negative case was never written down.

**4. Measure the firing rate before choosing a severity.**

```bash
make corpus
drg check .corpus/sigma/rules --no-config --fail-on off
```

Then read the findings. All of them, if there are fewer than fifty. The
severity follows from the rate: a check that fires on a quarter of the corpus
is a warning however serious the finding is, because a gate that fails the
build on a quarter of a team's rules gets removed in its first week. Record the
rate in `docs/checks.md` by running `make bench && make docs`.

If the check raises findings that turn out to be correct Sigma, write that up in
`docs/false-positives.md` with the per rule reasoning rather than fixing it
silently. Three of the checks here have such an entry. The failure rate of a
check is the number that decides whether a team keeps the gate on.

**5. Regenerate the documentation.** `make docs`. CI fails when
`docs/checks.md` has drifted from the registry.

## House style

**No em dashes or en dashes.** Commas, colons and parentheses. `make verify`
checks at the Unicode code point level over every git tracked file.

**Escape pipes inside markdown table cells.** Sigma writes field modifiers with
a pipe and a pipe inside a cell ends it. `tools/check_tables.py` catches it;
this rule exists because it was forgotten in the one document whose main table
is a list of Sigma selections.

**Every dependency is justified.** Two are declared and
`tools/check_dependencies.py` fails the build on a third that nothing imports.
[ADR-001](docs/adr/adr-001-dependency-budget.md) is the budget and the reason
for it. A new dependency needs an ADR, not a commit.

**Published numbers carry a marker.** Any figure in the README or in `docs/`
that came from a measurement is tagged:

```
<!--number:rules_loaded-->3799<!--/number-->
```

`tools/check_numbers.py` compares it against `docs/metrics.json`, which
`make bench` regenerates from executed code. A number with no marker is a
number nobody is checking.

**Verify and commit are two steps.** Never `pytest && git commit`. Run the
tests, read the output, then commit. Chaining them is how a failing test ends
up in history.

## Commits

Conventional Commits, verified by `tools/check_commit_subject.py` as a
`commit-msg` hook:

```bash
ln -s ../../tools/check_commit_subject.py .git/hooks/commit-msg
```

The subject says what changed. The body says why, and what was tried and
rejected. A commit whose body would help whoever is reading `git log` in two
years at 02:00 is worth the four extra lines.

## Changing the corpus pin

The pin in `tools/fetch_corpus.py` moves only in a commit that also updates
`docs/metrics.json`. CI enforces this: the corpus job regenerates the metrics
and fails if the committed file differs. Otherwise the firing rates in the
documentation and the corpus they were measured against drift apart, and a
published benchmark becomes a historical artefact that still reads as current.
