# ADR-001: Budget the dependencies, and refuse to publish the timing

Status: accepted
Date: 2026-10-20

## Context

This tool installs on every pull request that touches detection content. A
composite GitHub Action runs `pip install` on a fresh runner each time, so
every dependency is a download, an import and a supply chain edge paid
continuously rather than once.

The three preceding projects in this portfolio all use Typer for their command
line, and copying that choice here was the path of least resistance. Before
doing so I tried to measure what it costs.

## What I tried to measure, and why it is not in this document

The first measurement compared cold installs into fresh virtual environments:

```
baseline (empty venv)                5.67s   13MB
pyyaml                               0.90s   16MB
pyyaml + typer                      15.72s   31MB
pyyaml + typer + pydantic           16.39s   41MB
```

Typer appeared to cost roughly fifteen seconds per run. That is a large and
decisive looking number, and it is noise. Repeating the same four installs
three times:

```
rep1  pyyaml                2.15s     rep1  pyyaml typer         39.87s
rep2  pyyaml                2.61s     rep2  pyyaml typer         14.76s
rep3  pyyaml                8.24s     rep3  pyyaml typer          2.85s
```

The same specification took 2.85s, 14.76s and 39.87s. The spread within one
specification is an order of magnitude wider than any gap between
specifications, because the wall clock here is dominated by network and proxy
variance rather than by the packages. The first table measured the network.

So no install timing is published anywhere in this repository. The CI workflow
runs a `startup` job that times both install paths on a GitHub runner, where
the network is the one that actually matters to a user, and writes the result
to the run summary rather than into the README. A number in a README that was
measured somewhere nobody runs the tool is worse than no number.

## The same lesson, later, at a smaller scale

The throughput benchmark has the same shape of problem in miniature. Repeating
a five pass median over the corpus gave 1.594s and then 1.686s, a 6% move, and
the published figure had been written to four significant figures. Not noise on
the scale of the install timing, but more than enough to fail a number check
for no reason and more precision than the measurement supports.

So the README publishes throughput rounded, with no verification marker, and
says why. The markers are on the counts, which are deterministic: the same
corpus produces the same 1,439 findings every run. A number worth checking
automatically has to be a number that does not move on its own.

## What is measurable

Installed size and dependency count were identical across every repetition:

| dependencies | packages installed | installed size |
| --- | --- | --- |
| pyyaml, pydantic | 6 | 26MB |
| pyyaml, pydantic, typer | 13 | 41MB |

Typer brings `click`, `rich`, `pygments`, `markdown-it-py`, `mdurl`,
`shellingham` and `annotated-doc`: seven additional packages and 15MB, in
exchange for argument parsing. This tool has three subcommands and no
interactive output. `argparse` in the standard library does all of it.

## Decision

Depend on `pyyaml` and `pydantic` and nothing else. Use `argparse` for the
command line.

Keep `pydantic`. It is six packages against four and the structural validation
it gives is the boundary the whole design rests on, with error locations that
arrive as path tuples the mark index can turn into line numbers without any
translation. A hand rolled validator would be a few hundred lines reproducing
that badly.

## Consequences

The command line is more verbose to write than it would be with a decorator
based parser. That cost is paid once by me, in one file, rather than on every
run by every engineer whose pull request this gate inspects.

There is no coloured output and no shell completion, both of which `rich` and
`shellingham` would have provided. Neither matters in a CI log, which is where
this output is read.

The dependency check in `tools/check_dependencies.py` fails the build on any
declared dependency nothing imports, so this budget is enforced rather than
merely written down. That check has now found an unused declared dependency in
all four repositories it has run in.

## Related: composite action rather than a Docker action

Same reasoning, on the evidence available. A Docker action pulls or builds an
image on every run; a composite action starts in the runner's own Python. I
cannot measure the image pull from this environment, because the registry is
unreachable from it, and so no comparison is claimed. The decision rests on
what the composite action avoids rather than on a number I do not have: no
image to build, publish, pin, scan or keep patched, and no registry
authentication on a runner. If the `startup` CI job later shows the pull is
cheap, the only thing that changes is that a Docker action becomes an option,
not that this one became wrong.
