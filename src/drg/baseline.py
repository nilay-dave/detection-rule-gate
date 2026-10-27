"""Records the findings a repository already has, so the gate can be adopted.

This exists because of a number this project measured about itself. On the
public corpus, missing-falsepositives fires on 25% of rules and
attack-technique-missing on 12%. A team whose corpus looks anything like that
cannot turn the gate on: the first run blocks every pull request until somebody
fixes 1,500 rules, and what actually happens is the gate gets removed.

So the gate can be told what is already wrong. New findings fail the build;
recorded ones are reported as a count and nothing else. The backlog shrinks
when someone has time, rather than all at once before anyone has started.

Two decisions keep this from becoming a way to hide problems.

A baseline entry is not matched by line, so a finding that moved because
something unrelated was inserted above it stays recognised. It uses the same
fingerprint the SARIF output uses, for the same reason.

A baseline entry carries a count, not a flag. If a file had one unmapped rule
when the baseline was written and has two now, the second is new and fails,
even though both share a fingerprint. A flag would make a baseline a licence
to add as many more of the same finding as you like, in the one file where
nobody would notice.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from drg import __version__
from drg.checks import Finding
from drg.report.sarif import fingerprint_of

FILENAME = ".drg-baseline.json"
FORMAT_VERSION = 1


class BaselineError(Exception):
    """A baseline file that cannot be used as written."""


@dataclass(frozen=True)
class Baseline:
    """Counts of findings that were present when the baseline was recorded."""

    counts: Counter[str]
    recorded: str = ""
    tool_version: str = ""

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def record(findings: list[Finding], base: Path | None = None) -> str:
    """Render a baseline file from the findings of a run."""
    counts = Counter(fingerprint_of(finding, base) for finding in findings)
    # Sorted so a regenerated baseline produces a reviewable diff rather than a
    # reordered file.
    document = {
        "format": FORMAT_VERSION,
        "recorded": date.today().isoformat(),
        "tool_version": __version__,
        "total": sum(counts.values()),
        "findings": dict(sorted(counts.items())),
    }
    return json.dumps(document, indent=2) + "\n"


def load(path: Path) -> Baseline:
    """Read a baseline file."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BaselineError(f"{path}: not loadable JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise BaselineError(f"{path}: expected an object at the top level")

    version = document.get("format")
    if version != FORMAT_VERSION:
        raise BaselineError(
            f"{path}: baseline format {version!r} is not format {FORMAT_VERSION}. Regenerate it with: drg baseline"
        )

    entries = document.get("findings")
    if not isinstance(entries, dict) or any(not isinstance(value, int) for value in entries.values()):
        raise BaselineError(f"{path}: findings must be an object of fingerprint to count")

    return Baseline(
        counts=Counter({str(key): int(value) for key, value in entries.items()}),
        recorded=str(document.get("recorded", "")),
        tool_version=str(document.get("tool_version", "")),
    )


@dataclass
class Applied:
    """What a baseline did to a run."""

    new: list[Finding]
    baselined: int
    fixed: int


def apply(baseline: Baseline, findings: list[Finding], base: Path | None = None) -> Applied:
    """Split findings into those the baseline already knew and those it did not.

    ``fixed`` is how many recorded findings are no longer being reported, which
    is the number that makes a baseline shrink. Without it a baseline only ever
    grows, and a team has no signal that it is making progress.
    """
    allowance = Counter(baseline.counts)
    new: list[Finding] = []
    baselined = 0

    for finding in findings:
        key = fingerprint_of(finding, base)
        if allowance[key] > 0:
            allowance[key] -= 1
            baselined += 1
        else:
            new.append(finding)

    fixed = sum(count for count in allowance.values() if count > 0)
    return Applied(new=new, baselined=baselined, fixed=fixed)
