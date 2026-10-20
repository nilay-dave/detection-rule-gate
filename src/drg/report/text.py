"""The report a person reads.

Grouped by file and ordered by line, because that is the order someone works
through a diff. The check id is printed on every line so that the first thing a
reader wants, which is to turn one finding off or go and read about it, needs no
further lookup.
"""

from __future__ import annotations

from drg.checks import Severity, spec
from drg.engine import Report

MARK = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.NOTICE: "notice"}


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def render(report: Report, *, fail_on: Severity = Severity.ERROR, show_rationale: bool = False) -> str:
    lines: list[str] = []
    current: str | None = None

    for finding in report.findings:
        name = str(finding.file)
        if name != current:
            if current is not None:
                lines.append("")
            lines.append(name)
            current = name
        mark = MARK.get(finding.severity, finding.severity.value)
        lines.append(f"  {finding.line:>5}  {mark:<8}{finding.check}  {finding.detail}")
        if show_rationale:
            lines.append(f"         {spec(finding.check).rationale}")

    if report.findings:
        lines.append("")

    counts = report.counts()
    by_severity: dict[Severity, int] = {}
    for finding in report.findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    ordered = sorted(by_severity.items(), key=lambda item: -item[0].rank)
    tally = ", ".join(f"{count} {severity.value}" for severity, count in ordered)

    scanned = f"{_count(report.rules_loaded, 'rule')} in {_count(report.files_scanned, 'file')}"
    if not report.findings:
        lines.append(f"{scanned}: no findings")
    else:
        lines.append(f"{scanned}: {_count(len(report.findings), 'finding')} ({tally})")
        widest = max(len(name) for name in counts)
        for check, count in counts.items():
            lines.append(f"  {check:<{widest}}  {count}")

    if report.suppressed:
        word = _count(report.suppressed, "suppression").split(" ", 1)[1]
        lines.append(f"{_count(report.suppressed, 'finding')} hidden by {word} with a reason")

    threshold = "nothing" if fail_on is Severity.OFF else fail_on.value
    lines.append(f"failing on: {threshold}")
    return "\n".join(lines) + "\n"
