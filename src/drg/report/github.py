"""Workflow commands and a job summary.

An annotation puts the finding on the line of the diff, which is the only place
a reviewer is already looking. A job summary gives the same information as a
table on the run page, for whoever is reading the run rather than the diff.

Workflow command values have to be escaped: a literal newline or colon in a
message would end the command early and the annotation would be lost, or worse,
truncated into something that reads as complete.
"""

from __future__ import annotations

import os
from collections.abc import Iterable

from drg.checks import Severity, spec
from drg.engine import Report

COMMAND = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.NOTICE: "notice"}


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def annotations(report: Report, *, base: str | None = None) -> Iterable[str]:
    """One workflow command per finding."""
    for finding in report.findings:
        command = COMMAND.get(finding.severity)
        if command is None:
            continue
        path = _relative(str(finding.file), base)
        title = _escape_property(f"{finding.check}")
        yield (
            f"::{command} file={_escape_property(path)},line={finding.line},title={title}"
            f"::{_escape_data(finding.detail)}"
        )


def _relative(path: str, base: str | None) -> str:
    root = base if base is not None else os.environ.get("GITHUB_WORKSPACE", "")
    if root and path.startswith(root):
        path = path[len(root) :]
    return path.lstrip("/")


def job_summary(report: Report, *, fail_on: Severity = Severity.ERROR, base: str | None = None) -> str:
    """A markdown summary for the run page."""
    lines = ["## Detection rule gate", ""]
    if not report.findings:
        lines.append(f"No findings across {report.rules_loaded} rules.")
        if report.suppressed:
            lines.append("")
            lines.append(f"{report.suppressed} finding(s) hidden by suppressions with a reason.")
        return "\n".join(lines) + "\n"

    counts = report.counts()
    lines.append(f"{len(report.findings)} finding(s) across {report.rules_loaded} rules.")
    lines.append("")
    lines.append("| check | severity | count | why it is enforced |")
    lines.append("| --- | --- | --- | --- |")
    for check, count in counts.items():
        entry = spec(check)
        severity = next(f.severity for f in report.findings if f.check == check)
        lines.append(f"| `{check}` | {severity.value} | {count} | {entry.rationale} |")
    lines.append("")
    lines.append("<details><summary>Every finding</summary>")
    lines.append("")
    lines.append("| file | line | check | detail |")
    lines.append("| --- | --- | --- | --- |")
    for finding in report.findings:
        path = _relative(str(finding.file), base)
        lines.append(f"| `{path}` | {finding.line} | `{finding.check}` | {finding.detail} |")
    lines.append("")
    lines.append("</details>")
    lines.append("")
    threshold = "nothing" if fail_on is Severity.OFF else fail_on.value
    lines.append(f"Failing on: {threshold}.")
    return "\n".join(lines) + "\n"
