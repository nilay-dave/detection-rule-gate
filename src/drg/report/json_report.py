"""Machine readable output, for everything that is not GitHub.

SARIF is the right format when the destination is a code scanning tool, and it
is verbose and schema bound in ways that make it awkward for anything else. A
team wanting to chart its own findings over time, or feed them to a ticket
tracker, should not have to parse SARIF or scrape the text report.

The shape is flat and stable: a list of findings with the fields a consumer
needs and nothing nested. It carries the summary counts as well, so a dashboard
does not have to re-derive them and risk disagreeing with what the tool
printed.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

from drg import __version__
from drg.checks import Severity, spec
from drg.engine import Report

FORMAT_VERSION = 1


def _uri(path: Path, base: Path | None) -> str:
    if base is not None:
        try:
            return PurePosixPath(path.resolve().relative_to(base.resolve())).as_posix()
        except (ValueError, OSError):
            pass
    return PurePosixPath(path).as_posix()


def render(report: Report, *, base: Path | None = None, fail_on: Severity = Severity.ERROR) -> str:
    """Render the report as a flat JSON document."""
    findings = [
        {
            "check": finding.check,
            "severity": finding.severity.value,
            "summary": spec(finding.check).summary,
            "detail": finding.detail,
            "file": _uri(finding.file, base),
            "line": finding.line,
            "rule_id": finding.rule_id,
            "rule_title": finding.rule_title,
        }
        for finding in report.findings
    ]

    document = {
        "format": FORMAT_VERSION,
        "tool_version": __version__,
        "summary": {
            "files_scanned": report.files_scanned,
            "rules_loaded": report.rules_loaded,
            "findings": len(findings),
            "suppressed": report.suppressed,
            "fail_on": fail_on.value,
            "exit_code": report.exit_code(fail_on),
            "by_check": report.counts(),
            "by_severity": {
                severity.value: sum(1 for finding in report.findings if finding.severity is severity)
                for severity in (Severity.ERROR, Severity.WARNING, Severity.NOTICE)
            },
        },
        "findings": findings,
    }
    return json.dumps(document, indent=2) + "\n"
