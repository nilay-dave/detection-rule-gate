"""SARIF 2.1.0, so findings land in the GitHub security tab.

This is the output that changes where the tool lives. Annotations disappear
with the pull request; a SARIF upload gives every finding a page, a history, a
dismissal with a recorded reason, and an owner. It is the difference between a
gate that complains and a backlog a team can work through.

Three details decide whether GitHub accepts the file at all.

The artifact URI has to be relative to the repository root with forward
slashes. An absolute path is accepted by the schema and then silently fails to
map onto any file, so every finding arrives with no location and the upload
looks like it worked.

partialFingerprints is what lets GitHub recognise the same finding across runs
rather than closing and reopening it on every push. Without it a rule that
moves down a file by one line reads as a new finding and the old one as fixed.

Every rule referenced by a result must appear in tool.driver.rules, including
the structural findings nothing registers a callable for, which is why those
are in the registry rather than special cased in the engine.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from drg import __version__
from drg.checks import Severity, registry
from drg.engine import Report

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

# GitHub rejects an upload with more than 25,000 results. Truncating with a
# notice in the run output is better than an upload that fails whole.
MAX_RESULTS = 25_000

LEVEL = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.NOTICE: "note",
}


def _uri(path: Path, base: Path | None) -> str:
    """A repository relative URI with forward slashes."""
    if base is not None:
        try:
            relative = path.resolve().relative_to(base.resolve())
            return PurePosixPath(relative).as_posix()
        except ValueError:
            # Outside the base. Reported with the path as given rather than
            # with a traversal, which GitHub would reject.
            pass
    return PurePosixPath(path).as_posix().lstrip("/")


def _fingerprint(check: str, uri: str, detail: str) -> str:
    """A stable identity for one finding.

    Deliberately excludes the line number. A finding that moves because
    something unrelated was inserted above it is the same finding, and a
    fingerprint that included the line would close it and open a new one on
    every reshuffle of the file.
    """
    digest = hashlib.sha256(f"{check}\n{uri}\n{detail}".encode()).hexdigest()
    return digest[:32]


def _rules(repository: str | None) -> list[dict]:
    rules = []
    for check_id, entry in registry().items():
        rule = {
            "id": check_id,
            "name": "".join(part.capitalize() for part in check_id.split("-")),
            "shortDescription": {"text": entry.summary},
            "fullDescription": {"text": entry.rationale},
            "defaultConfiguration": {"level": LEVEL.get(entry.default, "none")},
            "properties": {"tags": ["detection-as-code", "sigma", entry.scope]},
        }
        if repository:
            rule["helpUri"] = f"{repository}/blob/main/docs/checks.md#{check_id}"
        rules.append(rule)
    return rules


def render(report: Report, *, base: Path | None = None, repository: str | None = None) -> str:
    """Render the report as a SARIF 2.1.0 log."""
    results = []
    for finding in report.findings:
        level = LEVEL.get(finding.severity)
        if level is None:
            continue
        uri = _uri(finding.file, base)
        result = {
            "ruleId": finding.check,
            "level": level,
            "message": {"text": finding.detail or registry()[finding.check].summary},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": max(1, finding.line)},
                    }
                }
            ],
            "partialFingerprints": {"drgFindingIdentity/v1": _fingerprint(finding.check, uri, finding.detail)},
        }
        if finding.rule_id:
            result["properties"] = {"sigmaRuleId": finding.rule_id}
        results.append(result)

    truncated = len(results) > MAX_RESULTS
    if truncated:
        results = results[:MAX_RESULTS]

    driver: dict = {
        "name": "detection-rule-gate",
        "version": __version__,
        "semanticVersion": __version__,
        "rules": _rules(repository),
    }
    if repository:
        driver["informationUri"] = repository

    log = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": driver},
                "results": results,
                "automationDetails": {"id": "detection-rule-gate/"},
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
                "properties": {
                    "rulesLoaded": report.rules_loaded,
                    "filesScanned": report.files_scanned,
                    "suppressed": report.suppressed,
                    "truncated": truncated,
                },
            }
        ],
    }
    return json.dumps(log, indent=2, sort_keys=False) + "\n"
