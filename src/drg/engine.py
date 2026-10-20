"""Runs the checks over a set of files and resolves what each finding means.

The engine owns everything a check deliberately does not: which files to read,
what line a path works out to, what severity the team chose, whether a
suppression applies, and what exit code comes out at the end.

Load failures become findings rather than exceptions. A linter that stops at
the first malformed file tells a reviewer about one problem per run, and a
reviewer fixing a pull request wants the whole list.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from drg.checks import Finding, Issue, Severity, corpus_checks, rule_checks
from drg.policy import Policy, Suppressions, default_policy, parse_suppressions
from drg.rules.marks import Located, ParseError
from drg.rules.marks import load as load_marks
from drg.rules.model import SigmaRule

RULE_SUFFIXES = (".yml", ".yaml")


@dataclass
class Report:
    """Everything one run produced."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    rules_loaded: int = 0
    suppressed: int = 0

    def worst(self) -> Severity:
        if not self.findings:
            return Severity.OFF
        return max((finding.severity for finding in self.findings), key=lambda severity: severity.rank)

    def exit_code(self, fail_on: Severity) -> int:
        """1 when anything reached ``fail_on``, else 0.

        A gate's exit code is its whole interface, so it is computed from the
        resolved severities and nothing else. OFF for fail_on means report and
        never block, which is how a team adopts the tool before it bites.
        """
        if fail_on is Severity.OFF:
            return 0
        return 1 if any(finding.severity.rank >= fail_on.rank for finding in self.findings) else 0

    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for finding in self.findings:
            tally[finding.check] = tally.get(finding.check, 0) + 1
        return dict(sorted(tally.items()))


def discover_files(targets: Sequence[Path], policy: Policy) -> list[Path]:
    """Every rule file under ``targets``, sorted, excludes applied."""
    found: list[Path] = []
    for target in targets:
        if target.is_file():
            if target.suffix.lower() in RULE_SUFFIXES and not policy.excludes(target):
                found.append(target)
            continue
        for path in sorted(target.rglob("*")):
            if path.is_file() and path.suffix.lower() in RULE_SUFFIXES and not policy.excludes(path):
                found.append(path)
    return sorted(set(found))


def _locate(issue: Issue, located: Located) -> int:
    return located.line_for(issue.path)


def _finding(
    issue: Issue,
    *,
    policy: Policy,
    path: Path,
    line: int,
    rule: SigmaRule | None,
    suppressions: Suppressions,
) -> Finding:
    # No OFF guard here. The caller skips a disabled check before running it,
    # so a disabled check never produces an issue to resolve. A second guard
    # would be a branch no test can reach and no reader can trust.
    severity = policy.severity_of(issue.check)
    reason = suppressions.reasons.get(issue.check)
    return Finding(
        check=issue.check,
        detail=issue.detail,
        severity=severity,
        file=path,
        line=line,
        rule_id=str(rule.id) if rule and rule.id else None,
        rule_title=rule.title if rule else None,
        suppressed_reason=reason,
    )


def run(targets: Sequence[Path], policy: Policy | None = None) -> Report:
    """Check every rule under ``targets`` and resolve the findings."""
    policy = policy or default_policy()
    report = Report()
    loaded: list[tuple[Path, SigmaRule, Located]] = []
    per_file_suppressions: dict[Path, Suppressions] = {}

    for path in discover_files(targets, policy):
        report.files_scanned += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        suppressions = parse_suppressions(text)
        per_file_suppressions[path] = suppressions

        for check_id, line in suppressions.without_reason:
            report.findings.append(
                Finding(
                    check="suppression-without-reason",
                    detail=f"suppression of {check_id!r} has no reason",
                    severity=Severity.ERROR,
                    file=path,
                    line=line,
                )
            )
        for check_id, line in suppressions.unknown:
            report.findings.append(
                Finding(
                    check="suppression-unknown-check",
                    detail=f"{check_id!r} is not a check this version defines",
                    severity=Severity.ERROR,
                    file=path,
                    line=line,
                )
            )

        try:
            located = load_marks(text)
        except ParseError as exc:
            report.findings.append(
                Finding(
                    check="rule-unparseable",
                    detail=exc.message,
                    severity=Severity.ERROR,
                    file=path,
                    line=exc.line or 1,
                )
            )
            continue

        try:
            rule = SigmaRule.model_validate(located.data)
        except ValidationError as exc:
            for error in exc.errors():
                where = ".".join(str(part) for part in error["loc"]) or "document"
                report.findings.append(
                    Finding(
                        check="rule-invalid",
                        detail=f"{where}: {error['msg']}",
                        severity=Severity.ERROR,
                        file=path,
                        line=located.line_for(tuple(error["loc"])),
                    )
                )
            continue

        report.rules_loaded += 1
        loaded.append((path, rule, located))

        for check_id, function in rule_checks().items():
            if policy.severity_of(check_id) is Severity.OFF:
                continue
            for issue in function(rule, located, policy.options_for(check_id)):
                report.findings.append(
                    _finding(
                        issue,
                        policy=policy,
                        path=path,
                        line=_locate(issue, located),
                        rule=rule,
                        suppressions=suppressions,
                    )
                )

    for check_id, function in corpus_checks().items():
        if policy.severity_of(check_id) is Severity.OFF:
            continue
        index = {path: (rule, located) for path, rule, located in loaded}
        for path, issue in function(loaded, policy.options_for(check_id)):
            rule, located = index[path]
            report.findings.append(
                _finding(
                    issue,
                    policy=policy,
                    path=path,
                    line=located.line_for(issue.path),
                    rule=rule,
                    suppressions=per_file_suppressions.get(path, Suppressions()),
                )
            )

    report.suppressed = sum(1 for finding in report.findings if finding.suppressed_reason)
    report.findings = [finding for finding in report.findings if not finding.suppressed_reason]
    report.findings.sort(key=lambda finding: (str(finding.file), finding.line, finding.check))
    return report
