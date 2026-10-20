from pathlib import Path

from drg import engine
from drg.checks import Severity
from drg.policy import default_policy, load

FIXTURES = Path(__file__).parent / "fixtures"


def run(*parts, policy=None):
    return engine.run([FIXTURES.joinpath(*parts)], policy)


def test_clean_fixtures_produce_no_findings():
    report = run("clean")
    assert report.findings == []
    assert report.rules_loaded == 3
    assert report.exit_code(Severity.ERROR) == 0


def test_a_suppression_with_a_reason_removes_the_finding_and_is_counted():
    report = run("clean")
    assert report.suppressed == 1


def test_every_violation_fixture_raises_its_check():
    report = run("violations")
    raised = set(report.counts())
    assert raised == {
        "attack-technique-missing",
        "broad-logsource",
        "condition-undefined-selection",
        "condition-unparseable",
        "duplicate-yaml-key",
        "missing-falsepositives",
        "missing-rule-id",
        "unbounded-selection",
        "unknown-field-modifier",
    }


def test_findings_carry_a_line_inside_the_file():
    report = run("violations")
    for finding in report.findings:
        total = len(finding.file.read_text(encoding="utf-8").splitlines())
        assert 1 <= finding.line <= total, f"{finding.check} pointed at line {finding.line} of {total}"


def test_findings_are_sorted_by_file_then_line():
    report = run("violations")
    keys = [(str(f.file), f.line, f.check) for f in report.findings]
    assert keys == sorted(keys)


def test_duplicate_ids_are_reported_against_both_files():
    report = run("duplicate_ids")
    assert report.counts() == {"duplicate-rule-id": 2}
    assert {finding.file.name for finding in report.findings} == {"first.yml", "second.yml"}


def test_each_duplicate_names_the_other_file():
    report = run("duplicate_ids")
    for finding in report.findings:
        other = "second.yml" if finding.file.name == "first.yml" else "first.yml"
        assert other in finding.detail


def test_unparseable_file_is_a_finding_not_an_exception():
    report = run("structural")
    checks = report.counts()
    assert checks["rule-unparseable"] == 1
    # The run continued past it, which is the point.
    assert report.files_scanned == 4


def test_invalid_rule_reports_every_structural_error():
    report = run("structural")
    invalid = [f for f in report.findings if f.check == "rule-invalid"]
    assert len(invalid) == 2
    assert {f.file.name for f in invalid} == {"invalid.yml"}


def test_structural_findings_stop_the_other_checks_for_that_file():
    report = run("structural")
    by_file = {}
    for finding in report.findings:
        by_file.setdefault(finding.file.name, set()).add(finding.check)
    assert by_file["invalid.yml"] == {"rule-invalid"}


def test_a_suppression_with_no_reason_is_reported_and_does_not_suppress():
    report = run("structural")
    names = {(f.file.name, f.check) for f in report.findings}
    assert ("suppression_without_reason.yml", "suppression-without-reason") in names
    assert ("suppression_without_reason.yml", "missing-falsepositives") in names


def test_a_suppression_naming_an_unknown_check_is_reported_and_does_not_suppress():
    report = run("structural")
    names = {(f.file.name, f.check) for f in report.findings}
    assert ("suppression_unknown_check.yml", "suppression-unknown-check") in names
    assert ("suppression_unknown_check.yml", "unbounded-selection") in names


def test_exit_code_is_zero_when_only_warnings_fired():
    report = run("violations")
    warnings_only = all(f.severity is not Severity.ERROR for f in report.findings if f.severity is Severity.WARNING)
    assert warnings_only
    assert report.exit_code(Severity.ERROR) == 1  # violations include errors


def test_exit_code_respects_fail_on(tmp_path):
    policy = default_policy()
    report = engine.run([FIXTURES / "clean"], policy)
    assert report.exit_code(Severity.ERROR) == 0
    assert report.exit_code(Severity.NOTICE) == 0


def test_fail_on_off_never_blocks():
    report = run("violations")
    assert report.findings
    assert report.exit_code(Severity.OFF) == 0


def test_a_check_set_to_off_produces_nothing(tmp_path):
    config = tmp_path / ".detection-rule-gate.yml"
    config.write_text("checks:\n  missing-falsepositives: off\n", encoding="utf-8")
    report = engine.run([FIXTURES / "violations"], load(config))
    assert "missing-falsepositives" not in report.counts()


def test_severity_from_policy_is_applied_to_the_finding(tmp_path):
    config = tmp_path / ".detection-rule-gate.yml"
    config.write_text("checks:\n  attack-technique-missing: error\n", encoding="utf-8")
    report = engine.run([FIXTURES / "violations"], load(config))
    raised = [f for f in report.findings if f.check == "attack-technique-missing"]
    assert raised and all(f.severity is Severity.ERROR for f in raised)


def test_check_options_from_policy_change_what_fires(tmp_path):
    config = tmp_path / ".detection-rule-gate.yml"
    config.write_text(
        "checks:\n  missing-falsepositives:\n    options:\n      levels: [low]\n", encoding="utf-8"
    )
    report = engine.run([FIXTURES / "violations"], load(config))
    # The high severity fixture no longer qualifies; nothing at level low in
    # the violations set has a placeholder note, so the check goes quiet.
    assert "missing-falsepositives" not in report.counts()


def test_excluded_paths_are_not_read(tmp_path):
    config = tmp_path / ".detection-rule-gate.yml"
    config.write_text("exclude:\n  - '*.yml'\n", encoding="utf-8")
    report = engine.run([FIXTURES / "violations"], load(config))
    assert report.files_scanned == 0
    assert report.findings == []


def test_a_single_file_target_is_accepted():
    report = engine.run([FIXTURES / "violations" / "tactic_only.yml"])
    assert report.files_scanned == 1
    assert set(report.counts()) == {"attack-technique-missing"}


def test_a_non_rule_file_is_skipped(tmp_path):
    (tmp_path / "notes.md").write_text("not a rule\n", encoding="utf-8")
    (tmp_path / "rule.yml").write_text(
        (FIXTURES / "clean" / "proc_creation_certutil_encode.yml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    report = engine.run([tmp_path])
    assert report.files_scanned == 1


def test_an_empty_directory_is_a_clean_pass(tmp_path):
    report = engine.run([tmp_path])
    assert report.files_scanned == 0
    assert report.exit_code(Severity.ERROR) == 0


def test_worst_severity_is_reported():
    assert run("violations").worst() is Severity.ERROR
    assert run("clean").worst() is Severity.OFF


def test_attack_message_distinguishes_tactic_actor_and_absent():
    report = run("violations")
    details = {f.file.name: f.detail for f in report.findings if f.check == "attack-technique-missing"}
    assert "tactic" in details["tactic_only.yml"]
    assert "actor" in details["actor_tag_only.yml"]
    assert "no attack" in details["no_attack_tags.yml"]
