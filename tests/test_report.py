import json
from pathlib import Path

from drg import engine
from drg.checks import Severity, registry
from drg.report import annotations, job_summary, sarif, text

FIXTURES = Path(__file__).parent / "fixtures"


def violations():
    return engine.run([FIXTURES / "violations"])


def clean():
    return engine.run([FIXTURES / "clean"])


def test_text_lists_every_finding_with_its_line():
    rendered = text(violations())
    for finding in violations().findings:
        assert str(finding.line) in rendered
        assert finding.check in rendered


def test_text_groups_by_file():
    rendered = text(violations())
    assert rendered.count("tests/fixtures/violations/tactic_only.yml") == 1


def test_text_reports_a_clean_run():
    assert "no findings" in text(clean())


def test_text_singular_and_plural_agree():
    rendered = text(clean())
    assert "3 rules in 3 files" in rendered
    assert "1 finding hidden by suppression with a reason" in rendered


def test_text_names_the_failure_threshold():
    assert "failing on: error" in text(violations(), fail_on=Severity.ERROR)
    assert "failing on: nothing" in text(violations(), fail_on=Severity.OFF)


def test_text_can_include_the_rationale():
    assert "coverage review counts techniques" in text(violations(), show_rationale=True)
    assert "coverage review counts techniques" not in text(violations())


def test_annotations_use_workflow_command_syntax():
    emitted = list(annotations(violations(), base=str(Path.cwd())))
    assert all(line.startswith(("::error ", "::warning ", "::notice ")) for line in emitted)
    assert all("file=" in line and "line=" in line for line in emitted)


def test_annotation_paths_are_relative_to_the_base():
    emitted = list(annotations(violations(), base=str(Path.cwd())))
    assert all("file=tests/fixtures/violations/" in line for line in emitted)


def test_annotation_escapes_characters_that_would_end_the_command():
    report = violations()
    report.findings[0] = type(report.findings[0])(
        check=report.findings[0].check,
        detail="a: b, c\nsecond line",
        severity=Severity.ERROR,
        file=Path("rules/x.yml"),
        line=3,
    )
    line = next(iter(annotations(report)))
    assert "\n" not in line
    assert "%0A" in line


def test_annotation_escapes_colon_and_comma_in_properties():
    report = violations()
    report.findings[0] = type(report.findings[0])(
        check="broad-logsource",
        detail="detail",
        severity=Severity.ERROR,
        file=Path("rules/a,b:c.yml"),
        line=1,
    )
    line = next(iter(annotations(report)))
    assert "%2C" in line and "%3A" in line


def test_job_summary_is_markdown_with_a_table():
    rendered = job_summary(violations())
    assert rendered.startswith("## Detection rule gate")
    assert "| check | severity | count |" in rendered
    assert "<details>" in rendered


def test_job_summary_reports_a_clean_run():
    assert "No findings across 3 rules" in job_summary(clean())


def test_sarif_is_valid_json_at_version_2_1_0():
    doc = json.loads(sarif(violations(), base=Path.cwd()))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(doc["runs"]) == 1


def test_sarif_declares_every_registered_check_as_a_rule():
    """GitHub rejects a result whose ruleId is not in tool.driver.rules."""
    doc = json.loads(sarif(violations(), base=Path.cwd()))
    declared = {rule["id"] for rule in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert declared == set(registry())
    referenced = {result["ruleId"] for result in doc["runs"][0]["results"]}
    assert referenced <= declared


def test_sarif_uris_are_relative_with_forward_slashes():
    """An absolute path passes the schema and then maps to no file at all,
    so every finding arrives with no location and the upload looks fine."""
    doc = json.loads(sarif(violations(), base=Path.cwd()))
    for result in doc["runs"][0]["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("/")
        assert "\\" not in uri
        assert uri.startswith("tests/fixtures/")


def test_sarif_region_start_line_is_at_least_one():
    doc = json.loads(sarif(violations(), base=Path.cwd()))
    for result in doc["runs"][0]["results"]:
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_sarif_fingerprint_is_stable_across_runs():
    first = json.loads(sarif(violations(), base=Path.cwd()))
    second = json.loads(sarif(violations(), base=Path.cwd()))
    assert [r["partialFingerprints"] for r in first["runs"][0]["results"]] == [
        r["partialFingerprints"] for r in second["runs"][0]["results"]
    ]


def test_sarif_fingerprint_ignores_the_line_number():
    """A finding that moved because something was inserted above it is the
    same finding. A fingerprint including the line would close it and open a
    new one on every reshuffle."""
    report = violations()
    original = [r["partialFingerprints"] for r in json.loads(sarif(report, base=Path.cwd()))["runs"][0]["results"]]
    shifted = engine.Report(
        findings=[
            type(finding)(
                check=finding.check,
                detail=finding.detail,
                severity=finding.severity,
                file=finding.file,
                line=finding.line + 10,
                rule_id=finding.rule_id,
                rule_title=finding.rule_title,
            )
            for finding in report.findings
        ],
        files_scanned=report.files_scanned,
        rules_loaded=report.rules_loaded,
    )
    moved = [r["partialFingerprints"] for r in json.loads(sarif(shifted, base=Path.cwd()))["runs"][0]["results"]]
    assert original == moved


def test_sarif_records_the_sigma_rule_id_when_the_rule_has_one():
    doc = json.loads(sarif(violations(), base=Path.cwd()))
    with_id = [r for r in doc["runs"][0]["results"] if "properties" in r]
    assert with_id
    assert all("sigmaRuleId" in r["properties"] for r in with_id)


def test_sarif_help_uri_is_added_when_a_repository_is_given():
    doc = json.loads(sarif(violations(), base=Path.cwd(), repository="https://github.com/a/b"))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert all(rule["helpUri"].startswith("https://github.com/a/b/blob/main/docs/checks.md#") for rule in rules)


def test_sarif_omits_help_uri_without_a_repository():
    doc = json.loads(sarif(violations(), base=Path.cwd()))
    assert all("helpUri" not in rule for rule in doc["runs"][0]["tool"]["driver"]["rules"])


def test_sarif_default_configuration_matches_the_registered_default():
    doc = json.loads(sarif(violations(), base=Path.cwd()))
    levels = {rule["id"]: rule["defaultConfiguration"]["level"] for rule in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert levels["condition-unparseable"] == "error"
    assert levels["attack-technique-missing"] == "warning"


def test_sarif_carries_run_properties():
    doc = json.loads(sarif(violations(), base=Path.cwd()))
    properties = doc["runs"][0]["properties"]
    assert properties["rulesLoaded"] == 12
    assert properties["truncated"] is False


def test_sarif_path_outside_the_base_is_not_a_traversal():
    report = engine.Report(
        findings=[
            engine.Finding(
                check="broad-logsource",
                detail="x",
                severity=Severity.WARNING,
                file=Path("/elsewhere/rule.yml"),
                line=1,
            )
        ],
        files_scanned=1,
        rules_loaded=1,
    )
    doc = json.loads(sarif(report, base=Path.cwd()))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert not uri.startswith("..")
    assert not uri.startswith("/")
