import json
from pathlib import Path

from drg import engine
from drg.checks import Severity, registry
from drg.report import render_annotations, render_job_summary, render_sarif, render_text

FIXTURES = Path(__file__).parent / "fixtures"


def violations():
    return engine.run([FIXTURES / "violations"])


def clean():
    return engine.run([FIXTURES / "clean"])


def test_text_lists_every_finding_with_its_line():
    rendered = render_text(violations())
    for finding in violations().findings:
        assert str(finding.line) in rendered
        assert finding.check in rendered


def test_text_groups_by_file():
    rendered = render_text(violations())
    assert rendered.count("tests/fixtures/violations/tactic_only.yml") == 1


def test_text_reports_a_clean_run():
    assert "no findings" in render_text(clean())


def test_text_singular_and_plural_agree():
    rendered = render_text(clean())
    assert "3 rules in 3 files" in rendered
    assert "1 finding hidden by suppression with a reason" in rendered


def test_text_names_the_failure_threshold():
    assert "failing on: error" in render_text(violations(), fail_on=Severity.ERROR)
    assert "failing on: nothing" in render_text(violations(), fail_on=Severity.OFF)


def test_text_can_include_the_rationale():
    assert "coverage review counts techniques" in render_text(violations(), show_rationale=True)
    assert "coverage review counts techniques" not in render_text(violations())


def test_annotations_use_workflow_command_syntax():
    emitted = list(render_annotations(violations(), base=str(Path.cwd())))
    assert all(line.startswith(("::error ", "::warning ", "::notice ")) for line in emitted)
    assert all("file=" in line and "line=" in line for line in emitted)


def test_annotation_paths_are_relative_to_the_base():
    emitted = list(render_annotations(violations(), base=str(Path.cwd())))
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
    line = next(iter(render_annotations(report)))
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
    line = next(iter(render_annotations(report)))
    assert "%2C" in line and "%3A" in line


def test_job_summary_is_markdown_with_a_table():
    rendered = render_job_summary(violations())
    assert rendered.startswith("## Detection rule gate")
    assert "| check | severity | count |" in rendered
    assert "<details>" in rendered


def test_job_summary_reports_a_clean_run():
    assert "No findings across 3 rules" in render_job_summary(clean())


def test_sarif_is_valid_json_at_version_2_1_0():
    doc = json.loads(render_sarif(violations(), base=Path.cwd()))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(doc["runs"]) == 1


def test_sarif_declares_every_registered_check_as_a_rule():
    """GitHub rejects a result whose ruleId is not in tool.driver.rules."""
    doc = json.loads(render_sarif(violations(), base=Path.cwd()))
    declared = {rule["id"] for rule in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert declared == set(registry())
    referenced = {result["ruleId"] for result in doc["runs"][0]["results"]}
    assert referenced <= declared


def test_sarif_uris_are_relative_with_forward_slashes():
    """An absolute path passes the schema and then maps to no file at all,
    so every finding arrives with no location and the upload looks fine."""
    doc = json.loads(render_sarif(violations(), base=Path.cwd()))
    for result in doc["runs"][0]["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("/")
        assert "\\" not in uri
        assert uri.startswith("tests/fixtures/")


def test_sarif_region_start_line_is_at_least_one():
    doc = json.loads(render_sarif(violations(), base=Path.cwd()))
    for result in doc["runs"][0]["results"]:
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_sarif_fingerprint_is_stable_across_runs():
    first = json.loads(render_sarif(violations(), base=Path.cwd()))
    second = json.loads(render_sarif(violations(), base=Path.cwd()))
    assert [r["partialFingerprints"] for r in first["runs"][0]["results"]] == [
        r["partialFingerprints"] for r in second["runs"][0]["results"]
    ]


def test_sarif_fingerprint_ignores_the_line_number():
    """A finding that moved because something was inserted above it is the
    same finding. A fingerprint including the line would close it and open a
    new one on every reshuffle."""
    report = violations()
    original = [r["partialFingerprints"] for r in json.loads(render_sarif(report, base=Path.cwd()))["runs"][0]["results"]]
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
    moved = [r["partialFingerprints"] for r in json.loads(render_sarif(shifted, base=Path.cwd()))["runs"][0]["results"]]
    assert original == moved


def test_sarif_records_the_sigma_rule_id_when_the_rule_has_one():
    doc = json.loads(render_sarif(violations(), base=Path.cwd()))
    with_id = [r for r in doc["runs"][0]["results"] if "properties" in r]
    assert with_id
    assert all("sigmaRuleId" in r["properties"] for r in with_id)


def test_sarif_help_uri_is_added_when_a_repository_is_given():
    doc = json.loads(render_sarif(violations(), base=Path.cwd(), repository="https://github.com/a/b"))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert all(rule["helpUri"].startswith("https://github.com/a/b/blob/main/docs/checks.md#") for rule in rules)


def test_sarif_omits_help_uri_without_a_repository():
    doc = json.loads(render_sarif(violations(), base=Path.cwd()))
    assert all("helpUri" not in rule for rule in doc["runs"][0]["tool"]["driver"]["rules"])


def test_sarif_default_configuration_matches_the_registered_default():
    doc = json.loads(render_sarif(violations(), base=Path.cwd()))
    levels = {rule["id"]: rule["defaultConfiguration"]["level"] for rule in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert levels["condition-unparseable"] == "error"
    assert levels["attack-technique-missing"] == "warning"


def test_sarif_carries_run_properties():
    doc = json.loads(render_sarif(violations(), base=Path.cwd()))
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
    doc = json.loads(render_sarif(report, base=Path.cwd()))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert not uri.startswith("..")
    assert not uri.startswith("/")


def _off_finding():
    return engine.Finding(
        check="broad-logsource", detail="x", severity=Severity.OFF, file=Path("rules/a.yml"), line=1
    )


def test_annotations_skip_a_finding_with_no_workflow_command():
    """OFF has no annotation severity. The engine never emits one, but these
    renderers are public functions and a caller can hand them anything."""
    report = engine.Report(findings=[_off_finding()], files_scanned=1, rules_loaded=1)
    assert list(render_annotations(report)) == []


def test_sarif_skips_a_finding_with_no_sarif_level():
    report = engine.Report(findings=[_off_finding()], files_scanned=1, rules_loaded=1)
    doc = json.loads(render_sarif(report, base=Path.cwd()))
    assert doc["runs"][0]["results"] == []


def test_sarif_truncates_rather_than_failing_the_whole_upload(monkeypatch):
    """GitHub rejects an upload with more than 25,000 results outright, so a
    truncated upload with the fact recorded beats no upload at all."""
    from drg.report import sarif as sarif_module

    monkeypatch.setattr(sarif_module, "MAX_RESULTS", 3)
    doc = json.loads(render_sarif(violations(), base=Path.cwd()))
    assert len(doc["runs"][0]["results"]) == 3
    assert doc["runs"][0]["properties"]["truncated"] is True


class TestJsonReport:
    """The format for everything that is not GitHub."""

    @staticmethod
    def document(report=None):
        from drg.report import render_json

        return json.loads(render_json(report or violations(), base=Path.cwd()))

    def test_it_is_valid_json_with_a_format_version(self):
        document = self.document()
        assert document["format"] == 1
        assert document["tool_version"]

    def test_every_finding_is_present_with_its_fields(self):
        document = self.document()
        report = violations()
        assert len(document["findings"]) == len(report.findings)
        for entry in document["findings"]:
            assert set(entry) == {
                "check",
                "severity",
                "summary",
                "detail",
                "file",
                "line",
                "rule_id",
                "rule_title",
            }

    def test_paths_are_relative_with_forward_slashes(self):
        for entry in self.document()["findings"]:
            assert not entry["file"].startswith(("/", ".."))
            assert "\\" not in entry["file"]

    def test_the_summary_agrees_with_the_report(self):
        """A dashboard should not have to re-derive the counts and risk
        disagreeing with what the tool printed."""
        report = violations()
        summary = self.document(report)["summary"]
        assert summary["findings"] == len(report.findings)
        assert summary["rules_loaded"] == report.rules_loaded
        assert summary["by_check"] == report.counts()
        assert sum(summary["by_severity"].values()) == len(report.findings)

    def test_the_exit_code_matches_the_fail_on_it_was_rendered_with(self):
        from drg.report import render_json

        report = violations()
        strict = json.loads(render_json(report, base=Path.cwd(), fail_on=Severity.ERROR))
        never = json.loads(render_json(report, base=Path.cwd(), fail_on=Severity.OFF))
        assert strict["summary"]["exit_code"] == 1
        assert never["summary"]["exit_code"] == 0
        assert never["summary"]["fail_on"] == "off"

    def test_a_clean_run_renders_an_empty_list_not_a_null(self):
        document = self.document(clean())
        assert document["findings"] == []
        assert document["summary"]["suppressed"] == 1

    def test_a_path_outside_the_base_is_not_rendered_as_a_traversal(self):
        from drg.report import render_json

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
        document = json.loads(render_json(report, base=Path.cwd()))
        assert document["findings"][0]["file"] == "/elsewhere/rule.yml"

    def test_rendering_without_a_base_keeps_the_path_as_given(self):
        from drg.report import render_json

        document = json.loads(render_json(violations()))
        assert all(entry["file"].startswith("tests/fixtures/") for entry in document["findings"])
