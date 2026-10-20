import json
from pathlib import Path

import pytest

from drg.cli import main

FIXTURES = Path(__file__).parent / "fixtures"

# Most of these exercise the default policy, so they pass --no-config. Without
# it the CLI discovers this repository's own .detection-rule-gate.yml by walking
# up from the target, and the test would be asserting against whatever that file
# happens to say. One of these did exactly that until the repository gained a
# policy of its own and the test started failing for a reason that had nothing
# to do with what it was testing.
NO_CONFIG = "--no-config"


def test_clean_rules_exit_zero(capsys):
    assert main(["check", str(FIXTURES / "clean"), NO_CONFIG]) == 0
    assert "no findings" in capsys.readouterr().out


def test_errors_exit_one(capsys):
    assert main(["check", str(FIXTURES / "violations"), NO_CONFIG]) == 1
    assert "condition-unparseable" in capsys.readouterr().out


def test_fail_on_off_exits_zero_with_findings(capsys):
    assert main(["check", str(FIXTURES / "violations"), NO_CONFIG, "--fail-on", "off"]) == 0
    assert "failing on: nothing" in capsys.readouterr().out


def test_fail_on_warning_catches_warnings(capsys):
    target = str(FIXTURES / "violations" / "tactic_only.yml")
    assert main(["check", target, NO_CONFIG]) == 0
    assert main(["check", target, NO_CONFIG, "--fail-on", "warning"]) == 1
    capsys.readouterr()


def test_format_github_emits_annotations(capsys):
    main(["check", str(FIXTURES / "violations"), NO_CONFIG, "--format", "github", "--base", str(Path.cwd())])
    out = capsys.readouterr().out
    assert "::error file=tests/fixtures/" in out
    # The text report follows, because an annotation only shows on a touched line.
    assert "failing on:" in out


def test_format_auto_picks_github_inside_actions(capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    main(["check", str(FIXTURES / "violations"), NO_CONFIG, "--base", str(Path.cwd())])
    assert "::error file=" in capsys.readouterr().out


def test_format_auto_picks_text_outside_actions(capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    main(["check", str(FIXTURES / "violations"), NO_CONFIG])
    assert "::error file=" not in capsys.readouterr().out


def test_sarif_output_to_a_file(tmp_path, capsys):
    destination = tmp_path / "nested" / "out.sarif"
    main(["check", str(FIXTURES / "violations"), NO_CONFIG, "--format", "sarif", "--output", str(destination)])
    capsys.readouterr()
    assert destination.is_file()
    assert json.loads(destination.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_summary_appends_to_the_step_summary_file(tmp_path, capsys, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    main(["check", str(FIXTURES / "violations"), NO_CONFIG, "--summary", "--format", "text"])
    capsys.readouterr()
    assert "## Detection rule gate" in summary.read_text(encoding="utf-8")


def test_summary_without_the_environment_variable_says_so(capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    main(["check", str(FIXTURES / "clean"), NO_CONFIG, "--summary"])
    assert "GITHUB_STEP_SUMMARY is not set" in capsys.readouterr().err


def test_config_is_applied(tmp_path, capsys):
    config = tmp_path / ".detection-rule-gate.yml"
    config.write_text("checks:\n  attack-technique-missing: off\n", encoding="utf-8")
    main(["check", str(FIXTURES / "violations"), "--config", str(config)])
    assert "attack-technique-missing" not in capsys.readouterr().out


def test_no_config_ignores_a_discovered_file(tmp_path, capsys):
    (tmp_path / ".detection-rule-gate.yml").write_text("checks:\n  missing-rule-id: off\n", encoding="utf-8")
    rule = tmp_path / "missing_id.yml"
    rule.write_text((FIXTURES / "violations" / "missing_id.yml").read_text(encoding="utf-8"), encoding="utf-8")
    assert main(["check", str(rule)]) == 0
    capsys.readouterr()
    assert main(["check", str(rule), "--no-config"]) == 1
    assert "missing-rule-id" in capsys.readouterr().out


def test_fail_on_from_config_is_used(tmp_path, capsys):
    config = tmp_path / ".detection-rule-gate.yml"
    config.write_text("fail_on: warning\n", encoding="utf-8")
    assert main(["check", str(FIXTURES / "violations" / "tactic_only.yml"), "--config", str(config)]) == 1
    capsys.readouterr()


def test_command_line_fail_on_overrides_config(tmp_path, capsys):
    config = tmp_path / ".detection-rule-gate.yml"
    config.write_text("fail_on: warning\n", encoding="utf-8")
    target = str(FIXTURES / "violations" / "tactic_only.yml")
    assert main(["check", target, "--config", str(config), "--fail-on", "error"]) == 0
    capsys.readouterr()


def test_a_bad_policy_file_exits_two_with_a_message(tmp_path, capsys):
    config = tmp_path / ".detection-rule-gate.yml"
    config.write_text("checks:\n  no-such-check: error\n", encoding="utf-8")
    assert main(["check", str(FIXTURES / "clean"), "--config", str(config)]) == 2
    assert "policy error" in capsys.readouterr().err


def test_a_missing_policy_file_exits_two(tmp_path, capsys):
    assert main(["check", str(FIXTURES / "clean"), "--config", str(tmp_path / "absent.yml")]) == 2
    assert "no such file" in capsys.readouterr().err


def test_checks_command_lists_every_check(capsys):
    assert main(["checks"]) == 0
    out = capsys.readouterr().out
    assert "unbounded-selection" in out
    assert "corpus" in out


def test_checks_command_shows_policy_severities(tmp_path, capsys):
    config = tmp_path / ".detection-rule-gate.yml"
    config.write_text("checks:\n  attack-technique-missing: error\n", encoding="utf-8")
    main(["checks", "--config", str(config)])
    line = next(row for row in capsys.readouterr().out.splitlines() if row.startswith("attack-technique-missing"))
    assert "error" in line


def test_checks_command_can_show_rationale(capsys):
    main(["checks", "--rationale"])
    assert "coverage review counts techniques" in capsys.readouterr().out


def test_explain_prints_the_rationale(capsys):
    assert main(["explain", "unbounded-selection"]) == 0
    out = capsys.readouterr().out
    assert "allowlist style detection" in out
    assert "default severity: warning" in out


def test_explain_shows_options_when_a_check_has_them(capsys):
    main(["explain", "missing-falsepositives"])
    assert "levels" in capsys.readouterr().out


def test_explain_an_unknown_check_exits_two_with_a_suggestion(capsys):
    assert main(["explain", "unbounded_selection"]) == 2
    assert "Did you mean unbounded-selection" in capsys.readouterr().err


def test_explain_an_unrecognisable_check_exits_two(capsys):
    assert main(["explain", "nonsense"]) == 2
    assert "no check called" in capsys.readouterr().err


def test_version_is_printed(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    assert "detection-rule-gate" in capsys.readouterr().out


def test_no_command_exits_two():
    with pytest.raises(SystemExit) as caught:
        main([])
    assert caught.value.code == 2


def test_excludes_behave_the_same_for_relative_and_absolute_paths(tmp_path, capsys):
    """Patterns are anchored to the policy file's directory.

    Before that they were matched against the path as given, so an exclude
    worked for a relative invocation and silently did nothing for an absolute
    one. Same tree, same config, different answer, no warning.
    """
    rules = tmp_path / "deprecated"
    rules.mkdir()
    (rules / "old.yml").write_text(
        (FIXTURES / "violations" / "tactic_only.yml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    config = tmp_path / ".detection-rule-gate.yml"
    config.write_text("exclude:\n  - 'deprecated/**'\n", encoding="utf-8")

    main(["check", str(rules), "--config", str(config)])
    absolute = capsys.readouterr().out
    main(["check", str(rules.resolve()), "--config", str(config)])
    resolved = capsys.readouterr().out
    assert "0 rules in 0 files" in absolute
    assert absolute == resolved
