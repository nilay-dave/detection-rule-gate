import json
from collections import Counter
from pathlib import Path

import pytest

from drg import engine
from drg.baseline import Baseline, BaselineError, apply, load, record
from drg.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def findings_of(*parts):
    return engine.run([FIXTURES.joinpath(*parts)]).findings


def test_record_counts_every_finding():
    findings = findings_of("violations")
    document = json.loads(record(findings, Path.cwd()))
    assert document["format"] == 1
    assert document["total"] == len(findings)
    assert sum(document["findings"].values()) == len(findings)


def test_record_is_sorted_so_a_regenerated_file_diffs_cleanly():
    document = json.loads(record(findings_of("violations"), Path.cwd()))
    keys = list(document["findings"])
    assert keys == sorted(keys)


def test_a_baseline_hides_every_finding_it_recorded(tmp_path):
    findings = findings_of("violations")
    path = tmp_path / "bl.json"
    path.write_text(record(findings, Path.cwd()), encoding="utf-8")
    applied = apply(load(path), findings, Path.cwd())
    assert applied.new == []
    assert applied.baselined == len(findings)
    assert applied.fixed == 0


def test_a_new_finding_is_not_hidden(tmp_path):
    """The baseline records the clean set, so everything in violations is new."""
    path = tmp_path / "bl.json"
    path.write_text(record(findings_of("clean"), Path.cwd()), encoding="utf-8")
    findings = findings_of("violations")
    applied = apply(load(path), findings, Path.cwd())
    assert len(applied.new) == len(findings)
    assert applied.baselined == 0


def test_a_second_identical_finding_is_new_even_though_it_shares_a_fingerprint():
    """A baseline entry carries a count, not a flag.

    A flag would make a baseline a licence to add as many more of the same
    finding as you like, in the one file where nobody would look.
    """
    findings = findings_of("violations")
    one = [finding for finding in findings if finding.check == "broad-logsource"]
    assert len(one) == 1
    recorded = next(iter(json.loads(record(one, Path.cwd()))["findings"]))
    baseline = Baseline(counts=Counter({recorded: 1}))
    doubled = one + one
    applied = apply(baseline, doubled, Path.cwd())
    assert applied.baselined == 1
    assert len(applied.new) == 1


def test_fixed_counts_recorded_findings_that_stopped_being_reported(tmp_path):
    path = tmp_path / "bl.json"
    path.write_text(record(findings_of("violations"), Path.cwd()), encoding="utf-8")
    applied = apply(load(path), findings_of("clean"), Path.cwd())
    assert applied.fixed == len(findings_of("violations"))
    assert applied.baselined == 0


def test_a_finding_that_moved_down_the_file_is_still_recognised(tmp_path):
    """The fingerprint excludes the line, so inserting a comment above a rule
    does not make every finding in the file look new."""
    findings = findings_of("violations")
    path = tmp_path / "bl.json"
    path.write_text(record(findings, Path.cwd()), encoding="utf-8")
    moved = [
        type(finding)(
            check=finding.check,
            detail=finding.detail,
            severity=finding.severity,
            file=finding.file,
            line=finding.line + 25,
            rule_id=finding.rule_id,
        )
        for finding in findings
    ]
    assert apply(load(path), moved, Path.cwd()).new == []


def test_a_baseline_from_another_format_version_is_refused(tmp_path):
    path = tmp_path / "bl.json"
    path.write_text(json.dumps({"format": 99, "findings": {}}), encoding="utf-8")
    with pytest.raises(BaselineError, match="not format 1"):
        load(path)


def test_a_baseline_that_is_not_json_is_refused(tmp_path):
    path = tmp_path / "bl.json"
    path.write_text("not json at all", encoding="utf-8")
    with pytest.raises(BaselineError, match="not loadable JSON"):
        load(path)


def test_a_baseline_that_is_not_an_object_is_refused(tmp_path):
    path = tmp_path / "bl.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(BaselineError, match="expected an object"):
        load(path)


def test_a_baseline_with_malformed_counts_is_refused(tmp_path):
    path = tmp_path / "bl.json"
    path.write_text(json.dumps({"format": 1, "findings": {"abc": "many"}}), encoding="utf-8")
    with pytest.raises(BaselineError, match="fingerprint to count"):
        load(path)


def test_baseline_total_is_the_sum_of_counts():
    assert Baseline(counts=Counter({"a": 2, "b": 3})).total == 5


def test_the_baseline_command_writes_a_file(tmp_path, capsys):
    out = tmp_path / "nested" / "bl.json"
    assert main(["baseline", str(FIXTURES / "violations"), "--out", str(out), "--no-config"]) == 0
    assert "recorded 12 finding(s)" in capsys.readouterr().out
    assert json.loads(out.read_text(encoding="utf-8"))["total"] == 12


def test_the_baseline_command_respects_the_policy(tmp_path, capsys):
    config = tmp_path / ".detection-rule-gate.yml"
    config.write_text("checks:\n  attack-technique-missing: off\n", encoding="utf-8")
    out = tmp_path / "bl.json"
    main(["baseline", str(FIXTURES / "violations"), "--out", str(out), "--config", str(config)])
    capsys.readouterr()
    assert json.loads(out.read_text(encoding="utf-8"))["total"] == 9


def test_check_with_a_baseline_passes_and_reports_the_count(tmp_path, capsys):
    out = tmp_path / "bl.json"
    main(["baseline", str(FIXTURES / "violations"), "--out", str(out), "--base", str(Path.cwd()), "--no-config"])
    capsys.readouterr()
    assert main(["check", str(FIXTURES / "violations"), "--baseline", str(out), "--base", str(Path.cwd()), "--no-config"]) == 0
    captured = capsys.readouterr()
    assert "no findings" in captured.out
    assert "12 known finding(s)" in captured.err


def test_check_reports_when_the_baseline_can_shrink(tmp_path, capsys):
    out = tmp_path / "bl.json"
    main(["baseline", str(FIXTURES / "violations"), "--out", str(out), "--base", str(Path.cwd()), "--no-config"])
    capsys.readouterr()
    main(["check", str(FIXTURES / "clean"), "--baseline", str(out), "--base", str(Path.cwd()), "--no-config"])
    assert "no longer reported, so the baseline can shrink" in capsys.readouterr().err


def test_a_broken_baseline_exits_two_with_a_message(tmp_path, capsys):
    path = tmp_path / "bl.json"
    path.write_text("{}", encoding="utf-8")
    assert main(["check", str(FIXTURES / "clean"), "--baseline", str(path), "--no-config"]) == 2
    assert "baseline error" in capsys.readouterr().err


def test_the_fingerprint_is_the_same_one_sarif_uses():
    """Two fingerprints would mean a moved finding is recognised in one place
    and not the other, with nothing to say so."""
    from drg.report.sarif import fingerprint_of, render

    findings = findings_of("violations")
    document = json.loads(render(engine.run([FIXTURES / "violations"]), base=Path.cwd()))
    from_sarif = {
        result["partialFingerprints"]["drgFindingIdentity/v1"] for result in document["runs"][0]["results"]
    }
    from_baseline = {fingerprint_of(finding, Path.cwd()) for finding in findings}
    assert from_sarif == from_baseline
