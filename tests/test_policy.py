from pathlib import Path

import pytest

from drg.checks import Severity, registry
from drg.policy import PolicyError, default_policy, discover, load, parse_suppressions


def write(tmp_path: Path, body: str, name: str = ".detection-rule-gate.yml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def test_default_policy_covers_every_registered_check():
    policy = default_policy()
    assert set(policy.severities) == set(registry())


def test_severity_may_be_given_as_a_bare_string(tmp_path):
    policy = load(write(tmp_path, "checks:\n  broad-logsource: error\n"))
    assert policy.severity_of("broad-logsource") is Severity.ERROR


def test_severity_may_be_given_as_a_mapping(tmp_path):
    policy = load(write(tmp_path, "checks:\n  broad-logsource:\n    severity: notice\n"))
    assert policy.severity_of("broad-logsource") is Severity.NOTICE


def test_off_disables_a_check(tmp_path):
    """Unquoted off is the boolean False by the time YAML is done with it.

    YAML 1.1 resolves off, no and false to False. Since off is both the obvious
    way to write "disable this" and the name of the severity, a policy loader
    that only accepted the string would reject the spelling every user reaches
    for first.
    """
    policy = load(write(tmp_path, "checks:\n  missing-falsepositives: off\n"))
    assert policy.severity_of("missing-falsepositives") is Severity.OFF


def test_quoted_off_disables_a_check_too(tmp_path):
    policy = load(write(tmp_path, 'checks:\n  missing-falsepositives: "off"\n'))
    assert policy.severity_of("missing-falsepositives") is Severity.OFF


def test_no_is_read_as_off(tmp_path):
    policy = load(write(tmp_path, "checks:\n  missing-falsepositives: no\n"))
    assert policy.severity_of("missing-falsepositives") is Severity.OFF


def test_on_is_rejected_because_it_names_no_severity(tmp_path):
    with pytest.raises(PolicyError, match="name the severity"):
        load(write(tmp_path, "checks:\n  missing-falsepositives: on\n"))


def test_unset_checks_keep_their_registered_default(tmp_path):
    policy = load(write(tmp_path, "checks:\n  broad-logsource: error\n"))
    assert policy.severity_of("attack-technique-missing") is registry()["attack-technique-missing"].default


def test_unknown_check_is_an_error_not_a_silent_no_op(tmp_path):
    """A setting that applies to nothing is a check a team believes is
    configured for as long as nobody looks."""
    with pytest.raises(PolicyError, match="unknown check"):
        load(write(tmp_path, "checks:\n  no-such-check: error\n"))


def test_underscore_spelling_of_a_check_id_suggests_the_real_one(tmp_path):
    with pytest.raises(PolicyError, match="did you mean unbounded-selection"):
        load(write(tmp_path, "checks:\n  unbounded_selection: error\n"))


def test_structural_findings_cannot_be_downgraded(tmp_path):
    with pytest.raises(PolicyError, match="cannot be configured"):
        load(write(tmp_path, "checks:\n  rule-invalid: warning\n"))


def test_unknown_top_level_setting_is_an_error(tmp_path):
    with pytest.raises(PolicyError, match="unknown setting"):
        load(write(tmp_path, "checkz: {}\n"))


def test_unknown_option_for_a_check_is_an_error(tmp_path):
    with pytest.raises(PolicyError, match="has no option"):
        load(write(tmp_path, "checks:\n  missing-falsepositives:\n    options:\n      lvls: [high]\n"))


def test_known_option_is_applied(tmp_path):
    policy = load(write(tmp_path, "checks:\n  missing-falsepositives:\n    options:\n      levels: [critical]\n"))
    assert policy.options_for("missing-falsepositives") == {"levels": ["critical"]}


def test_invalid_severity_name_is_rejected(tmp_path):
    with pytest.raises(PolicyError, match="is not a severity"):
        load(write(tmp_path, "checks:\n  broad-logsource: urgent\n"))


def test_fail_on_is_validated(tmp_path):
    with pytest.raises(PolicyError, match="fail_on"):
        load(write(tmp_path, "fail_on: whenever\n"))
    assert load(write(tmp_path, "fail_on: warning\n")).fail_on is Severity.WARNING


def test_exclude_must_be_a_list_of_strings(tmp_path):
    with pytest.raises(PolicyError, match="exclude"):
        load(write(tmp_path, "exclude: deprecated\n"))


def test_exclude_matches_a_path_or_a_bare_name(tmp_path):
    policy = load(write(tmp_path, "exclude:\n  - 'deprecated/**'\n  - 'scratch.yml'\n"))
    assert policy.excludes(Path("deprecated/old.yml"))
    assert policy.excludes(Path("anywhere/scratch.yml"))
    assert not policy.excludes(Path("rules/live.yml"))


def test_empty_policy_file_is_the_default_policy(tmp_path):
    assert load(write(tmp_path, "\n")).severities == default_policy().severities


def test_non_mapping_policy_file_is_rejected(tmp_path):
    with pytest.raises(PolicyError, match="mapping at the top level"):
        load(write(tmp_path, "- just\n- a list\n"))


def test_malformed_policy_yaml_is_rejected(tmp_path):
    with pytest.raises(PolicyError, match="not loadable YAML"):
        load(write(tmp_path, "checks:\n  a: b\n   c: d\n"))


def test_discover_walks_up_to_find_a_policy(tmp_path):
    write(tmp_path, "checks:\n  broad-logsource: error\n")
    nested = tmp_path / "rules" / "windows"
    nested.mkdir(parents=True)
    assert discover(nested).severity_of("broad-logsource") is Severity.ERROR


def test_discover_falls_back_to_defaults(tmp_path):
    assert discover(tmp_path).source is None


def test_discover_accepts_the_yaml_spelling(tmp_path):
    write(tmp_path, "checks:\n  broad-logsource: notice\n", name=".detection-rule-gate.yaml")
    assert discover(tmp_path).severity_of("broad-logsource") is Severity.NOTICE


def test_suppression_records_the_reason():
    found = parse_suppressions("# drg:ignore unbounded-selection reason: allowlist by design\ntitle: x\n")
    assert found.reasons == {"unbounded-selection": "allowlist by design"}


def test_suppression_without_a_reason_is_reported():
    found = parse_suppressions("# drg:ignore unbounded-selection\n")
    assert found.without_reason == (("unbounded-selection", 1),)
    assert found.reasons == {}


def test_suppression_with_an_empty_reason_is_reported():
    found = parse_suppressions("# drg:ignore unbounded-selection reason:   \n")
    assert found.without_reason == (("unbounded-selection", 1),)


def test_suppression_naming_an_unknown_check_is_reported():
    found = parse_suppressions("# drg:ignore not-a-check reason: typed from memory\n")
    assert found.unknown == (("not-a-check", 1),)
    assert found.reasons == {}


def test_suppression_line_number_is_recorded():
    text = "title: x\n\n# drg:ignore broad-logsource reason: single channel estate\n"
    assert parse_suppressions(text).reasons
    assert parse_suppressions("title: x\n# drg:ignore broad-logsource\n").without_reason[0][1] == 2


def test_several_suppressions_in_one_file():
    text = (
        "# drg:ignore broad-logsource reason: one channel only\n"
        "# drg:ignore unbounded-selection reason: allowlist detection\n"
    )
    assert set(parse_suppressions(text).reasons) == {"broad-logsource", "unbounded-selection"}


def test_a_comment_that_is_not_a_suppression_is_ignored():
    assert parse_suppressions("# a normal comment about the rule\n").reasons == {}
