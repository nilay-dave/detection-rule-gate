import datetime as dt

import pytest
from pydantic import ValidationError

from drg.rules.model import SigmaRule

MINIMAL = {
    "title": "Example",
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
}


def rule(**overrides):
    body = {**MINIMAL, **overrides}
    return SigmaRule.model_validate(body)


def test_minimal_rule_validates():
    parsed = rule()
    assert parsed.title == "Example"
    assert parsed.detection.conditions == ["selection"]
    assert list(parsed.detection.selections) == ["selection"]


def test_title_is_required():
    body = {k: v for k, v in MINIMAL.items() if k != "title"}
    with pytest.raises(ValidationError) as caught:
        SigmaRule.model_validate(body)
    assert caught.value.errors()[0]["loc"] == ("title",)


def test_detection_is_required():
    body = {k: v for k, v in MINIMAL.items() if k != "detection"}
    with pytest.raises(ValidationError):
        SigmaRule.model_validate(body)


def test_condition_is_required_inside_detection():
    with pytest.raises(ValidationError) as caught:
        rule(detection={"selection": {"A": 1}})
    assert caught.value.errors()[0]["loc"] == ("detection", "condition")


def test_blank_condition_is_rejected():
    with pytest.raises(ValidationError):
        rule(detection={"selection": {"A": 1}, "condition": "   "})


def test_condition_may_be_a_list():
    """The specification allows a list of conditions. The public corpus at the
    pinned commit contains none, so only a fixture exercises this path."""
    parsed = rule(detection={"selection": {"A": 1}, "condition": ["selection", "selection and selection"]})
    assert parsed.detection.conditions == ["selection", "selection and selection"]


def test_empty_condition_list_is_rejected():
    with pytest.raises(ValidationError):
        rule(detection={"selection": {"A": 1}, "condition": []})


def test_unknown_level_is_a_parse_error_not_a_finding():
    with pytest.raises(ValidationError) as caught:
        rule(level="urgent")
    assert caught.value.errors()[0]["loc"] == ("level",)


@pytest.mark.parametrize("level", ["informational", "low", "medium", "high", "critical"])
def test_every_specified_level_validates(level):
    assert rule(level=level).level == level


@pytest.mark.parametrize("status", ["stable", "test", "experimental", "deprecated", "unsupported"])
def test_every_specified_status_validates(status):
    assert rule(status=status).status == status


def test_unknown_top_level_fields_are_kept_not_rejected():
    """471 rules in the public corpus carry regression_tests_path and 100
    carry simulation. Neither is in the specification. A model that forbade
    extras would reject real rules from the project that defines the format."""
    parsed = rule(regression_tests_path="regression_data/info.yml", simulation={"atomic": 1})
    assert (parsed.model_extra or {})["regression_tests_path"] == "regression_data/info.yml"


def test_dates_are_parsed_as_dates():
    assert rule(date="2019-02-24").date == dt.date(2019, 2, 24)


def test_absent_tags_key_reads_as_no_tags():
    assert rule(tags=None).tag_list == []


def test_falsepositives_accepts_a_bare_string():
    assert rule(falsepositives="Admin activity").false_positive_notes == ["Admin activity"]


def test_falsepositives_drops_blank_and_null_entries():
    parsed = rule(falsepositives=["Admin activity", None, "   "])
    assert parsed.false_positive_notes == ["Admin activity"]


def test_title_longer_than_the_specification_allows_is_rejected():
    with pytest.raises(ValidationError):
        rule(title="x" * 257)


def test_selections_excludes_the_condition_key():
    parsed = rule(detection={"selection": {"A": 1}, "filter": {"B": 2}, "condition": "selection and not filter"})
    assert sorted(parsed.detection.selections) == ["filter", "selection"]
