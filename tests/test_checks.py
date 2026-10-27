"""Direct unit tests of the branches the fixture corpus does not reach."""

from pathlib import Path

import pytest

from drg.checks import CheckSpec, Severity, register_spec, registry, rule_check, spec
from drg.checks.attack import attack_technique_missing
from drg.checks.conditions import condition_undefined_selection
from drg.checks.duplicates import duplicate_yaml_key
from drg.checks.falsepositives import missing_falsepositives
from drg.checks.identity import duplicate_rule_id, missing_rule_id
from drg.checks.logsource import broad_logsource
from drg.checks.modifiers import unknown_field_modifier
from drg.checks.wildcards import unbounded_selection
from drg.rules.marks import load
from drg.rules.model import SigmaRule

BODY = """\
title: Example
id: 7f3a2b19-4c8d-4e52-9a61-0b5d8c3f2e74
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\cmd.exe'
    condition: selection
level: high
falsepositives:
    - Interactive administration
"""


def build(**overrides):
    located = load(BODY)
    data = {**located.data, **overrides}
    return SigmaRule.model_validate(data), located


def details(issues):
    return [issue.detail for issue in issues]


def test_registering_a_duplicate_check_id_is_refused():
    """A silently overwritten check is a check that stopped gating."""
    with pytest.raises(RuntimeError, match="registered twice"):

        @rule_check("broad-logsource", summary="x", rationale="y", default=Severity.ERROR)
        def _clash(rule, located, options):
            yield from ()


def test_registering_a_duplicate_spec_is_refused():
    with pytest.raises(RuntimeError, match="registered twice"):
        register_spec(CheckSpec("broad-logsource", "x", "y", Severity.ERROR, "file", {}))


def test_spec_lookup_returns_the_registered_entry():
    assert spec("broad-logsource").scope == "rule"
    assert spec("duplicate-rule-id").scope == "corpus"


def test_severity_rank_orders_as_expected():
    ranks = [Severity.OFF, Severity.NOTICE, Severity.WARNING, Severity.ERROR]
    assert [item.rank for item in ranks] == sorted(item.rank for item in ranks)


def test_finding_message_joins_summary_and_detail():
    from drg.checks import Finding

    with_detail = Finding("broad-logsource", "product 'windows'", Severity.WARNING, Path("a.yml"), 1)
    assert with_detail.message.startswith("log source names a product")
    assert with_detail.message.endswith("product 'windows'")
    bare = Finding("broad-logsource", "", Severity.WARNING, Path("a.yml"), 1)
    assert bare.message == spec("broad-logsource").summary


def test_attack_check_passes_a_sub_technique():
    rule, located = build(tags=["attack.t1059.001"])
    assert list(attack_technique_missing(rule, located, {})) == []


def test_attack_check_is_case_insensitive_about_the_tag():
    rule, located = build(tags=["ATTACK.T1059"])
    assert list(attack_technique_missing(rule, located, {})) == []


def test_attack_check_reports_several_tactics_sorted():
    rule, located = build(tags=["attack.persistence", "attack.execution"])
    detail = details(attack_technique_missing(rule, located, {}))[0]
    assert "attack.execution, attack.persistence" in detail


def test_attack_check_prefers_the_tactic_message_over_the_actor_one():
    rule, located = build(tags=["attack.execution", "attack.g0016"])
    assert "tactic" in details(attack_technique_missing(rule, located, {}))[0]


def test_logsource_with_nothing_at_all():
    rule, located = build(logsource={})
    assert "neither a product" in details(broad_logsource(rule, located, {}))[0]


def test_logsource_with_a_service_and_no_category_passes():
    rule, located = build(logsource={"product": "windows", "service": "security"})
    assert list(broad_logsource(rule, located, {})) == []


def test_logsource_with_a_definition_only_is_still_broad():
    rule, located = build(logsource={"product": "windows", "definition": "requires audit policy"})
    assert details(broad_logsource(rule, located, {}))


def test_falsepositives_absent_entirely():
    rule, located = build(falsepositives=None)
    assert "no falsepositives entry" in details(missing_falsepositives(rule, located, {}))[0]


def test_falsepositives_empty_list():
    rule, located = build(falsepositives=[])
    assert details(missing_falsepositives(rule, located, {}))


@pytest.mark.parametrize("note", ["Unknown", "unknown", "UNKNOWN", "None", "n/a", "TBD", "Unclear", "unknown."])
def test_falsepositives_placeholder_spellings_are_all_caught(note):
    rule, located = build(falsepositives=[note])
    assert details(missing_falsepositives(rule, located, {}))


def test_falsepositives_one_real_note_among_placeholders_passes():
    rule, located = build(falsepositives=["Unknown", "Backup tooling at 02:00"])
    assert list(missing_falsepositives(rule, located, {})) == []


def test_falsepositives_ignores_levels_outside_the_option():
    rule, located = build(level="low", falsepositives=["Unknown"])
    assert list(missing_falsepositives(rule, located, {"levels": ["high", "critical"]})) == []
    assert details(missing_falsepositives(rule, located, {"levels": ["low"]}))


def test_falsepositives_with_an_empty_levels_option_checks_every_level():
    rule, located = build(level="informational", falsepositives=["Unknown"])
    assert details(missing_falsepositives(rule, located, {"levels": []}))


def test_missing_id_accepts_a_valid_uuid():
    rule, located = build()
    assert list(missing_rule_id(rule, located, {})) == []


def test_missing_id_rejects_a_non_uuid():
    rule, located = build(id="DRG-0001")
    assert "is not a UUID" in details(missing_rule_id(rule, located, {}))[0]


def test_missing_id_rejects_a_blank_id():
    rule, located = build(id="   ")
    assert "no id field" in details(missing_rule_id(rule, located, {}))[0]


def test_duplicate_rule_id_ignores_rules_without_an_id():
    rule, located = build(id=None)
    pairs = list(duplicate_rule_id([(Path("a.yml"), rule, located), (Path("b.yml"), rule, located)], {}))
    assert pairs == []


def test_duplicate_rule_id_is_case_insensitive():
    upper, located = build(id="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
    lower, _ = build(id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    pairs = list(duplicate_rule_id([(Path("a.yml"), upper, located), (Path("b.yml"), lower, located)], {}))
    assert len(pairs) == 2


def test_unknown_modifier_walks_into_lists():
    rule, located = build(
        detection={"selection": [{"Image|endwith": "a"}, {"Image|endswith": "b"}], "condition": "selection"}
    )
    assert len(details(unknown_field_modifier(rule, located, {}))) == 1


def test_unknown_modifier_accepts_a_pipeline_defined_name():
    rule, located = build(detection={"selection": {"Field|lookup": "x"}, "condition": "selection"})
    assert details(unknown_field_modifier(rule, located, {}))
    assert list(unknown_field_modifier(rule, located, {"extra_modifiers": ["lookup"]})) == []


def test_unknown_modifier_accepts_chained_regex_flags():
    rule, located = build(detection={"selection": {"Field|re|i|m": "x"}, "condition": "selection"})
    assert list(unknown_field_modifier(rule, located, {})) == []


def test_unknown_modifier_rejects_a_flag_before_re():
    rule, located = build(detection={"selection": {"Field|i|re": "x"}, "condition": "selection"})
    assert "without a preceding 're'" in details(unknown_field_modifier(rule, located, {}))[0]


def test_unknown_modifier_ignores_a_field_with_no_modifier():
    rule, located = build(detection={"selection": {"Image": "cmd.exe"}, "condition": "selection"})
    assert list(unknown_field_modifier(rule, located, {})) == []


def test_unbounded_selection_ignores_an_unreadable_condition():
    """Guessing at sufficiency from a condition nobody read is how a check
    invents a finding. condition-unparseable reports it instead."""
    rule, located = build(detection={"selection": {"A": "*"}, "condition": "selection and"})
    assert list(unbounded_selection(rule, located, {})) == []


def test_unbounded_selection_ignores_a_rule_with_no_selections():
    rule, located = build(detection={"condition": "selection"})
    assert list(unbounded_selection(rule, located, {})) == []


def test_unbounded_selection_ignores_an_empty_selection_block():
    rule, located = build(detection={"selection": {}, "condition": "selection"})
    assert list(unbounded_selection(rule, located, {})) == []


@pytest.mark.parametrize("value", ["*", "**", "***"])
def test_unbounded_values_are_recognised(value):
    rule, located = build(detection={"selection": {"Field|contains": value}, "condition": "selection"})
    assert details(unbounded_selection(rule, located, {}))


@pytest.mark.parametrize("value", ["cmd.exe", "*cmd*", "", None, True, False, 0, 4688])
def test_bounded_values_are_not_flagged(value):
    rule, located = build(detection={"selection": {"Field": value}, "condition": "selection"})
    assert list(unbounded_selection(rule, located, {})) == []


def test_existence_idiom_beside_a_real_constraint_is_not_flagged():
    """field: '*' next to a narrowing field is the Sigma way of saying the
    field is present. Eight of the nine findings the first version of this
    check raised on the public corpus had exactly this shape."""
    rule, located = build(
        detection={
            "selection": {"verb": "create", "objectRef.resource": "pods", "hostPath": "*"},
            "condition": "selection",
        }
    )
    assert list(unbounded_selection(rule, located, {})) == []


def test_wildcard_inside_a_negated_filter_is_not_flagged():
    """A wildcard in a filter that is subtracted narrows the rule."""
    rule, located = build(
        detection={
            "selection": {"eventName": "CreateInstanceExportTask"},
            "filter1": {"errorMessage|contains": "*"},
            "condition": "selection and not 1 of filter*",
        }
    )
    assert list(unbounded_selection(rule, located, {})) == []


def test_unbounded_selection_walks_into_lists_of_values():
    rule, located = build(detection={"selection": {"Field|contains": ["*", "*"]}, "condition": "selection"})
    assert details(unbounded_selection(rule, located, {}))


def test_undefined_selection_skips_an_unreadable_condition():
    rule, located = build(detection={"selection": {"A": 1}, "condition": "selection and"})
    assert list(condition_undefined_selection(rule, located, {})) == []


def test_undefined_selection_reports_a_pattern_matching_nothing():
    rule, located = build(detection={"selection": {"A": 1}, "condition": "selection and not 1 of filter_*"})
    assert "matches none of the selections" in details(condition_undefined_selection(rule, located, {}))[0]


def test_undefined_selection_accepts_a_pattern_that_matches():
    rule, located = build(
        detection={"selection": {"A": 1}, "filter_x": {"B": 2}, "condition": "selection and not 1 of filter_*"}
    )
    assert list(condition_undefined_selection(rule, located, {})) == []


def test_undefined_selection_checks_every_condition_in_a_list():
    rule, located = build(detection={"selection": {"A": 1}, "condition": ["selection", "missing"]})
    assert details(condition_undefined_selection(rule, located, {}))


def test_duplicate_yaml_key_reports_nothing_when_there_are_none():
    rule, located = build()
    assert list(duplicate_yaml_key(rule, located, {})) == []


def test_registry_is_sorted_and_complete():
    names = list(registry())
    assert names == sorted(names)
    assert "rule-invalid" in names


def test_registering_a_duplicate_corpus_check_id_is_refused():
    from drg.checks import corpus_check

    with pytest.raises(RuntimeError, match="registered twice"):

        @corpus_check("duplicate-rule-id", summary="x", rationale="y", default=Severity.ERROR)
        def _clash(rules, options):
            yield from ()


def test_unknown_modifier_walks_into_nested_mappings():
    rule, located = build(detection={"selection": {"outer": {"Image|endwith": "a"}}, "condition": "selection"})
    assert "endwith" in details(unknown_field_modifier(rule, located, {}))[0]
