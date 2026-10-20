import pytest

from drg.rules.condition import ConditionError, is_solely_sufficient, parse, referenced_names


def refs(condition):
    return sorted(referenced_names(parse(condition)))


def holds(condition, true_names, known):
    return parse(condition).evaluate(set(true_names), set(known))


def test_bare_reference():
    assert refs("selection") == ["selection"]
    assert holds("selection", {"selection"}, {"selection"})
    assert not holds("selection", set(), {"selection"})


def test_and_requires_both():
    assert refs("a and b") == ["a", "b"]
    assert holds("a and b", {"a", "b"}, {"a", "b"})
    assert not holds("a and b", {"a"}, {"a", "b"})


def test_or_requires_either():
    assert holds("a or b", {"a"}, {"a", "b"})
    assert not holds("a or b", set(), {"a", "b"})


def test_not_inverts():
    assert holds("a and not b", {"a"}, {"a", "b"})
    assert not holds("a and not b", {"a", "b"}, {"a", "b"})


def test_not_binds_tighter_than_and():
    # "not a and b" is "(not a) and b", not "not (a and b)".
    assert holds("not a and b", {"b"}, {"a", "b"})
    assert not holds("not a and b", {"a", "b"}, {"a", "b"})


def test_and_binds_tighter_than_or():
    # "a or b and c" is "a or (b and c)".
    assert holds("a or b and c", {"a"}, {"a", "b", "c"})
    assert not holds("a or b and c", {"b"}, {"a", "b", "c"})


def test_parentheses_override_precedence():
    assert holds("(a or b) and c", {"b", "c"}, {"a", "b", "c"})
    assert not holds("(a or b) and c", {"b"}, {"a", "b", "c"})


def test_all_of_pattern_requires_every_match():
    known = {"selection_img", "selection_cli"}
    assert holds("all of selection_*", known, known)
    assert not holds("all of selection_*", {"selection_img"}, known)


def test_one_of_pattern_requires_any_match():
    known = {"filter_a", "filter_b"}
    assert holds("1 of filter_*", {"filter_b"}, known)
    assert not holds("1 of filter_*", set(), known)


def test_any_of_is_the_same_as_one_of():
    known = {"filter_a", "filter_b"}
    assert holds("any of filter_*", {"filter_a"}, known)


def test_all_of_them_covers_every_selection():
    known = {"a", "b"}
    assert holds("all of them", known, known)
    assert not holds("all of them", {"a"}, known)


def test_one_of_them_covers_any_selection():
    known = {"a", "b"}
    assert holds("1 of them", {"a"}, known)


def test_pattern_matching_nothing_is_unsatisfied():
    """Reported by the undefined selection check, so it is not reported twice
    here in different words."""
    assert not holds("1 of nothing_*", {"selection"}, {"selection"})


def test_reference_pattern_matches_by_prefix():
    assert holds("filter*", {"filter1"}, {"filter1"})


@pytest.mark.parametrize(
    "condition",
    [
        "selection and",
        "and selection",
        "selection or",
        "(selection",
        "selection)",
        "1 of",
        "1 selection",
        "all of and",
        "selection and not",
        "",
        "   ",
        "selection & filter",
        "selection and (a or)",
    ],
)
def test_unreadable_conditions_raise_rather_than_guess(condition):
    with pytest.raises(ConditionError):
        parse(condition)


def test_sole_sufficiency_ignores_filters_that_are_negated():
    """A wildcard inside a negated filter narrows the rule rather than
    broadening it, which is the distinction this function exists to draw."""
    known = {"selection", "filter1", "filter2"}
    node = parse("selection and not 1 of filter*")
    assert is_solely_sufficient(node, "selection", known)
    assert not is_solely_sufficient(node, "filter1", known)
    assert not is_solely_sufficient(node, "filter2", known)


def test_sole_sufficiency_is_false_when_selections_are_anded():
    known = {"selection_img", "selection_cli"}
    node = parse("all of selection_*")
    assert not is_solely_sufficient(node, "selection_img", known)
    assert not is_solely_sufficient(node, "selection_cli", known)


def test_sole_sufficiency_is_true_for_each_branch_of_an_or():
    known = {"selection1", "selection2", "filter"}
    node = parse("(selection1 or selection2) and not filter")
    assert is_solely_sufficient(node, "selection1", known)
    assert is_solely_sufficient(node, "selection2", known)


def test_condition_is_case_insensitive_for_keywords():
    assert holds("a AND NOT b", {"a"}, {"a", "b"})
    assert holds("ALL OF them", {"a"}, {"a"})


def test_or_collects_names_from_both_sides():
    assert refs("a or b") == ["a", "b"]


def test_two_adjacent_names_inside_parentheses_are_rejected():
    with pytest.raises(ConditionError, match="unbalanced parenthesis"):
        parse("(a b)")
