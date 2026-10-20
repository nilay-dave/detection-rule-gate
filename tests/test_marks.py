from pathlib import Path

import pytest
import yaml

from drg.rules.marks import USING_LIBYAML, ParseError, load

NESTED = """\
title: Example
detection:
    selection:
        Image|endswith: '\\\\cmd.exe'
        CommandLine|contains:
            - whoami
            - hostname
    condition: selection
level: high
"""


def test_top_level_keys_record_their_own_line():
    loc = load(NESTED)
    assert loc.line_for(("title",)) == 1
    assert loc.line_for(("detection",)) == 2
    assert loc.line_for(("level",)) == 9


def test_nested_mapping_keys_resolve():
    loc = load(NESTED)
    assert loc.line_for(("detection", "selection")) == 3
    assert loc.line_for(("detection", "selection", "Image|endswith")) == 4
    assert loc.line_for(("detection", "condition")) == 8


def test_sequence_items_resolve_by_index():
    loc = load(NESTED)
    assert loc.line_for(("detection", "selection", "CommandLine|contains", 0)) == 6
    assert loc.line_for(("detection", "selection", "CommandLine|contains", 1)) == 7


def test_unknown_path_falls_back_to_nearest_ancestor():
    loc = load(NESTED)
    # A check raising a finding about a field the rule never declared should
    # still land on the enclosing block rather than at the top of the file.
    assert loc.line_for(("detection", "selection", "ParentImage")) == 3
    assert loc.line_for(("falsepositives",)) == 1


def test_data_is_constructed_with_real_yaml_types():
    loc = load("date: 2019-02-24\ncount: 7\nflag: true\n")
    assert loc.data["date"].year == 2019
    assert loc.data["count"] == 7
    assert loc.data["flag"] is True


def test_duplicate_keys_are_recorded_not_discarded():
    """safe_load keeps the last duplicate and loses the first in silence.

    Two selection blocks with the same name means half a detection was thrown
    away by the parser, which no amount of reading the rendered rule reveals.
    """
    loc = load("detection:\n    selection:\n        A: 1\n    selection:\n        B: 2\n    condition: selection\n")
    assert loc.duplicates == ((("detection", "selection"), 4),)


def test_duplicate_keys_at_top_level_are_recorded():
    loc = load("title: one\nlevel: high\ntitle: two\n")
    paths = [path for path, _ in loc.duplicates]
    assert ("title",) in paths


def test_malformed_yaml_raises_with_a_line():
    with pytest.raises(ParseError) as caught:
        load("title: ok\n  bad indent: here\n")
    assert caught.value.line is not None


def test_empty_document_raises():
    with pytest.raises(ParseError, match="empty"):
        load("\n# just a comment\n")


def test_multi_document_stream_raises_rather_than_linting_the_first():
    """Linting document one and passing the file would hide document two."""
    with pytest.raises(ParseError):
        load("title: one\n---\ntitle: two\n")


def test_unresolvable_tag_raises_parse_error():
    with pytest.raises(ParseError):
        load("value: !!python/object:os.system {}\n")


def test_a_yaml_error_without_a_position_still_raises_parse_error():
    """A reader error has no problem_mark, so the line is unknown rather than
    wrong. Reporting line 1 for a file whose byte 4000 is bad would send a
    reviewer to the wrong place."""
    with pytest.raises(ParseError) as caught:
        load("title: ok\x00\n")
    assert caught.value.line is None


class TestBothLoadersAgree:
    """The C loader is used when libyaml is present and the pure Python one
    otherwise, so the two have to be interchangeable.

    A difference in the marks would move every finding to the wrong line, which
    is a correctness bug wearing a performance change as a disguise. These
    compare the two on every fixture; the same comparison across all 3,799
    rules of the pinned corpus is recorded in docs/adr/adr-002-yaml-loader.md.
    """

    @staticmethod
    def fixtures():
        root = Path(__file__).parent / "fixtures"
        return sorted(path for path in root.rglob("*.yml"))

    def test_libyaml_is_actually_being_used_here(self):
        # Not a requirement of the tool, but if it is absent in the environment
        # the suite runs in, the comparisons below are comparing one loader
        # with itself and prove nothing.
        assert USING_LIBYAML, "libyaml is absent, so the loader comparison tests are vacuous"

    @pytest.mark.parametrize("path", fixtures.__func__(), ids=lambda path: path.name)
    def test_marks_and_data_match_across_loaders(self, path):
        text = path.read_text(encoding="utf-8")
        try:
            pure = load(text, yaml.SafeLoader)
        except ParseError as pure_error:
            with pytest.raises(ParseError) as c_error:
                load(text, yaml.CSafeLoader)
            assert c_error.value.line == pure_error.line
            return
        compiled = load(text, yaml.CSafeLoader)
        assert pure.lines == compiled.lines
        assert pure.data == compiled.data
        assert pure.duplicates == compiled.duplicates

    @pytest.mark.parametrize(
        "text",
        [
            "title: ok\x00\n",
            "title: ok\n  bad: here\n",
            "a: 1\n---\nb: 2\n",
            "\n# only a comment\n",
            "v: !!python/object:os.system {}\n",
        ],
    )
    def test_failure_modes_match_across_loaders(self, text):
        outcomes = []
        for loader in (yaml.SafeLoader, yaml.CSafeLoader):
            try:
                load(text, loader)
                outcomes.append(("ok", None))
            except ParseError as exc:
                outcomes.append(("error", exc.line))
        assert outcomes[0] == outcomes[1]
