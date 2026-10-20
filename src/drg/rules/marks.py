"""Parses YAML once and keeps the line of every value.

A linter is only useful in code review if a finding lands on the offending
line. ``yaml.safe_load`` returns plain dicts and lists with the positions
discarded, and a pydantic model built from those dicts cannot recover them
either, so a naive implementation can only report the file. Reviewing a 60 line
rule by being told "something in this file is wrong" is barely better than
being told nothing.

PyYAML is layered, and the layer below ``safe_load`` is the one that helps. A
loader exposes two steps: compose a node tree, where every node carries a
start mark, and then construct Python objects from that tree. Calling both by
hand costs one parse and yields the data and the positions together.

The node tree also preserves information ``safe_load`` throws away silently.
A mapping with the same key twice arrives as two pairs here, where
``safe_load`` would quietly keep the last and lose the first. That is a real
way to lose half a detection, so duplicates are recorded rather than dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

Path = tuple[str | int, ...]


class ParseError(Exception):
    """A document that is not loadable YAML, carrying the position if known."""

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.line = line


@dataclass(frozen=True)
class Located:
    """A loaded document with the source position of each value.

    ``lines`` maps a path to the 1-based line the value starts on. For a
    mapping entry the recorded position is the key's, because that is what a
    reviewer looks for. ``duplicates`` records every mapping key that appeared
    more than once, with the line of each later occurrence.
    """

    data: Any
    lines: dict[Path, int] = field(default_factory=dict)
    duplicates: tuple[tuple[Path, int], ...] = ()

    def line_for(self, path: Path) -> int:
        """The line for ``path``, falling back to its nearest known ancestor.

        A finding is sometimes raised against a path that no node occupies, for
        example a field a rule should have had and does not. Walking up to the
        nearest ancestor puts the annotation on the enclosing block instead of
        defaulting to the top of the file, which is where a reviewer would have
        to start searching.
        """
        probe: Path = tuple(path)
        while probe:
            if probe in self.lines:
                return self.lines[probe]
            probe = probe[:-1]
        return self.lines.get((), 1)


def _index(node: yaml.Node, path: Path, lines: dict[Path, int], dupes: list[tuple[Path, int]]) -> None:
    lines.setdefault(path, node.start_mark.line + 1)
    if isinstance(node, yaml.MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            key = key_node.value
            child = (*path, key)
            if key in seen:
                dupes.append((child, key_node.start_mark.line + 1))
            else:
                seen.add(key)
                lines[child] = key_node.start_mark.line + 1
            _index(value_node, child, lines, dupes)
    elif isinstance(node, yaml.SequenceNode):
        for position, item in enumerate(node.value):
            child = (*path, position)
            lines[child] = item.start_mark.line + 1
            _index(item, child, lines, dupes)


def load(text: str) -> Located:
    """Load a single YAML document, keeping positions.

    Raises ParseError for unparseable YAML and for a stream that holds more
    than one document. Multi document rule collections are a real Sigma
    feature and are out of scope for this version; see
    docs/limitations.md for the trigger to implement them. Reporting them as a
    parse error with a clear message beats silently linting the first document
    and passing a file whose second half was never read.
    """
    # The constructor is inside the try on purpose. SafeLoader's Reader checks
    # the whole string for printable characters as it is built, so a file with
    # a stray control byte raises before get_single_node is ever called. With
    # the constructor outside, one such file ended the entire run instead of
    # becoming one finding, which is the failure the engine is built to avoid.
    try:
        loader = yaml.SafeLoader(text)
        node = loader.get_single_node()
    except yaml.MarkedYAMLError as exc:
        line = exc.problem_mark.line + 1 if exc.problem_mark else None
        raise ParseError(str(exc.problem or exc), line) from exc
    except yaml.YAMLError as exc:
        raise ParseError(str(exc)) from exc

    if node is None:
        loader.dispose()
        raise ParseError("document is empty")

    try:
        data = loader.construct_document(node)
    except yaml.MarkedYAMLError as exc:
        line = exc.problem_mark.line + 1 if exc.problem_mark else None
        raise ParseError(str(exc.problem or exc), line) from exc
    finally:
        loader.dispose()

    lines: dict[Path, int] = {}
    dupes: list[tuple[Path, int]] = []
    _index(node, (), lines, dupes)
    return Located(data=data, lines=lines, duplicates=tuple(dupes))
