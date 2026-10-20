"""Rejects a field modifier the specification does not define.

A misspelled modifier is the worst kind of bug in detection content because
nothing complains. ``TargetFilename|endwith: '\\\\cmd.exe'`` is accepted by a
YAML parser, converts to a query, deploys, runs, and matches nothing for as
long as nobody checks. The rule is in the coverage report the whole time.

The allowed set is transcribed from the Sigma specification appendix on
modifiers, version 2.1.0, at the commit recorded in docs/sources.md. The
regular expression flags are only valid directly after ``re``, so a chain that
uses one on its own is wrong even though the name is a real modifier.

The first draft of this check raised 3 findings on the public corpus, all of
them ``re|i``, and all three were correct Sigma that my allowed set was
missing. Transcribing from the specification rather than from memory took the
count to 0, which is the right answer for a corpus whose own CI validates
modifiers.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from drg.checks.base import Issue, Severity, rule_check
from drg.rules.marks import Located
from drg.rules.model import SigmaRule

GENERIC = {"all", "startswith", "endswith", "contains", "exists", "cased", "neq"}
STRING = {"windash"}
REGEX = {"re"}
REGEX_FLAGS = {"i", "m", "s"}
ENCODING = {"base64", "base64offset", "utf16le", "utf16be", "utf16", "wide"}
NUMERIC = {"lt", "lte", "gt", "gte"}
TIME = {"minute", "hour", "day", "week", "month", "year"}
NETWORK = {"cidr"}
SPECIFIC = {"expand", "fieldref"}

KNOWN = GENERIC | STRING | REGEX | ENCODING | NUMERIC | TIME | NETWORK | SPECIFIC


def _field_keys(block: Any) -> Iterable[tuple[tuple[str | int, ...], str]]:
    if isinstance(block, dict):
        for key, value in block.items():
            text = str(key)
            yield ((text,), text)
            for path, nested in _field_keys(value):
                yield ((text, *path), nested)
    elif isinstance(block, list):
        for index, value in enumerate(block):
            for path, nested in _field_keys(value):
                yield ((index, *path), nested)


@rule_check(
    "unknown-field-modifier",
    summary="field uses a modifier the specification does not define",
    rationale=(
        "A misspelled modifier does not fail. It converts, deploys, runs and matches nothing, while the "
        "rule still appears in the coverage report. Check the spelling against the Sigma modifier "
        "appendix, or add the name to extra_modifiers if your pipeline defines it."
    ),
    default=Severity.ERROR,
    options={"extra_modifiers": []},
)
def unknown_field_modifier(rule: SigmaRule, located: Located, options: dict[str, Any]) -> Iterable[Issue]:
    allowed = KNOWN | {str(name).lower() for name in options.get("extra_modifiers", [])}

    for name, block in rule.detection.selections.items():
        for path, key in _field_keys(block):
            if "|" not in key:
                continue
            parts = key.split("|")
            modifiers = [part.strip().lower() for part in parts[1:]]
            for position, modifier in enumerate(modifiers):
                if modifier in REGEX_FLAGS:
                    # i, m and s are sub modifiers of re, not modifiers in
                    # their own right. Valid only directly after it.
                    if position > 0 and modifiers[position - 1] in REGEX | REGEX_FLAGS:
                        continue
                    yield Issue(
                        "unknown-field-modifier",
                        f"{key!r} uses the regular expression flag {modifier!r} without a preceding 're'",
                        ("detection", name, *path),
                    )
                    continue
                if modifier not in allowed:
                    yield Issue(
                        "unknown-field-modifier",
                        f"{key!r} uses an unknown modifier {modifier!r}",
                        ("detection", name, *path),
                    )
