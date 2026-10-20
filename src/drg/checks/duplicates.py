"""Reports a YAML key that appears twice in the same mapping.

The parser is the only place this is visible. safe_load keeps the last value
for a repeated key and discards the earlier one without a word, so a rule with
two ``selection`` blocks loses half its detection inside the loader and then
behaves exactly like a rule that only ever had one. Nothing downstream can
tell the difference, which is why the loader records duplicates instead of
letting the parser decide.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from drg.checks.base import Issue, Severity, rule_check
from drg.rules.marks import Located
from drg.rules.model import SigmaRule


@rule_check(
    "duplicate-yaml-key",
    summary="the same key appears twice in one mapping",
    rationale=(
        "The YAML parser keeps the last value and discards the earlier one in silence. If the repeated "
        "key is a selection, half the detection was lost before any check could see it, and the rule "
        "will behave as though the first block was never written."
    ),
    default=Severity.ERROR,
)
def duplicate_yaml_key(rule: SigmaRule, located: Located, options: dict[str, Any]) -> Iterable[Issue]:
    for path, line in located.duplicates:
        name = ".".join(str(part) for part in path)
        yield Issue("duplicate-yaml-key", f"{name!r} is defined again on line {line}", path)
