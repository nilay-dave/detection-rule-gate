"""Checks that depend on reading the condition.

Two findings come out of here and they are deliberately separate. A condition
this tool cannot parse is reported as its own finding rather than silently
skipping the checks that needed it, because a gate that quietly stops checking
is worse than a gate that says it is confused.
"""

from __future__ import annotations

from collections.abc import Iterable
from fnmatch import fnmatchcase
from typing import Any

from drg.checks.base import Issue, Severity, rule_check
from drg.rules.condition import ConditionError, parse, referenced_names
from drg.rules.marks import Located
from drg.rules.model import SigmaRule


@rule_check(
    "condition-unparseable",
    summary="condition cannot be read",
    rationale=(
        "Either the condition is malformed, or it uses a form this tool does not implement. Both are "
        "worth stopping for: the first will not load in a backend, and the second means the checks that "
        "read the condition did not run on this rule, so the rule was not fully gated."
    ),
    default=Severity.ERROR,
)
def condition_unparseable(rule: SigmaRule, located: Located, options: dict[str, Any]) -> Iterable[Issue]:
    conditions = rule.detection.conditions
    for index, condition in enumerate(conditions):
        try:
            parse(condition)
        except ConditionError as exc:
            base = ("detection", "condition")
            path = base if len(conditions) == 1 else (*base, index)
            yield Issue("condition-unparseable", f"{condition!r}: {exc}", path)


@rule_check(
    "condition-undefined-selection",
    summary="condition names a selection the rule does not define",
    rationale=(
        "A backend resolves the missing name to nothing, so the rule either matches everything or "
        "matches nothing depending on where the name sits in the condition. Neither failure announces "
        "itself: the rule deploys, runs, and is silently not the detection anyone reviewed."
    ),
    default=Severity.ERROR,
)
def condition_undefined_selection(rule: SigmaRule, located: Located, options: dict[str, Any]) -> Iterable[Issue]:
    defined = set(rule.detection.selections)
    for condition in rule.detection.conditions:
        try:
            node = parse(condition)
        except ConditionError:
            # Reported by condition-unparseable. Raising it twice in different
            # words would make one problem look like two.
            continue
        for name in sorted(referenced_names(node)):
            if "*" in name:
                if not any(fnmatchcase(candidate, name) for candidate in defined):
                    yield Issue(
                        "condition-undefined-selection",
                        f"pattern {name!r} matches none of the selections this rule defines",
                        ("detection", "condition"),
                    )
            elif name not in defined:
                yield Issue(
                    "condition-undefined-selection",
                    f"{name!r} is not defined; the rule defines {sorted(defined)}",
                    ("detection", "condition"),
                )
