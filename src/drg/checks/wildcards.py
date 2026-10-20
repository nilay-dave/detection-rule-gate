"""Flags a selection that matches every event in its log source.

The first version of this check flagged any value that was a bare asterisk. On
the public corpus that raised 9 findings, and reading all 9 by hand showed 8
of them were correct Sigma. ``hostPath: '*'`` next to ``verb: create`` and
``objectRef.resource: pods`` is the idiom for "this field is present and not
empty", which is a constraint, not a bug. A check with that false positive
rate is worse than no check at all, because the first thing a team learns from
it is which flag turns the gate off.

What actually costs a SIEM is narrower. A rule is unbounded when some
selection is enough on its own to fire it and every constraint in that
selection matches anything. Then the rule matches every event the log source
produces, minus whatever its filters remove.

Both halves of that are needed. Sole sufficiency rules out the wildcard that
sits inside a negated filter, where matching anything excludes more rather
than less. Requiring every constraint to be unbounded rules out the existence
idiom, where the wildcard field is one constraint among several that narrow.

Against the same corpus the narrowed check raises 1 finding, and that one is a
rule whose only positive constraint is a non empty field, which is a decision
its author should state rather than a mistake. That is what suppressions with
a mandatory reason are for.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from drg.checks.base import Issue, Severity, rule_check
from drg.rules.condition import ConditionError, is_solely_sufficient, parse
from drg.rules.marks import Located
from drg.rules.model import SigmaRule

# A value that imposes no constraint beyond "the field is present". Sigma
# wildcards are * for any run of characters and ? for one character, so a value
# made only of those matches any non empty content.
UNBOUNDED_VALUES = {"*", "**", "*?*", "?*", "*?"}


def _is_unbounded_value(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return False
    text = str(value).strip()
    if not text:
        return False
    return text in UNBOUNDED_VALUES or set(text) == {"*"}


def _constraints(block: Any) -> list[tuple[tuple[str | int, ...], Any]]:
    """Every leaf value in a selection, with its path inside that selection."""
    found: list[tuple[tuple[str | int, ...], Any]] = []

    def walk(node: Any, path: tuple[str | int, ...]) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, (*path, str(key)))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, (*path, index))
        else:
            found.append((path, node))

    walk(block, ())
    return found


@rule_check(
    "unbounded-selection",
    summary="selection matches every event in the log source",
    rationale=(
        "Every constraint in this selection matches any value, and the condition makes the selection "
        "sufficient on its own, so the rule fires on everything the log source emits minus its filters. "
        "That may be deliberate for an allowlist style detection, in which case suppress it with the "
        "reason, so the next reviewer knows it was a decision."
    ),
    default=Severity.WARNING,
)
def unbounded_selection(rule: SigmaRule, located: Located, options: dict[str, Any]) -> Iterable[Issue]:
    selections = rule.detection.selections
    if not selections:
        return

    sufficient: set[str] = set()
    for condition in rule.detection.conditions:
        try:
            node = parse(condition)
        except ConditionError:
            # Reported by condition-unparseable. Guessing at sufficiency from
            # an unread condition is how a check invents a finding.
            continue
        for name in selections:
            if is_solely_sufficient(node, name, set(selections)):
                sufficient.add(name)

    for name in sorted(sufficient):
        constraints = _constraints(selections[name])
        if not constraints:
            continue
        if all(_is_unbounded_value(value) for _, value in constraints):
            fields = sorted({str(path[0]) for path, _ in constraints if path})
            listed = ", ".join(fields) if fields else "its only value"
            yield Issue(
                "unbounded-selection",
                f"selection {name!r} constrains only {listed}, and only to a non empty value",
                ("detection", name),
            )
