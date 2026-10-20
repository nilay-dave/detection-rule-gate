"""Requires a real false positive note on the rules that page someone.

Sigma convention fills the field with the literal word Unknown when nobody has
worked out what else fires the rule. That is honest, and as a handover it is
nothing: the analyst who gets the alert at 03:00 learns that the rule's author
also did not know.

The firing rate is why this check defaults to a warning rather than an error.
On the public corpus 1,575 of 3,799 rules have no usable note, and 949 of
those are high or critical. A gate that failed the build on a quarter of a
team's existing rules would be switched off in its first week, so the default
reports and does not block, and a team that has caught up can raise it.

Only high and critical are considered by default, because that is where the
cost of a blind alert lands. The levels are an option rather than a constant
so a team can widen it without editing the check.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from drg.checks.base import Issue, Severity, rule_check
from drg.rules.marks import Located
from drg.rules.model import SigmaRule

# Entries that occupy the field without saying anything. Compared case folded.
PLACEHOLDER_NOTES = {"unknown", "none", "n/a", "na", "no", "nothing", "not applicable", "tbd", "todo", "unclear"}


@rule_check(
    "missing-falsepositives",
    summary="rule has no usable false positive note",
    rationale=(
        "The note is the handover to whoever triages the alert. An empty field, or the word Unknown, "
        "tells them the author did not know either, which is the moment a real detection starts being "
        "closed as noise. Name one thing that legitimately fires this rule, or say explicitly that "
        "nothing is expected to."
    ),
    default=Severity.WARNING,
    options={"levels": ["high", "critical"]},
)
def missing_falsepositives(rule: SigmaRule, located: Located, options: dict[str, Any]) -> Iterable[Issue]:
    levels = {str(level).lower() for level in options.get("levels", ["high", "critical"])}
    if levels and (rule.level or "").lower() not in levels:
        return

    notes = rule.false_positive_notes
    if not notes:
        yield Issue("missing-falsepositives", f"level {rule.level} rule with no falsepositives entry", ("level",))
        return

    if all(note.strip().lower().rstrip(".") in PLACEHOLDER_NOTES for note in notes):
        listed = ", ".join(repr(note) for note in notes)
        yield Issue(
            "missing-falsepositives",
            f"level {rule.level} rule whose only falsepositives entry is {listed}",
            ("falsepositives",),
        )
