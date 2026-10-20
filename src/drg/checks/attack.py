"""Requires an ATT&CK technique, and tells a tactic apart from one.

``attack.execution`` is a tactic. ``attack.t1059`` is a technique.
``attack.g0016`` is a group and ``attack.s0002`` is a piece of software. All
four are legal Sigma tags in the ``attack`` namespace, and only the technique
answers the question a coverage review asks, which is what this rule detects
rather than why an adversary would do it.

A check that accepted any ``attack.`` prefixed tag would pass 468 rules in the
public corpus that carry a tactic and no technique. Telling the three cases
apart in the message matters too: "add a technique to the tactic you already
have" is a different job from "map this rule", and an engineer reading a
blocked pull request deserves to know which one they are being asked to do.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from drg.checks.base import Issue, Severity, rule_check
from drg.rules.marks import Located
from drg.rules.model import SigmaRule

TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
GROUP_OR_SOFTWARE = re.compile(r"^attack\.[gs]\d{4}$", re.IGNORECASE)


@rule_check(
    "attack-technique-missing",
    summary="rule has no ATT&CK technique tag",
    rationale=(
        "A coverage review counts techniques. A rule tagged only with a tactic cannot be placed on a "
        "coverage matrix, cannot be compared against a threat profile, and cannot be found by anyone "
        "asking what detects a specific technique. Groups and software tags describe who, not what."
    ),
    default=Severity.WARNING,
)
def attack_technique_missing(rule: SigmaRule, located: Located, options: dict[str, Any]) -> Iterable[Issue]:
    tags = rule.tag_list
    if any(TECHNIQUE.match(tag) for tag in tags):
        return

    attack_tags = [tag for tag in tags if tag.lower().startswith("attack.")]
    tactics = [tag for tag in attack_tags if not GROUP_OR_SOFTWARE.match(tag)]
    actors = [tag for tag in attack_tags if GROUP_OR_SOFTWARE.match(tag)]

    if tactics:
        listed = ", ".join(sorted(tactics))
        detail = f"tagged with the tactic {listed} but no technique; add the attack.tNNNN tag that goes with it"
    elif actors:
        listed = ", ".join(sorted(actors))
        detail = f"tagged with {listed}, which names an actor rather than a technique"
    else:
        detail = "no attack.* tags at all"

    yield Issue("attack-technique-missing", detail, ("tags",) if tags else ())
