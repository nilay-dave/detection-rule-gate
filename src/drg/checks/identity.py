"""Rule identity: the UUID, and whether two rules share one.

A rule without an identifier cannot be tracked across a rename, referenced
from a ticket, or deduplicated against an upstream rule it was copied from.
Every rule in the public corpus has one, which is the point: it is the cheap
hard requirement that the project enforcing it never has to think about.

Duplicate identifiers are the reason a corpus scope exists at all. The usual
way to get one is to copy a rule as a starting point and forget the id, and no
amount of reading either file on its own reveals it.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Iterable, Sequence
from pathlib import Path as FsPath
from typing import Any

from drg.checks.base import Issue, Severity, corpus_check, rule_check
from drg.rules.marks import Located
from drg.rules.model import SigmaRule


@rule_check(
    "missing-rule-id",
    summary="rule has no id",
    rationale=(
        "Without a UUID the rule cannot be tracked across a rename, cited in a ticket, or matched "
        "against the upstream rule it came from. Generate one once and it never changes again."
    ),
    default=Severity.ERROR,
)
def missing_rule_id(rule: SigmaRule, located: Located, options: dict[str, Any]) -> Iterable[Issue]:
    if rule.id is None or not str(rule.id).strip():
        yield Issue("missing-rule-id", "no id field", ("title",))
        return
    try:
        uuid.UUID(str(rule.id))
    except ValueError:
        yield Issue("missing-rule-id", f"id {rule.id!r} is not a UUID", ("id",))


@corpus_check(
    "duplicate-rule-id",
    summary="two rules share an id",
    rationale=(
        "The id is what every downstream system uses to tell one rule from another, so a duplicate "
        "means one of the two is invisible to deduplication, to tracking, and to whichever system "
        "loads them in an order nobody controls."
    ),
    default=Severity.ERROR,
)
def duplicate_rule_id(
    rules: Sequence[tuple[FsPath, SigmaRule, Located]], options: dict[str, Any]
) -> Iterable[Issue]:
    by_id: dict[str, list[FsPath]] = defaultdict(list)
    for path, rule, _ in rules:
        if rule.id and str(rule.id).strip():
            by_id[str(rule.id).strip().lower()].append(path)

    for identifier, paths in sorted(by_id.items()):
        if len(paths) < 2:
            continue
        # Reported against every file that shares the id, because a reviewer
        # looking at one of them needs to be told where the other is.
        for path in sorted(paths):
            others = ", ".join(str(other) for other in sorted(paths) if other != path)
            yield Issue("duplicate-rule-id", f"id {identifier} is also used by {others}", ("id",))
