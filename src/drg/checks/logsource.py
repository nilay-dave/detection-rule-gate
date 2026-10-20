"""Flags a log source that narrows nothing useful.

A logsource with a product and no category or service tells a backend to
evaluate the rule against every event that product emits. On a Windows estate
that is every Security, System, Application and Sysmon event, which is a
different order of magnitude from the process creation events the rule
probably meant.

This check fires on 19 of 3,799 rules in the public corpus, which is the
profile of a check worth having on as an error: specific, rare, and almost
always a mistake when it happens.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from drg.checks.base import Issue, Severity, rule_check
from drg.rules.marks import Located
from drg.rules.model import SigmaRule


@rule_check(
    "broad-logsource",
    summary="log source names a product with no category or service",
    rationale=(
        "The backend evaluates the rule against every event the product emits rather than one event "
        "channel, which multiplies the cost of the rule by the size of the estate. Add the category or "
        "the service the detection was written against."
    ),
    default=Severity.WARNING,
)
def broad_logsource(rule: SigmaRule, located: Located, options: dict[str, Any]) -> Iterable[Issue]:
    source = rule.logsource
    if source.category or source.service:
        return
    if not source.product:
        yield Issue("broad-logsource", "log source names neither a product, a category nor a service", ("logsource",))
        return
    yield Issue(
        "broad-logsource",
        f"product {source.product!r} with no category or service",
        ("logsource", "product"),
    )
