"""The checks, and the registry that holds them."""

# Importing the modules is what registers them. Listed explicitly rather than
# discovered by scanning the package, because a check that silently fails to
# register is a check that silently stops gating.
from drg.checks import (  # noqa: F401
    attack,
    conditions,
    duplicates,
    falsepositives,
    identity,
    logsource,
    modifiers,
    structural,
    wildcards,
)
from drg.checks.base import (
    CheckSpec,
    Finding,
    Issue,
    Severity,
    corpus_check,
    corpus_checks,
    register_spec,
    registry,
    rule_check,
    rule_checks,
    spec,
)

__all__ = [
    "CheckSpec",
    "Finding",
    "Issue",
    "Severity",
    "corpus_check",
    "corpus_checks",
    "register_spec",
    "registry",
    "rule_check",
    "rule_checks",
    "spec",
]
