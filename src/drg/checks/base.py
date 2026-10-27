"""Finding types and the check registry.

A check says what is wrong and where in the document. It does not decide how
serious that is, which file it lives in, or what line that works out to. The
engine resolves those, so a check stays a statement about a rule and the
policy stays in one place.

Every check declares its own default severity, and each default is set from the
rate the check fires at on the public corpus rather than from taste. A check
that fails the build on a quarter of a team's existing rules is a check that
gets switched off in week one, so a high firing rate argues for a warning
default even where the finding is worth making.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path as FsPath
from typing import Any

from drg.rules.marks import Located, Path
from drg.rules.model import SigmaRule


class Severity(StrEnum):
    """How a finding is treated. OFF disables the check entirely."""

    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"
    OFF = "off"

    @property
    def rank(self) -> int:
        return {"error": 3, "warning": 2, "notice": 1, "off": 0}[self.value]


@dataclass(frozen=True)
class Issue:
    """What a check found, before the engine resolves where and how severe.

    ``path`` is a path into the rule document, which the mark index turns into
    a line. ``detail`` is appended to the check's message and is where a check
    puts the specifics, for example which selection name was undefined.
    """

    check: str
    detail: str
    path: Path = ()


@dataclass(frozen=True)
class Finding:
    """A located, severity resolved issue, ready to report."""

    check: str
    detail: str
    severity: Severity
    file: FsPath
    line: int
    rule_id: str | None = None
    rule_title: str | None = None
    suppressed_reason: str | None = None

    @property
    def message(self) -> str:
        return f"{spec(self.check).summary}: {self.detail}" if self.detail else spec(self.check).summary


@dataclass(frozen=True)
class CheckSpec:
    """Everything the reporters and the documentation need about a check.

    ``rationale`` is what a SARIF consumer and the docs table both show. It
    answers the question an engineer asks when a gate blocks their pull
    request, which is not what the rule is but why anyone would enforce it.
    """

    id: str
    summary: str
    rationale: str
    default: Severity
    scope: str  # "rule" or "corpus"
    options: dict[str, Any]  # the check's own defaults, which a policy may override


# A rule check receives the parsed rule, its mark index, and its options from
# the policy file. Most checks ignore the options and take the uniform
# signature anyway, which keeps the registry from needing two shapes of
# callable to accommodate the one check that genuinely has a knob.
RuleCheckFn = Callable[[SigmaRule, Located, dict[str, Any]], Iterable[Issue]]
# A corpus check names the file each issue belongs to, because it is looking at
# many files at once and the engine has no way to infer which one an issue came
# from. An earlier version recovered the path by splitting the message text,
# which worked until a message was reworded.
CorpusCheckFn = Callable[[Sequence[tuple[FsPath, SigmaRule, Located]], dict[str, Any]], Iterable[tuple[FsPath, Issue]]]

_SPECS: dict[str, CheckSpec] = {}
_RULE_CHECKS: dict[str, RuleCheckFn] = {}
_CORPUS_CHECKS: dict[str, CorpusCheckFn] = {}


def rule_check(
    check_id: str, *, summary: str, rationale: str, default: Severity, options: dict[str, Any] | None = None
) -> Callable[[RuleCheckFn], RuleCheckFn]:
    """Register a check that looks at one rule at a time."""

    def register(function: RuleCheckFn) -> RuleCheckFn:
        if check_id in _SPECS:
            raise RuntimeError(f"check id {check_id!r} is registered twice")
        _SPECS[check_id] = CheckSpec(check_id, summary, rationale, default, "rule", dict(options or {}))
        _RULE_CHECKS[check_id] = function
        return function

    return register


def corpus_check(
    check_id: str, *, summary: str, rationale: str, default: Severity, options: dict[str, Any] | None = None
) -> Callable[[CorpusCheckFn], CorpusCheckFn]:
    """Register a check that needs every rule at once.

    Duplicate identifiers cannot be seen one file at a time, which is why the
    two scopes exist rather than pretending every check is per rule.
    """

    def register(function: CorpusCheckFn) -> CorpusCheckFn:
        if check_id in _SPECS:
            raise RuntimeError(f"check id {check_id!r} is registered twice")
        _SPECS[check_id] = CheckSpec(check_id, summary, rationale, default, "corpus", dict(options or {}))
        _CORPUS_CHECKS[check_id] = function
        return function

    return register


def register_spec(entry: CheckSpec) -> None:
    """Register a spec with no callable behind it.

    Used by the structural findings, which the loader raises directly rather
    than any check producing them, and which still need an entry so the
    reporters and the documentation table have no special case.
    """
    if entry.id in _SPECS:
        raise RuntimeError(f"check id {entry.id!r} is registered twice")
    _SPECS[entry.id] = entry


def spec(check_id: str) -> CheckSpec:
    return _SPECS[check_id]


def registry() -> dict[str, CheckSpec]:
    return dict(sorted(_SPECS.items()))


def rule_checks() -> dict[str, RuleCheckFn]:
    return dict(sorted(_RULE_CHECKS.items()))


def corpus_checks() -> dict[str, CorpusCheckFn]:
    return dict(sorted(_CORPUS_CHECKS.items()))
