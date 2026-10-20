"""The structural shape of a Sigma rule.

The boundary this module draws is the one the whole tool rests on. A model
error means "this is not a Sigma rule": the condition is missing, the level is
not a level, the detection block is a string. Those are always errors and no
policy file can downgrade them, because a rule that does not parse cannot be
assessed at all and will not load in the SIEM either.

Everything beyond that is a check, and every check has a severity a team can
set. "Your rule has no ATT&CK technique" is a policy position, not a parse
failure, and a team that has not finished mapping its backlog needs to be able
to run the gate anyway.

Unknown top level fields are permitted deliberately. The public corpus carries
``regression_tests_path`` on 471 rules and ``simulation`` on 100, neither of
which is in the specification. A model that forbade extras would reject real
rules from the project that defines the format, which is a strong hint that
the strictness belongs in the checks rather than the parser.
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Level = Literal["informational", "low", "medium", "high", "critical"]
Status = Literal["stable", "test", "experimental", "deprecated", "unsupported"]


class LogSource(BaseModel):
    """Where a rule expects its events to come from.

    Every field is optional in the specification, which is why a logsource that
    narrows nothing is a check rather than a parse error.
    """

    model_config = ConfigDict(extra="allow")

    category: str | None = None
    product: str | None = None
    service: str | None = None
    definition: str | None = None


class Detection(BaseModel):
    """The selections and the condition that combines them.

    Selections arrive as extra fields because their names are chosen by the
    rule author. ``condition`` is the only reserved key, and the specification
    allows either one condition or a list of them.
    """

    model_config = ConfigDict(extra="allow")

    condition: str | list[str]

    @field_validator("condition")
    @classmethod
    def _condition_is_not_blank(cls, value: str | list[str]) -> str | list[str]:
        items = [value] if isinstance(value, str) else value
        if not items or any(not str(item).strip() for item in items):
            raise ValueError("condition must not be empty")
        return value

    @property
    def conditions(self) -> list[str]:
        """The conditions as a list, whichever form the rule used."""
        return [self.condition] if isinstance(self.condition, str) else list(self.condition)

    @property
    def selections(self) -> dict[str, Any]:
        """The named selection blocks, which is every key except condition."""
        extra = self.model_extra or {}
        return {name: value for name, value in extra.items() if name != "condition"}


class SigmaRule(BaseModel):
    """A single Sigma rule.

    ``title``, ``logsource`` and ``detection`` are required because a rule
    without them cannot be deployed. Everything else the specification marks
    optional stays optional here, and the checks decide what a team requires.
    """

    model_config = ConfigDict(extra="allow")

    title: Annotated[str, Field(min_length=1, max_length=256)]
    detection: Detection
    logsource: LogSource

    id: str | None = None
    status: Status | None = None
    description: str | None = None
    references: list[str] | None = None
    author: str | None = None
    date: dt.date | None = None
    modified: dt.date | None = None
    tags: list[str] | None = None
    fields: list[str] | None = None
    falsepositives: list[str | None] | str | None = None
    level: Level | None = None
    related: list[dict[str, Any]] | None = None

    # 2 rules in the public corpus carry a `tags:` key with nothing under it,
    # which YAML loads as None rather than an empty list. The optional types
    # above already accept that, so no validator is needed; tag_list below is
    # what flattens the two spellings of "no tags" for the checks.

    @property
    def false_positive_notes(self) -> list[str]:
        """The falsepositives entries as a list of non empty strings."""
        value = self.falsepositives
        if value is None:
            return []
        items = [value] if isinstance(value, str) else value
        return [str(item) for item in items if item is not None and str(item).strip()]

    @property
    def tag_list(self) -> list[str]:
        """The tags as a list, with an absent tags key treated as no tags."""
        return list(self.tags or [])
