"""What a team has decided each check means to them.

Two principles shape this file.

A typo in a policy file must not be silent. ``unbounded_selection`` with an
underscore where the check id uses a hyphen would, in a forgiving loader, turn
into a setting that applies to nothing, and the team would believe a check was
configured for as long as nobody checked. Every unknown key is an error.

A suppression must carry a reason. Silencing a finding is a decision, and the
value of writing it down lands on whoever reads the rule next year rather than
on the person typing it, so the tool has to be the one that insists. A
suppression comment with no reason is itself a finding, which means the gate
cannot be quietly switched off one rule at a time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from drg.checks import Severity, registry
from drg.checks.structural import NON_CONFIGURABLE

CONFIG_NAMES = (".detection-rule-gate.yml", ".detection-rule-gate.yaml")

# A suppression names one check and gives a reason. The reason runs to the end
# of the line, so it needs no quoting and cannot be left empty by accident.
SUPPRESSION = re.compile(r"#\s*drg:ignore\s+(?P<check>[A-Za-z0-9_-]+)\s*(?P<rest>.*)$")
REASON = re.compile(r"^reason:\s*(?P<reason>\S.*?)\s*$")


class PolicyError(Exception):
    """A policy file that cannot be applied as written."""


class CheckSetting(BaseModel):
    """One check's entry in a policy file."""

    model_config = ConfigDict(extra="forbid")

    severity: Severity | None = None
    options: dict[str, Any] = {}

    @field_validator("severity", mode="before")
    @classmethod
    def _named_severity(cls, value: Any) -> Any:
        if isinstance(value, str) and value.lower() not in {item.value for item in Severity}:
            allowed = ", ".join(item.value for item in Severity)
            raise ValueError(f"{value!r} is not a severity; use one of {allowed}")
        return value.lower() if isinstance(value, str) else value


@dataclass(frozen=True)
class Policy:
    """The resolved policy: a severity and options for every known check."""

    severities: dict[str, Severity]
    options: dict[str, dict[str, Any]]
    exclude: tuple[str, ...] = ()
    fail_on: Severity = Severity.ERROR
    source: Path | None = None

    def severity_of(self, check_id: str) -> Severity:
        return self.severities.get(check_id, Severity.ERROR)

    def options_for(self, check_id: str) -> dict[str, Any]:
        return self.options.get(check_id, {})

    def excludes(self, path: Path) -> bool:
        """Whether ``path`` is excluded by this policy.

        Patterns are anchored to the directory holding the policy file, the way
        a .gitignore is. Before that, they were matched against the path as
        given, which meant `exclude: ['deprecated/**']` worked when the tool was
        run with a relative path and silently did nothing when it was run with
        an absolute one. Same tree, same config, different answer, no warning,
        which is the exact failure the rest of this loader exists to prevent.
        """
        candidates = [path.as_posix(), path.name]
        root = self.source.parent if self.source else None
        if root is not None:
            try:
                candidates.append(path.resolve().relative_to(root.resolve()).as_posix())
            except (ValueError, OSError):
                # Outside the policy file's tree, so only the path as given and
                # the bare name can match.
                pass
        return any(fnmatch(text, pattern) for text in candidates for pattern in self.exclude)


def default_policy() -> Policy:
    """Every check at the default severity it registered with."""
    specs = registry()
    return Policy(
        severities={check_id: entry.default for check_id, entry in specs.items()},
        options={check_id: dict(entry.options) for check_id, entry in specs.items()},
    )


def load(path: Path) -> Policy:
    """Read a policy file and resolve it against the registry."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: not loadable YAML: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyError(f"{path}: expected a mapping at the top level, found {type(raw).__name__}")

    unknown_top = sorted(set(raw) - {"checks", "exclude", "fail_on"})
    if unknown_top:
        raise PolicyError(f"{path}: unknown setting(s) {', '.join(unknown_top)}; expected checks, exclude or fail_on")

    base = default_policy()
    severities = dict(base.severities)
    options = {check_id: dict(values) for check_id, values in base.options.items()}

    checks = raw.get("checks") or {}
    if not isinstance(checks, dict):
        raise PolicyError(f"{path}: checks must be a mapping of check id to severity")

    known = set(registry())
    for check_id, value in checks.items():
        if check_id not in known:
            close = sorted(name for name in known if name.replace("-", "_") == str(check_id).replace("-", "_"))
            hint = f"; did you mean {close[0]}?" if close else ""
            raise PolicyError(f"{path}: unknown check {check_id!r}{hint}")
        if check_id in NON_CONFIGURABLE:
            raise PolicyError(
                f"{path}: {check_id!r} cannot be configured. A file that does not load cannot be "
                f"assessed, so this finding is always an error."
            )
        setting = _coerce_setting(path, check_id, value)
        if setting.severity is not None:
            severities[check_id] = setting.severity
        if setting.options:
            unknown_options = sorted(set(setting.options) - set(options.get(check_id, {})))
            if unknown_options:
                raise PolicyError(
                    f"{path}: {check_id!r} has no option(s) {', '.join(unknown_options)}"
                )
            options[check_id].update(setting.options)

    exclude = raw.get("exclude") or []
    if not isinstance(exclude, list) or any(not isinstance(item, str) for item in exclude):
        raise PolicyError(f"{path}: exclude must be a list of glob patterns")

    fail_on = raw.get("fail_on", Severity.ERROR.value)
    if str(fail_on).lower() not in {item.value for item in Severity}:
        allowed = ", ".join(item.value for item in Severity)
        raise PolicyError(f"{path}: fail_on must be one of {allowed}")

    return Policy(
        severities=severities,
        options=options,
        exclude=tuple(exclude),
        fail_on=Severity(str(fail_on).lower()),
        source=path,
    )


def _coerce_setting(path: Path, check_id: str, value: Any) -> CheckSetting:
    # YAML 1.1 resolves bare off, no and false to the boolean False, and on,
    # yes and true to True. "off" is the natural way to write "disable this
    # check" and the severity is spelled off, so an unquoted off never reaches
    # here as a string. False is taken as the author's meaning; True is
    # rejected, because on does not say which severity was wanted.
    if value is False:
        value = {"severity": Severity.OFF.value}
    elif value is True:
        raise PolicyError(
            f"{path}: {check_id!r} is set to a value YAML read as true. To disable a check write off; "
            f"to enable one name the severity you want."
        )
    if isinstance(value, str):
        value = {"severity": value}
    if not isinstance(value, dict):
        raise PolicyError(f"{path}: {check_id!r} must be a severity or a mapping, found {type(value).__name__}")
    try:
        return CheckSetting.model_validate(value)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(part) for part in first["loc"]) or check_id
        raise PolicyError(f"{path}: {check_id}.{where}: {first['msg']}") from exc


def discover(start: Path) -> Policy:
    """Find a policy file at or above ``start``, or fall back to defaults."""
    here = start if start.is_dir() else start.parent
    for directory in [here, *here.parents]:
        for name in CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return load(candidate)
    return default_policy()


@dataclass(frozen=True)
class Suppressions:
    """The suppressions declared in one file."""

    reasons: dict[str, str] = field(default_factory=dict)
    without_reason: tuple[tuple[str, int], ...] = ()
    unknown: tuple[tuple[str, int], ...] = ()


def parse_suppressions(text: str, known: set[str] | None = None) -> Suppressions:
    """Read ``# drg:ignore <check> reason: ...`` comments out of a rule file.

    A suppression naming a check that does not exist, and one with no reason,
    are both returned for the engine to report. Dropping either on the floor
    would let a rule look suppressed while the gate still fired, or let the
    gate be switched off without anyone writing down why.
    """
    names = known if known is not None else set(registry())
    reasons: dict[str, str] = {}
    without_reason: list[tuple[str, int]] = []
    unknown: list[tuple[str, int]] = []

    for number, line in enumerate(text.splitlines(), start=1):
        match = SUPPRESSION.search(line)
        if match is None:
            continue
        check_id = match.group("check")
        if check_id not in names:
            unknown.append((check_id, number))
            continue
        reason_match = REASON.match(match.group("rest").strip())
        if reason_match is None:
            without_reason.append((check_id, number))
            continue
        reasons[check_id] = reason_match.group("reason")

    return Suppressions(reasons=reasons, without_reason=tuple(without_reason), unknown=tuple(unknown))
