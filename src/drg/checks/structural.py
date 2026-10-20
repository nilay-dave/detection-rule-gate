"""The two findings a policy file is not allowed to downgrade.

A rule that does not parse, or that parses and is not a Sigma rule, cannot be
assessed. Letting a team set these to a warning would mean a gate that passes
files the SIEM will reject, which is the one outcome a gate exists to prevent.
They are registered like any other check so the reporters, the documentation
table and the SARIF rule list need no special case, and policy.py refuses to
change their severity by name.
"""

from __future__ import annotations

from drg.checks.base import CheckSpec, Severity, register_spec

NON_CONFIGURABLE = frozenset(
    {"rule-unparseable", "rule-invalid", "suppression-without-reason", "suppression-unknown-check"}
)

register_spec(
    CheckSpec(
        id="rule-unparseable",
        summary="file is not loadable YAML",
        rationale=(
            "The file could not be parsed, so no other check ran against it. A backend will reject it "
            "for the same reason."
        ),
        default=Severity.ERROR,
        scope="file",
        options={},
    )
)

register_spec(
    CheckSpec(
        id="rule-invalid",
        summary="file is valid YAML but not a Sigma rule",
        rationale=(
            "A required field is absent or has a value the specification does not allow. The rule will "
            "not load, so the remaining checks were not run against it."
        ),
        default=Severity.ERROR,
        scope="file",
        options={},
    )
)

register_spec(
    CheckSpec(
        id="suppression-without-reason",
        summary="suppression comment gives no reason",
        rationale=(
            "Silencing a finding is a decision, and the person who benefits from it being written down "
            "is whoever reads the rule next year. Add 'reason: ' and a sentence after the check name."
        ),
        default=Severity.ERROR,
        scope="file",
        options={},
    )
)

register_spec(
    CheckSpec(
        id="suppression-unknown-check",
        summary="suppression names a check that does not exist",
        rationale=(
            "The suppression applies to nothing, so the rule looks silenced and the gate still fires. "
            "A misspelled check id here is the quietest way to believe a finding was handled."
        ),
        default=Severity.ERROR,
        scope="file",
        options={},
    )
)
