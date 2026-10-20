"""Tests for the two distribution channels.

A GitHub runner cannot be run here, so these test what is testable: that the
metadata is well formed, that the action depends on nothing third party, and
that the shell in it agrees with what the tool actually prints. The last is the
one that matters, because a counting expression that quietly disagrees with the
output format reports the wrong number of findings on every run and nothing
fails.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / "action.yml"
HOOKS = ROOT / ".pre-commit-hooks.yaml"
FIXTURES = Path(__file__).parent / "fixtures"


def action() -> dict:
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))


def commands(script: str) -> str:
    """The executable lines of a shell block, with comments removed.

    The first version of the install test searched the raw block for the
    command it wanted absent, and failed on the comment that explains why that
    command is absent. A test of what a script does should not read what the
    script says about itself.
    """
    return "\n".join(line for line in script.splitlines() if not line.strip().startswith("#"))


def test_action_metadata_has_what_the_marketplace_requires():
    data = action()
    assert data["name"]
    assert data["description"]
    assert data["runs"]["using"] == "composite"
    assert set(data["branding"]) == {"icon", "color"}


def test_every_composite_step_names_a_shell():
    """A composite step without shell is a validation error at run time, and
    the only way to find out is to push."""
    for step in action()["runs"]["steps"]:
        assert step.get("shell") == "bash", step.get("name")


def test_the_action_uses_no_third_party_action():
    """Every uses: in a composite action runs with the caller's token. The way
    to avoid pinning a SHA and rotating it forever is to need none."""
    assert all("uses" not in step for step in action()["runs"]["steps"])


def test_the_action_installs_from_its_own_checkout():
    """pip install detection-rule-gate here would upgrade the gate under a
    workflow pinned to a tag, and a new check arriving on its own is a build
    that breaks for no reason anyone can see."""
    install = commands(action()["runs"]["steps"][0]["run"])
    assert "$GITHUB_ACTION_PATH" in install
    assert "pip install detection-rule-gate" not in install


def test_the_action_declares_the_outputs_its_step_writes():
    data = action()
    declared = set(data["outputs"])
    written = set(re.findall(r'echo "([a-z-]+)=', data["runs"]["steps"][1]["run"]))
    assert declared == written


def test_the_action_captures_the_exit_code_rather_than_dying_on_it():
    """A gate that fails and leaves no SARIF has told the team there is a
    problem and hidden what it was."""
    run = commands(action()["runs"]["steps"][1]["run"])
    assert "set +e" in run
    assert "PIPESTATUS" in run
    assert run.strip().endswith('exit "$code"')


def test_the_annotation_count_expression_matches_the_real_output(tmp_path):
    """The action counts findings with a grep over the tool's own output. If
    the two ever disagree the reported count is wrong on every run and nothing
    fails, so the expression is run against real output here."""
    data = action()
    pattern = re.search(r"grep -cE '([^']+)'", data["runs"]["steps"][1]["run"]).group(1)

    report = tmp_path / "report.txt"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "drg.cli",
            "check",
            str(FIXTURES / "violations"),
            "--no-config",
            "--format",
            "github",
            "--base",
            str(ROOT),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    report.write_text(completed.stdout, encoding="utf-8")

    counted = subprocess.run(
        ["grep", "-cE", pattern, str(report)], capture_output=True, text=True, check=False
    )
    from drg import engine

    expected = len(engine.run([FIXTURES / "violations"]).findings)
    assert int(counted.stdout.strip()) == expected


def test_the_action_fails_the_step_when_the_gate_fails():
    completed = subprocess.run(
        [sys.executable, "-m", "drg.cli", "check", str(FIXTURES / "violations"), "--no-config", "--format", "github"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert completed.returncode == 1


def test_pre_commit_hook_metadata_is_well_formed():
    hooks = yaml.safe_load(HOOKS.read_text(encoding="utf-8"))
    assert len(hooks) == 1
    hook = hooks[0]
    assert hook["id"] == "detection-rule-gate"
    assert hook["language"] == "python"
    assert hook["entry"].startswith("drg check")
    assert hook["types_or"] == ["yaml"]
    assert hook["pass_filenames"] is True


def test_the_hook_entry_point_exists_in_the_package_metadata():
    """A hook whose entry names a console script the package does not declare
    installs cleanly and fails on first use."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    hook = yaml.safe_load(HOOKS.read_text(encoding="utf-8"))[0]
    command = hook["entry"].split()[0]
    assert f"{command} = " in pyproject


def test_the_hook_command_accepts_the_arguments_pre_commit_will_pass():
    """pre-commit appends the staged filenames, so the entry has to take a
    list of files as positional arguments."""
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "drg.cli",
            "check",
            str(FIXTURES / "clean" / "net_connection_rare_port.yml"),
            str(FIXTURES / "clean" / "proc_creation_certutil_encode.yml"),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert completed.returncode == 0
    assert "2 rules in 2 files" in completed.stdout
