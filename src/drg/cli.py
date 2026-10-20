"""The command line interface.

argparse rather than a third party argument parser, and the reasoning is in
docs/adr/adr-001-dependency-budget.md. Short version: this runs on every pull
request, every dependency is a download and a supply chain edge on every run,
and nothing here needs more than the standard library provides.

Three commands. ``check`` is the gate. ``checks`` lists what the gate enforces
and at what severity, so a team can read the policy without reading the source.
``explain`` prints why one check exists, which is the question someone asks
when a gate has just blocked their pull request.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from drg import __version__
from drg.checks import Severity, registry
from drg.engine import run
from drg.policy import PolicyError, default_policy, discover, load
from drg.report import render_annotations, render_job_summary, render_sarif, render_text

FORMATS = ("auto", "text", "github", "sarif")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="drg",
        description="Fail a detection-as-code change when a Sigma rule is unmapped, unbounded or undocumented.",
    )
    parser.add_argument("--version", action="version", version=f"detection-rule-gate {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="check rules and set the exit code")
    check.add_argument("paths", nargs="+", type=Path, help="files or directories of Sigma rules")
    check.add_argument(
        "--format",
        choices=FORMATS,
        default="auto",
        help="auto picks github inside GitHub Actions and text everywhere else",
    )
    check.add_argument("--output", type=Path, help="write the report here instead of to stdout")
    check.add_argument(
        "--fail-on",
        choices=[item.value for item in Severity],
        help="exit non zero at this severity or above; off never fails (default: from config, else error)",
    )
    check.add_argument("--config", type=Path, help="policy file (default: nearest .detection-rule-gate.yml)")
    check.add_argument("--no-config", action="store_true", help="ignore any policy file and use the defaults")
    check.add_argument("--base", type=Path, help="repository root, for paths in github and sarif output")
    check.add_argument("--rationale", action="store_true", help="print why each finding is enforced")
    check.add_argument("--repository", help="repository URL, used for help links in sarif output")
    check.add_argument(
        "--summary",
        action="store_true",
        help="append a markdown summary to the file named by GITHUB_STEP_SUMMARY",
    )

    listing = subparsers.add_parser("checks", help="list every check, its severity and its scope")
    listing.add_argument("--config", type=Path, help="show the severities this policy file resolves to")
    listing.add_argument("--rationale", action="store_true", help="include why each check is enforced")

    explain = subparsers.add_parser("explain", help="print why one check exists")
    explain.add_argument("check", help="the check id")

    return parser


def _resolve_policy(args: argparse.Namespace, first_target: Path):
    if getattr(args, "no_config", False):
        return default_policy()
    if getattr(args, "config", None):
        return load(args.config)
    return discover(first_target)


def _command_check(args: argparse.Namespace) -> int:
    policy = _resolve_policy(args, args.paths[0])
    fail_on = Severity(args.fail_on) if args.fail_on else policy.fail_on
    report = run(args.paths, policy)

    chosen = args.format
    if chosen == "auto":
        chosen = "github" if os.environ.get("GITHUB_ACTIONS") == "true" else "text"

    base = args.base
    if chosen == "sarif":
        rendered = render_sarif(report, base=base or Path.cwd(), repository=args.repository)
    elif chosen == "github":
        # Annotations land on the diff; the text report goes to the log, because
        # an annotation only shows on a line that the pull request touched and
        # a reviewer still needs the whole list.
        rendered = "\n".join(render_annotations(report, base=str(base) if base else None))
        report_text = render_text(report, fail_on=fail_on, show_rationale=args.rationale)
        rendered = f"{rendered}\n\n{report_text}"
    else:
        rendered = render_text(report, fail_on=fail_on, show_rationale=args.rationale)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(rendered, end="" if rendered.endswith("\n") else "\n")

    if args.summary:
        destination = os.environ.get("GITHUB_STEP_SUMMARY")
        if destination:
            with open(destination, "a", encoding="utf-8") as handle:
                handle.write(render_job_summary(report, fail_on=fail_on, base=str(base) if base else None))
        else:
            print("--summary was given but GITHUB_STEP_SUMMARY is not set", file=sys.stderr)

    return report.exit_code(fail_on)


def _command_checks(args: argparse.Namespace) -> int:
    policy = load(args.config) if args.config else default_policy()
    specs = registry()
    widest = max(len(name) for name in specs)
    print(f"{'check':<{widest}}  {'severity':<8}  scope")
    for check_id, entry in specs.items():
        severity = policy.severity_of(check_id)
        print(f"{check_id:<{widest}}  {severity.value:<8}  {entry.scope}")
        if args.rationale:
            print(f"{'':<{widest}}  {entry.rationale}")
    return 0


def _command_explain(args: argparse.Namespace) -> int:
    specs = registry()
    entry = specs.get(args.check)
    if entry is None:
        close = sorted(name for name in specs if name.replace("-", "_") == args.check.replace("-", "_"))
        hint = f" Did you mean {close[0]}?" if close else ""
        print(f"no check called {args.check!r}.{hint}", file=sys.stderr)
        print("Run 'drg checks' for the list.", file=sys.stderr)
        return 2
    print(f"{entry.id}")
    print(f"  {entry.summary}")
    print()
    print(f"  {entry.rationale}")
    print()
    print(f"  default severity: {entry.default.value}")
    print(f"  scope: {entry.scope}")
    if entry.options:
        print(f"  options: {entry.options}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "check":
            return _command_check(args)
        if args.command == "checks":
            return _command_checks(args)
        return _command_explain(args)
    except PolicyError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"{exc.filename}: no such file or directory", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
