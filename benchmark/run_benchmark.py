"""Measures the gate against the pinned public corpus.

Every number the README publishes comes from here, and the repeat count is the
reason. An earlier attempt to compare dependency sets by wall clock in this
same environment produced 2.85s, 14.76s and 39.87s for identical work, which
is a range wider than any difference the comparison was looking for. A single
sample would have been reported as a finding. So throughput is measured over
several passes and reported as the median, and the spread is recorded next to
it so a reader can see how much to trust it.

What is measured here: throughput, peak memory, and how often each check fires
across 3,799 real rules. What is not measured here, because it cannot be, is
whether each finding is correct. That is a hand assessment and it lives in
docs/false-positives.md with the rule by rule reasoning.
"""

from __future__ import annotations

import argparse
import json
import resource
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from drg import __version__  # noqa: E402
from drg.checks import Severity, registry  # noqa: E402
from drg.engine import run  # noqa: E402
from drg.policy import default_policy  # noqa: E402

sys.path.insert(0, str(ROOT / "tools"))
from fetch_corpus import COMMIT, DESTINATION, rule_paths  # noqa: E402

REPEATS = 5


def peak_memory_mib() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports kibibytes, macOS reports bytes.
    return usage / 1024 if sys.platform != "darwin" else usage / (1024 * 1024)


def measure(targets: list[Path], repeats: int) -> dict:
    policy = default_policy()
    durations: list[float] = []
    report = None
    for _ in range(repeats):
        start = time.perf_counter()
        report = run(targets, policy)
        durations.append(time.perf_counter() - start)

    assert report is not None
    median = statistics.median(durations)
    counts = report.counts()

    return {
        "tool_version": __version__,
        "corpus_commit": COMMIT,
        "repeats": repeats,
        "files_scanned": report.files_scanned,
        "rules_loaded": report.rules_loaded,
        "findings_total": len(report.findings),
        "suppressed": report.suppressed,
        "seconds_median": round(median, 3),
        "seconds_min": round(min(durations), 3),
        "seconds_max": round(max(durations), 3),
        "rules_per_second": round(report.rules_loaded / median, 1),
        "seconds_per_thousand_rules": round(median / report.rules_loaded * 1000, 3),
        "peak_memory_mib": round(peak_memory_mib(), 1),
        "exit_code_at_error": report.exit_code(Severity.ERROR),
        "exit_code_at_warning": report.exit_code(Severity.WARNING),
        "checks": {
            check_id: {
                "fired": counts.get(check_id, 0),
                "rate_percent": round(counts.get(check_id, 0) / report.rules_loaded * 100, 2),
                "default_severity": entry.default.value,
                "scope": entry.scope,
            }
            for check_id, entry in registry().items()
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DESTINATION)
    parser.add_argument("--repeats", type=int, default=REPEATS)
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "metrics.json")
    args = parser.parse_args(argv)

    if not args.corpus.is_dir():
        print(f"{args.corpus} is absent. Run: make corpus", file=sys.stderr)
        return 1

    targets = rule_paths(args.corpus)
    if not targets:
        print(f"{args.corpus} holds no rule directories", file=sys.stderr)
        return 1

    results = measure(targets, args.repeats)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    print(f"corpus {results['corpus_commit'][:12]}  {results['rules_loaded']} rules")
    print(
        f"median {results['seconds_median']}s over {results['repeats']} passes "
        f"(min {results['seconds_min']}s, max {results['seconds_max']}s)"
    )
    print(f"{results['rules_per_second']} rules/s  {results['seconds_per_thousand_rules']}s per 1000 rules")
    print(f"peak memory {results['peak_memory_mib']} MiB")
    print(f"{results['findings_total']} findings")
    print()
    widest = max(len(name) for name in results["checks"])
    print(f"{'check':<{widest}}  {'fired':>6}  {'rate':>7}  default")
    for check_id, entry in results["checks"].items():
        print(f"{check_id:<{widest}}  {entry['fired']:>6}  {entry['rate_percent']:>6}%  {entry['default_severity']}")
    print()
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
