"""Fetches the public Sigma rule corpus at a pinned commit.

Not vendored. Copying 3,799 third party YAML files into this repository would
bury its own code in the language bar, put somebody else's content in every
diff, and make the corpus a thing that has to be updated by hand. Pinning a
commit gives the same reproducibility with none of that: anyone can run this
and get byte for byte what the published numbers were measured against.

The pin moves only in a commit that also updates docs/metrics.json, so the
numbers in the README and the corpus they came from cannot drift apart.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPOSITORY = "https://github.com/SigmaHQ/sigma.git"
COMMIT = "e3f466211866e92553d8389d621ed13cfed5523d"
ROOT = Path(__file__).resolve().parent.parent
DESTINATION = ROOT / ".corpus" / "sigma"

# The directories of rules, which the project keeps apart by maturity.
RULE_DIRECTORIES = (
    "rules",
    "rules-emerging-threats",
    "rules-threat-hunting",
    "rules-compliance",
    "rules-placeholder",
    "rules-dfir",
)


def run(*command: str, cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)


def fetch(destination: Path = DESTINATION, commit: str = COMMIT) -> Path:
    """Clone the corpus at ``commit``, reusing an existing checkout if it matches."""
    if (destination / ".git").is_dir():
        current = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=destination, capture_output=True, text=True, check=False
        ).stdout.strip()
        if current == commit:
            return destination
        shutil.rmtree(destination)

    destination.parent.mkdir(parents=True, exist_ok=True)
    # A full clone of a shallow pin is wasteful; fetch just the one commit.
    run("git", "init", "--quiet", str(destination))
    run("git", "remote", "add", "origin", REPOSITORY, cwd=destination)
    run("git", "fetch", "--quiet", "--depth", "1", "origin", commit, cwd=destination)
    run("git", "checkout", "--quiet", "FETCH_HEAD", cwd=destination)
    return destination


def rule_paths(root: Path) -> list[Path]:
    """The rule directories that exist in this checkout."""
    return [root / name for name in RULE_DIRECTORIES if (root / name).is_dir()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=DESTINATION)
    parser.add_argument("--commit", default=COMMIT)
    args = parser.parse_args(argv)

    try:
        root = fetch(args.destination, args.commit)
    except subprocess.CalledProcessError as exc:
        message = (exc.stderr or "").strip() or "git failed"
        print(f"could not fetch the corpus: {message}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print("git is not on PATH", file=sys.stderr)
        return 1

    counted = sum(len(list(path.rglob("*.yml"))) for path in rule_paths(root))
    print(f"corpus at {root} commit {args.commit[:12]}: {counted} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
