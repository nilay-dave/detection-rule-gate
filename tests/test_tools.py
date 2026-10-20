"""Tests for the scripts that gate every build.

These run on every commit and decide whether it lands, and until now none of
them had a test. A quality check that is quietly broken is worse than no check,
because the build stays green and everyone believes the thing is being checked.
Two of them were in fact broken when this file was written, and both bugs are
pinned below.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"


def run_tool(name: str, *args: str, cwd: Path | None = None):
    return subprocess.run(
        [sys.executable, str(TOOLS / name), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd or ROOT,
    )


class TestCheckDashes:
    def test_a_clean_file_passes(self, tmp_path):
        target = tmp_path / "clean.md"
        target.write_text("A sentence, with a comma: and a colon.\n", encoding="utf-8")
        assert run_tool("check_dashes.py", str(target)).returncode == 0

    @pytest.mark.parametrize("code_point", [0x2014, 0x2013, 0x2012, 0x2015])
    def test_each_forbidden_dash_is_caught(self, tmp_path, code_point):
        target = tmp_path / "dashed.md"
        target.write_text(f"a {chr(code_point)} b\n", encoding="utf-8")
        result = run_tool("check_dashes.py", str(target))
        assert result.returncode == 1
        assert "dash" in result.stderr

    def test_a_hyphen_is_not_a_dash(self, tmp_path):
        target = tmp_path / "hyphen.md"
        target.write_text("a well-known thing\n", encoding="utf-8")
        assert run_tool("check_dashes.py", str(target)).returncode == 0

    def test_the_tool_does_not_trip_over_its_own_table(self):
        """The forbidden characters are built from code points rather than
        written literally, so this file can be run over itself."""
        assert run_tool("check_dashes.py", str(TOOLS / "check_dashes.py")).returncode == 0

    def test_the_position_is_reported(self, tmp_path):
        target = tmp_path / "dashed.md"
        target.write_text(f"first line\nsecond {chr(0x2014)} here\n", encoding="utf-8")
        assert ":2:8:" in run_tool("check_dashes.py", str(target)).stderr

    def test_with_no_arguments_it_reads_the_git_file_list(self):
        """Regression: it walked the working tree for markdown, so a third
        party corpus fetched into an ignored directory failed the build on
        somebody else's README."""
        source = (TOOLS / "check_dashes.py").read_text(encoding="utf-8")
        assert "git" in source and "ls-files" in source
        assert run_tool("check_dashes.py").returncode == 0

    def test_a_binary_file_is_skipped(self, tmp_path):
        target = tmp_path / "image.png"
        target.write_bytes(b"\x89PNG\r\n\x1a\n\xff\xfe")
        assert run_tool("check_dashes.py", str(target)).returncode == 0


class TestCheckTables:
    def test_a_well_formed_table_passes(self, tmp_path):
        target = tmp_path / "t.md"
        target.write_text("| a | b |\n| --- | --- |\n| 1 | 2 |\n", encoding="utf-8")
        assert run_tool("check_tables.py", str(target)).returncode == 0

    def test_an_unescaped_pipe_in_a_cell_is_caught(self, tmp_path):
        """The bug this tool exists for: Sigma writes modifiers with a pipe,
        and a pipe inside a cell ends the cell."""
        target = tmp_path / "t.md"
        target.write_text("| rule | selection |\n| --- | --- |\n| x | Image|endswith |\n", encoding="utf-8")
        result = run_tool("check_tables.py", str(target))
        assert result.returncode == 1
        assert "3 columns" in result.stderr

    def test_an_escaped_pipe_is_fine(self, tmp_path):
        target = tmp_path / "t.md"
        target.write_text("| rule | selection |\n| --- | --- |\n| x | Image\\|endswith |\n", encoding="utf-8")
        assert run_tool("check_tables.py", str(target)).returncode == 0

    def test_a_table_inside_a_fence_is_ignored(self, tmp_path):
        """A pipe in a code block is shell, not a table."""
        target = tmp_path / "t.md"
        target.write_text("```\ngrep x | wc -l\n```\n", encoding="utf-8")
        assert run_tool("check_tables.py", str(target)).returncode == 0

    def test_a_short_row_is_caught(self, tmp_path):
        target = tmp_path / "t.md"
        target.write_text("| a | b | c |\n| --- | --- | --- |\n| 1 | 2 |\n", encoding="utf-8")
        assert run_tool("check_tables.py", str(target)).returncode == 1

    def test_this_repository_has_no_malformed_tables(self):
        assert run_tool("check_tables.py").returncode == 0


class TestCheckNumbers:
    def test_a_matching_number_passes(self, tmp_path):
        metrics = tmp_path / "m.json"
        metrics.write_text(json.dumps({"rules_loaded": 3799}), encoding="utf-8")
        readme = tmp_path / "README.md"
        readme.write_text("over <!--number:rules_loaded-->3799<!--/number--> rules\n", encoding="utf-8")
        assert run_tool("check_numbers.py", "--readme", str(readme), "--metrics", str(metrics)).returncode == 0

    def test_a_drifted_number_fails(self, tmp_path):
        metrics = tmp_path / "m.json"
        metrics.write_text(json.dumps({"rules_loaded": 3799}), encoding="utf-8")
        readme = tmp_path / "README.md"
        readme.write_text("over <!--number:rules_loaded-->4000<!--/number--> rules\n", encoding="utf-8")
        assert run_tool("check_numbers.py", "--readme", str(readme), "--metrics", str(metrics)).returncode == 1

    def test_a_hyphenated_metric_path_resolves(self, tmp_path):
        """Regression: the path pattern excluded hyphens, and every check id in
        this project is hyphenated. Fourteen published numbers were going
        unparsed."""
        metrics = tmp_path / "m.json"
        metrics.write_text(json.dumps({"checks": {"broad-logsource": {"fired": 19}}}), encoding="utf-8")
        readme = tmp_path / "README.md"
        readme.write_text("<!--number:checks.broad-logsource.fired-->19<!--/number-->\n", encoding="utf-8")
        assert run_tool("check_numbers.py", "--readme", str(readme), "--metrics", str(metrics)).returncode == 0

    def test_a_relative_path_argument_does_not_crash(self, tmp_path):
        """Regression: relative_to raised on a path given relative to the
        working directory, which is the one invocation a person types."""
        result = run_tool("check_numbers.py", "--readme", "README.md", "--metrics", "docs/metrics.json")
        assert result.returncode == 0, result.stderr

    def test_an_unparseable_marker_fails_rather_than_being_skipped(self, tmp_path):
        metrics = tmp_path / "m.json"
        metrics.write_text(json.dumps({"a": 1}), encoding="utf-8")
        readme = tmp_path / "README.md"
        readme.write_text("<!--number:not a path-->1<!--/number-->\n", encoding="utf-8")
        assert run_tool("check_numbers.py", "--readme", str(readme), "--metrics", str(metrics)).returncode == 1

    def test_rounding_within_tolerance_passes(self, tmp_path):
        metrics = tmp_path / "m.json"
        metrics.write_text(json.dumps({"seconds": 1.5942}), encoding="utf-8")
        readme = tmp_path / "README.md"
        readme.write_text("<!--number:seconds-->1.594<!--/number-->\n", encoding="utf-8")
        assert run_tool("check_numbers.py", "--readme", str(readme), "--metrics", str(metrics)).returncode == 0


class TestCheckDependencies:
    def test_this_repository_declares_nothing_it_does_not_import(self):
        result = run_tool("check_dependencies.py")
        assert result.returncode == 0
        assert "2 declared dependencies" in result.stdout


class TestGenerateChecksDoc:
    def test_the_committed_file_matches_the_registry(self):
        assert run_tool("generate_checks_doc.py", "--check").returncode == 0

    def test_every_table_link_resolves_to_a_heading(self):
        """The SARIF help link points at an anchor in this file, so a check
        with no section is a link to nothing from the security tab."""
        import re

        text = (ROOT / "docs" / "checks.md").read_text(encoding="utf-8")
        links = set(re.findall(r"\]\(#([a-z-]+)\)", text))
        headings = set(re.findall(r"^## ([a-z-]+)$", text, re.M))
        assert links and links <= headings

    def test_every_registered_check_has_a_section(self):
        sys.path.insert(0, str(ROOT / "src"))
        from drg.checks import registry

        text = (ROOT / "docs" / "checks.md").read_text(encoding="utf-8")
        for check_id in registry():
            assert f"## {check_id}" in text, check_id

    def test_a_drifted_file_is_reported(self, tmp_path, monkeypatch):
        target = ROOT / "docs" / "checks.md"
        original = target.read_text(encoding="utf-8")
        try:
            target.write_text(original + "\nstray line\n", encoding="utf-8")
            result = run_tool("generate_checks_doc.py", "--check")
            assert result.returncode == 1
            assert "out of date" in result.stderr
        finally:
            target.write_text(original, encoding="utf-8")


class TestFetchCorpus:
    def test_the_pin_is_a_full_commit_sha(self):
        """An abbreviated sha or a branch name is not a pin, and a corpus that
        moves makes every published number unreproducible."""
        sys.path.insert(0, str(TOOLS))
        from fetch_corpus import COMMIT

        assert len(COMMIT) == 40
        assert all(character in "0123456789abcdef" for character in COMMIT)

    def test_the_pin_matches_the_one_the_metrics_were_measured_against(self):
        sys.path.insert(0, str(TOOLS))
        from fetch_corpus import COMMIT

        metrics = json.loads((ROOT / "docs" / "metrics.json").read_text(encoding="utf-8"))
        assert metrics["corpus_commit"] == COMMIT

    def test_the_corpus_directory_is_ignored_rather_than_vendored(self):
        assert ".corpus/" in (ROOT / ".gitignore").read_text(encoding="utf-8")
        tracked = subprocess.run(
            ["git", "ls-files", ".corpus"], capture_output=True, text=True, check=False, cwd=ROOT
        )
        assert tracked.stdout.strip() == ""
