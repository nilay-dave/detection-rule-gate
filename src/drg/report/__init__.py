"""Ways of rendering a report."""

from drg.report.github import annotations, job_summary
from drg.report.sarif import sarif
from drg.report.text import text

__all__ = ["annotations", "job_summary", "sarif", "text"]
