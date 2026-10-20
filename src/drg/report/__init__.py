"""Ways of rendering a report.

Each module exposes ``render``, and the names are re-exported from here with a
prefix. An earlier version named the function in sarif.py ``sarif``, which
shadowed the module of the same name inside this package and made
drg.report.sarif resolve to the function. Nothing broke until a test needed to
reach the module to patch a constant in it, at which point the only way through
was sys.modules. Two things with one qualified name is worth the rename.
"""

from drg.report.github import render_annotations, render_job_summary
from drg.report.json_report import render as render_json
from drg.report.sarif import render as render_sarif
from drg.report.text import render as render_text

__all__ = ["render_annotations", "render_job_summary", "render_json", "render_sarif", "render_text"]
