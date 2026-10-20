# PYTHON is the interpreter everything runs through. The console scripts pip
# installs bind to whichever interpreter installed them, which on a machine with
# several Pythons is not necessarily the one on PATH. Running modules through an
# explicit interpreter removes that class of "works for me" report.
# Override with: make verify PYTHON=python3.12
PYTHON ?= python3

.PHONY: install verify test lint corpus bench selfcheck clean

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check src tests tools benchmark scripts

test:
	$(PYTHON) -m pytest --cov=drg --cov-report=term-missing --cov-report=xml

# Runs every check CI runs, in the same order, so a green local verify means a
# green build. A verify that is a subset of CI is a verify that lies.
verify: lint test
	$(PYTHON) tools/check_dashes.py
	$(PYTHON) tools/check_dependencies.py
	$(PYTHON) scripts/provenance_check.py

# Fetches the public Sigma corpus at the commit pinned in tools/fetch_corpus.py.
# Not vendored: see the note in .gitignore.
corpus:
	$(PYTHON) tools/fetch_corpus.py

bench: corpus
	$(PYTHON) benchmark/run_benchmark.py

# The gate run against this repository's own fixtures. A linter that cannot be
# pointed at a directory and produce a stable exit code is not a gate.
selfcheck:
	$(PYTHON) -m drg.cli check tests/fixtures/clean --fail-on error

clean:
	rm -rf .pytest_cache .ruff_cache htmlcov coverage.xml .coverage build dist
