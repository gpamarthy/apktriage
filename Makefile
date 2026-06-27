.PHONY: help install lint format typecheck test coverage corpus-fetch corpus clean

UV      ?= uv
VENV    ?= .venv
PY      := $(VENV)/bin/python
RUFF    := $(VENV)/bin/ruff
MYPY    := $(VENV)/bin/mypy
PYTEST  := $(VENV)/bin/pytest

help:
	@echo "Targets:"
	@echo "  install     create py3.12 venv (uv) and install dev deps"
	@echo "  lint        ruff check + format check"
	@echo "  format      ruff format (write) + autofix"
	@echo "  typecheck   mypy --strict on src/"
	@echo "  test        full pytest (offline; corpus deselected)"
	@echo "  corpus-fetch download the real-APK corpus (network)"
	@echo "  corpus      fetch + run real-APK validation tests"
	@echo "  coverage    pytest with coverage report"
	@echo "  clean       remove venv + caches"

install: $(VENV)/.installed

$(VENV)/.installed: pyproject.toml
	$(UV) venv --python 3.12 $(VENV)
	$(UV) pip install --python $(PY) -e ".[all]"
	touch $(VENV)/.installed

lint: install
	$(RUFF) check src tests examples
	$(RUFF) format --check src tests examples

format: install
	$(RUFF) check --fix src tests examples
	$(RUFF) format src tests examples

typecheck: install
	$(MYPY) src

test: install
	$(PYTEST) -q

corpus-fetch: install
	$(PY) tests/corpus/fetch.py

corpus: corpus-fetch
	$(PYTEST) -q -m corpus

coverage: install
	$(PYTEST) --cov=apktriage --cov-branch --cov-report=term-missing --cov-report=xml

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache .mypy_cache build dist .coverage coverage.xml htmlcov *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
