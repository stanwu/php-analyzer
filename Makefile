.PHONY: all install-all test test-all test-claude test-codex test-gemini \
        coverage-claude coverage-codex coverage-gemini coverage-all \
        lint-all format-all clean-all

PYTHON := python3

# ── Default ───────────────────────────────────────────────────────────────────
all: test-all

# ── Installation ──────────────────────────────────────────────────────────────
install-all: install-claude install-codex install-gemini

install-claude:
	cd claude && pip install -r requirements.txt

install-codex:
	cd codex && pip install -r requirements.txt

install-gemini:
	cd gemini && pip install -r requirements.txt

# ── Tests ─────────────────────────────────────────────────────────────────────
test: test-all

test-all: test-claude test-codex test-gemini

test-claude:
	@echo "==> Testing claude/"
	cd claude && $(PYTHON) -m pytest tests/ -v --tb=short

test-codex:
	@echo "==> Testing codex/"
	cd codex && $(PYTHON) -m pytest tests/ -v --tb=short

test-gemini:
	@echo "==> Testing gemini/"
	cd gemini && $(PYTHON) -m pytest tests/ -v --tb=short

# ── Coverage ──────────────────────────────────────────────────────────────────
coverage-all: coverage-claude coverage-codex coverage-gemini

coverage-claude:
	@echo "==> Coverage claude/"
	cd claude && $(PYTHON) -m pytest tests/ --cov=. --cov-report=term-missing --cov-report=html

coverage-codex:
	@echo "==> Coverage codex/"
	cd codex && $(PYTHON) -m pytest tests/ --cov=. --cov-report=term-missing --cov-report=html

coverage-gemini:
	@echo "==> Coverage gemini/"
	cd gemini && $(PYTHON) -m pytest tests/ --cov=. --cov-report=term-missing --cov-report=html

# ── Lint ──────────────────────────────────────────────────────────────────────
lint-all:
	@echo "==> Lint claude/"
	cd claude && flake8 . --max-line-length=100 --exclude=tests/fixtures,__pycache__
	@echo "==> Lint codex/"
	cd codex && flake8 . --max-line-length=100 --exclude=tests/fixtures,__pycache__,venv
	@echo "==> Lint gemini/"
	cd gemini && flake8 . --max-line-length=100 --exclude=tests/fixtures,__pycache__

# ── Format ────────────────────────────────────────────────────────────────────
format-all:
	@echo "==> Format claude/"
	cd claude && black . --line-length 100 --exclude tests/fixtures
	@echo "==> Format codex/"
	cd codex && black . --line-length 100 --exclude tests/fixtures
	@echo "==> Format gemini/"
	cd gemini && black . --line-length 100 --exclude tests/fixtures

# ── Clean ─────────────────────────────────────────────────────────────────────
clean-all:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null; true
	find . -type d -name htmlcov -exec rm -rf {} + 2>/dev/null; true
	find . -name ".coverage" -delete
	find . -name "coverage.xml" -delete
	find . -name "report.md" -delete
	find . -name "report.json" -delete
