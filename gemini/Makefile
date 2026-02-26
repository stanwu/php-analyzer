.PHONY: install test lint format clean run-sample

VENV_PYTHON = venv/bin/python3

.PHONY: install test lint format clean run-sample

install:
	$(VENV_PYTHON) -m pip install -r requirements.txt

test:
	$(VENV_PYTHON) -m pytest tests/ -v --tb=short

test-coverage:
	$(VENV_PYTHON) -m pytest tests/ --cov=. --cov-report=term-missing --cov-report=html

lint:
	$(VENV_PYTHON) -m flake8 . --max-line-length=100 --exclude=tests/fixtures

format:
	$(VENV_PYTHON) -m black . --line-length 100

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/ venv/

run-sample:
	$(VENV_PYTHON) analyzer.py /path/to/your/php/project \
	  --mode all --format both --severity HIGH --output report


