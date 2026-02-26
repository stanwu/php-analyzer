.PHONY: install test test-coverage lint format clean run-sample

install:
	@echo "No runtime dependencies to install."
	@echo "Optional: create a venv and install dev tools (black/flake8) if desired."

test:
	python3 -m unittest -v

test-coverage:
	@echo "Coverage target requires extra tooling (e.g. coverage.py)."
	@echo "Run: python3 -m pip install coverage && coverage run -m unittest && coverage report"

lint:
	flake8 . --max-line-length=100 --exclude=tests/fixtures

format:
	black . --line-length 100

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/

run-sample:
	python analyzer.py /path/to/your/php/project \
	  --mode all --format both --severity HIGH --output report
