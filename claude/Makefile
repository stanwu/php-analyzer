.PHONY: install test test-coverage lint format clean run-sample

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v --tb=short

test-coverage:
	pytest tests/ --cov=. --cov-report=term-missing --cov-report=html

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
