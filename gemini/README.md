# PHP Project Security & Structure Analyzer

A Python CLI tool to statically analyze a PHP web project for security vulnerabilities, hardcoded credentials, dependency structure, and dead/backup files.

## Usage

```bash
# Install dependencies
make install

# Run on a sample project
python analyzer.py /path/to/your/php/project --mode all --format both

# Run tests
make test
```
