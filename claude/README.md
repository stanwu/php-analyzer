# php-analyzer

A Python CLI tool for static security analysis of PHP web projects. Efficiently
handles large codebases (~15,000 PHP files) by filtering out third-party vendor
directories before analysis.

## Features

- **Credential Scanner** — Detects hardcoded DB passwords, API keys, secrets,
  and tokens (`define()`, constructor args, variable assignments, base64 keys)
- **Security Scanner** — Flags SQL injection, XSS, `eval()`, dynamic includes,
  shell execution, and open redirects
- **Dependency Analyzer** — Builds a `require`/`include` graph; identifies hubs,
  orphans, and circular dependencies using `networkx`
- **Dead File Detector** — Flags backup files, old copies, demo scripts, and
  known dangerous files like `phpinfo.php`

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```
usage: analyzer.py [-h] [--mode {security,deps,dead,all}]
                   [--output OUTPUT] [--format {md,json,both}]
                   [--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
                   [--no-color]
                   root
```

### Examples

```bash
# Full scan, Markdown report, HIGH+ severity
python analyzer.py /path/to/php_project

# Security only, both formats
python analyzer.py /path/to/php_project --mode security --format both

# Dependency graph only
python analyzer.py /path/to/php_project --mode deps --format json

# All scans, all severities, custom output path
python analyzer.py /path/to/php_project --mode all --severity INFO --output /tmp/scan
```

### Sample Terminal Output

```
[*] Collecting PHP files...
[*] Found 436 custom PHP files (excluded 14,194 vendor files)
[*] Running credential scanner...   done (12 findings)
[*] Running security scanner...     done (34 findings)
[*] Running dependency scanner...   done (graph: 436 nodes, 891 edges)
[*] Running dead file scanner...    done (9 files flagged)
[+] Report written to report.md
```

## Vendor Directories Excluded

The following directories are treated as third-party and excluded from analysis:

| Directory | Description |
|-----------|-------------|
| `vendor/` | Composer packages |
| `google_config/` | Google SDK |
| `fb_config/` | Facebook SDK |
| `mailer/vendor/` | Mailer dependencies |
| `test/PHPExcel/` | PHPExcel library |
| `classes/mailer/` | PHPMailer |

## Scanner Rules

### Credential Scanner

| Rule | Severity | Description |
|------|----------|-------------|
| `hardcoded_db_password` | CRITICAL | `new mysqli(` / `new MysqliDb(` with literal string password |
| `define_secret` | CRITICAL | `define('*KEY*'/'*SECRET*'/'*PASSWORD*'/'*TOKEN*', '...')` |
| `hardcoded_assignment` | HIGH | `$var = '...'` where var name contains key/secret/token/password |
| `base64_encoded_key` | HIGH | Base64 strings >40 chars in credential-named variables |

### Security Scanner

| Rule | Severity | Description |
|------|----------|-------------|
| `sql_injection` | CRITICAL | `query()`/`execute()` with un-sanitized `$_GET`/`$_POST`/`$_REQUEST` |
| `shell_exec` | CRITICAL | `shell_exec(`, `exec(`, `system(`, `passthru(` |
| `eval_usage` | HIGH | Any `eval(` call |
| `xss_direct_echo` | HIGH | `echo $_GET[`/`$_POST[`/`$_REQUEST[`/`$_COOKIE[` without sanitization |
| `dynamic_include` | HIGH | `include`/`require` with a variable path |
| `open_redirect` | MEDIUM | `header('Location:' . $_` |

### Dead File Scanner

Flags files whose names contain: `backup`, `bak`, `bcakup`, `old`, `0ld`,
`tmp`, `copy`, `debug`, `123`, or match pattern `demo-[a-z0-9]{10,}-`.
Also flags `phpinfo.php`, `wp-config.php`, `test.php`, `info.php`.

## Development

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage

# Lint
make lint

# Format
make format

# Clean build artifacts
make clean
```

## Requirements

- Python 3.10+
- `networkx>=3.0` (dependency graph)
- `pytest>=7.0`, `pytest-cov>=4.0` (testing)
- `flake8>=6.0`, `black>=23.0` (code quality)

No external PHP parser is required — analysis uses `re` (regex) only.
