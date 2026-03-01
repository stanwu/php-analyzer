# PHP Security Analysis

[![CI](https://github.com/stanwu/php-security-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/stanwu/php-security-analysis/actions/workflows/ci.yml)

A Python CLI tool for **static security analysis of PHP web projects**, implemented independently by three AI assistants (Claude, Codex, Gemini) for comparison. Handles large codebases (~15,000+ PHP files) by filtering out vendor directories before analysis.

## Project Structure

```
php-security-analysis/
├── .github/workflows/ci.yml   # GitHub Actions CI (test + lint)
├── .githooks/pre-commit        # Security pre-commit hook
├── claude/                     # Implementation by Claude (Anthropic)
├── codex/                      # Implementation by Codex (OpenAI) — stdlib only
└── gemini/                     # Implementation by Gemini (Google)
```

Each subdirectory is a standalone, runnable tool with identical CLI interface and four scanners.

---

## Features

### Credential Scanner
Detects hardcoded secrets left in source code:

| Rule | Severity | Pattern |
|------|----------|---------|
| `hardcoded_db_password` | CRITICAL | `new mysqli(` / `new MysqliDb(` with literal password |
| `define_secret` | CRITICAL | `define('*KEY*'/'*SECRET*'/'*PASSWORD*'/'*TOKEN*', '...')` |
| `hardcoded_assignment` | HIGH | `$var = '...'` where var name contains key/secret/token/password |
| `base64_encoded_key` | HIGH | Base64 string >40 chars in a credential-named variable |

### Security Scanner
Flags common PHP vulnerabilities:

| Rule | Severity | Pattern |
|------|----------|---------|
| `sql_injection` | CRITICAL | `query()`/`execute()` with un-sanitized `$_GET`/`$_POST`/`$_REQUEST` |
| `shell_exec` | CRITICAL | `shell_exec(`, `exec(`, `system(`, `passthru(` |
| `eval_usage` | HIGH | Any `eval(` call |
| `xss_direct_echo` | HIGH | `echo $_GET[` / `$_POST[` / `$_COOKIE[` without sanitization |
| `dynamic_include` | HIGH | `include`/`require` with a variable path |
| `open_redirect` | MEDIUM | `header('Location:' . $_` |

### Dependency Analyzer
Builds a `require`/`include` call graph using `networkx` (Claude/Gemini) or a custom DiGraph (Codex):

- **Hubs** — files included by many others (high in-degree)
- **Orphans** — files never included (potential dead entry points)
- **Cycles** — circular dependencies (`A → B → A`)

### Dead File Detector
Flags suspicious file names associated with leftover/debug files:

- Name contains: `backup`, `bak`, `bcakup`, `old`, `0ld`, `tmp`, `copy`, `debug`, `123`
- Pattern: `demo-[a-z0-9]{10,}-`
- Known dangerous: `phpinfo.php`, `wp-config.php`, `test.php`, `info.php`

---

## Requirements

- Python 3.10+
- `networkx>=3.0` — Claude and Gemini implementations only (dependency graph)
- `pytest>=7.0`, `pytest-cov>=4.0` — testing
- `flake8>=6.0`, `black>=23.0` — code quality

> **Note:** The Codex implementation has **zero runtime dependencies** (stdlib only).

---

## Installation

```bash
# Claude
pip install -r claude/requirements.txt

# Codex (no runtime deps — dev tools only)
pip install -r codex/requirements.txt

# Gemini
pip install -r gemini/requirements.txt

# Or install all at once
make install-all
```

---

## Usage

```
python analyzer.py [-h] [--mode {security,deps,dead,all}]
                   [--output OUTPUT] [--format {md,json,both}]
                   [--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
                   [--no-color]
                   root
```

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `root` | *(required)* | PHP project root directory |
| `--mode` | `all` | Which scanners to run: `security`, `deps`, `dead`, or `all` |
| `--output` | `report` | Output path without extension |
| `--format` | `md` | Output format: `md`, `json`, or `both` |
| `--severity` | `HIGH` | Minimum severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `--no-color` | off | Disable ANSI terminal colors |

### Examples

```bash
# Full scan — Markdown report, HIGH+ severity
cd claude && python analyzer.py /path/to/php_project

# Security only, both output formats
python analyzer.py /path/to/php_project --mode security --format both

# Dependency graph only, JSON output
python analyzer.py /path/to/php_project --mode deps --format json

# All scans, all severities, custom output path
python analyzer.py /path/to/php_project --mode all --severity INFO --output /tmp/scan

# No color (useful for CI)
python analyzer.py /path/to/php_project --no-color
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

---

## Vendor Directories Excluded

| Directory | Description |
|-----------|-------------|
| `vendor/` | Composer packages |
| `google_config/` | Google SDK |
| `fb_config/` | Facebook SDK |
| `mailer/vendor/` | Mailer dependencies |
| `test/PHPExcel/` | PHPExcel library |
| `classes/mailer/` | PHPMailer |

---

## Implementation Comparison

| Feature | Claude | Codex | Gemini |
|---------|:------:|:-----:|:------:|
| Runtime dependencies | networkx | **None** (stdlib) | networkx |
| Dependency graph | networkx DiGraph | Custom DiGraph | networkx DiGraph |
| Taint tracking (SQL) | No | Yes | No |
| Severity scale | 1–5 | 10–50 | string Literal |
| Report badges | emoji | backtick | shields.io |
| Test framework | pytest | pytest + unittest | pytest |
| Vendor path pruning | recursive walk | early os.walk prune | rglob |
| Config helpers | basic | relpath, count_php | basic |

---

## Development

### Pre-commit Security Hook

A security hook runs automatically before every `git commit`. Install it once:

```bash
make install-hooks
```

The hook scans **staged files only** and blocks the commit if it finds:

| Check | Scope | Blocked patterns |
|-------|-------|-----------------|
| Credential scan | `.py` / `.php` / `.env` | Stripe live keys, AWS access keys, GitHub PATs, private keys, hardcoded passwords |
| Flake8 lint | `.py` | Style errors, unused imports, undefined names (`--max-line-length=100`) |

Files containing `FAKE`, `PLACEHOLDER`, `EXAMPLE`, or similar markers are automatically allow-listed.

### CI / CD

Every push and pull request to `main` triggers GitHub Actions:

| Job | Description |
|-----|-------------|
| `test (claude)` | Install deps → pytest with coverage → upload `coverage.xml` |
| `test (codex)` | Install deps → pytest with coverage → upload `coverage.xml` |
| `test (gemini)` | Install deps → pytest with coverage → upload `coverage.xml` |
| `lint` | flake8 across all three implementations |

### Makefile Reference

All commands work from a subdirectory (`cd claude`, `cd codex`, `cd gemini`). Use the root `Makefile` to operate on all three at once.

```bash
# Install git hooks (run once after cloning)
make install-hooks

# Run tests
make test

# Run tests with coverage
make coverage-all

# Lint all implementations
make lint-all

# Format all implementations
make format-all

# Clean build artifacts
make clean-all
```

---

## License

MIT — see [LICENSE](LICENSE)
