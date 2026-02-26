# php-analyzer

Static analyzer for PHP web projects that focuses on:

- Hardcoded credentials (defines, assignments, DB constructors)
- High-signal security patterns (SQLi, XSS, eval, dynamic include, shell exec, open redirect)
- File-level dependency graph from `require`/`include`
- Suspicious backup/demo/dead files

## Install

No runtime dependencies (stdlib only). Use `python3`.

## Run

```bash
python3 analyzer.py /path/to/php/project --mode all --format both --severity HIGH --output report
```

Outputs `report.md` and/or `report.json` (depending on `--format`).

## Notes

- Vendor/third-party directories are excluded from scanning early for performance.
- Uses regex only (no PHP parser).

## Test

```bash
make test
```
