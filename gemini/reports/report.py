import json
from pathlib import Path
from typing import Dict, List

from config import Finding


def write_markdown(results: Dict[str, List[Finding]], output_path: Path):
    """Writes the analysis results to a Markdown file."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# PHP Security & Structure Analysis Report\n\n")

        # Summary Table
        f.write("## Summary\n\n")
        f.write("| Scanner | Findings |\n")
        f.write("|---------|----------|\n")
        total_findings = 0
        for scanner, findings in results.items():
            f.write(f"| {scanner.replace('_', ' ').title()} | {len(findings)} |\n")
            total_findings += len(findings)
        f.write(f"| **Total** | **{total_findings}** |\n\n")

        if total_findings == 0:
            f.write("✅ No issues found.\n")
            return

        # Detailed Findings
        for scanner, findings in results.items():
            if not findings:
                continue
            f.write(f"## {scanner.replace('_', ' ').title()} Scanner\n\n")

            sorted_findings = sorted(findings, key=lambda x: (x.file, x.line))

            for finding in sorted_findings:
                severity_badge = f"![{finding.severity}](https://img.shields.io/badge/severity-{finding.severity}-red)"
                if finding.severity == "HIGH":
                    severity_badge = f"![{finding.severity}](https://img.shields.io/badge/severity-{finding.severity}-orange)"
                elif finding.severity == "MEDIUM":
                    severity_badge = f"![{finding.severity}](https://img.shields.io/badge/severity-{finding.severity}-yellow)"
                elif finding.severity in ["LOW", "INFO"]:
                    severity_badge = f"![{finding.severity}](https://img.shields.io/badge/severity-{finding.severity}-blue)"

                f.write(f"### `{finding.rule}`\n\n")
                f.write(f"- **Severity:** {finding.severity} {severity_badge}\n")
                f.write(f"- **File:** `{finding.file}`\n")
                if finding.line > 0:
                    f.write(f"- **Line:** {finding.line}\n")
                f.write(f"- **Match:**\n```php\n{finding.match}\n```\n\n")


def write_json(results: Dict[str, List[Finding]], output_path: Path):
    """Writes the analysis results to a JSON file."""
    serializable_results = {}
    for scanner, findings in results.items():
        serializable_results[scanner] = [
            {
                "file": str(finding.file),
                "line": finding.line,
                "rule": finding.rule,
                "severity": finding.severity,
                "match": finding.match,
            }
            for finding in findings
        ]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(serializable_results, f, indent=2)
