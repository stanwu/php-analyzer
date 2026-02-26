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

            # Handle dependency analysis results separately
            if scanner == "dependency_analysis":
                dep_results = findings
                f.write(f"- **Graph:** {dep_results['nodes']} nodes, {dep_results['edges']} edges\n")
                if dep_results.get("cycles"):
                    f.write(f"- **Cycles Detected:** {len(dep_results['cycles'])}\n")
                
                if dep_results.get("hubs"):
                    f.write("- **Top 5 Hubs (most included files):**\n")
                    for hub, score in dep_results["hubs"]:
                        f.write(f"  - `{hub}` (score: {score})\n")
                
                if dep_results.get("orphans"):
                    f.write("- **Orphan Files (not included by any other file):**\n")
                    for orphan in dep_results["orphans"]:
                        f.write(f"  - `{orphan}`\n")
                f.write("\n")
                continue

            sorted_findings = sorted(findings, key=lambda x: (x.file, x.line))

            for finding in sorted_findings:
                sev = finding.severity
                color = {"HIGH": "orange", "MEDIUM": "yellow", "LOW": "blue", "INFO": "blue"}.get(
                    sev, "red"
                )
                severity_badge = (
                    f"![{sev}](https://img.shields.io/badge/severity-{sev}-{color})"
                )

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
        # Handle dependency analysis results separately for JSON
        if scanner == "dependency_analysis":
            serializable_results[scanner] = findings
            continue

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
