import json
from pathlib import Path
from datetime import datetime

from scanners.base import Finding, SEVERITY_ORDER

_SEVERITY_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🔵 LOW",
    "INFO": "⚪ INFO",
}

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def write_markdown(results: dict, output: Path) -> None:
    """Write a structured Markdown report."""
    lines: list[str] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines.append("# PHP Security Analysis Report")
    lines.append(f"\n**Generated:** {now}")

    root = results.get("root", "unknown")
    lines.append(f"**Project root:** `{root}`")
    lines.append("")

    # Summary table
    all_findings: list[Finding] = []
    for key in ("credential_findings", "security_findings"):
        all_findings.extend(results.get(key, []))

    counts = _count_by_severity(all_findings)

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        badge = _SEVERITY_BADGE.get(sev, sev)
        lines.append(f"| {badge} | {counts.get(sev, 0)} |")
    lines.append("")

    # Stats
    stats = results.get("stats", {})
    if stats:
        lines.append("## File Statistics")
        lines.append("")
        lines.append(f"- **Custom PHP files scanned:** {stats.get('custom_files', 0)}")
        lines.append(f"- **Vendor files excluded:** {stats.get('vendor_files', 0)}")
        lines.append(f"- **Total PHP files found:** {stats.get('total_files', 0)}")
        lines.append("")

    root_path = Path(root) if root != "unknown" else None

    # Credential findings
    cred_findings: list[Finding] = results.get("credential_findings", [])
    if cred_findings is not None:
        lines.append("## Credential & Secret Findings")
        lines.append("")
        if cred_findings:
            _append_findings_table(lines, cred_findings, root_path)
        else:
            lines.append("_No credential findings._")
        lines.append("")

    # Security findings
    sec_findings: list[Finding] = results.get("security_findings", [])
    if sec_findings is not None:
        lines.append("## Security Vulnerability Findings")
        lines.append("")
        if sec_findings:
            _append_findings_table(lines, sec_findings, root_path)
        else:
            lines.append("_No security findings._")
        lines.append("")

    # Dependency analysis
    dep_results = results.get("dependency_results")
    if dep_results:
        lines.append("## Dependency Analysis")
        lines.append("")
        lines.append(
            f"- **Nodes (files):** {dep_results.get('node_count', 0)}"
        )
        lines.append(f"- **Edges (include relationships):** {dep_results.get('edge_count', 0)}")

        hubs = dep_results.get("hubs", [])
        if hubs:
            lines.append("")
            lines.append("### Top Included Files (Hubs)")
            lines.append("")
            lines.append("| File | In-degree |")
            lines.append("|------|-----------|")
            for node, degree in hubs[:10]:
                try:
                    node_display = Path(node).relative_to(root_path) if root_path else node
                except ValueError:
                    node_display = node
                lines.append(f"| `{node_display}` | {degree} |")

        cycles = dep_results.get("cycles", [])
        if cycles:
            lines.append("")
            lines.append(f"### Circular Dependencies ({len(cycles)} detected)")
            lines.append("")
            for i, cycle in enumerate(cycles[:10], 1):
                cycle_str = " → ".join(f"`{n}`" for n in cycle)
                lines.append(f"{i}. {cycle_str}")

        orphans = dep_results.get("orphans", [])
        if orphans:
            lines.append("")
            lines.append(f"### Orphaned Files ({len(orphans)} files with no incoming includes)")
            lines.append("")
            for orphan in orphans[:20]:
                try:
                    orphan_display = Path(orphan).relative_to(root_path) if root_path else orphan
                except ValueError:
                    orphan_display = orphan
                lines.append(f"- `{orphan_display}`")
            if len(orphans) > 20:
                lines.append(f"- _...and {len(orphans) - 20} more_")
        lines.append("")

    # Dead files
    dead_findings: list[Finding] = results.get("dead_findings", [])
    if dead_findings is not None:
        lines.append("## Dead / Backup File Findings")
        lines.append("")
        if dead_findings:
            lines.append("| File | Reason |")
            lines.append("|------|--------|")
            for f in dead_findings:
                try:
                    dead_display = f.file.relative_to(root_path) if root_path else f.file.name
                except ValueError:
                    dead_display = f.file.name
                lines.append(f"| `{dead_display}` | {f.match} |")
        else:
            lines.append("_No dead/backup files found._")
        lines.append("")

    output.write_text("\n".join(lines), encoding="utf-8")


def _append_findings_table(
    lines: list[str], findings: list[Finding], root: Path | None = None
) -> None:
    """Append a formatted findings table to lines."""
    # Sort by severity then file
    sorted_findings = sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), str(f.file), f.line),
    )

    lines.append("| Severity | File | Line | Rule | Match |")
    lines.append("|----------|------|------|------|-------|")
    for f in sorted_findings:
        badge = _SEVERITY_BADGE.get(f.severity, f.severity)
        # Show path relative to root when possible, fall back to filename only
        try:
            display_path = f.file.relative_to(root) if root else f.file.name
        except ValueError:
            display_path = f.file.name
        # Sanitize match: strip newlines, escape pipes, truncate
        match_clean = " ".join(f.match.splitlines()).strip()
        match_escaped = match_clean.replace("|", "\\|")[:80]
        if len(match_clean) > 80:
            match_escaped += "…"
        lines.append(
            f"| {badge} | `{display_path}` | {f.line} | `{f.rule}` | `{match_escaped}` |"
        )


def write_json(results: dict, output: Path) -> None:
    """Write a machine-readable JSON report."""

    def _finding_to_dict(f: Finding) -> dict:
        return {
            "file": str(f.file),
            "line": f.line,
            "rule": f.rule,
            "severity": f.severity,
            "match": f.match,
        }

    dep_results = results.get("dependency_results")
    dep_serializable = None
    if dep_results:
        dep_serializable = {
            "node_count": dep_results.get("node_count", 0),
            "edge_count": dep_results.get("edge_count", 0),
            "hubs": dep_results.get("hubs", []),
            "orphans": dep_results.get("orphans", []),
            "cycles": dep_results.get("cycles", []),
        }

    payload = {
        "generated_at": datetime.now().isoformat(),
        "root": str(results.get("root", "")),
        "stats": results.get("stats", {}),
        "credential_findings": [
            _finding_to_dict(f) for f in results.get("credential_findings", [])
        ],
        "security_findings": [
            _finding_to_dict(f) for f in results.get("security_findings", [])
        ],
        "dead_findings": [
            _finding_to_dict(f) for f in results.get("dead_findings", [])
        ],
        "dependency_results": dep_serializable,
    }

    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
