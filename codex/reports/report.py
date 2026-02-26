from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanners.base import SEVERITY_ORDER


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(results: dict[str, Any], output: Path) -> None:
    payload = dict(results)
    payload.setdefault("generated_at", _now_iso())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _severity_counts(results: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for scanner_name, items in results.get("findings", {}).items():
        for f in items:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        counts.setdefault(sev, 0)
    return counts


def _badge(sev: str) -> str:
    return f"`{sev}`"


def write_markdown(results: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)

    meta = results.get("meta", {})
    counts = _severity_counts(results)

    lines: list[str] = []
    lines.append("# php-analyzer report")
    lines.append("")
    lines.append(f"- Root: `{meta.get('root', '')}`")
    if "custom_php_files" in meta:
        lines.append(f"- Custom PHP files: `{meta['custom_php_files']}`")
    if "vendor_php_files" in meta:
        lines.append(f"- Vendor PHP files (excluded): `{meta['vendor_php_files']}`")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"| {_badge(sev)} | {counts.get(sev, 0)} |")
    lines.append("")

    dep = results.get("dependency", {})
    if dep:
        lines.append("## Dependency Graph")
        lines.append("")
        lines.append(
            f"- Graph: `{dep.get('nodes', 0)}` nodes, `{dep.get('edges', 0)}` edges"
        )
        hubs = dep.get("hubs", [])
        if hubs:
            lines.append("- Top hubs (in-degree):")
            for name, deg in hubs:
                lines.append(f"  - `{name}`: `{deg}`")
        cycles = dep.get("cycles", [])
        if cycles:
            lines.append(f"- Cycles detected: `{len(cycles)}`")
        lines.append("")

    lines.append("## Findings")
    lines.append("")

    all_findings: list[dict[str, Any]] = []
    for scanner_name, items in results.get("findings", {}).items():
        for f in items:
            f2 = dict(f)
            f2["scanner"] = scanner_name
            all_findings.append(f2)

    def sort_key(f: dict[str, Any]) -> tuple[int, str, int]:
        sev = f.get("severity", "INFO")
        weight = SEVERITY_ORDER.get(sev, 0)
        file = f.get("file", "")
        line = int(f.get("line", 0))
        return (-weight, file, line)

    all_findings.sort(key=sort_key)
    if not all_findings:
        lines.append("_No findings._")
        lines.append("")
    else:
        for f in all_findings:
            sev = f.get("severity", "INFO")
            file = f.get("file", "")
            line = f.get("line", 1)
            rule = f.get("rule", "")
            match = f.get("match", "")
            link = f"[`{file}:{line}`]({file}#L{line})"
            lines.append(
                f"- {_badge(sev)} {link} **{rule}** ({f.get('scanner', '')}): `{match}`"
            )

    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
