from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from config import count_php_files, iter_custom_php, iter_non_vendor_files, relpath
from reports.report import write_json, write_markdown
from scanners.base import SEVERITY_ORDER, Finding, Severity
from scanners.credential import CredentialScanner
from scanners.deadfile import DeadFileScanner
from scanners.dependency import build_graph, detect_cycles, find_hubs, find_orphans
from scanners.security import SecurityScanner


def _supports_color(no_color: bool) -> bool:
    if no_color:
        return False
    return sys.stderr.isatty()


def _c(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def _min_severity(s: str) -> Severity:
    s = s.upper()
    if s not in SEVERITY_ORDER:
        raise ValueError(f"Unknown severity: {s}")
    return s  # type: ignore[return-value]


def _filter_findings(findings: list[Finding], minimum: Severity) -> list[Finding]:
    min_w = SEVERITY_ORDER[minimum]
    return [f for f in findings if SEVERITY_ORDER[f.severity] >= min_w]


def _finding_to_dict(f: Finding, root: Path) -> dict[str, Any]:
    return {
        "file": relpath(f.file, root),
        "line": f.line,
        "rule": f.rule,
        "severity": f.severity,
        "match": f.match,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="php-analyzer")
    p.add_argument("root", help="PHP project root directory")
    p.add_argument("--mode", choices=["security", "deps", "dead", "all"], default="all")
    p.add_argument("--output", default="report", help="Output file path (default: report)")
    p.add_argument("--format", choices=["md", "json", "both"], default="md")
    p.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="HIGH",
        help="Minimum severity to report (default: HIGH)",
    )
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors in terminal output")
    args = p.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"[!] Root does not exist: {root}", file=sys.stderr)
        return 2

    color = _supports_color(args.no_color)
    minimum = _min_severity(args.severity)

    custom_count, vendor_count = count_php_files(root)
    print(
        f"[*] Found {custom_count} custom PHP files (excluded {vendor_count} vendor files)",
        file=sys.stderr,
    )

    custom_files = list(iter_custom_php(root))

    results: dict[str, Any] = {
        "meta": {
            "root": str(root),
            "custom_php_files": len(custom_files),
            "vendor_php_files": vendor_count,
        },
        "findings": {},
        "dependency": {},
    }

    if args.mode in ("all", "security"):
        cred = CredentialScanner()
        sec = SecurityScanner()

        print("[*] Running credential scanner...   ", end="", file=sys.stderr)
        cred_findings: list[Finding] = []
        for f in custom_files:
            cred_findings.extend(cred.scan(f))
        cred_findings = _filter_findings(cred_findings, minimum)
        print(f"done ({len(cred_findings)} findings)", file=sys.stderr)

        print("[*] Running security scanner...     ", end="", file=sys.stderr)
        sec_findings: list[Finding] = []
        for f in custom_files:
            sec_findings.extend(sec.scan(f))
        sec_findings = _filter_findings(sec_findings, minimum)
        print(f"done ({len(sec_findings)} findings)", file=sys.stderr)

        results["findings"]["credential"] = [_finding_to_dict(x, root) for x in cred_findings]
        results["findings"]["security"] = [_finding_to_dict(x, root) for x in sec_findings]

    if args.mode in ("all", "deps"):
        print("[*] Running dependency scanner...   ", end="", file=sys.stderr)
        G = build_graph(custom_files, root)
        hubs = find_hubs(G, top_n=10)
        all_rel = [relpath(f, root) for f in custom_files]
        orphans = find_orphans(G, all_rel)
        cycles = detect_cycles(G)
        results["dependency"] = {
            "nodes": int(G.number_of_nodes()),
            "edges": int(G.number_of_edges()),
            "hubs": hubs,
            "orphans": orphans,
            "cycles": cycles,
        }
        print(
            f"done (graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges)",
            file=sys.stderr,
        )

    if args.mode in ("all", "dead"):
        print("[*] Running dead file scanner...    ", end="", file=sys.stderr)
        dead = DeadFileScanner(root)
        dead_findings: list[Finding] = []
        for f in iter_non_vendor_files(root):
            dead_findings.extend(dead.scan(f))
        dead_findings = _filter_findings(dead_findings, minimum)
        results["findings"]["deadfile"] = [_finding_to_dict(x, root) for x in dead_findings]
        print(f"done ({len(dead_findings)} files flagged)", file=sys.stderr)

    out_base = Path(args.output)
    wrote: list[Path] = []
    if args.format in ("md", "both"):
        md_path = out_base.with_suffix(".md")
        write_markdown(results, md_path)
        wrote.append(md_path)
    if args.format in ("json", "both"):
        json_path = out_base.with_suffix(".json")
        write_json(results, json_path)
        wrote.append(json_path)

    for pth in wrote:
        print(_c(f"[+] Report written to {pth}", "32", color), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
