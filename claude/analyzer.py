#!/usr/bin/env python3
"""PHP Project Security & Structure Analyzer — CLI entry point."""

import argparse
import sys
import time
from pathlib import Path

from config import iter_custom_php, is_custom_file
from scanners.base import SEVERITY_ORDER, Finding
from scanners.credential import CredentialScanner
from scanners.security import SecurityScanner
from scanners.dependency import DependencyScanner
from scanners.deadfile import DeadFileScanner
from reports.report import write_markdown, write_json

# ANSI colors
_RESET = "\033[0m"
_BOLD = "\033[1m"
_GREEN = "\033[32m"
_CYAN = "\033[36m"
_YELLOW = "\033[33m"
_RED = "\033[31m"


def _status(msg: str, use_color: bool = True) -> None:
    if use_color:
        print(f"{_CYAN}[*]{_RESET} {msg}", file=sys.stderr)
    else:
        print(f"[*] {msg}", file=sys.stderr)


def _success(msg: str, use_color: bool = True) -> None:
    if use_color:
        print(f"{_GREEN}[+]{_RESET} {msg}", file=sys.stderr)
    else:
        print(f"[+] {msg}", file=sys.stderr)


def _count_total_php(root: Path) -> int:
    """Count ALL PHP files under root (including vendor)."""
    count = 0
    try:
        for p in root.rglob("*.php"):
            count += 1
    except Exception:
        pass
    return count


def _filter_by_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    min_level = SEVERITY_ORDER.get(min_severity, 0)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= min_level]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyzer.py",
        description="Static security analyzer for PHP projects.",
    )
    parser.add_argument("root", type=Path, help="PHP project root directory")
    parser.add_argument(
        "--mode",
        choices=["security", "deps", "dead", "all"],
        default="all",
        help="Which scanners to run (default: all)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("report"),
        help="Output file path without extension (default: report)",
    )
    parser.add_argument(
        "--format",
        choices=["md", "json", "both"],
        default="md",
        help="Output format (default: md)",
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="HIGH",
        help="Minimum severity to report (default: HIGH)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    root: Path = args.root.resolve()
    use_color = not args.no_color

    if not root.is_dir():
        print(f"[!] Error: '{root}' is not a directory or does not exist.", file=sys.stderr)
        return 1

    # Collect custom PHP files
    _status("Collecting PHP files...", use_color)
    custom_files = list(iter_custom_php(root))
    custom_count = len(custom_files)

    # Count total for stats
    total_count = _count_total_php(root)
    vendor_count = total_count - custom_count

    _status(
        f"Found {custom_count} custom PHP files (excluded {vendor_count} vendor files)",
        use_color,
    )

    results: dict = {
        "root": root,
        "stats": {
            "custom_files": custom_count,
            "vendor_files": vendor_count,
            "total_files": total_count,
        },
        "credential_findings": [],
        "security_findings": [],
        "dead_findings": [],
        "dependency_results": None,
    }

    mode = args.mode
    run_security = mode in ("security", "all")
    run_deps = mode in ("deps", "all")
    run_dead = mode in ("dead", "all")

    # Credential scanner (part of security mode)
    if run_security:
        _status("Running credential scanner...", use_color)
        cred_scanner = CredentialScanner()
        cred_findings: list[Finding] = []
        for f in custom_files:
            cred_findings.extend(cred_scanner.scan(f))
        cred_findings = _filter_by_severity(cred_findings, args.severity)
        results["credential_findings"] = cred_findings
        _status(
            f"Running credential scanner...   done ({len(cred_findings)} findings)",
            use_color,
        )

        # Security scanner
        _status("Running security scanner...", use_color)
        sec_scanner = SecurityScanner()
        sec_findings: list[Finding] = []
        for f in custom_files:
            sec_findings.extend(sec_scanner.scan(f))
        sec_findings = _filter_by_severity(sec_findings, args.severity)
        results["security_findings"] = sec_findings
        _status(
            f"Running security scanner...     done ({len(sec_findings)} findings)",
            use_color,
        )

    # Dependency scanner
    if run_deps:
        _status("Running dependency scanner...", use_color)
        dep_scanner = DependencyScanner(root)
        dep_results = dep_scanner.scan_all(custom_files)
        results["dependency_results"] = dep_results
        _status(
            f"Running dependency scanner...   done "
            f"(graph: {dep_results['node_count']} nodes, {dep_results['edge_count']} edges)",
            use_color,
        )

    # Dead file scanner
    if run_dead:
        _status("Running dead file scanner...", use_color)
        dead_scanner = DeadFileScanner()
        dead_findings: list[Finding] = []
        for f in custom_files:
            dead_findings.extend(dead_scanner.scan(f))
        results["dead_findings"] = dead_findings
        _status(
            f"Running dead file scanner...    done ({len(dead_findings)} files flagged)",
            use_color,
        )

    # Write reports
    fmt = args.format
    output_base = args.output

    if fmt in ("md", "both"):
        md_path = output_base.with_suffix(".md")
        write_markdown(results, md_path)
        _success(f"Report written to {md_path}", use_color)

    if fmt in ("json", "both"):
        json_path = output_base.with_suffix(".json")
        write_json(results, json_path)
        _success(f"Report written to {json_path}", use_color)

    return 0


if __name__ == "__main__":
    sys.exit(main())
