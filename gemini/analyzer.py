import argparse
import sys
from pathlib import Path
from collections import defaultdict

from config import iter_custom_php, Severity
from scanners.credential import CredentialScanner
from scanners.security import SecurityScanner
from scanners.dependency import DependencyScanner
from scanners.deadfile import DeadfileScanner
from reports.report import write_markdown, write_json


# ANSI color codes
class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"


def print_summary(msg: str, color: str = Colors.RESET, file=sys.stderr):
    if args.no_color:
        print(msg, file=file)
    else:
        print(f"{color}{msg}{Colors.RESET}", file=file)


def main(args):
    root_path = Path(args.root).resolve()
    if not root_path.is_dir():
        print_summary(f"Error: Root path '{root_path}' is not a valid directory.", Colors.RED)
        sys.exit(1)

    all_php_files = list(root_path.rglob("*.php"))
    custom_php_files = list(iter_custom_php(root_path))

    excluded_count = len(all_php_files) - len(custom_php_files)
    print_summary(
        f"[*] Found {len(custom_php_files)} custom PHP files "
        f"(excluded {excluded_count} vendor files)",
        Colors.BLUE,
    )

    results = defaultdict(list)
    scanners = {
        "security": SecurityScanner(),
        "credential": CredentialScanner(),
        "dead": DeadfileScanner(),
        "deps": DependencyScanner(),
    }

    modes_to_run = scanners.keys() if args.mode == "all" else [args.mode]

    for mode in modes_to_run:
        if mode == "deps":
            continue  # Handled separately

        scanner = scanners[mode]
        print_summary(f"[*] Running {mode} scanner...", Colors.YELLOW, file=sys.stderr)
        for file in custom_php_files:
            findings = scanner.scan(file)
            # Filter by severity
            for finding in findings:
                if Severity.__args__.index(finding.severity) <= Severity.__args__.index(
                    args.severity
                ):
                    results[f"{mode}_scanner"].append(finding)
        print_summary(
            f"[*] Running {mode} scanner... done ({len(results[f'{mode}_scanner'])} findings)",
            Colors.GREEN,
            file=sys.stderr,
        )

    if args.mode == "all" or args.mode == "deps":
        print_summary("[*] Running dependency scanner...", Colors.YELLOW)
        dep_scanner = scanners["deps"]
        graph = dep_scanner.build_graph(custom_php_files, root_path)
        hubs = dep_scanner.find_hubs(graph)
        orphans = dep_scanner.find_orphans(graph, custom_php_files, root_path)
        cycles = dep_scanner.detect_cycles(graph)

        results["dependency_analysis"] = {
            "nodes": graph.number_of_nodes(),
            "edges": graph.number_of_edges(),
            "hubs": hubs,
            "orphans": orphans,
            "cycles": cycles,
        }
        print_summary(
            f"[*] Running dependency scanner... done "
            f"(graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges)",
            Colors.GREEN,
        )

    # Generate reports
    if args.format in ["md", "both"]:
        output_md = Path(f"{args.output}.md").resolve()
        write_markdown(results, output_md)
        print_summary(f"[+] Report written to {output_md}", Colors.GREEN)

    if args.format in ["json", "both"]:
        output_json = Path(f"{args.output}.json").resolve()
        write_json(results, output_json)
        print_summary(f"[+] Report written to {output_json}", Colors.GREEN)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PHP Project Security & Structure Analyzer")
    parser.add_argument("root", help="PHP project root directory")
    parser.add_argument(
        "--mode",
        choices=["security", "deps", "dead", "credential", "all"],
        default="all",
        help="Which scanners to run (default: all)",
    )
    parser.add_argument(
        "--output", default="report", help="Output file path without extension (default: report)"
    )
    parser.add_argument(
        "--format", choices=["md", "json", "both"], default="md", help="Output format (default: md)"
    )
    parser.add_argument(
        "--severity",
        choices=Severity.__args__,
        default="HIGH",
        help="Minimum severity to report (default: HIGH)",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colors in terminal output"
    )

    args = parser.parse_args()
    main(args)
