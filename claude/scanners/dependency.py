import re
import sys
from pathlib import Path

import networkx as nx

from .base import BaseScanner, Finding

# Match require/include statements and capture the path argument
_RE_INCLUDE = re.compile(
    r"""\b(?:require|require_once|include|include_once)\s*\(?\s*['"]([^'"]+)['"]\s*\)?""",
    re.IGNORECASE,
)

# Also catch dirname(__FILE__) / __DIR__ based paths — extract what we can
_RE_INCLUDE_DIR = re.compile(
    r"""\b(?:require|require_once|include|include_once)\s*\(?\s*(?:dirname\s*\(\s*__FILE__\s*\)|__DIR__)\s*\.\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def _resolve_include(source_file: Path, include_path: str, root: Path) -> Path | None:
    """Attempt to resolve an include path relative to the source file or root."""
    # Try relative to the file's directory first
    candidate = (source_file.parent / include_path).resolve()
    if candidate.exists():
        return candidate

    # Try relative to root
    candidate = (root / include_path.lstrip("/")).resolve()
    if candidate.exists():
        return candidate

    return None


def build_graph(files: list[Path], root: Path) -> nx.DiGraph:
    """Build a dependency digraph from require/include statements."""
    G = nx.DiGraph()
    file_set = {f.resolve() for f in files}

    # Add all files as nodes
    for f in files:
        G.add_node(str(f.resolve()))

    for source in files:
        content: str | None = None
        try:
            content = source.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"[!] Warning: cannot read {source}: {e}", file=sys.stderr)
            continue

        lines = content.splitlines()
        for line in lines:
            # Standard include with string literal
            for m in _RE_INCLUDE.finditer(line):
                include_path = m.group(1)
                resolved = _resolve_include(source, include_path, root)
                if resolved and resolved in file_set:
                    G.add_edge(str(source.resolve()), str(resolved))

            # __DIR__ / dirname(__FILE__) based includes
            for m in _RE_INCLUDE_DIR.finditer(line):
                include_path = m.group(1)
                resolved = _resolve_include(source, include_path, root)
                if resolved and resolved in file_set:
                    G.add_edge(str(source.resolve()), str(resolved))

    return G


def find_hubs(G: nx.DiGraph, top_n: int = 10) -> list[tuple[str, int]]:
    """Return top_n nodes sorted by in-degree (most-included files)."""
    in_degrees = [(node, G.in_degree(node)) for node in G.nodes()]
    in_degrees.sort(key=lambda x: x[1], reverse=True)
    return in_degrees[:top_n]


def find_orphans(G: nx.DiGraph, all_files: list[Path]) -> list[str]:
    """Return files with no incoming edges (nothing includes them)."""
    orphans = []
    for node in G.nodes():
        if G.in_degree(node) == 0:
            orphans.append(node)
    return sorted(orphans)


def detect_cycles(G: nx.DiGraph) -> list[list[str]]:
    """Return all simple cycles in the dependency graph."""
    try:
        cycles = list(nx.simple_cycles(G))
        return cycles
    except Exception:
        return []


class DependencyScanner(BaseScanner):
    """Wraps dependency scanning into the BaseScanner interface for unified reporting."""

    def __init__(self, root: Path):
        self.root = root
        self._graph: nx.DiGraph | None = None

    def scan(self, file: Path) -> list[Finding]:
        # Dependency scanner works at graph level; per-file scan returns empty
        return []

    def scan_all(self, files: list[Path]) -> dict:
        """Build and analyze the full dependency graph."""
        G = build_graph(files, self.root)
        self._graph = G
        return {
            "graph": G,
            "node_count": G.number_of_nodes(),
            "edge_count": G.number_of_edges(),
            "hubs": find_hubs(G),
            "orphans": find_orphans(G, files),
            "cycles": detect_cycles(G),
        }

    @property
    def graph(self) -> nx.DiGraph | None:
        return self._graph
