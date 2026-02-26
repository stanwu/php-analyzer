import re
import sys
from pathlib import Path
from typing import List, Tuple

import networkx as nx

from scanners.base import BaseScanner


class DependencyScanner(BaseScanner):
    """Builds a dependency graph from include/require statements."""

    INCLUDE_PATTERN = re.compile(
        r"(?:include|require)(?:_once)?\s*\(?\s*['\"]([^'\"]+)['\"]", re.IGNORECASE
    )

    def scan(self, file: Path) -> list:
        # This scanner doesn't produce findings in the same way,
        # it's used to build the graph.
        return []

    def build_graph(self, files: List[Path], root: Path) -> nx.DiGraph:
        """Builds a directed graph of file dependencies."""
        graph = nx.DiGraph()
        file_map = {str(f.relative_to(root)): f for f in files}
        graph.add_nodes_from(file_map.keys())

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8")
                source_node = str(file_path.relative_to(root))
                for match in self.INCLUDE_PATTERN.finditer(content):
                    target_file = match.group(1)
                    # Resolve target path relative to the current file's directory
                    target_path = (file_path.parent / target_file).resolve()
                    
                    try:
                        # Normalize and find the relative path from the project root
                        target_node = str(target_path.relative_to(root))
                        if target_node in file_map:
                            graph.add_edge(source_node, target_node)
                    except ValueError:
                        # Included file is outside the project root, ignore it
                        pass

            except (UnicodeDecodeError, IOError) as e:
                print(f"Warning: Could not read file {file_path}: {e}", file=sys.stderr)
        return graph

    def find_hubs(self, graph: nx.DiGraph, top_n: int = 10) -> List[Tuple[str, int]]:
        """Finds the most included files (hubs)."""
        in_degrees = sorted(graph.in_degree, key=lambda item: item[1], reverse=True)
        return in_degrees[:top_n]

    def find_orphans(self, graph: nx.DiGraph, all_files: List[Path], root: Path) -> List[str]:
        """Finds files that are not included by any other file."""
        all_nodes = {str(f.relative_to(root)) for f in all_files}
        included_nodes = {node for edge in graph.edges for node in edge}
        # A better definition of orphan: has no incoming edges.
        # We must also exclude common entrypoints like index.php
        orphans = [node for node, degree in graph.in_degree if degree == 0 and 'index.php' not in node]
        return orphans


    def detect_cycles(self, graph: nx.DiGraph) -> List[List[str]]:
        """Detects circular dependencies."""
        return list(nx.simple_cycles(graph))
