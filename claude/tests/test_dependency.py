"""Tests for the dependency scanner."""
import pytest
import tempfile
from pathlib import Path

from scanners.dependency import build_graph, find_hubs, find_orphans, detect_cycles


def _write_php(directory: Path, name: str, content: str) -> Path:
    p = directory / name
    p.write_text(content, encoding="utf-8")
    return p


def test_graph_builds_correctly():
    """Two files where A includes B: assert edge A→B exists in graph."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        file_b = _write_php(root, "b.php", "<?php\n// library file\n")
        file_a = _write_php(root, "a.php", f'<?php\nrequire_once "b.php";\n')

        files = [file_a, file_b]
        G = build_graph(files, root)

        assert str(file_a.resolve()) in G.nodes(), "a.php should be a node"
        assert str(file_b.resolve()) in G.nodes(), "b.php should be a node"
        assert G.has_edge(str(file_a.resolve()), str(file_b.resolve())), (
            "Expected edge from a.php to b.php"
        )


def test_find_hubs_returns_sorted():
    """The hub with the most in-edges must appear first."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        # Create a hub file included by many others
        hub = _write_php(root, "hub.php", "<?php // shared library\n")
        files = [hub]
        for i in range(5):
            f = _write_php(root, f"consumer_{i}.php", f'<?php\nrequire "hub.php";\n')
            files.append(f)
        # One file included by only 1 other
        minor = _write_php(root, "minor.php", "<?php // minor\n")
        includer = _write_php(root, "includer.php", '<?php\nrequire "minor.php";\n')
        files.extend([minor, includer])

        G = build_graph(files, root)
        hubs = find_hubs(G, top_n=10)

        assert hubs, "Expected at least one hub"
        assert hubs[0][0] == str(hub.resolve()), (
            f"Expected hub.php to be the top hub, got {hubs[0][0]}"
        )
        assert hubs[0][1] >= 5, f"Expected hub in-degree >= 5, got {hubs[0][1]}"
        # Verify sorted order: each hub should have >= in-degree of the next
        for i in range(len(hubs) - 1):
            assert hubs[i][1] >= hubs[i + 1][1], "Hubs should be sorted by in-degree descending"


def test_detect_cycles():
    """Files A includes B and B includes A: assert cycle is detected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        file_a = _write_php(root, "cycle_a.php", '<?php\nrequire "cycle_b.php";\n')
        file_b = _write_php(root, "cycle_b.php", '<?php\nrequire "cycle_a.php";\n')

        files = [file_a, file_b]
        G = build_graph(files, root)
        cycles = detect_cycles(G)

        assert len(cycles) >= 1, (
            f"Expected at least 1 cycle between cycle_a.php and cycle_b.php, found none"
        )


def test_no_cycle_for_dag():
    """A simple DAG (A→B→C) should produce no cycles."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        file_c = _write_php(root, "c.php", "<?php // leaf\n")
        file_b = _write_php(root, "b.php", '<?php\nrequire "c.php";\n')
        file_a = _write_php(root, "a.php", '<?php\nrequire "b.php";\n')

        files = [file_a, file_b, file_c]
        G = build_graph(files, root)
        cycles = detect_cycles(G)

        assert len(cycles) == 0, f"Expected no cycles in a DAG, found: {cycles}"


def test_find_orphans():
    """Files with no incoming edges are orphans."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        orphan = _write_php(root, "orphan.php", "<?php // nothing includes this\n")
        included = _write_php(root, "lib.php", "<?php // library\n")
        includer = _write_php(root, "main.php", '<?php\nrequire "lib.php";\n')

        files = [orphan, included, includer]
        G = build_graph(files, root)
        orphans = find_orphans(G, files)

        # Both orphan.php and main.php have no incoming edges
        assert str(orphan.resolve()) in orphans, "orphan.php should be an orphan"
        assert str(includer.resolve()) in orphans, "main.php should be an orphan (entry point)"
        assert str(included.resolve()) not in orphans, "lib.php should NOT be an orphan"
