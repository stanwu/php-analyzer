from pathlib import Path
import pytest
from scanners.dependency import DependencyScanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"
ROOT_DIR = Path(__file__).parent.parent


@pytest.fixture
def dep_scanner():
    return DependencyScanner()


@pytest.fixture
def simple_graph(dep_scanner):
    files = [FIXTURES_DIR / "a.php", FIXTURES_DIR / "b.php"]
    return dep_scanner.build_graph(files, ROOT_DIR)


@pytest.fixture
def cycle_graph(dep_scanner):
    files = [FIXTURES_DIR / "c.php", FIXTURES_DIR / "d.php"]
    return dep_scanner.build_graph(files, ROOT_DIR)


@pytest.fixture
def hub_graph(dep_scanner):
    files = [FIXTURES_DIR / "hub.php", FIXTURES_DIR / "spoke1.php", FIXTURES_DIR / "spoke2.php"]
    return dep_scanner.build_graph(files, ROOT_DIR)


def test_graph_builds_correctly(simple_graph):
    a_node = str((FIXTURES_DIR / "a.php").relative_to(ROOT_DIR))
    b_node = str((FIXTURES_DIR / "b.php").relative_to(ROOT_DIR))
    assert simple_graph.has_node(a_node)
    assert simple_graph.has_node(b_node)
    assert simple_graph.has_edge(a_node, b_node)


def test_detect_cycles(dep_scanner, cycle_graph):
    cycles = dep_scanner.detect_cycles(cycle_graph)
    c_node = str((FIXTURES_DIR / "c.php").relative_to(ROOT_DIR))
    d_node = str((FIXTURES_DIR / "d.php").relative_to(ROOT_DIR))
    assert [c_node, d_node] in cycles or [d_node, c_node] in cycles


def test_find_hubs_returns_sorted(dep_scanner, hub_graph):
    hubs = dep_scanner.find_hubs(hub_graph)
    hub_node = str((FIXTURES_DIR / "hub.php").relative_to(ROOT_DIR))
    assert hubs[0][0] == hub_node
    assert hubs[0][1] == 2


def test_find_orphans(dep_scanner):
    files = [FIXTURES_DIR / "orphan.php", FIXTURES_DIR / "a.php", FIXTURES_DIR / "b.php"]
    graph = dep_scanner.build_graph(files, ROOT_DIR)
    orphans = dep_scanner.find_orphans(graph, files, ROOT_DIR)
    orphan_node = str((FIXTURES_DIR / "orphan.php").relative_to(ROOT_DIR))
    assert orphan_node in orphans
