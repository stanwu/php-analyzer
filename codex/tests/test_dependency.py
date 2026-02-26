from scanners.dependency import build_graph, detect_cycles, find_hubs
from tests.util import TempDirTestCase


class DependencyTests(TempDirTestCase):
    def test_graph_builds_correctly(self) -> None:
        root = self.tmp_path()
        a = root / "a.php"
        b = root / "b.php"
        a.write_text("<?php include 'b.php';\n", encoding="utf-8")
        b.write_text("<?php echo 'x';\n", encoding="utf-8")

        G = build_graph([a, b], root)
        self.assertTrue(G.has_edge("a.php", "b.php"))

    def test_find_hubs_returns_sorted(self) -> None:
        root = self.tmp_path()
        hub = root / "hub.php"
        a = root / "a.php"
        b = root / "b.php"
        hub.write_text("<?php echo 'hub';\n", encoding="utf-8")
        a.write_text("<?php include 'hub.php';\n", encoding="utf-8")
        b.write_text("<?php include 'hub.php';\n", encoding="utf-8")

        G = build_graph([hub, a, b], root)
        hubs = find_hubs(G, top_n=3)
        self.assertEqual(hubs[0][0], "hub.php")
        self.assertEqual(hubs[0][1], 2)

    def test_detect_cycles(self) -> None:
        root = self.tmp_path()
        a = root / "a.php"
        b = root / "b.php"
        a.write_text("<?php require 'b.php';\n", encoding="utf-8")
        b.write_text("<?php require 'a.php';\n", encoding="utf-8")

        G = build_graph([a, b], root)
        cycles = detect_cycles(G)
        self.assertTrue(any(set(c) == {"a.php", "b.php"} for c in cycles))
