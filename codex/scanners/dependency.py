from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Optional

from scanners.digraph import DiGraph, simple_cycles


_INCLUDE_RX = re.compile(
    r"\b(include|include_once|require|require_once)\b\s*(?:\(\s*)?(?P<arg>[^;]+?)\s*\)?\s*;",
    re.IGNORECASE,
)
_QUOTED = re.compile(r"^\s*(['\"])(?P<path>.+?)\1\s*$")


def _extract_literal_path(arg: str) -> Optional[str]:
    arg = arg.strip()
    m = _QUOTED.match(arg)
    if not m:
        return None
    return m.group("path")


def _resolve_include(src: Path, raw: str, root: Path) -> Optional[Path]:
    raw = raw.strip()
    if "://" in raw:
        return None
    p = Path(raw)
    candidates: list[Path] = []
    if p.is_absolute():
        candidates.append(root / p.as_posix().lstrip("/"))
    else:
        candidates.append((src.parent / p).resolve())
        candidates.append((root / p).resolve())

    expanded: list[Path] = []
    for c in candidates:
        expanded.append(c)
        if c.suffix == "":
            expanded.append(c.with_suffix(".php"))

    for c in expanded:
        if c.exists():
            return c
    # Best-effort: still return normalized candidate within root if possible.
    for c in expanded:
        try:
            _ = c.resolve().relative_to(root.resolve())
            return c.resolve()
        except Exception:
            continue
    return None


def build_graph(files: Iterable[Path], root: Path) -> DiGraph:
    root = root.resolve()
    file_list = [f.resolve() for f in files]
    file_set = set(file_list)

    G = DiGraph()
    for f in file_list:
        try:
            rel = f.relative_to(root).as_posix()
        except Exception:
            rel = f.as_posix()
        G.add_node(rel)

    for src in file_list:
        try:
            src_rel = src.relative_to(root).as_posix()
        except Exception:
            src_rel = src.as_posix()
        try:
            text = src.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            for m in _INCLUDE_RX.finditer(line):
                raw = _extract_literal_path(m.group("arg"))
                if not raw:
                    continue
                resolved = _resolve_include(src, raw, root)
                if not resolved:
                    continue
                resolved = resolved.resolve()
                if resolved not in file_set:
                    continue
                try:
                    dst_rel = resolved.relative_to(root).as_posix()
                except Exception:
                    dst_rel = resolved.as_posix()
                G.add_edge(src_rel, dst_rel)
    return G


def find_hubs(G: DiGraph, top_n: int = 10) -> list[tuple[str, int]]:
    hubs = [(n, int(G.in_degree(n))) for n in G.nodes]
    hubs.sort(key=lambda t: (-t[1], t[0]))
    return hubs[:top_n]


def find_orphans(G: DiGraph, all_files: Iterable[str]) -> list[str]:
    entry_names = {"index.php", "main.php", "app.php", "bootstrap.php"}
    orphans: list[str] = []
    all_set = set(all_files)
    for n in all_set:
        if G.in_degree(n) != 0:
            continue
        base = Path(n).name.lower()
        if base in entry_names:
            continue
        if base == "index.php":
            continue
        orphans.append(n)
    orphans.sort()
    return orphans


def detect_cycles(G: DiGraph) -> list[list[str]]:
    cycles = [c for c in simple_cycles(G)]
    cycles.sort(key=lambda c: (len(c), c))
    return cycles
