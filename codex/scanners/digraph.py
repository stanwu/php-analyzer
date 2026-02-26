from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import TypeVar

T = TypeVar("T", bound=str)


class DiGraph:
    def __init__(self) -> None:
        self._succ: dict[str, set[str]] = {}
        self._in_degree: dict[str, int] = {}
        self._edge_count = 0

    @property
    def nodes(self) -> list[str]:
        return list(self._succ.keys())

    def add_node(self, n: str) -> None:
        if n in self._succ:
            return
        self._succ[n] = set()
        self._in_degree.setdefault(n, 0)

    def add_edge(self, u: str, v: str) -> None:
        self.add_node(u)
        self.add_node(v)
        if v in self._succ[u]:
            return
        self._succ[u].add(v)
        self._in_degree[v] = self._in_degree.get(v, 0) + 1
        self._edge_count += 1

    def has_edge(self, u: str, v: str) -> bool:
        return v in self._succ.get(u, set())

    def in_degree(self, n: str) -> int:
        return int(self._in_degree.get(n, 0))

    def number_of_nodes(self) -> int:
        return len(self._succ)

    def number_of_edges(self) -> int:
        return int(self._edge_count)

    def successors(self, n: str) -> Iterable[str]:
        return self._succ.get(n, set())


def simple_cycles(G: DiGraph) -> Iterator[list[str]]:
    """
    Yield simple directed cycles.

    - Each cycle is returned as a list of nodes without repeating the start node.
    - To avoid duplicates, cycles are anchored at their lexicographically-smallest node.
    """

    nodes = sorted(G.nodes)
    index = {n: i for i, n in enumerate(nodes)}

    seen: set[tuple[str, ...]] = set()

    for start in nodes:
        start_i = index[start]
        path: list[str] = [start]

        def dfs(v: str) -> Iterator[list[str]]:
            for w in sorted(G.successors(v)):
                wi = index.get(w)
                if wi is None or wi < start_i:
                    continue
                if w == start:
                    cyc = tuple(path)
                    if cyc not in seen:
                        seen.add(cyc)
                        yield list(path)
                    continue
                if w in path:
                    continue
                path.append(w)
                yield from dfs(w)
                path.pop()

        yield from dfs(start)
