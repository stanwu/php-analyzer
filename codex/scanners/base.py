from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass(frozen=True)
class Finding:
    file: Path
    line: int
    rule: str
    severity: Severity
    match: str


SEVERITY_ORDER: dict[Severity, int] = {
    "CRITICAL": 50,
    "HIGH": 40,
    "MEDIUM": 30,
    "LOW": 20,
    "INFO": 10,
}


class BaseScanner(ABC):
    name: str

    @abstractmethod
    def scan(self, file: Path) -> list[Finding]:
        raise NotImplementedError

    def read_text(self, file: Path) -> Optional[str]:
        try:
            return file.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            print(f"[!] Skipping unreadable file: {file} ({exc})", file=sys.stderr)
            return None


def line_starts(text: str) -> list[int]:
    starts = [0]
    for idx, ch in enumerate(text):
        if ch == "\n":
            starts.append(idx + 1)
    return starts


def pos_to_line(starts: list[int], pos: int) -> int:
    # 1-based line number
    return max(1, bisect_right(starts, pos))


def shorten(s: str, limit: int = 160) -> str:
    s = " ".join(s.split())
    if len(s) <= limit:
        return s
    return s[: limit - 1] + "…"
