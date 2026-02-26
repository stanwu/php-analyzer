from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


@dataclass
class Finding:
    file: Path
    line: int
    rule: str
    severity: Severity
    match: str

    def __str__(self) -> str:
        return f"[{self.severity}] {self.file}:{self.line} ({self.rule}): {self.match!r}"


class BaseScanner(ABC):
    @abstractmethod
    def scan(self, file: Path) -> list[Finding]:
        """Scan a single PHP file and return a list of findings."""
        ...

    def safe_read(self, file: Path) -> str | None:
        """Read file contents, returning None on error (with stderr warning)."""
        import sys

        try:
            return file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"[!] Warning: cannot read {file}: {e}", file=sys.stderr)
            return None
