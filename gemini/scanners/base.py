from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from config import Finding


class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    @abstractmethod
    def scan(self, file: Path) -> List[Finding]:
        """
        Scan a single file for vulnerabilities or patterns.

        Args:
            file: The path to the file to scan.

        Returns:
            A list of Finding objects.
        """
        raise NotImplementedError
