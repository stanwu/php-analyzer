from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal

# Vendor directories to exclude from analysis
ROOT_VENDOR_DIRS = {
    "google_config",
    "vendor",
    "fb_config",
    "mailer/vendor",
    "test/PHPExcel",
    "classes/mailer",
}

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

@dataclass(frozen=True)
class Finding:
    file: Path
    line: int
    rule: str
    severity: Severity
    match: str

def is_custom_file(path: Path, root: Path) -> bool:
    """Return True only if the file is NOT inside a vendor directory."""
    try:
        relative_path = path.relative_to(root)
        # Check if any part of the path is a vendor directory
        return not any(part in ROOT_VENDOR_DIRS for part in relative_path.parts)
    except ValueError:
        # If the path is not within the root, it's not a custom file
        return False

def iter_custom_php(root: Path) -> Iterable[Path]:
    """Yield all custom PHP file Paths under root."""
    for file_path in root.rglob("*.php"):
        if file_path.is_file() and is_custom_file(file_path, root):
            yield file_path
