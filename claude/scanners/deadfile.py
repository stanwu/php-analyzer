import re
from pathlib import Path

from .base import BaseScanner, Finding

# Filename patterns that suggest dead/backup files
_DANGEROUS_SUBSTRINGS = (
    "backup",
    "bak",
    ".bak",
    "bcakup",  # common typo
    "-old",
    "-last-",
    "0ld",
    "_old",
    ".old",
    "tmp",
    "copy",
    "-copy",
    "_copy",
    "test",
    "debug",
    "123",
)

# Demo file pattern: demo- followed by 10+ alphanumeric chars
_RE_DEMO_PATTERN = re.compile(r"""demo-[a-z0-9]{10,}-""", re.IGNORECASE)

# Files starting with special characters suggesting disabled/old files
_RE_SPECIAL_PREFIX = re.compile(r"""^(x---|_|-)\w""")

# Known dangerous demo/sample filenames
_DANGEROUS_EXACT = {
    "wp-config.php",
    "wp-config-sample.php",
    "phpinfo.php",
    "info.php",
    "test.php",
}


def _is_dead_file(path: Path) -> tuple[bool, str]:
    """
    Check if a file looks like a dead/backup/dangerous file.
    Returns (is_dead, reason).
    """
    name = path.name.lower()

    # Exact matches for known dangerous files
    if name in _DANGEROUS_EXACT:
        return True, f"known dangerous filename: {path.name}"

    # Demo pattern in filename
    if _RE_DEMO_PATTERN.search(name):
        return True, f"demo file pattern: {path.name}"

    # Special character prefix
    if _RE_SPECIAL_PREFIX.match(name):
        return True, f"special prefix in filename: {path.name}"

    # Dangerous substrings in stem or full name
    for substr in _DANGEROUS_SUBSTRINGS:
        if substr in name:
            return True, f"suspicious substring '{substr}' in filename: {path.name}"

    return False, ""


class DeadFileScanner(BaseScanner):
    def scan(self, file: Path) -> list[Finding]:
        is_dead, reason = _is_dead_file(file)
        if is_dead:
            return [
                Finding(
                    file=file,
                    line=0,
                    rule="dead_file",
                    severity="MEDIUM",
                    match=reason,
                )
            ]
        return []
