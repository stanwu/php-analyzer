import re
from pathlib import Path
from typing import List

from config import Finding
from scanners.base import BaseScanner

# Patterns for dead/backup files
DEADFILE_PATTERNS = {
    "backup_extension": (re.compile(r"device\.bcakup\.php", re.IGNORECASE), "INFO"),
    "backup_in_name": (
        re.compile(
            r".*(backup|bak|old|tmp|copy|test|debug|-last-|\d{3,}|-old|0ld).*\.php$", re.IGNORECASE
        ),
        "LOW",
    ),
    "special_prefix": (re.compile(r"^(?:x--|_|-).*\.php$", re.IGNORECASE), "MEDIUM"),
    "dangerous_demo": (re.compile(r"demo-[a-z0-9]{10,}.*\.php$", re.IGNORECASE), "HIGH"),
    "misplaced_wp_config": (
        re.compile(r"wp-config\.php", re.IGNORECASE),
        "CRITICAL",
    ),  # Context check is separate
}


class DeadfileScanner(BaseScanner):
    """Scans for dead, backup, or temporary files."""

    def scan(self, file: Path) -> List[Finding]:
        findings = []
        filename = file.name

        for rule_id, (pattern, severity) in DEADFILE_PATTERNS.items():
            if pattern.match(filename):
                # Special check for wp-config, it should only be flagged if not in a WP project
                # This is a simplified check. A real one would be more robust.
                if rule_id == "misplaced_wp_config" and "wp-includes" in [
                    p.name for p in file.parent.iterdir()
                ]:
                    continue

                findings.append(
                    Finding(
                        file=file,
                        line=0,
                        rule=f"deadfile_{rule_id}",
                        severity=severity,
                        match=f"Filename matches pattern: {pattern.pattern}",
                    )
                )
        return findings
