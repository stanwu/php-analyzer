from __future__ import annotations

import re
from pathlib import Path

from .base import BaseScanner, Finding


class DeadFileScanner(BaseScanner):
    name = "deadfile"

    _DEMO_RX = re.compile(r"demo-[a-z0-9]{8,}-", re.IGNORECASE)

    def __init__(self, root: Path):
        self.root = root.resolve()

    def _wordpress_context_present(self) -> bool:
        return any((self.root / p).exists() for p in ["wp-includes", "wp-admin", "wp-settings.php"])

    def scan(self, file: Path) -> list[Finding]:
        name = file.name
        low = name.lower()

        reasons: list[str] = []
        if low.startswith(("x---", "_", "-")):
            reasons.append("suspicious_prefix")
        if any(k in low for k in ["backup", ".bcakup", ".bak", " bak", "old", "tmp", "copy", "test", "debug"]):
            reasons.append("backup_or_temp")
        if any(k in low for k in ["-old", "-last-", "123", "0ld"]):
            reasons.append("suspicious_suffix")
        if self._DEMO_RX.search(low):
            reasons.append("demo_pattern")
        if low == "wp-config.php" and not self._wordpress_context_present():
            reasons.append("wp_config_outside_wordpress")

        if not reasons:
            return []

        return [
            Finding(
                file=file,
                line=1,
                rule="dead_or_backup_file",
                severity="LOW",
                match=";".join(reasons),
            )
        ]
