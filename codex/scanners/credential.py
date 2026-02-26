from __future__ import annotations

import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity, line_starts, pos_to_line, shorten


class CredentialScanner(BaseScanner):
    name = "credential"

    _RULES: list[tuple[str, Severity, re.Pattern[str]]] = [
        (
            "hardcoded_db_password",
            "CRITICAL",
            re.compile(
                r"new\s+(?:mysqli|MysqliDb)\s*\("
                r"\s*(['\"]).+?\1\s*,\s*(['\"]).+?\2\s*,\s*(['\"]).+?\3",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "define_secret",
            "CRITICAL",
            re.compile(
                r"define\s*\(\s*(['\"])(?P<name>[^'\"]*(?:KEY|SECRET|PASSWORD|TOKEN)[^'\"]*)\1"
                r"\s*,\s*(['\"])(?P<val>[^'\"]+)\3",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "hardcoded_assignment",
            "HIGH",
            re.compile(
                r"\$(?P<var>[A-Za-z_][A-Za-z0-9_]*(?:key|secret|token|password|passwd|pwd)"
                r"[A-Za-z0-9_]*)\s*=\s*(['\"])(?P<val>.*?)\2\s*;",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "base64_encoded_key",
            "HIGH",
            re.compile(
                r"\$(?P<var>[A-Za-z_][A-Za-z0-9_]*(?:key|secret|token|password|passwd|pwd)"
                r"[A-Za-z0-9_]*)\s*=\s*(['\"])(?P<val>[A-Za-z0-9+/]{40,}={0,2})\2\s*;",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
    ]

    def scan(self, file: Path) -> list[Finding]:
        text = self.read_text(file)
        if text is None:
            return []
        starts = line_starts(text)
        findings: list[Finding] = []
        for rule_id, severity, rx in self._RULES:
            for m in rx.finditer(text):
                line = pos_to_line(starts, m.start())
                findings.append(
                    Finding(
                        file=file,
                        line=line,
                        rule=rule_id,
                        severity=severity,
                        match=shorten(m.group(0)),
                    )
                )
        return findings
