from __future__ import annotations

import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity, line_starts, pos_to_line, shorten


_TAINT_ASSIGN = re.compile(
    r"\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+?)\s*;",
    re.IGNORECASE,
)
_SUPERGLOBAL = re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\b", re.IGNORECASE)


def _is_sanitized(rhs: str) -> bool:
    rhs_l = rhs.lower()
    return any(
        pat in rhs_l
        for pat in [
            "(int)",
            "intval(",
            "filter_input(",
            "mysqli_real_escape_string(",
            "pg_escape_string(",
            "htmlspecialchars(",
            "htmlentities(",
            "urlencode(",
            "rawurlencode(",
        ]
    )


class SecurityScanner(BaseScanner):
    name = "security"

    _RULES: list[tuple[str, Severity, re.Pattern[str]]] = [
        ("eval_usage", "HIGH", re.compile(r"\beval\s*\(", re.IGNORECASE)),
        (
            "shell_exec",
            "CRITICAL",
            re.compile(r"\b(shell_exec|exec|system|passthru)\s*\(", re.IGNORECASE),
        ),
        (
            "dynamic_include",
            "HIGH",
            re.compile(
                r"\b(include|include_once|require|require_once)"
                r"\s*(?:\(\s*)?\$[A-Za-z_][A-Za-z0-9_]*",
                re.IGNORECASE,
            ),
        ),
        (
            "xss_direct_echo",
            "HIGH",
            re.compile(r"\becho\s+\$_(GET|POST|REQUEST|COOKIE)\b", re.IGNORECASE),
        ),
        (
            "open_redirect",
            "MEDIUM",
            re.compile(
                r"\bheader\s*\(\s*(['\"])Location:.*?\1\s*\.\s*\$_",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
    ]

    _QUERY_CALL = re.compile(r"->\s*(query|execute)\s*\(", re.IGNORECASE)

    def scan(self, file: Path) -> list[Finding]:
        text = self.read_text(file)
        if text is None:
            return []

        starts = line_starts(text)
        findings: list[Finding] = []

        # Very small taint tracker for variables assigned from superglobals.
        tainted: set[str] = set()
        for line in text.splitlines():
            m = _TAINT_ASSIGN.search(line)
            if not m:
                continue
            rhs = m.group("rhs")
            if not _SUPERGLOBAL.search(rhs):
                continue
            if _is_sanitized(rhs):
                continue
            tainted.add(m.group("var"))

        # SQL injection: query/execute that uses superglobals or tainted vars.
        for m in self._QUERY_CALL.finditer(text):
            start = m.start()
            end = text.find(";", start)
            if end == -1:
                end = min(len(text), start + 600)
            snippet = text[start:end]
            if _SUPERGLOBAL.search(snippet) or any(f"${v}" in snippet for v in tainted):
                line = pos_to_line(starts, start)
                findings.append(
                    Finding(
                        file=file,
                        line=line,
                        rule="sql_injection",
                        severity="CRITICAL",
                        match=shorten(snippet),
                    )
                )

        # Other pattern rules.
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
