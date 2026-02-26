import re
import sys
from pathlib import Path
from typing import List

from config import Finding
from scanners.base import BaseScanner

SECURITY_PATTERNS = {
    "sql_injection": {
        "pattern": re.compile(
            r"(?:query|execute)\s*\(.*\$_(?:GET|POST|REQUEST)\[",
            re.IGNORECASE | re.DOTALL,
        ),
        "severity": "CRITICAL",
    },
    "eval_usage": {
        "pattern": re.compile(r"eval\s*\(", re.IGNORECASE),
        "severity": "HIGH",
    },
    "xss_direct_echo": {
        "pattern": re.compile(
            r"echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[", re.IGNORECASE
        ),
        "severity": "HIGH",
    },
    "dynamic_include": {
        "pattern": re.compile(
            r"(?:include|require)(?:_once)?\s*\(?\$", re.IGNORECASE
        ),
        "severity": "HIGH",
    },
    "shell_exec": {
        "pattern": re.compile(
            r"(?:shell_exec|exec|system|passthru)\s*\(", re.IGNORECASE
        ),
        "severity": "CRITICAL",
    },
    "open_redirect": {
        "pattern": re.compile(
            r"header\s*\(\s*['\"]Location:\s*['\"]\s*\.\s*\$_", re.IGNORECASE
        ),
        "severity": "MEDIUM",
    },
}


class SecurityScanner(BaseScanner):
    """Scans for common security vulnerabilities."""

    def scan(self, file: Path) -> List[Finding]:
        findings = []
        try:
            content = file.read_text(encoding="utf-8")
            for rule_id, details in SECURITY_PATTERNS.items():
                for match in details["pattern"].finditer(content):
                    findings.append(
                        Finding(
                            file=file,
                            line=content.count("\n", 0, match.start()) + 1,
                            rule=rule_id,
                            severity=details["severity"],
                            match=match.group(0).strip(),
                        )
                    )
        except (UnicodeDecodeError, IOError) as e:
            print(f"Warning: Could not read file {file}: {e}", file=sys.stderr)
        return findings
