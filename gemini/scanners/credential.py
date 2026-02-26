import re
import sys
from pathlib import Path
from typing import List

from config import Finding
from scanners.base import BaseScanner

# Regex patterns are case-insensitive and multiline where appropriate
CREDENTIAL_PATTERNS = {
    "hardcoded_db_password": {
        "pattern": re.compile(
            r'''(?:new\s+mysqli|new\s+MysqliDb)\s*\(\s*['"].*?['"],\s*['"].*?['"],\s*['"](.+?)['"]\)''',
            re.IGNORECASE,
        ),
        "severity": "CRITICAL",
    },
    "define_secret": {
        "pattern": re.compile(
            r'''define\s*\(\s*['"].*(?:KEY|SECRET|PASSWORD|TOKEN).*['"],\s*['"](.+?)['"]\s*\)''',
            re.IGNORECASE,
        ),
        "severity": "CRITICAL",
    },
    "hardcoded_assignment": {
        "pattern": re.compile(
            r'''\$(?:[a-zA-Z0-9_]*)(?:KEY|SECRET|TOKEN|PASSWORD)(?:[a-zA-Z0-9_]*)\s*=\s*['"](.{4,})['"]''',
            re.IGNORECASE,
        ),
        "severity": "HIGH",
    },
    "base64_encoded_key": {
        "pattern": re.compile(
            r'''['"]([a-zA-Z0-9+/=]{40,})['"]''',
            re.IGNORECASE,
        ),
        "severity": "HIGH",
    },
}


class CredentialScanner(BaseScanner):
    """Scans for hardcoded credentials."""

    def scan(self, file: Path) -> List[Finding]:
        findings = []
        try:
            content = file.read_text(encoding="utf-8")
            for rule_id, details in CREDENTIAL_PATTERNS.items():
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