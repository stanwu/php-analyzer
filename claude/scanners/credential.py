import re
from pathlib import Path

from .base import BaseScanner, Finding

# Match: new mysqli( or new MysqliDb( followed by string literal arguments
# Captures the entire constructor call line
_RE_DB_CONSTRUCTOR = re.compile(
    r"""new\s+(?:mysqli|MysqliDb)\s*\("""
    r"""\s*['"][^'"]+['"]\s*,\s*['"][^'"]*['"]\s*,\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

# Match: define('SOMETHING_KEY'/'SECRET'/'PASSWORD'/'TOKEN', 'value')
_RE_DEFINE_SECRET = re.compile(
    r"""define\s*\(\s*['"]([^'"]*(?:KEY|SECRET|PASSWORD|TOKEN|PASS|API)[^'"]*)['"]\s*"""
    r""",\s*['"]([^'"]{3,})['"]""",
    re.IGNORECASE,
)

# Match: $var_name_with_key_secret_token_password = 'literal'
_RE_HARDCODED_ASSIGNMENT = re.compile(
    r"""\$(\w*(?:key|secret|token|password|pass|api_key|apikey|auth)\w*)"""
    r"""\s*=\s*['"]([^'"]{4,})['"]""",
    re.IGNORECASE,
)

# Match base64 strings longer than 40 chars assigned to credential-like variables
_RE_BASE64_KEY = re.compile(
    r"""\$(\w*(?:key|secret|token|password|pass|auth)\w*)"""
    r"""\s*=\s*['"]([A-Za-z0-9+/]{40,}={0,2})['"]""",
    re.IGNORECASE,
)


class CredentialScanner(BaseScanner):
    def scan(self, file: Path) -> list[Finding]:
        content = self.safe_read(file)
        if content is None:
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, start=1):
            # hardcoded_db_password
            if _RE_DB_CONSTRUCTOR.search(line):
                m = _RE_DB_CONSTRUCTOR.search(line)
                findings.append(
                    Finding(
                        file=file,
                        line=lineno,
                        rule="hardcoded_db_password",
                        severity="CRITICAL",
                        match=line.strip(),
                    )
                )

            # define_secret
            m = _RE_DEFINE_SECRET.search(line)
            if m:
                findings.append(
                    Finding(
                        file=file,
                        line=lineno,
                        rule="define_secret",
                        severity="CRITICAL",
                        match=line.strip(),
                    )
                )

            # hardcoded_assignment — only if not already caught by define_secret
            m = _RE_HARDCODED_ASSIGNMENT.search(line)
            if m and not _RE_DEFINE_SECRET.search(line):
                value = m.group(2)
                # Skip obvious false positives: empty or whitespace-only values,
                # or values that are clearly placeholders already flagged elsewhere
                if value.strip():
                    findings.append(
                        Finding(
                            file=file,
                            line=lineno,
                            rule="hardcoded_assignment",
                            severity="HIGH",
                            match=line.strip(),
                        )
                    )

            # base64_encoded_key
            m = _RE_BASE64_KEY.search(line)
            if m:
                # Avoid duplicate with hardcoded_assignment
                already_reported = any(
                    f.line == lineno and f.rule == "hardcoded_assignment" for f in findings
                )
                if not already_reported:
                    findings.append(
                        Finding(
                            file=file,
                            line=lineno,
                            rule="base64_encoded_key",
                            severity="HIGH",
                            match=line.strip(),
                        )
                    )

        return findings
