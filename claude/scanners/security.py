import re
from pathlib import Path

from .base import BaseScanner, Finding

# SQL injection: query()/execute() with un-sanitized superglobal in same expression
# Looks for query/execute calls containing $_GET, $_POST, or $_REQUEST
_RE_SQL_INJECTION = re.compile(
    r"""(?:->|\b)(?:query|execute)\s*\(.*\$_(GET|POST|REQUEST)\s*\[""",
    re.IGNORECASE,
)

# Multiline approach: flag lines where a query call concatenates a superglobal
_RE_SQL_CONCAT = re.compile(
    r"""(?:->|\b)(?:query|execute)\s*\([^)]*\.\s*\$_(GET|POST|REQUEST)""",
    re.IGNORECASE,
)

# eval( usage
_RE_EVAL = re.compile(r"""\beval\s*\(""", re.IGNORECASE)

# XSS: echo with un-sanitized superglobal (no htmlspecialchars/htmlentities wrapping)
_RE_XSS = re.compile(
    r"""\becho\b.*\$_(GET|POST|REQUEST|COOKIE)\s*\[""",
    re.IGNORECASE,
)

# Dynamic include/require with a variable path
_RE_DYNAMIC_INCLUDE = re.compile(
    r"""\b(?:include|require)(?:_once)?\s*[\(\s]['"]*\s*\$\w""",
    re.IGNORECASE,
)

# Also catch include/require with concatenated variable
_RE_DYNAMIC_INCLUDE_CONCAT = re.compile(
    r"""\b(?:include|require)(?:_once)?\s*\(?\s*(?:['"]\w+['"]\s*\.\s*)?\$\w""",
    re.IGNORECASE,
)

# Shell execution functions
_RE_SHELL_EXEC = re.compile(
    r"""\b(?:shell_exec|exec|system|passthru)\s*\(""",
    re.IGNORECASE,
)

# Open redirect: header('Location:' . $_
_RE_OPEN_REDIRECT = re.compile(
    r"""header\s*\(\s*['"]Location:\s*['"]?\s*\.\s*\$_""",
    re.IGNORECASE,
)


def _is_sanitized(line: str) -> bool:
    """Heuristic: check if the line uses common sanitization functions."""
    sanitizers = (
        "htmlspecialchars",
        "htmlentities",
        "strip_tags",
        "filter_input",
        "filter_var",
        "intval",
        "floatval",
        "(int)",
        "(float)",
        "mysqli_real_escape_string",
        "addslashes",
        "prepare(",
    )
    line_lower = line.lower()
    return any(s in line_lower for s in sanitizers)


class SecurityScanner(BaseScanner):
    def scan(self, file: Path) -> list[Finding]:
        content = self.safe_read(file)
        if content is None:
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()

            # sql_injection
            if _RE_SQL_INJECTION.search(line) or _RE_SQL_CONCAT.search(line):
                if not _is_sanitized(line):
                    findings.append(
                        Finding(
                            file=file,
                            line=lineno,
                            rule="sql_injection",
                            severity="CRITICAL",
                            match=stripped,
                        )
                    )

            # eval_usage
            if _RE_EVAL.search(line):
                findings.append(
                    Finding(
                        file=file,
                        line=lineno,
                        rule="eval_usage",
                        severity="HIGH",
                        match=stripped,
                    )
                )

            # xss_direct_echo
            if _RE_XSS.search(line) and not _is_sanitized(line):
                findings.append(
                    Finding(
                        file=file,
                        line=lineno,
                        rule="xss_direct_echo",
                        severity="HIGH",
                        match=stripped,
                    )
                )

            # dynamic_include
            if _RE_DYNAMIC_INCLUDE.search(line) or _RE_DYNAMIC_INCLUDE_CONCAT.search(line):
                findings.append(
                    Finding(
                        file=file,
                        line=lineno,
                        rule="dynamic_include",
                        severity="HIGH",
                        match=stripped,
                    )
                )

            # shell_exec
            if _RE_SHELL_EXEC.search(line):
                findings.append(
                    Finding(
                        file=file,
                        line=lineno,
                        rule="shell_exec",
                        severity="CRITICAL",
                        match=stripped,
                    )
                )

            # open_redirect
            if _RE_OPEN_REDIRECT.search(line):
                findings.append(
                    Finding(
                        file=file,
                        line=lineno,
                        rule="open_redirect",
                        severity="MEDIUM",
                        match=stripped,
                    )
                )

        return findings
