"""Tests for the credential scanner."""
import pytest
from pathlib import Path

from scanners.credential import CredentialScanner

FIXTURES = Path(__file__).parent / "fixtures"


def test_detects_define_secret():
    """credential_leak.php must yield at least one CRITICAL define_secret finding."""
    scanner = CredentialScanner()
    findings = scanner.scan(FIXTURES / "credential_leak.php")
    define_secret_findings = [f for f in findings if f.rule == "define_secret"]
    assert len(define_secret_findings) >= 1, (
        f"Expected at least 1 define_secret finding, got {len(define_secret_findings)}"
    )
    assert all(f.severity == "CRITICAL" for f in define_secret_findings)


def test_detects_db_constructor():
    """credential_leak.php must yield a CRITICAL hardcoded_db_password finding."""
    scanner = CredentialScanner()
    findings = scanner.scan(FIXTURES / "credential_leak.php")
    db_findings = [f for f in findings if f.rule == "hardcoded_db_password"]
    assert len(db_findings) >= 1, (
        f"Expected at least 1 hardcoded_db_password finding, got {len(db_findings)}"
    )
    assert all(f.severity == "CRITICAL" for f in db_findings)


def test_detects_hardcoded_assignment():
    """credential_leak.php should also flag hardcoded variable assignments."""
    scanner = CredentialScanner()
    findings = scanner.scan(FIXTURES / "credential_leak.php")
    assign_findings = [f for f in findings if f.rule == "hardcoded_assignment"]
    assert len(assign_findings) >= 1, (
        "Expected at least 1 hardcoded_assignment finding"
    )


def test_no_false_positive_on_clean():
    """clean.php must yield 0 credential findings."""
    scanner = CredentialScanner()
    findings = scanner.scan(FIXTURES / "clean.php")
    assert len(findings) == 0, (
        f"Expected 0 findings on clean.php, got {len(findings)}: "
        + "; ".join(str(f) for f in findings)
    )


def test_finding_has_correct_fields():
    """Findings should have file, line, rule, severity, match populated."""
    scanner = CredentialScanner()
    findings = scanner.scan(FIXTURES / "credential_leak.php")
    assert findings, "Expected at least one finding"
    f = findings[0]
    assert isinstance(f.file, Path)
    assert isinstance(f.line, int) and f.line > 0
    assert f.rule
    assert f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    assert f.match
