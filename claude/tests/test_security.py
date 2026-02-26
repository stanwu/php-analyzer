"""Tests for the security scanner."""
import pytest
from pathlib import Path

from scanners.security import SecurityScanner

FIXTURES = Path(__file__).parent / "fixtures"


def test_detects_sql_injection():
    """sql_injection.php must yield at least one CRITICAL sql_injection finding."""
    scanner = SecurityScanner()
    findings = scanner.scan(FIXTURES / "sql_injection.php")
    sql_findings = [f for f in findings if f.rule == "sql_injection"]
    assert len(sql_findings) >= 1, (
        f"Expected at least 1 sql_injection finding, got {len(sql_findings)}"
    )
    assert all(f.severity == "CRITICAL" for f in sql_findings)


def test_no_false_positive_prepared_statement():
    """clean.php must yield 0 sql_injection findings."""
    scanner = SecurityScanner()
    findings = scanner.scan(FIXTURES / "clean.php")
    sql_findings = [f for f in findings if f.rule == "sql_injection"]
    assert len(sql_findings) == 0, (
        f"Expected 0 sql_injection findings on clean.php, got {len(sql_findings)}"
    )


def test_detects_eval():
    """eval_usage.php must yield at least one HIGH eval_usage finding."""
    scanner = SecurityScanner()
    findings = scanner.scan(FIXTURES / "eval_usage.php")
    eval_findings = [f for f in findings if f.rule == "eval_usage"]
    assert len(eval_findings) >= 1, (
        f"Expected at least 1 eval_usage finding, got {len(eval_findings)}"
    )
    assert all(f.severity == "HIGH" for f in eval_findings)


def test_detects_xss():
    """xss.php must yield at least one HIGH xss_direct_echo finding."""
    scanner = SecurityScanner()
    findings = scanner.scan(FIXTURES / "xss.php")
    xss_findings = [f for f in findings if f.rule == "xss_direct_echo"]
    assert len(xss_findings) >= 1, (
        f"Expected at least 1 xss_direct_echo finding, got {len(xss_findings)}"
    )
    assert all(f.severity == "HIGH" for f in xss_findings)


def test_detects_shell_exec():
    """eval_usage.php must flag shell_exec usage as CRITICAL."""
    scanner = SecurityScanner()
    findings = scanner.scan(FIXTURES / "eval_usage.php")
    shell_findings = [f for f in findings if f.rule == "shell_exec"]
    assert len(shell_findings) >= 1, (
        f"Expected at least 1 shell_exec finding, got {len(shell_findings)}"
    )
    assert all(f.severity == "CRITICAL" for f in shell_findings)


def test_detects_dynamic_include():
    """eval_usage.php must flag dynamic include as HIGH."""
    scanner = SecurityScanner()
    findings = scanner.scan(FIXTURES / "eval_usage.php")
    dyn_findings = [f for f in findings if f.rule == "dynamic_include"]
    assert len(dyn_findings) >= 1, (
        f"Expected at least 1 dynamic_include finding, got {len(dyn_findings)}"
    )
    assert all(f.severity == "HIGH" for f in dyn_findings)


def test_no_findings_on_clean():
    """clean.php should produce no security findings."""
    scanner = SecurityScanner()
    findings = scanner.scan(FIXTURES / "clean.php")
    assert len(findings) == 0, (
        f"Expected 0 security findings on clean.php, got {len(findings)}: "
        + "; ".join(str(f) for f in findings)
    )
