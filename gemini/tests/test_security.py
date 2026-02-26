from pathlib import Path
import pytest

from scanners.security import SecurityScanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"

@pytest.fixture
def security_scanner():
    return SecurityScanner()

def test_detects_sql_injection(security_scanner):
    file = FIXTURES_DIR / "sql_injection.php"
    findings = security_scanner.scan(file)
    assert len(findings) >= 1
    assert any(f.rule == "sql_injection" and f.severity == "CRITICAL" for f in findings)

def test_no_false_positive_prepared_statement(security_scanner):
    file = FIXTURES_DIR / "clean.php"
    findings = security_scanner.scan(file)
    assert not any(f.rule == "sql_injection" for f in findings)

def test_detects_eval(security_scanner):
    file = FIXTURES_DIR / "eval_usage.php"
    findings = security_scanner.scan(file)
    assert any(f.rule == "eval_usage" and f.severity == "HIGH" for f in findings)

def test_detects_xss(security_scanner):
    file = FIXTURES_DIR / "xss.php"
    findings = security_scanner.scan(file)
    assert any(f.rule == "xss_direct_echo" and f.severity == "HIGH" for f in findings)

def test_detects_dynamic_include(security_scanner):
    file = FIXTURES_DIR / "eval_usage.php"
    findings = security_scanner.scan(file)
    assert any(f.rule == "dynamic_include" and f.severity == "HIGH" for f in findings)

def test_detects_shell_exec(security_scanner):
    file = FIXTURES_DIR / "eval_usage.php"
    findings = security_scanner.scan(file)
    assert any(f.rule == "shell_exec" and f.severity == "CRITICAL" for f in findings)

def test_detects_open_redirect(security_scanner):
    file = FIXTURES_DIR / "xss.php"
    findings = security_scanner.scan(file)
    assert any(f.rule == "open_redirect" and f.severity == "MEDIUM" for f in findings)
