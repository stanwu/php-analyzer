from pathlib import Path
import pytest

from scanners.credential import CredentialScanner
from config import Finding

FIXTURES_DIR = Path(__file__).parent / "fixtures"

@pytest.fixture
def credential_scanner():
    return CredentialScanner()

def test_detects_define_secret(credential_scanner):
    file = FIXTURES_DIR / "credential_leak.php"
    findings = credential_scanner.scan(file)
    assert len(findings) >= 1
    assert any(f.rule == "define_secret" and f.severity == "CRITICAL" for f in findings)

def test_detects_db_constructor(credential_scanner):
    file = FIXTURES_DIR / "credential_leak.php"
    findings = credential_scanner.scan(file)
    assert any(f.rule == "hardcoded_db_password" and f.severity == "CRITICAL" for f in findings)

def test_detects_hardcoded_assignment(credential_scanner):
    file = FIXTURES_DIR / "credential_leak.php"
    findings = credential_scanner.scan(file)
    assert any(f.rule == "hardcoded_assignment" and f.severity == "HIGH" for f in findings)

def test_detects_base64_key(credential_scanner):
    file = FIXTURES_DIR / "credential_leak.php"
    findings = credential_scanner.scan(file)
    assert any(f.rule == "base64_encoded_key" and f.severity == "HIGH" for f in findings)

def test_no_false_positive_on_clean(credential_scanner):
    file = FIXTURES_DIR / "clean.php"
    findings = credential_scanner.scan(file)
    assert len(findings) == 0
