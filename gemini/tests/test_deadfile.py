from pathlib import Path
import pytest

from scanners.deadfile import DeadfileScanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"

@pytest.fixture
def deadfile_scanner():
    return DeadfileScanner()

def test_flags_backup_filename(deadfile_scanner):
    file = FIXTURES_DIR / "device.bcakup.php"
    findings = deadfile_scanner.scan(file)
    assert len(findings) > 0
    assert any(f.rule == "deadfile_backup_extension" for f in findings)

def test_flags_old_suffix(deadfile_scanner):
    # This test is tricky because the regex for backup_in_name is simple.
    # Let's assume a file like 'file-old.php'
    file = Path(FIXTURES_DIR / "file-old.php")
    file.touch() # create file for test
    findings = deadfile_scanner.scan(file)
    file.unlink() # cleanup
    assert len(findings) > 0
    assert any(f.rule == "deadfile_backup_in_name" for f in findings)


def test_flags_demo_pattern(deadfile_scanner):
    file = FIXTURES_DIR / "demo-abc123xyzab-get-key.php"
    file.touch()
    findings = deadfile_scanner.scan(file)
    file.unlink()
    assert len(findings) > 0
    assert any(f.rule == "deadfile_dangerous_demo" for f in findings)

def test_ignores_normal_file(deadfile_scanner):
    file = FIXTURES_DIR / "dashboard.php"
    findings = deadfile_scanner.scan(file)
    assert len(findings) == 0
