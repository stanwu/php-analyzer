"""Tests for the dead file scanner."""
import tempfile
from pathlib import Path

from scanners.deadfile import DeadFileScanner


def _make_file(directory: Path, name: str) -> Path:
    p = directory / name
    p.write_text("<?php // fixture\n", encoding="utf-8")
    return p


def test_flags_backup_filename():
    """A file containing 'backup' in its name should be flagged."""
    with tempfile.TemporaryDirectory() as tmpdir:
        f = _make_file(Path(tmpdir), "device.backup.php")
        scanner = DeadFileScanner()
        findings = scanner.scan(f)
        assert len(findings) >= 1, "Expected 'device.backup.php' to be flagged"
        assert findings[0].rule == "dead_file"


def test_flags_bcakup_typo():
    """A file with the 'bcakup' typo should be flagged."""
    with tempfile.TemporaryDirectory() as tmpdir:
        f = _make_file(Path(tmpdir), "device.bcakup.php")
        scanner = DeadFileScanner()
        findings = scanner.scan(f)
        assert len(findings) >= 1, "Expected 'device.bcakup.php' to be flagged"


def test_flags_old_suffix():
    """A file containing '0ld' should be flagged."""
    with tempfile.TemporaryDirectory() as tmpdir:
        f = _make_file(Path(tmpdir), "device-0ld.php")
        scanner = DeadFileScanner()
        findings = scanner.scan(f)
        assert len(findings) >= 1, "Expected 'device-0ld.php' to be flagged"


def test_flags_demo_pattern():
    """A file matching the demo-[a-z0-9]{10,}- pattern should be flagged."""
    with tempfile.TemporaryDirectory() as tmpdir:
        f = _make_file(Path(tmpdir), "demo-abc123xyz99-get-key.php")
        scanner = DeadFileScanner()
        findings = scanner.scan(f)
        assert len(findings) >= 1, (
            "Expected 'demo-abc123xyz99-get-key.php' to be flagged as demo pattern"
        )


def test_ignores_normal_file():
    """A normal file like dashboard.php should NOT be flagged."""
    with tempfile.TemporaryDirectory() as tmpdir:
        f = _make_file(Path(tmpdir), "dashboard.php")
        scanner = DeadFileScanner()
        findings = scanner.scan(f)
        assert len(findings) == 0, (
            f"Expected 'dashboard.php' NOT to be flagged, got: {findings}"
        )


def test_flags_bak_extension():
    """A file with '.bak' in the name should be flagged."""
    with tempfile.TemporaryDirectory() as tmpdir:
        f = _make_file(Path(tmpdir), "config.bak.php")
        scanner = DeadFileScanner()
        findings = scanner.scan(f)
        assert len(findings) >= 1, "Expected 'config.bak.php' to be flagged"


def test_flags_tmp_in_name():
    """A file with 'tmp' in the name should be flagged."""
    with tempfile.TemporaryDirectory() as tmpdir:
        f = _make_file(Path(tmpdir), "upload_tmp.php")
        scanner = DeadFileScanner()
        findings = scanner.scan(f)
        assert len(findings) >= 1, "Expected 'upload_tmp.php' to be flagged"


def test_flags_phpinfo():
    """phpinfo.php is a known dangerous file and should be flagged."""
    with tempfile.TemporaryDirectory() as tmpdir:
        f = _make_file(Path(tmpdir), "phpinfo.php")
        scanner = DeadFileScanner()
        findings = scanner.scan(f)
        assert len(findings) >= 1, "Expected 'phpinfo.php' to be flagged"
