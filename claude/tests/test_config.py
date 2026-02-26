"""Tests for the config module (vendor filtering logic)."""
from pathlib import Path

from config import ROOT_VENDOR_DIRS, is_custom_file, iter_custom_php


# ── is_custom_file ────────────────────────────────────────────────────────────

def test_custom_file_outside_vendor(tmp_path):
    """A file in a plain subdirectory is custom."""
    f = tmp_path / "app" / "index.php"
    f.parent.mkdir(parents=True)
    f.touch()
    assert is_custom_file(f, tmp_path) is True


def test_file_inside_vendor_dir_excluded(tmp_path):
    """A file inside composer vendor/ must NOT be considered custom."""
    f = tmp_path / "vendor" / "lib" / "autoload.php"
    f.parent.mkdir(parents=True)
    f.touch()
    assert is_custom_file(f, tmp_path) is False


def test_file_inside_google_config_excluded(tmp_path):
    """A file inside google_config/ must NOT be considered custom."""
    f = tmp_path / "google_config" / "client.php"
    f.parent.mkdir(parents=True)
    f.touch()
    assert is_custom_file(f, tmp_path) is False


def test_file_inside_nested_vendor_excluded(tmp_path):
    """A file inside mailer/vendor/ (multi-part vendor path) is excluded."""
    f = tmp_path / "mailer" / "vendor" / "phpmailer.php"
    f.parent.mkdir(parents=True)
    f.touch()
    assert is_custom_file(f, tmp_path) is False


def test_file_outside_root_returns_false(tmp_path):
    """A file that is not under root at all returns False."""
    other = Path("/tmp/unrelated.php")
    assert is_custom_file(other, tmp_path) is False


def test_root_vendor_dirs_contains_expected_entries():
    """ROOT_VENDOR_DIRS must include the core vendor directories."""
    assert "vendor" in ROOT_VENDOR_DIRS
    assert "google_config" in ROOT_VENDOR_DIRS
    assert "fb_config" in ROOT_VENDOR_DIRS


# ── iter_custom_php ───────────────────────────────────────────────────────────

def test_iter_custom_php_finds_php_files(tmp_path):
    """iter_custom_php yields .php files outside vendor dirs."""
    (tmp_path / "app.php").write_text("<?php echo 1;")
    (tmp_path / "lib").mkdir(exist_ok=True)
    (tmp_path / "lib" / "helper.php").write_text("<?php function f(){}")

    files = list(iter_custom_php(tmp_path))
    names = {f.name for f in files}
    assert "app.php" in names


def test_iter_custom_php_skips_vendor(tmp_path):
    """iter_custom_php must not yield files inside vendor/."""
    vendor_dir = tmp_path / "vendor" / "autoload"
    vendor_dir.mkdir(parents=True)
    (vendor_dir / "loader.php").write_text("<?php // vendor")
    (tmp_path / "main.php").write_text("<?php // custom")

    files = list(iter_custom_php(tmp_path))
    names = [f.name for f in files]
    assert "loader.php" not in names
    assert "main.php" in names


def test_iter_custom_php_ignores_non_php(tmp_path):
    """iter_custom_php must only yield .php files."""
    (tmp_path / "script.js").write_text("console.log(1)")
    (tmp_path / "style.css").write_text("body{}")
    (tmp_path / "page.php").write_text("<?php echo 1;")

    files = list(iter_custom_php(tmp_path))
    assert all(f.suffix.lower() == ".php" for f in files)


def test_iter_custom_php_handles_permission_error(tmp_path, monkeypatch):
    """iter_custom_php should not raise on unreadable directories."""
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "secret.php").write_text("<?php")
    (tmp_path / "accessible.php").write_text("<?php")

    original_iterdir = Path.iterdir

    def mock_iterdir(self):
        if self == locked.resolve():
            raise PermissionError("Permission denied")
        return original_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", mock_iterdir)

    # Should not raise; accessible files still returned
    files = list(iter_custom_php(tmp_path))
    assert any(f.name == "accessible.php" for f in files)
