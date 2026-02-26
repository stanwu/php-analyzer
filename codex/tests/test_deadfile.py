from scanners.deadfile import DeadFileScanner
from tests.util import TempDirTestCase


class DeadFileTests(TempDirTestCase):
    def test_flags_backup_filename(self) -> None:
        root = self.tmp_path()
        f = root / "device.bcakup.php"
        f.write_text("<?php echo 'x';\n", encoding="utf-8")
        findings = DeadFileScanner(root).scan(f)
        self.assertTrue(findings, "expected backup-ish file to be flagged")

    def test_flags_old_suffix(self) -> None:
        root = self.tmp_path()
        f = root / "device-0ld.php"
        f.write_text("<?php echo 'x';\n", encoding="utf-8")
        findings = DeadFileScanner(root).scan(f)
        self.assertTrue(findings)

    def test_flags_demo_pattern(self) -> None:
        root = self.tmp_path()
        f = root / "demo-abc123xyz-get-key.php"
        f.write_text("<?php echo 'x';\n", encoding="utf-8")
        findings = DeadFileScanner(root).scan(f)
        self.assertTrue(findings)

    def test_ignores_normal_file(self) -> None:
        root = self.tmp_path()
        f = root / "dashboard.php"
        f.write_text("<?php echo 'x';\n", encoding="utf-8")
        findings = DeadFileScanner(root).scan(f)
        self.assertEqual(findings, [])
