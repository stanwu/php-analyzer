from pathlib import Path

from scanners.credential import CredentialScanner
from tests.util import TempDirTestCase


FIXTURES = Path(__file__).parent / "fixtures"


class CredentialTests(TempDirTestCase):
    def test_detects_define_secret(self) -> None:
        f = FIXTURES / "credential_leak.php"
        findings = CredentialScanner().scan(f)
        self.assertTrue(any(x.rule == "define_secret" and x.severity == "CRITICAL" for x in findings))

    def test_detects_db_constructor(self) -> None:
        f = FIXTURES / "credential_leak.php"
        findings = CredentialScanner().scan(f)
        self.assertTrue(any(x.rule == "hardcoded_db_password" for x in findings))

    def test_no_false_positive_on_clean(self) -> None:
        f = FIXTURES / "clean.php"
        findings = CredentialScanner().scan(f)
        self.assertEqual(findings, [])
