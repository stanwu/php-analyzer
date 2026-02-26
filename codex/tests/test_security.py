from pathlib import Path

from scanners.security import SecurityScanner
from tests.util import TempDirTestCase


FIXTURES = Path(__file__).parent / "fixtures"


class SecurityTests(TempDirTestCase):
    def test_detects_sql_injection(self) -> None:
        f = FIXTURES / "sql_injection.php"
        findings = SecurityScanner().scan(f)
        self.assertTrue(
            any(x.rule == "sql_injection" and x.severity == "CRITICAL" for x in findings)
        )

    def test_no_false_positive_prepared_statement(self) -> None:
        f = FIXTURES / "clean.php"
        findings = SecurityScanner().scan(f)
        self.assertFalse(any(x.rule == "sql_injection" for x in findings))

    def test_detects_eval(self) -> None:
        f = FIXTURES / "eval_usage.php"
        findings = SecurityScanner().scan(f)
        self.assertTrue(any(x.rule == "eval_usage" and x.severity == "HIGH" for x in findings))

    def test_detects_xss(self) -> None:
        f = FIXTURES / "xss.php"
        findings = SecurityScanner().scan(f)
        self.assertTrue(any(x.rule == "xss_direct_echo" and x.severity == "HIGH" for x in findings))
