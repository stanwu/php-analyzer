import json

from reports.report import write_json, write_markdown
from tests.util import TempDirTestCase


class ReportTests(TempDirTestCase):
    def test_markdown_output_contains_severity(self) -> None:
        root = self.tmp_path()
        out = root / "report.md"
        results = {
            "meta": {"root": "/tmp/x"},
            "findings": {
                "security": [
                    {"file": "a.php", "line": 1, "rule": "sql_injection", "severity": "CRITICAL", "match": "x"}
                ]
            },
            "dependency": {},
        }
        write_markdown(results, out)
        text = out.read_text(encoding="utf-8")
        self.assertIn("CRITICAL", text)

    def test_json_output_is_valid(self) -> None:
        root = self.tmp_path()
        out = root / "report.json"
        write_json({"meta": {}, "findings": {}, "dependency": {}}, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertIsInstance(data, dict)

    def test_empty_results_produce_valid_report(self) -> None:
        root = self.tmp_path()
        out_md = root / "empty.md"
        out_json = root / "empty.json"
        results = {"meta": {}, "findings": {}, "dependency": {}}
        write_markdown(results, out_md)
        write_json(results, out_json)
        self.assertTrue(out_md.exists())
        self.assertEqual(json.loads(out_json.read_text(encoding="utf-8"))["findings"], {})
