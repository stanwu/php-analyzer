"""Tests for the report writers."""
import json
import tempfile
from pathlib import Path

from scanners.base import Finding
from reports.report import write_markdown, write_json


def _make_results(
    cred_findings=None,
    sec_findings=None,
    dead_findings=None,
    dep_results=None,
) -> dict:
    return {
        "root": Path("/fake/project"),
        "stats": {"custom_files": 10, "vendor_files": 90, "total_files": 100},
        "credential_findings": cred_findings or [],
        "security_findings": sec_findings or [],
        "dead_findings": dead_findings or [],
        "dependency_results": dep_results,
    }


def _make_finding(rule="test_rule", severity="CRITICAL") -> Finding:
    return Finding(
        file=Path("/fake/project/test.php"),
        line=42,
        rule=rule,
        severity=severity,
        match="some matching code snippet",
    )


def test_markdown_output_contains_severity():
    """Markdown output must contain 'CRITICAL' when there are critical findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "report.md"
        results = _make_results(
            cred_findings=[_make_finding("define_secret", "CRITICAL")],
            sec_findings=[_make_finding("sql_injection", "CRITICAL")],
        )
        write_markdown(results, output)

        content = output.read_text(encoding="utf-8")
        assert "CRITICAL" in content, "Expected 'CRITICAL' in markdown output"


def test_markdown_output_contains_rule_name():
    """Markdown output should reference rule names from findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "report.md"
        results = _make_results(
            sec_findings=[_make_finding("sql_injection", "CRITICAL")],
        )
        write_markdown(results, output)
        content = output.read_text(encoding="utf-8")
        assert "sql_injection" in content


def test_json_output_is_valid():
    """json.loads() must succeed on the output without raising an exception."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "report.json"
        results = _make_results(
            cred_findings=[_make_finding("define_secret", "CRITICAL")],
            sec_findings=[_make_finding("sql_injection", "HIGH")],
        )
        write_json(results, output)

        raw = output.read_text(encoding="utf-8")
        parsed = json.loads(raw)  # Must not raise

        assert "credential_findings" in parsed
        assert "security_findings" in parsed
        assert parsed["credential_findings"][0]["rule"] == "define_secret"
        assert parsed["security_findings"][0]["severity"] == "HIGH"


def test_empty_results_produce_valid_markdown():
    """No findings → markdown report is still generated without error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "report.md"
        results = _make_results()
        write_markdown(results, output)

        assert output.exists(), "Report file should be created"
        content = output.read_text(encoding="utf-8")
        assert "PHP Security Analysis Report" in content


def test_empty_results_produce_valid_json():
    """No findings → JSON report is still generated without error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "report.json"
        results = _make_results()
        write_json(results, output)

        raw = output.read_text(encoding="utf-8")
        parsed = json.loads(raw)
        assert parsed["credential_findings"] == []
        assert parsed["security_findings"] == []
        assert parsed["dead_findings"] == []


def test_json_output_contains_stats():
    """JSON output should include file statistics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "report.json"
        results = _make_results()
        write_json(results, output)

        parsed = json.loads(output.read_text(encoding="utf-8"))
        assert "stats" in parsed
        assert parsed["stats"]["custom_files"] == 10
        assert parsed["stats"]["vendor_files"] == 90


def test_markdown_with_dependency_results():
    """Markdown report should include dependency section when dep_results provided."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "report.md"
        dep_results = {
            "node_count": 50,
            "edge_count": 120,
            "hubs": [("/fake/hub.php", 15), ("/fake/lib.php", 8)],
            "orphans": ["/fake/orphan.php"],
            "cycles": [],
        }
        results = _make_results(dep_results=dep_results)
        write_markdown(results, output)

        content = output.read_text(encoding="utf-8")
        assert "Dependency Analysis" in content
        assert "50" in content  # node count
        assert "120" in content  # edge count
