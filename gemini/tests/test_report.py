import json
from pathlib import Path
import pytest

from reports.report import write_markdown, write_json
from config import Finding

@pytest.fixture
def sample_results():
    return {
        "credential_scanner": [
            Finding(
                file=Path("/project/db.php"),
                line=10,
                rule="hardcoded_db_password",
                severity="CRITICAL",
                match="new MysqliDb('host', 'user', 'password', 'db')",
            )
        ],
        "security_scanner": [],
    }

@pytest.fixture
def empty_results():
    return {
        "credential_scanner": [],
        "security_scanner": [],
    }

def test_markdown_output_contains_severity(tmp_path, sample_results):
    output_file = tmp_path / "report.md"
    write_markdown(sample_results, output_file)
    content = output_file.read_text()
    assert "CRITICAL" in content
    assert "![CRITICAL]" in content

def test_json_output_is_valid(tmp_path, sample_results):
    output_file = tmp_path / "report.json"
    write_json(sample_results, output_file)
    with open(output_file) as f:
        data = json.load(f)
    assert "credential_scanner" in data
    assert len(data["credential_scanner"]) == 1
    assert data["credential_scanner"][0]["rule"] == "hardcoded_db_password"

def test_empty_results_produce_valid_markdown_report(tmp_path, empty_results):
    output_file = tmp_path / "report.md"
    write_markdown(empty_results, output_file)
    content = output_file.read_text()
    assert "No issues found" in content

def test_empty_results_produce_valid_json_report(tmp_path, empty_results):
    output_file = tmp_path / "report.json"
    write_json(empty_results, output_file)
    with open(output_file) as f:
        data = json.load(f)
    assert "credential_scanner" in data
    assert len(data["credential_scanner"]) == 0
