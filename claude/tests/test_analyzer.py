"""Tests for the main analyzer CLI (argument parsing and severity filtering)."""
import json
import sys
import tempfile
from pathlib import Path

import pytest

from analyzer import build_arg_parser, _filter_by_severity
from scanners.base import Finding, SEVERITY_ORDER


# ── _filter_by_severity ───────────────────────────────────────────────────────

def _make_finding(severity: str) -> Finding:
    return Finding(
        file=Path("dummy.php"),
        line=1,
        rule="test_rule",
        severity=severity,
        match="test match",
    )


def test_filter_keeps_exact_severity():
    findings = [_make_finding("HIGH")]
    result = _filter_by_severity(findings, "HIGH")
    assert len(result) == 1


def test_filter_keeps_higher_severity():
    findings = [_make_finding("CRITICAL"), _make_finding("HIGH")]
    result = _filter_by_severity(findings, "HIGH")
    assert len(result) == 2


def test_filter_drops_lower_severity():
    findings = [_make_finding("LOW"), _make_finding("INFO")]
    result = _filter_by_severity(findings, "HIGH")
    assert len(result) == 0


def test_filter_info_keeps_all():
    findings = [
        _make_finding("CRITICAL"),
        _make_finding("HIGH"),
        _make_finding("MEDIUM"),
        _make_finding("LOW"),
        _make_finding("INFO"),
    ]
    result = _filter_by_severity(findings, "INFO")
    assert len(result) == 5


def test_filter_critical_keeps_only_critical():
    findings = [
        _make_finding("CRITICAL"),
        _make_finding("HIGH"),
        _make_finding("MEDIUM"),
    ]
    result = _filter_by_severity(findings, "CRITICAL")
    assert len(result) == 1
    assert result[0].severity == "CRITICAL"


def test_filter_empty_list():
    assert _filter_by_severity([], "HIGH") == []


# ── build_arg_parser ──────────────────────────────────────────────────────────

def test_default_mode_is_all():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp"])
    assert args.mode == "all"


def test_default_format_is_md():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp"])
    assert args.format == "md"


def test_default_severity_is_high():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp"])
    assert args.severity == "HIGH"


def test_default_no_color_is_false():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp"])
    assert args.no_color is False


def test_no_color_flag():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp", "--no-color"])
    assert args.no_color is True


def test_mode_security():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp", "--mode", "security"])
    assert args.mode == "security"


def test_mode_deps():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp", "--mode", "deps"])
    assert args.mode == "deps"


def test_mode_dead():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp", "--mode", "dead"])
    assert args.mode == "dead"


def test_format_json():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp", "--format", "json"])
    assert args.format == "json"


def test_format_both():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp", "--format", "both"])
    assert args.format == "both"


def test_severity_critical():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp", "--severity", "CRITICAL"])
    assert args.severity == "CRITICAL"


def test_severity_info():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp", "--severity", "INFO"])
    assert args.severity == "INFO"


def test_custom_output_path():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp", "--output", "/out/scan"])
    assert str(args.output) == "/out/scan"


def test_root_is_parsed_as_path():
    parser = build_arg_parser()
    args = parser.parse_args(["/tmp"])
    assert isinstance(args.root, Path)


def test_invalid_mode_raises():
    parser = build_arg_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["/tmp", "--mode", "invalid"])


def test_invalid_format_raises():
    parser = build_arg_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["/tmp", "--format", "xml"])


def test_invalid_severity_raises():
    parser = build_arg_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["/tmp", "--severity", "EXTREME"])


# ── SEVERITY_ORDER completeness ───────────────────────────────────────────────

def test_severity_order_contains_all_levels():
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        assert level in SEVERITY_ORDER, f"SEVERITY_ORDER missing '{level}'"


def test_severity_order_is_ascending():
    assert SEVERITY_ORDER["INFO"] < SEVERITY_ORDER["LOW"]
    assert SEVERITY_ORDER["LOW"] < SEVERITY_ORDER["MEDIUM"]
    assert SEVERITY_ORDER["MEDIUM"] < SEVERITY_ORDER["HIGH"]
    assert SEVERITY_ORDER["HIGH"] < SEVERITY_ORDER["CRITICAL"]
