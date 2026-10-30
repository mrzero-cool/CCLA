"""Tests for the Stryker mutation testing adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clca.adapters.stryker import StrykerAdapter
from clca.intake import ChangeManifest


def _manifest() -> ChangeManifest:
    return ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("src/foo.py",),
    )


def test_missing_report_returns_gap():
    adapter = StrykerAdapter(report_path=Path("/nonexistent/report.json"))
    result = adapter.collect(Path("/tmp/repo"), _manifest())
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == "missing_required_test"
    assert result.assets == []


def test_high_mutation_score_no_gap():
    report = {
        "stats": {"killed": 80, "survived": 10, "timeout": 0, "total": 90},
        "files": {
            "src/foo.py": {
                "mutants": [
                    {"id": 1, "status": "killed", "mutator": "ArithmeticOperator"},
                    {"id": 2, "status": "survived", "mutator": "EqualityOperator"},
                ],
            },
        },
    }
    with tempfile.TemporaryDirectory() as td:
        report_path = Path(td) / "stryker_report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        adapter = StrykerAdapter(report_path=report_path, mutation_threshold=0.70)
        result = adapter.collect(Path("/tmp/repo"), _manifest())

    assert result.facts["stryker_mutation_score"] == 80 / 90
    assert result.facts["stryker_below_threshold"] is False
    assert len(result.gaps) == 0  # score above threshold, no gap
    assert len(result.assets) == 1


def test_low_mutation_score_creates_gap():
    report = {
        "stats": {"killed": 30, "survived": 50, "timeout": 0, "total": 80},
        "files": {
            "src/bar.py": {
                "mutants": [
                    {"id": 1, "status": "survived", "mutator": "EqualityOperator"},
                ],
            },
        },
    }
    with tempfile.TemporaryDirectory() as td:
        report_path = Path(td) / "stryker_report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        adapter = StrykerAdapter(report_path=report_path, mutation_threshold=0.70)
        result = adapter.collect(Path("/tmp/repo"), _manifest())

    assert result.facts["stryker_mutation_score"] == 30 / 80
    assert result.facts["stryker_below_threshold"] is True
    assert len(result.gaps) >= 1
    assert "below threshold" in result.gaps[0].why_it_matters.lower()
    assert result.gaps[0].required is True  # low score is required to fix


def test_zero_mutants_score_is_zero():
    report = {"stats": {"killed": 0, "survived": 0, "timeout": 0, "total": 0}, "files": {}}
    with tempfile.TemporaryDirectory() as td:
        report_path = Path(td) / "stryker_report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        adapter = StrykerAdapter(report_path=report_path, mutation_threshold=0.70)
        result = adapter.collect(Path("/tmp/repo"), _manifest())

    assert result.facts["stryker_mutation_score"] == 0.0
    assert result.facts["stryker_below_threshold"] is True


def test_load_stryker_adapter_factory():
    adapter = StrykerAdapter()
    assert adapter.name == "stryker"
