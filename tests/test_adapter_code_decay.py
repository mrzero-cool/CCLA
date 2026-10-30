"""Tests for the CodeDecay adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clca.adapters.code_decay import CodeDecayAdapter
from clca.intake import ChangeManifest


def _manifest() -> ChangeManifest:
    return ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("src/foo.py",),
    )


def test_missing_export_returns_gap():
    adapter = CodeDecayAdapter(export_path=Path("/nonexistent/export.json"))
    result = adapter.collect(Path("/tmp/repo"), _manifest())
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == "unsupported_asset"
    assert result.assets == []


def test_valid_export_normalizes_risk_and_regressions():
    export = {
        "regression_risk_score": 0.68,
        "risk_level": "high",
        "planted_issues_detected": 5,
        "false_positive_rate": 0.022,
        "affected_areas": [
            {
                "id": "area1",
                "type": "function",
                "name": "calculate_price",
                "path": "src/foo.py",
                "risk_contribution": 0.5,
                "change_type": "logic",
            },
        ],
        "weak_test_areas": [
            {
                "id": "wta1",
                "area": "src/foo.py",
                "description": "No test for edge case in calculate_price",
            },
        ],
        "maintainability_issues": [
            {
                "id": "mi1",
                "area": "src/foo.py",
                "description": "High cyclomatic complexity",
                "severity": "medium",
            },
        ],
        "regressions": [
            {
                "id": "reg1",
                "area": "src/foo.py",
                "description": "Price calculation may return negative values",
                "severity": "high",
                "remediation": "Add regression test for negative price guard.",
            },
        ],
    }
    with tempfile.TemporaryDirectory() as td:
        export_path = Path(td) / "code_decay_export.json"
        export_path.write_text(json.dumps(export), encoding="utf-8")
        adapter = CodeDecayAdapter(export_path=export_path)
        result = adapter.collect(Path("/tmp/repo"), _manifest())

    assert len(result.assets) == 1
    assert result.assets[0].kind.value == "code.function"
    assert result.assets[0].criticality == "high"

    # Regression (high) -> blocking gap, required
    assert len(result.gaps) >= 3  # weak test + maintainability + regression
    assert any(g.required is True for g in result.gaps)
    assert any("negative values" in g.why_it_matters.lower() for g in result.gaps)

    assert len(result.evidence) == 1
    assert result.evidence[0].producer_name == "code_decay"
    assert result.facts["code_decay_regression_risk_score"] == 0.68
    assert result.facts["code_decay_risk_level"] == "high"
    assert result.facts["code_decay_planted_issues_detected"] == 5
    assert result.facts["code_decay_false_positive_rate"] == 0.022


def test_load_code_decay_adapter_factory():
    adapter = CodeDecayAdapter()
    assert adapter.name == "code_decay"
