"""Tests for the Farol adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clca.adapters.farol import FarolAdapter
from clca.intake import ChangeManifest


def _manifest() -> ChangeManifest:
    return ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("src/routes.py",),
    )


def test_missing_export_returns_gap():
    adapter = FarolAdapter(export_path=Path("/nonexistent/export.json"))
    result = adapter.collect(Path("/tmp/repo"), _manifest())
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == "unsupported_asset"
    assert result.assets == []


def test_valid_export_normalizes_risk_and_findings():
    export = {
        "risk_score": 0.73,
        "risk_level": "high",
        "affected_entry_points": [
            {
                "id": "ep1",
                "type": "api_route",
                "name": "POST /orders",
                "path": "src/routes.py",
                "risk_contribution": 0.4,
                "coverage_percentage": 65.0,
            },
        ],
        "contract_breaks": [
            {
                "id": "cb1",
                "entry_point": "ep1",
                "description": "Response schema changed for POST /orders",
                "severity": "high",
                "remediation": "Update downstream consumers.",
            },
        ],
        "security_findings": [
            {
                "id": "sf1",
                "entry_point": "ep1",
                "description": "Missing authorization check on POST /orders",
                "severity": "critical",
                "remediation": "Add authz middleware.",
            },
        ],
        "coverage_info": {"percentage": 65.0},
    }
    with tempfile.TemporaryDirectory() as td:
        export_path = Path(td) / "farol_export.json"
        export_path.write_text(json.dumps(export), encoding="utf-8")
        adapter = FarolAdapter(export_path=export_path)
        result = adapter.collect(Path("/tmp/repo"), _manifest())

    assert len(result.assets) == 1
    assert result.assets[0].kind.value == "api.endpoint"
    assert result.assets[0].criticality == "high"
    assert len(result.relationships) == 1
    assert result.relationships[0].relation_type == "calls"

    # Contract break (high) -> blocking gap
    assert len(result.gaps) >= 2  # contract break + security + coverage
    assert any(g.blocking is True for g in result.gaps)
    assert any("schema changed" in g.why_it_matters.lower() for g in result.gaps)
    assert any("authorization" in g.why_it_matters.lower() or "authz" in g.why_it_matters.lower() for g in result.gaps)

    # Coverage below 80% -> gap
    assert any("coverage" in g.why_it_matters.lower() for g in result.gaps)

    assert len(result.evidence) == 1
    assert result.evidence[0].producer_name == "farol"
    assert result.facts["farol_risk_score"] == 0.73
    assert result.facts["farol_risk_level"] == "high"


def test_load_farol_adapter_factory():
    adapter = FarolAdapter()
    assert adapter.name == "farol"
