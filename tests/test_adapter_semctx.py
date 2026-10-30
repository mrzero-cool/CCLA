"""Tests for the semctx adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clca.adapters.semctx import SemctxAdapter
from clca.intake import ChangeManifest


def _manifest() -> ChangeManifest:
    return ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("src/routes.ts",),
    )


def test_missing_export_returns_gap():
    adapter = SemctxAdapter(export_path=Path("/nonexistent/export.json"))
    result = adapter.collect(Path("/tmp/repo"), _manifest())
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == "unsupported_asset"
    assert result.assets == []


def test_valid_export_normalizes_verdict_and_contracts():
    export = {
        "verdict": "BLOCK",
        "confidence": 0.85,
        "contracts": [
            {
                "id": "contract1",
                "name": "OrderAPI.createOrder",
                "type": "exported_contract",
                "path": "src/contracts/order.ts",
                "exported": True,
                "declared_rules": ["rule1"],
            },
        ],
        "declared_rules": [
            {
                "id": "rule1",
                "name": "no_breaking_changes",
                "rule_type": "compatibility",
                "severity": "high",
                "applies_to": "contract1",
            },
        ],
        "tests": [
            {"id": "test1", "name": "test_createOrder", "path": "src/test/order.test.ts"},
        ],
        "findings": [
            {
                "id": "finding1",
                "contract": "contract1",
                "description": "Breaking change: removed optional field",
                "severity": "high",
                "remediation": "Add backward-compatible field alias.",
            },
        ],
    }
    with tempfile.TemporaryDirectory() as td:
        export_path = Path(td) / "semctx_export.json"
        export_path.write_text(json.dumps(export), encoding="utf-8")
        adapter = SemctxAdapter(export_path=export_path)
        result = adapter.collect(Path("/tmp/repo"), _manifest())

    assert len(result.assets) >= 2  # contract + rule
    assert any(a.kind.value == "data.model" for a in result.assets)
    assert any(a.kind.value == "code.function" for a in result.assets)
    assert len(result.relationships) >= 1  # rule validates contract
    assert any(r.relation_type == "validated_by" for r in result.relationships)

    # Finding -> blocking gap (BLOCK verdict)
    assert len(result.gaps) >= 1
    assert any(g.blocking is True for g in result.gaps)
    assert any("breaking change" in g.why_it_matters.lower() for g in result.gaps)

    assert len(result.evidence) == 1
    assert result.evidence[0].producer_name == "semctx"
    assert result.facts["semctx_verdict"] == "BLOCK"
    assert result.facts["semctx_confidence"] == 0.85


def test_load_semctx_adapter_factory():
    adapter = SemctxAdapter()
    assert adapter.name == "semctx"
