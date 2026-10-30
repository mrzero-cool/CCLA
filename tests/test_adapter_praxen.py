"""Tests for the Praxen adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clca.adapters.praxen import PraxenAdapter
from clca.intake import ChangeManifest


def _manifest() -> ChangeManifest:
    return ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("agents/replenishment/agent.py",),
    )


def test_missing_export_returns_gap():
    adapter = PraxenAdapter(export_path=Path("/nonexistent/export.json"))
    result = adapter.collect(Path("/tmp/repo"), _manifest())
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == "unsupported_asset"
    assert result.assets == []


def test_valid_export_normalizes_and_flags_violations():
    export = {
        "agents": [
            {"id": "agent1", "name": "replenishment-agent", "declared_remit": ["read-only"]},
        ],
        "tools": [
            {"id": "tool1", "name": "write_purchase_orders", "access": "write"},
        ],
        "policies": [
            {"id": "policy1", "name": "new_write_tool_requires_review"},
        ],
        "comparisons": [
            {
                "agent_id": "agent1",
                "tool_id": "tool1",
                "status": "violation",
                "violation": "Agent granted write tool outside declared remit",
            },
        ],
    }
    with tempfile.TemporaryDirectory() as td:
        export_path = Path(td) / "praxen_export.json"
        export_path.write_text(json.dumps(export), encoding="utf-8")
        adapter = PraxenAdapter(export_path=export_path)
        result = adapter.collect(Path("/tmp/repo"), _manifest())

    assert len(result.assets) == 3
    assert any(a.kind.value == "ai.agent" for a in result.assets)
    assert any(a.kind.value == "ai.tool" for a in result.assets)
    assert any(a.kind.value == "ai.policy" for a in result.assets)
    assert len(result.relationships) == 1
    assert result.relationships[0].relation_type == "grants_tool"

    # Violation becomes a coverage gap
    assert len(result.gaps) >= 1
    assert any("write tool outside declared remit" in g.why_it_matters for g in result.gaps)

    assert len(result.evidence) == 1
    assert result.evidence[0].producer_name == "praxen"
    assert result.facts["praxen_comparison_count"] == 1


def test_load_praxen_adapter_factory():
    adapter = PraxenAdapter()
    assert adapter.name == "praxen"
