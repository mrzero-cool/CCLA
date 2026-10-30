"""Tests for the AxiomCode Graph adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clca.adapters.axiomcode import AxiomCodeAdapter, load_axiomcode_adapter
from clca.adapters.base import relationship_id
from clca.intake import ChangeManifest


def _manifest() -> ChangeManifest:
    return ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("src/foo.py", "src/bar.py"),
    )


def test_missing_export_returns_gap():
    adapter = AxiomCodeAdapter(export_path=Path("/nonexistent/export.json"))
    result = adapter.collect(Path("/tmp/repo"), _manifest())
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == "unsupported_asset"
    assert result.assets == []
    assert result.relationships == []


def test_valid_export_normalizes_assets_and_edges():
    export = {
        "nodes": [
            {"id": "n1", "kind": "function", "label": "calculate_price", "path": "src/foo.py", "line": 10},
            {"id": "n2", "kind": "class", "label": "PricingService", "path": "src/bar.py", "line": 5},
            {"id": "n3", "kind": "test", "label": "test_calculate_price", "path": "tests/test_foo.py"},
        ],
        "edges": [
            {"source": "n1", "target": "n2", "kind": "calls"},
            {"source": "n3", "target": "n1", "kind": "tests"},
        ],
    }
    with tempfile.TemporaryDirectory() as td:
        export_path = Path(td) / "axiom_export.json"
        export_path.write_text(json.dumps(export), encoding="utf-8")
        adapter = AxiomCodeAdapter(export_path=export_path)
        result = adapter.collect(Path("/tmp/repo"), _manifest())

    assert len(result.assets) == 3
    assert any(a.name == "calculate_price" for a in result.assets)
    assert any(a.name == "PricingService" for a in result.assets)
    assert any(a.name == "test_calculate_price" for a in result.assets)
    assert len(result.relationships) == 2

    # Check relationship types are normalized
    rel_types = {r.relation_type for r in result.relationships}
    assert "calls" in rel_types
    assert "validated_by" in rel_types

    # Check evidence exists
    assert len(result.evidence) == 1
    assert result.evidence[0].producer_name == "axiomcodegraph"

    # Check facts
    assert result.facts["axiomcodegraph_node_count"] == 3
    assert result.facts["axiomcodegraph_edge_count"] == 2


def test_relationship_id_deterministic():
    r1 = relationship_id("axiom:n1", "axiom:n2", "calls")
    r2 = relationship_id("axiom:n1", "axiom:n2", "calls")
    assert r1 == r2
    assert r1.startswith("rel:")


def test_load_axiomcode_adapter_factory():
    adapter = load_axiomcode_adapter()
    assert adapter.name == "axiomcodegraph"
