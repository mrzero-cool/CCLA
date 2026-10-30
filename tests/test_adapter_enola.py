"""Tests for the Enola adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clca.adapters.enola import EnolaAdapter
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
    adapter = EnolaAdapter(export_path=Path("/nonexistent/export.json"))
    result = adapter.collect(Path("/tmp/repo"), _manifest())
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == "unsupported_asset"
    assert result.assets == []


def test_valid_export_normalizes_assets_and_edges():
    export = {
        "nodes": [
            {"id": "svc1", "kind": "service", "label": "order-service", "repository": "demo/order"},
            {"id": "route1", "kind": "api_route", "label": "POST /orders", "path": "src/routes.py"},
            {"id": "db1", "kind": "database", "label": "orders_db", "path": "infra/schema.sql"},
        ],
        "edges": [
            {"source": "svc1", "target": "route1", "kind": "exposes"},
            {"source": "svc1", "target": "db1", "kind": "writes_to"},
        ],
    }
    with tempfile.TemporaryDirectory() as td:
        export_path = Path(td) / "enola_export.json"
        export_path.write_text(json.dumps(export), encoding="utf-8")
        adapter = EnolaAdapter(export_path=export_path)
        result = adapter.collect(Path("/tmp/repo"), _manifest())

    assert len(result.assets) == 3
    assert any(a.name == "order-service" for a in result.assets)
    assert any(a.kind.value == "api.endpoint" for a in result.assets)
    assert any(a.kind.value == "data.table" for a in result.assets)
    assert len(result.relationships) == 2

    rel_types = {r.relation_type for r in result.relationships}
    assert "exposes" in rel_types
    assert "writes_to" in rel_types

    assert len(result.evidence) == 1
    assert result.evidence[0].producer_name == "enola"
    assert result.facts["enola_node_count"] == 3
    assert result.facts["enola_edge_count"] == 2


def test_load_enola_adapter_factory():
    adapter = EnolaAdapter()
    assert adapter.name == "enola"
