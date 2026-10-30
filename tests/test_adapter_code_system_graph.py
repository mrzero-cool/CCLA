"""Tests for the Code System Graph adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clca.adapters.code_system_graph import CodeSystemGraphAdapter
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
    adapter = CodeSystemGraphAdapter(export_path=Path("/nonexistent/export.json"))
    result = adapter.collect(Path("/tmp/repo"), _manifest())
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == "unsupported_asset"
    assert result.assets == []


def test_valid_export_normalizes_assets_edges_and_gaps():
    export = {
        "nodes": [
            {
                "id": "api1",
                "kind": "api",
                "label": "GET /users",
                "repository": "demo/repo",
                "confidence": 0.9,
                "freshness": "current",
                "incomplete_areas": ["missing authz rule"],
            },
            {
                "id": "db1",
                "kind": "database",
                "label": "users_db",
                "path": "infra/schema.sql",
                "confidence": 0.3,
                "freshness": "stale",
            },
        ],
        "edges": [
            {"source": "api1", "target": "db1", "kind": "reads_from", "confidence": 0.8},
        ],
    }
    with tempfile.TemporaryDirectory() as td:
        export_path = Path(td) / "csg_export.json"
        export_path.write_text(json.dumps(export), encoding="utf-8")
        adapter = CodeSystemGraphAdapter(export_path=export_path)
        result = adapter.collect(Path("/tmp/repo"), _manifest())

    assert len(result.assets) == 2
    assert any(a.kind.value == "api.endpoint" for a in result.assets)
    assert any(a.kind.value == "data.table" for a in result.assets)
    assert len(result.relationships) == 1
    assert result.relationships[0].relation_type == "reads_from"
    assert result.relationships[0].resolution == "resolved"

    # Incomplete areas become coverage gaps
    assert len(result.gaps) >= 1
    assert any("authz" in g.why_it_matters for g in result.gaps)

    assert len(result.evidence) == 1
    assert result.evidence[0].producer_name == "code_system_graph"
    assert result.facts["code_system_graph_gap_count"] >= 1


def test_load_code_system_graph_adapter_factory():
    adapter = CodeSystemGraphAdapter()
    assert adapter.name == "code_system_graph"
