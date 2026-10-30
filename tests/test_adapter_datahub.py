"""Tests for the DataHub/OpenLineage adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clca.adapters.datahub import DataHubAdapter
from clca.intake import ChangeManifest


def _manifest() -> ChangeManifest:
    return ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("data/dbt/manifest.json",),
    )


def test_missing_export_returns_gap():
    adapter = DataHubAdapter(export_path=Path("/nonexistent/export.json"))
    result = adapter.collect(Path("/tmp/repo"), _manifest())
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == "missing_lineage"
    assert result.assets == []


def test_valid_export_normalizes_entities_and_relationships():
    export = {
        "entities": [
            {
                "id": "tbl1",
                "type": "table",
                "name": "stg_sales",
                "platform": "bigquery",
                "qualified_name": "bigquery.demo.stg_sales",
                "freshness": "current",
            },
            {
                "id": "col1",
                "type": "column",
                "name": "customer_id",
                "path": "data/dbt/models/stg_sales.sql",
                "freshness": "stale",
            },
        ],
        "relationships": [
            {"source": "tbl1", "target": "col1", "type": "writes_to"},
        ],
    }
    with tempfile.TemporaryDirectory() as td:
        export_path = Path(td) / "datahub_export.json"
        export_path.write_text(json.dumps(export), encoding="utf-8")
        adapter = DataHubAdapter(export_path=export_path)
        result = adapter.collect(Path("/tmp/repo"), _manifest())

    assert len(result.assets) == 2
    assert any(a.kind.value == "data.table" for a in result.assets)
    assert any(a.kind.value == "data.column" for a in result.assets)
    assert len(result.relationships) == 1
    assert result.relationships[0].relation_type == "writes_to"

    # Stale freshness becomes a coverage gap
    assert len(result.gaps) >= 1
    assert any("stale" in g.why_it_matters.lower() for g in result.gaps)

    assert len(result.evidence) == 1
    assert result.evidence[0].producer_name == "datahub"
    assert result.facts["datahub_entity_count"] == 2
    assert result.facts["datahub_relationship_count"] == 1


def test_load_datahub_adapter_factory():
    adapter = DataHubAdapter()
    assert adapter.name == "datahub"
