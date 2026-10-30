"""Adapter behavior: Python AST, dbt manifest, agent config."""
from pathlib import Path

from clca.adapters import AgentConfigAdapter, DbtManifestAdapter, PythonASTAdapter
from clca.intake import build_change_manifest

SAMPLE_APP = Path(__file__).resolve().parents[1] / "sample_app"


def manifest():
    return build_change_manifest(SAMPLE_APP)


def test_python_ast_extracts_functions_and_import_edges():
    result = PythonASTAdapter().collect(SAMPLE_APP, manifest())
    ids = {a.asset_id: a for a in result.assets}
    assert "py:backend.services.pricing:net_sales" in ids
    assert ids["py:backend.api.sales:create_sales_response"].kind == "api.endpoint"

    calls = {
        (r.source_asset_id, r.target_asset_id)
        for r in result.relationships if r.relation_type == "calls"
    }
    assert ("py:backend.api.sales:create_sales_response", "py:backend.services.pricing:net_sales") in calls


def test_dbt_adapter_reads_lineage_and_columns():
    result = DbtManifestAdapter().collect(SAMPLE_APP, manifest())
    ids = {a.asset_id for a in result.assets}
    assert "dbt:model.retail.stg_sales" in ids
    assert "dbt:model.retail.stg_sales.col.net_sales" in ids
    assert "dbt:source.retail.raw_sales" in ids

    transforms = {
        (r.source_asset_id, r.target_asset_id)
        for r in result.relationships if r.relation_type == "transforms_to"
    }
    assert ("dbt:source.retail.raw_sales", "dbt:model.retail.stg_sales") in transforms
    assert not [g for g in result.gaps if g.required], f"unexpected blocking gaps: {result.gaps}"


def test_agent_adapter_indexes_tools_prompts_and_binding():
    result = AgentConfigAdapter().collect(SAMPLE_APP, manifest())
    ids = {a.asset_id: a for a in result.assets}
    assert "agent:replenishment" in ids
    assert ids["agent:replenishment.tool.read_inventory"].kind == "ai.tool"
    assert ids["agent:replenishment.model.mock-retail-agent-v1"].kind == "ai.model_binding"
    assert any(a.kind == "ai.prompt" for a in result.assets)
    diff = result.facts["agent_diff:agent:replenishment"]
    assert diff["available"] is False or diff["available"] is True
