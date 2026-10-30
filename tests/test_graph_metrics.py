"""Graph analytics: metrics, Cytoscape element view, DOT export."""
from clca.graph import build_graph_view, impact_from_plan, to_dot
from clca.graph.metrics import compute_metrics, _layer
from clca.models import Asset, Relationship


def _sample_world():
    assets = [
        Asset(asset_id="dbt:orders", kind="data.model", name="orders_model", path="data/dbt/models/orders.sql"),
        Asset(asset_id="col:order_id", kind="data.column", name="order_id", criticality="critical"),
        Asset(asset_id="py:pricing", kind="code.function", name="price_order", path="backend/pricing.py"),
        Asset(asset_id="agent:repl", kind="ai.agent", name="replenishment", criticality="high"),
        Asset(asset_id="tool:po", kind="ai.tool", name="write_po", criticality="critical"),
    ]
    rels = [
        Relationship(relationship_id="r1", source_asset_id="dbt:orders", target_asset_id="col:order_id",
                     relation_type="owns", impact_direction="forward", resolution="resolved"),
        Relationship(relationship_id="r2", source_asset_id="py:pricing", target_asset_id="dbt:orders",
                     relation_type="reads_from", impact_direction="forward", resolution="resolved"),
        Relationship(relationship_id="r3", source_asset_id="agent:repl", target_asset_id="tool:po",
                     relation_type="grants_tool", impact_direction="forward", resolution="resolved"),
        Relationship(relationship_id="r4", source_asset_id="py:pricing", target_asset_id="tool:po",
                     relation_type="calls", impact_direction="forward", resolution="unresolved"),
    ]
    return assets, rels


def _impact():
    from clca.graph.traverse import ImpactResult
    return ImpactResult(
        changed_asset_ids=["py:pricing"],
        changed_kinds={"code.function"},
        impacted_asset_ids=["dbt:orders", "col:order_id", "tool:po"],
        impact_paths=[["py:pricing", "dbt:orders", "col:order_id"], ["py:pricing", "tool:po"]],
        unknown_critical_impact=False,
        gaps=[],
    )


def test_graph_view_has_states_and_layers():
    assets, rels = _sample_world()
    view = build_graph_view(assets, rels, _impact())
    states = {n["data"]["id"]: n["data"]["state"] for n in view["nodes"]}
    assert states["py:pricing"] == "changed"
    assert states["dbt:orders"] == "impacted"
    assert states["agent:repl"] == "context"        # one ring of context
    layers = {n["data"]["id"]: n["data"]["layer"] for n in view["nodes"]}
    assert layers["py:pricing"] == "code"
    assert layers["agent:repl"] == "ai"


def test_graph_view_flags_path_and_resolution_edges():
    assets, rels = _sample_world()
    view = build_graph_view(assets, rels, _impact())
    by_id = {e["data"]["id"]: e["data"] for e in view["edges"]}
    assert by_id["r2"]["path"] is True              # on a recorded impact path
    assert by_id["r4"]["resolution"] == "unresolved"
    assert by_id["r1"]["propagates"] is True        # owns is traversable


def test_metrics_detect_cycles_hubs_and_dagness():
    assets, rels = _sample_world()
    # add a cycle: tool -> pricing (not present above)
    rels.append(Relationship(relationship_id="r5", source_asset_id="tool:po",
                             target_asset_id="py:pricing", relation_type="owns",
                             impact_direction="forward", resolution="inferred"))
    metrics = compute_metrics({a.asset_id: a for a in assets}, rels, _impact())
    assert metrics["is_dag"] is False
    assert metrics["cycle_count"] >= 1
    assert metrics["cycle_present"] is True
    assert metrics["cycle_count_exact"] is False
    assert metrics["cycle_count_label"] == ">=1"
    assert metrics["cycles"], "expected one representative cycle"
    assert metrics["hubs"], "expected centrality hubs"
    assert metrics["unresolved_edges"] == 1
    assert metrics["cone_layers"]["code"] == 1
    assert metrics["impact_depth"] == 2


def test_metrics_survive_missing_networkx(monkeypatch):
    import clca.graph.metrics as m
    monkeypatch.setattr(m, "_import_networkx", lambda: None)
    assets, rels = _sample_world()
    metrics = compute_metrics({a.asset_id: a for a in assets}, rels, _impact())
    assert metrics["networkx"] is False
    assert metrics["nodes"] == 5


def test_dot_export_contains_changed_node():
    assets, rels = _sample_world()
    dot = to_dot(assets, rels, _impact())
    assert dot.startswith("digraph clca_impact")
    assert '"py:pricing"' in dot
    assert "fillcolor=" in dot
    assert '"agent:repl"' not in dot   # context nodes excluded from DOT cone


def test_impact_from_plan_roundtrip():
    plan = {"impact": {
        "changed_asset_ids": ["a"],
        "changed_asset_kinds": ["code.function"],
        "impacted_asset_ids": ["b"],
        "impact_paths": [["a", "b"]],
        "unknown_critical_impact": True,
    }}
    impact = impact_from_plan(plan)
    assert impact.changed_asset_ids == ["a"]
    assert impact.changed_kinds == {"code.function"}
    assert impact.unknown_critical_impact is True
    assert impact_from_plan(None).changed_asset_ids == []


def test_layer_mapping():
    assert _layer("ai.tool") == "ai"
    assert _layer("data.model") == "data"
    assert _layer("weird.thing") == "other"


def test_metrics_do_not_enumerate_all_simple_cycles(monkeypatch):
    import networkx as nx
    import clca.graph.metrics as metrics_module
    assets, rels = _sample_world()
    rels.append(Relationship(relationship_id="r5", source_asset_id="tool:po", target_asset_id="py:pricing",
                             relation_type="owns", impact_direction="forward", resolution="inferred"))

    def forbidden(_graph):
        raise AssertionError("simple cycle enumeration is unbounded and must not be called")

    monkeypatch.setattr(nx, "simple_cycles", forbidden)
    result = metrics_module.compute_metrics({a.asset_id: a for a in assets}, rels, _impact())
    assert result["cycle_present"] is True
    assert result["cycle_count_is_lower_bound"] is True


def test_large_graph_uses_deterministic_sampled_centrality():
    from clca.graph.traverse import ImpactResult
    assets = [Asset(asset_id=f"node:{i}", kind="code.function", name=f"fn_{i}") for i in range(501)]
    impact = ImpactResult(changed_asset_ids=["node:0"], changed_kinds={"code.function"},
                          impacted_asset_ids=[], impact_paths=[], unknown_critical_impact=False, gaps=[])
    result = compute_metrics({a.asset_id: a for a in assets}, [], impact)
    assert result["centrality_method"] == "sampled_deterministic"
    assert result["centrality_exact"] is False
