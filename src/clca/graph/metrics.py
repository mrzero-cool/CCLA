"""Graph analytics over the cross-layer asset/relationship model.

The evidence model is already a property graph: assets are nodes, declared
relationships are typed directed edges, and impact propagation follows the
traversal policy in :mod:`.traverse`. This module makes that graph explicit:

* **metrics** — hubs (betweenness), fan-in/fan-out, cycle presence, weak
  components and impact depth. Cycle reporting is bounded: cyclic graphs show
  one representative cycle and a lower bound, never an exponential full count.
* **a Cytoscape.js element view** — what the web console renders.
* **DOT export** — interop with Graphviz and friends.

networkx is used for the algorithms that would be silly to hand-roll;
everything is computed in-memory from the sealed bundle — never from a live
graph database — so the decision stays reproducible from the bundle alone.
"""
from __future__ import annotations

from typing import Any

from ..models import Asset, Relationship
from .traverse import ImpactResult, _TRAVERSAL_POLICY

# Rendering caps: the sample graphs are small; these bound worst-case payload.
MAX_NODES = 500
MAX_EDGES = 900

_LAYER_BY_PREFIX = {
    "code": "code", "api": "api", "data": "data", "ai": "ai",
    "test": "test", "deployment": "deploy", "business": "metric",
}


def _layer(kind: str) -> str:
    return _LAYER_BY_PREFIX.get(kind.split(".", 1)[0], "other")


def _import_networkx():
    try:
        import networkx as nx  # noqa: PLC0415 (optional at import time, required for metrics)
        return nx
    except ImportError:  # pragma: no cover - exercised only on bare installs
        return None


def build_graph_view(
    assets: list[Asset],
    relationships: list[Relationship],
    impact: ImpactResult,
    max_nodes: int = MAX_NODES,
    max_edges: int = MAX_EDGES,
) -> dict[str, Any]:
    """Return ``{nodes, edges, metrics}`` for the console + DOT export.

    Nodes carry ``state`` = changed | impacted | context so the UI can colour
    the blast radius. Edges carry ``path`` when they sit on a recorded impact
    path, and ``resolution`` so unresolved evidence is visibly dashed.
    """
    changed = set(impact.changed_asset_ids)
    impacted = set(impact.impacted_asset_ids)
    cone = changed | impacted

    by_id = {a.asset_id: a for a in assets}
    # Keep the whole change cone plus one ring of context around it so the
    # viewer sees *why* something is impacted, not an orphan subgraph.
    keep = set(cone)
    if cone:
        for rel in relationships:
            if rel.source_asset_id in cone or rel.target_asset_id in cone:
                keep.add(rel.source_asset_id)
                keep.add(rel.target_asset_id)

    ordered = [a for a in assets if a.asset_id in keep] or list(assets)
    truncated = len(ordered) > max_nodes
    ordered = ordered[:max_nodes]
    kept_ids = {a.asset_id for a in ordered}

    def state(aid: str) -> str:
        if aid in changed:
            return "changed"
        if aid in impacted:
            return "impacted"
        return "context"

    nodes = [
        {
            "data": {
                "id": a.asset_id,
                "label": a.name,
                "kind": a.kind.value if hasattr(a.kind, "value") else str(a.kind),
                "layer": _layer(a.kind.value if hasattr(a.kind, "value") else str(a.kind)),
                "criticality": a.criticality,
                "state": state(a.asset_id),
                "path": a.path or "",
            },
        }
        for a in ordered
    ]

    # Adjacent pairs along recorded impact paths → highlighted edges.
    path_pairs: set[tuple[str, str]] = set()
    for path in impact.impact_paths:
        for src, dst in zip(path, path[1:]):
            path_pairs.add((src, dst))
            path_pairs.add((dst, src))  # direction may be reverse-propagating

    edges: list[dict[str, Any]] = []
    edge_truncated = False
    for rel in relationships:
        if rel.source_asset_id not in kept_ids or rel.target_asset_id not in kept_ids:
            continue
        if len(edges) >= max_edges:
            edge_truncated = True
            break
        propagates = _TRAVERSAL_POLICY.get(rel.relation_type) is not None
        edges.append({
            "data": {
                "id": rel.relationship_id,
                "source": rel.source_asset_id,
                "target": rel.target_asset_id,
                "label": rel.relation_type,
                "resolution": rel.resolution,
                "impact_direction": rel.impact_direction,
                "propagates": propagates,
                "path": (rel.source_asset_id, rel.target_asset_id) in path_pairs,
                "in_cone": rel.source_asset_id in cone and rel.target_asset_id in cone,
            },
        })

    metrics = compute_metrics(by_id, relationships, impact)
    metrics["truncated"] = truncated or edge_truncated
    return {"nodes": nodes, "edges": edges, "metrics": metrics}


def compute_metrics(
    by_id: dict[str, Asset],
    relationships: list[Relationship],
    impact: ImpactResult,
) -> dict[str, Any]:
    """Graph-theoretic facts about the change's world (networkx-backed)."""
    nx = _import_networkx()
    cone = set(impact.changed_asset_ids) | set(impact.impacted_asset_ids)

    base: dict[str, Any] = {
        "nodes": len(by_id),
        "edges": len(relationships),
        "changed": len(impact.changed_asset_ids),
        "impacted": len(impact.impacted_asset_ids),
        "impact_depth": max((len(p) - 1 for p in impact.impact_paths), default=0),
        "unknown_critical_impact": impact.unknown_critical_impact,
        "unresolved_edges": sum(
            1 for r in relationships
            if r.resolution in ("unresolved", "ambiguous")
        ),
        "non_propagating_edges": sum(
            1 for r in relationships
            if _TRAVERSAL_POLICY.get(r.relation_type) is None
        ),
    }
    if nx is None:
        base["networkx"] = False
        return base
    base["networkx"] = True

    g = nx.DiGraph()
    for aid in by_id:
        g.add_node(aid, layer=_layer(by_id[aid].kind.value))
    for rel in relationships:
        g.add_edge(rel.source_asset_id, rel.target_asset_id,
                   relation=rel.relation_type, resolution=rel.resolution)

    # Exact betweenness is expensive on large graphs. Keep the result
    # deterministic while switching to a fixed-size sample beyond 500 nodes;
    # disclose the method so approximate scores are never presented as exact.
    node_count = g.number_of_nodes()
    if node_count == 0:
        centrality = {}
        centrality_method = "none"
    elif node_count <= 500:
        centrality = nx.betweenness_centrality(g)
        centrality_method = "exact"
    else:
        centrality = nx.betweenness_centrality(g, k=min(100, node_count), seed=0)
        centrality_method = "sampled_deterministic"
    base["centrality_method"] = centrality_method
    base["centrality_exact"] = centrality_method in ("exact", "none")
    hubs = sorted(
        (
            {"id": aid, "score": round(score, 4),
             "fan_out": g.out_degree(aid), "fan_in": g.in_degree(aid)}
            for aid, score in centrality.items()
            if aid in cone or score > 0
        ),
        key=lambda h: h["score"],
        reverse=True,
    )[:5]

    # Do not enumerate every simple cycle: the number of cycles can grow
    # exponentially and turn a dashboard metric into a denial-of-service on a
    # large or adversarial dependency graph. Detect DAG-ness and retain at most
    # one representative cycle. For cyclic graphs, cycle_count=1 is a lower
    # bound, not a claim that exactly one cycle exists.
    is_dag = nx.is_directed_acyclic_graph(g)
    sample_cycles: list[list[str]] = []
    if is_dag:
        cycle_count = 0
    else:
        cycle_count = 1
        try:
            cycle_edges = nx.find_cycle(g)
            cycle_nodes = [edge[0] for edge in cycle_edges]
            if cycle_edges:
                cycle_nodes.append(cycle_edges[-1][1])
            sample_cycles = [cycle_nodes[:7]]
        except nx.NetworkXNoCycle:  # defensive consistency fallback
            is_dag = True
            cycle_count = 0
    base["cycles"] = sample_cycles
    base["cycle_count"] = cycle_count
    base["cycle_count_exact"] = is_dag
    base["cycle_count_label"] = str(cycle_count) if is_dag else ">=1"
    base["cycle_count_is_lower_bound"] = not is_dag
    base["cycle_present"] = not is_dag
    base["weakly_connected_components"] = nx.number_weakly_connected_components(g) if g.number_of_nodes() else 0
    base["density"] = round(nx.density(g), 4) if g.number_of_nodes() > 1 else 0.0
    base["hubs"] = hubs
    base["is_dag"] = is_dag

    # Layer composition of the change cone (what kind of system is being touched).
    layers: dict[str, int] = {}
    for aid in cone:
        if aid in by_id:
            layer = _layer(by_id[aid].kind.value)
            layers[layer] = layers.get(layer, 0) + 1
    base["cone_layers"] = dict(sorted(layers.items()))
    return base


def to_dot(
    assets: list[Asset],
    relationships: list[Relationship],
    impact: ImpactResult,
) -> str:
    """Graphviz DOT serialization of the change cone (interop export)."""
    changed = set(impact.changed_asset_ids)
    impacted = set(impact.impacted_asset_ids)
    lines = [
        'digraph clca_impact {',
        '  rankdir=LR;',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10];',
        '  edge [fontsize=8, fontname="Helvetica"];',
    ]
    for a in assets:
        if a.asset_id not in (changed | impacted):
            continue
        fill = "#f2545b" if a.asset_id in changed else "#6d5efc"
        text = "white"
        label = a.name.replace('"', "'")
        lines.append(f'  "{a.asset_id}" [label="{label}\\n{a.kind.value}", fillcolor="{fill}", fontcolor="{text}"];')
    for rel in relationships:
        if rel.source_asset_id not in (changed | impacted) or rel.target_asset_id not in (changed | impacted):
            continue
        style = "solid" if rel.resolution == "resolved" else "dashed"
        lines.append(
            f'  "{rel.source_asset_id}" -> "{rel.target_asset_id}" '
            f'[label="{rel.relation_type}", style={style}];'
        )
    lines.append('}')
    return "\n".join(lines)
