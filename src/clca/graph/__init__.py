from .traverse import ImpactResult, resolve_impact, _TRAVERSAL_POLICY

__all__ = ["ImpactResult", "resolve_impact", "impact_from_plan", "build_graph_view", "to_dot"]


def impact_from_plan(plan: dict | None) -> ImpactResult:
    """Rebuild the ImpactResult from the plan block embedded in a bundle.

    Lets analytics and the API work from a serialized bundle without
    re-running resolution.
    """
    block = (plan or {}).get("impact") or {}
    kinds = set(block.get("changed_asset_kinds", []))
    return ImpactResult(
        changed_asset_ids=list(block.get("changed_asset_ids", [])),
        changed_kinds={str(k) for k in kinds},
        impacted_asset_ids=list(block.get("impacted_asset_ids", [])),
        impact_paths=[list(p) for p in block.get("impact_paths", [])],
        unknown_critical_impact=bool(block.get("unknown_critical_impact", False)),
        gaps=[],
    )


def build_graph_view(*args, **kwargs):
    from .metrics import build_graph_view as _impl
    return _impl(*args, **kwargs)


def to_dot(*args, **kwargs):
    from .metrics import to_dot as _impl
    return _impl(*args, **kwargs)
