"""Impact resolver: policy-scoped traversal plus the coverage-gap registry.

Only declared relation types are traversed, and only in their adapter-declared
impact direction. Unresolved edges never disappear; they either promote the
fallback suite or become a blocking gap (architecture sections 2 and 4).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Asset, CoverageGap, Relationship

# Which relation types may propagate impact, and in which direction.
# "forward": a change at the source affects the target.
# "reverse": a change at the target affects the source.
_TRAVERSAL_POLICY: dict[str, str] = {
    "calls": "forward",
    "imports": "forward",
    "implements": "forward",
    "reads_from": "forward",
    "writes_to": "both",
    "transforms_to": "forward",
    "exposes": "forward",
    "consumes": "reverse",
    "uses_prompt": "both",
    "uses_model": "forward",
    "grants_tool": "forward",
    "validated_by": "reverse",
    "deployed_as": "forward",
    "owns": "forward",
}

_CRITICAL_KINDS = {"api.endpoint", "ai.tool", "ai.policy", "data.model", "data.table"}
_MAX_HOPS = 4


@dataclass
class ImpactResult:
    changed_asset_ids: list[str]
    changed_kinds: set[str]
    impacted_asset_ids: list[str]
    impact_paths: list[list[str]] = field(default_factory=list)
    unknown_critical_impact: bool = False
    gaps: list[CoverageGap] = field(default_factory=list)


def resolve_impact(
    assets: list[Asset],
    relationships: list[Relationship],
    changed_paths: set[str],
    adapter_gaps: list[CoverageGap] | None = None,
) -> ImpactResult:
    by_id = {a.asset_id: a for a in assets}
    changed = {
        a.asset_id for a in assets
        if a.path and a.path in changed_paths
    }
    # Assets can also be declared by a file that is not their own location
    # (e.g. dbt models declared inside manifest.json); a change to the declaring
    # file changes the declared asset.
    changed |= {
        a.asset_id for a in assets
        if a.attributes.get("declared_by") in changed_paths
    }
    changed_kinds = {by_id[aid].kind for aid in changed}

    adjacency: dict[str, list[tuple[str, str]]] = {}
    for rel in relationships:
        propagation = _TRAVERSAL_POLICY.get(rel.relation_type)
        if propagation is None:
            continue
        if propagation in ("forward", "both"):
            adjacency.setdefault(rel.source_asset_id, []).append((rel.target_asset_id, rel.relationship_id))
        if propagation in ("reverse", "both"):
            adjacency.setdefault(rel.target_asset_id, []).append((rel.source_asset_id, rel.relationship_id))

    impacted: set[str] = set()
    paths: list[list[str]] = []
    frontier = {aid: [aid] for aid in changed}
    for _ in range(_MAX_HOPS):
        next_frontier: dict[str, list[str]] = {}
        for source, prefix in frontier.items():
            for target, _rel_id in adjacency.get(source, []):
                if target in changed:
                    continue
                path = prefix + [target]
                if target not in impacted:
                    impacted.add(target)
                    if len(paths) < 50:
                        paths.append(path)
                next_frontier.setdefault(target, path)
        if not next_frontier:
            break
        frontier = next_frontier

    gaps = list(adapter_gaps or [])
    unknown_critical = False
    for rel in relationships:
        if rel.resolution in ("unresolved", "ambiguous"):
            involves_critical = any(
                by_id.get(ref) is not None and by_id[ref].kind in _CRITICAL_KINDS
                for ref in (rel.source_asset_id, rel.target_asset_id)
            )
            if involves_critical or rel.source_asset_id in changed or rel.target_asset_id in changed:
                unknown_critical = True

    # A changed critical asset with zero known relationships means our evidence
    # about its blast radius is empty, which is not the same as "no impact".
    involved = {rel.source_asset_id for rel in relationships} | {rel.target_asset_id for rel in relationships}
    _EXPECTED_EDGE_KINDS = {"api.endpoint", "data.model", "data.table"}
    for aid in changed:
        asset = by_id.get(aid)
        if (
            asset is not None
            and asset.kind in _EXPECTED_EDGE_KINDS
            and aid not in involved
        ):
            unknown_critical = True
            gaps.append(CoverageGap(
                gap_id=f"gap-no-impact-evidence:{aid}",
                kind="unresolved_dependency",
                severity="high", subject_refs=[aid],
                why_it_matters="A critical asset changed but no relationship evidence was found for it; blast radius is unknown.",
                blocking=True, required=True,
                remediation="Register the asset's relationships or accept the promoted full-suite fallback.",
            ))

    # Blocking adapter gaps on critical subjects also mean critical impact is unknown.
    for gap in gaps:
        if gap.required and gap.severity in ("critical", "high"):
            unknown_critical = True

    return ImpactResult(
        changed_asset_ids=sorted(changed),
        changed_kinds=changed_kinds,
        impacted_asset_ids=sorted(impacted - changed),
        impact_paths=paths,
        unknown_critical_impact=unknown_critical,
        gaps=gaps,
    )
