"""Transparent rule-driven validation planner for the MVP."""
from __future__ import annotations

from typing import Any


def plan_checks(
    changed_kinds: set[str],
    catalog: dict[str, Any],
    budget_seconds: float,
    unknown_critical_impact: bool = False,
) -> dict[str, Any]:
    """Select checks while never dropping triggered mandatory checks for budget.

    A catalog check with requirement=conditional becomes mandatory when one of
    its trigger asset kinds changed. Optional checks can be skipped by budget.
    When critical impact is unknown, configured fallback checks are promoted to
    mandatory; if no fallback is available, the plan emits a blocking gap.
    """
    specs = catalog.get("checks", [])
    selected: dict[str, dict[str, Any]] = {}
    excluded: list[dict[str, str]] = []
    gaps: list[dict[str, str]] = []

    for spec in specs:
        triggers = set(spec.get("triggers", []))
        if "*" not in triggers and not (triggers & changed_kinds):
            continue
        requirement = spec.get("requirement", "optional")
        effective = "mandatory" if requirement in ("mandatory", "conditional") else "optional"
        selected[spec["check_id"]] = {
            **spec,
            "effective_requirement": effective,
            "selection_reason": ["changed asset kind matched catalog trigger"],
        }

    if unknown_critical_impact:
        fallback_ids = set(catalog.get("unknown_critical_fallback_check_ids", []))
        promoted = 0
        for spec in specs:
            if spec.get("check_id") in fallback_ids:
                item = selected.setdefault(spec["check_id"], {
                    **spec,
                    "effective_requirement": "mandatory",
                    "selection_reason": [],
                })
                item["effective_requirement"] = "mandatory"
                item["selection_reason"].append("promoted because critical impact is unresolved")
                promoted += 1
        if promoted == 0:
            gaps.append({
                "gap_id": "gap-no-critical-impact-fallback",
                "kind": "unresolved_dependency",
                "severity": "critical",
                "subject_refs": sorted(changed_kinds),
                "why_it_matters": "Critical impact is unresolved and the catalog defines no fallback checks.",
                "blocking": True,
                "required": True,
                "remediation": "Add fallback checks to the catalog or resolve the impact evidence.",
            })

    ordered = sorted(
        selected.values(),
        key=lambda item: (0 if item["effective_requirement"] == "mandatory" else 1,
                          -float(item.get("priority", 1)),
                          float(item.get("estimated_seconds", 0))),
    )
    mandatory_total = sum(float(x.get("estimated_seconds", 0)) for x in ordered if x["effective_requirement"] == "mandatory")
    optional_budget = max(0.0, budget_seconds - mandatory_total)
    chosen: list[dict[str, Any]] = []
    optional_used = 0.0

    for item in ordered:
        duration = float(item.get("estimated_seconds", 0))
        if item["effective_requirement"] == "mandatory":
            chosen.append(item)
        elif optional_used + duration <= optional_budget:
            chosen.append(item)
            optional_used += duration
        else:
            excluded.append({
                "check_id": item["check_id"],
                "reason": "optional verification budget exhausted; no mandatory check was skipped",
            })

    if excluded:
        gaps.append({
            "gap_id": "gap-optional-budget-exhausted",
            "kind": "budget_exhausted",
            "severity": "low",
            "subject_refs": [item["check_id"] for item in excluded],
            "why_it_matters": "Optional checks were skipped by budget; the skipped work is disclosed, not hidden.",
            "blocking": False,
            "required": False,
            "remediation": "Raise --budget-seconds if deeper optional coverage is desired.",
        })

    return {
        "schema_version": "0.2.0",
        "changed_asset_kinds": sorted(changed_kinds),
        "budget_seconds": budget_seconds,
        "mandatory_estimated_seconds": mandatory_total,
        "selected_estimated_seconds": sum(float(x.get("estimated_seconds", 0)) for x in chosen),
        "mandatory_budget_overrun": mandatory_total > budget_seconds,
        "selected_checks": chosen,
        "excluded_checks": excluded,
        "coverage_gaps": gaps,
        "policy_note": "Budget orders/skips optional checks only; mandatory checks are never silently omitted.",
    }
