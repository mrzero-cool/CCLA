#!/usr/bin/env python3
"""Compare CLCA's current check planner with the benchmark's target selections.

This is a planner-contract diagnostic only. It does NOT execute seeded faults,
run tests, validate final decisions, or establish regression-detection rates.
The benchmark manifest remains the target contract; mismatches are not silently
rewritten to whatever the current planner happens to select.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from clca.planner import plan_checks  # noqa: E402


def compare(root: Path = ROOT, budget_seconds: float = 60.0) -> dict[str, Any]:
    manifest = json.loads((root / "benchmark/scenarios/scenarios.json").read_text(encoding="utf-8"))
    catalog = json.loads((root / "config/check_catalog.json").read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for scenario in manifest.get("scenarios", []):
        plan = plan_checks(
            changed_kinds=set(scenario.get("changed_asset_kinds", [])),
            catalog=catalog,
            budget_seconds=budget_seconds,
            unknown_critical_impact=bool(scenario.get("unknown_critical_impact", False)),
        )
        actual = sorted(
            item["check_id"] for item in plan.get("selected_checks", [])
            if item.get("effective_requirement") == "mandatory"
        )
        expected = sorted(scenario.get("expected_mandatory_checks", []))
        if actual != expected:
            rows.append({
                "scenario_id": scenario.get("scenario_id"),
                "name": scenario.get("name"),
                "unknown_critical_impact": bool(scenario.get("unknown_critical_impact", False)),
                "expected_mandatory_checks": expected,
                "planned_mandatory_checks": actual,
                "missing_from_plan": sorted(set(expected) - set(actual)),
                "unexpected_in_plan": sorted(set(actual) - set(expected)),
                "expected_status": scenario.get("expected_status"),
                "note": "selection mismatch; not a regression-detection result",
            })
    total = len(manifest.get("scenarios", []))
    return {
        "diagnostic": "planner_vs_benchmark_selection_contract",
        "is_full_benchmark": False,
        "budget_seconds": budget_seconds,
        "scenario_count": total,
        "aligned_count": total - len(rows),
        "mismatch_count": len(rows),
        "status": "aligned" if not rows else "needs_review",
        "mismatches": rows,
        "limitations": [
            "Does not execute scenario mutations or validation commands.",
            "Does not compare regression detection, false blocks, runtime, or cost.",
            "Uses the manifest's unknown_critical_impact field; omitted fields default to false.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--budget-seconds", type=float, default=60.0)
    parser.add_argument("--output", type=Path, help="optional JSON output path")
    parser.add_argument("--strict", action="store_true", help="exit 1 when any scenario differs")
    args = parser.parse_args()
    result = compare(args.root.resolve(), args.budget_seconds)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 1 if args.strict and result["mismatch_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
