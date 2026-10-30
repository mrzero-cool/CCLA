import json
from pathlib import Path

from clca.planner import plan_checks

ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / "config" / "check_catalog.json").read_text())


def test_mandatory_checks_are_not_skipped_when_budget_is_too_small():
    plan = plan_checks({"data.column"}, CATALOG, budget_seconds=1)
    selected_ids = {c["check_id"] for c in plan["selected_checks"]}
    assert "static-manifest-validation" in selected_ids
    assert "data-contract-tests" in selected_ids
    assert plan["mandatory_budget_overrun"] is True


def test_optional_checks_can_be_skipped_with_reason():
    plan = plan_checks({"code.function"}, CATALOG, budget_seconds=15)
    assert any(item["reason"].startswith("optional verification budget exhausted") for item in plan["excluded_checks"])


def test_unknown_critical_impact_promotes_fallback_checks():
    plan = plan_checks({"data.column"}, CATALOG, budget_seconds=1, unknown_critical_impact=True)
    selected = {c["check_id"]: c for c in plan["selected_checks"]}
    assert selected["full-applicable-tests"]["effective_requirement"] == "mandatory"
    assert selected["policy-security-smoke"]["effective_requirement"] == "mandatory"


def test_catalog_is_explainable():
    plan = plan_checks({"ai.prompt"}, CATALOG, budget_seconds=100)
    assert all("selection_reason" in check for check in plan["selected_checks"])
