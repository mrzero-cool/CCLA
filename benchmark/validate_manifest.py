"""Validate the scenario manifest's basic structure and expected family counts."""
from __future__ import annotations
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
manifest = json.loads((ROOT / "scenarios" / "scenarios.json").read_text(encoding="utf-8"))
scenarios = manifest.get("scenarios", [])
assert len(scenarios) == 48, f"Expected 48 scenarios, found {len(scenarios)}"
ids = [scenario.get("scenario_id") for scenario in scenarios]
assert len(ids) == len(set(ids)), "Scenario IDs must be unique"
for scenario in scenarios:
    for field in ("scenario_id", "family", "name", "expected_status", "changed_asset_kinds", "expected_mandatory_checks", "seeded_fault"):
        assert field in scenario, f"{scenario.get('scenario_id')}: missing {field}"
    assert scenario["expected_status"] in {"PASS", "WARN", "BLOCK", "INCOMPLETE"}
counts = Counter(s["family"] for s in scenarios)
expected = {
    "safe_low_impact": 12,
    "code_api": 12,
    "data_lineage": 12,
    "agent_ai_permissions": 12,
}
assert counts == expected, f"Family counts differ: {counts}"
print(json.dumps({"status": "valid", "scenario_count": len(scenarios), "family_counts": counts}, indent=2))
