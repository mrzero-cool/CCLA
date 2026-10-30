"""Deterministic agent behavior assertions (no live model calls)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from agents.replenishment.agent import REQUIRED_OUTPUT_KEYS, ReplenishmentAgent  # noqa: E402

PROMPT = (ROOT / "agents" / "replenishment" / "prompts" / "system.md").read_text(encoding="utf-8")


def test_prompt_requires_evidence_refs():
    assert "evidence_refs" in PROMPT


def test_prompt_requires_json_output_contract():
    assert "JSON object" in PROMPT


def test_agent_output_schema_is_stable():
    agent = ReplenishmentAgent(evidence_refs=["tool:read_inventory"])
    output = agent.recommend("sku-1", on_hand=2, reorder_point=10)
    assert set(output) == set(REQUIRED_OUTPUT_KEYS)
    assert output["recommended_quantity"] == 8
    assert output["evidence_refs"], "agent must not claim data without evidence refs"


def test_agent_does_not_over_order():
    agent = ReplenishmentAgent(evidence_refs=["tool:read_inventory"])
    output = agent.recommend("sku-1", on_hand=50, reorder_point=10)
    assert output["recommended_quantity"] == 0
