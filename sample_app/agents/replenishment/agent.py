"""Synthetic replenishment agent used by the CLCA demo benchmark.

The agent itself is deterministic: it only consumes data returned by the tools
declared in tool_manifest.json and always emits evidence references.
"""
from __future__ import annotations

from dataclasses import dataclass, field

REQUIRED_OUTPUT_KEYS = ("product_id", "recommended_quantity", "rationale", "evidence_refs")


@dataclass
class ReplenishmentAgent:
    agent_id: str = "replenishment-assistant"
    evidence_refs: list[str] = field(default_factory=list)

    def recommend(self, product_id: str, on_hand: int, reorder_point: int) -> dict:
        if on_hand >= reorder_point:
            quantity = 0
            rationale = "on-hand stock already meets the reorder point"
        else:
            quantity = reorder_point - on_hand
            rationale = "on-hand stock is below the reorder point"
        return {
            "product_id": product_id,
            "recommended_quantity": quantity,
            "rationale": rationale,
            "evidence_refs": list(self.evidence_refs),
        }
