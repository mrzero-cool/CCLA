"""Praxen adapter — agent remit vs observed behavior evidence.

Praxen compares an agent's declared remit (authorized tools, mission, restrictions)
with available code, deployment or behavioral evidence.  This adapter reads Praxen's
comparison export (JSON) and normalizes it into UCEM: ai.agent, ai.tool, ai.policy
assets with grants_tool relationships and coverage gaps for remit violations.

If the Praxen export is unavailable, returns an empty result with a coverage gap.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ..digest import digest_obj
from ..intake import ChangeManifest
from .base import Adapter, AdapterResult, make_evidence, relationship_id
from ..models import Asset, AssetKind, CoverageGap, Relationship

logger = logging.getLogger("clca.adapters.praxen")

_KIND_MAP: dict[str, AssetKind] = {
    "agent": AssetKind.AI_AGENT,
    "tool": AssetKind.AI_TOOL,
    "policy": AssetKind.AI_POLICY,
    "manifest": AssetKind.AI_POLICY,
    "deployment": AssetKind.DEPLOYMENT_CONFIG,
}

_RELATION_MAP: dict[str, str] = {
    "grants_tool": "grants_tool",
    "authorized_tool": "grants_tool",
    "declares_tool": "grants_tool",
    "calls": "calls",
    "imports": "imports",
    "violates": "calls",
    "exceeds": "calls",
}


class PraxenAdapter(Adapter):
    """Reads Praxen remit-vs-behavior comparison output and normalizes to UCEM."""

    name = "praxen"
    version = "0.4.0"

    def __init__(self, export_path: Path | str | None = None) -> None:
        self.export_path = Path(export_path) if export_path else None

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()

        if self.export_path is None or not self.export_path.is_file():
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:praxen:missing",
                    kind="unsupported_asset",
                    severity="medium",
                    subject_refs=[manifest.head_revision],
                    why_it_matters="Praxen remit comparison export not found; "
                    "agent permission evidence will be incomplete.",
                    blocking=False,
                    required=False,
                    remediation="Run Praxen comparison and point --praxen-export at "
                    "the output JSON file.",
                )
            )
            return result

        try:
            data = json.loads(self.export_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Praxen export unreadable: %s", exc)
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:praxen:unreadable",
                    kind="runner_unavailable",
                    severity="high",
                    subject_refs=[manifest.head_revision],
                    why_it_matters=f"Praxen export could not be parsed: {exc}",
                    blocking=False,
                    required=False,
                    remediation="Re-run Praxen comparison and verify JSON validity.",
                )
            )
            return result

        agents = data.get("agents", [])
        tools = data.get("tools", [])
        policies = data.get("policies", [])
        comparisons = data.get("comparisons", data.get("remit_comparisons", []))

        for item, kind_key in (
            (agents, "agent"),
            (tools, "tool"),
            (policies, "policy"),
        ):
            for item_data in item:
                item_id = str(item_data.get("id") or item_data.get("key") or "")
                if not item_id:
                    continue
                kind = _KIND_MAP.get(kind_key, AssetKind.AI_AGENT)
                asset = Asset(
                    asset_id=f"praxen:{kind_key}:{item_id}",
                    kind=kind,
                    name=str(item_data.get("name") or item_data.get("label") or item_id),
                    repository=manifest.repository,
                    path=str(item_data.get("path") or ""),
                    revision=manifest.head_revision,
                    criticality="unknown",
                    identity_status="adapter_scoped",
                    attributes={
                        "source": "praxen",
                        "original_type": kind_key,
                        "declared_remit": item_data.get("declared_remit", []),
                        "restrictions": item_data.get("restrictions", []),
                    },
                )
                result.assets.append(asset)

        # Comparison results: agent -> tool grants, violations
        for comp in comparisons:
            agent_id = str(comp.get("agent_id") or comp.get("agent") or "")
            tool_id = str(comp.get("tool_id") or comp.get("tool") or "")
            status = str(comp.get("status", "unknown")).lower()
            violation = str(comp.get("violation") or "")

            if agent_id and tool_id:
                rel = Relationship(
                    relationship_id=relationship_id(
                        f"praxen:agent:{agent_id}", f"praxen:tool:{tool_id}", "grants_tool"
                    ),
                    source_asset_id=f"praxen:agent:{agent_id}",
                    target_asset_id=f"praxen:tool:{tool_id}",
                    relation_type="grants_tool",  # type: ignore[arg-type]
                    impact_direction="forward",
                    resolution="resolved" if status == "compliant" else "inferred",
                    provenance_refs=["praxen"],
                    observed_revision=manifest.head_revision,
                    limitations=[f"Remit status: {status}", violation] if violation else [f"Remit status: {status}"],
                )
                result.relationships.append(rel)

            # Violations become coverage gaps
            if status in ("violation", "non_compliant", "failed") and violation:
                result.gaps.append(
                    CoverageGap(
                        gap_id=f"gap:praxen:{agent_id}:{digest_obj([violation])[7:15]}",
                        kind="unsupported_asset",
                        severity="high",
                        subject_refs=[f"praxen:agent:{agent_id}"],
                        why_it_matters=f"Praxen remit violation: {violation}",
                        blocking=False,
                        required=False,
                        remediation="Align agent behavior with declared remit or "
                        "update the declared policy.",
                    )
                )

        input_digest = digest_obj(
            [str(self.export_path), manifest.head_revision, str(len(agents)), str(len(comparisons))]
        )
        result.evidence.append(
            make_evidence(
                adapter="praxen",
                evidence_type="agent_remit_comparison",
                subject_refs=[manifest.head_revision],
                observed_revision=manifest.head_revision,
                input_digest=input_digest,
                support="derived",
                limitations=[
                    "Remit comparison depends on Praxen export freshness",
                    "Declared remit may not match actual runtime behavior",
                ],
            )
        )

        result.facts["praxen_agent_count"] = len(agents)
        result.facts["praxen_tool_count"] = len(tools)
        result.facts["praxen_comparison_count"] = len(comparisons)
        return result


def load_praxen_adapter(export_path: Path | str | None = None) -> PraxenAdapter:
    return PraxenAdapter(export_path=export_path)
