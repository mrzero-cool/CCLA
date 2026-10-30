"""OWASP Agent Security Regression Harness adapter — agent/AI behavior evaluation.

The OWASP Agent Security Regression Harness runs repeatable agent security scenarios
and evaluates policy assertions, including for MCP-integrated workflows.  This
adapter reads the harness result export (JSON) and normalizes it into UCEM:
ai.agent, ai.prompt, ai.tool assets with security/behavior check results and
coverage gaps for unsupported scenarios.

If the harness export is unavailable, returns an empty result with a coverage gap.
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

logger = logging.getLogger("clca.adapters.owasp_agent")

_KIND_MAP: dict[str, AssetKind] = {
    "agent": AssetKind.AI_AGENT,
    "prompt": AssetKind.AI_PROMPT,
    "model": AssetKind.AI_MODEL_BINDING,
    "tool": AssetKind.AI_TOOL,
    "policy": AssetKind.AI_POLICY,
    "eval": AssetKind.TEST_CHECK,
}

_RELATION_MAP: dict[str, str] = {
    "uses_prompt": "uses_prompt",
    "uses_model": "uses_model",
    "grants_tool": "grants_tool",
    "validated_by": "validated_by",
    "calls": "calls",
    "imports": "imports",
}


class OWASPAgentAdapter(Adapter):
    """Reads OWASP Agent Security Harness results and normalizes to UCEM."""

    name = "owasp_agent_security"
    version = "0.4.0"

    def __init__(self, export_path: Path | str | None = None) -> None:
        self.export_path = Path(export_path) if export_path else None

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()

        if self.export_path is None or not self.export_path.is_file():
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:owasp_agent_security:missing",
                    kind="unsupported_asset",
                    severity="medium",
                    subject_refs=[manifest.head_revision],
                    why_it_matters="OWASP Agent Security Harness export not found; "
                    "AI/agent behavior evidence will be incomplete.",
                    blocking=False,
                    required=False,
                    remediation="Run OWASP Agent Security Harness and point "
                    "--owasp-agent-export at the output JSON file.",
                )
            )
            return result

        try:
            data = json.loads(self.export_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("OWASP agent export unreadable: %s", exc)
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:owasp_agent_security:unreadable",
                    kind="runner_unavailable",
                    severity="high",
                    subject_refs=[manifest.head_revision],
                    why_it_matters=f"OWASP agent export could not be parsed: {exc}",
                    blocking=False,
                    required=False,
                    remediation="Re-run OWASP Agent Security Harness and verify JSON validity.",
                )
            )
            return result

        agents = data.get("agents", data.get("nodes", []))
        prompts = data.get("prompts", [])
        tools = data.get("tools", [])
        policies = data.get("policies", [])
        results = data.get("results", data.get("scenario_results", []))

        all_assets = []
        for item, kind_key in (
            (agents, "agent"),
            (prompts, "prompt"),
            (tools, "tool"),
            (policies, "policy"),
        ):
            for item_data in item:
                item_id = str(item_data.get("id") or item_data.get("key") or "")
                if not item_id:
                    continue
                kind = _KIND_MAP.get(kind_key, AssetKind.AI_AGENT)
                asset = Asset(
                    asset_id=f"owasp:{kind_key}:{item_id}",
                    kind=kind,
                    name=str(item_data.get("name") or item_data.get("label") or item_id),
                    repository=manifest.repository,
                    path=str(item_data.get("path") or ""),
                    revision=manifest.head_revision,
                    criticality="unknown",
                    identity_status="adapter_scoped",
                    attributes={
                        "source": "owasp_agent_security",
                        "original_type": kind_key,
                        "metadata": item_data.get("metadata", {}),
                    },
                )
                all_assets.append(asset)
                result.assets.append(asset)

        # Map scenario results to relationships (agent -> prompt/tool validation)
        for res in results:
            agent_id = str(res.get("agent_id") or res.get("agent") or "")
            prompt_id = str(res.get("prompt_id") or res.get("prompt") or "")
            tool_id = str(res.get("tool_id") or res.get("tool") or "")
            status = str(res.get("status", "unknown")).lower()
            finding = str(res.get("finding") or res.get("issue") or "")

            if agent_id and prompt_id:
                rel = Relationship(
                    relationship_id=relationship_id(
                        f"owasp:agent:{agent_id}", f"owasp:prompt:{prompt_id}", "uses_prompt"
                    ),
                    source_asset_id=f"owasp:agent:{agent_id}",
                    target_asset_id=f"owasp:prompt:{prompt_id}",
                    relation_type="uses_prompt",  # type: ignore[arg-type]
                    impact_direction="forward",
                    resolution="resolved" if status == "passed" else "inferred",
                    provenance_refs=["owasp_agent_security"],
                    observed_revision=manifest.head_revision,
                    limitations=[f"Scenario status: {status}", finding] if finding else [f"Scenario status: {status}"],
                )
                result.relationships.append(rel)

            if agent_id and tool_id:
                rel = Relationship(
                    relationship_id=relationship_id(
                        f"owasp:agent:{agent_id}", f"owasp:tool:{tool_id}", "grants_tool"
                    ),
                    source_asset_id=f"owasp:agent:{agent_id}",
                    target_asset_id=f"owasp:tool:{tool_id}",
                    relation_type="grants_tool",  # type: ignore[arg-type]
                    impact_direction="forward",
                    resolution="resolved" if status == "passed" else "inferred",
                    provenance_refs=["owasp_agent_security"],
                    observed_revision=manifest.head_revision,
                    limitations=[f"Scenario status: {status}", finding] if finding else [f"Scenario status: {status}"],
                )
                result.relationships.append(rel)

            # Failed/passed scenario results become policy findings or evidence gaps
            if status in ("failed", "blocked") and finding:
                result.gaps.append(
                    CoverageGap(
                        gap_id=f"gap:owasp:{agent_id}:{digest_obj([finding])[7:15]}",
                        kind="unsupported_asset",
                        severity="high",
                        subject_refs=[f"owasp:agent:{agent_id}"],
                        why_it_matters=f"Agent security finding: {finding}",
                        blocking=False,
                        required=False,
                        remediation="Review and remediate the agent security finding "
                        "before merging.",
                    )
                )

        input_digest = digest_obj(
            [str(self.export_path), manifest.head_revision, str(len(all_assets)), str(len(results))]
        )
        result.evidence.append(
            make_evidence(
                adapter="owasp_agent_security",
                evidence_type="agent_security_scenario_results",
                subject_refs=[manifest.head_revision],
                observed_revision=manifest.head_revision,
                input_digest=input_digest,
                support="derived",
                limitations=[
                    "Results depend on OWASP Agent Security Harness scenario coverage",
                    "Nondeterministic agent behavior may require repeated trials",
                ],
            )
        )

        result.facts["owasp_agent_count"] = len(agents)
        result.facts["owasp_prompt_count"] = len(prompts)
        result.facts["owasp_tool_count"] = len(tools)
        result.facts["owasp_result_count"] = len(results)
        return result


def load_owasp_agent_adapter(export_path: Path | str | None = None) -> OWASPAgentAdapter:
    return OWASPAgentAdapter(export_path=export_path)
