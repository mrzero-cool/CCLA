"""Executable policy rules derived from config/policy.json.

The booleans in the policy file are no longer decorative: this module evaluates
them against adapter facts (notably the agent tool-manifest diff) and emits
deterministic PolicyFindings. An LLM never participates here.
"""
from __future__ import annotations

from typing import Any

from .models import CoverageGap, PolicyFinding


def evaluate_policy_rules(policy: dict[str, Any], facts: dict[str, Any]) -> tuple[list[PolicyFinding], list[CoverageGap]]:
    findings: list[PolicyFinding] = []
    gaps: list[CoverageGap] = []
    agent_policy = policy.get("agent_policy", {})

    for key, diff in sorted(facts.items()):
        if not key.startswith("agent_diff:"):
            continue
        if not isinstance(diff, dict):
            continue
        agent_id = key.split(":", 1)[1]

        if not diff.get("available"):
            gaps.append(CoverageGap(
                gap_id=f"gap-privilege-diff-unavailable:{agent_id}",
                kind="missing_baseline",
                severity="critical", subject_refs=[agent_id],
                why_it_matters="Privilege escalation cannot be ruled out without a baseline tool manifest.",
                blocking=True, required=True,
                remediation="Supply the base revision, or review the tool manifest manually before merge.",
            ))
            continue

        head_tools: dict[str, dict] = diff.get("head_tools") or {}  # type: ignore[assignment]
        added: list[str] = list(diff.get("added_tools") or [])

        for tool_name in added:
            spec = head_tools.get(tool_name) or {}
            if not spec.get("allowed", False):
                continue
            access = str(spec.get("access", "unknown")).lower()
            external = bool(spec.get("external", False))
            if access == "write" and agent_policy.get("new_write_tool_requires_review", True):
                findings.append(PolicyFinding(
                    rule_id="AGENT_NEW_WRITE_TOOL",
                    action="BLOCK",
                    summary=f"Agent {agent_id} gained allowed write tool '{tool_name}'.",
                    subject_refs=[f"{agent_id}.tool.{tool_name}"],
                ))
            if external and agent_policy.get("new_external_recipient_tool_requires_review", True):
                findings.append(PolicyFinding(
                    rule_id="AGENT_NEW_EXTERNAL_TOOL",
                    action="BLOCK",
                    summary=f"Agent {agent_id} gained allowed outbound tool '{tool_name}'.",
                    subject_refs=[f"{agent_id}.tool.{tool_name}"],
                ))
            if access not in ("read", "write") and agent_policy.get("new_write_tool_requires_review", True):
                findings.append(PolicyFinding(
                    rule_id="AGENT_UNCLASSIFIED_TOOL_ACCESS",
                    action="WARN",
                    summary=f"Tool '{tool_name}' of {agent_id} declares access '{access}', which the policy does not classify.",
                    subject_refs=[f"{agent_id}.tool.{tool_name}"],
                ))

        changed_fields = [str(f) for f in (diff.get("changed_fields") or [])]
        policy_doc = diff.get("head_document") or {}
        head_policy_flags = policy_doc.get("policy", {}) if isinstance(policy_doc, dict) else {}

        if "policy" in changed_fields:
            base_doc = diff.get("base_document") or {}
            base_flags = base_doc.get("policy", {}) if isinstance(base_doc, dict) else {}
            for flag in ("allow_write_tools", "allow_external_recipients"):
                if head_policy_flags.get(flag) and not base_flags.get(flag):
                    findings.append(PolicyFinding(
                        rule_id=f"AGENT_POLICY_FLAG_ESCALATION:{flag}",
                        action="BLOCK",
                        summary=f"Agent {agent_id} enabled policy flag '{flag}'.",
                        subject_refs=[f"{agent_id}.policy"],
                    ))

        if "model_binding" in changed_fields and agent_policy.get("model_binding_change_requires_behavior_eval", True):
            findings.append(PolicyFinding(
                rule_id="AGENT_MODEL_BINDING_CHANGED",
                action="WARN",
                summary=f"Agent {agent_id} changed model binding; behavior evaluation must accompany this change.",
                subject_refs=[agent_id],
            ))

    return findings, gaps
