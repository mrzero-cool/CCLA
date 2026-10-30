"""Wire adapter results into the planner and policy engine.

This module takes the merged AdapterResult from all external tool adapters
(AxiomCode, Enola, Code System Graph, DataHub, OWASP, Praxen, Stryker, Farol,
CodeDecay, semctx, etc.) and:

1. Merges adapter coverage gaps into the planner's coverage gaps.
2. Uses adapter facts to promote checks to mandatory (e.g., OWASP violation
   promotes agent-security-smoke to mandatory).
3. Produces adapter-derived policy findings (e.g., low mutation score → INCOMPLETE).
4. Returns an enhanced plan dict that the CLI/service can consume.

The integration is intentionally additive: adapters never *remove* checks or
weaken policy. They only add evidence, gaps, and mandatory promotions.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .adapters.base import AdapterResult
from .adapters.registry import AdapterRegistry, default_registry
from .intake import ChangeManifest

logger = logging.getLogger("clca.adapter_integration")


def collect_all_adapters(
    repo: Path,
    manifest: ChangeManifest,
    registry: AdapterRegistry | None = None,
    adapter_names: list[str] | None = None,
) -> AdapterResult:
    """Run all enabled adapters and merge their results."""
    reg = registry or default_registry
    return reg.collect_all(repo, manifest, names=adapter_names)


def merge_adapter_gaps_into_plan(
    plan: dict[str, Any],
    adapter_result: AdapterResult,
) -> dict[str, Any]:
    """Merge adapter coverage gaps into the planner plan.

    Adapter gaps are appended to plan['coverage_gaps']. Adapter facts that
    indicate missing mandatory evidence (e.g. low mutation score) are promoted
    to blocking gaps so the decision engine can mark INCOMPLETE.
    """
    gaps = list(plan.get("coverage_gaps", []))

    for gap in adapter_result.gaps:
        gap_dict = {
            "gap_id": gap.gap_id,
            "kind": gap.kind,
            "severity": gap.severity,
            "subject_refs": gap.subject_refs,
            "why_it_matters": gap.why_it_matters,
            "blocking": gap.blocking,
            "required": gap.required,
            "remediation": gap.remediation,
            "source": "adapter",
        }
        # Avoid duplicate gap_ids
        existing_ids = {g.get("gap_id") for g in gaps}
        if gap_dict["gap_id"] not in existing_ids:
            gaps.append(gap_dict)

    plan["coverage_gaps"] = gaps
    return plan


def promote_checks_from_adapter_facts(
    plan: dict[str, Any],
    adapter_result: AdapterResult,
) -> dict[str, Any]:
    """Use adapter facts to promote checks to mandatory.

    Rules (additive only):
    - Stryker mutation_score below threshold → promote mutation-testing check to mandatory
    - OWASP agent violation → promote agent-security-smoke to mandatory
    - Praxen remit violation → promote agent-security-smoke to mandatory
    - Farol risk_level critical/high → promote security-review to mandatory
    - CodeDecay regression detected → promote regression-test to mandatory
    - semctx verdict BLOCK → promote deterministic-review to mandatory
    - Code System Graph incomplete areas → promote impact-review to mandatory
    """
    selected = plan.get("selected_checks", [])
    facts = adapter_result.facts

    # Stryker: low mutation score → mutation testing mandatory
    if facts.get("stryker_below_threshold"):
        _promote_check(selected, "mutation-testing", "mandatory",
                       "promoted: Stryker mutation score below threshold")

    # OWASP: security finding → agent security check mandatory
    owasp_gaps = [g for g in adapter_result.gaps
                  if g.gap_id.startswith("gap:owasp:")]
    if owasp_gaps:
        _promote_check(selected, "agent-security-smoke", "mandatory",
                       "promoted: OWASP agent security violation detected")

    # Praxen: remit violation → agent security mandatory
    praxen_violations = [g for g in adapter_result.gaps
                         if g.gap_id.startswith("gap:praxen:")]
    if praxen_violations:
        _promote_check(selected, "agent-security-smoke", "mandatory",
                       "promoted: Praxen remit violation detected")

    # Farol: critical/high risk → security review mandatory
    risk_level = facts.get("farol_risk_level", "unknown")
    if risk_level in ("critical", "high"):
        _promote_check(selected, "security-review", "mandatory",
                       f"promoted: Farol risk level is {risk_level}")

    # CodeDecay: regression detected → regression test mandatory
    if facts.get("code_decay_regressions", 0) > 0:
        _promote_check(selected, "regression-test", "mandatory",
                       "promoted: CodeDecay regression detected")

    # semctx: BLOCK verdict → deterministic review mandatory
    if facts.get("semctx_verdict") == "BLOCK":
        _promote_check(selected, "deterministic-review", "mandatory",
                       "promoted: semctx deterministic verdict is BLOCK")

    # Code System Graph: incomplete areas → impact review mandatory
    csg_gaps = [g for g in adapter_result.gaps
                if g.gap_id.startswith("gap:csg:")]
    if csg_gaps:
        _promote_check(selected, "impact-review", "mandatory",
                       "promoted: Code System Graph incomplete coverage areas")

    plan["selected_checks"] = selected
    return plan


def _promote_check(
    selected: list[dict[str, Any]],
    check_id: str,
    requirement: str,
    reason: str,
) -> None:
    """Promote a check in the selected list to a given requirement level."""
    for item in selected:
        if item.get("check_id") == check_id:
            item["effective_requirement"] = requirement
            item["selection_reason"] = list(item.get("selection_reason", []))
            item["selection_reason"].append(reason)
            return
    # Check not in plan; add it as a new mandatory selection
    selected.append({
        "check_id": check_id,
        "effective_requirement": requirement,
        "selection_reason": [reason],
        "source": "adapter_promotion",
    })


def adapter_derived_policy_findings(
    adapter_result: AdapterResult,
) -> list[dict[str, Any]]:
    """Produce policy findings from adapter results that the decision engine can use.

    Returns findings that can be merged into bundle.policy_findings:
    - Low mutation score → finding about test effectiveness
    - OWASP violation → security policy finding
    - Praxen violation → agent remit finding
    - Farol BLOCK/critical → risk policy finding
    - CodeDecay regression → regression risk finding
    - semctx BLOCK → deterministic gate finding
    """
    findings: list[dict[str, Any]] = []
    facts = adapter_result.facts

    # Stryker mutation score
    score = facts.get("stryker_mutation_score")
    if score is not None and facts.get("stryker_below_threshold"):
        findings.append({
            "rule_id": "adapter.stryker.low_mutation_score",
            "action": "WARN",
            "summary": (
                f"Mutation score {score:.0%} below threshold; "
                "test suite may not detect all defects."
            ),
            "source": "adapter:stryker",
        })

    # OWASP violations
    owasp_gaps = [g for g in adapter_result.gaps
                  if g.gap_id.startswith("gap:owasp:")]
    for gap in owasp_gaps:
        findings.append({
            "rule_id": "adapter.owasp_agent_security.violation",
            "action": "BLOCK",
            "summary": gap.why_it_matters,
            "source": "adapter:owasp_agent_security",
        })

    # Praxen violations
    praxen_gaps = [g for g in adapter_result.gaps
                   if g.gap_id.startswith("gap:praxen:")]
    for gap in praxen_gaps:
        findings.append({
            "rule_id": "adapter.praxen.remit_violation",
            "action": "BLOCK",
            "summary": gap.why_it_matters,
            "source": "adapter:praxen",
        })

    # Farol risk
    risk_level = facts.get("farol_risk_level", "unknown")
    risk_score = facts.get("farol_risk_score", 0.0)
    if risk_level in ("critical", "high"):
        findings.append({
            "rule_id": "adapter.farol.high_risk",
            "action": "WARN" if risk_level == "high" else "BLOCK",
            "summary": (
                f"Farol PR risk level {risk_level} (score {risk_score:.2f}); "
                "review recommended before merge."
            ),
            "source": "adapter:farol",
        })

    # CodeDecay regressions
    regressions = facts.get("code_decay_regressions", 0)
    if regressions > 0:
        findings.append({
            "rule_id": "adapter.code_decay.regression_detected",
            "action": "BLOCK",
            "summary": (
                f"CodeDecay detected {regressions} potential regression(s); "
                "regression test required before merge."
            ),
            "source": "adapter:code_decay",
        })

    # semctx BLOCK
    if facts.get("semctx_verdict") == "BLOCK":
        findings.append({
            "rule_id": "adapter.semctx.block",
            "action": "BLOCK",
            "summary": "semctx deterministic change gate returned BLOCK.",
            "source": "adapter:semctx",
        })

    return findings


def build_enhanced_plan(
    repo: Path,
    manifest: ChangeManifest,
    base_plan: dict[str, Any],
    registry: AdapterRegistry | None = None,
    adapter_names: list[str] | None = None,
) -> dict[str, Any]:
    """Run all adapters and merge results into the base planner plan.

    Returns a plan dict with:
    - All original planner fields
    - Merged adapter coverage gaps
    - Adapter-promoted mandatory checks
    - adapter_facts and adapter_findings for the decision engine
    - adapter_evidence summary
    """
    adapter_result = collect_all_adapters(repo, manifest, registry=registry,
                                          adapter_names=adapter_names)

    plan = merge_adapter_gaps_into_plan(base_plan, adapter_result)
    plan = promote_checks_from_adapter_facts(plan, adapter_result)

    # Recompute mandatory budget after promotions
    mandatory_total = sum(
        float(x.get("estimated_seconds", 0))
        for x in plan.get("selected_checks", [])
        if x.get("effective_requirement") == "mandatory"
    )
    plan["mandatory_estimated_seconds"] = mandatory_total
    plan["mandatory_budget_overrun"] = mandatory_total > float(
        plan.get("budget_seconds", 0)
    )

    # Attach adapter context for downstream decision engine
    plan["adapter_facts"] = adapter_result.facts
    plan["adapter_findings"] = adapter_derived_policy_findings(adapter_result)
    plan["adapter_evidence_count"] = len(adapter_result.evidence)
    plan["adapter_gap_count"] = len(adapter_result.gaps)
    plan["adapters_used"] = adapter_result.facts  # facts contain per-adapter counts

    logger.info(
        "adapter integration: %d adapters, %d gaps, %d findings, %d promoted checks",
        len(adapter_result.facts) // 4,  # rough estimate
        len(adapter_result.gaps),
        len(plan["adapter_findings"]),
        sum(1 for x in plan.get("selected_checks", [])
            if x.get("source") == "adapter_promotion"),
    )

    return plan
