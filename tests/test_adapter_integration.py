"""Tests for adapter integration into the planner."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from clca.adapter_integration import (
    build_enhanced_plan,
    collect_all_adapters,
    merge_adapter_gaps_into_plan,
    promote_checks_from_adapter_facts,
    adapter_derived_policy_findings,
)
from clca.adapters.base import Adapter, AdapterResult
from clca.adapters.registry import AdapterRegistry
from clca.intake import ChangeManifest
from clca.models import CoverageGap


class _DummyAdapter(Adapter):
    name = "dummy"

    def __init__(self, result: AdapterResult) -> None:
        self._result = result

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        return self._result


def _manifest() -> ChangeManifest:
    return ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("src/foo.py",),
    )


def _base_plan() -> dict[str, Any]:
    return {
        "schema_version": "0.2.0",
        "changed_asset_kinds": ["code.function"],
        "budget_seconds": 60.0,
        "mandatory_estimated_seconds": 10.0,
        "selected_estimated_seconds": 10.0,
        "mandatory_budget_overrun": False,
        "selected_checks": [
            {
                "check_id": "static-manifest-validation",
                "effective_requirement": "mandatory",
                "selection_reason": ["changed asset kind matched catalog trigger"],
                "estimated_seconds": 10,
            },
            {
                "check_id": "python-unit-tests",
                "effective_requirement": "mandatory",
                "selection_reason": ["changed asset kind matched catalog trigger"],
                "estimated_seconds": 20,
            },
        ],
        "excluded_checks": [],
        "coverage_gaps": [],
    }


def test_merge_adapter_gaps_into_plan():
    plan = _base_plan()
    result = AdapterResult(
        gaps=[
            CoverageGap(
                gap_id="gap:adapter:stryker:low_score",
                kind="missing_required_test",
                severity="high",
                subject_refs=["b" * 40],
                why_it_matters="Mutation score below threshold",
                blocking=False,
                required=True,
                remediation="Add mutation-killing tests",
            )
        ]
    )
    merged = merge_adapter_gaps_into_plan(plan, result)
    assert len(merged["coverage_gaps"]) == 1
    assert merged["coverage_gaps"][0]["gap_id"] == "gap:adapter:stryker:low_score"
    assert merged["coverage_gaps"][0]["required"] is True


def test_merge_does_not_duplicate_gaps():
    plan = _base_plan()
    result = AdapterResult(
        gaps=[
            CoverageGap(
                gap_id="gap:duplicate",
                kind="unsupported_asset",
                severity="medium",
                subject_refs=["b" * 40],
                why_it_matters="test",
                blocking=False,
                required=False,
            )
        ]
    )
    merged = merge_adapter_gaps_into_plan(plan, result)
    merged = merge_adapter_gaps_into_plan(merged, result)
    assert len(merged["coverage_gaps"]) == 1


def test_promote_checks_from_adapter_facts():
    plan = _base_plan()
    result = AdapterResult(
        facts={
            "stryker_below_threshold": True,
            "stryker_mutation_score": 0.45,
        },
        gaps=[
            CoverageGap(
                gap_id="gap:owasp:agent1:finding1",
                kind="unsupported_asset",
                severity="high",
                subject_refs=["b" * 40],
                why_it_matters="OWASP violation",
                blocking=False,
                required=False,
            )
        ],
    )
    promoted = promote_checks_from_adapter_facts(plan, result)
    check_ids = {c["check_id"] for c in promoted["selected_checks"]}
    assert "mutation-testing" in check_ids
    assert "agent-security-smoke" in check_ids
    # Verify promotion reason recorded
    mt = next(c for c in promoted["selected_checks"] if c["check_id"] == "mutation-testing")
    assert "Stryker mutation score below threshold" in " ".join(mt["selection_reason"])


def test_adapter_derived_policy_findings():
    result = AdapterResult(
        facts={
            "stryker_mutation_score": 0.45,
            "stryker_below_threshold": True,
            "farol_risk_level": "critical",
            "farol_risk_score": 0.9,
            "semctx_verdict": "BLOCK",
            "code_decay_regressions": 2,
        },
        gaps=[
            CoverageGap(
                gap_id="gap:owasp:agent1:finding1",
                kind="unsupported_asset",
                severity="high",
                subject_refs=["b" * 40],
                why_it_matters="OWASP violation",
                blocking=False,
                required=False,
            ),
            CoverageGap(
                gap_id="gap:praxen:agent1:finding2",
                kind="unsupported_asset",
                severity="high",
                subject_refs=["b" * 40],
                why_it_matters="Praxen remit violation",
                blocking=False,
                required=False,
            ),
        ],
    )
    findings = adapter_derived_policy_findings(result)
    rule_ids = {f["rule_id"] for f in findings}
    assert "adapter.stryker.low_mutation_score" in rule_ids
    assert "adapter.farol.high_risk" in rule_ids
    assert "adapter.semctx.block" in rule_ids
    assert "adapter.code_decay.regression_detected" in rule_ids
    assert "adapter.owasp_agent_security.violation" in rule_ids
    assert "adapter.praxen.remit_violation" in rule_ids


def test_build_enhanced_plan_end_to_end():
    reg = AdapterRegistry()
    reg.register("stryker", _DummyAdapter(AdapterResult(
        facts={"stryker_below_threshold": True, "stryker_mutation_score": 0.3},
        gaps=[
            CoverageGap(
                gap_id="gap:stryker:low_score",
                kind="missing_required_test",
                severity="high",
                subject_refs=["b" * 40],
                why_it_matters="Mutation score too low",
                blocking=False,
                required=True,
            )
        ],
    )))
    plan = build_enhanced_plan(Path("/tmp/repo"), _manifest(), _base_plan(), registry=reg)
    assert "adapter_facts" in plan
    assert "adapter_findings" in plan
    assert "adapter_evidence_count" in plan
    assert len(plan["coverage_gaps"]) >= 1
    assert any(f["rule_id"] == "adapter.stryker.low_mutation_score"
               for f in plan["adapter_findings"])


def test_collect_all_adapters_uses_default_registry():
    # Should not raise even with empty registry
    result = collect_all_adapters(Path("/tmp/repo"), _manifest())
    assert isinstance(result, AdapterResult)
