"""Evidence bundle assembly: intake + adapters + impact + rules + plan.

The assembled bundle is sealed with a canonical digest so later mutation is
detectable by the policy engine.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from .adapters import AgentConfigAdapter, DbtManifestAdapter, PythonASTAdapter
from .digest import canonical_json, sha256_hex
from .graph import resolve_impact
from .intake import ChangeManifest
from .models import (
    Asset, CoverageGap, EvidenceBundle, EvidenceRecord, PolicyFinding,
    Relationship, ValidationCheck, ChangeSet,
)
from .planner import plan_checks
from .policy import compute_policy_digest
from .rules import evaluate_policy_rules


def catalog_digest(catalog: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(catalog))


def build_bundle(
    repo: Path,
    manifest: ChangeManifest,
    catalog: dict[str, Any],
    policy: dict[str, Any],
    budget_seconds: float,
    artifacts_root: str | None = None,
) -> tuple[EvidenceBundle, dict[str, Any]]:
    """Return (sealed bundle, plan). The plan is also embedded in the bundle."""
    adapters = [PythonASTAdapter(), DbtManifestAdapter(), AgentConfigAdapter()]
    assets: list[Asset] = []
    relationships: list[Relationship] = []
    evidence: list[EvidenceRecord] = []
    gaps: list[CoverageGap] = []
    facts: dict[str, Any] = {}
    adapter_records: list[dict[str, Any]] = []

    for adapter in adapters:
        result = adapter.collect(repo, manifest)
        assets.extend(result.assets)
        relationships.extend(result.relationships)
        evidence.extend(result.evidence)
        gaps.extend(result.gaps)
        facts.update(result.facts)
        adapter_records.append({
            "name": adapter.name,
            "version": "0.4.0",
            "status": "collected",
            "assets": len(result.assets),
            "relationships": len(result.relationships),
        })

    impact = resolve_impact(assets, relationships, set(manifest.changed_paths), gaps)
    gaps = impact.gaps

    if not manifest.version_bound:
        gaps.append(CoverageGap(
            gap_id="gap-unversioned-source",
            kind="unversioned_source",
            severity="medium",
            why_it_matters=(
                "No VCS binding was available; evidence is bound to a working-tree content "
                "digest rather than an immutable commit."
            ),
            blocking=False,
            required=False,
            remediation="Run inside a Git repository with resolvable base/head commits.",
        ))

    findings, rule_gaps = evaluate_policy_rules(policy, facts)
    gaps.extend(rule_gaps)

    plan = plan_checks(
        changed_kinds=impact.changed_kinds,
        catalog=catalog,
        budget_seconds=budget_seconds,
        unknown_critical_impact=impact.unknown_critical_impact,
    )
    plan["impact"] = {
        "changed_asset_ids": impact.changed_asset_ids,
        "changed_asset_kinds": sorted(impact.changed_kinds),
        "impacted_asset_count": len(impact.impacted_asset_ids),
        "impacted_asset_ids": impact.impacted_asset_ids,
        "impact_paths": impact.impact_paths,
        "unknown_critical_impact": impact.unknown_critical_impact,
    }
    for gap in plan["coverage_gaps"]:
        gaps.append(CoverageGap(
            gap_id=gap["gap_id"], kind=gap["kind"], severity=gap["severity"],
            subject_refs=gap.get("subject_refs", []),
            why_it_matters=gap["why_it_matters"],
            blocking=bool(gap["blocking"]), required=bool(gap["required"]),
            remediation=gap.get("remediation"),
        ))

    checks = [
        ValidationCheck(
            check_id=spec["check_id"],
            category=spec.get("category", "quality"),
            # The declared requirement mirrors the catalog exactly; the plan's
            # selection is expressed through required_check_ids instead.
            requirement=spec.get("requirement", "optional"),
            command_ref=spec.get("command_ref"),
            selection_reason=list(spec.get("selection_reason", [])),
        )
        for spec in plan["selected_checks"]
    ]
    required_ids = sorted({
        spec["check_id"] for spec in plan["selected_checks"]
        if spec["effective_requirement"] == "mandatory"
    })

    change = ChangeSet(
        change_id=f"run-{uuid.uuid4().hex[:12]}",
        repository=manifest.repository,
        base_revision=manifest.base_revision,
        head_revision=manifest.head_revision,
        diff_digest=manifest.diff_digest,
        trigger="pull_request" if manifest.version_bound else "local_cli",
    )

    bundle = EvidenceBundle(
        change=change,
        assets=assets,
        relationships=relationships,
        evidence=evidence,
        checks=checks,
        required_check_ids=required_ids,
        coverage_gaps=gaps,
        policy_findings=findings,
        policy_id=policy.get("policy_id", "default-pr-policy"),
        policy_version=policy.get("version", "0.2.0"),
        policy_digest=compute_policy_digest(policy),
        check_catalog_digest=catalog_digest(catalog),
        artifact_root=artifacts_root,
        plan=plan,
        adapters=adapter_records,
    )
    bundle.bundle_digest = compute_sealed_digest(bundle)
    return bundle, plan


def compute_sealed_digest(bundle: EvidenceBundle) -> str:
    payload = bundle.model_dump(mode="json", exclude={"bundle_digest", "created_at"})
    return sha256_hex(canonical_json(payload))
