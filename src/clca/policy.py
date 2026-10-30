"""Deterministic release policy. LLMs must never choose the final status.

Hardening (architecture addendum, section A.2) — the decision no longer trusts
the bundle alone:

1. ``policy_digest`` must match the digest of the loaded policy file.
2. ``bundle_digest`` must match a recomputation over the canonical bundle.
3. Check requirements and ``required_check_ids`` are derived from the
   version-controlled check catalog, never from bundle-declared fields.
4. Evidence freshness and revision binding are enforced.
5. ``passed`` mandatory checks must have verifiable on-disk artifacts.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from .digest import canonical_json, is_digest, sha256_hex
from .models import CheckRequirement, CheckStatus, EvidenceBundle
from .planner import plan_checks
from .runner import ArtifactStore


def compute_policy_digest(policy: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(policy))


def compute_bundle_digest(bundle: EvidenceBundle) -> str:
    payload = bundle.model_dump(mode="json", exclude={"bundle_digest", "created_at"})
    return sha256_hex(canonical_json(payload))


@dataclass(frozen=True)
class DecisionResult:
    decision: str
    reasons: tuple[str, ...]
    mandatory_checks_total: int
    mandatory_checks_satisfied: int
    blocking_gaps: int
    nonblocking_gaps: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def decide(
    bundle: EvidenceBundle,
    catalog: dict[str, Any],
    policy: dict[str, Any],
    artifact_store: ArtifactStore | None = None,
) -> DecisionResult:
    """Apply the documented precedence: BLOCK > INCOMPLETE > WARN > PASS."""
    reasons: list[str] = []
    checks_by_id = {check.check_id: check for check in bundle.checks}
    catalog_specs = {spec.get("check_id"): spec for spec in catalog.get("checks", [])}
    hard_block = False
    incomplete = False
    warning = False

    # 1. Policy identity must match the trusted policy file.
    expected_policy_digest = compute_policy_digest(policy)
    if bundle.policy_digest.strip() != expected_policy_digest:
        incomplete = True
        reasons.append(
            "Bundle policy digest does not match the loaded policy file; "
            "the decision cannot be version-bound to a trusted policy."
        )
    if bundle.policy_id != policy.get("policy_id") or bundle.policy_version != policy.get("version"):
        incomplete = True
        reasons.append("Bundle policy_id/version does not match the loaded policy file.")

    # 2. Bundle self-integrity.  A bundle with an EMPTY digest was never
    # sealed, so the tamper check cannot be skipped by stripping the digest:
    # an unsealed bundle is INCOMPLETE (cannot prove integrity), never PASS.
    if not bundle.bundle_digest or not bundle.bundle_digest.strip():
        incomplete = True
        reasons.append(
            "Bundle has no sealed digest; it was never sealed, so its integrity cannot be proven."
        )
    elif bundle.bundle_digest != compute_bundle_digest(bundle):
        incomplete = True
        reasons.append("Bundle digest mismatch: the bundle was modified after it was sealed.")

    # 3. Catalog integrity binding is required, not optional. Omitting the
    # digest must not disable the consistency check.
    expected_catalog_digest = sha256_hex(canonical_json(catalog))
    if not bundle.check_catalog_digest or not bundle.check_catalog_digest.strip():
        incomplete = True
        reasons.append("Bundle has no check-catalog digest; catalog/version binding cannot be proven.")
    elif bundle.check_catalog_digest != expected_catalog_digest:
        incomplete = True
        reasons.append("Check catalog changed after the plan was created; results are not comparable.")

    # 4. Derive the expected check selection from the trusted catalog and the
    # recorded change kinds. Do not accept a bundle that simply deletes a
    # conditional check and edits required_check_ids to match.
    if not any(spec.get("requirement") in ("mandatory", "conditional")
               for spec in catalog_specs.values()):
        incomplete = True
        reasons.append(
            "Check catalog declares no mandatory or conditional checks; "
            "there is no enforcement floor, so a PASS would be vacuous."
        )

    required_ids: set[str] = set()
    expected_check_ids: set[str] | None = None
    plan = bundle.plan
    if not isinstance(plan, dict):
        incomplete = True
        reasons.append("Bundle has no validation plan; expected checks cannot be independently re-derived.")
    else:
        changed_kinds = plan.get("changed_asset_kinds")
        budget_seconds = plan.get("budget_seconds")
        impact = plan.get("impact") if isinstance(plan.get("impact"), dict) else {}
        unknown_critical = impact.get("unknown_critical_impact", False)
        if (not isinstance(changed_kinds, list)
                or any(not isinstance(kind, str) for kind in changed_kinds)
                or isinstance(budget_seconds, bool)
                or not isinstance(budget_seconds, (int, float))
                or budget_seconds < 0
                or not isinstance(unknown_critical, bool)):
            incomplete = True
            reasons.append("Bundle validation plan has invalid changed kinds, budget, or impact metadata.")
        else:
            expected_plan = plan_checks(
                changed_kinds=set(changed_kinds),
                catalog=catalog,
                budget_seconds=float(budget_seconds),
                unknown_critical_impact=unknown_critical,
            )
            selected = expected_plan.get("selected_checks", [])
            expected_check_ids = {item["check_id"] for item in selected}
            required_ids = {
                item["check_id"] for item in selected
                if item.get("effective_requirement") == "mandatory"
            }
            actual_ids = set(checks_by_id)
            missing_from_bundle = sorted(expected_check_ids - actual_ids)
            unexpected_in_bundle = sorted(actual_ids - expected_check_ids)
            if missing_from_bundle:
                incomplete = True
                reasons.append("Planned checks missing from bundle: " + ", ".join(missing_from_bundle))
            if unexpected_in_bundle:
                incomplete = True
                reasons.append("Bundle contains checks not selected by the trusted plan: " + ", ".join(unexpected_in_bundle))
            if set(bundle.required_check_ids) != required_ids:
                incomplete = True
                reasons.append("Bundle required_check_ids do not match the checks derived from the trusted catalog and plan.")

    for check in bundle.checks:
        spec = catalog_specs.get(check.check_id)
        if spec is None:
            incomplete = True
            reasons.append(f"Check '{check.check_id}' is not in the version-controlled catalog.")
            continue
        catalog_requirement = spec.get("requirement", "optional")
        if check.requirement.value != catalog_requirement:
            incomplete = True
            reasons.append(
                f"Check '{check.check_id}' declares requirement '{check.requirement.value}' "
                f"but the catalog says '{catalog_requirement}'."
            )

    missing_required = sorted(required_ids - set(checks_by_id))
    if missing_required:
        incomplete = True
        reasons.append("Required checks missing from bundle: " + ", ".join(missing_required))

    mandatory_total = len(required_ids)
    mandatory_satisfied = 0

    # Every status of PASSED, including optional checks, must carry real proof.
    # Optional controls cannot smuggle a success claim without provenance.
    proof_failures: dict[str, str] = {}
    for check in bundle.checks:
        if check.status != CheckStatus.PASSED:
            continue
        proof_fields_present = (
            check.exit_code == 0
            and check.duration_ms is not None
            and is_digest(check.input_digest)
            and is_digest(check.environment_digest)
            and bool(check.artifact_refs)
            and set(check.artifact_digests) == set(check.artifact_refs)
            and all(is_digest(check.artifact_digests.get(ref)) for ref in check.artifact_refs)
        )
        if not proof_fields_present:
            incomplete = True
            proof_failures[check.check_id] = "missing or malformed execution proof/digests"
            reasons.append(f"Check marked passed lacks complete execution proof: {check.check_id}")
            continue
        if artifact_store is None:
            incomplete = True
            proof_failures[check.check_id] = "artifact store not supplied; on-disk proof was not verified"
            reasons.append(f"Check marked passed cannot be verified without an artifact store: {check.check_id}")
            continue
        verified, artifact_problem = _verify_artifacts(check.artifact_refs, check.artifact_digests, artifact_store)
        if not verified:
            incomplete = True
            proof_failures[check.check_id] = artifact_problem
            reasons.append(f"Check '{check.check_id}' artifact verification failed: {artifact_problem}")

    for check_id in sorted(required_ids):
        check = checks_by_id.get(check_id)
        if check is None:
            continue
        if check.status == CheckStatus.FAILED:
            hard_block = True
            reasons.append(f"Mandatory check failed: {check_id}")
            continue
        if check.status != CheckStatus.PASSED:
            incomplete = True
            reasons.append(f"Mandatory check is not proven passed: {check_id} ({check.status.value})")
            continue
        if check_id in proof_failures:
            incomplete = True
            continue
        mandatory_satisfied += 1

    # 5. Evidence freshness and revision binding.
    for record in bundle.evidence:
        if record.freshness == "stale":
            incomplete = True
            reasons.append(f"Evidence {record.evidence_id} is stale ({record.evidence_type}).")
        elif record.freshness == "unknown":
            warning = True
            reasons.append(f"Evidence {record.evidence_id} has unknown freshness ({record.evidence_type}).")
        if record.observed_revision and record.observed_revision != bundle.change.head_revision:
            incomplete = True
            reasons.append(
                f"Evidence {record.evidence_id} was observed at {record.observed_revision[:12]}, "
                f"not at head revision {bundle.change.head_revision[:12]}."
            )

    # 6. Optional checks must stay visible.
    for check in bundle.checks:
        if check.requirement != CheckRequirement.OPTIONAL:
            continue
        if check.status in (
            CheckStatus.FAILED, CheckStatus.ERROR, CheckStatus.TIMED_OUT,
            CheckStatus.UNSUPPORTED, CheckStatus.NOT_RUN, CheckStatus.PLANNED,
        ):
            warning = True
            reasons.append(f"Optional check did not provide a clean pass: {check.check_id} ({check.status.value})")

    # 7. Coverage gaps.
    blocking_gaps = [g for g in bundle.coverage_gaps if g.blocking or g.required]
    nonblocking_gaps = [g for g in bundle.coverage_gaps if not (g.blocking or g.required)]
    if blocking_gaps:
        incomplete = True
        reasons.extend(f"Required evidence gap: {g.gap_id} ({g.kind})" for g in blocking_gaps)
    if nonblocking_gaps:
        warning = True
        reasons.extend(f"Non-blocking evidence gap: {g.gap_id} ({g.kind})" for g in nonblocking_gaps)

    for finding in bundle.policy_findings:
        reasons.append(f"Policy {finding.action}: {finding.rule_id} — {finding.summary}")
        if finding.action == "BLOCK":
            hard_block = True
        else:
            warning = True

    if hard_block:
        decision = "BLOCK"
    elif incomplete:
        decision = "INCOMPLETE"
    elif warning:
        decision = "WARN"
    else:
        decision = "PASS"
        reasons.append("All required checks passed and no blocking or warning evidence gaps remain.")

    return DecisionResult(
        decision=decision,
        reasons=tuple(dict.fromkeys(reasons)),
        mandatory_checks_total=mandatory_total,
        mandatory_checks_satisfied=mandatory_satisfied,
        blocking_gaps=len(blocking_gaps),
        nonblocking_gaps=len(nonblocking_gaps),
    )


def _verify_artifacts(
    refs: list[str], digests: dict[str, str], store: ArtifactStore
) -> tuple[bool, str]:
    if not refs:
        return False, "no artifact references were recorded"
    if set(digests) != set(refs):
        return False, "artifact refs and digest keys do not match exactly"
    for ref in refs:
        status = store.verify(ref, digests.get(ref))
        if status == "missing_digest":
            return False, f"artifact digest missing or malformed: {ref[:80]}"
        if status == "missing":
            return False, f"artifact missing on disk: {ref[:80]}"
        if status == "mismatch":
            return False, f"artifact digest mismatch: {ref[:80]}"
    return True, ""
