from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from clca.digest import canonical_json, sha256_hex
from clca.bundle import compute_sealed_digest
from clca.models import (
    ChangeSet, CoverageGap, EvidenceBundle, PolicyFinding,
    ValidationCheck, CheckRequirement, CheckStatus,
)
from clca.policy import decide
from clca.planner import plan_checks
from clca.runner import ArtifactStore

POLICY = {
    "policy_id": "default-pr-policy",
    "version": "0.2.0",
    "agent_policy": {"new_write_tool_requires_review": True},
}
POLICY_DIGEST = sha256_hex(canonical_json(POLICY))

CATALOG = {
    "checks": [
        {"check_id": "unit", "requirement": "mandatory", "triggers": ["code.function"], "estimated_seconds": 1},
        {"check_id": "contract-check", "requirement": "conditional", "triggers": ["data.column"], "estimated_seconds": 1},
        {"check_id": "optional-extra", "requirement": "optional", "triggers": ["*"], "estimated_seconds": 1000},
    ]
}


def bundle(checks=None, required=None, gaps=None, findings=None, policy=POLICY,
           changed_kinds=None, budget=60):
    changed_kinds = changed_kinds if changed_kinds is not None else ["code.function"]
    plan = plan_checks(set(changed_kinds), CATALOG, budget_seconds=budget)
    required_from_plan = sorted(
        item["check_id"] for item in plan["selected_checks"]
        if item.get("effective_requirement") == "mandatory"
    )
    plan["impact"] = {"unknown_critical_impact": False}
    b = EvidenceBundle(
        policy_digest=sha256_hex(canonical_json(policy)),
        check_catalog_digest=sha256_hex(canonical_json(CATALOG)),
        change=ChangeSet(
            change_id="test-run-1",
            repository="demo/retail-assurance",
            base_revision="a" * 40,
            head_revision="b" * 40,
            diff_digest="sha256:" + "c" * 64,
            created_at=datetime.now(timezone.utc),
        ),
        checks=checks or [],
        required_check_ids=required if required is not None else required_from_plan,
        coverage_gaps=gaps or [],
        policy_findings=findings or [],
        policy_id=policy["policy_id"],
        policy_version=policy["version"],
        plan=plan,
    )
    b.bundle_digest = compute_sealed_digest(b)
    return b


def evaluate(b, catalog=CATALOG, policy=POLICY):
    """Attach real test artifacts so positive-path policy tests can prove PASS."""
    with TemporaryDirectory(prefix="clca-policy-test-") as root:
        store = ArtifactStore(Path(root))
        for item in b.checks:
            if item.status == CheckStatus.PASSED:
                ref, digest = store.write("test-run", item.check_id, {"check_id": item.check_id, "exit_code": 0})
                item.artifact_refs = [ref]
                item.artifact_digests = {ref: digest}
        b.bundle_digest = compute_sealed_digest(b)
        return decide(b, catalog, policy, store)


def check(check_id="unit", status=CheckStatus.PASSED, requirement=CheckRequirement.MANDATORY):
    return ValidationCheck(
        check_id=check_id,
        category="unit",
        requirement=requirement,
        status=status,
        exit_code=0 if status == CheckStatus.PASSED else (1 if status == CheckStatus.FAILED else None),
        duration_ms=20 if status == CheckStatus.PASSED else None,
        input_digest="sha256:" + "a" * 64 if status == CheckStatus.PASSED else None,
        environment_digest="sha256:" + "b" * 64 if status == CheckStatus.PASSED else None,
        artifact_refs=["artifact://test/unit.json"] if status == CheckStatus.PASSED else [],
    )


def test_pass_only_when_mandatory_check_passes_and_no_gaps():
    result = evaluate(bundle(checks=[check()]))
    assert result.decision == "PASS"


def test_failed_mandatory_check_blocks():
    result = evaluate(bundle(checks=[check(status=CheckStatus.FAILED)]))
    assert result.decision == "BLOCK"


def test_missing_required_check_is_incomplete_not_pass():
    result = decide(bundle(required=["contract-check"]), CATALOG, POLICY)
    assert result.decision == "INCOMPLETE"


def test_required_gap_is_incomplete():
    gap = CoverageGap(
        gap_id="missing-lineage",
        kind="missing_lineage",
        severity="critical",
        why_it_matters="A critical downstream table may be unknown.",
        blocking=True,
        required=True,
    )
    result = evaluate(bundle(checks=[check()], gaps=[gap]))
    assert result.decision == "INCOMPLETE"


def test_block_precedes_incomplete():
    gap = CoverageGap(
        gap_id="missing-lineage",
        kind="missing_lineage",
        severity="critical",
        why_it_matters="Unresolved dependency.",
        blocking=True,
        required=True,
    )
    finding = PolicyFinding(rule_id="DENIED_TOOL_GRANT", action="BLOCK", summary="New prohibited write tool.")
    result = evaluate(bundle(checks=[check()], gaps=[gap], findings=[finding]))
    assert result.decision == "BLOCK"


def test_nonblocking_gap_produces_warn():
    gap = CoverageGap(
        gap_id="optional-docs",
        kind="unsupported_asset",
        severity="low",
        why_it_matters="Documentation-only relationship not parsed.",
        blocking=False,
        required=False,
    )
    result = evaluate(bundle(checks=[check()], gaps=[gap]))
    assert result.decision == "WARN"


def test_nonpassed_mandatory_check_is_incomplete_unless_failed():
    result = evaluate(bundle(checks=[check(status=CheckStatus.TIMED_OUT)]))
    assert result.decision == "INCOMPLETE"


def test_passed_status_without_execution_proof_is_incomplete():
    invalidly_claimed_pass = ValidationCheck(
        check_id="unit", category="unit", requirement=CheckRequirement.MANDATORY,
        status=CheckStatus.PASSED,
    )
    result = decide(bundle(checks=[invalidly_claimed_pass]), CATALOG, POLICY)
    assert result.decision == "INCOMPLETE"


def test_optional_check_that_was_not_run_produces_warn_not_silence():
    result = evaluate(bundle(
        checks=[check(), check("optional-extra", CheckStatus.NOT_RUN, CheckRequirement.OPTIONAL)],
        budget=2000,
    ))
    assert result.decision == "WARN"


def test_unsealed_bundle_without_digest_is_incomplete_not_pass():
    """CT-3a: `bundle_digest` empty means the tamper check never ran at all.

    A bundle that carries no sealed digest cannot prove it was not edited
    after sealing, so it must never be able to reach PASS.  The old code
    guarded the check with `if bundle.bundle_digest and ...`, which silently
    SKIPPED integrity verification for an unsealed (empty-digest) bundle and
    let it pass.
    """
    b = bundle(checks=[check()])
    b.bundle_digest = ""  # unsealed: no digest recorded at sealing time
    result = decide(b, CATALOG, POLICY)
    assert result.decision == "INCOMPLETE", result.reasons
    assert any("digest" in r.lower() for r in result.reasons)


def test_empty_catalog_is_incomplete_not_vacuous_pass():
    """CT-3b: an empty check catalog must not produce a vacuous PASS.

    With `catalog == {"checks": []}` there are no specs, so `required_ids`
    stays empty, `mandatory_total == 0`, and every guard passes vacuously —
    the decision fell through to PASS with zero required checks satisfied.
    An empty catalog means the gate has no rules to enforce, which is
    INCOMPLETE (cannot prove), never PASS.
    """
    empty_catalog = {"checks": []}
    result = decide(bundle(checks=[check()]), empty_catalog, POLICY)
    assert result.decision == "INCOMPLETE", result.reasons
    # The vacuous case the audit reproduced (`clca run --catalog '{}'`):
    # NO bundle checks AND an empty catalog must also refuse to PASS.
    result = decide(bundle(checks=[]), empty_catalog, POLICY)
    assert result.decision == "INCOMPLETE", result.reasons


def test_catalog_without_any_mandatory_checks_is_incomplete_not_pass():
    """CT-3b edge: catalog has checks but none mandatory/conditional.

    A catalog that declares only optional checks provides no enforcement
    floor, so a PASS would again be vacuous (nothing was required to pass).
    """
    optional_only = {"checks": [{"check_id": "unit", "requirement": "optional"}]}
    result = decide(bundle(checks=[check(requirement=CheckRequirement.OPTIONAL)]),
                    optional_only, POLICY)
    assert result.decision == "INCOMPLETE", result.reasons


def test_missing_catalog_digest_is_incomplete_even_with_valid_bundle_digest():
    b = bundle(checks=[check()])
    b.check_catalog_digest = None
    b.bundle_digest = compute_sealed_digest(b)
    result = evaluate(b)
    assert result.decision == "INCOMPLETE"
    assert any("no check-catalog digest" in reason for reason in result.reasons)


def test_plan_rederivation_detects_deleted_triggered_check_and_tampered_required_ids():
    # A data.column change must select both the wildcard static check and the
    # conditional contract check. Removing them and clearing required IDs must
    # not let a self-consistent but weakened bundle pass.
    b = bundle(checks=[], required=[], changed_kinds=["data.column"])
    b.required_check_ids = []
    b.bundle_digest = compute_sealed_digest(b)
    result = evaluate(b)
    assert result.decision == "INCOMPLETE"
    assert any("planned checks missing from bundle" in reason.lower() for reason in result.reasons)
    assert any("required_check_ids" in reason for reason in result.reasons)


def test_optional_pass_without_artifact_proof_is_incomplete():
    from tempfile import TemporaryDirectory
    from pathlib import Path
    from clca.runner import ArtifactStore

    mandatory = check()
    optional = ValidationCheck(
        check_id="optional-extra", category="quality", requirement=CheckRequirement.OPTIONAL,
        status=CheckStatus.PASSED, exit_code=0, duration_ms=5,
        input_digest="sha256:" + "a" * 64, environment_digest="sha256:" + "b" * 64,
        artifact_refs=[], artifact_digests={},
    )
    b = bundle(checks=[mandatory, optional], budget=2000)
    with TemporaryDirectory(prefix="clca-policy-test-") as root:
        store = ArtifactStore(Path(root))
        ref, digest = store.write("test-run", "unit", {"check_id": "unit", "exit_code": 0})
        mandatory.artifact_refs = [ref]
        mandatory.artifact_digests = {ref: digest}
        b.bundle_digest = compute_sealed_digest(b)
        result = decide(b, CATALOG, POLICY, store)
    assert result.decision == "INCOMPLETE"
    assert any("optional-extra" in reason and "proof" in reason.lower() for reason in result.reasons)
