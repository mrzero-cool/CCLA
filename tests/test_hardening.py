"""Hardening tests: forged bundles, tampered requirements, stale evidence, artifacts."""
from datetime import datetime, timezone

from clca.digest import canonical_json, sha256_hex
from clca.models import (
    ChangeSet, EvidenceBundle, EvidenceRecord, ValidationCheck,
    CheckRequirement, CheckStatus,
)
from clca.policy import compute_bundle_digest, compute_policy_digest, decide
from clca.bundle import compute_sealed_digest
from clca.planner import plan_checks
from clca.runner import ArtifactStore

POLICY = {"policy_id": "default-pr-policy", "version": "0.2.0"}
CATALOG = {"checks": [{"check_id": "unit", "requirement": "mandatory", "triggers": ["*"], "estimated_seconds": 1}]}
HEAD = "b" * 40


def make_bundle(**overrides) -> EvidenceBundle:
    defaults = dict(
        change=ChangeSet(
            change_id="hardening-run",
            repository="demo/retail",
            base_revision="a" * 40,
            head_revision=HEAD,
            diff_digest="sha256:" + "1" * 64,
            created_at=datetime.now(timezone.utc),
        ),
        policy_digest=compute_policy_digest(POLICY),
        check_catalog_digest=sha256_hex(canonical_json(CATALOG)),
        policy_id=POLICY["policy_id"],
        policy_version=POLICY["version"],
        plan={**plan_checks(set(), CATALOG, 60), "impact": {"unknown_critical_impact": False}},
        required_check_ids=["unit"],
    )
    defaults.update(overrides)
    bundle = EvidenceBundle(**defaults)
    # Seal unless the test explicitly set a digest (e.g. a forged/empty one):
    # a well-formed bundle always carries a digest, and decide() treats a
    # missing digest as an unsealed bundle (INCOMPLETE). Tests that exercise
    # digest-mismatch paths override bundle_digest after this call.
    if not bundle.bundle_digest:
        bundle.bundle_digest = compute_bundle_digest(bundle)
    return bundle


def passing_check() -> ValidationCheck:
    return ValidationCheck(
        check_id="unit", category="unit", requirement=CheckRequirement.MANDATORY,
        status=CheckStatus.PASSED, exit_code=0, duration_ms=12,
        input_digest="sha256:" + "a" * 64,
        environment_digest="sha256:" + "b" * 64,
        artifact_refs=["artifact://run/unit.0.json"],
        artifact_digests={"artifact://run/unit.0.json": sha256_hex(b"proof")},
    )


def test_policy_digest_mismatch_is_incomplete():
    tampered = make_bundle(policy_digest="sha256:" + "d" * 64)
    result = decide(tampered, CATALOG, POLICY)
    assert result.decision == "INCOMPLETE"
    assert any("policy digest" in r.lower() for r in result.reasons)


def test_forged_bundle_digest_is_detected():
    bundle = make_bundle(checks=[passing_check()])
    bundle.bundle_digest = compute_bundle_digest(bundle)
    # Attacker flips the status after sealing but keeps the old digest.
    bundle.checks[0].status = CheckStatus.PASSED
    bundle.checks[0].exit_code = 0
    forged = "sha256:" + "e" * 64
    bundle.bundle_digest = forged
    result = decide(bundle, CATALOG, POLICY)
    assert result.decision == "INCOMPLETE"
    assert any("digest mismatch" in r.lower() for r in result.reasons)


def test_requirement_downgrade_in_bundle_is_detected():
    # The bundle calls the mandatory check "optional"; the catalog disagrees.
    bundle = make_bundle(
        checks=[ValidationCheck(
            check_id="unit", category="unit", requirement=CheckRequirement.OPTIONAL,
            status=CheckStatus.PASSED, exit_code=0, duration_ms=1,
            input_digest="sha256:" + "a" * 64, environment_digest="sha256:" + "b" * 64,
            artifact_refs=["artifact://run/unit.0.json"],
        )]
    )
    result = decide(bundle, CATALOG, POLICY)
    assert result.decision == "INCOMPLETE"
    assert any("declares requirement" in r for r in result.reasons)


def test_unknown_check_id_cannot_sneak_into_required():
    bundle = make_bundle(required_check_ids=["not-in-catalog"])
    result = decide(bundle, CATALOG, POLICY)
    assert result.decision == "INCOMPLETE"


def test_stale_evidence_blocks_pass():
    bundle = make_bundle(
        checks=[passing_check()],
        evidence=[EvidenceRecord(
            evidence_id="ev:stale", producer_name="dbt-manifest", producer_version="0.3.0",
            evidence_type="dbt_manifest", support="derived", freshness="stale",
            observed_revision=HEAD,
        )],
    )
    result = decide(bundle, CATALOG, POLICY)
    assert result.decision == "INCOMPLETE"
    assert any("stale" in r.lower() for r in result.reasons)


def test_evidence_from_another_revision_is_invalidated():
    bundle = make_bundle(
        checks=[passing_check()],
        evidence=[EvidenceRecord(
            evidence_id="ev:old", producer_name="python-ast", producer_version="0.3.0",
            evidence_type="python_ast_index", support="derived", freshness="current",
            observed_revision="f" * 40,
        )],
    )
    result = decide(bundle, CATALOG, POLICY)
    assert result.decision == "INCOMPLETE"
    assert any("not at head revision" in r for r in result.reasons)


def test_missing_artifact_on_disk_is_incomplete(tmp_path):
    store = ArtifactStore(tmp_path)
    result = decide(make_bundle(checks=[passing_check()]), CATALOG, POLICY, store)
    assert result.decision == "INCOMPLETE"
    assert any("artifact missing" in r for r in result.reasons)


def test_artifact_digest_mismatch_is_incomplete(tmp_path):
    store = ArtifactStore(tmp_path)
    store.write("run", "unit.0", {"hello": "world"})
    result = decide(make_bundle(checks=[passing_check()]), CATALOG, POLICY, store)
    # The digest recorded in the check does not match the on-disk content.
    assert result.decision == "INCOMPLETE"
    assert any("digest mismatch" in r for r in result.reasons)


def test_verified_artifact_allows_pass(tmp_path):
    store = ArtifactStore(tmp_path)
    ref, digest = store.write("run", "unit.0", {"hello": "world"})
    check = passing_check()
    check.artifact_refs = [ref]
    check.artifact_digests = {ref: digest}
    result = decide(make_bundle(checks=[check]), CATALOG, POLICY, store)
    assert result.decision == "PASS"


def test_artifact_store_sanitizes_untrusted_run_id(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    ref, digest = store.write("../../outside", "unit", {"safe": True})
    assert ref.startswith("artifact://")
    assert ".." not in ref.split("artifact://", 1)[1].split("/", 1)[0]
    assert (store.root / ref.split("artifact://", 1)[1]).is_file()
    assert store.verify(ref, digest) == "ok"


def test_missing_artifact_digest_is_not_verified(tmp_path):
    store = ArtifactStore(tmp_path)
    ref, _digest = store.write("run", "unit", {"hello": "world"})
    assert store.verify(ref, None) == "missing_digest"


def test_missing_catalog_digest_cannot_be_used_as_a_downgrade():
    bundle = make_bundle(checks=[passing_check()], check_catalog_digest=None)
    bundle.bundle_digest = compute_bundle_digest(bundle)
    result = decide(bundle, CATALOG, POLICY)
    assert result.decision == "INCOMPLETE"
    assert any("no check-catalog digest" in reason for reason in result.reasons)
