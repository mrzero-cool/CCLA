"""Versioned domain models for Cross-Layer Change Assurance (CLCA) MVP."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AssetKind(str, Enum):
    CODE_FUNCTION = "code.function"
    CODE_CLASS = "code.class"
    API_ENDPOINT = "api.endpoint"
    DATA_TABLE = "data.table"
    DATA_COLUMN = "data.column"
    DATA_MODEL = "data.model"
    BUSINESS_METRIC = "business.metric"
    AI_AGENT = "ai.agent"
    AI_PROMPT = "ai.prompt"
    AI_MODEL_BINDING = "ai.model_binding"
    AI_TOOL = "ai.tool"
    AI_POLICY = "ai.policy"
    TEST_CHECK = "test.check"
    DEPLOYMENT_CONFIG = "deployment.config"


class Asset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1)
    kind: AssetKind
    name: str = Field(min_length=1)
    repository: str | None = None
    path: str | None = None
    revision: str | None = None
    criticality: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    identity_status: Literal["stable", "adapter_scoped", "provisional"] = "adapter_scoped"
    attributes: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relationship_id: str = Field(min_length=1)
    source_asset_id: str = Field(min_length=1)
    target_asset_id: str = Field(min_length=1)
    relation_type: Literal[
        "calls", "imports", "implements", "reads_from", "writes_to",
        "transforms_to", "exposes", "consumes", "uses_prompt", "uses_model",
        "grants_tool", "validated_by", "deployed_as", "owns"
    ]
    impact_direction: Literal["forward", "reverse", "both", "none"]
    resolution: Literal["resolved", "inferred", "ambiguous", "unresolved"]
    provenance_refs: list[str] = Field(default_factory=list)
    observed_revision: str | None = None
    limitations: list[str] = Field(default_factory=list)


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1)
    producer_name: str
    producer_version: str
    evidence_type: str
    subject_refs: list[str] = Field(default_factory=list)
    observed_at: datetime = Field(default_factory=utc_now)
    observed_revision: str | None = None
    input_digest: str | None = None
    artifact_digest: str | None = None
    artifact_ref: str | None = None
    support: Literal["direct", "derived", "heuristic", "manual"]
    freshness: Literal["current", "stale", "unknown"] = "unknown"
    limitations: list[str] = Field(default_factory=list)


class CheckStatus(str, Enum):
    PLANNED = "planned"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    TIMED_OUT = "timed_out"
    NOT_RUN = "not_run"
    SKIPPED_POLICY = "skipped_policy"
    UNSUPPORTED = "unsupported"


class CheckRequirement(str, Enum):
    MANDATORY = "mandatory"
    CONDITIONAL = "conditional"
    OPTIONAL = "optional"


class ValidationCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_id: str = Field(min_length=1)
    category: Literal["unit", "integration", "contract", "security", "agent_behavior", "quality", "performance", "manual"]
    requirement: CheckRequirement
    status: CheckStatus = CheckStatus.PLANNED
    command_ref: str | None = None
    selection_reason: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    artifact_refs: list[str] = Field(default_factory=list)
    artifact_digests: dict[str, str] = Field(default_factory=dict)
    input_digest: str | None = None
    environment_digest: str | None = None
    runner_image_digest: str | None = None
    stdout_excerpt: str | None = None


class CoverageGap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gap_id: str = Field(min_length=1)
    kind: Literal[
        "unresolved_dependency", "unsupported_asset", "missing_lineage", "stale_evidence",
        "missing_required_test", "check_not_run", "runner_unavailable", "insufficient_ai_trials",
        "unknown_policy", "probe_denied", "budget_exhausted", "flaky_baseline",
        "unversioned_source", "missing_baseline", "artifact_missing", "artifact_mismatch"
    ]
    severity: Literal["critical", "high", "medium", "low"]
    subject_refs: list[str] = Field(default_factory=list)
    why_it_matters: str
    # Prevents PASS; a missing/unknown fact normally yields INCOMPLETE rather than BLOCK.
    # Known hard policy violations belong in PolicyFinding(action="BLOCK").
    blocking: bool = False
    required: bool = False
    remediation: str | None = None


class PolicyFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    action: Literal["BLOCK", "WARN"]
    summary: str
    subject_refs: list[str] = Field(default_factory=list)


class ChangeSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    change_id: str
    repository: str
    base_revision: str
    head_revision: str
    diff_digest: str
    trigger: Literal["pull_request", "local_cli", "scheduled_recheck"] = "local_cli"
    created_at: datetime = Field(default_factory=utc_now)


class EvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "0.2.0"
    change: ChangeSet
    assets: list[Asset] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    checks: list[ValidationCheck] = Field(default_factory=list)
    required_check_ids: list[str] = Field(default_factory=list)
    coverage_gaps: list[CoverageGap] = Field(default_factory=list)
    policy_findings: list[PolicyFinding] = Field(default_factory=list)
    policy_id: str = "default-pr-policy"
    policy_version: str = "0.2.0"
    policy_digest: str = Field(min_length=1)
    check_catalog_digest: str | None = None
    artifact_root: str | None = None
    plan: dict[str, Any] | None = None
    adapters: list[dict[str, Any]] = Field(default_factory=list)
    decision: Literal["PASS", "WARN", "BLOCK", "INCOMPLETE"] | None = None
    bundle_digest: str | None = None
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def ensure_unique_ids(self) -> "EvidenceBundle":
        check_ids = [c.check_id for c in self.checks]
        if len(check_ids) != len(set(check_ids)):
            raise ValueError("check_id values must be unique within a bundle")
        asset_ids = [a.asset_id for a in self.assets]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("asset_id values must be unique within a bundle")
        return self
