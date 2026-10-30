"""Adapter contract: every adapter returns normalized UCEM evidence plus gaps."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..digest import digest_obj
from ..intake import ChangeManifest
from ..models import Asset, CoverageGap, EvidenceRecord, Relationship

_ADAPTER_VERSION = "0.4.0"


@dataclass
class AdapterResult:
    assets: list[Asset] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    gaps: list[CoverageGap] = field(default_factory=list)
    # Extra structured facts consumed by the policy-rule evaluator
    # (e.g. the parsed agent tool manifest for privilege-diff rules).
    facts: dict[str, object] = field(default_factory=dict)

    def extend(self, other: "AdapterResult") -> None:
        self.assets.extend(other.assets)
        self.relationships.extend(other.relationships)
        self.evidence.extend(other.evidence)
        self.gaps.extend(other.gaps)
        self.facts.update(other.facts)


class Adapter(Protocol):
    name: str

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult: ...


def relationship_id(source: str, target: str, relation_type: str) -> str:
    return "rel:" + digest_obj([source, target, relation_type])[7:19]


def make_evidence(
    adapter: str,
    evidence_type: str,
    subject_refs: list[str],
    observed_revision: str,
    input_digest: str,
    limitations: list[str] | None = None,
    support: str = "derived",
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=f"ev:{adapter}:{digest_obj([evidence_type, subject_refs, input_digest])[7:19]}",
        producer_name=adapter,
        producer_version=_ADAPTER_VERSION,
        evidence_type=evidence_type,
        subject_refs=subject_refs,
        observed_revision=observed_revision,
        input_digest=input_digest,
        support=support,  # type: ignore[arg-type]
        freshness="current",
        limitations=limitations or [],
    )
