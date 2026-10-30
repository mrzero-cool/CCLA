"""semctx adapter — TypeScript Git diff → exported contracts → deterministic verdict.

semctx maps TypeScript Git diffs to exported contracts, declared rules and tests,
then issues a deterministic PASS/WARN/BLOCK verdict. Runs locally without an LLM
or network service — direct overlap with a deterministic change gate.

This adapter reads semctx's verdict export (JSON) and normalizes it into UCEM:
verdict evidence, contract assets, rule findings, and coverage gaps.

If the semctx export is unavailable, returns an empty result with a coverage gap.
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

logger = logging.getLogger("clca.adapters.semctx")

_RISK_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

_VERDICT_MAP: dict[str, str] = {
    "pass": "PASS",
    "warn": "WARN",
    "block": "BLOCK",
    "ready_to_ship": "PASS",
    "needs_review": "WARN",
    "blocked": "BLOCK",
}

_KIND_MAP: dict[str, AssetKind] = {
    "contract": AssetKind.DATA_MODEL,
    "exported_contract": AssetKind.DATA_MODEL,
    "rule": AssetKind.CODE_FUNCTION,
    "test": AssetKind.TEST_CHECK,
    "function": AssetKind.CODE_FUNCTION,
    "class": AssetKind.CODE_CLASS,
    "api_route": AssetKind.API_ENDPOINT,
}


class SemctxAdapter(Adapter):
    """Reads semctx verdict export and normalizes to UCEM."""

    name = "semctx"
    version = "0.4.0"

    def __init__(self, export_path: Path | str | None = None) -> None:
        self.export_path = Path(export_path) if export_path else None

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()

        if self.export_path is None or not self.export_path.is_file():
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:semctx:missing",
                    kind="unsupported_asset",
                    severity="medium",
                    subject_refs=[manifest.head_revision],
                    why_it_matters="semctx verdict export not found; deterministic "
                    "change-gate verdict evidence incomplete.",
                    blocking=False,
                    required=False,
                    remediation="Run semctx analysis and point --semctx-export at "
                    "the output JSON file.",
                )
            )
            return result

        try:
            data = json.loads(self.export_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("semctx export unreadable: %s", exc)
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:semctx:unreadable",
                    kind="runner_unavailable",
                    severity="high",
                    subject_refs=[manifest.head_revision],
                    why_it_matters=f"semctx export could not be parsed: {exc}",
                    blocking=False,
                    required=False,
                    remediation="Re-run semctx analysis and verify JSON validity.",
                )
            )
            return result

        # semctx report structure (simplified):
        # {
        #   "verdict": "PASS",
        #   "confidence": 0.85,
        #   "contracts": [...],
        #   "declared_rules": [...],
        #   "tests": [...],
        #   "findings": [...]
        # }
        verdict = str(data.get("verdict", "UNKNOWN")).upper()
        confidence = float(data.get("confidence", 0.0))
        contracts = data.get("contracts", [])
        declared_rules = data.get("declared_rules", [])
        tests = data.get("tests", [])
        findings = data.get("findings", [])

        # Contracts as assets
        for contract in contracts:
            contract_id = str(contract.get("id") or contract.get("name") or "")
            if not contract_id:
                continue
            kind = _KIND_MAP.get(str(contract.get("type", "contract")).lower(), AssetKind.DATA_MODEL)
            asset = Asset(
                asset_id=f"semctx:{contract_id}",
                kind=kind,
                name=str(contract.get("name") or contract_id),
                repository=manifest.repository,
                path=str(contract.get("path") or ""),
                revision=manifest.head_revision,
                criticality="high" if verdict == "BLOCK" else "medium",
                identity_status="adapter_scoped",
                attributes={
                    "source": "semctx",
                    "original_type": contract.get("type"),
                    "exported": contract.get("exported", False),
                    "declared_rules": contract.get("declared_rules", []),
                },
            )
            result.assets.append(asset)

        # Declared rules as assets + relationships to contracts
        for rule in declared_rules:
            rule_id = str(rule.get("id") or rule.get("name") or "")
            if not rule_id:
                continue
            asset = Asset(
                asset_id=f"semctx:rule:{rule_id}",
                kind=AssetKind.CODE_FUNCTION,
                name=str(rule.get("name") or rule_id),
                repository=manifest.repository,
                path=str(rule.get("path") or ""),
                revision=manifest.head_revision,
                criticality="high",
                identity_status="adapter_scoped",
                attributes={
                    "source": "semctx",
                    "rule_type": rule.get("rule_type"),
                    "severity": rule.get("severity", "medium"),
                },
            )
            result.assets.append(asset)

            # Relationship: rule governs contract
            for contract in contracts:
                contract_id = str(contract.get("id") or contract.get("name") or "")
                if contract_id and rule.get("applies_to") == contract_id:
                    rel = Relationship(
                        relationship_id=relationship_id(
                            f"semctx:rule:{rule_id}", f"semctx:{contract_id}", "validated_by"
                        ),
                        source_asset_id=f"semctx:rule:{rule_id}",
                        target_asset_id=f"semctx:{contract_id}",
                        relation_type="validated_by",  # type: ignore[arg-type]
                        impact_direction="forward",
                        resolution="resolved",
                        provenance_refs=["semctx"],
                        observed_revision=manifest.head_revision,
                        limitations=["Deterministic rule-contract mapping from semctx"],
                    )
                    result.relationships.append(rel)

        # Findings -> coverage gaps (blocking if BLOCK verdict)
        for finding in findings:
            severity = _RISK_SEVERITY.get(str(finding.get("severity", "medium")).lower(), "medium")
            result.gaps.append(
                CoverageGap(
                    gap_id=f"gap:semctx:finding:{digest_obj([str(finding)])[7:15]}",
                    kind="unsupported_asset",
                    severity=severity,  # type: ignore[arg-type]
                    subject_refs=[str(finding.get("contract", finding.get("id", "")))],
                    why_it_matters=str(
                        finding.get("description") or finding.get("message") or "Deterministic finding"
                    ),
                    blocking=verdict == "BLOCK" or severity in ("critical", "high"),
                    required=False,
                    remediation=str(finding.get("remediation") or "Address the semctx finding."),
                )
            )

        # Evidence: deterministic verdict
        input_digest = digest_obj(
            [str(self.export_path), manifest.head_revision, verdict, str(confidence)]
        )
        result.evidence.append(
            make_evidence(
                adapter="semctx",
                evidence_type="deterministic_change_verdict",
                subject_refs=[manifest.head_revision],
                observed_revision=manifest.head_revision,
                input_digest=input_digest,
                support="direct",
                limitations=[
                    "semctx runs locally without LLM or network service",
                    "TypeScript/JavaScript scope only; no code execution",
                ],
            )
        )

        result.facts["semctx_verdict"] = verdict
        result.facts["semctx_confidence"] = confidence
        result.facts["semctx_contracts"] = len(contracts)
        result.facts["semctx_declared_rules"] = len(declared_rules)
        result.facts["semctx_tests"] = len(tests)
        result.facts["semctx_findings"] = len(findings)
        return result


def load_semctx_adapter(export_path: Path | str | None = None) -> SemctxAdapter:
    return SemctxAdapter(export_path=export_path)
