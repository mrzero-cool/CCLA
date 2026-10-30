"""Farol adapter — PR risk scoring and review prioritization.

Farol calculates a PR risk score, maps changed code to affected entry points,
uses coverage information and highlights contract breaks and security findings.
It is intentionally static (review-assistance workflow, no code execution).

This adapter reads Farol's risk assessment export (JSON) and normalizes it into
UCEM: risk score evidence, affected entry-point assets, contract break findings,
and coverage gaps for unanalyzed areas.

If the Farol export is unavailable, returns an empty result with a coverage gap.
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

logger = logging.getLogger("clca.adapters.farol")

# Farol risk level -> CLCA severity mapping
_RISK_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
}

_KIND_MAP: dict[str, AssetKind] = {
    "entry_point": AssetKind.API_ENDPOINT,
    "api_route": AssetKind.API_ENDPOINT,
    "function": AssetKind.CODE_FUNCTION,
    "class": AssetKind.CODE_CLASS,
    "module": AssetKind.CODE_FUNCTION,
    "contract": AssetKind.DATA_MODEL,
    "security_finding": AssetKind.CODE_FUNCTION,
}


class FarolAdapter(Adapter):
    """Reads Farol PR risk export and normalizes to UCEM."""

    name = "farol"
    version = "0.4.0"

    def __init__(self, export_path: Path | str | None = None) -> None:
        self.export_path = Path(export_path) if export_path else None

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()

        if self.export_path is None or not self.export_path.is_file():
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:farol:missing",
                    kind="unsupported_asset",
                    severity="medium",
                    subject_refs=[manifest.head_revision],
                    why_it_matters="Farol risk assessment export not found; "
                    "PR risk scoring and review prioritization evidence incomplete.",
                    blocking=False,
                    required=False,
                    remediation="Run Farol PR risk analysis and point "
                    "--farol-export at the output JSON file.",
                )
            )
            return result

        try:
            data = json.loads(self.export_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Farol export unreadable: %s", exc)
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:farol:unreadable",
                    kind="runner_unavailable",
                    severity="high",
                    subject_refs=[manifest.head_revision],
                    why_it_matters=f"Farol risk export could not be parsed: {exc}",
                    blocking=False,
                    required=False,
                    remediation="Re-run Farol risk analysis and verify JSON validity.",
                )
            )
            return result

        # Farol report structure (simplified):
        # {
        #   "risk_score": 0.73,
        #   "risk_level": "high",
        #   "affected_entry_points": [
        #     {"id": "ep1", "type": "api_route", "path": "src/routes.py", "risk_contribution": 0.4}
        #   ],
        #   "contract_breaks": [...],
        #   "security_findings": [...],
        #   "coverage_info": {...}
        # }
        risk_score = float(data.get("risk_score", 0.0))
        risk_level = str(data.get("risk_level", "unknown")).lower()
        affected_eps = data.get("affected_entry_points", [])
        contract_breaks = data.get("contract_breaks", [])
        security_findings = data.get("security_findings", [])
        coverage_info = data.get("coverage_info", {})

        # Affected entry points as assets
        for ep in affected_eps:
            ep_id = str(ep.get("id") or ep.get("path") or "")
            if not ep_id:
                continue
            kind = _KIND_MAP.get(str(ep.get("type", "")).lower(), AssetKind.API_ENDPOINT)
            asset = Asset(
                asset_id=f"farol:{ep_id}",
                kind=kind,
                name=str(ep.get("name") or ep.get("label") or ep_id),
                repository=manifest.repository,
                path=str(ep.get("path") or ""),
                revision=manifest.head_revision,
                criticality=_risk_to_criticality(risk_level),
                identity_status="adapter_scoped",
                attributes={
                    "source": "farol",
                    "original_type": ep.get("type"),
                    "risk_contribution": ep.get("risk_contribution", 0.0),
                    "coverage_percentage": ep.get("coverage_percentage"),
                },
            )
            result.assets.append(asset)

            # Relationship: change -> affected entry point
            rel = Relationship(
                relationship_id=relationship_id(
                    f"change:{manifest.head_revision[:12]}", f"farol:{ep_id}", "affects"
                ),
                source_asset_id=f"change:{manifest.head_revision[:12]}",
                target_asset_id=f"farol:{ep_id}",
                relation_type="calls",  # closest semantic: change affects entry point
                impact_direction="forward",
                resolution="resolved",
                provenance_refs=["farol"],
                observed_revision=manifest.head_revision,
                limitations=[
                    f"Farol risk contribution: {ep.get('risk_contribution', 0.0):.2f}"
                ],
            )
            result.relationships.append(rel)

        # Contract breaks -> coverage gaps (blocking if high severity)
        for cb in contract_breaks:
            severity = _RISK_SEVERITY.get(str(cb.get("severity", "medium")).lower(), "medium")
            result.gaps.append(
                CoverageGap(
                    gap_id=f"gap:farol:contract:{digest_obj([str(cb)])[7:15]}",
                    kind="unresolved_dependency",
                    severity=severity,  # type: ignore[arg-type]
                    subject_refs=[f"farol:{cb.get('entry_point', cb.get('id', ''))}"],
                    why_it_matters=str(cb.get("description") or cb.get("message") or "Contract break detected"),
                    blocking=severity in ("critical", "high"),
                    required=False,
                    remediation=str(cb.get("remediation") or "Review and fix the contract break."),
                )
            )

        # Security findings -> coverage gaps
        for sf in security_findings:
            severity = _RISK_SEVERITY.get(str(sf.get("severity", "medium")).lower(), "medium")
            result.gaps.append(
                CoverageGap(
                    gap_id=f"gap:farol:security:{digest_obj([str(sf)])[7:15]}",
                    kind="unresolved_dependency",
                    severity=severity,  # type: ignore[arg-type]
                    subject_refs=[f"farol:{sf.get('entry_point', sf.get('id', ''))}"],
                    why_it_matters=str(sf.get("description") or sf.get("message") or "Security finding"),
                    blocking=severity in ("critical", "high"),
                    required=False,
                    remediation=str(sf.get("remediation") or "Address the security finding."),
                )
            )

        # Coverage info
        coverage_pct = coverage_info.get("percentage") or coverage_info.get("coverage")
        if coverage_pct is not None and float(coverage_pct) < 80.0:
            result.gaps.append(
                CoverageGap(
                    gap_id=f"gap:farol:coverage:{manifest.head_revision[:12]}",
                    kind="missing_required_test",
                    severity="medium",
                    subject_refs=[manifest.head_revision],
                    why_it_matters=f"Test coverage {float(coverage_pct):.0%} is below 80% threshold.",
                    blocking=False,
                    required=False,
                    remediation="Increase test coverage for affected areas.",
                )
            )

        # Evidence: risk score
        input_digest = digest_obj(
            [str(self.export_path), manifest.head_revision, str(risk_score), risk_level]
        )
        result.evidence.append(
            make_evidence(
                adapter="farol",
                evidence_type="pr_risk_assessment",
                subject_refs=[manifest.head_revision],
                observed_revision=manifest.head_revision,
                input_digest=input_digest,
                support="derived",
                limitations=[
                    "Farol is static analysis only; no code execution",
                    "Risk score depends on Farol's heuristic model",
                ],
            )
        )

        result.facts["farol_risk_score"] = risk_score
        result.facts["farol_risk_level"] = risk_level
        result.facts["farol_affected_entry_points"] = len(affected_eps)
        result.facts["farol_contract_breaks"] = len(contract_breaks)
        result.facts["farol_security_findings"] = len(security_findings)
        return result


def _risk_to_criticality(risk_level: str) -> str:
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "low",
        "unknown": "unknown",
    }
    return mapping.get(risk_level, "unknown")


def load_farol_adapter(export_path: Path | str | None = None) -> FarolAdapter:
    return FarolAdapter(export_path=export_path)
