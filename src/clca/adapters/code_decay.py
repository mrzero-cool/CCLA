"""CodeDecay adapter — AI-generated change safety and regression-risk detection.

CodeDecay detects potential regressions, weak test evidence, maintainability
issues and affected product areas. It supports deterministic analysis, optional
configured checks, local probes and developer-agent integrations.

This adapter reads CodeDecay's regression-risk export (JSON) and normalizes it into
UCEM: regression risk evidence, weak-test areas, maintainability findings, and
coverage gaps for high-risk changes.

If the CodeDecay export is unavailable, returns an empty result with a coverage gap.
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

logger = logging.getLogger("clca.adapters.code_decay")

_RISK_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

_KIND_MAP: dict[str, AssetKind] = {
    "function": AssetKind.CODE_FUNCTION,
    "class": AssetKind.CODE_CLASS,
    "module": AssetKind.CODE_FUNCTION,
    "file": AssetKind.CODE_FUNCTION,
    "area": AssetKind.CODE_FUNCTION,
    "product_area": AssetKind.CODE_FUNCTION,
    "test": AssetKind.TEST_CHECK,
    "weak_test": AssetKind.TEST_CHECK,
}


class CodeDecayAdapter(Adapter):
    """Reads CodeDecay regression-risk export and normalizes to UCEM."""

    name = "code_decay"
    version = "0.4.0"

    def __init__(self, export_path: Path | str | None = None) -> None:
        self.export_path = Path(export_path) if export_path else None

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()

        if self.export_path is None or not self.export_path.is_file():
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:code_decay:missing",
                    kind="unsupported_asset",
                    severity="medium",
                    subject_refs=[manifest.head_revision],
                    why_it_matters="CodeDecay regression-risk export not found; "
                    "AI-generated change safety evidence incomplete.",
                    blocking=False,
                    required=False,
                    remediation="Run CodeDecay regression analysis and point "
                    "--code-decay-export at the output JSON file.",
                )
            )
            return result

        try:
            data = json.loads(self.export_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("CodeDecay export unreadable: %s", exc)
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:code_decay:unreadable",
                    kind="runner_unavailable",
                    severity="high",
                    subject_refs=[manifest.head_revision],
                    why_it_matters=f"CodeDecay export could not be parsed: {exc}",
                    blocking=False,
                    required=False,
                    remediation="Re-run CodeDecay regression analysis and verify JSON validity.",
                )
            )
            return result

        # CodeDecay report structure (simplified):
        # {
        #   "regression_risk_score": 0.68,
        #   "risk_level": "high",
        #   "planted_issues_detected": 5,
        #   "false_positive_rate": 0.022,
        #   "affected_areas": [...],
        #   "weak_test_areas": [...],
        #   "maintainability_issues": [...],
        #   "regressions": [...]
        # }
        risk_score = float(data.get("regression_risk_score", 0.0))
        risk_level = str(data.get("risk_level", "unknown")).lower()
        planted_issues = int(data.get("planted_issues_detected", 0))
        false_positive_rate = float(data.get("false_positive_rate", 0.0))
        affected_areas = data.get("affected_areas", [])
        weak_test_areas = data.get("weak_test_areas", [])
        maintainability_issues = data.get("maintainability_issues", [])
        regressions = data.get("regressions", [])

        # Affected areas as assets
        for area in affected_areas:
            area_id = str(area.get("id") or area.get("name") or "")
            if not area_id:
                continue
            kind = _KIND_MAP.get(str(area.get("type", "area")).lower(), AssetKind.CODE_FUNCTION)
            asset = Asset(
                asset_id=f"code_decay:{area_id}",
                kind=kind,
                name=str(area.get("name") or area_id),
                repository=manifest.repository,
                path=str(area.get("path") or ""),
                revision=manifest.head_revision,
                criticality=_risk_to_criticality(risk_level),
                identity_status="adapter_scoped",
                attributes={
                    "source": "code_decay",
                    "original_type": area.get("type"),
                    "risk_contribution": area.get("risk_contribution", 0.0),
                    "change_type": area.get("change_type"),
                },
            )
            result.assets.append(asset)

        # Weak test areas -> coverage gaps
        for wta in weak_test_areas:
            result.gaps.append(
                CoverageGap(
                    gap_id=f"gap:code_decay:weak_test:{digest_obj([str(wta)])[7:15]}",
                    kind="missing_required_test",
                    severity="medium",
                    subject_refs=[str(wta.get("area", wta.get("id", "")))],
                    why_it_matters=str(
                        wta.get("description") or wta.get("message") or "Weak test evidence detected"
                    ),
                    blocking=False,
                    required=True,
                    remediation=str(wta.get("remediation") or "Strengthen test coverage in this area."),
                )
            )

        # Maintainability issues -> coverage gaps
        for mi in maintainability_issues:
            severity = _RISK_SEVERITY.get(str(mi.get("severity", "medium")).lower(), "medium")
            result.gaps.append(
                CoverageGap(
                    gap_id=f"gap:code_decay:maint:{digest_obj([str(mi)])[7:15]}",
                    kind="unsupported_asset",
                    severity=severity,  # type: ignore[arg-type]
                    subject_refs=[str(mi.get("area", mi.get("id", "")))],
                    why_it_matters=str(mi.get("description") or mi.get("message") or "Maintainability issue"),
                    blocking=severity in ("critical", "high"),
                    required=False,
                    remediation=str(mi.get("remediation") or "Address the maintainability issue."),
                )
            )

        # Regressions -> coverage gaps (blocking)
        for reg in regressions:
            severity = _RISK_SEVERITY.get(str(reg.get("severity", "high")).lower(), "high")
            result.gaps.append(
                CoverageGap(
                    gap_id=f"gap:code_decay:regression:{digest_obj([str(reg)])[7:15]}",
                    kind="missing_required_test",
                    severity=severity,  # type: ignore[arg-type]
                    subject_refs=[str(reg.get("area", reg.get("id", "")))],
                    why_it_matters=str(reg.get("description") or reg.get("message") or "Potential regression detected"),
                    blocking=severity in ("critical", "high"),
                    required=True,
                    remediation=str(reg.get("remediation") or "Add regression test before merging."),
                )
            )

        # Evidence: regression risk score
        input_digest = digest_obj(
            [str(self.export_path), manifest.head_revision, str(risk_score), str(planted_issues)]
        )
        result.evidence.append(
            make_evidence(
                adapter="code_decay",
                evidence_type="regression_risk_assessment",
                subject_refs=[manifest.head_revision],
                observed_revision=manifest.head_revision,
                input_digest=input_digest,
                support="derived",
                limitations=[
                    "CodeDecay reported 23/23 planted issues on its own benchmark; "
                    "enterprise-scale generalization not independently verified",
                    "False-positive rate may vary by repository",
                ],
            )
        )

        result.facts["code_decay_regression_risk_score"] = risk_score
        result.facts["code_decay_risk_level"] = risk_level
        result.facts["code_decay_planted_issues_detected"] = planted_issues
        result.facts["code_decay_false_positive_rate"] = false_positive_rate
        result.facts["code_decay_affected_areas"] = len(affected_areas)
        result.facts["code_decay_weak_test_areas"] = len(weak_test_areas)
        result.facts["code_decay_regressions"] = len(regressions)
        return result


def _risk_to_criticality(risk_level: str) -> str:
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "unknown": "unknown",
    }
    return mapping.get(risk_level, "unknown")


def load_code_decay_adapter(export_path: Path | str | None = None) -> CodeDecayAdapter:
    return CodeDecayAdapter(export_path=export_path)
