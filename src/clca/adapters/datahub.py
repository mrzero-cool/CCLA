"""DataHub/OpenLineage adapter — data lineage and catalog integration.

DataHub and OpenMetadata provide upstream/downstream data lineage across datasets,
dashboards and catalog assets. OpenLineage is a protocol for collecting job, run and
dataset lineage metadata.  This adapter reads lineage export (JSON) and normalizes
it into UCEM: data.table, data.column, data.metric assets with READS_TABLE,
WRITES_TABLE, DERIVES_FROM relationships, plus freshness evidence.

If the lineage export is unavailable, returns an empty result with a coverage gap.
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

logger = logging.getLogger("clca.adapters.datahub")

_KIND_MAP: dict[str, AssetKind] = {
    "table": AssetKind.DATA_TABLE,
    "view": AssetKind.DATA_TABLE,
    "column": AssetKind.DATA_COLUMN,
    "dataset": AssetKind.DATA_TABLE,
    "dashboard": AssetKind.BUSINESS_METRIC,
    "metric": AssetKind.BUSINESS_METRIC,
    "ml_model": AssetKind.AI_MODEL_BINDING,
    "container": AssetKind.DATA_TABLE,
    "topic": AssetKind.DATA_TABLE,
    "pipeline": AssetKind.DEPLOYMENT_CONFIG,
}

_RELATION_MAP: dict[str, str] = {
    "reads_from": "reads_from",
    "writes_to": "writes_to",
    "derived_from": "transforms_to",
    "transforms_to": "transforms_to",
    "lineage": "reads_from",
    "upstream": "reads_from",
    "downstream": "writes_to",
    "depends_on": "reads_from",
}


class DataHubAdapter(Adapter):
    """Reads DataHub/OpenLineage lineage export and normalizes to UCEM."""

    name = "datahub"
    version = "0.4.0"

    def __init__(self, export_path: Path | str | None = None) -> None:
        self.export_path = Path(export_path) if export_path else None

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()

        if self.export_path is None or not self.export_path.is_file():
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:datahub:missing",
                    kind="missing_lineage",
                    severity="medium",
                    subject_refs=[manifest.head_revision],
                    why_it_matters="Data lineage export not found; data-layer "
                    "impact analysis will lack upstream/downstream evidence.",
                    blocking=False,
                    required=False,
                    remediation="Run DataHub/OpenLineage lineage export and point "
                    "--datahub-export at the output JSON file.",
                )
            )
            return result

        try:
            data = json.loads(self.export_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("DataHub export unreadable: %s", exc)
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:datahub:unreadable",
                    kind="runner_unavailable",
                    severity="high",
                    subject_refs=[manifest.head_revision],
                    why_it_matters=f"DataHub lineage export could not be parsed: {exc}",
                    blocking=False,
                    required=False,
                    remediation="Re-run DataHub/OpenLineage export and verify JSON validity.",
                )
            )
            return result

        entities = data.get("entities", data.get("nodes", []))
        relationships = data.get("relationships", data.get("edges", []))

        for entity in entities:
            entity_id = str(entity.get("id") or entity.get("key") or "")
            if not entity_id:
                continue
            kind = _KIND_MAP.get(str(entity.get("type", "")).lower(), AssetKind.DATA_TABLE)
            freshness = str(entity.get("freshness", "unknown")).lower()
            if freshness not in ("current", "stale", "unknown"):
                freshness = "unknown"

            asset = Asset(
                asset_id=f"datahub:{entity_id}",
                kind=kind,
                name=str(entity.get("name") or entity.get("label") or entity_id),
                repository=str(entity.get("platform") or manifest.repository),
                path=str(entity.get("qualified_name") or entity.get("path") or ""),
                revision=manifest.head_revision,
                criticality="unknown",
                identity_status="adapter_scoped",
                attributes={
                    "source": "datahub",
                    "original_type": entity.get("type"),
                    "platform": entity.get("platform"),
                    "env": entity.get("env"),
                    "freshness": freshness,
                    "custom_properties": entity.get("custom_properties", {}),
                },
            )
            result.assets.append(asset)

            if freshness == "stale":
                result.gaps.append(
                    CoverageGap(
                        gap_id=f"gap:datahub:{entity_id}:stale",
                        kind="stale_evidence",
                        severity="medium",
                        subject_refs=[f"datahub:{entity_id}"],
                        why_it_matters=f"Lineage entity '{entity_id}' has stale "
                        "freshness; downstream impact may be based on outdated metadata.",
                        blocking=False,
                        required=False,
                        remediation="Refresh DataHub metadata for this entity.",
                    )
                )

        for rel in relationships:
            source = str(rel.get("source") or rel.get("from") or "")
            target = str(rel.get("target") or rel.get("to") or "")
            rel_type = _RELATION_MAP.get(str(rel.get("type", "")).lower(), "reads_from")
            if not source or not target:
                continue
            rel_obj = Relationship(
                relationship_id=relationship_id(
                    f"datahub:{source}", f"datahub:{target}", rel_type
                ),
                source_asset_id=f"datahub:{source}",
                target_asset_id=f"datahub:{target}",
                relation_type=rel_type,  # type: ignore[arg-type]
                impact_direction="forward",
                resolution="resolved",
                provenance_refs=["datahub"],
                observed_revision=manifest.head_revision,
                limitations=["Data lineage depends on DataHub/OpenLineage freshness"],
            )
            result.relationships.append(rel_obj)

        input_digest = digest_obj(
            [str(self.export_path), manifest.head_revision, str(len(entities)), str(len(relationships))]
        )
        result.evidence.append(
            make_evidence(
                adapter="datahub",
                evidence_type="data_lineage_snapshot",
                subject_refs=[manifest.head_revision],
                observed_revision=manifest.head_revision,
                input_digest=input_digest,
                support="derived",
                limitations=[
                    "Lineage freshness depends on last DataHub/OpenLineage export run",
                    "Only cataloged entities are represented",
                ],
            )
        )

        result.facts["datahub_entity_count"] = len(entities)
        result.facts["datahub_relationship_count"] = len(relationships)
        return result


def load_datahub_adapter(export_path: Path | str | None = None) -> DataHubAdapter:
    return DataHubAdapter(export_path=export_path)
