"""Enola adapter — cross-repository software system graph.

Enola analyzes modules, functions, API routes, database interactions and messaging
topics across repositories, exposing a broad system graph.  This adapter reads
Enola's graph export (JSON) and normalizes it into CLCA's UCEM: assets, cross-repo
relationships (CONSUMES, EXPOSES, DEPLOYED_AS, OWNS), and evidence records.

If the Enola export is unavailable, returns an empty result with a coverage gap.
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

logger = logging.getLogger("clca.adapters.enola")

_KIND_MAP: dict[str, AssetKind] = {
    "module": AssetKind.CODE_FUNCTION,
    "function": AssetKind.CODE_FUNCTION,
    "class": AssetKind.CODE_CLASS,
    "api_route": AssetKind.API_ENDPOINT,
    "endpoint": AssetKind.API_ENDPOINT,
    "database": AssetKind.DATA_TABLE,
    "table": AssetKind.DATA_TABLE,
    "topic": AssetKind.BUSINESS_METRIC,
    "service": AssetKind.DEPLOYMENT_CONFIG,
    "owner": AssetKind.DEPLOYMENT_CONFIG,
}

_RELATION_MAP: dict[str, str] = {
    "calls": "calls",
    "imports": "imports",
    "consumes": "consumes",
    "exposes": "exposes",
    "deployed_as": "deployed_as",
    "deployed_to": "deployed_as",
    "owned_by": "owns",
    "owns": "owns",
    "reads_from": "reads_from",
    "writes_to": "writes_to",
}


class EnolaAdapter(Adapter):
    """Reads Enola graph output and normalizes to UCEM."""

    name = "enola"
    version = "0.4.0"

    def __init__(self, export_path: Path | str | None = None) -> None:
        self.export_path = Path(export_path) if export_path else None

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()

        if self.export_path is None or not self.export_path.is_file():
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:enola:missing",
                    kind="unsupported_asset",
                    severity="medium",
                    subject_refs=[manifest.head_revision],
                    why_it_matters="Enola system graph export not found; "
                    "cross-repository dependency evidence will be incomplete.",
                    blocking=False,
                    required=False,
                    remediation="Run Enola export and point --enola-export at the "
                    "output JSON file.",
                )
            )
            return result

        try:
            data = json.loads(self.export_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Enola export unreadable: %s", exc)
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:enola:unreadable",
                    kind="runner_unavailable",
                    severity="high",
                    subject_refs=[manifest.head_revision],
                    why_it_matters=f"Enola graph export could not be parsed: {exc}",
                    blocking=False,
                    required=False,
                    remediation="Re-run Enola export and verify JSON validity.",
                )
            )
            return result

        nodes = data.get("nodes", data.get("elements", []))
        edges = data.get("edges", data.get("relationships", []))

        for node in nodes:
            node_id = str(node.get("id") or node.get("key") or "")
            if not node_id:
                continue
            kind = _KIND_MAP.get(str(node.get("kind", "")).lower(), AssetKind.CODE_FUNCTION)
            asset = Asset(
                asset_id=f"enola:{node_id}",
                kind=kind,
                name=str(node.get("label") or node.get("name") or node_id),
                repository=str(node.get("repository") or manifest.repository),
                path=str(node.get("path") or ""),
                revision=manifest.head_revision,
                criticality="unknown",
                identity_status="adapter_scoped",
                attributes={
                    "source": "enola",
                    "original_kind": node.get("kind"),
                    "repository": node.get("repository"),
                    "metadata": node.get("metadata", {}),
                },
            )
            result.assets.append(asset)

        for edge in edges:
            source = str(edge.get("source") or edge.get("from") or "")
            target = str(edge.get("target") or edge.get("to") or "")
            rel_type = _RELATION_MAP.get(str(edge.get("kind", "")).lower(), "calls")
            if not source or not target:
                continue
            rel = Relationship(
                relationship_id=relationship_id(
                    f"enola:{source}", f"enola:{target}", rel_type
                ),
                source_asset_id=f"enola:{source}",
                target_asset_id=f"enola:{target}",
                relation_type=rel_type,  # type: ignore[arg-type]
                impact_direction="forward",
                resolution="resolved",
                provenance_refs=["enola"],
                observed_revision=manifest.head_revision,
                limitations=["cross-repository graph; depends on Enola export freshness"],
            )
            result.relationships.append(rel)

        input_digest = digest_obj(
            [str(self.export_path), manifest.head_revision, str(len(nodes)), str(len(edges))]
        )
        result.evidence.append(
            make_evidence(
                adapter="enola",
                evidence_type="system_graph_snapshot",
                subject_refs=[manifest.head_revision],
                observed_revision=manifest.head_revision,
                input_digest=input_digest,
                support="derived",
                limitations=[
                    "Graph freshness depends on last Enola export run",
                    "Cross-repository edges may span outside the change scope",
                ],
            )
        )

        result.facts["enola_node_count"] = len(nodes)
        result.facts["enola_edge_count"] = len(edges)
        return result


def load_enola_adapter(export_path: Path | str | None = None) -> EnolaAdapter:
    return EnolaAdapter(export_path=export_path)
