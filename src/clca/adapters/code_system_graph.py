"""Code System Graph adapter — cross-repository contracts and dependency mapping.

Code System Graph connects APIs, events, schemas, packages, databases, deployments,
tests, owners and documentation. It exposes graph context through MCP and tracks
evidence, freshness, confidence and incomplete coverage areas.  It does not stage
changes, run tests, commit, push or merge — exactly CLCA's execution layer's input.

This adapter reads Code System Graph's JSON/MCP export and normalizes it into UCEM:
assets, relationships with confidence/freshness/provenance, and coverage gaps for
incomplete areas.
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

logger = logging.getLogger("clca.adapters.code_system_graph")

_KIND_MAP: dict[str, AssetKind] = {
    "api": AssetKind.API_ENDPOINT,
    "endpoint": AssetKind.API_ENDPOINT,
    "schema": AssetKind.DATA_MODEL,
    "package": AssetKind.CODE_FUNCTION,
    "database": AssetKind.DATA_TABLE,
    "table": AssetKind.DATA_TABLE,
    "deployment": AssetKind.DEPLOYMENT_CONFIG,
    "owner": AssetKind.DEPLOYMENT_CONFIG,
    "test": AssetKind.TEST_CHECK,
    "documentation": AssetKind.CODE_FUNCTION,
}

_RELATION_MAP: dict[str, str] = {
    "calls": "calls",
    "imports": "imports",
    "implements": "implements",
    "reads_from": "reads_from",
    "writes_to": "writes_to",
    "transforms_to": "transforms_to",
    "exposes": "exposes",
    "consumes": "consumes",
    "uses_prompt": "uses_prompt",
    "grants_tool": "grants_tool",
    "validated_by": "validated_by",
    "deployed_as": "deployed_as",
    "owns": "owns",
}


class CodeSystemGraphAdapter(Adapter):
    """Reads Code System Graph output and normalizes to UCEM."""

    name = "code_system_graph"
    version = "0.4.0"

    def __init__(self, export_path: Path | str | None = None) -> None:
        self.export_path = Path(export_path) if export_path else None

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()

        if self.export_path is None or not self.export_path.is_file():
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:code_system_graph:missing",
                    kind="unsupported_asset",
                    severity="medium",
                    subject_refs=[manifest.head_revision],
                    why_it_matters="Code System Graph export not found; "
                    "cross-repository contract and dependency evidence incomplete.",
                    blocking=False,
                    required=False,
                    remediation="Run Code System Graph export and point "
                    "--code-system-graph-export at the output JSON file.",
                )
            )
            return result

        try:
            data = json.loads(self.export_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Code System Graph export unreadable: %s", exc)
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:code_system_graph:unreadable",
                    kind="runner_unavailable",
                    severity="high",
                    subject_refs=[manifest.head_revision],
                    why_it_matters=f"Code System Graph export could not be parsed: {exc}",
                    blocking=False,
                    required=False,
                    remediation="Re-run Code System Graph export and verify JSON validity.",
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
            confidence = float(node.get("confidence", 0.5))
            freshness = str(node.get("freshness", "unknown")).lower()
            if freshness not in ("current", "stale", "unknown"):
                freshness = "unknown"

            asset = Asset(
                asset_id=f"csg:{node_id}",
                kind=kind,
                name=str(node.get("label") or node.get("name") or node_id),
                repository=str(node.get("repository") or manifest.repository),
                path=str(node.get("path") or ""),
                revision=manifest.head_revision,
                criticality="unknown",
                identity_status="adapter_scoped",
                attributes={
                    "source": "code_system_graph",
                    "original_kind": node.get("kind"),
                    "confidence": confidence,
                    "freshness": freshness,
                    "evidence_refs": node.get("evidence_refs", []),
                    "incomplete_areas": node.get("incomplete_areas", []),
                },
            )
            result.assets.append(asset)

            # Incomplete coverage areas become coverage gaps
            for area in node.get("incomplete_areas", []):
                result.gaps.append(
                    CoverageGap(
                        gap_id=f"gap:csg:{node_id}:{digest_obj([str(area)])[7:15]}",
                        kind="unresolved_dependency",
                        severity="medium",
                        subject_refs=[f"csg:{node_id}"],
                        why_it_matters=str(area),
                        blocking=False,
                        required=False,
                        remediation="Resolve the incomplete coverage area in "
                        "Code System Graph or add manual evidence.",
                    )
                )

        for edge in edges:
            source = str(edge.get("source") or edge.get("from") or "")
            target = str(edge.get("target") or edge.get("to") or "")
            rel_type = _RELATION_MAP.get(str(edge.get("kind", "")).lower(), "calls")
            confidence = float(edge.get("confidence", 0.5))
            if not source or not target:
                continue
            rel = Relationship(
                relationship_id=relationship_id(
                    f"csg:{source}", f"csg:{target}", rel_type
                ),
                source_asset_id=f"csg:{source}",
                target_asset_id=f"csg:{target}",
                relation_type=rel_type,  # type: ignore[arg-type]
                impact_direction="forward",
                resolution="resolved" if confidence > 0.5 else "inferred",
                provenance_refs=["code_system_graph"],
                observed_revision=manifest.head_revision,
                limitations=[
                    f"Confidence: {confidence:.2f}; "
                    "depends on Code System Graph export freshness",
                ],
            )
            result.relationships.append(rel)

        input_digest = digest_obj(
            [str(self.export_path), manifest.head_revision, str(len(nodes)), str(len(edges))]
        )
        result.evidence.append(
            make_evidence(
                adapter="code_system_graph",
                evidence_type="cross_repo_graph_snapshot",
                subject_refs=[manifest.head_revision],
                observed_revision=manifest.head_revision,
                input_digest=input_digest,
                support="derived",
                limitations=[
                    "Graph freshness depends on last Code System Graph export run",
                    "Edges below confidence threshold are marked inferred",
                ],
            )
        )

        result.facts["code_system_graph_node_count"] = len(nodes)
        result.facts["code_system_graph_edge_count"] = len(edges)
        result.facts["code_system_graph_gap_count"] = len(result.gaps)
        return result


def load_code_system_graph_adapter(
    export_path: Path | str | None = None,
) -> CodeSystemGraphAdapter:
    return CodeSystemGraphAdapter(export_path=export_path)
