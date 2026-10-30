"""AxiomCode Graph adapter — compiler-grounded code impact and test selection.

AxiomCode maps callers, callees, implementation paths and tests using compiler or
type-checker ground truth.  This adapter reads AxiomCode's graph export (JSON) and
normalizes it into CLCA's UCEM (Unified Change Evidence Model): assets, relationships
(CALLS, IMPORTS, IMPLEMENTS, VALIDATED_BY), and evidence records.

If the AxiomCode export is unavailable, the adapter returns an empty result with a
coverage gap so the planner can treat missing code-graph data as INCOMPLETE rather
than guessing.
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

logger = logging.getLogger("clca.adapters.axiomcode")

# AxiomCode node kind -> CLCA asset kind
_KIND_MAP: dict[str, AssetKind] = {
    "function": AssetKind.CODE_FUNCTION,
    "class": AssetKind.CODE_CLASS,
    "method": AssetKind.CODE_FUNCTION,
    "module": AssetKind.CODE_FUNCTION,  # closest approximation
    "file": AssetKind.CODE_FUNCTION,
    "test": AssetKind.TEST_CHECK,
    "api_endpoint": AssetKind.API_ENDPOINT,
    "component": AssetKind.CODE_CLASS,
}

# AxiomCode edge kind -> CLCA relationship type
_RELATION_MAP: dict[str, str] = {
    "calls": "calls",
    "call": "calls",
    "imports": "imports",
    "import": "imports",
    "implements": "implements",
    "implementation": "implements",
    "extends": "implements",
    "references": "uses_prompt",
    "tests": "validated_by",
    "tested_by": "validated_by",
    "validates": "validated_by",
}


class AxiomCodeAdapter(Adapter):
    """Reads AxiomCode graph output and normalizes to UCEM."""

    name = "axiomcodegraph"
    version = "0.4.0"

    def __init__(self, export_path: Path | str | None = None) -> None:
        self.export_path = Path(export_path) if export_path else None

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()

        if self.export_path is None or not self.export_path.is_file():
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:axiomcodegraph:missing",
                    kind="unsupported_asset",
                    severity="medium",
                    subject_refs=[manifest.head_revision],
                    why_it_matters="AxiomCode graph export not found; code impact "
                    "resolution will fall back to native Python AST adapter.",
                    blocking=False,
                    required=False,
                    remediation="Run AxiomCode graph export and point --axiomcode-export "
                    "at the output JSON file.",
                )
            )
            return result

        try:
            data = json.loads(self.export_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("AxiomCode export unreadable: %s", exc)
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:axiomcodegraph:unreadable",
                    kind="runner_unavailable",
                    severity="high",
                    subject_refs=[manifest.head_revision],
                    why_it_matters=f"AxiomCode graph export could not be parsed: {exc}",
                    blocking=False,
                    required=False,
                    remediation="Re-run AxiomCode export and verify JSON validity.",
                )
            )
            return result

        nodes = data.get("nodes", data.get("elements", []))
        edges = data.get("edges", data.get("relationships", []))

        asset_index: dict[str, Asset] = {}

        for node in nodes:
            node_id = str(node.get("id") or node.get("key") or "")
            if not node_id:
                continue
            kind = _KIND_MAP.get(str(node.get("kind", "")).lower(), AssetKind.CODE_FUNCTION)
            asset = Asset(
                asset_id=f"axiom:{node_id}",
                kind=kind,
                name=str(node.get("label") or node.get("name") or node_id),
                repository=manifest.repository,
                path=str(node.get("path") or ""),
                revision=manifest.head_revision,
                criticality="unknown",
                identity_status="adapter_scoped",
                attributes={
                    "source": "axiomcodegraph",
                    "original_kind": node.get("kind"),
                    "file": node.get("file"),
                    "line": node.get("line"),
                },
            )
            asset_index[node_id] = asset
            result.assets.append(asset)

        for edge in edges:
            source = str(edge.get("source") or edge.get("from") or "")
            target = str(edge.get("target") or edge.get("to") or "")
            rel_type = _RELATION_MAP.get(str(edge.get("kind", "")).lower(), "calls")
            if not source or not target:
                continue
            rel = Relationship(
                relationship_id=relationship_id(
                    f"axiom:{source}", f"axiom:{target}", rel_type
                ),
                source_asset_id=f"axiom:{source}",
                target_asset_id=f"axiom:{target}",
                relation_type=rel_type,  # type: ignore[arg-type]
                impact_direction="forward",
                resolution="resolved",
                provenance_refs=["axiomcodegraph"],
                observed_revision=manifest.head_revision,
                limitations=["compiler-grounded; depends on AxiomCode export freshness"],
            )
            result.relationships.append(rel)

        # Evidence: graph snapshot itself
        input_digest = digest_obj(
            [str(self.export_path), manifest.head_revision, str(len(nodes)), str(len(edges))]
        )
        result.evidence.append(
            make_evidence(
                adapter="axiomcodegraph",
                evidence_type="code_graph_snapshot",
                subject_refs=[manifest.head_revision],
                observed_revision=manifest.head_revision,
                input_digest=input_digest,
                support="derived",
                limitations=[
                    "Graph freshness depends on last AxiomCode export run",
                    "Only assets present in export are represented",
                ],
            )
        )

        result.facts["axiomcodegraph_node_count"] = len(nodes)
        result.facts["axiomcodegraph_edge_count"] = len(edges)
        return result


def load_axiomcode_adapter(export_path: Path | str | None = None) -> AxiomCodeAdapter:
    """Factory for the AxiomCode adapter."""
    return AxiomCodeAdapter(export_path=export_path)
