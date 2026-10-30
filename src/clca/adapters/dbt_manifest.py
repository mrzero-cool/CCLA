"""dbt-style lineage adapter.

Ingests a checked-in ``manifest.json`` (declared models, dependencies, columns)
and cross-checks it against SQL files found in the repository. A changed SQL
model with no manifest entry is a coverage gap, never an implicit "no dependency".
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..digest import digest_text
from ..intake import ChangeManifest
from ..models import Asset, CoverageGap, Relationship
from .base import AdapterResult, make_evidence, relationship_id

_MANIFEST_CANDIDATES = ("data/dbt/manifest.json", "dbt/manifest.json", "manifest.json")
_SQL_REF = re.compile(r"\b(?:from|join)\s+([a-zA-Z_][\w.]*)(?![\w.]*\()", re.IGNORECASE)


class DbtManifestAdapter:
    name = "dbt-manifest"

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()
        manifest_path = self._find_manifest(repo)
        nodes: dict[str, dict] = {}

        if manifest_path is None:
            sql_files = self._sql_files(repo)
            if sql_files:
                result.gaps.append(CoverageGap(
                    gap_id="gap-dbt-manifest-missing",
                    kind="missing_lineage",
                    severity="high",
                    subject_refs=sorted(sql_files),
                    why_it_matters="SQL models exist without a declared lineage manifest; downstream impact cannot be established.",
                    blocking=True,
                    required=True,
                    remediation="Check in a dbt manifest.json or accept the promoted full-suite fallback.",
                ))
            return result

        raw = manifest_path.read_text(encoding="utf-8")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            result.gaps.append(CoverageGap(
                gap_id="gap-dbt-manifest-invalid",
                kind="missing_lineage",
                severity="high",
                subject_refs=[manifest_path.relative_to(repo).as_posix()],
                why_it_matters=f"dbt manifest could not be parsed ({exc.msg}); lineage is unknown.",
                blocking=True, required=True,
            ))
            return result

        rel_manifest = manifest_path.relative_to(repo).as_posix()
        nodes = document.get("nodes", {}) if isinstance(document, dict) else {}
        sources = document.get("sources", {}) if isinstance(document, dict) else {}

        for node_id, node in {**nodes, **sources}.items():
            if not isinstance(node, dict):
                continue
            resource = node.get("resource_type", "model")
            if resource not in ("model", "source"):
                continue
            kind = "data.model" if resource == "model" else "data.table"
            asset_id = f"dbt:{node_id}"
            node_path = self._repo_relative_path(repo, manifest_path, node)
            declaring_file = manifest_path.relative_to(repo).as_posix()
            result.assets.append(Asset(
                asset_id=asset_id, kind=kind, name=node.get("name", node_id),
                path=node_path, revision=manifest.head_revision,
                criticality="high" if resource == "model" else "medium",
                identity_status="stable",
                attributes={"dbt_resource_type": resource, "database": node.get("database"), "declared_by": declaring_file},
            ))
            for column in (node.get("columns") or {}):
                column_id = f"{asset_id}.col.{column}"
                result.assets.append(Asset(
                    asset_id=column_id, kind="data.column", name=column,
                    path=node_path, revision=manifest.head_revision,
                    criticality="medium", identity_status="stable",
                    attributes={"parent": asset_id, "declared_by": declaring_file},
                ))
                result.relationships.append(Relationship(
                    relationship_id=relationship_id(asset_id, column_id, "owns"),
                    source_asset_id=asset_id, target_asset_id=column_id,
                    relation_type="owns", impact_direction="forward",
                    resolution="resolved", observed_revision=manifest.head_revision,
                ))
            for upstream in (node.get("depends_on", {}) or {}).get("nodes", []) if isinstance(node.get("depends_on"), dict) else []:
                upstream_id = f"dbt:{upstream}"
                result.relationships.append(Relationship(
                    relationship_id=relationship_id(upstream_id, asset_id, "transforms_to"),
                    source_asset_id=upstream_id, target_asset_id=asset_id,
                    relation_type="transforms_to", impact_direction="forward",
                    resolution="resolved", observed_revision=manifest.head_revision,
                ))

        # Cross-check: every SQL model file should be declared in the manifest.
        declared_paths = {
            (node.get("path") or "")
            for node in {**nodes, **sources}.values() if isinstance(node, dict)
        }
        for sql_rel in self._sql_files(repo):
            suffix = sql_rel.split("models/")[-1] if "models/" in sql_rel else sql_rel
            if not any(declared.endswith(suffix) or suffix.endswith(declared) for declared in declared_paths if declared):
                result.gaps.append(CoverageGap(
                    gap_id=f"gap-undeclared-sql:{sql_rel}",
                    kind="missing_lineage",
                    severity="high",
                    subject_refs=[sql_rel],
                    why_it_matters="A SQL model file is not declared in the lineage manifest; its consumers are unknown.",
                    blocking=True, required=True,
                    remediation="Add the model to the dbt manifest or declare the omission in excluded_paths.",
                ))

        # Literal table references from SQL bodies (optional enrichment).
        for node_id, node in nodes.items():
            if not isinstance(node, dict) or node.get("resource_type") != "model":
                continue
            raw_code = node.get("raw_code", "")
            for ref in _SQL_REF.findall(raw_code):
                ref_id = f"sql-ref:{ref}"
                if not any(a.asset_id == ref_id for a in result.assets):
                    result.assets.append(Asset(
                        asset_id=ref_id, kind="data.table", name=ref,
                        revision=manifest.head_revision, criticality="unknown",
                        identity_status="provisional",
                        attributes={"source": "sql_literal_reference"},
                    ))
                result.relationships.append(Relationship(
                    relationship_id=relationship_id(ref_id, f"dbt:{node_id}", "reads_from"),
                    source_asset_id=f"dbt:{node_id}", target_asset_id=ref_id,
                    relation_type="reads_from", impact_direction="forward",
                    resolution="inferred", observed_revision=manifest.head_revision,
                    limitations=["Literal SQL reference; dynamic/templated SQL is not resolved."],
                ))

        result.evidence.append(make_evidence(
            self.name, "dbt_manifest", sorted(nodes) + sorted(sources),
            manifest.head_revision, digest_text(raw),
            limitations=["Lineage limited to the checked-in manifest snapshot."],
        ))
        result.facts["dbt_nodes"] = sorted(nodes)
        return result

    @staticmethod
    def _repo_relative_path(repo: Path, manifest_path: Path, node: dict) -> str:
        """dbt ``path`` fields are relative to the dbt project root (manifest dir)."""
        node_path = node.get("path")
        if node_path:
            candidate = (manifest_path.parent / str(node_path)).resolve()
            if candidate.is_relative_to(repo):
                return candidate.relative_to(repo).as_posix()
        return manifest_path.relative_to(repo).as_posix()

    @staticmethod
    def _find_manifest(repo: Path) -> Path | None:
        for candidate in _MANIFEST_CANDIDATES:
            path = repo / "data" / "dbt" / candidate if not candidate.startswith(("data/", "dbt/")) else repo / candidate
            if candidate == "manifest.json":
                path = repo / "data" / "dbt" / "manifest.json"
            if path.is_file():
                return path
        return None

    @staticmethod
    def _sql_files(repo: Path) -> list[str]:
        from ..digest import iter_files

        return [
            p.relative_to(repo).as_posix()
            for p in iter_files(repo)
            if p.suffix.lower() == ".sql"
        ]
