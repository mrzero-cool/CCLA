"""AI agent configuration adapter.

Parses agent tool manifests (tools, access levels, model binding, policy flags)
and prompt files, and — when a baseline revision is available — records the
structured head-vs-base diff consumed by the privilege policy rules.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..digest import digest_text, iter_files
from ..intake import ChangeManifest, read_at_revision
from ..models import Asset, CoverageGap, Relationship
from .base import AdapterResult, make_evidence, relationship_id

_AGENT_GLOB = "agents"


class AgentConfigAdapter:
    name = "agent-config"

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()
        agents_root = repo / _AGENT_GLOB
        if not agents_root.is_dir():
            return result

        for agent_dir in sorted(p for p in agents_root.iterdir() if p.is_dir()):
            agent_name = agent_dir.name
            agent_id = f"agent:{agent_name}"
            manifest_path = agent_dir / "tool_manifest.json"

            result.assets.append(Asset(
                asset_id=agent_id, kind="ai.agent", name=agent_name,
                path=agent_dir.relative_to(repo).as_posix(), revision=manifest.head_revision,
                criticality="high", identity_status="stable",
            ))

            if manifest_path.is_file():
                self._collect_manifest(repo, manifest, agent_dir, agent_id, manifest_path, result)
            else:
                result.gaps.append(CoverageGap(
                    gap_id=f"gap-agent-manifest:{agent_name}",
                    kind="unsupported_asset",
                    severity="high", subject_refs=[agent_id],
                    why_it_matters="Agent directory has no tool manifest; its permissions cannot be verified.",
                    blocking=True, required=True,
                    remediation="Check in tool_manifest.json for every agent.",
                ))

            for prompt in sorted(agent_dir.rglob("*.md")):
                prompt_rel = prompt.relative_to(repo).as_posix()
                prompt_id = f"prompt:{agent_name}:{prompt.name}"
                result.assets.append(Asset(
                    asset_id=prompt_id, kind="ai.prompt", name=f"{agent_name} {prompt.stem} prompt",
                    path=prompt_rel, revision=manifest.head_revision,
                    criticality="high", identity_status="stable",
                ))
                result.relationships.append(Relationship(
                    relationship_id=relationship_id(agent_id, prompt_id, "uses_prompt"),
                    source_asset_id=agent_id, target_asset_id=prompt_id,
                    relation_type="uses_prompt", impact_direction="both",
                    resolution="resolved", observed_revision=manifest.head_revision,
                ))
                result.evidence.append(make_evidence(
                    self.name, "agent_prompt", [prompt_id], manifest.head_revision,
                    digest_text(prompt.read_text(encoding="utf-8")),
                ))

        return result

    def _collect_manifest(
        self, repo: Path, manifest: ChangeManifest, agent_dir: Path,
        agent_id: str, manifest_path: Path, result: AdapterResult,
    ) -> None:
        raw = manifest_path.read_text(encoding="utf-8")
        rel = manifest_path.relative_to(repo).as_posix()
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            result.gaps.append(CoverageGap(
                gap_id=f"gap-agent-manifest-invalid:{agent_id}",
                kind="unsupported_asset", severity="high", subject_refs=[rel],
                why_it_matters=f"Tool manifest could not be parsed ({exc.msg}); permissions are unknown.",
                blocking=True, required=True,
            ))
            return

        head_tools = {
            tool.get("name"): tool
            for tool in document.get("tools", []) if isinstance(tool, dict) and tool.get("name")
        }
        for tool_name, tool in head_tools.items():
            tool_id = f"{agent_id}.tool.{tool_name}"
            result.assets.append(Asset(
                asset_id=tool_id, kind="ai.tool", name=tool_name, path=rel,
                revision=manifest.head_revision,
                criticality="high" if tool.get("access") == "write" else "medium",
                identity_status="stable",
                attributes={
                    "access": tool.get("access", "unknown"),
                    "allowed": bool(tool.get("allowed", False)),
                    "external": bool(tool.get("external", False)),
                },
            ))
            result.relationships.append(Relationship(
                relationship_id=relationship_id(agent_id, tool_id, "grants_tool"),
                source_asset_id=agent_id, target_asset_id=tool_id,
                relation_type="grants_tool", impact_direction="forward",
                resolution="resolved", observed_revision=manifest.head_revision,
            ))

        binding = document.get("model_binding") or {}
        if binding:
            binding_id = f"{agent_id}.model.{binding.get('model_id', 'unknown')}"
            result.assets.append(Asset(
                asset_id=binding_id, kind="ai.model_binding",
                name=str(binding.get("model_id", "unknown")), path=rel,
                revision=manifest.head_revision, criticality="high",
                identity_status="stable", attributes=dict(binding),
            ))
            result.relationships.append(Relationship(
                relationship_id=relationship_id(agent_id, binding_id, "uses_model"),
                source_asset_id=agent_id, target_asset_id=binding_id,
                relation_type="uses_model", impact_direction="forward",
                resolution="resolved", observed_revision=manifest.head_revision,
            ))

        policy_flags = document.get("policy") or {}
        policy_id = f"{agent_id}.policy"
        result.assets.append(Asset(
            asset_id=policy_id, kind="ai.policy", name=f"{agent_name_of(agent_id)} safety policy",
            path=rel, revision=manifest.head_revision, criticality="critical",
            identity_status="stable", attributes=dict(policy_flags),
        ))

        # Baseline comparison (architecture section 7, change detection layer 1).
        baseline_raw = read_at_revision(repo, manifest.base_revision, rel)
        if baseline_raw is None and manifest.version_bound:
            result.gaps.append(CoverageGap(
                gap_id=f"gap-agent-baseline:{agent_id}",
                kind="missing_baseline", severity="high", subject_refs=[rel],
                why_it_matters="No baseline version of the tool manifest; privilege escalation cannot be ruled out.",
                blocking=True, required=True,
                remediation="Provide the base revision or review the manifest manually.",
            ))
            return

        diff: dict[str, object] = {"available": baseline_raw is not None, "added_tools": [], "removed_tools": [], "changed_fields": []}
        if baseline_raw is not None:
            try:
                base_doc = json.loads(baseline_raw)
            except json.JSONDecodeError:
                base_doc = {}
            base_tools = {
                tool.get("name"): tool
                for tool in base_doc.get("tools", []) if isinstance(tool, dict) and tool.get("name")
            }
            diff["added_tools"] = sorted(
                tool for tool, spec in head_tools.items()
                if tool not in base_tools or base_tools[tool] != spec
            )
            diff["removed_tools"] = sorted(set(base_tools) - set(head_tools))
            changed = []
            for field in ("model_binding", "policy"):
                if base_doc.get(field) != document.get(field):
                    changed.append(field)
            diff["changed_fields"] = changed
            diff["base_tools"] = base_tools
            diff["head_tools"] = head_tools
            diff["base_document"] = base_doc
            diff["head_document"] = document
            diff["manifest_path"] = rel

        result.facts[f"agent_diff:{agent_id}"] = diff
        result.evidence.append(make_evidence(
            self.name, "agent_tool_manifest", [rel], manifest.head_revision, digest_text(raw),
            limitations=["Privilege diff requires a resolvable base revision."],
        ))


def agent_name_of(asset_id: str) -> str:
    return asset_id.split(":", 1)[1]
