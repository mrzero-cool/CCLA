"""Tests for the OWASP Agent Security adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clca.adapters.owasp_agent import OWASPAgentAdapter
from clca.intake import ChangeManifest


def _manifest() -> ChangeManifest:
    return ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("agents/replenishment/agent.py",),
    )


def test_missing_export_returns_gap():
    adapter = OWASPAgentAdapter(export_path=Path("/nonexistent/export.json"))
    result = adapter.collect(Path("/tmp/repo"), _manifest())
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == "unsupported_asset"
    assert result.assets == []


def test_valid_export_normalizes_agents_prompts_tools_and_results():
    export = {
        "agents": [
            {"id": "agent1", "name": "replenishment-agent", "path": "agents/replenishment/agent.py"},
        ],
        "prompts": [
            {"id": "prompt1", "name": "system.md", "path": "agents/replenishment/prompts/system.md"},
        ],
        "tools": [
            {"id": "tool1", "name": "write_purchase_orders", "access": "write"},
        ],
        "policies": [
            {"id": "policy1", "name": "new_write_tool_requires_review"},
        ],
        "results": [
            {
                "agent_id": "agent1",
                "prompt_id": "prompt1",
                "status": "passed",
                "finding": "",
            },
            {
                "agent_id": "agent1",
                "tool_id": "tool1",
                "status": "failed",
                "finding": "NEW_WRITE_TOOL_DETECTED: write_purchase_orders requires human review",
            },
        ],
    }
    with tempfile.TemporaryDirectory() as td:
        export_path = Path(td) / "owasp_export.json"
        export_path.write_text(json.dumps(export), encoding="utf-8")
        adapter = OWASPAgentAdapter(export_path=export_path)
        result = adapter.collect(Path("/tmp/repo"), _manifest())

    assert len(result.assets) == 4  # 1 agent + 1 prompt + 1 tool + 1 policy
    assert any(a.kind.value == "ai.agent" for a in result.assets)
    assert any(a.kind.value == "ai.prompt" for a in result.assets)
    assert any(a.kind.value == "ai.tool" for a in result.assets)
    assert any(a.kind.value == "ai.policy" for a in result.assets)
    assert len(result.relationships) == 2  # uses_prompt + grants_tool

    # Failed result becomes a coverage gap
    assert len(result.gaps) >= 1
    assert any("write_purchase_orders" in g.why_it_matters for g in result.gaps)

    assert len(result.evidence) == 1
    assert result.evidence[0].producer_name == "owasp_agent_security"
    assert result.facts["owasp_agent_count"] == 1
    assert result.facts["owasp_result_count"] == 2


def test_load_owasp_agent_adapter_factory():
    adapter = OWASPAgentAdapter()
    assert adapter.name == "owasp_agent_security"
