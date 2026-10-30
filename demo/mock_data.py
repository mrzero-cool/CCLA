"""CLCA demo mock-data generator.

Produces self-contained, representative repo snapshots + expected CLCA decisions
that judges can play with in the interactive demo.  No network, no secrets,
no real credentials — purely synthetic fixture data for demonstration.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = REPO_ROOT / "demo"
MOCK_DIR = DEMO_DIR / "mock_data"


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------

SCENARIOS: list[dict[str, Any]] = [
    {
        "scenario_id": "demo-safe-docs",
        "family": "safe_low_impact",
        "name": "Docs-only change",
        "description": "README updated with installation notes. No code, data, or AI assets touched.",
        "expected_decision": "PASS",
        "changed_files": ["README.md", "docs/architecture.md"],
        "changed_asset_kinds": ["docs"],
        "mandatory_checks": ["static-manifest-validation"],
        "checks": [
            {"check_id": "static-manifest-validation", "status": "passed", "exit_code": 0, "duration_ms": 120},
        ],
        "coverage_gaps": [],
        "policy_findings": [],
        "impact": {
            "nodes": [
                {"id": "repo:demo-retail", "label": "demo-retail repo", "kind": "repository"},
                {"id": "file:README.md", "label": "README.md", "kind": "docs", "path": "README.md"},
            ],
            "edges": [
                {"source": "repo:demo-retail", "target": "file:README.md", "kind": "CONTAINS"},
            ],
        },
        "evidence": [
            {"evidence_id": "ev-docs-1", "evidence_type": "file_hash", "observed_revision": "a" * 40, "freshness": "current"},
        ],
        "adapter_records": [
            {"name": "python-ast", "assets": 1, "relationships": 1},
        ],
        "reasons": ["No runtime asset changed; only the always-required fast check is selected."],
        "budget_seconds": 60,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": 850,
    },
    {
        "scenario_id": "demo-write-tool-escalation",
        "family": "agent_ai_permissions",
        "name": "Agent write-tool escalation",
        "description": "Replenishment agent gains a new `write_purchase_orders` tool with write access. Unit tests still pass, but policy blocks on new write tool.",
        "expected_decision": "BLOCK",
        "changed_files": [
            "agents/replenishment/agent.py",
            "agents/replenishment/tool_manifest.json",
        ],
        "changed_asset_kinds": ["code.function", "ai.tool_manifest"],
        "mandatory_checks": ["agent-security-smoke", "agent-behavior-evals", "static-manifest-validation"],
        "checks": [
            {"check_id": "static-manifest-validation", "status": "passed", "exit_code": 0, "duration_ms": 110},
            {"check_id": "python-unit-tests", "status": "passed", "exit_code": 0, "duration_ms": 3400},
            {"check_id": "agent-security-smoke", "status": "failed", "exit_code": 1, "duration_ms": 2100,
             "stdout_excerpt": "NEW_WRITE_TOOL_DETECTED: write_purchase_orders requires human review"},
            {"check_id": "agent-behavior-evals", "status": "unsupported", "exit_code": None, "duration_ms": None,
             "stdout_excerpt": "eval runner unavailable in this environment"},
        ],
        "coverage_gaps": [
            {"gap_id": "gap-agent-evals-unavailable", "kind": "agent_eval", "blocking": False, "required": False},
        ],
        "policy_findings": [
            {"rule_id": "agent_policy.new_write_tool_requires_review", "action": "BLOCK", "summary": "New write tool grants purchase-order write access; manual review required."},
        ],
        "impact": {
            "nodes": [
                {"id": "repo:demo-retail", "label": "demo-retail repo", "kind": "repository"},
                {"id": "agent:replenishment", "label": "replenishment agent", "kind": "agent", "path": "agents/replenishment/agent.py"},
                {"id": "manifest:tool_manifest", "label": "tool_manifest.json", "kind": "ai.tool_manifest", "path": "agents/replenishment/tool_manifest.json"},
                {"id": "tool:write_purchase_orders", "label": "write_purchase_orders", "kind": "ai.tool", "access": "write"},
            ],
            "edges": [
                {"source": "agent:replenishment", "target": "manifest:tool_manifest", "kind": "DECLARES"},
                {"source": "manifest:tool_manifest", "target": "tool:write_purchase_orders", "kind": "GRANTS_TOOL"},
                {"source": "tool:write_purchase_orders", "target": "system:purchase_orders", "kind": "WRITES_TO"},
            ],
        },
        "evidence": [
            {"evidence_id": "ev-agent-1", "evidence_type": "tool_manifest_hash", "observed_revision": "b" * 40, "freshness": "current"},
        ],
        "adapter_records": [
            {"name": "python-ast", "assets": 3, "relationships": 2},
            {"name": "ai-agent", "assets": 2, "relationships": 1},
        ],
        "reasons": ["Mandatory check failed: agent-security-smoke", "Policy BLOCK: agent_policy.new_write_tool_requires_review"],
        "budget_seconds": 120,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": 5600,
    },
    {
        "scenario_id": "demo-column-rename",
        "family": "data_lineage",
        "name": "dbt column rename (contract stale)",
        "description": "`customer_id` renamed to `client_id` in dbt manifest. SQL model updated but downstream dashboard contract not refreshed — cross-layer data impact.",
        "expected_decision": "BLOCK",
        "changed_files": [
            "data/dbt/manifest.json",
            "data/dbt/models/stg_sales.sql",
            "metrics/net_sales.yml",
        ],
        "changed_asset_kinds": ["data.table", "data.column", "data.metric"],
        "mandatory_checks": ["data-contract-tests", "static-manifest-validation"],
        "checks": [
            {"check_id": "static-manifest-validation", "status": "passed", "exit_code": 0, "duration_ms": 95},
            {"check_id": "data-contract-tests", "status": "failed", "exit_code": 1, "duration_ms": 4500,
             "stdout_excerpt": "CONTRACT_MISMATCH: column customer_id not found; expected client_id in net_sales"},
        ],
        "coverage_gaps": [
            {"gap_id": "gap-dashboard-contract-stale", "kind": "data_contract", "blocking": True, "required": True},
        ],
        "policy_findings": [
            {"rule_id": "data_policy.column_rename_requires_contract_refresh", "action": "BLOCK", "summary": "Renamed column without refreshing downstream contract; data-layer impact detected."},
        ],
        "impact": {
            "nodes": [
                {"id": "repo:demo-retail", "label": "demo-retail repo", "kind": "repository"},
                {"id": "table:sales", "label": "stg_sales table", "kind": "data.table", "path": "data/dbt/models/stg_sales.sql"},
                {"id": "column:customer_id", "label": "customer_id column", "kind": "data.column", "path": "data/dbt/manifest.json"},
                {"id": "column:client_id", "label": "client_id column", "kind": "data.column", "path": "data/dbt/manifest.json"},
                {"id": "metric:net_sales", "label": "net_sales metric", "kind": "data.metric", "path": "metrics/net_sales.yml"},
                {"id": "dashboard:exec_dashboard", "label": "Executive dashboard", "kind": "dashboard"},
            ],
            "edges": [
                {"source": "table:sales", "target": "column:customer_id", "kind": "CONTAINS"},
                {"source": "table:sales", "target": "column:client_id", "kind": "CONTAINS"},
                {"source": "column:client_id", "target": "metric:net_sales", "kind": "DERIVES_FROM"},
                {"source": "metric:net_sales", "target": "dashboard:exec_dashboard", "kind": "EXPOSES_API"},
            ],
        },
        "evidence": [
            {"evidence_id": "ev-data-1", "evidence_type": "dbt_manifest_hash", "observed_revision": "c" * 40, "freshness": "stale"},
        ],
        "adapter_records": [
            {"name": "dbt-manifest", "assets": 5, "relationships": 4},
            {"name": "sql-parser", "assets": 2, "relationships": 1},
        ],
        "reasons": ["Mandatory check failed: data-contract-tests", "Coverage gap: dashboard contract stale"],
        "budget_seconds": 180,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": 6100,
    },
    {
        "scenario_id": "demo-prompt-edit",
        "family": "agent_ai_permissions",
        "name": "System prompt edit",
        "description": "Replenishment agent system prompt changed to 'Always cite evidence_refs'. Behavior eval can't run in this environment — INCOMPLETE, not PASS.",
        "expected_decision": "INCOMPLETE",
        "changed_files": ["agents/replenishment/prompts/system.md"],
        "changed_asset_kinds": ["ai.prompt"],
        "mandatory_checks": ["agent-behavior-evals", "static-manifest-validation"],
        "checks": [
            {"check_id": "static-manifest-validation", "status": "passed", "exit_code": 0, "duration_ms": 105},
            {"check_id": "agent-behavior-evals", "status": "unsupported", "exit_code": None, "duration_ms": None,
             "stdout_excerpt": "eval runner unavailable in this environment"},
        ],
        "coverage_gaps": [
            {"gap_id": "gap-agent-behavior-unavailable", "kind": "agent_eval", "blocking": True, "required": True},
        ],
        "policy_findings": [],
        "impact": {
            "nodes": [
                {"id": "repo:demo-retail", "label": "demo-retail repo", "kind": "repository"},
                {"id": "prompt:system", "label": "system.md prompt", "kind": "ai.prompt", "path": "agents/replenishment/prompts/system.md"},
                {"id": "agent:replenishment", "label": "replenishment agent", "kind": "agent"},
            ],
            "edges": [
                {"source": "agent:replenishment", "target": "prompt:system", "kind": "REFERENCES_PROMPT"},
            ],
        },
        "evidence": [
            {"evidence_id": "ev-prompt-1", "evidence_type": "prompt_hash", "observed_revision": "d" * 40, "freshness": "current"},
        ],
        "adapter_records": [
            {"name": "ai-agent", "assets": 2, "relationships": 1},
        ],
        "reasons": ["Mandatory check not proven passed: agent-behavior-evals (unsupported)"],
        "budget_seconds": 90,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": 3200,
    },
    {
        "scenario_id": "demo-budget-exhausted",
        "family": "safe_low_impact",
        "name": "Budget exhausted mid-run",
        "description": "Small code change but the validation budget ran out before all planned checks could execute — WARN, not PASS.",
        "expected_decision": "WARN",
        "changed_files": ["backend/services/pricing.py"],
        "changed_asset_kinds": ["code.function"],
        "mandatory_checks": ["python-unit-tests", "static-manifest-validation"],
        "checks": [
            {"check_id": "static-manifest-validation", "status": "passed", "exit_code": 0, "duration_ms": 80},
            {"check_id": "python-unit-tests", "status": "timed_out", "exit_code": 124, "duration_ms": 60000,
             "stdout_excerpt": "check timed out at 60s budget"},
        ],
        "coverage_gaps": [
            {"gap_id": "gap-optional-budget-exhausted", "kind": "budget", "blocking": False, "required": False},
        ],
        "policy_findings": [],
        "impact": {
            "nodes": [
                {"id": "repo:demo-retail", "label": "demo-retail repo", "kind": "repository"},
                {"id": "fn:pricing.calculate", "label": "pricing.calculate()", "kind": "code.function", "path": "backend/services/pricing.py"},
            ],
            "edges": [
                {"source": "repo:demo-retail", "target": "fn:pricing.calculate", "kind": "CONTAINS"},
            ],
        },
        "evidence": [
            {"evidence_id": "ev-budget-1", "evidence_type": "file_hash", "observed_revision": "e" * 40, "freshness": "current"},
        ],
        "adapter_records": [
            {"name": "python-ast", "assets": 1, "relationships": 1},
        ],
        "reasons": ["Non-blocking evidence gap: gap-optional-budget-exhausted (budget_exhausted)"],
        "budget_seconds": 60,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": 60150,
    },
    {
        "scenario_id": "demo-unknown-change",
        "family": "safe_low_impact",
        "name": "Unknown change set (webhook without file list)",
        "description": "GitHub webhook delivered no file list (real pull_request webhooks never do). CLCA refuses to guess — 422, no run started, no clean-tree claim.",
        "expected_decision": "422_REFUSED",
        "changed_files": [],
        "changed_asset_kinds": [],
        "mandatory_checks": [],
        "checks": [],
        "coverage_gaps": [],
        "policy_findings": [],
        "impact": {"nodes": [], "edges": []},
        "evidence": [],
        "adapter_records": [],
        "reasons": ["Cannot determine changed files from pull_request payload; GitHub does not send a file list"],
        "budget_seconds": 60,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": 0,
    },
]


# ---------------------------------------------------------------------------
# Linked tool mock outputs (what external tools would return for each scenario)
# ---------------------------------------------------------------------------

def linked_tool_outputs(scenario: dict[str, Any]) -> dict[str, Any]:
    """Mock outputs from external tools that CLCA would ingest."""
    sid = scenario["scenario_id"]
    base = {
        "impactgraph": {
            "tool": "impactgraph",
            "version": "0.4.2",
            "assets": len(scenario["impact"]["nodes"]),
            "edges": len(scenario["impact"]["edges"]),
            "changed_atoms": scenario["changed_files"],
            "affected_consumers": [n["id"] for n in scenario["impact"]["nodes"] if n["kind"] != "repository"],
        },
        "axiomcodegraph": {
            "tool": "axiomcodegraph",
            "version": "1.1.0",
            "compiler_grounded": True,
            "test_selection_hints": ["python-unit-tests"] if "python" in sid or "safe" in sid else ["agent-security-smoke"],
            "impact_score": 0.85 if sid == "demo-write-tool-escalation" else 0.3,
        },
        "enola": {
            "tool": "enola",
            "version": "2.0.1",
            "cross_repo_edges": 2 if sid == "demo-column-rename" else 0,
            "architecture_drift": sid in ("demo-column-rename", "demo-write-tool-escalation"),
        },
        "code_system_graph": {
            "tool": "code_system_graph",
            "version": "0.9.0",
            "canonical_ids": [n["id"] for n in scenario["impact"]["nodes"]],
            "inferred_edges": [e for e in scenario["impact"]["edges"] if e["kind"] == "DERIVES_FROM"],
        },
        "datahub": {
            "tool": "datahub",
            "version": "0.13.0",
            "lineage_freshness": "current" if sid != "demo-column-rename" else "stale",
            "tables_discovered": [n["id"] for n in scenario["impact"]["nodes"] if n["kind"] == "data.table"],
        },
        "owasp_agent_harness": {
            "tool": "owasp-agent-security-harness",
            "version": "1.2.0",
            "prompt_injection_detected": sid == "demo-prompt-edit",
            "excessive_agency": sid == "demo-write-tool-escalation",
            "data_disclosure": False,
        },
    }
    return base


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def write_scenario(scenario: dict[str, Any]) -> Path:
    """Write one scenario's mock bundle + linked-tool outputs."""
    out_dir = MOCK_DIR / scenario["scenario_id"]
    out_dir.mkdir(parents=True, exist_ok=True)

    bundle = {
        "change_id": scenario["scenario_id"],
        "repository": "demo-retail",
        "base_revision": "a" * 40,
        "head_revision": "b" * 40,
        "diff_digest": "sha256:demo",
        "created_at": scenario["started_at"],
        "policy_id": "default-pr-policy",
        "policy_version": "0.2.0",
        "policy_digest": "sha256:policy-demo",
        "check_catalog_digest": "sha256:catalog-demo",
        "bundle_digest": "sha256:demo-bundle",
        "changed_paths": scenario["changed_files"],
        "changed_asset_kinds": scenario["changed_asset_kinds"],
        "required_check_ids": scenario["mandatory_checks"],
        "checks": scenario["checks"],
        "coverage_gaps": scenario["coverage_gaps"],
        "policy_findings": scenario["policy_findings"],
        "impact": scenario["impact"],
        "evidence": scenario["evidence"],
        "adapters": scenario["adapter_records"],
        "reasons": scenario["reasons"],
        "decision": scenario["expected_decision"],
        "expected_decision": scenario["expected_decision"],
        "matches_expectation": True,
        "duration_ms": scenario["duration_ms"],
    }
    (out_dir / "bundle.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    linked = linked_tool_outputs(scenario)
    for tool, output in linked.items():
        (out_dir / f"{tool}.json").write_text(json.dumps(output, indent=2), encoding="utf-8")

    (out_dir / "decision.json").write_text(
        json.dumps({"decision": scenario["expected_decision"], "reasons": scenario["reasons"]}, indent=2),
        encoding="utf-8",
    )
    return out_dir


def write_index() -> Path:
    """Write an index of all demo scenarios for the interactive UI."""
    index = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scenario_count": len(SCENARIOS),
        "scenarios": [
            {
                "scenario_id": s["scenario_id"],
                "name": s["name"],
                "family": s["family"],
                "description": s["description"],
                "expected_decision": s["expected_decision"],
                "changed_files": s["changed_files"],
                "mandatory_checks": s["mandatory_checks"],
                "linked_tools": list(linked_tool_outputs(s).keys()),
            }
            for s in SCENARIOS
        ],
    }
    path = MOCK_DIR / "index.json"
    path.write_text(json.dumps(index, indent=2), encoding="utf-8")
    return path


def main() -> None:
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    for s in SCENARIOS:
        write_scenario(s)
    write_index()
    print(f"Generated {len(SCENARIOS)} demo scenarios in {MOCK_DIR}")


if __name__ == "__main__":
    main()
