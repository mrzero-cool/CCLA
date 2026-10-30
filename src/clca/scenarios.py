"""Self-contained demo scenarios and the shared pipeline executor.

The service never accepts an arbitrary repository URL or credentials
(architecture section 11); it only runs these built-in, synthetic scenarios
against a temporary copy of ``sample_app``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .adapter_integration import build_enhanced_plan
from .bundle import build_bundle, compute_sealed_digest
from .graph import build_graph_view, impact_from_plan
from .graph.metrics import to_dot
from .intake import build_change_manifest
from .models import CheckRequirement, CheckStatus, CoverageGap, EvidenceBundle, PolicyFinding
from .observability import SpanAttrs, create_span, set_span_status
from .policy import DecisionResult, decide
from .redact import redact_excerpt
from .reporting import render_markdown
from .runner import ArtifactStore, SubprocessRunner, load_command_catalog, resolve_command

_ROOT = Path(os.environ.get("CLCA_ROOT") or Path(__file__).resolve().parents[2])
SAMPLE_APP = _ROOT / "sample_app"
CONFIG_DIR = _ROOT / "config"

_COPY_IGNORE = shutil.ignore_patterns(".git", "artifacts", "__pycache__", ".pytest_cache")


class ScenarioError(RuntimeError):
    pass


def _git(repo: Path, *args: str) -> str:
    try:
        # CT-5b: bound every git call. An unbounded `git` hang would pin the
        # worker thread forever; combined with the admission cap that leaks a
        # run slot until service restart (permanent 429).
        proc = subprocess.run(["git", *args], cwd=repo, capture_output=True,
                              text=True, timeout=60)
    except subprocess.TimeoutExpired as exc:
        raise ScenarioError(f"git {' '.join(args)} timed out after 60s") from exc
    if proc.returncode != 0:
        raise ScenarioError(f"git {' '.join(args)} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout.strip()


def _edit(path: Path, transform: Callable[[str], str]) -> None:
    path.write_text(transform(path.read_text(encoding="utf-8")), encoding="utf-8")


def _clean(repo: Path) -> None:
    pass


def _safe_code_change(repo: Path) -> None:
    _edit(repo / "backend" / "services" / "pricing.py", lambda text: text + "\n# cosmetic: clarified discount comment\n")


def _write_tool_escalation(repo: Path) -> None:
    path = repo / "agents" / "replenishment" / "tool_manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["tools"].append({"name": "write_purchase_orders", "access": "write", "allowed": True})
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _column_rename(repo: Path) -> None:
    # Mutate both the checked-in SQL and the generated manifest, while leaving
    # the consumer contract unchanged. This is closer to a realistic schema
    # change than changing metadata alone.
    for path in (
        repo / "data" / "dbt" / "models" / "stg_sales.sql",
        repo / "data" / "dbt" / "manifest.json",
    ):
        _edit(path, lambda text: text.replace("customer_id", "client_id"))


def _prompt_edit(repo: Path) -> None:
    path = repo / "agents" / "replenishment" / "prompts" / "system.md"
    _edit(path, lambda text: text + "\nAlways cite evidence_refs for every recommendation.\n")


def _prompt_behavior_regression(repo: Path) -> None:
    # Remove a required output-contract term. The deterministic behavior suite
    # should fail, demonstrating a measured prompt regression rather than a
    # mere text diff. No live LLM or network dependency is used.
    path = repo / "agents" / "replenishment" / "prompts" / "system.md"
    _edit(path, lambda text: text.replace("evidence_refs", "supporting_sources"))


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    description: str
    expected_decision: str
    apply: Callable[[Path], None]


SCENARIOS: dict[str, Scenario] = {
    scenario.scenario_id: scenario
    for scenario in (
        Scenario(
            "clean_tree", "No changes",
            "Nothing changed: the gate verifies the baseline and should clear it.",
            "PASS", _clean,
        ),
        Scenario(
            "safe_code_change", "Cosmetic code change",
            "A comment-only edit in pricing logic: Python unit tests are selected and pass. "
            "Optional checks skipped by the verification budget are disclosed, so the decision is WARN.",
            "WARN", _safe_code_change,
        ),
        Scenario(
            "write_tool_escalation", "Agent privilege escalation",
            "A write tool is granted to the replenishment agent. Unit tests still pass, "
            "but deterministic policy blocks the merge (AGENT_NEW_WRITE_TOOL).",
            "BLOCK", _write_tool_escalation,
        ),
        Scenario(
            "column_rename", "Data contract break",
            "customer_id is renamed to client_id in the dbt model without updating the contract.",
            "BLOCK", _column_rename,
        ),
        Scenario(
            "prompt_edit", "Agent prompt edit",
            "The agent system prompt changes, so behavior evaluation becomes mandatory and runs. "
            "Optional checks skipped by budget are disclosed, so the decision is WARN.",
            "WARN", _prompt_edit,
        ),
        Scenario(
            "prompt_behavior_regression", "Prompt behavior regression",
            "The prompt loses a required evidence_refs contract. The deterministic behavior evaluation must fail and the mandatory check blocks the change.",
            "BLOCK", _prompt_behavior_regression,
        ),
    )
}


@dataclass
class RunResult:
    run_id: str
    scenario_id: str
    decision: str
    expected_decision: str
    base_revision: str
    head_revision: str
    bundle_digest: str
    reasons: list[str]
    checks: list[dict[str, Any]]
    policy_findings: list[dict[str, Any]]
    coverage_gaps: list[dict[str, Any]]
    report_markdown: str
    changed_paths: list[str] = field(default_factory=list)
    impact: dict[str, Any] = field(default_factory=dict)
    graph: dict[str, Any] = field(default_factory=dict)
    graph_dot: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    adapters: list[dict[str, Any]] = field(default_factory=list)
    adapter_findings: list[dict[str, Any]] = field(default_factory=list)
    adapter_gaps: list[dict[str, Any]] = field(default_factory=list)
    adapter_facts: dict[str, Any] = field(default_factory=dict)
    policy_id: str = ""
    policy_version: str = ""
    diff_digest: str = ""
    started_at: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "decision": self.decision,
            "expected_decision": self.expected_decision,
            "matches_expectation": self.decision == self.expected_decision,
            "base_revision": self.base_revision,
            "head_revision": self.head_revision,
            "diff_digest": self.diff_digest,
            "bundle_digest": self.bundle_digest,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "changed_paths": self.changed_paths,
            "impact": self.impact,
            "evidence": self.evidence,
            "adapters": self.adapters,
            "adapter_findings": self.adapter_findings,
            "adapter_gaps": self.adapter_gaps,
            "adapter_facts": self.adapter_facts,
            "reasons": self.reasons,
            "checks": self.checks,
            "policy_findings": self.policy_findings,
            "coverage_gaps": self.coverage_gaps,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
        }


def run_scenario(scenario_id: str, budget_seconds: float = 60.0) -> RunResult:
    """Copy sample_app to a temp worktree, apply the scenario, and run the gate."""
    from clca.observability import create_span, set_span_status

    span = create_span(
        "clca.run_scenario",
        {
            SpanAttrs.SCENARIO_ID: scenario_id,
            SpanAttrs.BUDGET_SECONDS: budget_seconds,
        },
    )
    try:
        scenario = SCENARIOS.get(scenario_id)
        if scenario is None:
            raise ScenarioError(f"unknown scenario '{scenario_id}'; choose from {sorted(SCENARIOS)}")

        catalog = json.loads((CONFIG_DIR / "check_catalog.json").read_text(encoding="utf-8"))
        policy = json.loads((CONFIG_DIR / "policy.json").read_text(encoding="utf-8"))
        commands = load_command_catalog(CONFIG_DIR / "commands.json")

        workdir = Path(tempfile.mkdtemp(prefix=f"clca-{scenario_id}-"))
        # CT-5b: Verify workdir is not a symlink to prevent symlink attacks where
        # an attacker pre-creates a symlink at the expected temp path, causing
        # CLCA to write evidence or reports into an attacker-controlled location.
        if workdir.is_symlink():
            shutil.rmtree(workdir, ignore_errors=True)
            raise ScenarioError(f"temp directory {workdir} is a symlink; refusing to use it")
        repo = workdir / "app"
        started = time.monotonic()
        started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

        shutil.copytree(SAMPLE_APP, repo, ignore=_COPY_IGNORE)
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "clca-service@example.com")
        _git(repo, "config", "user.name", "CLCA Service")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "scenario baseline")
        base = _git(repo, "rev-parse", "HEAD")

        scenario.apply(repo)
        if _git(repo, "status", "--porcelain"):
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", f"scenario: {scenario.scenario_id}")

        manifest = build_change_manifest(repo, base=base)
        bundle, plan = build_bundle(
            repo, manifest, catalog, policy,
            budget_seconds=budget_seconds,
            artifacts_root=str(repo / "artifacts"),
        )

        # ---- Adapter integration: external tool evidence ----
        # Run registered external tool adapters (AxiomCode, Enola, Code System
        # Graph, DataHub, OWASP, Praxen, Stryker, Farol, CodeDecay, semctx).
        # Their coverage gaps are merged into the bundle, their findings become
        # policy findings, and their facts promote checks to mandatory.
        # Controlled by CLCA_ADAPTERS env var (comma-separated list; default: all).
        adapter_names = None
        adapter_env = os.environ.get("CLCA_ADAPTERS", "").strip()
        if adapter_env:
            adapter_names = [name.strip() for name in adapter_env.split(",") if name.strip()]

        enhanced_plan = build_enhanced_plan(
            repo=repo,
            manifest=manifest,
            base_plan=plan,
            adapter_names=adapter_names,
        )

        # Apply promoted checks: adapter facts can raise requirement to mandatory.
        for check in bundle.checks:
            for enhanced_check in enhanced_plan.get("selected_checks", []):
                if check.check_id == enhanced_check.get("check_id"):
                    new_req = enhanced_check.get("effective_requirement")
                    if new_req and new_req != check.requirement.value:
                        check.requirement = CheckRequirement(new_req)
                        check.selection_reason.extend(
                            enhanced_check.get("selection_reason", [])
                        )

        # Add adapter-derived policy findings to the bundle.
        for finding in enhanced_plan.get("adapter_findings", []):
            bundle.policy_findings.append(PolicyFinding(
                rule_id=finding["rule_id"],
                action=finding["action"],
                summary=finding["summary"],
            ))

        # Add adapter coverage gaps to the bundle (deduplicated by gap_id).
        existing_gap_ids = {g.gap_id for g in bundle.coverage_gaps}
        for gap in enhanced_plan.get("coverage_gaps", []):
            if gap.get("gap_id") not in existing_gap_ids:
                bundle.coverage_gaps.append(CoverageGap(
                    gap_id=gap["gap_id"],
                    kind=gap["kind"],
                    severity=gap["severity"],
                    subject_refs=gap.get("subject_refs", []),
                    why_it_matters=gap["why_it_matters"],
                    blocking=gap.get("blocking", False),
                    required=gap.get("required", False),
                    remediation=gap.get("remediation"),
                ))
                existing_gap_ids.add(gap["gap_id"])

        # Re-seal after adding adapter evidence: the decision must be bound to
        # the final evidence state, not the pre-adapter snapshot.
        bundle.bundle_digest = compute_sealed_digest(bundle)

        # Capture adapter context for the service API and run record.
        adapter_findings = enhanced_plan.get("adapter_findings", [])
        adapter_gaps = enhanced_plan.get("coverage_gaps", [])
        adapter_facts = enhanced_plan.get("adapters_used", {})

        store = ArtifactStore(repo / "artifacts")
        runner = SubprocessRunner(repo, store)
        run_id = bundle.change.change_id

        for check in bundle.checks:
            if check.status not in (CheckStatus.PLANNED, CheckStatus.NOT_RUN):
                continue
            try:
                spec = resolve_command(commands, check.command_ref or "", check.check_id)
            except Exception as exc:  # allow-list refusal stays visible, never silent
                check.status = CheckStatus.UNSUPPORTED
                check.selection_reason.append(f"not executed: {exc}")
                continue
            outcome = runner.run(spec, run_id)
            check.status = CheckStatus(outcome.status)
            check.exit_code = outcome.exit_code
            check.duration_ms = outcome.duration_ms
            check.input_digest = outcome.input_digest
            check.environment_digest = outcome.environment_digest
            check.artifact_refs = outcome.artifact_refs
            check.artifact_digests = outcome.artifact_digests
            check.stdout_excerpt = outcome.stdout_excerpt

        # Re-seal after recording execution results: the decision must be bound
        # to the final check states, not the pre-execution snapshot.
        bundle.bundle_digest = compute_sealed_digest(bundle)
        result: DecisionResult = decide(bundle, catalog, policy, store)
        bundle.decision = result.decision
        bundle.bundle_digest = compute_sealed_digest(bundle)
        report = redact_excerpt(render_markdown(bundle, result), 200_000)

        result_obj = RunResult(
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            decision=result.decision,
            expected_decision=scenario.expected_decision,
            base_revision=manifest.base_revision,
            head_revision=manifest.head_revision,
            bundle_digest=bundle.bundle_digest or "",
            reasons=list(result.reasons),
            checks=[
                {
                    "check_id": c.check_id,
                    "category": c.category,
                    "requirement": c.requirement.value,
                    "status": c.status.value,
                    "exit_code": c.exit_code,
                    "duration_ms": c.duration_ms,
                    "artifacts": len(c.artifact_refs),
                    "artifact_refs": c.artifact_refs[:10],
                    "selection_reason": c.selection_reason,
                    # Log tail shown in the UI's check drawer (already redacted upstream).
                    "log_tail": redact_excerpt(c.stdout_excerpt or "", 1600),
                }
                for c in bundle.checks
            ],
            policy_findings=[f.model_dump(mode="json") for f in bundle.policy_findings],
            coverage_gaps=[g.model_dump(mode="json") for g in bundle.coverage_gaps],
            report_markdown=report,
            changed_paths=list(manifest.changed_paths),
            impact=plan.get("impact", {}),
            graph=build_graph_view(
                bundle.assets, bundle.relationships, impact_from_plan(bundle.plan),
            ),
            graph_dot=to_dot(
                bundle.assets, bundle.relationships, impact_from_plan(bundle.plan),
            ),
            evidence=[
                {
                    "evidence_id": e.evidence_id,
                    "producer": f"{e.producer_name}@{e.producer_version}",
                    "evidence_type": e.evidence_type,
                    "subject_refs": e.subject_refs[:8],
                    "support": e.support,
                    "freshness": e.freshness,
                    "observed_at": e.observed_at.isoformat(),
                    "input_digest": e.input_digest,
                    "limitations": e.limitations,
                }
                for e in bundle.evidence[:40]
            ],
            adapters=list(bundle.adapters),
            adapter_findings=adapter_findings,
            adapter_gaps=adapter_gaps,
            adapter_facts=adapter_facts,
            policy_id=bundle.policy_id,
            policy_version=bundle.policy_version,
            diff_digest=manifest.diff_digest,
            started_at=started_at,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

        set_span_status(span, "ok" if result.decision != "INCOMPLETE" else "error")
        span.set_attribute(SpanAttrs.DECISION, result.decision)
        span.set_attribute(SpanAttrs.POLICY_ID, bundle.policy_id)
        span.set_attribute(SpanAttrs.BUNDLE_DIGEST, bundle.bundle_digest or "")
        span.end()
        return result_obj
    except Exception as exc:
        set_span_status(span, "error", str(exc))
        span.set_attribute(SpanAttrs.DECISION, "error")
        span.end()
        raise
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
