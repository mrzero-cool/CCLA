"""Tests for CLI adapter integration: cmd_run with external tool adapters."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from clca.adapter_integration import build_enhanced_plan
from clca.adapters.base import AdapterResult
from clca.adapters.registry import AdapterRegistry
from clca.cli import main
from clca.intake import ChangeManifest
from clca.models import CoverageGap


class _FindingAdapter:
    """Adapter that produces a coverage gap."""
    name = "finding-adapter"

    def __init__(self, result: AdapterResult) -> None:
        self._result = result

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        return self._result


def test_cmd_run_with_no_adapters(tmp_path):
    """cmd_run with --no-adapters should complete normally without adapter integration."""
    repo = tmp_path / "repo"
    shutil.copytree(Path(__file__).resolve().parents[1] / "sample_app", repo)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True, capture_output=True)

    # Make a change
    (repo / "backend" / "services" / "pricing.py").write_text(
        (repo / "backend" / "services" / "pricing.py").read_text() + "\n# test\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "change"], cwd=repo, check=True, capture_output=True)

    config_dir = Path(__file__).resolve().parents[1] / "config"
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()

    code = main([
        "run", "--repo", str(repo), "--head", head,
        "--catalog", str(config_dir / "check_catalog.json"),
        "--policy", str(config_dir / "policy.json"),
        "--commands", str(config_dir / "commands.json"),
        "--no-adapters",
    ])
    assert code in (0, 1, 2), f"clca run with --no-adapters failed with code {code}"


def test_build_enhanced_plan_with_finding_adapter(tmp_path):
    """build_enhanced_plan merges adapter gaps and findings into the plan."""
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest = ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("src/foo.py",),
    )
    base_plan = {
        "schema_version": "0.2.0",
        "changed_asset_kinds": ["code.function"],
        "budget_seconds": 60.0,
        "mandatory_estimated_seconds": 10.0,
        "selected_estimated_seconds": 10.0,
        "mandatory_budget_overrun": False,
        "selected_checks": [
            {
                "check_id": "static-manifest-validation",
                "effective_requirement": "mandatory",
                "selection_reason": ["changed asset kind matched catalog trigger"],
                "estimated_seconds": 10,
            },
        ],
        "excluded_checks": [],
        "coverage_gaps": [],
    }

    reg = AdapterRegistry()
    reg.register("finding-adapter", _FindingAdapter(AdapterResult(
        gaps=[
            CoverageGap(
                gap_id="gap:finding-adapter:test-gap",
                kind="unsupported_asset",
                severity="medium",
                subject_refs=[manifest.head_revision],
                why_it_matters="Test gap from finding adapter",
                blocking=False,
                required=False,
                remediation="Test remediation",
            )
        ],
    )))

    plan = build_enhanced_plan(repo, manifest, base_plan, registry=reg)

    assert "adapter_facts" in plan
    assert "adapter_findings" in plan
    assert "adapter_evidence_count" in plan
    assert len(plan["coverage_gaps"]) == 1
    assert plan["coverage_gaps"][0]["gap_id"] == "gap:finding-adapter:test-gap"
