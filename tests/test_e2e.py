"""End-to-end pipeline: analyze → verify → decide on a synthetic retail repo.

These tests exercise the real CLI path, including allow-listed subprocess
execution of the sample app's checks.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from clca.cli import main
from clca.models import CheckStatus, EvidenceBundle
from clca.policy import decide
from clca.runner import ArtifactStore, load_command_catalog

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_APP = ROOT / "sample_app"
CATALOG = ROOT / "config" / "check_catalog.json"
POLICY = ROOT / "config" / "policy.json"
COMMANDS = ROOT / "config" / "commands.json"


def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


pytestmark = pytest.mark.skipif(not _git_available(), reason="git is not available")


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


@pytest.fixture
def repo(tmp_path):
    target = tmp_path / "app"
    shutil.copytree(SAMPLE_APP, target, ignore=shutil.ignore_patterns(".git", "artifacts", "__pycache__"))
    _git(target, "init", "-q")
    _git(target, "config", "user.email", "clca@example.com")
    _git(target, "config", "user.name", "CLCA")
    _git(target, "add", "-A")
    _git(target, "commit", "-qm", "base")
    return target


def _head(repo: Path) -> str:
    return _git(repo, "rev-parse", "HEAD")


def _run(repo: Path, base: str, capsys) -> tuple[int, EvidenceBundle]:
    code = main([
        "run", "--repo", str(repo), "--base", base,
        "--catalog", str(CATALOG), "--policy", str(POLICY), "--commands", str(COMMANDS),
        "--budget-seconds", "60",
    ])
    bundles = sorted((repo / "artifacts").glob("*.bundle.json"))
    assert bundles, "no evidence bundle was written"
    bundle = EvidenceBundle.model_validate(json.loads(bundles[-1].read_text(encoding="utf-8")))
    return code, bundle


def test_safe_code_change_is_not_blocked_and_is_not_unverified(repo, capsys):
    base = _head(repo)
    target = repo / "backend" / "services" / "pricing.py"
    target.write_text(target.read_text(encoding="utf-8") + "\n# cosmetic comment\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "comment")

    code, bundle = _run(repo, base, capsys)
    assert bundle.decision in ("PASS", "WARN"), bundle.decision
    assert code == 0
    unit = next(c for c in bundle.checks if c.check_id == "python-unit-tests")
    assert unit.status == CheckStatus.PASSED
    assert unit.exit_code == 0 and unit.artifact_refs and unit.input_digest


def test_write_tool_escalation_blocks_even_when_unit_tests_pass(repo, capsys):
    base = _head(repo)
    manifest_path = repo / "agents" / "replenishment" / "tool_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["tools"].append({"name": "write_purchase_orders", "access": "write", "allowed": True})
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    # Also touch application code, so the Python unit suite is selected and passes:
    # the block must come from policy, not from unrelated test noise.
    agent_py = repo / "agents" / "replenishment" / "agent.py"
    agent_py.write_text(agent_py.read_text(encoding="utf-8") + "\n# behavior tweak\n", encoding="utf-8")
    pricing = repo / "backend" / "services" / "pricing.py"
    pricing.write_text(pricing.read_text(encoding="utf-8") + "\n# touched\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "grant write tool")

    code, bundle = _run(repo, base, capsys)
    assert bundle.decision == "BLOCK"
    assert code == 1
    rules = {f.rule_id for f in bundle.policy_findings}
    assert "AGENT_NEW_WRITE_TOOL" in rules
    # Independent signal: the repo's own agent security check failed too.
    security = next(c for c in bundle.checks if c.check_id == "agent-security-smoke")
    assert security.status == CheckStatus.FAILED
    # The unit suite still passed: policy, not test luck, produced the block.
    unit = next(c for c in bundle.checks if c.check_id == "python-unit-tests")
    assert unit.status == CheckStatus.PASSED


def test_column_rename_breaks_contract_and_blocks(repo, capsys):
    base = _head(repo)
    manifest_path = repo / "data" / "dbt" / "manifest.json"
    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8").replace('"customer_id"', '"client_id"'),
        encoding="utf-8",
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "rename column in model only")

    code, bundle = _run(repo, base, capsys)
    assert bundle.decision == "BLOCK"
    assert code == 1
    contract = next(c for c in bundle.checks if c.check_id == "data-contract-tests")
    assert contract.status == CheckStatus.FAILED
    changed_kinds = set(bundle.plan["changed_asset_kinds"])
    assert "data.column" in changed_kinds or "data.model" in changed_kinds


def test_unavailable_mandatory_check_is_incomplete_not_pass(repo, capsys):
    base = _head(repo)
    prompt = repo / "agents" / "replenishment" / "prompts" / "system.md"
    prompt.write_text(prompt.read_text(encoding="utf-8") + "\nAlways cite evidence_refs.\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "prompt edit")

    # Simulate "the agent evaluation runner is unavailable in this environment".
    from clca.cli import _analyze, _verify
    import argparse

    args = argparse.Namespace(
        repo=str(repo), catalog=str(CATALOG), policy=str(POLICY), commands=str(COMMANDS),
        artifacts_root=None, output=None, base=base, head=None, budget_seconds=60.0,
    )
    bundle_path = _analyze(args)
    commands = load_command_catalog(Path(COMMANDS))
    commands["commands"].pop("check.agent-behavior-evals")
    # Write a catalog that lacks the eval entry, then verify against it.
    broken = repo / "artifacts" / "commands_missing_eval.json"
    broken.write_text(json.dumps(commands), encoding="utf-8")
    args.commands = str(broken)
    bundle_path = _verify(args, bundle_path)

    bundle = EvidenceBundle.model_validate(json.loads(Path(bundle_path).read_text(encoding="utf-8")))
    catalog = json.loads(Path(CATALOG).read_text(encoding="utf-8"))
    policy = json.loads(Path(POLICY).read_text(encoding="utf-8"))
    result = decide(bundle, catalog, policy, ArtifactStore(repo / "artifacts"))
    assert result.decision == "INCOMPLETE", result.reasons
    eval_check = next(c for c in bundle.checks if c.check_id == "agent-behavior-evals")
    assert eval_check.status == CheckStatus.UNSUPPORTED


def test_workflow_style_output_flag_does_not_crash_the_gate(repo, capsys):
    """Regression (CT-1, FATAL): the GitHub Actions workflow invokes
    `clca run --output artifacts/decision.json`.  All four stages historically
    shared that one path: `_verify` saved the sealed bundle there, `_decide`
    overwrote it with the decision payload, and `_report` re-loaded it as an
    EvidenceBundle -> 8 pydantic validation errors -> exit 3.  Exit 3 is not
    a decision exit code, so the workflow's enforce step failed every PR.

    The contract asserted here: with --output given, `run` must terminate
    with PASS/WARN=0, BLOCK=1, INCOMPLETE=2 (never 3), the --output file must
    be the decision payload (has "decision"), and the evidence bundle must
    survive at a separate path so the report stage can load it.
    """
    base = _head(repo)
    target = repo / "backend" / "services" / "pricing.py"
    target.write_text(target.read_text(encoding="utf-8") + "\n# cosmetic comment\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "comment")

    out = repo / "artifacts" / "decision.json"
    code = main([
        "run", "--repo", str(repo), "--base", base,
        "--catalog", str(CATALOG), "--policy", str(POLICY), "--commands", str(COMMANDS),
        "--budget-seconds", "60",
        "--output", str(out),  # exactly as .github/workflows/clca.yml passes it
    ])
    assert code in (0, 1, 2), (
        f"clca run must terminate with a decision exit code, got {code} "
        "(3 = indeterminate pipeline failure; this broke every PR gate)"
    )
    # --output holds the decision payload the enforce step consumes.
    decision = json.loads(out.read_text(encoding="utf-8"))
    assert decision["decision"] in ("PASS", "WARN", "BLOCK", "INCOMPLETE")
    assert "reasons" in decision and "bundle_context" in decision
    # The sealed bundle still exists and loads as a bundle (the report stage
    # depends on re-loading it from its own path).
    bundles = list((repo / "artifacts").glob("*.bundle.json"))
    assert bundles, "evidence bundle must be written to its own path"
    bundle = EvidenceBundle.model_validate(json.loads(bundles[-1].read_text(encoding="utf-8")))
    assert bundle.bundle_digest
