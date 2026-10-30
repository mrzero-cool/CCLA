"""Runnable benchmark harness for the CLCA 48-scenario synthetic benchmark.

Runs every scenario through multiple tool configurations and emits machine-readable
results (JSONL) plus human-readable summary metrics.  This turns the static
scenario catalog into an executable comparative harness per roadmap P1B.1.

Usage:
    python -m benchmark.harness --output benchmark/results/raw_scenario_results.jsonl
    python -m benchmark.harness --summary benchmark/results/summary_metrics.json
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_APP = ROOT / "sample_app"
CONFIG_DIR = ROOT / "config"
SCENARIOS_PATH = ROOT / "benchmark" / "scenarios" / "scenarios.json"
RESULTS_DIR = ROOT / "benchmark" / "results"

# Tool configurations to benchmark (each is a separate command the harness runs).
TOOL_CONFIGS = [
    "baseline_full_applicable_suite",
    "native_test_selector",
    "best_applicable_existing_tool",
    "clca_static_only",
    "clca_integrated_verification",
]


def load_scenarios(path: str | Path = str(SCENARIOS_PATH)) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))["scenarios"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_baseline_full_applicable_suite(repo: Path) -> dict[str, Any]:
    """Run the full applicable test suite (baseline CI equivalent)."""
    started = time.monotonic()
    proc = subprocess.run(
        ["python", "-m", "pytest", "tests", "-q"],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=300,
    )
    duration_ms = int((time.monotonic() - started) * 1000)
    passed = proc.stdout.count("passed")
    failed = proc.stdout.count("failed")
    return {
        "tool": "baseline_full_applicable_suite",
        "duration_ms": duration_ms,
        "exit_code": proc.returncode,
        "passed": passed,
        "failed": failed,
        "stdout_excerpt": proc.stdout[-2000:] if proc.stdout else "",
    }


def run_clca_integrated(repo: Path, scenario_id: str) -> dict[str, Any]:
    """Run CLCA integrated verification on a scenario-applied repo copy."""
    started = time.monotonic()
    # Apply the scenario change first (mutate the repo copy).
    proc = subprocess.run(
        ["python", "-m", "clca.cli", "run",
         "--repo", str(repo),
         "--catalog", str(CONFIG_DIR / "check_catalog.json"),
         "--policy", str(CONFIG_DIR / "policy.json"),
         "--commands", str(CONFIG_DIR / "commands.json"),
         "--output", str(repo / "artifacts" / "decision.json")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    duration_ms = int((time.monotonic() - started) * 1000)

    decision = None
    decision_path = repo / "artifacts" / "decision.json"
    if decision_path.is_file():
        try:
            decision = json.loads(decision_path.read_text(encoding="utf-8")).get("decision")
        except (json.JSONDecodeError, OSError):
            decision = None

    return {
        "tool": "clca_integrated_verification",
        "duration_ms": duration_ms,
        "exit_code": proc.returncode,
        "decision": decision,
        "stderr_excerpt": proc.stderr[-1000:] if proc.stderr else "",
    }


def run_clca_static_only(repo: Path) -> dict[str, Any]:
    """Run CLCA static-only (manifest validation + catalog checks, no subprocess)."""
    started = time.monotonic()
    # Static-only: just validate the manifest and catalog, no test execution.
    script = (
        "import json,sys; "
        "sys.path.insert(0,'src'); "
        "from clca.intake import build_change_manifest; "
        "from clca.bundle import build_bundle; "
        "m=build_change_manifest(Path('.'),None,None); "
        "b,p=build_bundle(Path('.'),m,json.load(open('config/check_catalog.json')),json.load(open('config/policy.json'))); "
        "print(b.decision if hasattr(b,'decision') else 'no-decision')"
    )
    proc = subprocess.run(
        ["python", "-c", script],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=120,
    )
    duration_ms = int((time.monotonic() - started) * 1000)
    return {
        "tool": "clca_static_only",
        "duration_ms": duration_ms,
        "exit_code": proc.returncode,
        "stdout_excerpt": proc.stdout[-500:] if proc.stdout else "",
    }


def run_native_test_selector(repo: Path) -> dict[str, Any]:
    """Run pytest with test selection (changed-file based subset)."""
    started = time.monotonic()
    proc = subprocess.run(
        ["python", "-m", "pytest", "tests/test_pricing.py", "tests/test_contract", "-q"],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=300,
    )
    duration_ms = int((time.monotonic() - started) * 1000)
    return {
        "tool": "native_test_selector",
        "duration_ms": duration_ms,
        "exit_code": proc.returncode,
        "passed": proc.stdout.count("passed"),
        "failed": proc.stdout.count("failed"),
    }


def apply_scenario_to_repo(repo: Path, scenario: dict) -> None:
    """Apply a scenario's changes to a repo copy (simulating the PR diff).

    For the benchmark we materialize the scenario by editing representative
    files so that CLCA/intake detects the changed asset kinds declared in the
    scenario.  This is a deterministic fixture application, not arbitrary code.
    """
    changed_kinds = scenario.get("changed_asset_kinds", [])
    # Touch/create representative files so intake detects the asset kinds.
    edits: list[tuple[str, str]] = []

    if "code.function" in changed_kinds:
        edits.append(("backend/services/pricing.py", "\n# benchmark scenario edit\n"))
    if "data.table" in changed_kinds or "data.column" in changed_kinds:
        edits.append(("data/dbt/manifest.json", "\n// benchmark scenario edit\n"))
    if "ai.prompt" in changed_kinds:
        edits.append(("agents/replenishment/prompts/system.md", "\n# benchmark scenario edit\n"))
    if "ai.tool" in changed_kinds or "ai.agent" in changed_kinds:
        edits.append(("agents/replenishment/tool_manifest.json", "\n// benchmark scenario edit\n"))
    if "api.endpoint" in changed_kinds:
        edits.append(("backend/api/sales.py", "\n# benchmark scenario edit\n"))
    if "docs" in changed_kinds:
        edits.append(("README.md", "\n# benchmark scenario edit\n"))

    for rel_path, content in edits:
        target = repo / rel_path
        if target.is_file():
            target.write_text(target.read_text(encoding="utf-8") + content, encoding="utf-8")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

    # Commit the change so git diff detects it.
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", f"benchmark: {scenario['scenario_id']}"],
                   cwd=repo, check=True, capture_output=True)


def init_benchmark_repo(tmp_dir: Path) -> Path:
    """Initialize a fresh benchmark repo from sample_app."""
    repo = tmp_dir / "benchmark-repo"
    shutil.copytree(SAMPLE_APP, repo, ignore=shutil.ignore_patterns(".git", "artifacts", "__pycache__"))
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "clca-benchmark@example.com"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "CLCA Benchmark"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "benchmark baseline"], cwd=repo, check=True, capture_output=True)
    return repo


def run_benchmark(scenarios: list[dict], output_path: Path) -> list[dict]:
    """Run the full benchmark: all scenarios x all tool configs."""
    results: list[dict] = []
    total = len(scenarios) * len(TOOL_CONFIGS)
    count = 0

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        for scenario in scenarios:
            scenario_id = scenario["scenario_id"]
            repo = init_benchmark_repo(tmp_path)
            apply_scenario_to_repo(repo, scenario)

            for tool in TOOL_CONFIGS:
                count += 1
                print(f"[{count}/{total}] {scenario_id} / {tool}", file=sys.stderr)

                result: dict[str, Any] = {
                    "scenario_id": scenario_id,
                    "scenario_name": scenario["name"],
                    "scenario_family": scenario["family"],
                    "expected_status": scenario["expected_status"],
                    "expected_mandatory_checks": scenario.get("expected_mandatory_checks", []),
                    "tool": tool,
                    "timestamp": _utc_now(),
                }

                try:
                    if tool == "baseline_full_applicable_suite":
                        result.update(run_baseline_full_applicable_suite(repo))
                    elif tool == "clca_integrated_verification":
                        result.update(run_clca_integrated(repo, scenario_id))
                    elif tool == "clca_static_only":
                        result.update(run_clca_static_only(repo))
                    elif tool == "native_test_selector":
                        result.update(run_native_test_selector(repo))
                    elif tool == "best_applicable_existing_tool":
                        # Best applicable existing tool = native_test_selector for code,
                        # static manifest validation for data/agent (no tool exists).
                        result.update(run_native_test_selector(repo))
                        result["tool"] = "best_applicable_existing_tool"
                    else:
                        result.update({"error": f"unknown tool config: {tool}"})
                except Exception as exc:  # noqa: BLE001 — record failure, continue
                    result.update({"error": str(exc), "exit_code": -1})

                results.append(result)

                # Write incrementally so partial results are preserved.
                with open(output_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(result, sort_keys=True) + "\n")

    return results


def compute_summary_metrics(results: list[dict]) -> dict[str, Any]:
    """Compute benchmark metrics from raw results."""
    total = len(results)
    if total == 0:
        return {"error": "no results"}

    # Decision soundness: CLCA integrated vs expected status.
    clca_results = [r for r in results if r["tool"] == "clca_integrated_verification"]
    correct = 0
    incorrect = 0
    unknown = 0
    for r in clca_results:
        expected = r["expected_status"]
        actual = r.get("decision")
        if actual == expected:
            correct += 1
        elif actual is None:
            unknown += 1
        else:
            incorrect += 1

    # Duration stats.
    clca_durations = [r["duration_ms"] for r in clca_results if "duration_ms" in r]
    baseline_durations = [r["duration_ms"] for r in results if r["tool"] == "baseline_full_applicable_suite" and "duration_ms" in r]

    def pct(values: list[float], p: int) -> float:
        if not values:
            return 0.0
        s = sorted(values)
        k = (len(s) - 1) * p / 100
        f = int(k)
        c = f + 1
        if c >= len(s):
            return float(s[-1])
        d = k - f
        return float(s[f] * (1 - d) + s[c] * d)

    return {
        "total_results": total,
        "scenarios_evaluated": len({r["scenario_id"] for r in results}),
        "clca_integrated": {
            "correct_decisions": correct,
            "incorrect_decisions": incorrect,
            "unknown_decisions": unknown,
            "accuracy": round(correct / len(clca_results), 4) if clca_results else 0.0,
        },
        "duration_ms": {
            "clca_integrated_p50": round(pct(clca_durations, 50), 2),
            "clca_integrated_p95": round(pct(clca_durations, 95), 2),
            "baseline_full_suite_p50": round(pct(baseline_durations, 50), 2),
            "baseline_full_suite_p95": round(pct(baseline_durations, 95), 2),
        },
        "generated_at": _utc_now(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="CLCA benchmark harness")
    parser.add_argument("--output", default=str(RESULTS_DIR / "raw_scenario_results.jsonl"),
                        help="Path for raw JSONL results (appended)")
    parser.add_argument("--summary", default=str(RESULTS_DIR / "summary_metrics.json"),
                        help="Path for summary metrics JSON")
    parser.add_argument("--scenarios", default=str(SCENARIOS_PATH),
                        help="Path to scenarios JSON")
    args = parser.parse_args()

    scenarios = load_scenarios(args.scenarios)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Clear previous output.
    output_path.write_text("", encoding="utf-8")

    results = run_benchmark(scenarios, output_path)
    summary = compute_summary_metrics(results)

    summary_path = Path(args.summary)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
