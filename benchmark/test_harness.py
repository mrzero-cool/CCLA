"""Tests for the CLCA benchmark harness (P1B.1)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from benchmark.harness import (
    TOOL_CONFIGS,
    apply_scenario_to_repo,
    compute_summary_metrics,
    init_benchmark_repo,
    load_scenarios,
    run_benchmark,
)


def test_load_scenarios_returns_48():
    scenarios = load_scenarios()
    assert len(scenarios) == 48
    ids = {s["scenario_id"] for s in scenarios}
    assert ids == {f"S{i:03d}" for i in range(1, 49)}


def test_init_benchmark_repo_creates_git_repo(tmp_path):
    repo = init_benchmark_repo(tmp_path)
    assert repo.is_dir()
    assert (repo / ".git").is_dir()
    assert (repo / "backend" / "services" / "pricing.py").is_file()


def test_apply_scenario_to_repo_changes_files(tmp_path):
    repo = init_benchmark_repo(tmp_path)
    scenario = {
        "scenario_id": "S999",
        "name": "test scenario",
        "changed_asset_kinds": ["code.function", "docs"],
    }
    apply_scenario_to_repo(repo, scenario)

    # Files should have been modified (commit exists after apply).
    import subprocess
    result = subprocess.run(["git", "log", "--oneline", "-1"], cwd=repo,
                            capture_output=True, text=True, check=True)
    assert "benchmark scenario edit" in result.stdout or "benchmark:" in result.stdout


def test_compute_summary_metrics_empty():
    summary = compute_summary_metrics([])
    assert "error" in summary


def test_compute_summary_metrics_with_results():
    results = [
        {
            "scenario_id": "S001",
            "scenario_name": "docs-only-change",
            "scenario_family": "safe_low_impact",
            "expected_status": "PASS",
            "expected_mandatory_checks": ["static-manifest-validation"],
            "tool": "clca_integrated_verification",
            "decision": "PASS",
            "duration_ms": 100,
        },
        {
            "scenario_id": "S002",
            "scenario_name": "comment-only-python-change",
            "scenario_family": "safe_low_impact",
            "expected_status": "PASS",
            "expected_mandatory_checks": ["static-manifest-validation"],
            "tool": "clca_integrated_verification",
            "decision": "BLOCK",
            "duration_ms": 200,
        },
        {
            "scenario_id": "S003",
            "scenario_name": "format-only-python-change",
            "scenario_family": "safe_low_impact",
            "expected_status": "PASS",
            "expected_mandatory_checks": ["static-manifest-validation", "python-unit-tests"],
            "tool": "clca_integrated_verification",
            "decision": None,
            "duration_ms": 300,
        },
    ]
    summary = compute_summary_metrics(results)
    assert summary["total_results"] == 3
    assert summary["clca_integrated"]["correct_decisions"] == 1
    assert summary["clca_integrated"]["incorrect_decisions"] == 1
    assert summary["clca_integrated"]["unknown_decisions"] == 1
    assert abs(summary["clca_integrated"]["accuracy"] - 1 / 3) < 0.0001
    assert summary["duration_ms"]["clca_integrated_p50"] == 200.0


def test_run_benchmark_small_subset(tmp_path):
    """Run the harness on a tiny subset to verify end-to-end flow."""
    scenarios = [
        {
            "scenario_id": "S001",
            "family": "safe_low_impact",
            "name": "docs-only-change",
            "expected_status": "PASS",
            "changed_asset_kinds": ["docs"],
            "expected_mandatory_checks": ["static-manifest-validation"],
            "seeded_fault": False,
        },
    ]
    output_path = tmp_path / "results.jsonl"
    results = run_benchmark(scenarios, output_path)

    assert len(results) == len(TOOL_CONFIGS := ["baseline_full_applicable_suite",
                                                 "native_test_selector",
                                                 "best_applicable_existing_tool",
                                                 "clca_static_only",
                                                 "clca_integrated_verification"])
    for r in results:
        assert r["scenario_id"] == "S001"
        assert r["tool"] in TOOL_CONFIGS
        assert "timestamp" in r
        assert output_path.is_file()


def test_compute_summary_metrics_duration_percentiles():
    results = [
        {
            "scenario_id": "S001",
            "scenario_name": "s1",
            "scenario_family": "safe",
            "expected_status": "PASS",
            "expected_mandatory_checks": [],
            "tool": "clca_integrated_verification",
            "decision": "PASS",
            "duration_ms": 100,
        },
        {
            "scenario_id": "S002",
            "scenario_name": "s2",
            "scenario_family": "safe",
            "expected_status": "PASS",
            "expected_mandatory_checks": [],
            "tool": "clca_integrated_verification",
            "decision": "PASS",
            "duration_ms": 200,
        },
        {
            "scenario_id": "S003",
            "scenario_name": "s3",
            "scenario_family": "safe",
            "expected_status": "PASS",
            "expected_mandatory_checks": [],
            "tool": "clca_integrated_verification",
            "decision": "PASS",
            "duration_ms": 300,
        },
        {
            "scenario_id": "S004",
            "scenario_name": "s4",
            "scenario_family": "safe",
            "expected_status": "PASS",
            "expected_mandatory_checks": [],
            "tool": "clca_integrated_verification",
            "decision": "PASS",
            "duration_ms": 400,
        },
    ]
    summary = compute_summary_metrics(results)
    assert summary["duration_ms"]["clca_integrated_p50"] == 250.0
    assert summary["duration_ms"]["clca_integrated_p95"] == 385.0
