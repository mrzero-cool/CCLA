"""Tests for SLO monitoring (P2.4)."""
from __future__ import annotations

from datetime import datetime, timezone

from clca.slo import SLOMonitor, SLOTarget, slo_monitor, slo_check


def test_slo_target_creation():
    target = SLOTarget(
        name="test-slo",
        description="Test SLO",
        target=0.99,
        window_minutes=60,
    )
    assert target.name == "test-slo"
    assert target.target == 0.99
    assert target.current == 0.0
    assert target.breached is False


def test_slo_availability_calculation():
    monitor = SLOMonitor()
    # Record 100 requests, 95 successful (2xx), 5 failed (5xx)
    for _ in range(95):
        monitor.request_counts["/api/v1/runs"]["200"] += 1
    for _ in range(5):
        monitor.request_counts["/api/v1/runs"]["500"] += 1

    availability = monitor._availability()
    assert availability == 0.95


def test_slo_breach_detection():
    monitor = SLOMonitor()
    # All requests fail → availability = 0 < 0.999 target → breached
    for _ in range(100):
        monitor.request_counts["/api/v1/runs"]["500"] += 1

    report = monitor.evaluate()
    availability_slo = next(s for s in report["slo_targets"] if s["name"] == "control-plane-availability")
    assert availability_slo["breached"] is True
    assert report["overall_healthy"] is False


def test_slo_healthy_when_all_passing():
    monitor = SLOMonitor()
    # All requests succeed with fast latency
    for _ in range(100):
        monitor.request_counts["/api/v1/runs"]["200"] += 1
        monitor.latencies["/api/v1/runs"].append(50.0)  # 50ms, well under 10s
    # All runs succeed
    monitor.run_decisions["PASS"] = 50

    report = monitor.evaluate()
    assert report["overall_healthy"] is True


def test_slo_check_helper():
    """slo_check() returns bool for a named SLO."""
    result = slo_check("control-plane-availability")
    assert isinstance(result, bool)


def test_slo_stuck_runs():
    monitor = SLOMonitor()
    monitor.run_decisions["PASS"] = 10
    monitor.run_decisions["BLOCK"] = 5
    # Mark 2 runs as stuck
    monitor.stuck_runs["run-1"] = datetime.now(timezone.utc)
    monitor.stuck_runs["run-2"] = datetime.now(timezone.utc)

    report = monitor.evaluate()
    stuck_slo = next(s for s in report["slo_targets"] if s["name"] == "no-silent-stuck-jobs")
    # 15 total runs, 2 stuck → 13/15 = 0.867 < 1.0 → breached
    assert stuck_slo["breached"] is True
    assert abs(stuck_slo["current"] - 13 / 15) < 0.001
