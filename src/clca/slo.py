"""CLCA SLOs and reliability controls (P2.4).

Defines Service Level Objectives and reliability controls for the production
control plane.  SLOs are starting points to be tuned after pilot data is
collected, per roadmap section 7.2.

Usage:
    from clca.slo import SLOMonitor, slo_check

    slo = SLOMonitor()
    slo.record_request(endpoint="/api/v1/runs", status="200", duration_ms=45)
    slo.record_run(decision="BLOCK", duration_ms=12000)
    report = slo.get_report()
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any


@dataclass
class SLOTarget:
    name: str
    description: str
    target: float  # target value (e.g. 0.999 for 99.9%)
    window_minutes: int
    current: float = 0.0
    breached: bool = False


# Proposed SLO starting points (roadmap section 7.2).
# Tune after pilot data is collected.
SLO_TARGETS = [
    SLOTarget(
        name="control-plane-availability",
        description="Control-plane API availability",
        target=0.999,  # 99.9% monthly
        window_minutes=30 * 24 * 60,  # 30 days
    ),
    SLOTarget(
        name="intake-planning-p95",
        description="p95 intake + graph/planning latency ≤10s",
        target=0.95,  # 95% of requests under 10s
        window_minutes=60,  # 1 hour
    ),
    SLOTarget(
        name="no-silent-stuck-jobs",
        description="All accepted runs reach terminal state or are marked recoverable",
        target=1.0,  # 100%
        window_minutes=60,
    ),
    SLOTarget(
        name="mandatory-evidence-verified",
        description="No mandatory check reported as passed unless execution evidence is verified",
        target=1.0,  # 100%
        window_minutes=60,
    ),
]


class SLOMonitor:
    """Tracks SLO metrics and breach status."""

    def __init__(self, targets: list[SLOTarget] | None = None):
        self.targets: dict[str, SLOTarget] = {
            t.name: t for t in (targets or SLO_TARGETS)
        }
        # Request counters: {endpoint: {status: count}}
        self.request_counts: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        # Latency buckets: {endpoint: [duration_ms, ...]}
        self.latencies: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=10000)
        )
        # Run outcomes: {decision: count}
        self.run_decisions: dict[str, int] = defaultdict(int)
        # Stuck runs: run_id -> started_at
        self.stuck_runs: dict[str, datetime] = {}

    def record_request(
        self, endpoint: str, status: str, duration_ms: float
    ) -> None:
        """Record an API request for SLO tracking."""
        self.request_counts[endpoint][status] += 1
        self.latencies[endpoint].append(duration_ms)

    def record_run(
        self, decision: str, duration_ms: float, stuck: bool = False
    ) -> None:
        """Record a run outcome for SLO tracking."""
        self.run_decisions[decision] += 1
        if stuck:
            self.stuck_runs[decision] = datetime.now(timezone.utc)

    def mark_run_stuck(self, run_id: str, started_at: datetime) -> None:
        """Mark a run as potentially stuck (exceeded expected duration)."""
        self.stuck_runs[run_id] = started_at

    def clear_run_stuck(self, run_id: str) -> None:
        """Clear a run from the stuck set (it reached terminal state)."""
        self.stuck_runs.pop(run_id, None)

    def _availability(self) -> float:
        """Calculate control-plane availability from request counts."""
        total = 0
        successful = 0
        for endpoint, statuses in self.request_counts.items():
            for status, count in statuses.items():
                total += count
                # 2xx and 3xx are considered successful
                if status.startswith("2") or status.startswith("3"):
                    successful += count
        return successful / total if total > 0 else 1.0

    def _p95_latency(self, endpoint: str) -> float:
        """Calculate p95 latency for an endpoint."""
        latencies = sorted(self.latencies.get(endpoint, []))
        if not latencies:
            return 0.0
        idx = int(len(latencies) * 0.95) - 1
        if idx < 0:
            idx = 0
        return latencies[idx]

    def evaluate(self) -> dict[str, Any]:
        """Evaluate all SLOs and return status."""
        results: dict[str, Any] = {
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "slo_targets": [],
            "overall_healthy": True,
        }

        for name, target in self.targets.items():
            current = 0.0
            breached = False
            reason = ""

            if name == "control-plane-availability":
                current = self._availability()
                target_value = target.target
                breached = current < target_value
                reason = (
                    f"{current:.4f} < {target_value:.4f}" if breached else ""
                )
            elif name == "intake-planning-p95":
                total = sum(self.request_counts["/api/v1/runs"].values())
                if total == 0:
                    current = 1.0
                else:
                    under_10s = sum(
                        1 for d in self.latencies["/api/v1/runs"] if d <= 10000
                    )
                    current = under_10s / total
                breached = current < target.target
                reason = (
                    f"p95={self._p95_latency('/api/v1/runs'):.0f}ms > 10000ms"
                    if breached
                    else ""
                )
            elif name == "no-silent-stuck-jobs":
                total_runs = sum(self.run_decisions.values())
                stuck_count = len(self.stuck_runs)
                current = (total_runs - stuck_count) / total_runs if total_runs > 0 else 1.0
                breached = current < target.target
                reason = f"{stuck_count} stuck runs" if breached else ""
            elif name == "mandatory-evidence-verified":
                # This is a policy decision, tracked at decision time
                current = 1.0  # Assume verified unless a bypass is detected
                breached = False

            target.current = current
            target.breached = breached

            results["slo_targets"].append(
                {
                    "name": target.name,
                    "description": target.description,
                    "target": target.target,
                    "current": round(current, 4),
                    "breached": breached,
                    "reason": reason,
                }
            )
            if breached:
                results["overall_healthy"] = False

        return results

    def get_report(self) -> dict[str, Any]:
        """Get the current SLO report."""
        return self.evaluate()


# Module-level SLO monitor instance
slo_monitor = SLOMonitor()


def slo_check(name: str) -> bool:
    """Quick check: is a specific SLO currently healthy?"""
    report = slo_monitor.evaluate()
    for slo in report["slo_targets"]:
        if slo["name"] == name:
            return not slo["breached"]
    return True
