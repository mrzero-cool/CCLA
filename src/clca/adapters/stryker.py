"""Stryker mutation testing adapter — measures test-suite effectiveness.

Stryker deliberately introduces small code changes (mutants) and checks whether the
test suite detects them.  CLCA uses this to answer: "do our selected checks actually
catch defects?"  A mutation score below threshold makes a mandatory check INCOMPLETE
(test evidence is insufficient to prove correctness).

This adapter reads Stryker's mutation test report (JSON) and normalizes it into UCEM:
evidence records with mutation_score per check, plus coverage gaps for low scores.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ..digest import digest_obj
from ..intake import ChangeManifest
from .base import Adapter, AdapterResult, make_evidence, relationship_id
from ..models import Asset, AssetKind, CoverageGap, Relationship

logger = logging.getLogger("clca.adapters.stryker")

# Mutation score threshold below which a check is considered INCOMPLETE
DEFAULT_MUTATION_THRESHOLD = 0.70


class StrykerAdapter(Adapter):
    """Reads Stryker mutation report and normalizes to UCEM evidence."""

    name = "stryker"
    version = "0.4.0"

    def __init__(
        self,
        report_path: Path | str | None = None,
        mutation_threshold: float = DEFAULT_MUTATION_THRESHOLD,
    ) -> None:
        self.report_path = Path(report_path) if report_path else None
        self.mutation_threshold = mutation_threshold

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()

        if self.report_path is None or not self.report_path.is_file():
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:stryker:missing",
                    kind="missing_required_test",
                    severity="medium",
                    subject_refs=[manifest.head_revision],
                    why_it_matters="Stryker mutation report not found; test-suite "
                    "effectiveness cannot be measured.  Mandatory checks may be "
                    "marked INCOMPLETE.",
                    blocking=False,
                    required=False,
                    remediation="Run Stryker mutation testing and point "
                    "--stryker-report at the output JSON file.",
                )
            )
            return result

        try:
            data = json.loads(self.report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Stryker report unreadable: %s", exc)
            result.gaps.append(
                CoverageGap(
                    gap_id="gap:adapter:stryker:unreadable",
                    kind="runner_unavailable",
                    severity="high",
                    subject_refs=[manifest.head_revision],
                    why_it_matters=f"Stryker mutation report could not be parsed: {exc}",
                    blocking=False,
                    required=False,
                    remediation="Re-run Stryker mutation testing and verify JSON validity.",
                )
            )
            return result

        # Stryker report structure (simplified):
        # {
        #   "files": {
        #     "src/foo.js": {
        #       "mutants": [
        #         {"id": 1, "status": "killed", "mutator": "ArithmeticOperator"},
        #         {"id": 2, "status": "survived", "mutator": "EqualityOperator"},
        #       ]
        #     }
        #   },
        #   "stats": { "killed": 10, "survived": 5, "timeout": 2, "total": 17 }
        # }
        files = data.get("files", {})
        stats = data.get("stats", {})

        total_mutants = int(stats.get("total", 0))
        killed = int(stats.get("killed", 0))
        survived = int(stats.get("survived", 0))
        timed_out = int(stats.get("timeout", 0))

        mutation_score = killed / total_mutants if total_mutants > 0 else 0.0

        # Per-file mutation breakdown
        per_file: dict[str, dict[str, int]] = {}
        for file_path, file_data in files.items():
            file_mutants = file_data.get("mutants", [])
            f_killed = sum(1 for m in file_mutants if m.get("status") == "killed")
            f_survived = sum(1 for m in file_mutants if m.get("status") == "survived")
            f_timeout = sum(1 for m in file_mutants if m.get("status") == "timeout")
            per_file[file_path] = {
                "killed": f_killed,
                "survived": f_survived,
                "timeout": f_timeout,
                "total": len(file_mutants),
            }

        # Assets: each mutated file becomes a code.function asset
        for file_path, counts in per_file.items():
            asset = Asset(
                asset_id=f"stryker:{digest_obj([file_path])[7:19]}",
                kind=AssetKind.CODE_FUNCTION,
                name=file_path,
                repository=manifest.repository,
                path=file_path,
                revision=manifest.head_revision,
                criticality="high" if counts["total"] > 0 else "medium",
                identity_status="adapter_scoped",
                attributes={
                    "source": "stryker",
                    "mutants_killed": counts["killed"],
                    "mutants_survived": counts["survived"],
                    "mutants_timeout": counts["timeout"],
                    "mutation_score": counts["killed"] / counts["total"] if counts["total"] > 0 else 0.0,
                },
            )
            result.assets.append(asset)

        # If overall mutation score is below threshold, add a coverage gap
        if mutation_score < self.mutation_threshold:
            result.gaps.append(
                CoverageGap(
                    gap_id=f"gap:stryker:low_score:{manifest.head_revision[:12]}",
                    kind="missing_required_test",
                    severity="high",
                    subject_refs=[manifest.head_revision],
                    why_it_matters=(
                        f"Mutation score {mutation_score:.0%} is below threshold "
                        f"{self.mutation_threshold:.0%}.  Selected checks may not "
                        "detect defects introduced by this change."
                    ),
                    blocking=False,
                    required=True,
                    remediation="Improve test coverage or add mutation-killing tests "
                    "before the change can be considered verified.",
                )
            )

        # Evidence: mutation score itself
        input_digest = digest_obj(
            [str(self.report_path), manifest.head_revision, str(total_mutants), str(killed)]
        )
        result.evidence.append(
            make_evidence(
                adapter="stryker",
                evidence_type="mutation_test_report",
                subject_refs=[manifest.head_revision],
                observed_revision=manifest.head_revision,
                input_digest=input_digest,
                support="direct",
                limitations=[
                    "Mutation testing measures test effectiveness, not correctness",
                    "Mutant selection may not cover all defect types",
                ],
            )
        )

        result.facts["stryker_total_mutants"] = total_mutants
        result.facts["stryker_killed"] = killed
        result.facts["stryker_survived"] = survived
        result.facts["stryker_timeout"] = timed_out
        result.facts["stryker_mutation_score"] = mutation_score
        result.facts["stryker_threshold"] = self.mutation_threshold
        result.facts["stryker_below_threshold"] = mutation_score < self.mutation_threshold
        return result


def load_stryker_adapter(
    report_path: Path | str | None = None,
    mutation_threshold: float = DEFAULT_MUTATION_THRESHOLD,
) -> StrykerAdapter:
    return StrykerAdapter(report_path=report_path, mutation_threshold=mutation_threshold)
