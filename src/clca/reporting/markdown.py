"""Human-readable Markdown report.

Bundle-controlled strings are untrusted (they can originate from pull-request
content), so they are escaped and length-limited before rendering.
"""
from __future__ import annotations

import re

from ..models import EvidenceBundle
from ..policy import DecisionResult

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MAX_CELL = 240


def _safe(text: object, limit: int = _MAX_CELL) -> str:
    cleaned = _CONTROL.sub("", str(text))
    cleaned = cleaned.replace("<", "‹").replace(">", "›")
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1] + "…"
    return cleaned.replace("|", "\\|").replace("\n", " ")


def render_markdown(bundle: EvidenceBundle, result: DecisionResult) -> str:
    lines: list[str] = []
    lines.append(f"# CLCA decision: **{_safe(result.decision, 20)}**")
    lines.append("")
    lines.append(
        f"- Repository: `{_safe(bundle.change.repository)}`  \n"
        f"- Base: `{_safe(bundle.change.base_revision, 16)}` → Head: `{_safe(bundle.change.head_revision, 16)}`  \n"
        f"- Diff digest: `{_safe(bundle.change.diff_digest, 80)}`  \n"
        f"- Policy: `{_safe(bundle.policy_id)}` v{_safe(bundle.policy_version)} (`{_safe(bundle.policy_digest, 80)}`)  \n"
        f"- Bundle digest: `{_safe(bundle.bundle_digest or 'unsealed', 80)}`"
    )
    lines.append("")
    lines.append(
        f"Mandatory checks satisfied: {result.mandatory_checks_satisfied}/"
        f"{result.mandatory_checks_total} · blocking gaps: {result.blocking_gaps} · "
        f"non-blocking gaps: {result.nonblocking_gaps}"
    )
    lines.append("")
    lines.append("> This is a scoped, evidence-bound policy outcome for the exact inputs above — not a guarantee of system safety.")
    lines.append("")

    if bundle.policy_findings:
        lines.append("## Policy findings")
        lines.append("")
        lines.append("| Rule | Action | Summary |")
        lines.append("|---|---|---|")
        for finding in bundle.policy_findings:
            lines.append(f"| `{_safe(finding.rule_id)}` | {_safe(finding.action, 12)} | {_safe(finding.summary)} |")
        lines.append("")

    if bundle.checks:
        lines.append("## Checks")
        lines.append("")
        lines.append("| Check | Requirement | Status | Duration | Artifacts |")
        lines.append("|---|---|---|---|---|")
        for check in bundle.checks:
            duration = f"{check.duration_ms} ms" if check.duration_ms is not None else "—"
            lines.append(
                f"| `{_safe(check.check_id)}` | {_safe(check.requirement.value, 12)} | "
                f"{_safe(check.status.value, 14)} | {duration} | {len(check.artifact_refs)} |"
            )
        lines.append("")

    if bundle.coverage_gaps:
        lines.append("## Coverage gaps")
        lines.append("")
        lines.append("| Gap | Kind | Severity | Blocks PASS | Why it matters |")
        lines.append("|---|---|---|---|---|")
        for gap in bundle.coverage_gaps:
            blocks = "yes" if (gap.blocking or gap.required) else "no"
            lines.append(
                f"| `{_safe(gap.gap_id)}` | {_safe(gap.kind, 22)} | {_safe(gap.severity, 10)} | "
                f"{blocks} | {_safe(gap.why_it_matters)} |"
            )
        lines.append("")

    if bundle.plan and bundle.plan.get("excluded_checks"):
        lines.append("## Checks excluded by budget")
        lines.append("")
        for item in bundle.plan["excluded_checks"]:
            lines.append(f"- `{_safe(item['check_id'])}` — {_safe(item['reason'])}")
        lines.append("")

    lines.append("## Reasons")
    lines.append("")
    for reason in result.reasons:
        lines.append(f"- {_safe(reason, 400)}")
    lines.append("")
    return "\n".join(lines)
