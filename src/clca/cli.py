"""CLCA CLI: analyze → plan → verify → decide → report."""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .adapter_integration import build_enhanced_plan
from .bundle import build_bundle, compute_sealed_digest
from .intake import IntakeError, build_change_manifest
from .models import CheckStatus, CoverageGap, EvidenceBundle, PolicyFinding
from .observability import SpanAttrs, init_observability
from .policy import decide
from .redact import redact_excerpt
from .reporting import render_markdown
from .runner import (
    AllowListError, ArtifactStore, SubprocessRunner, load_command_catalog, resolve_command,
)

EXIT_CODES = {"PASS": 0, "WARN": 0, "INCOMPLETE": 2, "BLOCK": 1}

# Initialize observability for the CLI (P2.3)
init_observability()


def _read_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return document


def _write_json(payload: dict[str, Any], output: str, allowed_roots: list[Path]) -> None:
    target = Path(output)
    # Reject symlinks at every path component to prevent symlink-based path
    # traversal attacks where a symlink inside an allowed root points outside
    # it, allowing writes to arbitrary host paths.
    if target.is_symlink():
        raise PermissionError(f"refusing to write through symlink: {target}")
    target = target.resolve()
    # Resolve may follow symlinks on parent dirs; re-check after resolution
    if target.is_symlink():
        raise PermissionError(f"refusing to write through symlink: {target}")
    if not any(target.is_relative_to(root.resolve()) for root in allowed_roots):
        raise PermissionError(f"refusing to write outside the repository/artifact roots: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(payload, indent=2, sort_keys=True, default=str)
    target.write_text(redact_excerpt(body, 2_000_000) + "\n", encoding="utf-8")


def _load_bundle(path: Path) -> EvidenceBundle:
    return EvidenceBundle.model_validate(_read_json(path))


def _save_bundle(bundle: EvidenceBundle, path: Path, allowed_roots: list[Path]) -> None:
    _write_json(bundle.model_dump(mode="json"), str(path), allowed_roots)


def _artifact_store(bundle: EvidenceBundle, repo: Path, override: str | None) -> ArtifactStore:
    repo = repo.resolve()
    if override:
        # Explicit CLI overrides are an operator choice, not bundle-controlled.
        root = Path(override).resolve()
    elif bundle.artifact_root:
        # Do not let an untrusted bundle nominate an arbitrary host path.
        root = Path(bundle.artifact_root).resolve()
        if not root.is_relative_to(repo):
            raise PermissionError("bundle artifact_root must be inside the repository; use --artifacts-root for an explicit trusted override")
    else:
        root = (repo / "artifacts").resolve()
    root.mkdir(parents=True, exist_ok=True)
    return ArtifactStore(root)


def _default_bundle_path(repo: Path, bundle: EvidenceBundle) -> Path:
    return repo / "artifacts" / f"{bundle.change.change_id}.bundle.json"


def _analyze(args: argparse.Namespace) -> Path:
    repo = Path(args.repo).resolve()
    catalog = _read_json(Path(args.catalog))
    policy = _read_json(Path(args.policy))
    manifest = build_change_manifest(repo, args.base, args.head)
    bundle, _plan = build_bundle(
        repo, manifest, catalog, policy,
        budget_seconds=args.budget_seconds,
        artifacts_root=str((repo / "artifacts").resolve()),
    )
    output = Path(args.output) if getattr(args, "output", None) else _default_bundle_path(repo, bundle)
    _save_bundle(bundle, output, [repo])
    print(json.dumps({
        "step": "analyze",
        "change_id": bundle.change.change_id,
        "head_revision": bundle.change.head_revision,
        "changed_paths": len(manifest.changed_paths),
        "assets": len(bundle.assets),
        "relationships": len(bundle.relationships),
        "changed_asset_kinds": sorted(bundle.plan["changed_asset_kinds"]) if bundle.plan else [],
        "planned_checks": [c.check_id for c in bundle.checks],
        "policy_findings": [f.rule_id for f in bundle.policy_findings],
        "coverage_gaps": [g.gap_id for g in bundle.coverage_gaps],
        "bundle": str(output),
    }, indent=2))
    return output


def _verify(args: argparse.Namespace, bundle_path: Path) -> Path:
    repo = Path(args.repo).resolve()
    bundle = _load_bundle(bundle_path)
    catalog = _read_json(Path(args.catalog))
    commands = load_command_catalog(Path(args.commands))
    store = _artifact_store(bundle, repo, args.artifacts_root)
    runner = SubprocessRunner(repo, store)
    run_id = f"{bundle.change.change_id}-{uuid.uuid4().hex[:8]}"
    catalog_ids = {spec.get("check_id") for spec in catalog.get("checks", [])}

    for check in bundle.checks:
        if check.check_id not in catalog_ids:
            check.status = CheckStatus.UNSUPPORTED
            check.selection_reason.append("not executed: check_id absent from the version-controlled catalog")
            continue
        if check.status not in (CheckStatus.PLANNED, CheckStatus.NOT_RUN):
            continue
        try:
            spec = resolve_command(commands, check.command_ref or "", check.check_id)
        except AllowListError as exc:
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

    bundle.bundle_digest = compute_sealed_digest(bundle)
    output = bundle_path if not getattr(args, "output", None) else Path(args.output)
    _save_bundle(bundle, output, [repo])
    print(json.dumps({
        "step": "verify",
        "change_id": bundle.change.change_id,
        "results": {c.check_id: c.status.value for c in bundle.checks},
        "bundle": str(output),
    }, indent=2))
    return output


def _decide(args: argparse.Namespace, bundle_path: Path) -> int:
    bundle = _load_bundle(bundle_path)
    catalog = _read_json(Path(args.catalog))
    policy = _read_json(Path(args.policy))
    repo = Path(args.repo).resolve()
    store = _artifact_store(bundle, repo, args.artifacts_root)
    result = decide(bundle, catalog, policy, store)
    bundle.decision = result.decision
    bundle.bundle_digest = compute_sealed_digest(bundle)
    _save_bundle(bundle, bundle_path, [repo])
    payload = result.to_dict()
    payload["bundle_context"] = {
        "repository": bundle.change.repository,
        "head_revision": bundle.change.head_revision,
        "policy_id": bundle.policy_id,
        "policy_digest": bundle.policy_digest,
        "bundle_digest": bundle.bundle_digest,
    }
    if getattr(args, "output", None):
        _write_json(payload, args.output, [repo, store.root])
    print(redact_excerpt(json.dumps(payload, indent=2, sort_keys=True, default=str), 2_000_000))
    return EXIT_CODES[result.decision]


def _report(args: argparse.Namespace, bundle_path: Path) -> int:
    bundle = _load_bundle(bundle_path)
    catalog = _read_json(Path(args.catalog))
    policy = _read_json(Path(args.policy))
    repo = Path(args.repo).resolve()
    store = _artifact_store(bundle, repo, args.artifacts_root)
    result = decide(bundle, catalog, policy, store)
    # Reports can contain strings derived from untrusted repository files.
    # Redact before both stdout and file output, not only in JSON/artifacts.
    markdown = redact_excerpt(render_markdown(bundle, result), 2_000_000)
    if getattr(args, "output", None):
        target = Path(args.output).resolve()
        if not any(target.is_relative_to(root) for root in (repo, store.root)):
            raise PermissionError(f"refusing to write outside allowed roots: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(markdown, encoding="utf-8")
    print(markdown)
    return EXIT_CODES[result.decision]


def cmd_analyze(args: argparse.Namespace) -> int:
    _analyze(args)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    _verify(args, Path(args.bundle))
    return 0


def cmd_decide(args: argparse.Namespace) -> int:
    return _decide(args, Path(args.bundle))


def cmd_report(args: argparse.Namespace) -> int:
    return _report(args, Path(args.bundle))


def cmd_run(args: argparse.Namespace) -> int:
    """Full pipeline: analyze -> verify -> decide -> report.

    Output separation (Chairman CT-1, FATAL): `--output` receives the DECISION
    payload only — the file the workflow's enforce step parses.  The sealed
    evidence bundle is written to its own path (default:
    <repo>/artifacts/<change_id>.bundle.json, or `--bundle-output`), and the
    markdown report goes to stdout (or `--report-output`).  Historically all
    four stages shared one path: `_verify` saved the bundle to `--output`,
    `_decide` overwrote it with the decision payload, and `_report` re-loaded
    that payload as an EvidenceBundle -> 8 pydantic validation errors ->
    exit 3, i.e. the CI gate failed every pull request.

    Adapter integration: after analyze, external tool adapters (AxiomCode,
    Enola, Code System Graph, DataHub, OWASP, Praxen, Stryker, Farol,
    CodeDecay, semctx) are run against the repo.  Their coverage gaps are
    merged into the bundle, their findings become policy findings, and their
    facts promote checks to mandatory.  This happens before verify so the
    decision engine sees all evidence.
    """
    from clca.observability import create_span, set_span_status

    tracer_span = create_span(
        "clca.run",
        {
            SpanAttrs.RUN_ID: getattr(args, "output", "unknown") or "unknown",
            SpanAttrs.REPOSITORY: str(getattr(args, "repo", ".")),
            SpanAttrs.BASE_REVISION: str(getattr(args, "base", "unknown")),
            SpanAttrs.HEAD_REVISION: str(getattr(args, "head", "unknown")),
        },
    )
    try:
        decision_output = getattr(args, "output", None)
        report_output = getattr(args, "report_output", None)
        # Stages 1-2 own the bundle; give them --bundle-output (or the default
        # artifacts path) instead of the decision path.
        args.output = getattr(args, "bundle_output", None)
        bundle_path = _analyze(args)

        # ---- Adapter integration (between analyze and verify) ----
        if not getattr(args, "no_adapters", False):
            repo = Path(args.repo).resolve()
            catalog = _read_json(Path(args.catalog))
            policy = _read_json(Path(args.policy))
            manifest = build_change_manifest(repo, args.base, args.head)
            bundle = _load_bundle(bundle_path)
            base_plan = bundle.plan or {}

            enhanced_plan = build_enhanced_plan(
                repo=repo,
                manifest=manifest,
                base_plan=base_plan,
                adapter_names=getattr(args, "adapters", None),
            )

            # Add adapter-derived policy findings to the bundle.
            for finding in enhanced_plan.get("adapter_findings", []):
                bundle.policy_findings.append(PolicyFinding(
                    rule_id=finding["rule_id"],
                    action=finding["action"],
                    summary=finding["summary"],
                ))

            # Add adapter coverage gaps to the bundle.
            for gap in enhanced_plan.get("coverage_gaps", []):
                # Skip gaps already in the bundle (deduplicate by gap_id).
                existing_ids = {g.gap_id for g in bundle.coverage_gaps}
                if gap.get("gap_id") not in existing_ids:
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

            # Re-seal the bundle with adapter evidence included.
            bundle.bundle_digest = compute_sealed_digest(bundle)
            _save_bundle(bundle, bundle_path, [repo])
            print(json.dumps({
                "step": "adapter-integration",
                "change_id": bundle.change.change_id,
                "adapter_findings": len(enhanced_plan.get("adapter_findings", [])),
                "adapter_gaps": len(enhanced_plan.get("coverage_gaps", [])),
                "adapters_used": list(enhanced_plan.get("adapters_used", {}).keys()),
            }, indent=2))

        bundle_path = _verify(args, bundle_path)
        # Stage 3 writes the decision payload to --output.
        args.output = decision_output
        code = _decide(args, bundle_path)
        # Stage 4 renders markdown; it must never clobber the decision payload.
        args.output = report_output
        _report(args, bundle_path)
        args.output = decision_output
        if getattr(args, "github_repo", None):
            _post_github_report(args, bundle_path)
        set_span_status(tracer_span, "ok" if code in (0, 1, 2) else "error")
        tracer_span.set_attribute(SpanAttrs.DECISION, str(code))
        tracer_span.end()
        return code
    except Exception as exc:
        set_span_status(tracer_span, "error", str(exc))
        tracer_span.set_attribute(SpanAttrs.DECISION, "error")
        tracer_span.end()
        raise


def _post_github_report(args: argparse.Namespace, bundle_path: Path) -> int:
    """Post the sealed decision as a GitHub check run (CI mode integration)."""
    from .integrations import GitHubError, post_check_run
    from .reporting import render_markdown as _render

    bundle = _load_bundle(bundle_path)
    catalog = _read_json(Path(args.catalog))
    policy = _read_json(Path(args.policy))
    store = _artifact_store(bundle, Path(args.repo).resolve(), args.artifacts_root)
    result = decide(bundle, catalog, policy, store)
    markdown = redact_excerpt(_render(bundle, result), 60_000)
    sha = args.github_sha or bundle.change.head_revision
    try:
        response = post_check_run(
            repo=args.github_repo,
            head_sha=sha,
            decision=result.decision,
            scenario_id="cli-run",
            run_id=bundle.change.change_id,
            summary_markdown=markdown,
            api_base=getattr(args, "github_api", None),
        )
    except GitHubError as exc:
        print(f"clca: github-report: {exc}", file=sys.stderr)
        return 3
    print(json.dumps({
        "step": "github-report",
        "check_run_id": response.get("id"),
        "repo": args.github_repo,
        "head_sha": sha,
        "conclusion": response.get("conclusion"),
        "html_url": response.get("html_url"),
    }, indent=2))
    return 0


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", default=".", help="repository root (default: current directory)")
    parser.add_argument("--catalog", default="config/check_catalog.json")
    parser.add_argument("--policy", default="config/policy.json")
    parser.add_argument("--artifacts-root")
    parser.add_argument("--output")


def _add_change_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--budget-seconds", type=float, default=60)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clca", description="Cross-Layer Change Assurance MVP")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="intake diff, collect cross-layer evidence, build a plan")
    _add_common(analyze)
    _add_change_args(analyze)
    analyze.set_defaults(func=cmd_analyze)

    verify = sub.add_parser("verify", help="execute allow-listed checks and record execution proof")
    _add_common(verify)
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--commands", default="config/commands.json")
    verify.set_defaults(func=cmd_verify)

    decide_parser = sub.add_parser("decide", help="evaluate a sealed evidence bundle against the policy")
    _add_common(decide_parser)
    decide_parser.add_argument("--bundle", required=True)
    decide_parser.set_defaults(func=cmd_decide)

    report = sub.add_parser("report", help="render a human-readable Markdown report")
    _add_common(report)
    report.add_argument("--bundle", required=True)
    report.set_defaults(func=cmd_report)

    run = sub.add_parser("run", help="analyze + verify + decide + report in one invocation")
    _add_common(run)
    _add_change_args(run)
    run.add_argument("--commands", default="config/commands.json")
    run.add_argument("--bundle-output",
                     help="sealed evidence bundle path (default: <repo>/artifacts/<change_id>.bundle.json)")
    run.add_argument("--report-output",
                     help="also write the Markdown report to this file (default: stdout only)")
    run.add_argument("--github-repo", help="owner/name: also post the decision as a GitHub check run (needs GITHUB_TOKEN)")
    run.add_argument("--github-sha", help="head SHA for the check run (default: bundle head revision)")
    run.add_argument("--github-api", help="GitHub API base URL (default: https://api.github.com; set for GHES/tests)")
    run.add_argument("--adapters", nargs="*", default=None,
                     help="external tool adapters to run (axiomcodegraph, enola, code_system_graph, "
                          "datahub, owasp_agent_security, praxen, stryker, farol, code_decay, semctx). "
                          "Default: all registered adapters.")
    run.add_argument("--no-adapters", action="store_true", default=False,
                     help="skip all external tool adapters (planner-only mode).")
    run.set_defaults(func=cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Only reconfigure an actual interactive console. Test capture streams and
    # CI pipes may expose a reconfigure method without being a real terminal;
    # mutating them can interfere with nested CLI/test subprocesses.
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream.isatty() and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")  # Windows console encoding
        except (AttributeError, OSError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, json.JSONDecodeError, ValueError, ValidationError, IntakeError, AllowListError, PermissionError) as exc:
        print(f"clca: error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
