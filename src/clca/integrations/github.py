"""GitHub integration: signed webhooks + Checks API reporting (stdlib only).

Two integration modes:

1. **CI mode (primary, recommended)** — the GitHub Actions workflow in
   ``.github/workflows/clca.yml`` checks out the PR and runs ``clca run``
   locally, then posts the decision as a check run with ``clca github-report``.
   This preserves the trust model: the gate only ever reads code the CI
   runner already has; no repository URL or credential enters CLCA.

2. **Webhook mode (demo)** — the service accepts signed ``pull_request``
   events (HMAC-SHA256 via ``X-Hub-Signature-256``), maps the changed files
   to a built-in scenario, and optionally posts the decision back as a check
   run when ``GITHUB_TOKEN`` is configured. It still never clones anything.

Conclusions follow the GitHub Checks API vocabulary:
    PASS -> success, WARN -> success (with disclosed gaps),
    BLOCK -> failure, INCOMPLETE -> action_required (cannot prove).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Callable

from .. import __version__

GITHUB_API = "https://api.github.com"

# owner/name as GitHub accepts it — the repo is interpolated into the API path,
# so only this charset may reach the URL. fullmatch (not $) so a trailing
# newline or any control character is refused: $ would match before '\n'.
# Each segment must start with a letter/digit so dot-traversal forms like
# `../x` or `.hidden/x` are refused (A1 finding: dots in the class alone let
# `..` through as a "valid" segment).
_REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*")

# CLCA decision -> GitHub check-run conclusion.
CONCLUSION = {
    "PASS": "success",
    "WARN": "success",
    "BLOCK": "failure",
    "INCOMPLETE": "action_required",
}

# Which built-in scenario a changed file set maps to (demo webhook mode).
# Most specific path first — the first match wins.
_PATH_HINTS = (
    (("tool_manifest.json",), "write_tool_escalation"),
    (("prompts/", "prompt"), "prompt_edit"),
    (("data/dbt/", "data/contracts/"), "column_rename"),
    (("backend/", "tests/"), "safe_code_change"),
)


class GitHubError(RuntimeError):
    pass


def verify_webhook_signature(secret: str, payload: bytes, signature_header: str) -> bool:
    """Constant-time check of X-Hub-Signature-256 ('sha256=<hex>').

    The header value comes straight off the wire; an attacker can send
    non-ASCII garbage. `hmac.compare_digest` raises TypeError on non-ASCII
    str arguments, which would crash the handler instead of rejecting — so we
    normalize to bytes first and never let it propagate.
    """
    if not secret or not signature_header:
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    try:
        return hmac.compare_digest(expected, signature_header)
    except TypeError:
        return False


def sign_payload(secret: str, payload: bytes) -> str:
    """Compute a signature (used by tests and the doc examples)."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def scenario_for_paths(changed_paths: list[str] | None) -> str:
    """Map a fully understood demo path set to one synthetic scenario.

    Every path must map to the same scenario. A mixed PR, or a path with no
    mapping, cannot be represented by a single fixture and returns
    ``unknown_change``. This mapping is for demo UX only; it never attests the
    real pull request's contents or posts a real PR check result.
    """
    if not changed_paths:
        return "unknown_change"
    mapped: set[str] = set()
    for raw_path in changed_paths:
        path = str(raw_path).replace("\\", "/").lstrip("./")
        scenario_id = None
        for hints, candidate in _PATH_HINTS:
            if any(path.startswith(hint) or hint in path for hint in hints):
                scenario_id = candidate
                break
        if scenario_id is None:
            return "unknown_change"
        mapped.add(scenario_id)
        if len(mapped) > 1:
            return "unknown_change"
    return next(iter(mapped))


def build_check_run_payload(
    decision: str,
    scenario_id: str,
    run_id: str,
    summary_markdown: str,
    title: str | None = None,
    head_sha: str | None = None,
) -> dict[str, Any]:
    """Body for POST /repos/{owner}/{repo}/check-runs.

    ``head_sha`` is the real head SHA of the checked revision (set explicitly;
    ``run_id`` is only a fallback so the payload is always self-contained).
    """
    conclusion = CONCLUSION.get(decision, "action_required")
    summary = summary_markdown[:65000]  # API limit is 65535 chars
    return {
        "name": "CLCA evidence gate",
        "head_sha": head_sha or run_id,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title or f"{decision}: {scenario_id}",
            "summary": summary,
        },
        "details_url": f"https://github.com/CLCA",
    }


def post_check_run(
    repo: str,
    head_sha: str,
    decision: str,
    scenario_id: str,
    run_id: str,
    summary_markdown: str,
    token: str | None = None,
    api_base: str | None = None,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Create a check run on GitHub. Returns the API response.

    ``opener`` is injectable so tests can run against a fake server.
    ``repo`` is ``owner/name``. The token comes from the environment by
    default (GITHUB_TOKEN) — never from the request payload.
    """
    token = token or os.environ.get("GITHUB_TOKEN") or ""
    if not token:
        raise GitHubError("no GitHub token available (set GITHUB_TOKEN)")
    if not _REPO_RE.fullmatch(repo or ""):
        raise GitHubError("repo must be 'owner/name' using letters, digits, '.', '_' or '-'")

    payload = build_check_run_payload(decision, scenario_id, run_id, summary_markdown, head_sha=head_sha)
    body = json.dumps(payload).encode("utf-8")
    url = f"{(api_base or GITHUB_API)}/repos/{repo}/check-runs"
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": f"clca/{__version__}",
        "Content-Type": "application/json",
    })
    open_url = opener or urllib.request.urlopen
    try:
        with open_url(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:  # surface GitHub's message, not a stack
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise GitHubError(f"check-run creation failed: HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise GitHubError(f"cannot reach GitHub API: {exc.reason}") from exc


def parse_pull_request_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Extract what we need from a pull_request webhook. None if unusable.

    CT-2: a real GitHub ``pull_request`` webhook does NOT carry a file list.
    (The file list comes from the Files API; ``changes`` only appears on
    ``edited`` actions and never contains ``files``.) The old code read the
    fantasy field ``payload["changes"]["files"]``, which was always absent on
    real deliveries, so ``changed_paths`` came back empty and every PR mapped
    to ``clean_tree`` -> a green PASS no matter what it touched. We now return
    ``paths_known`` so the caller can refuse to claim a clean tree.
    """
    action = payload.get("action")
    if action not in ("opened", "synchronize", "reopened", "ready_for_review"):
        return None
    pr = payload.get("pull_request") or {}
    repo = (payload.get("repository") or {}).get("full_name") or ""
    head = (pr.get("head") or {})
    # Only trust a file list if the sender actually supplied one. A real
    # GitHub delivery never does, so paths are marked unknown (not "clean").
    raw_files = (payload.get("changes") or {}).get("files") if isinstance(payload.get("changes"), dict) else None
    paths_known = isinstance(raw_files, list)
    changed = [
        f["filename"]
        for f in (raw_files or [])
        if isinstance(f, dict) and f.get("filename")
    ] if paths_known else []
    head_sha = head.get("sha") or ""
    if not head_sha:
        return None  # without an immutable head SHA there is nothing to attest
    return {
        "action": action,
        "repo": repo,
        "number": pr.get("number"),
        "head_sha": head_sha,
        "title": (pr.get("title") or "")[:200],
        "changed_paths": changed,
        "paths_known": paths_known,
        "html_url": pr.get("html_url") or "",
    }


def webhook_configured() -> bool:
    """Whether a webhook secret is present (endpoint rejects when absent)."""
    return bool(os.environ.get("CLCA_GITHUB_WEBHOOK_SECRET"))
