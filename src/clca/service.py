"""HTTP API + web console for CLCA demo runs (stdlib only).

API endpoints:
    GET  /healthz                 liveness probe (App Service / ACR health check)
    GET  /v1/scenarios            available synthetic scenarios
    POST /v1/runs                 start a run: {"scenario": "<id>", "budget_seconds": 60}
    GET  /v1/runs                 run history (newest first)
    GET  /v1/runs/{id}            run status/result (poll while status=running)
    GET  /v1/runs/{id}/report     Markdown report for a completed run
    GET  /v1/runs/{id}/graph      impact graph (Cytoscape.js elements + metrics)
    GET  /v1/runs/{id}/graph.dot  Graphviz DOT export of the change cone
    GET  /v1/integrations         configured outbound integrations (no secrets)
    POST /v1/webhooks/github      signed GitHub pull_request events (HMAC)

Web console:
    GET  /                        single-page console (web/index.html)
    GET  /static/...              console assets (styles.css, app.js)

Security: this service never accepts repository URLs, credentials, or commands.
Demo runs only execute built-in synthetic scenarios against a temp copy of
sample_app, through the same allow-listed runner the CLI uses. The GitHub
webhook only accepts HMAC-signed events and never clones anything.

Run:  python -m clca.service    (listens on $PORT, default 8080)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import __version__
from .adapters import (
    default_registry,
    load_axiomcode_adapter,
    load_code_decay_adapter,
    load_code_system_graph_adapter,
    load_datahub_adapter,
    load_enola_adapter,
    load_farol_adapter,
    load_owasp_agent_adapter,
    load_praxen_adapter,
    load_semctx_adapter,
    load_stryker_adapter,
)
from .integrations.github import (
    parse_pull_request_event,
    scenario_for_paths,
    verify_webhook_signature,
    webhook_configured,
)
from .redact import redact_excerpt
from .security import Role, SecurityMiddleware
from .scenarios import SCENARIOS, run_scenario

MAX_BODY_BYTES = 64 * 1024
MAX_HISTORY = 100
_RUN_LOCK = threading.Lock()
_RUNS: dict[str, dict[str, Any]] = {}  # insertion-ordered, newest last

# Admission control (F1): unbounded concurrent runs would let any caller
# exhaust threads, CPU, and temp disk. Slots are released in the worker's
# finally, so a crashed run cannot leak one.
_active_runs = 0

# API security middleware (P0.6). In demo mode (no CLCA_API_TOKEN), all
# requests are allowed. In production, set CLCA_API_TOKEN and the middleware
# enforces bearer-token auth, RBAC, and rate limiting.
security = SecurityMiddleware(
    api_token=os.environ.get("CLCA_API_TOKEN"),
    rate_limit_per_minute=int(os.environ.get("CLCA_RATE_LIMIT_PER_MINUTE", "60")),
)

# Webhook replay window (F3): HMAC proves authenticity, not freshness.
# X-GitHub-Delivery GUIDs are remembered for this long; replays are answered
# with 200 {duplicate:true} (2xx so GitHub stops retrying the delivery).
_DELIVERY_TTL_SECONDS = 6 * 3600
_DELIVERY_MAX = 1000
_DELIVERIES: dict[str, float] = {}  # guid -> monotonic time first seen


def _max_active() -> int:
    """Configured admission cap; env read per call so tests/deploy can tune it."""
    try:
        return max(1, int(os.environ.get("CLCA_MAX_ACTIVE_RUNS", "3")))
    except ValueError:
        return 3


def _try_admit() -> bool:
    global _active_runs
    with _RUN_LOCK:
        if _active_runs >= _max_active():
            return False
        _active_runs += 1
        return True


def _release_slot() -> None:
    global _active_runs
    with _RUN_LOCK:
        _active_runs = max(0, _active_runs - 1)


def _delivery_replay(guid: str) -> bool:
    """True when this delivery GUID was already accepted inside the TTL.

    Check-only: the GUID is recorded by :func:`_remember_delivery` only after
    the delivery is actually accepted, so a 429'd delivery can still be
    retried by GitHub without being mistaken for a replay.
    """
    now = time.monotonic()
    with _RUN_LOCK:
        for key in [k for k, seen_at in _DELIVERIES.items() if now - seen_at > _DELIVERY_TTL_SECONDS]:
            del _DELIVERIES[key]
        return guid in _DELIVERIES


def _remember_delivery(guid: str) -> None:
    with _RUN_LOCK:
        if len(_DELIVERIES) >= _DELIVERY_MAX:
            _DELIVERIES.pop(next(iter(_DELIVERIES)))
        _DELIVERIES[guid] = time.monotonic()


class BodyError(ValueError):
    """Malformed request body. status carries the HTTP code to answer with."""

    status = 400


class BodyTooLarge(BodyError):
    status = 413

_WEB_ROOT = Path(os.environ.get("CLCA_WEB_ROOT") or Path(__file__).resolve().parents[2] / "web")
_STATIC_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}

_RUN_ID_RE = re.compile(r"/v1/runs/([A-Za-z0-9_-]+)(/report|/graph(?:\.dot)?)?")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _enqueue(record: dict[str, Any]) -> None:
    with _RUN_LOCK:
        _RUNS[record["run_id"]] = record
        while len(_RUNS) > MAX_HISTORY:
            _RUNS.pop(next(iter(_RUNS)))


def _start_run_async(scenario_id: str, budget_seconds: float) -> dict[str, Any]:
    placeholder_id = f"pending-{int(time.time() * 1000)}-{len(_RUNS)}"
    record: dict[str, Any] = {
        "run_id": placeholder_id,
        "scenario_id": scenario_id,
        "status": "running",
        "submitted_at": _utc_now(),
        "error": None,
        "result": None,
    }
    _enqueue(record)

    def worker() -> None:
        try:
            result = run_scenario(scenario_id, budget_seconds=budget_seconds)
            payload = result.to_dict()
            payload.pop("report_markdown", None)
            with _RUN_LOCK:
                # Update in place: the caller polls the placeholder id, which
                # must resolve before, during, and after execution. The public
                # run_id stays stable; the bundle's change_id is kept separately.
                record.update(payload)
                record["change_id"] = result.run_id
                record["run_id"] = placeholder_id
                record["status"] = "completed"
                record["report_markdown"] = result.report_markdown
                record["report_url"] = f"/v1/runs/{placeholder_id}/report"
                record["graph"] = result.graph            # heavy: /graph only
                record["graph_dot"] = result.graph_dot    # heavy: /graph.dot only
                _RUNS[placeholder_id] = record
        except Exception as exc:  # never leak internals to the client
            with _RUN_LOCK:
                record["status"] = "failed"
                record["error"] = f"{exc.__class__.__name__}: {redact_excerpt(str(exc), 300)}"
                _RUNS[placeholder_id] = record
        finally:
            _release_slot()  # a crashed run must not leak its admission slot

    try:
        threading.Thread(target=worker, daemon=True).start()
    except Exception:
        # CT-5: admission already took a slot, and the worker's finally (the
        # only place it is normally released) will never run because the thread
        # never started. Release it here and mark the run failed, or a single
        # Thread.start() failure would pin the slot and 429 every later run
        # until restart.
        with _RUN_LOCK:
            record["status"] = "failed"
            record["error"] = "could not start worker thread"
            _RUNS[placeholder_id] = record
        _release_slot()
        raise
    return record


class Handler(BaseHTTPRequestHandler):
    server_version = f"CLCA/{__version__}"
    # CT-5 / Taleb #1: without a read timeout a slowloris client that opens a
    # connection and trickles bytes pins this handler thread forever. The run
    # admission cap only limits runs, not handler threads, so an unbounded
    # number of stalled connections would exhaust threads on a 1-vCPU box and
    # take down the /healthz probe (restart loop). A slow client now gets its
    # socket torn down and the thread is released.
    timeout = 15

    # ---------- helpers ----------
    def _send(self, status: int, body: bytes, content_type: str,
              extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        SecurityMiddleware.security_headers(self)
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _security_check(self) -> bool:
        """Run auth + RBAC + rate limit. Returns True if allowed, False if
        an error response was already sent."""
        ok, role, status, msg = security.check(self)
        if not ok:
            assert status is not None and msg is not None
            self._error(status, msg)
            return False
        return True

    def _json(self, status: int, payload: Any,
              extra_headers: dict[str, str] | None = None) -> None:
        self._send(
            status,
            redact_excerpt(json.dumps(payload, indent=2, sort_keys=True), 2_000_000).encode("utf-8"),
            "application/json; charset=utf-8",
            extra_headers=extra_headers,
        )

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def log_message(self, fmt: str, *args: Any) -> None:  # keep logs tidy and redacted
        print(f"clca.service: {redact_excerpt(fmt % args, 300)}")

    # ---------- static ----------
    def _serve_static(self, rel: str) -> None:
        if ".." in rel or rel.startswith("/"):
            self._error(400, "bad path")
            return
        path = (_WEB_ROOT / rel).resolve()
        try:
            path.relative_to(_WEB_ROOT.resolve())  # no escaping the web root
        except ValueError:
            self._error(400, "bad path")
            return
        if not path.is_file():
            self._error(404, f"no such asset '{rel}'")
            return
        ctype = _STATIC_TYPES.get(path.suffix.lower(), "application/octet-stream")
        self._send(200, path.read_bytes(), ctype)

    # ---------- routing ----------
    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        if not self._security_check():
            return
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            index = _WEB_ROOT / "index.html"
            if index.is_file():
                self._send(200, index.read_bytes(), "text/html; charset=utf-8")
            else:
                self._send(200, b"CLCA demo service; web console assets not found.", "text/plain; charset=utf-8")
        elif path.startswith("/static/"):
            self._serve_static(path[len("/static/"):])
        elif path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
        elif path == "/healthz":
            with _RUN_LOCK:
                active = sum(1 for r in _RUNS.values() if r.get("status") == "running")
            self._json(200, {
                "status": "ok",
                "version": __version__,
                "scenarios": len(SCENARIOS),
                "active_runs": active,
                "stored_runs": len(_RUNS),
            })
        elif path == "/v1/scenarios":
            self._json(200, {
                "scenarios": [
                    {
                        "scenario_id": s.scenario_id,
                        "title": s.title,
                        "description": s.description,
                    }
                    for s in SCENARIOS.values()
                ]
            })
        elif path == "/v1/integrations":
            # Honest status of outbound wiring. Never exposes tokens/secrets.
            self._json(200, {
                "github": {
                    "webhook": {
                        "configured": webhook_configured(),
                        "endpoint": "/v1/webhooks/github",
                        "algorithm": "HMAC-SHA256 (X-Hub-Signature-256)",
                        "accepts": "pull_request: opened|synchronize|reopened|ready_for_review",
                        "clones_repositories": False,
                    },
                    "checks_api": {
                        "token_present": bool(os.environ.get("GITHUB_TOKEN")),
                        "endpoint": f"{os.environ.get('GITHUB_API_BASE', 'https://api.github.com')}/repos/{{owner}}/{{repo}}/check-runs",
                        "via": ["clca run --github-repo owner/name"],
                        "webhook_posts_check_runs": False,
                    },
                    "actions_workflow": ".github/workflows/clca.yml",
                    "actions_workflow_mode": "self-validation only; no PR verdict is published",
                },
                "cli": {"command": "clca run ... [--github-repo owner/name]"},
                "webhook_secret_set": webhook_configured(),
            })
        elif path == "/v1/runs":
            with _RUN_LOCK:
                summary = [
                    {
                        "run_id": r["run_id"],
                        "scenario_id": r.get("scenario_id"),
                        "status": r.get("status"),
                        "decision": (r.get("result") or {}).get("decision") or r.get("decision"),
                        "submitted_at": r.get("submitted_at") or r.get("started_at"),
                        "duration_ms": (r.get("result") or {}).get("duration_ms") or r.get("duration_ms"),
                    }
                    for r in reversed(list(_RUNS.values()))
                ]
            self._json(200, {"runs": summary})
        elif match := _RUN_ID_RE.fullmatch(path):
            run_id, sub = match.group(1), (match.group(2) or "")
            with _RUN_LOCK:
                record = _RUNS.get(run_id)
                if record is None:  # pending placeholder lookup by scenario order is not supported
                    record = next(
                        (r for r in _RUNS.values() if r["run_id"] == run_id),
                        None,
                    )
            if record is None:
                self._error(404, f"unknown run_id '{run_id}'")
            elif record.get("status") != "completed":
                if sub:
                    self._error(409, "artifact not ready; run is still in progress or failed")
                else:
                    self._json(200, {
                        "run_id": record["run_id"],
                        "scenario_id": record.get("scenario_id"),
                        "status": record.get("status"),
                        "submitted_at": record.get("submitted_at"),
                        "error": record.get("error"),
                    })
            elif sub == "/report":
                self._send(200, record["report_markdown"].encode("utf-8"), "text/markdown; charset=utf-8")
            elif sub == "/graph":
                self._json(200, record.get("graph") or {"nodes": [], "edges": [], "metrics": {}})
            elif sub == "/graph.dot":
                self._send(200, (record.get("graph_dot") or "digraph clca {}").encode("utf-8"),
                           "text/vnd.graphviz; charset=utf-8")
            else:
                # Flat shape: completed runs return their result inline, but the
                # heavy graph is only served from /graph.
                flat = {k: v for k, v in record.items()
                        if k not in ("report_markdown", "result", "graph", "graph_dot")}
                self._json(200, flat)
        else:
            self._error(404, f"unknown path '{path}'")

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length < 0:
            # read(-1) would block until the client closes: reject outright.
            raise BodyError("Content-Length must not be negative")
        if length > MAX_BODY_BYTES:
            raise BodyTooLarge("request body too large")
        if length == 0:
            return b"{}"
        # Read body in chunks; on Windows rfile.read() may return fewer bytes
        # than requested even with a socket timeout set, so loop until we have
        # everything. Handler.timeout (15s) protects against slowloris clients.
        chunks: list[bytes] = []
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(remaining)
            if not chunk:
                raise BodyError("request body read terminated early")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def do_POST(self) -> None:  # noqa: N802
        if not self._security_check():
            return
        path = self.path.split("?", 1)[0]
        if path == "/v1/webhooks/github":
            self._handle_github_webhook()
            return
        if path != "/v1/runs":
            self._error(404, f"unknown path '{path}'")
            return
        try:
            raw = self._read_body()
        except BodyError as exc:
            self._error(exc.status, str(exc))
            return
        try:
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            self._error(400, f"invalid JSON body: {exc}")
            return

        scenario_id = str(body.get("scenario", ""))
        if scenario_id not in SCENARIOS:
            self._error(400, f"unknown scenario '{scenario_id}'; choose from {sorted(SCENARIOS)}")
            return
        try:
            budget = float(body.get("budget_seconds", 60.0))
        except (TypeError, ValueError):
            self._error(400, "budget_seconds must be a number")
            return
        if not 1 <= budget <= 900:
            self._error(400, "budget_seconds must be between 1 and 900")
            return

        if not _try_admit():
            self._json(429, {
                "error": f"too many concurrent runs (limit {_max_active()}); retry shortly",
                "retry_after_seconds": 5,
            }, extra_headers={"Retry-After": "5"})
            return

        try:
            record = _start_run_async(scenario_id, budget)
        except Exception:
            # _start_run_async already released the slot and marked the run
            # failed; surface a 500 rather than crashing the handler thread.
            self._error(500, "could not start run; retry shortly")
            return
        self._json(202, {
            "run_id": record["run_id"],
            "scenario_id": scenario_id,
            "status": "running",
            "submitted_at": record["submitted_at"],
            "poll_url": f"/v1/runs/{record['run_id']}",
        })

    # ---------- GitHub webhook ----------
    def _handle_github_webhook(self) -> None:
        """Signed pull_request events → mapped scenario run + optional check run.

        Refuses unsigned/unconfigured webhooks, never clones a repository,
        and only ever launches built-in scenarios.
        """
        secret = os.environ.get("CLCA_GITHUB_WEBHOOK_SECRET", "")
        if not secret:
            self._error(503, "webhook disabled: set CLCA_GITHUB_WEBHOOK_SECRET to enable it")
            return
        try:
            raw = self._read_body()
        except BodyError as exc:
            self._error(exc.status, str(exc))
            return

        signature = self.headers.get("X-Hub-Signature-256", "")
        if not verify_webhook_signature(secret, raw, signature):
            self._error(401, "invalid webhook signature")
            return

        # Replay guard (F3 + CT-4): a captured signed delivery must not launch
        # runs or duplicate check runs. HMAC-SHA256 signs the body only, so the
        # client-chosen X-GitHub-Delivery GUID cannot be trusted as the sole
        # dedup key — an attacker holding one valid signed body could rotate the
        # GUID to launch duplicate runs. Dedup therefore also keys on the body
        # digest, which cannot be changed without invalidating the signature.
        # Both keys are remembered on accept so same-body or same-GUID retries
        # are answered 2xx (GitHub stops retrying) without re-running.
        delivery = self.headers.get("X-GitHub-Delivery", "")
        body_key = hashlib.sha256(raw).hexdigest()
        if _delivery_replay(body_key) or (delivery and _delivery_replay(f"guid:{delivery}")):
            self._json(200, {"duplicate": True, "delivery": delivery})
            return

        event = self.headers.get("X-GitHub-Event", "")
        if event == "ping":
            self._json(200, {"zen": "webhook verified", "ok": True})
            return
        if event != "pull_request":
            self._json(200, {"ignored": f"event '{event}' not handled"})
            return

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(400, "webhook payload is not valid JSON")
            return

        parsed = parse_pull_request_event(payload or {})
        if parsed is None:
            self._json(200, {"ignored": "pull_request action not relevant"})
            return
        if not parsed["head_sha"]:
            self._error(400, "pull_request event missing head SHA")
            return

        scenario_id = scenario_for_paths(parsed["changed_paths"])
        if scenario_id == "unknown_change":
            # CT-2: a real pull_request webhook carries no file list, so we
            # cannot know what changed. Mapping that to a benign scenario would
            # produce a green PASS on any PR. Refuse honestly instead of guessing.
            self._error(
                422,
                "cannot determine changed files from this pull_request payload "
                "(GitHub does not send a file list; the demo webhook does not call the "
                "Files API). Not guessing: no run started, no clean-tree claim made.",
            )
            return
        if not _try_admit():
            # Do NOT remember the delivery GUID here: GitHub will retry a
            # non-2xx delivery, and that retry must be allowed to run.
            self._json(429, {
                "error": f"too many concurrent runs (limit {_max_active()}); delivery not accepted",
                "retry_after_seconds": 5,
            }, extra_headers={"Retry-After": "5"})
            return
        try:
            record = _start_run_async(scenario_id, 60.0)
        except Exception:
            # Do NOT remember the delivery: GitHub will retry a non-2xx
            # delivery, and that retry must be allowed to run. (Same reason as
            # the 429 path above.)
            self._error(500, "could not start run; delivery not accepted")
            return
        if delivery:
            _remember_delivery(f"guid:{delivery}")
        _remember_delivery(body_key)  # CT-4: body digest can't be rotated past
        context = {
            "source": "github-webhook",
            "repo": parsed["repo"],
            "pr": parsed["number"],
            "head_sha": parsed["head_sha"],
            "pr_title": parsed["title"],
            "mapped_scenario": scenario_id,
        }
        with _RUN_LOCK:
            record["source"] = context

        # IMPORTANT: this endpoint runs a built-in synthetic scenario, not the
        # pull request's actual checkout. It must never post the synthetic
        # fixture verdict to the real PR as a GitHub Check Run. Use the CLI or
        # a trusted GitHub Actions integration against the actual checkout for
        # a real release decision.
        context["demo_only"] = True
        context["warning"] = "Synthetic scenario result; not a verdict on the actual pull request code."
        with _RUN_LOCK:
            record["source"] = context

        self._json(202, {
            "run_id": record["run_id"],
            "scenario_id": scenario_id,
            "status": "running",
            "poll_url": f"/v1/runs/{record['run_id']}",
            "context": context,
            "demo_only": True,
            "will_report_check_run": False,
        })


def _register_default_adapters() -> None:
    """Register external tool adapters whose export paths are configured via env vars.

    Adapters without a configured export path are simply not registered; the
    planner treats them as unavailable and emits coverage gaps instead of
    guessing.  This keeps the service start fast and dependency-free.
    """
    reg = default_registry

    adapters = [
        ("CLCA_AXIOMCODE_EXPORT", load_axiomcode_adapter, "axiomcodegraph"),
        ("CLCA_ENOLA_EXPORT", load_enola_adapter, "enola"),
        ("CLCA_CODE_SYSTEM_GRAPH_EXPORT", load_code_system_graph_adapter, "code_system_graph"),
        ("CLCA_DATAHUB_EXPORT", load_datahub_adapter, "datahub"),
        ("CLCA_OWASP_AGENT_EXPORT", load_owasp_agent_adapter, "owasp_agent_security"),
        ("CLCA_PRAXEN_EXPORT", load_praxen_adapter, "praxen"),
        ("CLCA_STRYKER_EXPORT", load_stryker_adapter, "stryker"),
        ("CLCA_FAROL_EXPORT", load_farol_adapter, "farol"),
        ("CLCA_CODE_DECAY_EXPORT", load_code_decay_adapter, "code_decay"),
        ("CLCA_SEMCTX_EXPORT", load_semctx_adapter, "semctx"),
    ]

    for env_name, loader, adapter_name in adapters:
        export_path = os.environ.get(env_name, "").strip()
        if export_path and Path(export_path).is_file():
            reg.register(adapter_name, loader(export_path))
        elif export_path:
            print(f"clca.service: adapter {adapter_name} export path not found: {export_path}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    _register_default_adapters()
    port = int(os.environ.get("PORT", "8080"))
    host = os.environ.get("HOST", "0.0.0.0")
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"clca.service: listening on {host}:{port} ({len(SCENARIOS)} scenarios, {len(default_registry.names())} adapters, console at /)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("clca.service: shutting down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
