"""HTTP service: async scenario runs + web console assets (the container entrypoint)."""
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from clca.service import Handler
from clca.scenarios import SCENARIOS


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _get(url: str) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=300) as response:
        return response.status, response.read().decode("utf-8")


def _post_json(url: str, payload: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def _wait_for_run(server: str, run_id: str, timeout: float = 300.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _, body = _get(f"{server}/v1/runs/{run_id}")
        payload = json.loads(body)
        if payload["status"] in ("completed", "failed"):
            return payload
        time.sleep(0.3)
    raise AssertionError(f"run {run_id} did not finish within {timeout}s")


def test_healthz(server):
    status, body = _get(f"{server}/healthz")
    assert status == 200
    assert json.loads(body)["status"] == "ok"


def test_scenarios_endpoint_lists_every_scenario(server):
    status, body = _get(f"{server}/v1/scenarios")
    payload = json.loads(body)
    assert status == 200
    assert {s["scenario_id"] for s in payload["scenarios"]} == set(SCENARIOS)
    assert all("expected_decision" not in item for item in payload["scenarios"])


def test_index_and_static_assets_served(server):
    status, html = _get(f"{server}/")
    assert status == 200
    assert "CLCA" in html and "/static/app.js" in html

    status, css = _get(f"{server}/static/styles.css")
    assert status == 200 and "--accent" in css

    status, js = _get(f"{server}/static/app.js")
    assert status == 200 and "pollRun" in js


def test_static_path_traversal_refused(server):
    try:
        _get(f"{server}/static/../pyproject.toml")
        raise AssertionError("expected an HTTP error")
    except urllib.error.HTTPError as exc:
        assert exc.code in (400, 404)


def test_unknown_scenario_is_a_client_error(server):
    try:
        _post_json(f"{server}/v1/runs", {"scenario": "not-a-scenario"})
        raise AssertionError("expected an HTTP error")
    except urllib.error.HTTPError as exc:
        assert exc.code == 400


def test_escalation_scenario_blocks_through_the_api(server):
    status, accepted = _post_json(f"{server}/v1/runs", {"scenario": "write_tool_escalation"})
    assert status == 202
    assert accepted["status"] == "running"

    run = _wait_for_run(server, accepted["run_id"])
    assert run["status"] == "completed"
    assert run["decision"] == "BLOCK"
    assert run["matches_expectation"] is True
    assert "AGENT_NEW_WRITE_TOOL" in {f["rule_id"] for f in run["policy_findings"]}

    # enriched payload for the console
    assert run["impact"]["changed_asset_ids"]
    assert run["evidence"] and all("evidence_id" in e for e in run["evidence"])
    assert all("log_tail" in c for c in run["checks"])

    report_status, report = _get(f"{server}{run['report_url']}")
    assert report_status == 200
    assert "**BLOCK**" in report
    assert "AGENT_NEW_WRITE_TOOL" in report


def test_run_history_lists_completed_run(server):
    _, accepted = _post_json(f"{server}/v1/runs", {"scenario": "clean_tree"})
    _wait_for_run(server, accepted["run_id"])
    status, body = _get(f"{server}/v1/runs")
    runs = json.loads(body)["runs"]
    assert status == 200
    assert any(r["run_id"] == accepted["run_id"] and r["decision"] == "PASS" for r in runs)


def test_graph_and_dot_endpoints(server):
    _, accepted = _post_json(f"{server}/v1/runs", {"scenario": "write_tool_escalation"})
    run = _wait_for_run(server, accepted["run_id"])
    assert "graph" not in run          # heavy payload is not inlined

    status, body = _get(f"{server}/v1/runs/{accepted['run_id']}/graph")
    graph = json.loads(body)
    assert status == 200
    assert graph["nodes"] and graph["edges"]
    metrics = graph["metrics"]
    assert metrics["changed"] >= 1
    assert metrics["networkx"] is True
    states = {n["data"]["state"] for n in graph["nodes"]}
    assert "changed" in states

    status, dot = _get(f"{server}/v1/runs/{accepted['run_id']}/graph.dot")
    assert status == 200 and dot.startswith("digraph clca_impact")


def test_artifact_endpoint_conflicts_while_running(server, monkeypatch):
    """A not-yet-completed run must answer 409 for artifact sub-resources.

    CT-7 (was vacuous): the old test asserted `exc.code in (409, 200)`, which
    accepts any outcome and therefore tested nothing. We hold the run open on
    a stub so the "still running" path is deterministic, then require 409."""
    import clca.service as svc

    started = threading.Event()
    release = threading.Event()

    def blocked_run(scenario_id, budget_seconds=60.0):
        started.set()
        release.wait(10)
        raise RuntimeError("released for test")

    monkeypatch.setattr(svc, "run_scenario", blocked_run)
    try:
        _, accepted = _post_json(f"{server}/v1/runs", {"scenario": "safe_code_change"})
        assert started.wait(10), "run never started"
        try:
            _get(f"{server}/v1/runs/{accepted['run_id']}/report")
            raise AssertionError("expected 409 while the run is still in progress")
        except urllib.error.HTTPError as exc:
            assert exc.code == 409
    finally:
        release.set()


def test_integrations_endpoint_lists_github_wiring(server):
    status, body = _get(f"{server}/v1/integrations")
    payload = json.loads(body)
    assert status == 200
    gh = payload["github"]
    assert gh["webhook"]["endpoint"] == "/v1/webhooks/github"
    assert gh["webhook"]["clones_repositories"] is False
    assert gh["actions_workflow"].endswith("clca.yml")
    # never leak secrets
    assert "secret" not in json.dumps(payload).lower().replace("webhook_secret_set", "")


def test_webhook_rejected_without_secret(server, monkeypatch):
    monkeypatch.delenv("CLCA_GITHUB_WEBHOOK_SECRET", raising=False)
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"{server}/v1/webhooks/github", data=b"{}", method="POST"), timeout=30)
        raise AssertionError("expected an HTTP error")
    except urllib.error.HTTPError as exc:
        assert exc.code == 503


def test_webhook_rejects_bad_signature(server, monkeypatch):
    monkeypatch.setenv("CLCA_GITHUB_WEBHOOK_SECRET", "test-secret")
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"{server}/v1/webhooks/github", data=b"{}", method="POST",
            headers={"X-Hub-Signature-256": "sha256=bad"}), timeout=30)
        raise AssertionError("expected an HTTP error")
    except urllib.error.HTTPError as exc:
        assert exc.code == 401


def _pr_event_with_files(files, action="opened", sha="cafe123", number=3, title="pr"):
    """A pull_request payload that DOES carry an explicit file list.

    A real GitHub webhook never sends one (see CT-2), but the Files API (or a
    test/sender that pre-resolves paths) can. When `changes.files` is present
    the parser trusts it and marks paths_known=True, which is the only way the
    demo webhook can map a path to a scenario.
    """
    return {
        "action": action,
        "pull_request": {"number": number, "title": title, "head": {"sha": sha}},
        "repository": {"full_name": "acme/app"},
        "changes": {"files": [{"filename": f} for f in files]},
    }


def test_webhook_ping_and_pr_event(server, monkeypatch):
    from clca.integrations import sign_payload
    monkeypatch.setenv("CLCA_GITHUB_WEBHOOK_SECRET", "test-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-be-used-for-synthetic-demo")

    def send(payload: dict, event: str) -> tuple[int, dict]:
        raw = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(f"{server}/v1/webhooks/github", data=raw, method="POST", headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": event,
            "X-Hub-Signature-256": sign_payload("test-secret", raw),
        })
        with urllib.request.urlopen(req, timeout=300) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    status, body = send({"zen": "hello"}, "ping")
    assert status == 200 and body["ok"] is True

    status, body = send(_pr_event_with_files(["agents/replenishment/tool_manifest.json"]), "pull_request")
    assert status == 202
    assert body["scenario_id"] == "write_tool_escalation"   # path-mapped
    assert body["context"]["head_sha"] == "cafe123"
    assert body["will_report_check_run"] is False            # synthetic results are never posted
    assert body["demo_only"] is True
    assert body["context"]["demo_only"] is True

    run = _wait_for_run(server, body["run_id"])
    assert run["decision"] == "BLOCK"


# ---------- security: availability + replay (audit fixes) ----------

def test_negative_content_length_is_rejected(server):
    """F2: a negative Content-Length must not reach rfile.read(-1).

    read(-1) blocks until the client closes, which lets an unauthenticated
    caller pin handler threads with a single header.
    """
    import socket

    host, port = server.split("//")[1].split(":")
    with socket.create_connection((host, int(port)), timeout=10) as sock:
        sock.sendall(
            b"POST /v1/runs HTTP/1.1\r\nHost: t\r\nContent-Length: -1\r\n\r\n"
        )
        first_line = sock.recv(4096).split(b"\r\n")[0]
    assert b"400" in first_line


def test_concurrent_run_admission_cap_returns_429(server, monkeypatch):
    """F1: only CLCA_MAX_ACTIVE_RUNS runs may execute at once; the rest get 429."""
    import clca.service as svc

    monkeypatch.setenv("CLCA_MAX_ACTIVE_RUNS", "1")
    release = threading.Event()
    started = threading.Event()

    def blocked_run(scenario_id, budget_seconds=60.0):
        started.set()
        release.wait(30)
        raise RuntimeError("released for test")

    monkeypatch.setattr(svc, "run_scenario", blocked_run)
    try:
        status, _ = _post_json(f"{server}/v1/runs", {"scenario": "clean_tree"})
        assert status == 202
        assert started.wait(10), "first run never started"

        try:
            _post_json(f"{server}/v1/runs", {"scenario": "clean_tree"})
            raise AssertionError("expected 429 while the slot is occupied")
        except urllib.error.HTTPError as exc:
            assert exc.code == 429
            # CT-7 (was vacuous): the old assert was a conditional expression
            # (`X if cond else True`) that silently passed when `as_bytes` was
            # absent, so the Retry-After header was never actually checked.
            assert exc.headers.get("Retry-After") is not None, (
                "a 429 must carry Retry-After so the client knows when to back off")
    finally:
        release.set()


def test_webhook_delivery_replay_is_deduplicated(server, monkeypatch):
    """F3: a replayed signed delivery (same X-GitHub-Delivery) starts no new run."""
    import clca.service as svc
    from clca.integrations import sign_payload

    monkeypatch.setenv("CLCA_GITHUB_WEBHOOK_SECRET", "test-secret")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    calls: list[str] = []

    def stub_run(scenario_id, budget_seconds=60.0):
        calls.append(scenario_id)
        raise RuntimeError("stub run for replay test")

    monkeypatch.setattr(svc, "run_scenario", stub_run)

    raw = json.dumps(_pr_event_with_files(["backend/pricing.py"], number=9, title="replay", sha="feed99")).encode("utf-8")

    def send() -> tuple[int, dict]:
        req = urllib.request.Request(f"{server}/v1/webhooks/github", data=raw, method="POST", headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "delivery-replay-1",
            "X-Hub-Signature-256": sign_payload("test-secret", raw),
        })
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    status, body = send()
    assert status == 202 and body["run_id"]

    deadline = time.monotonic() + 5
    while not calls and time.monotonic() < deadline:
        time.sleep(0.05)
    assert calls == ["safe_code_change"]          # first delivery launched exactly one run

    status, body = send()                          # byte-identical replay
    assert status == 200
    assert body["duplicate"] is True
    time.sleep(0.3)
    assert calls == ["safe_code_change"]           # replay launched nothing new


def test_webhook_replay_blocked_even_when_guid_is_rotated(server, monkeypatch):
    """CT-4: an attacker who holds ONE valid signed body must not be able to
    launch duplicate runs by rotating the client-chosen X-GitHub-Delivery GUID.

    HMAC-SHA256 covers the body only; the old replay guard keyed dedup on the
    GUID header alone, so three requests with the same signed bytes but
    different GUIDs each launched a run. Dedup must also key on the body
    digest, which cannot be rotated without invalidating the signature.
    """
    import clca.service as svc
    from clca.integrations import sign_payload

    monkeypatch.setenv("CLCA_GITHUB_WEBHOOK_SECRET", "test-secret")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    calls: list[str] = []

    def stub_run(scenario_id, budget_seconds=60.0):
        calls.append(scenario_id)
        raise RuntimeError("stub run for rotation test")

    monkeypatch.setattr(svc, "run_scenario", stub_run)

    raw = json.dumps(_pr_event_with_files(["backend/pricing.py"], number=11, title="rotate", sha="feed98")).encode("utf-8")
    signature = sign_payload("test-secret", raw)

    def send(guid: str) -> tuple[int, dict]:
        req = urllib.request.Request(f"{server}/v1/webhooks/github", data=raw, method="POST", headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": guid,
            "X-Hub-Signature-256": signature,
        })
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    status, body = send("rotation-guid-A")
    assert status == 202 and body["run_id"]

    deadline = time.monotonic() + 5
    while not calls and time.monotonic() < deadline:
        time.sleep(0.05)
    assert calls == ["safe_code_change"]

    # Same signed body, DIFFERENT GUID: must be treated as a replay, not a run.
    status, body = send("rotation-guid-B")
    assert status == 200 and body["duplicate"] is True
    status, body = send("rotation-guid-C")
    assert status == 200 and body["duplicate"] is True
    time.sleep(0.3)
    assert calls == ["safe_code_change"], "rotated GUID launched a duplicate run"


def test_webhook_unknown_paths_return_422_not_green_pass(server, monkeypatch):
    """CT-2: a real pull_request webhook has no file list, so the demo webhook
    cannot know what changed. It must refuse (422) rather than map the empty
    path set to `clean_tree` and report a green PASS on any PR."""
    import clca.service as svc
    from clca.integrations import sign_payload

    monkeypatch.setenv("CLCA_GITHUB_WEBHOOK_SECRET", "test-secret")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    calls: list[str] = []
    monkeypatch.setattr(svc, "run_scenario",
                        lambda sid, budget_seconds=60.0: calls.append(sid))

    # Faithful real-world payload: GitHub sends NO "changes.files" list.
    raw = json.dumps({
        "action": "opened",
        "pull_request": {"number": 5, "title": "real pr", "head": {"sha": "beef42"}},
        "repository": {"full_name": "acme/app"},
    }).encode("utf-8")
    req = urllib.request.Request(f"{server}/v1/webhooks/github", data=raw, method="POST", headers={
        "Content-Type": "application/json",
        "X-GitHub-Event": "pull_request",
        "X-Hub-Signature-256": sign_payload("test-secret", raw),
    })
    try:
        urllib.request.urlopen(req, timeout=60)
        raise AssertionError("expected 422: unknown changed files must not start a run")
    except urllib.error.HTTPError as exc:
        assert exc.code == 422
        body = json.loads(exc.read().decode("utf-8"))
        assert "cannot determine changed files" in body["error"]
    time.sleep(0.3)
    assert calls == [], "an unknown-path delivery must not launch any scenario"
