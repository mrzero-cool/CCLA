"""GitHub integration: HMAC webhook auth, event parsing, check-run payloads.

No network access: the check-run poster is tested against a fake opener.
"""
import io
import json

import pytest

from clca.integrations import github as gh


# ---------- webhook signatures ----------

def test_signature_roundtrip():
    payload = b'{"action":"opened"}'
    sig = gh.sign_payload("s3cret", payload)
    assert gh.verify_webhook_signature("s3cret", payload, sig) is True


def test_signature_rejects_wrong_secret_and_tampering():
    payload = b'{"action":"opened"}'
    sig = gh.sign_payload("s3cret", payload)
    assert gh.verify_webhook_signature("other", payload, sig) is False
    assert gh.verify_webhook_signature("s3cret", b'{"action":"closed"}', sig) is False
    assert gh.verify_webhook_signature("s3cret", payload, "") is False
    assert gh.verify_webhook_signature("s3cret", payload, "sha256=deadbeef") is False


def test_signature_is_constant_time_shape():
    # compare_digest requires equal-length inputs; malformed lengths must not raise
    assert gh.verify_webhook_signature("s", b"{}", "sha256=short") is False


def test_signature_with_non_ascii_header_is_rejected_not_raised():
    """A non-ASCII X-Hub-Signature-256 header must be a clean 401, not a 500.

    `hmac.compare_digest` raises TypeError when a str argument contains
    non-ASCII characters ("comparing strings with non-ASCII characters is not
    supported"). The header value comes straight off the wire, so an attacker
    could send a signature header with a non-ASCII byte and crash the handler
    instead of being rejected. Signature verification must never raise.
    """
    payload = b'{"action":"opened"}'
    assert gh.verify_webhook_signature("s3cret", payload, "sha256=é" * 32) is False
    assert gh.verify_webhook_signature("s3cret", payload, "sha256=中文") is False
    assert gh.verify_webhook_signature("s3cret", payload, "é") is False


# ---------- PR event parsing ----------

def _pr_event(action="opened", sha="abc123", files=None):
    return {
        "action": action,
        "pull_request": {
            "number": 7,
            "title": "Update agent tools",
            "head": {"sha": sha},
            "html_url": "https://github.com/acme/app/pull/7",
        },
        "repository": {"full_name": "acme/app"},
        "changes": {"files": [{"filename": f} for f in (files or [])]},
    }


def test_parse_pull_request_event_extracts_essentials():
    parsed = gh.parse_pull_request_event(_pr_event(files=["agents/replenishment/tool_manifest.json"]))
    assert parsed["repo"] == "acme/app"
    assert parsed["head_sha"] == "abc123"
    assert parsed["number"] == 7
    assert parsed["changed_paths"] == ["agents/replenishment/tool_manifest.json"]


@pytest.mark.parametrize("action", ["closed", "labeled", "edited", "converted_to_draft"])
def test_parse_ignores_irrelevant_actions(action):
    assert gh.parse_pull_request_event(_pr_event(action=action)) is None


def test_parse_returns_none_for_non_pr_payload():
    assert gh.parse_pull_request_event({"action": "push"}) is None


def test_parse_does_not_invent_paths_from_fantasy_changes_field():
    """CT-2: a REAL GitHub `pull_request` webhook carries no file list.

    The old parser read `payload["changes"]["files"]`, which GitHub does not
    send on pull_request events (`changes` only appears on `edited` and never
    contains `files`; the real file list comes from the Files API). On a real
    delivery that field is always absent, so `changed_paths` came back empty
    and `scenario_for_paths([])` mapped it to `clean_tree` -> a green PASS on
    any PR regardless of what it touched. The parser must now mark paths as
    unknown rather than silently defaulting them to an empty list.
    """
    # A faithful real-world payload: NO "changes" key at all.
    real = {
        "action": "opened",
        "pull_request": {
            "number": 7,
            "title": "Update agent tools",
            "head": {"sha": "abc123"},
            "html_url": "https://github.com/acme/app/pull/7",
        },
        "repository": {"full_name": "acme/app"},
    }
    parsed = gh.parse_pull_request_event(real)
    assert parsed is not None
    assert parsed["changed_paths"] == []
    assert parsed.get("paths_known") is False, (
        "a real delivery (no file list) must be flagged paths_known=False, "
        "not silently treated as an empty/clean change set"
    )


def test_parse_requires_head_sha():
    event = _pr_event()
    event["pull_request"]["head"] = {}
    assert gh.parse_pull_request_event(event) is None


# ---------- scenario mapping ----------

def test_scenario_mapping_by_changed_path():
    assert gh.scenario_for_paths(["agents/replenishment/tool_manifest.json"]) == "write_tool_escalation"
    assert gh.scenario_for_paths(["data/dbt/manifest.json"]) == "column_rename"
    assert gh.scenario_for_paths(["agents/replenishment/prompts/system.md"]) == "prompt_edit"
    assert gh.scenario_for_paths(["backend/services/pricing.py"]) == "safe_code_change"
    assert gh.scenario_for_paths(["README.md"]) == "unknown_change"


def test_unknown_paths_never_map_to_clean_tree():
    """CT-2: an empty path list means "we do not know what changed", not
    "nothing changed". Mapping it to clean_tree made every real webhook
    delivery (which carries no file list) resolve to the benign scenario and
    produce a green PASS. It must now resolve to an honest unknown marker so
    the caller can refuse to claim a clean tree."""
    assert gh.scenario_for_paths([]) == "unknown_change"
    assert gh.scenario_for_paths(None) == "unknown_change"
    assert gh.scenario_for_paths(["README.md", "unknown/config.toml"]) == "unknown_change"
    assert gh.scenario_for_paths([
        "agents/replenishment/tool_manifest.json", "backend/services/pricing.py"
    ]) == "unknown_change"


# ---------- check runs ----------

def test_conclusion_mapping_covers_all_decisions():
    assert gh.CONCLUSION == {
        "PASS": "success", "WARN": "success",
        "BLOCK": "failure", "INCOMPLETE": "action_required",
    }


def test_build_check_run_payload_shape_and_truncation():
    payload = gh.build_check_run_payload("BLOCK", "write_tool_escalation", "run-1", "# hi" * 20000)
    assert payload["name"] == "CLCA evidence gate"
    assert payload["status"] == "completed"
    assert payload["conclusion"] == "failure"
    assert payload["head_sha"] == "run-1"
    assert len(payload["output"]["summary"]) <= 65000
    assert payload["output"]["title"].startswith("BLOCK")


def test_build_check_run_payload_uses_real_head_sha():
    """head_sha must be the real head SHA, not the run_id fallback."""
    payload = gh.build_check_run_payload(
        "PASS", "safe_code_change", "run-2", "# ok",
        head_sha="abc123def456",
    )
    assert payload["head_sha"] == "abc123def456"
    assert payload["head_sha"] != "run-2"


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    @property
    def status(self):
        return 201


def test_post_check_run_sends_auth_headers_and_sha(monkeypatch):
    seen = {}

    def fake_opener(request, timeout=None):
        seen["url"] = request.full_url
        seen["auth"] = request.get_header("Authorization")
        seen["body"] = json.loads(request.data.decode("utf-8"))
        return _FakeResponse(b'{"id": 42, "conclusion": "failure", "html_url": "https://x/c/42"}')

    resp = gh.post_check_run(
        repo="acme/app", head_sha="deadbeef", decision="BLOCK",
        scenario_id="s", run_id="run-1", summary_markdown="# report",
        token="tok", api_base="https://fake.api", opener=fake_opener,
    )
    assert seen["url"] == "https://fake.api/repos/acme/app/check-runs"
    assert seen["auth"] == "Bearer tok"
    assert seen["body"]["head_sha"] == "deadbeef"
    assert seen["body"]["conclusion"] == "failure"
    assert resp["id"] == 42


def test_post_check_run_requires_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(gh.GitHubError):
        gh.post_check_run(repo="a/b", head_sha="x", decision="PASS",
                          scenario_id="s", run_id="r", summary_markdown="", token=None,
                          opener=None)


def test_repo_format_regex_is_the_actual_gate():
    """CT-6: the old test only did `pytest.raises(GitHubError)`, which is
    vacuous -- `post_check_run` also raises GitHubError for a missing token,
    bad JSON, or any opener failure, so the test passed even if `_REPO_RE`
    rejected nothing. Test the regex itself: the repo is interpolated into the
    API path, so only `owner/name` in this charset may match."""
    valid = ["acme/app", "Acme-corp/my.repo_1", "a/b", "owner.name/repo-name"]
    for repo in valid:
        assert gh._REPO_RE.fullmatch(repo), f"should be allowed: {repo!r}"
    invalid = [
        "no-slash", "../evil/x", "acme/app/../..", "acme/app\n", "/x", "a b/c",
        "..", "acme/", "/app", "a//b", "acme/app ", " acme/app",
    ]
    for repo in invalid:
        assert not gh._REPO_RE.fullmatch(repo), f"must be refused: {repo!r}"


def test_post_check_run_rejects_malformed_repo():
    """End-to-end: a malformed repo is refused BEFORE any network call."""
    def _no_network(*args, **kwargs):
        raise AssertionError("network opener must not be reached for a bad repo")

    with pytest.raises(gh.GitHubError, match="owner/name"):
        gh.post_check_run(repo="../evil/x", head_sha="x", decision="PASS",
                          scenario_id="s", run_id="r", summary_markdown="",
                          token="t", opener=_no_network)


def test_post_check_run_accepts_normal_repos():
    # valid repo passes validation and reaches the (injected, fake) opener
    seen = {}

    def fake_opener(request, timeout=None):
        seen["url"] = request.full_url
        raise gh.GitHubError("reached-opener")

    with pytest.raises(gh.GitHubError) as excinfo:
        gh.post_check_run(repo="Acme-corp/my.repo_1", head_sha="x", decision="PASS",
                          scenario_id="s", run_id="r", summary_markdown="", token="t",
                          api_base="https://fake.api", opener=fake_opener)
    assert "reached-opener" in str(excinfo.value)
    assert seen["url"] == "https://fake.api/repos/Acme-corp/my.repo_1/check-runs"
