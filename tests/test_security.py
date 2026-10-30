"""Tests for CLCA API security middleware (P0.6)."""
from __future__ import annotations

from clca.security import Role, SecurityMiddleware, required_role_for_path


class _FakeHandler:
    """Minimal fake handler for security middleware tests."""

    def __init__(self, path: str, headers: dict[str, str] | None = None,
                 client_address: tuple[str, int] = ("127.0.0.1", 12345)):
        self.path = path
        self.headers = headers or {}
        self.client_address = client_address


def test_demo_mode_allows_all():
    """No CLCA_API_TOKEN -> all requests allowed (with auditor role)."""
    mw = SecurityMiddleware(api_token=None)
    handler = _FakeHandler("/v1/runs", {"Authorization": "Bearer wrong"})
    ok, role, status, msg = mw.check(handler)
    assert ok is True
    assert role == Role.AUDITOR
    assert status is None
    assert msg is None


def test_production_mode_requires_token():
    """With CLCA_API_TOKEN, missing token -> 401."""
    mw = SecurityMiddleware(api_token="secret-token")
    handler = _FakeHandler("/v1/runs")
    ok, role, status, msg = mw.check(handler)
    assert ok is False
    assert status == 401
    assert "Authorization" in msg


def test_production_mode_wrong_token():
    mw = SecurityMiddleware(api_token="secret-token")
    handler = _FakeHandler("/v1/runs", {"Authorization": "Bearer wrong-token"})
    ok, role, status, msg = mw.check(handler)
    assert ok is False
    assert status == 401


def test_production_mode_viewer_can_read_healthz():
    mw = SecurityMiddleware(api_token="secret-token")
    handler = _FakeHandler("/healthz", {"Authorization": "Bearer secret-token"})
    ok, role, status, msg = mw.check(handler)
    assert ok is True
    assert role == Role.VIEWER
    assert status is None


def test_production_mode_viewer_cannot_post_runs():
    """VIEWER cannot POST to /v1/runs (developer+ only)."""
    mw = SecurityMiddleware(api_token="secret-token")
    handler = _FakeHandler("/v1/runs", {
        "Authorization": "Bearer secret-token",
        "X-CLCA-Role": "viewer",
    })
    ok, role, status, msg = mw.check(handler)
    assert ok is False
    assert status == 403


def test_production_mode_developer_can_post_runs():
    mw = SecurityMiddleware(api_token="secret-token")
    handler = _FakeHandler("/v1/runs", {
        "Authorization": "Bearer secret-token",
        "X-CLCA-Role": "developer",
    })
    ok, role, status, msg = mw.check(handler)
    assert ok is True
    assert role == Role.DEVELOPER


def test_production_mode_policy_admin_can_access_admin():
    mw = SecurityMiddleware(api_token="secret-token")
    handler = _FakeHandler("/v1/admin/policy", {
        "Authorization": "Bearer secret-token",
        "X-CLCA-Role": "policy_admin",
    })
    ok, role, status, msg = mw.check(handler)
    assert ok is True
    assert role == Role.POLICY_ADMIN


def test_production_mode_invalid_role_header():
    mw = SecurityMiddleware(api_token="secret-token")
    handler = _FakeHandler("/healthz", {
        "Authorization": "Bearer secret-token",
        "X-CLCA-Role": "superuser",
    })
    ok, role, status, msg = mw.check(handler)
    assert ok is False
    assert status == 400


def test_required_role_for_path():
    assert required_role_for_path("/healthz") is not None
    assert required_role_for_path("/v1/runs") is not None
    assert required_role_for_path("/v1/admin/policy") is not None
    assert required_role_for_path("/v1/unknown") is None


def test_rate_limiting_in_production():
    mw = SecurityMiddleware(api_token="secret-token", rate_limit_per_minute=60, burst=2)
    headers = {"Authorization": "Bearer secret-token", "X-CLCA-Role": "viewer"}
    handler = _FakeHandler("/healthz", headers)

    # First two requests should pass (burst=2)
    assert mw.check(handler)[0] is True
    assert mw.check(handler)[0] is True

    # Third should be rate limited
    ok, role, status, msg = mw.check(handler)
    assert ok is False
    assert status == 429


def test_security_headers():
    mw = SecurityMiddleware(api_token=None)
    headers: dict[str, str] = {}

    class FakeHandler:
        def send_header(self, name, value):
            headers[name] = value
        def send_response(self, code):
            pass
        def end_headers(self):
            pass

    fh = FakeHandler()
    mw.security_headers(fh)
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in headers
    assert "Strict-Transport-Security" in headers
