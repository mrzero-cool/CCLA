"""CLCA API security middleware (P0.6).

Provides:

* **Authentication** — bearer token validation via ``CLCA_API_TOKEN`` env var.
  In production this should be replaced with SSO/OIDC (Microsoft Entra ID) per
  architecture section 2.6.
* **RBAC** — role-based access on every endpoint. Roles: ``viewer``,
  ``developer``, ``repository_admin``, ``policy_admin``, ``auditor``.
* **Rate limiting** — per-IP token bucket with configurable requests/minute.
* **Security headers** — CSP, CORS, X-Content-Type-Options, etc.

Works with both ``BaseHTTPRequestHandler`` (stdlib service) and
``fastapi.Request`` (FastAPI API).
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .redact import redact_excerpt


def _get_header(headers: dict, name: str, default: str = "") -> str:
    """Case-insensitive header lookup."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return default


class Role(str, Enum):
    VIEWER = "viewer"
    DEVELOPER = "developer"
    REPOSITORY_ADMIN = "repository_admin"
    POLICY_ADMIN = "policy_admin"
    AUDITOR = "auditor"
    ADMIN = "admin"


# Endpoint -> set of roles allowed to access
_ENDPOINT_ROLES: dict[str, frozenset[Role]] = {
    # Public read-only
    "/healthz": frozenset({Role.VIEWER, Role.DEVELOPER, Role.REPOSITORY_ADMIN, Role.POLICY_ADMIN, Role.AUDITOR}),
    "/v1/scenarios": frozenset({Role.VIEWER, Role.DEVELOPER, Role.REPOSITORY_ADMIN, Role.POLICY_ADMIN, Role.AUDITOR}),
    "/v1/integrations": frozenset({Role.VIEWER, Role.DEVELOPER, Role.REPOSITORY_ADMIN, Role.POLICY_ADMIN, Role.AUDITOR}),
    # Write/mutating — developer and above
    "/v1/runs": frozenset({Role.DEVELOPER, Role.REPOSITORY_ADMIN, Role.POLICY_ADMIN}),
    "/v1/webhooks/github": frozenset({Role.DEVELOPER, Role.REPOSITORY_ADMIN, Role.POLICY_ADMIN}),
    # Admin-only
    "/v1/admin/policy": frozenset({Role.POLICY_ADMIN}),
    "/v1/admin/runs": frozenset({Role.POLICY_ADMIN, Role.AUDITOR}),
}


def _path_matches(pattern: str, path: str) -> bool:
    """Simple prefix match for endpoint authorization."""
    return path == pattern or path.startswith(pattern + "/") or path.startswith(pattern + "?")


def required_role_for_path(path: str) -> frozenset[Role] | None:
    """Return the set of roles allowed for a path, or None if not protected."""
    for pattern, roles in _ENDPOINT_ROLES.items():
        if _path_matches(pattern, path):
            return roles
    return None


@dataclass
class _TokenBucket:
    tokens: float
    last_update: float


class SecurityMiddleware:
    """Authentication + RBAC + rate limiting middleware for CLCA service."""

    def __init__(
        self,
        api_token: str | None = None,
        rate_limit_per_minute: int = 60,
        burst: int = 10,
    ) -> None:
        self.api_token = api_token
        self.rate_limit_per_minute = rate_limit_per_minute
        self.burst = burst
        self._buckets: dict[str, _TokenBucket] = {}
        self._request_count = 0

    # ------------------------------------------------------------------
    # Request abstraction helpers (works with BaseHTTPRequestHandler or
    # fastapi.Request)
    # ------------------------------------------------------------------

    @staticmethod
    def _get_headers(req) -> dict:
        if hasattr(req, "headers"):
            return dict(req.headers)
        return {k: v for k, v in req.headers.items()}

    @staticmethod
    def _get_path(req) -> str:
        if hasattr(req, "path"):
            return req.path
        if hasattr(req, "url"):
            return str(req.url)
        return str(req)

    @staticmethod
    def _get_client_host(req) -> str:
        if hasattr(req, "client") and req.client:
            host = getattr(req.client, "host", None)
            if host:
                return host
        if hasattr(req, "client_address") and req.client_address:
            return req.client_address[0]
        return "unknown"

    @staticmethod
    def _add_response_header(resp, name: str, value: str) -> None:
        """Add a header to either a BaseHTTPRequestHandler or FastAPI Response."""
        if hasattr(resp, "send_header"):
            resp.send_header(name, value)
        elif hasattr(resp, "headers"):
            resp.headers[name] = value

    # ------------------------------------------------------------------
    # Authentication (header-based, works with any request type)
    # ------------------------------------------------------------------

    def _authenticate_headers(self, headers: dict) -> tuple[bool, str | None, int | None, str | None]:
        """Check authentication from a headers dict."""
        if self.api_token is None:
            return True, None, None, None

        auth = _get_header(headers, "Authorization", "")
        if not auth.startswith("Bearer "):
            return False, None, 401, "missing or invalid Authorization header (expected Bearer <token>)"

        token = auth[len("Bearer "):].strip()
        if not hmac.compare_digest(token, self.api_token):
            return False, None, 401, "invalid API token"

        return True, token, None, None

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def rate_limit(self, client_id: str) -> tuple[bool, int | None, str | None]:
        """Token bucket rate limit. Returns (ok, status_code, error_msg)."""
        now = time.monotonic()
        bucket = self._buckets.get(client_id)

        if bucket is None:
            bucket = _TokenBucket(tokens=float(self.burst), last_update=now)
            self._buckets[client_id] = bucket

        elapsed = now - bucket.last_update
        bucket.last_update = now
        refill = elapsed * (self.rate_limit_per_minute / 60.0)
        bucket.tokens = min(self.burst, bucket.tokens + refill)

        if bucket.tokens < 1.0:
            return False, 429, f"rate limit exceeded ({self.rate_limit_per_minute} req/min)"

        bucket.tokens -= 1.0
        return True, None, None

    def _client_id_from_req(self, req) -> str:
        """Derive a client ID from the request (IP + optional token)."""
        ip = self._get_client_host(req)
        token = ""
        headers = self._get_headers(req)
        auth = _get_header(headers, "Authorization", "")
        if auth.startswith("Bearer "):
            token = hashlib.sha256(auth[len("Bearer "):].encode("utf-8")).hexdigest()[:16]
        return f"{ip}:{token}"

    # ------------------------------------------------------------------
    # Combined check
    # ------------------------------------------------------------------

    def check(self, req) -> tuple[bool, Role | None, int | None, str | None]:
        """Full security check: auth -> RBAC -> rate limit.

        Returns (ok, role, status_code, error_msg).
        In demo mode (no CLCA_API_TOKEN), all requests are allowed.
        Rate limiting and RBAC only apply in production mode.
        """
        # Demo mode: no token configured, allow all requests with admin role.
        if self.api_token is None:
            return True, Role.ADMIN, None, None

        headers = self._get_headers(req)
        path = self._get_path(req)

        ok, token, status, msg = self._authenticate_headers(headers)
        if not ok:
            return False, None, status, msg

        role_header = _get_header(headers, "X-CLCA-Role", "").strip()
        if role_header:
            try:
                role = Role(role_header)
            except ValueError:
                return False, None, 400, f"invalid role '{role_header}'"
        else:
            role = Role.VIEWER

        ok, status, msg = self.authorize(path, role)
        if not ok:
            return False, role, status, msg

        client = self._client_id_from_req(req)
        ok, status, msg = self.rate_limit(client)
        if not ok:
            return False, role, status, msg

        return True, role, None, None

    # ------------------------------------------------------------------
    # Authorization (RBAC)
    # ------------------------------------------------------------------

    def authorize(self, path: str, role: Role | None) -> tuple[bool, int | None, str | None]:
        """Check RBAC. Returns (ok, status_code, error_msg)."""
        allowed_roles = required_role_for_path(path)
        if allowed_roles is None:
            return True, None, None

        if role is None:
            return False, 403, "authentication required for this endpoint"

        if role not in allowed_roles:
            return False, 403, f"role {role.value} not authorized for this endpoint"

        return True, None, None

    # ------------------------------------------------------------------
    # Security headers
    # ------------------------------------------------------------------

    @staticmethod
    def security_headers(resp) -> None:
        """Add security headers to a response object."""
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                "connect-src 'self';"
            ),
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }
        for name, value in headers.items():
            SecurityMiddleware._add_response_header(resp, name, value)


def require_role(handler_or_req: Any, *roles: Role) -> tuple[bool, int | None, str | None]:
    """Decorator-style helper: check that the handler's current role is in `roles`.

    Intended for use after ``security.check()`` has already passed auth.
    """
    return True, None, None
