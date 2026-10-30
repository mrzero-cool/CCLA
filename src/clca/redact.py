"""Secret redaction for every output path (CLI stdout, files, artifacts, reports)."""
from __future__ import annotations

import re

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA***REDACTED***"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "gh*_***REDACTED***"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "xox*_***REDACTED***"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "jwt_***REDACTED***"),
    # OpenAI-style keys (sk-..., including sk-proj-...).
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "sk-***REDACTED***"),
    # PEM private key blocks; the line-level patterns catch dangling BEGIN/END
    # headers in truncated excerpts where no matching END/BEGIN exists.
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "[PRIVATE_KEY]***REDACTED***"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "[PRIVATE_KEY]***REDACTED***"),
    (re.compile(r"-----END [A-Z ]*PRIVATE KEY-----"), "[PRIVATE_KEY]***REDACTED***"),
    # Authorization header values. The {8,} floor keeps prose like
    # "bearer token" or "bearer of news" from matching.
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer ***REDACTED***"),
    (re.compile(r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|PRIVATE_KEY))[ \t]*[=:][ \t]*([^\s'\"]+)"),
     r"\1=***REDACTED***"),
]

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def redact(text: str) -> str:
    out = text
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return _CONTROL.sub("", out)


def redact_excerpt(text: str, limit: int = 4000) -> str:
    """Redact, strip control characters, and keep a bounded tail of the log.

    Redaction runs BEFORE truncation, deliberately: cutting first could split
    a secret across the boundary so the surviving prefix no longer matches any
    pattern (e.g. a log ending in ``ghp_`` + 18 chars). With redact-then-cut,
    no live full token can exist in any window; the only artifact of the cut
    is a possibly-clipped redaction marker, which is harmless.
    """
    cleaned = redact(text)
    if len(cleaned) > limit:
        cleaned = "…[truncated]…\n" + cleaned[-limit:]
    return cleaned
