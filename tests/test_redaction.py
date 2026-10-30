"""Focused regression tests for secret redaction.

There was previously no test anywhere asserting redaction behaviour; this
module is the regression net for `clca.redact` (existing patterns + the
OpenAI-key / PEM-block / Bearer-token additions, control-char stripping,
excerpt truncation ordering, and prose false-positive safety).
"""
from __future__ import annotations

from clca.redact import redact, redact_excerpt


# --- new patterns -----------------------------------------------------------

def test_openai_style_key_redacted():
    key = "sk-proj-abc123def456ghi789JKLM"
    out = redact(f"using key {key} now")
    assert key not in out
    assert "sk-***REDACTED***" in out


def test_openai_style_key_bare_sk_min_length():
    key = "sk-0123456789abcdef"  # exactly 16 chars after sk-
    assert key not in redact(f"api={key}")
    # shorter than the threshold stays (not a key shape we claim to catch)
    assert "sk-abc" in redact("task-sk-abc")


def test_pem_private_key_block_redacted():
    text = (
        "header\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZF1pGSHvW\n"
        "-----END RSA PRIVATE KEY-----\n"
        "footer"
    )
    out = redact(text)
    assert "MIIEpAIBAAKCAQEA" not in out
    assert "-----BEGIN" not in out
    assert "-----END" not in out
    assert "[PRIVATE_KEY]***REDACTED***" in out
    assert "header" in out and "footer" in out


def test_dangling_pem_begin_header_redacted():
    # excerpts may be truncated with no END line present
    text = "log tail\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktaGVh"
    out = redact(text)
    assert "-----BEGIN" not in out
    assert "[PRIVATE_KEY]***REDACTED***" in out
    assert "b3BlbnNzaC1rZXktaGVh" in out  # body untouched without a block marker


def test_dangling_pem_end_line_redacted():
    out = redact("...\n-----END EC PRIVATE KEY-----\n")
    assert "-----END" not in out
    assert "[PRIVATE_KEY]***REDACTED***" in out


def test_bearer_token_redacted():
    out = redact("Authorization: Bearer abcDEfgh12345.+-_xyz")
    assert "abcDEfgh12345" not in out
    assert "Bearer ***REDACTED***" in out


def test_bearer_with_jwt_gets_jwt_marker_first():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
    out = redact(f"Authorization: Bearer {jwt}")
    assert jwt not in out
    assert "jwt_***REDACTED***" in out


# --- existing patterns (regression net) -------------------------------------

def test_akia_key_redacted():
    key = "AKIAIOSFODNN7EXAMPLE"
    assert key not in redact(f"aws id {key}")
    assert "AKIA***REDACTED***" in redact(f"aws id {key}")


def test_github_token_redacted():
    tok = "ghp_abcdefghijklmnopqrstuvwxyz123456"
    out = redact(f"url={tok}")
    assert tok not in out
    assert "gh*_***REDACTED***" in out


def test_slack_token_redacted():
    tok = "xoxb-1234567890-abcdef123456-0123456789abcdef"
    out = redact(f"hook {tok} end")
    assert tok not in out
    assert "xox*_***REDACTED***" in out


def test_jwt_redacted():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
    out = redact(f"cookie={jwt}")
    assert jwt not in out
    assert "jwt_***REDACTED***" in out


def test_token_assignment_redacted():
    assert "abc123XYZ" not in redact("TOKEN=abc123XYZ")
    assert "TOKEN=***REDACTED***" in redact("TOKEN=abc123XYZ")
    assert "hunter2" not in redact("password : hunter2")
    assert "sk-0123456789abcdef" not in redact("API_KEY=sk-0123456789abcdef")


# --- control characters -----------------------------------------------------

def test_control_chars_stripped():
    assert redact("a\x00b\x07c\x0bd\x0ce\x1ff\x7fg") == "abcdefg"


# --- excerpt truncation -----------------------------------------------------

def test_excerpt_redacts_and_bounds_length():
    tok = "ghp_abcdefghijklmnopqrstuvwxyz123456"
    text = ("filler line\n" * 1000) + f"secret {tok}"
    out = redact_excerpt(text)
    assert tok not in out
    assert "ghp_" not in out  # marker form is gh*_, never the live prefix
    assert out.startswith("…[truncated]…\n")
    assert len(out) <= 4000 + len("…[truncated]…\n")


def test_excerpt_token_at_very_end_is_redacted():
    # proves redact runs BEFORE truncation: the kept tail is redacted too
    tok = "ghp_zyxwvutsrqponmlkjihgfedcba654321"
    text = ("filler line\n" * 1000) + f"last word {tok}"
    out = redact_excerpt(text)
    assert tok not in out
    assert "ghp_" not in out
    assert out.rstrip().endswith("gh*_***REDACTED***")


def test_excerpt_token_spanning_cut_point_cannot_survive():
    # a token positioned so the truncation boundary splits it must not leave
    # a live-looking prefix (redact-then-cut makes this impossible by design)
    tok = "ghp_QQQQQQQQQQQQQQQQQQQQQQQQQQ"
    text = ("x" * 100) + tok + ("y" * 3985)  # cut at len-4000 lands mid-token
    out = redact_excerpt(text)
    assert tok not in out
    assert "ghp_" not in out
    assert "…[truncated]…" in out


def test_excerpt_short_text_untouched_shape():
    text = "short log line"
    assert redact_excerpt(text) == text
    tok = "ghp_abcdefghijklmnopqrstuvwxyz123456"
    out = redact_excerpt(f"short {tok} line")
    assert tok not in out and "ghp_" not in out
    assert "[truncated]" not in out


# --- no false positives on benign prose -------------------------------------

def test_benign_prose_untouched():
    sentences = [
        "You should use a password manager for all your credentials.",
        "The committee decided to bear the cost of the migration.",
        "A bearer of good news arrived at the standup.",
        "The bearer token was refreshed before the request.",
        "Store the api key somewhere safe, not in code.",
        "This change touches pricing, contracts, and agent prompts.",
    ]
    for s in sentences:
        assert redact(s) == s, f"false positive on: {s!r}"


def test_prose_with_short_bearer_word_not_redacted():
    # "bearer" without an 8+ char token must not match
    assert redact("bearer token") == "bearer token"
    assert redact("Bearer of the message") == "Bearer of the message"
