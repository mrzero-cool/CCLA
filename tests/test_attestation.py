"""Tests for CLCA evidence signing and attestation (P0.3)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clca.attestation import (
    AttestationError,
    AttestationEnvelope,
    attestation_summary,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_bundle,
    sign_bundle_file,
    verify_bundle,
    verify_bundle_file,
)


def test_generate_keypair_produces_valid_pem():
    private_pem, public_pem = generate_keypair()
    assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    priv = load_private_key(private_pem)
    pub = load_public_key(public_pem)
    assert priv is not None
    assert pub is not None


def test_sign_and_verify_roundtrip():
    bundle = {
        "change_id": "change-abc123",
        "repository": "demo/repo",
        "head_revision": "b" * 40,
        "base_revision": "a" * 40,
        "decision": "BLOCK",
        "reasons": ["Mandatory check failed: agent-security-smoke"],
        "bundle_digest": "sha256:" + "d" * 64,
    }
    private_pem, public_pem = generate_keypair()

    envelope = sign_bundle(bundle, private_pem, key_id="key-1", signer="clca-reporter")
    assert envelope.signature != ""
    assert envelope.signer == "clca-reporter"
    assert envelope.key_id == "key-1"
    assert envelope.signed_at != ""

    # Verify returns the exact same bundle
    verified = verify_bundle(envelope.to_dict(), public_pem)
    assert verified["change_id"] == "change-abc123"
    assert verified["decision"] == "BLOCK"
    assert verified["bundle_digest"] == bundle["bundle_digest"]


def test_tampered_bundle_fails_verification():
    bundle = {
        "change_id": "change-xyz",
        "decision": "PASS",
        "bundle_digest": "sha256:" + "e" * 64,
    }
    private_pem, public_pem = generate_keypair()
    envelope = sign_bundle(bundle, private_pem)

    # Tamper with the decision after signing
    tampered = envelope.to_dict()
    tampered["bundle"]["decision"] = "PASS"  # was already PASS, change something
    tampered["bundle"]["decision"] = "BLOCK"  # now it's different from what was signed

    try:
        verify_bundle(tampered, public_pem)
        assert False, "should have raised AttestationError"
    except AttestationError:
        pass


def test_wrong_key_fails_verification():
    bundle = {"change_id": "change-1", "decision": "PASS"}
    private_pem_a, public_pem_a = generate_keypair()
    private_pem_b, public_pem_b = generate_keypair()

    envelope = sign_bundle(bundle, private_pem_a)

    try:
        verify_bundle(envelope.to_dict(), public_pem_b)
        assert False, "should have raised AttestationError with wrong key"
    except AttestationError:
        pass


def test_expected_subject_mismatch_fails():
    bundle = {"change_id": "change-1", "decision": "PASS"}
    private_pem, public_pem = generate_keypair()
    envelope = sign_bundle(bundle, private_pem)

    try:
        verify_bundle(envelope.to_dict(), public_pem, expected_subject="different-change")
        assert False, "should have raised AttestationError"
    except AttestationError:
        pass


def test_expected_subject_match_succeeds():
    bundle = {"change_id": "change-1", "decision": "PASS"}
    private_pem, public_pem = generate_keypair()
    envelope = sign_bundle(bundle, private_pem)

    verified = verify_bundle(envelope.to_dict(), public_pem, expected_subject="change-1")
    assert verified["change_id"] == "change-1"


def test_sign_and_verify_bundle_file():
    bundle = {
        "change_id": "change-file",
        "decision": "WARN",
        "bundle_digest": "sha256:" + "f" * 64,
    }
    private_pem, public_pem = generate_keypair()

    with tempfile.TemporaryDirectory() as td:
        bundle_path = Path(td) / "bundle.json"
        envelope_path = Path(td) / "bundle.attested.json"
        bundle_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

        written = sign_bundle_file(bundle_path, private_pem, output_path=envelope_path)
        assert written == envelope_path
        assert envelope_path.is_file()

        verified = verify_bundle_file(envelope_path, public_pem)
        assert verified["change_id"] == "change-file"
        assert verified["decision"] == "WARN"


def test_attestation_summary():
    private_pem, public_pem = generate_keypair()
    bundle = {"change_id": "change-summary", "decision": "BLOCK"}
    envelope = sign_bundle(bundle, private_pem, key_id="key-abc", signer="reporter-1")

    summary = attestation_summary(envelope.to_dict())
    assert summary["signer"] == "reporter-1"
    assert summary["key_id"] == "key-abc"
    assert summary["has_signature"] is True
    assert summary["bundle_has_digest"] is False  # bundle has no bundle_digest


def test_load_private_key_from_str():
    private_pem, _ = generate_keypair()
    priv = load_private_key(private_pem.decode("utf-8"))
    assert priv is not None


def test_load_public_key_from_str():
    _, public_pem = generate_keypair()
    pub = load_public_key(public_pem.decode("utf-8"))
    assert pub is not None
