"""Evidence signing and attestation for CLCA production trust boundaries.

Implements SLSA-compatible provenance: evidence bundles are signed by a
trusted workload identity (Ed25519) and independently verified before any
GitHub Check Run is posted.  The signing credential is never available to
the untrusted test process — it lives only in the control plane / reporter.

Usage:
    from clca.attestation import sign_bundle, verify_bundle, AttestationError

    signed = sign_bundle(bundle_dict, private_key_pem)
    is_valid = verify_bundle(signed, public_key_pem)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .digest import canonical_json


class AttestationError(RuntimeError):
    """Raised when evidence signing or verification fails."""


@dataclass
class AttestationEnvelope:
    """SLSA-compatible provenance envelope wrapping a signed evidence bundle."""

    payload_type: str = "application/vnd.clca.bundle.v1+json"
    subject: dict[str, Any] = field(default_factory=dict)
    bundle: dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    signer: str = ""
    signed_at: str = ""
    key_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "_type": self.payload_type,
            "subject": self.subject,
            "bundle": self.bundle,
            "signature": self.signature,
            "signer": self.signer,
            "signed_at": self.signed_at,
            "key_id": self.key_id,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 key pair.

    Returns (private_key_pem, public_key_pem) as bytes.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def load_private_key(private_key_pem: bytes | str) -> ed25519.Ed25519PrivateKey:
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode("utf-8")
    return serialization.load_pem_private_key(private_key_pem, password=None)


def load_public_key(public_key_pem: bytes | str) -> ed25519.Ed25519PublicKey:
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")
    return serialization.load_pem_public_key(public_key_pem)


def _canonical_bundle(bundle: dict[str, Any]) -> bytes:
    """Canonical JSON bytes of the bundle, excluding mutable signature fields."""
    return canonical_json(bundle)


def sign_bundle(
    bundle: dict[str, Any],
    private_key_pem: bytes | str,
    key_id: str = "",
    signer: str = "clca-control-plane",
) -> AttestationEnvelope:
    """Sign an evidence bundle with Ed25519 and return an attestation envelope.

    The bundle is canonicalized before signing so that any byte-level
    re-serialization invalidates the signature — tampering is detectable.
    """
    private_key = load_private_key(private_key_pem)

    subject = {
        "name": bundle.get("change_id", "unknown"),
        "digest": {
            "sha256": hashlib.sha256(_canonical_bundle(bundle)).hexdigest(),
        },
    }

    canonical = _canonical_bundle(bundle)
    signature_bytes = private_key.sign(canonical)
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    return AttestationEnvelope(
        payload_type="application/vnd.clca.bundle.v1+json",
        subject=subject,
        bundle=bundle,
        signature=signature_b64,
        signer=signer,
        signed_at=_utc_now(),
        key_id=key_id,
    )


def verify_bundle(
    envelope: dict[str, Any],
    public_key_pem: bytes | str,
    expected_subject: str | None = None,
) -> dict[str, Any]:
    """Verify a signed evidence bundle and return the inner bundle.

    Raises AttestationError if:
    - the signature does not verify (tampered bundle or wrong key)
    - the envelope structure is invalid
    - expected_subject is given and does not match
    """
    public_key = load_public_key(public_key_pem)

    if not isinstance(envelope, dict):
        raise AttestationError("envelope must be a JSON object")

    bundle = envelope.get("bundle")
    signature_b64 = envelope.get("signature", "")
    signer = envelope.get("signer", "")
    subject = envelope.get("subject", {})

    if bundle is None:
        raise AttestationError("envelope missing 'bundle' field")
    if not signature_b64:
        raise AttestationError("envelope missing 'signature' field")

    if expected_subject is not None and subject.get("name") != expected_subject:
        raise AttestationError(
            f"subject mismatch: expected {expected_subject!r}, got {subject.get('name')!r}"
        )

    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception as exc:
        raise AttestationError(f"invalid signature encoding: {exc}") from exc

    canonical = _canonical_bundle(bundle)
    try:
        public_key.verify(signature_bytes, canonical)
    except InvalidSignature as exc:
        raise AttestationError("bundle signature verification failed — bundle may be tampered") from exc

    return bundle


def sign_bundle_file(
    bundle_path: Path | str,
    private_key_pem: bytes | str,
    output_path: Path | str | None = None,
    key_id: str = "",
    signer: str = "clca-control-plane",
) -> Path:
    """Read a bundle JSON file, sign it, and write the attestation envelope.

    Returns the path to the written envelope file.
    """
    bundle_path = Path(bundle_path)
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))

    envelope = sign_bundle(bundle, private_key_pem, key_id=key_id, signer=signer)

    out_path = Path(output_path) if output_path else bundle_path.with_suffix(".attested.json")
    out_path.write_text(json.dumps(envelope.to_dict(), indent=2), encoding="utf-8")
    return out_path


def verify_bundle_file(
    envelope_path: Path | str,
    public_key_pem: bytes | str,
    expected_subject: str | None = None,
) -> dict[str, Any]:
    """Read an attested envelope file, verify it, and return the inner bundle."""
    envelope_path = Path(envelope_path)
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    return verify_bundle(envelope, public_key_pem, expected_subject=expected_subject)


def attestation_summary(envelope: dict[str, Any]) -> dict[str, Any]:
    """Human-readable summary of an attestation envelope (no verification)."""
    return {
        "signer": envelope.get("signer", "unknown"),
        "signed_at": envelope.get("signed_at", "unknown"),
        "key_id": envelope.get("key_id", "unknown"),
        "has_signature": bool(envelope.get("signature")),
        "subject": envelope.get("subject", {}),
        "bundle_has_digest": bool(envelope.get("bundle", {}).get("bundle_digest")),
    }



