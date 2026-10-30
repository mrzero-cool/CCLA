"""Canonical digest helpers.

Digest specification (architecture addendum, section A.1):
- Algorithm: SHA-256, always rendered as ``sha256:<64 lowercase hex>``.
- Canonical JSON: UTF-8, sorted keys, separators ``(",", ":")``, no NaN,
  ``None``/missing fields treated as absent (excluded by ``exclude_none``).
- File-tree digest: sorted ``relative/path\\tsha256:<hash>`` lines joined by ``\\n``.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PREFIX = ("a" * 64)
EMPTY_DIGEST = f"sha256:{_PREFIX[:0]}"  # placeholder replaced below

# Content digest of the empty input, used for deterministic defaults.
EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()

DEFAULT_EXCLUDES = {".git", ".venv", "node_modules", "__pycache__", "artifacts", ".pytest_cache"}


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def is_digest(value: str | None) -> bool:
    return bool(value) and bool(DIGEST_RE.match(value))


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def digest_obj(obj: Any) -> str:
    return sha256_hex(canonical_json(obj))


def digest_text(text: str) -> str:
    return sha256_hex(text.encode("utf-8"))


def iter_files(root: Path, excludes: Iterable[str] = DEFAULT_EXCLUDES) -> list[Path]:
    skip = set(excludes)
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        parts = set(path.relative_to(root).parts)
        if parts & skip:
            continue
        out.append(path)
    return out


def digest_tree(root: Path, excludes: Iterable[str] = DEFAULT_EXCLUDES) -> str:
    """Merkle-style digest over a working tree (used as the check input digest)."""
    lines: list[str] = []
    for path in iter_files(root, excludes):
        rel = path.relative_to(root).as_posix()
        lines.append(f"{rel}\t{sha256_hex(path.read_bytes())}")
    return sha256_hex("\n".join(lines).encode("utf-8"))
