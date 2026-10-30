"""Artifact handling: every executed check writes a redacted, digested artifact."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..digest import is_digest, sha256_hex
from ..redact import redact_excerpt


class ArtifactStore:
    def __init__(self, root: Path):
        self.root = root.resolve()

    def _resolve(self, ref: str) -> Path:
        if not ref.startswith("artifact://"):
            raise ValueError(f"unsupported artifact reference scheme: {ref[:40]}")
        relative = ref[len("artifact://"):]
        target = (self.root / relative).resolve()
        if not target.is_relative_to(self.root):
            raise ValueError(f"artifact reference escapes the artifact root: {ref[:80]}")
        return target

    def write(self, run_id: str, name: str, payload: dict[str, Any]) -> tuple[str, str]:
        """Write an artifact and return (artifact_ref, sha256 digest)."""
        safe_run_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(run_id))[:120]
        safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in str(name))[:160]
        if safe_run_id in ("", ".", ".."):
            safe_run_id = "run"
        if safe_name in ("", ".", ".."):
            safe_name = "artifact"
        run_dir = self.root / safe_run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        resolved_dir = run_dir.resolve()
        if not resolved_dir.is_relative_to(self.root):
            raise ValueError("artifact run directory escapes the artifact root")
        target = resolved_dir / f"{safe_name}.json"
        if not target.resolve().is_relative_to(self.root):
            raise ValueError("artifact target escapes the artifact root")
        body = json.dumps(payload, indent=2, sort_keys=True, default=str)
        target.write_text(redact_excerpt(body, limit=200_000) + "\n", encoding="utf-8")
        return f"artifact://{safe_run_id}/{safe_name}.json", sha256_hex(target.read_bytes())

    def verify(self, ref: str, expected_digest: str | None) -> str:
        """Return None-like status string: 'ok', 'missing' or 'mismatch'."""
        try:
            target = self._resolve(ref)
        except ValueError:
            return "missing"
        if not target.is_file():
            return "missing"
        # Existence is not execution proof. Missing or malformed digest must
        # never be treated as a verified artifact.
        if not is_digest(expected_digest):
            return "missing_digest"
        actual = sha256_hex(target.read_bytes())
        if actual != expected_digest:
            return "mismatch"
        return "ok"
