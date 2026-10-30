"""Agent security smoke: the declared permissions must stay least-privilege."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((ROOT / "agents" / "replenishment" / "tool_manifest.json").read_text(encoding="utf-8"))


def test_no_allowed_write_tools():
    offenders = [t["name"] for t in MANIFEST["tools"] if t.get("allowed") and t.get("access") == "write"]
    assert not offenders, f"allowed write tools present: {sorted(offenders)}"


def test_no_allowed_external_tools():
    offenders = [t["name"] for t in MANIFEST["tools"] if t.get("allowed") and t.get("external")]
    assert not offenders, f"allowed outbound tools present: {sorted(offenders)}"


def test_policy_flags_stay_locked_down():
    policy = MANIFEST["policy"]
    assert policy["allow_write_tools"] is False
    assert policy["allow_external_recipients"] is False
    assert policy["require_evidence_refs"] is True


def test_model_binding_is_pinned():
    binding = MANIFEST["model_binding"]
    assert binding["model_id"], "model binding must be pinned to an explicit model id"
