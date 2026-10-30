from datetime import datetime, timezone

import pytest

from clca.cli import _artifact_store
from clca.models import ChangeSet, EvidenceBundle


def make_bundle(artifact_root):
    return EvidenceBundle(
        change=ChangeSet(
            change_id="untrusted-bundle", repository="demo",
            base_revision="a" * 40, head_revision="b" * 40,
            diff_digest="sha256:" + "c" * 64, created_at=datetime.now(timezone.utc),
        ),
        policy_digest="sha256:" + "d" * 64,
        artifact_root=str(artifact_root),
    )


def test_bundle_cannot_choose_artifact_root_outside_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    bundle = make_bundle(outside)
    with pytest.raises(PermissionError, match="must be inside the repository"):
        _artifact_store(bundle, repo, None)
    assert not outside.exists()


def test_explicit_operator_artifact_root_override_is_allowed(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "operator-artifacts"
    bundle = make_bundle(tmp_path / "forged-bundle-root")
    store = _artifact_store(bundle, repo, str(outside))
    assert store.root == outside.resolve()
    assert outside.is_dir()
