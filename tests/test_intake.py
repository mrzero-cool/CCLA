"""Change intake: revision binding, diff digest, unversioned fallback."""
import shutil
import subprocess
from pathlib import Path

import pytest

from clca.intake import IntakeError, build_change_manifest, read_at_revision

SAMPLE_APP = Path(__file__).resolve().parents[1] / "sample_app"


def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


requires_git = pytest.mark.skipif(not _git_available(), reason="git is not available")


@requires_git
def test_git_manifest_binds_commits_and_digest(tmp_path):
    repo = tmp_path / "app"
    shutil.copytree(SAMPLE_APP, repo, ignore=shutil.ignore_patterns(".git", "artifacts", "__pycache__"))
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "clca@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "CLCA"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)

    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()

    target = repo / "backend" / "services" / "pricing.py"
    target.write_text(target.read_text(encoding="utf-8") + "\n# touched\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "touch"], cwd=repo, check=True)

    manifest = build_change_manifest(repo, base=base)
    assert manifest.version_bound is True
    assert manifest.changed_paths == ("backend/services/pricing.py",)
    assert manifest.diff_digest.startswith("sha256:")
    assert manifest.base_revision == base
    assert manifest.head_revision != base

    # Deterministic digest for the same change.
    again = build_change_manifest(repo, base=base)
    assert again.diff_digest == manifest.diff_digest


@requires_git
def test_read_at_revision_returns_baseline(tmp_path):
    repo = tmp_path / "app"
    shutil.copytree(SAMPLE_APP, repo, ignore=shutil.ignore_patterns(".git", "artifacts", "__pycache__"))
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "clca@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "CLCA"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)

    content = read_at_revision(repo, "HEAD", "agents/replenishment/tool_manifest.json")
    assert content is not None and "read_inventory" in content
    assert read_at_revision(repo, "HEAD", "does/not/exist.json") is None


def test_unversioned_scan_falls_back_to_content_digest(tmp_path):
    repo = tmp_path / "plain"
    shutil.copytree(SAMPLE_APP, repo, ignore=shutil.ignore_patterns(".git", "artifacts", "__pycache__"))
    manifest = build_change_manifest(repo)
    assert manifest.version_bound is False
    assert manifest.head_revision.startswith("worktree:")
    assert "backend/api/sales.py" in manifest.changed_paths

    again = build_change_manifest(repo)
    assert again.diff_digest == manifest.diff_digest


@requires_git
def test_git_manifest_refuses_dirty_worktree(tmp_path):
    repo = tmp_path / "app"
    shutil.copytree(SAMPLE_APP, repo, ignore=shutil.ignore_patterns(".git", "artifacts", "__pycache__"))
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "clca@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "CLCA"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
    (repo / "backend" / "services" / "pricing.py").write_text("# uncommitted drift\n", encoding="utf-8")

    with pytest.raises(IntakeError, match="working tree differs"):
        build_change_manifest(repo)


@requires_git
def test_git_manifest_refuses_head_that_is_not_checked_out(tmp_path):
    repo = tmp_path / "app"
    shutil.copytree(SAMPLE_APP, repo, ignore=shutil.ignore_patterns(".git", "artifacts", "__pycache__"))
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "clca@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "CLCA"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()
    (repo / "README.md").write_text("second commit\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "head"], cwd=repo, check=True)
    with pytest.raises(IntakeError, match="does not match requested head"):
        build_change_manifest(repo, head=base)
