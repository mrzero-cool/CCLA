"""Tests for immutable repository binding (P0.4)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from clca.intake.git_diff import (
    build_change_manifest,
    is_merge_commit,
    record_content_hashes,
    validate_merge_base,
    verify_tree_integrity,
)


def test_record_content_hashes(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "file1.txt").write_text("hello world", encoding="utf-8")
    (repo / "file2.txt").write_text("goodbye", encoding="utf-8")

    hashes = record_content_hashes(repo, ["file1.txt", "file2.txt", "missing.txt"])

    assert "file1.txt" in hashes
    assert hashes["file1.txt"].startswith("sha256:")
    assert len(hashes["file1.txt"]) > 10
    assert "file2.txt" in hashes
    # Missing file is skipped, not an error
    assert "missing.txt" not in hashes


def test_record_content_hashes_different_content_different_hash(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.txt").write_text("content A", encoding="utf-8")
    (repo / "b.txt").write_text("content B", encoding="utf-8")

    hashes = record_content_hashes(repo, ["a.txt", "b.txt"])
    assert hashes["a.txt"] != hashes["b.txt"]


def test_verify_tree_integrity_matching(tmp_path):
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
    (repo / "f.txt").write_text("initial", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True, capture_output=True)

    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()

    # Should not raise (head matches, no tree digest check)
    verify_tree_integrity(repo, head)


def test_verify_tree_integrity_tree_changed(tmp_path):
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
    (repo / "f.txt").write_text("initial", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True, capture_output=True)

    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    tree_digest_before = __import__("clca.intake.git_diff", fromlist=["_tree_digest"])._tree_digest(repo)

    # Modify a file (changes tree digest but not HEAD)
    (repo / "f.txt").write_text("changed", encoding="utf-8")

    try:
        verify_tree_integrity(repo, head, tree_digest_before)
        assert False, "should have raised IntakeError"
    except Exception as exc:
        assert "commit-bound" in str(exc)



def test_verify_tree_integrity_wrong_head(tmp_path):
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
    (repo / "f.txt").write_text("initial", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True, capture_output=True)

    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()

    try:
        verify_tree_integrity(repo, "a" * 40)
        assert False, "should have raised IntakeError"
    except Exception as exc:
        assert "HEAD changed" in str(exc) or "commit-bound" in str(exc)


def test_is_merge_commit(tmp_path):
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
    (repo / "f.txt").write_text("initial", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True, capture_output=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()

    # Single commit: not a merge
    assert is_merge_commit(repo, head) is False


def test_validate_merge_base_valid(tmp_path):
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
    (repo / "f.txt").write_text("initial", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True, capture_output=True)
    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    (repo / "f.txt").write_text("modified", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "head"], cwd=repo, check=True, capture_output=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()

    # base should be valid merge base for head
    result = validate_merge_base(repo, base, head)
    assert result == base


def test_build_change_manifest_version_bound(tmp_path):
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
    (repo / "f.txt").write_text("initial", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True, capture_output=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()

    manifest = build_change_manifest(repo, head=head)
    assert manifest.version_bound is True
    assert manifest.head_revision == head
