from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from clca.scripts.prepare_sample_app import prepare_sample_app


ROOT = Path(__file__).resolve().parents[1]


def test_prepare_sample_app_initializes_portable_copy(tmp_path):
    source = ROOT / "sample_app"
    target = tmp_path / "sample_app"
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "artifacts"),
    )
    assert not (target / ".git").exists()
    assert prepare_sample_app(target) == "initialized"
    top = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], cwd=target,
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert Path(top).resolve() == target.resolve()
    assert subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"], cwd=target,
        capture_output=True, text=True, check=False,
    ).returncode == 0


def test_prepare_sample_app_does_not_commit_existing_head(tmp_path):
    target = tmp_path / "sample_app"
    shutil.copytree(
        ROOT / "sample_app", target,
        ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "artifacts"),
    )
    prepare_sample_app(target)
    before = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=target,
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    (target / "README.md").write_text("dirty working tree\n", encoding="utf-8")
    assert prepare_sample_app(target) == "already_initialized"
    after = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=target,
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert after == before
    assert subprocess.run(
        ["git", "status", "--porcelain"], cwd=target,
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def test_prepare_sample_app_creates_nested_repo_when_parent_is_git_repo(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=parent, check=True)
    subprocess.run(["git", "config", "user.name", "Parent"], cwd=parent, check=True)
    subprocess.run(["git", "config", "user.email", "parent@localhost"], cwd=parent, check=True)
    (parent / "outer.txt").write_text("outer\n", encoding="utf-8")
    subprocess.run(["git", "add", "outer.txt"], cwd=parent, check=True)
    subprocess.run(["git", "commit", "-qm", "outer baseline"], cwd=parent, check=True)

    target = parent / "sample_app"
    shutil.copytree(
        ROOT / "sample_app", target,
        ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "artifacts"),
    )
    assert prepare_sample_app(target) == "initialized"
    top = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], cwd=target,
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert Path(top).resolve() == target.resolve()
