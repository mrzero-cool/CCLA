#!/usr/bin/env python3
"""Initialize a portable, local-only Git baseline for the synthetic sample app.

The nested sample_app/.git directory is deliberately not distributed in source
archives. The CLI's diff-based intake expects a Git repository, so this helper
creates a local baseline when one is absent. It never configures a remote and
never changes an existing repository that already has a HEAD commit.
"""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, check=False,
        timeout=30,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result


def prepare_sample_app(repo: Path | None = None) -> str:
    sample = (repo or Path(__file__).resolve().parents[1] / "sample_app").resolve()
    if not sample.is_dir():
        raise FileNotFoundError(f"sample app directory not found: {sample}")
    top = _git(sample, "rev-parse", "--show-toplevel", check=False)
    # A sample app nested inside the CLCA repository inherits the parent Git
    # root. That is not a baseline for the sample app: initialize a nested local
    # repository unless the discovered top-level directory is exactly sample.
    is_sample_repo = (
        top.returncode == 0
        and Path(top.stdout.strip()).resolve() == sample
    )
    if not is_sample_repo:
        _git(sample, "init", "-q")
        # Local-only identity, scoped to this demo repo; no global config.
        _git(sample, "config", "user.name", "CLCA Demo")
        _git(sample, "config", "user.email", "clca-demo@localhost")
        _git(sample, "add", "-A")
        _git(sample, "commit", "-qm", "CLCA synthetic sample baseline")
        return "initialized"

    if _git(sample, "rev-parse", "--verify", "HEAD", check=False).returncode != 0:
        _git(sample, "config", "user.name", "CLCA Demo")
        _git(sample, "config", "user.email", "clca-demo@localhost")
        _git(sample, "add", "-A")
        _git(sample, "commit", "-qm", "CLCA synthetic sample baseline")
        return "committed_initial_baseline"

    return "already_initialized"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, help="sample app path (defaults to ./sample_app)")
    args = parser.parse_args()
    state = prepare_sample_app(args.repo)
    sample = (args.repo or Path(__file__).resolve().parents[1] / "sample_app").resolve()
    head = _git(sample, "rev-parse", "--short", "HEAD").stdout.strip()
    print(f"sample_app_git={state} head={head} repo={sample}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
