"""Change intake: immutable revision binding and diff digest computation."""
from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..digest import digest_text, digest_tree

_GIT_EXCLUDES = (".git", ".venv", "node_modules", "__pycache__", "artifacts", ".pytest_cache")


def _is_excluded_path(path: str, excluded_paths: tuple[str, ...] = ()) -> bool:
    normalized = path.replace("\\", "/").lstrip("./")
    parts = set(normalized.split("/"))
    return bool(parts.intersection(_GIT_EXCLUDES)) or any(
        normalized == excluded or normalized.startswith(excluded.rstrip("/") + "/")
        for excluded in excluded_paths
    )


def _assert_checkout_matches_head(repo: Path, head_rev: str, excluded_paths: tuple[str, ...]) -> None:
    """Reject analysis when adapters would read bytes different from ``head_rev``.

    Intake binds the PR to committed revisions, while source adapters inspect
    files on disk. Letting those sources diverge creates evidence for one diff
    and executes tests against another tree. This check is a correctness guard,
    not a sandbox or protection against a malicious checkout.
    """
    current_head = _git(repo, "rev-parse", "HEAD").strip()
    if current_head != head_rev:
        raise IntakeError(
            f"checked-out HEAD ({current_head[:12]}) does not match requested head "
            f"({head_rev[:12]}); check out the requested revision before analysis"
        )

    status = _git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    dirty: list[str] = []
    for line in status.splitlines():
        if len(line) < 4:
            continue
        path_text = line[3:]
        paths = path_text.split(" -> ") if " -> " in path_text else [path_text]
        for path in paths:
            path = path.strip().strip('"')
            if path and not _is_excluded_path(path, excluded_paths):
                dirty.append(path)
    if dirty:
        sample = ", ".join(sorted(set(dirty))[:8])
        raise IntakeError(
            "working tree differs from committed source; adapters and checks would not match "
            f"the revision-bound diff (changed paths: {sample}). Commit/stash the change or "
            "exclude generated paths explicitly before running CLCA."
        )


class IntakeError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChangeManifest:
    repository: str
    base_revision: str
    head_revision: str
    diff_digest: str
    changed_paths: tuple[str, ...]
    excluded_paths: tuple[str, ...] = ()
    parser_versions: dict[str, str] = field(default_factory=dict)
    event_origin: str = "local_cli"
    version_bound: bool = True  # False when no VCS binding was available
    is_merge_commit: bool = False  # True when head is a merge commit
    content_hashes: dict[str, str] = field(default_factory=dict)  # path -> sha256:hex


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=str(repo), capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        raise IntakeError(f"git {' '.join(args)} failed: {proc.stderr.strip()[:400]}")
    return proc.stdout


def is_git_repo(repo: Path) -> bool:
    try:
        return _git(repo, "rev-parse", "--is-inside-work-tree").strip() == "true"
    except (IntakeError, FileNotFoundError):
        return False


def read_at_revision(repo: Path, revision: str, path: str) -> str | None:
    """Return file content at a revision, or None when unavailable."""
    try:
        return _git(repo, "show", f"{revision}:{path}")
    except (IntakeError, FileNotFoundError):
        return None


def _tree_digest(repo: Path) -> str:
    lines = []
    for rel in _tracked_paths(repo):
        sha = _git(repo, "rev-parse", f"HEAD:{rel}").strip() if _has_head(repo) else None
        lines.append(f"{rel}\t{sha or 'untracked'}")
    return digest_text("\n".join(lines))


def _has_head(repo: Path) -> bool:
    try:
        _git(repo, "rev-parse", "--verify", "HEAD")
        return True
    except IntakeError:
        return False


def _tracked_paths(repo: Path) -> list[str]:
    out = _git(repo, "ls-files").splitlines()
    return [p for p in out if not any(part in _GIT_EXCLUDES for part in p.split("/"))]


def _scan_paths(repo: Path) -> list[str]:
    from ..digest import iter_files

    return [p.relative_to(repo).as_posix() for p in iter_files(repo, _GIT_EXCLUDES)]


def build_change_manifest(
    repo: Path,
    base: str | None = None,
    head: str | None = None,
    excluded_paths: tuple[str, ...] = (),
) -> ChangeManifest:
    """Build an immutable change manifest.

    Git mode requires resolved base/head commit SHAs. When the repository has no
    VCS binding (demo/evaluation mode), the manifest is bound to a content digest
    of the working tree instead and ``version_bound`` is False, which surfaces as
    a non-blocking coverage gap rather than silently claiming commit identity.
    """
    repo = repo.resolve()
    if not repo.is_dir():
        raise IntakeError(f"repository path does not exist: {repo}")

    if is_git_repo(repo):
        head_rev = _git(repo, "rev-parse", head or "HEAD").strip()
        _assert_checkout_matches_head(repo, head_rev, excluded_paths)

        # Detect merge commits and validate merge base
        if is_merge_commit(repo, head_rev):
            parent_count = len(_git(repo, "rev-list", "--parents", "-n", "1", head_rev).strip().split()) - 1
            if parent_count >= 2:
                # Merge commit: base should be one of the parents or a valid merge base
                pass  # base validation below handles this

        if base:
            base_rev = validate_merge_base(repo, base, head_rev)
        else:
            try:
                base_rev = _git(repo, "rev-parse", f"{head_rev}^").strip() if _has_head(repo) else head_rev
            except IntakeError:
                base_rev = head_rev  # single-commit repository: no parent to diff against
        raw = _git(repo, "diff", "--name-only", base_rev, head_rev)
        changed = tuple(sorted(p for p in raw.splitlines() if p and p not in excluded_paths))
        diff_lines = []
        for path in changed:
            sha = _git(repo, "rev-parse", f"{head_rev}:{path}").strip() if _file_in_rev(repo, head_rev, path) else "deleted"
            diff_lines.append(f"{path}\t{sha}")
        return ChangeManifest(
            repository=repo.name,
            base_revision=base_rev,
            head_revision=head_rev,
            diff_digest=digest_text("\n".join(diff_lines)),
            changed_paths=changed,
            excluded_paths=excluded_paths,
            parser_versions={"git": _git(repo, "--version").strip()},
            version_bound=True,
            is_merge_commit=is_merge_commit(repo, head_rev),
        )

    paths = tuple(p for p in _scan_paths(repo) if p not in excluded_paths)
    tree = digest_tree(repo)
    return ChangeManifest(
        repository=repo.name,
        base_revision=f"worktree:{tree}",
        head_revision=f"worktree:{tree}",
        diff_digest=tree,
        changed_paths=paths,
        excluded_paths=excluded_paths,
        parser_versions={"scan": "1"},
        event_origin="local_cli_unversioned",
        version_bound=False,
        is_merge_commit=False,
    )


def _file_in_rev(repo: Path, revision: str, path: str) -> bool:
    try:
        _git(repo, "cat-file", "-e", f"{revision}:{path}")
        return True
    except (IntakeError, FileNotFoundError):
        return False


def record_content_hashes(repo: Path, paths: list[str]) -> dict[str, str]:
    """Record SHA-256 content hashes for files actually inspected by adapters.

    Returns a mapping of relative path -> ``sha256:<hex>``.  These hashes are
    stored in the evidence bundle so that any post-validation modification of
    inspected files is detectable.
    """
    hashes: dict[str, str] = {}
    for path in paths:
        full = repo / path
        if not full.is_file():
            continue
        try:
            digest = digest_text(full.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            # Binary or unreadable file: hash raw bytes instead
            data = full.read_bytes()
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
        hashes[path] = digest
    return hashes


def verify_tree_integrity(
    repo: Path,
    expected_head: str,
    expected_tree_digest: str | None = None,
) -> None:
    """Re-check commit/tree identity after validation completes.

    Called after checks have run to ensure the working tree hasn't been
    modified during analysis (evidence bound to one revision, tests executed
    against another).  Raises IntakeError on mismatch.
    """
    current_head = _git(repo, "rev-parse", "HEAD").strip()
    if current_head != expected_head:
        raise IntakeError(
            f"HEAD changed during analysis: was {expected_head[:12]}, now "
            f"{current_head[:12]}; evidence is no longer commit-bound"
        )

    if expected_tree_digest is not None:
        current_tree = _tree_digest(repo)
        if current_tree != expected_tree_digest:
            raise IntakeError(
                f"working tree digest changed during analysis; evidence is "
                f"no longer commit-bound"
            )

    # Re-verify dirty state
    status = _git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    dirty: list[str] = []
    for line in status.splitlines():
        if len(line) < 4:
            continue
        path_text = line[3:]
        paths = path_text.split(" -> ") if " -> " in path_text else [path_text]
        for path in paths:
            path = path.strip().strip('"')
            if path and not _is_excluded_path(path):
                dirty.append(path)
    if dirty:
        sample = ", ".join(sorted(set(dirty))[:8])
        raise IntakeError(
            f"working tree became dirty during analysis: {sample}; "
            f"evidence is no longer commit-bound"
        )


def is_merge_commit(repo: Path, revision: str) -> bool:
    """Return True if the revision is a merge commit (has 2+ parents)."""
    try:
        parents = _git(repo, "rev-list", "--parents", "-n", "1", revision).strip()
        # First token is the commit itself; remaining tokens are parents.
        parent_count = len(parents.split()) - 1
        return parent_count >= 2
    except IntakeError:
        return False


def validate_merge_base(repo: Path, base_rev: str, head_rev: str) -> str:
    """Validate that base_rev is a valid merge base for head_rev.

    Returns the actual merge base SHA.  Raises IntakeError if base_rev is not
    an ancestor of head_rev (e.g. after a rebase where base was rewritten).
    """
    try:
        merge_base = _git(repo, "merge-base", base_rev, head_rev).strip()
    except IntakeError as exc:
        raise IntakeError(
            f"cannot compute merge-base between {base_rev[:12]} and "
            f"{head_rev[:12]}: {exc}"
        ) from exc

    if merge_base != base_rev:
        raise IntakeError(
            f"base {base_rev[:12]} is not a valid merge base for head "
            f"{head_rev[:12]} (actual merge base: {merge_base[:12]}). "
            f"The PR may have been rebased; re-run the gate against the "
            f"current base."
        )
    return merge_base
