"""Strict command catalog and allow-list enforcement.

``command_ref`` values resolve only to entries of a version-controlled catalog.
The plan can never carry a shell string, and every argv is validated before
execution (architecture section 14).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

ALLOWED_EXECUTABLES = {"python", "python3", "pytest"}
# Arguments are static, catalog-authored strings. Anything that smells like shell
# syntax or an environment/redirect operator is refused before execution.
_ARG_RE = re.compile(r"^[A-Za-z0-9_\-.,/:=@+ ]+$")
_FORBIDDEN_SUBSTRINGS = ("$(", "`", ";", "|", "&", ">", "<", "\n", "\r", "*", "?", "~")


class AllowListError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandSpec:
    check_id: str
    command_ref: str
    argvs: tuple[tuple[str, ...], ...]
    cwd: str  # relative to repository root
    timeout_seconds: int


def load_command_catalog(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("commands"), dict):
        raise AllowListError(f"invalid command catalog: {path}")
    return document


def resolve_command(catalog: dict, command_ref: str, check_id: str) -> CommandSpec:
    entry = catalog["commands"].get(command_ref)
    if entry is None:
        raise AllowListError(
            f"check '{check_id}' references unknown command_ref '{command_ref}'; "
            "only version-controlled catalog entries may run"
        )
    argvs_raw = entry.get("argvs")
    if not isinstance(argvs_raw, list) or not argvs_raw:
        raise AllowListError(f"command_ref '{command_ref}' has no argvs")
    argvs: list[tuple[str, ...]] = []
    for argv in argvs_raw:
        if not isinstance(argv, list) or not argv:
            raise AllowListError(f"command_ref '{command_ref}' contains an empty argv")
        argvs.append(tuple(validate_argv(argv, command_ref)))
    cwd = entry.get("cwd", ".")
    if not isinstance(cwd, str) or any(token in cwd for token in _FORBIDDEN_SUBSTRINGS):
        raise AllowListError(f"command_ref '{command_ref}' declares an unsafe cwd")
    timeout = int(entry.get("timeout_seconds", 120))
    if timeout <= 0 or timeout > 900:
        raise AllowListError(f"command_ref '{command_ref}' declares an out-of-range timeout")
    return CommandSpec(
        check_id=check_id, command_ref=command_ref, argvs=tuple(argvs),
        cwd=cwd, timeout_seconds=timeout,
    )


def validate_argv(argv: list[str], command_ref: str) -> list[str]:
    # A basename-only check is unsafe: `/tmp/attacker/python` has basename
    # `python` and would pass even though it is an arbitrary executable. The
    # catalog may name only an exact bare token; executable resolution belongs
    # to the controlled runner environment.
    raw_executable = str(argv[0])
    if raw_executable != raw_executable.strip() or not raw_executable:
        raise AllowListError(f"command_ref '{command_ref}' has an invalid executable token")
    if "/" in raw_executable or "\\" in raw_executable or Path(raw_executable).is_absolute():
        raise AllowListError(
            f"command_ref '{command_ref}' must use a bare allow-listed executable, not a path: {raw_executable!r}"
        )
    executable = raw_executable.lower()
    if executable.endswith(".exe"):
        executable = executable[:-4]
    if executable not in ALLOWED_EXECUTABLES:
        raise AllowListError(
            f"command_ref '{command_ref}' uses executable '{argv[0]}', "
            f"which is not in the allow-list {sorted(ALLOWED_EXECUTABLES)}"
        )
    for arg in argv[1:]:
        text = str(arg)
        if any(token in text for token in _FORBIDDEN_SUBSTRINGS) or not _ARG_RE.match(text):
            raise AllowListError(
                f"command_ref '{command_ref}' contains an unsafe argument: {text[:80]!r}"
            )
    return [str(a) for a in argv]
