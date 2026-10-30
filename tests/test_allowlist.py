"""Allow-list enforcement: nothing outside the version-controlled catalog runs."""
import json
from pathlib import Path

import pytest

from clca.runner import AllowListError, resolve_command
from clca.runner.allowlist import validate_argv

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = json.loads((ROOT / "config" / "commands.json").read_text(encoding="utf-8"))


def test_registered_command_resolves():
    spec = resolve_command(COMMANDS, "check.python-unit-tests", "python-unit-tests")
    assert spec.argvs[0][:3] == ("python", "-m", "pytest")
    assert spec.timeout_seconds > 0


def test_unknown_command_ref_is_refused():
    with pytest.raises(AllowListError):
        resolve_command(COMMANDS, "check.attacker-added", "anything")


def test_non_allowlisted_executable_is_refused():
    with pytest.raises(AllowListError):
        validate_argv(["curl", "http://example.com"], "check.evil")
    with pytest.raises(AllowListError):
        validate_argv(["powershell", "-Command", "Remove-Item x"], "check.evil")


def test_shell_metacharacters_in_arguments_are_refused():
    for evil in ("foo; rm -rf /", "a && b", "`whoami`", "$(id)", "a|b", "a>b", "*", "~/x"):
        with pytest.raises(AllowListError):
            validate_argv(["python", "-m", "pytest", evil], "check.evil")


def test_real_catalog_is_fully_allowlisted():
    catalog_path = ROOT / "config" / "check_catalog.json"
    check_catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    for spec in check_catalog["checks"]:
        resolve_command(COMMANDS, spec["command_ref"], spec["check_id"])


def test_absolute_or_relative_executable_paths_are_refused():
    for executable in ("/tmp/attacker/python", "./python", "..\\python.exe"):
        with pytest.raises(AllowListError):
            validate_argv([executable, "-m", "pytest"], "check.path-spoof")
