"""Tests for the sandboxed subprocess runner (P0.1)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from clca.runner.allowlist import CommandSpec
from clca.runner.artifacts import ArtifactStore
from clca.runner.sandbox import (
    DEFAULT_CONFIG,
    SandboxConfig,
    _apply_posix_limits,
    is_posix,
    is_windows,
    run_in_sandbox,
)


def test_sandbox_config_defaults():
    config = SandboxConfig.from_dict(None)
    assert config.cpu_seconds == DEFAULT_CONFIG["cpu_seconds"]
    assert config.max_memory_bytes == DEFAULT_CONFIG["max_memory_bytes"]
    assert config.max_file_size_bytes == DEFAULT_CONFIG["max_file_size_bytes"]
    assert config.max_open_files == DEFAULT_CONFIG["max_open_files"]
    assert config.max_processes == DEFAULT_CONFIG["max_processes"]
    assert config.no_core_dump is True
    assert config.wall_clock_seconds == DEFAULT_CONFIG["wall_clock_seconds"]


def test_sandbox_config_from_dict():
    config = SandboxConfig.from_dict({"cpu_seconds": 30, "max_memory_bytes": 512 * 1024 * 1024})
    assert config.cpu_seconds == 30
    assert config.max_memory_bytes == 512 * 1024 * 1024
    assert config.wall_clock_seconds == DEFAULT_CONFIG["wall_clock_seconds"]


def test_is_posix_and_is_windows_are_booleans():
    assert isinstance(is_posix(), bool)
    assert isinstance(is_windows(), bool)
    assert is_posix() != is_windows()


def test_apply_posix_limits_does_not_crash():
    if not is_posix():
        # On Windows, _apply_posix_limits imports `resource` which is POSIX-only.
        return
    import resource

    config = SandboxConfig.from_dict(None)
    old_cpu = resource.getrlimit(resource.RLIMIT_CPU)
    try:
        _apply_posix_limits(config)
        new_cpu = resource.getrlimit(resource.RLIMIT_CPU)
        assert new_cpu[0] == config.cpu_seconds
    finally:
        try:
            resource.setrlimit(resource.RLIMIT_CPU, old_cpu)
        except OSError:
            pass


def test_sandboxed_runner_executes_simple_command(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    runner_cls = __import__("clca.runner.sandbox", fromlist=["SandboxedSubprocessRunner"]).SandboxedSubprocessRunner
    runner = runner_cls(tmp_path, store)
    spec = CommandSpec(
        check_id="sandbox.test",
        command_ref="python",
        argvs=((sys.executable, "-c", "print('hello sandbox')"),),
        cwd=".",
        timeout_seconds=10,
    )
    outcome = runner.run(spec, "run-1")
    assert outcome.status == "passed"
    assert outcome.exit_code == 0
    assert "hello sandbox" in outcome.stdout_excerpt


def test_sandboxed_runner_timeout(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    runner_cls = __import__("clca.runner.sandbox", fromlist=["SandboxedSubprocessRunner"]).SandboxedSubprocessRunner
    runner = runner_cls(tmp_path, store)
    spec = CommandSpec(
        check_id="sandbox.timeout",
        command_ref="python",
        argvs=((sys.executable, "-c", "import time; time.sleep(30)"),),
        cwd=".",
        timeout_seconds=1,
    )
    outcome = runner.run(spec, "run-timeout")
    assert outcome.status == "timed_out"


def test_run_in_sandbox_convenience(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    spec = CommandSpec(
        check_id="sandbox.convenience",
        command_ref="python",
        argvs=((sys.executable, "-c", "print('ok')"),),
        cwd=".",
        timeout_seconds=10,
    )
    outcome = run_in_sandbox(spec, "run-conv", tmp_path, store)
    assert outcome.status == "passed"
    assert outcome.exit_code == 0


def test_sandbox_preexec_fn_injected_on_posix(monkeypatch, tmp_path):
    if not is_posix():
        return
    import clca.runner.sandbox as sandbox_mod

    captured = {}

    class FakePopen:
        def __init__(self, *args, **kwargs):
            captured["kwargs"] = kwargs
            self.pid = 1234
            self.returncode = 0

        def communicate(self, timeout=None):
            return ("", "")

        def poll(self):
            return 0

        def kill(self):
            pass

    monkeypatch.setattr(sandbox_mod.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(os, "killpg", lambda *a, **k: None)

    config = SandboxConfig.from_dict(None)
    runner = sandbox_mod.SandboxedSubprocessRunner(tmp_path, None, config=config)
    spec = CommandSpec(
        check_id="sandbox.preexec",
        command_ref="python",
        argvs=((sys.executable, "-c", "print('x')"),),
        cwd=".",
        timeout_seconds=5,
    )
    runner.run(spec, "run-preexec")
    kwargs = captured.get("kwargs", {})
    assert "preexec_fn" in kwargs, "preexec_fn should be injected on POSIX"
    assert callable(kwargs["preexec_fn"])
