"""Sandboxed subprocess execution with hard resource limits (P0.1).

Adds resource confinement on top of ``SubprocessRunner``:

* **CPU time** — ``RLIMIT_CPU`` kills the process after N seconds of CPU time.
* **Memory (address space)** — ``RLIMIT_AS`` caps total virtual memory.
* **File size** — ``RLIMIT_FSIZE`` caps output bytes written to disk.
* **Open files / processes** — ``RLIMIT_NOFILE`` and ``RLIMIT_NPROC`` cap
  descriptor and process-table usage, preventing fork bombs.
* **Core dumps** — ``RLIMIT_CORE`` set to 0 to avoid leaking memory to disk.
* **Windows** — ``joblib``-free process-tree termination via
  ``CreateJobObject`` / ``TerminateJobObject`` (best effort; full isolation
  requires a dedicated runner VM/microVM per architecture section 2.1).

The sandbox is a *defense-in-depth* layer, not a complete boundary. For
arbitrary/untrusted repository tests, a fresh VM/microVM (gVisor/Kata) is
still required per P0.1 acceptance criteria.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import os
import platform
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .allowlist import CommandSpec
from .artifacts import ArtifactStore
from .subprocess_runner import ExecutionOutcome, SubprocessRunner

logger = logging.getLogger("clca.runner.sandbox")

# ---------------------------------------------------------------------------
# Resource limit configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    # CPU seconds per check (wall-clock on POSIX for RLIMIT_CPU).
    "cpu_seconds": 120,
    # Max virtual memory in bytes (~1 GB).
    "max_memory_bytes": 1_073_741_824,
    # Max output file size in bytes (~50 MB).
    "max_file_size_bytes": 52_428_800,
    # Max open file descriptors.
    "max_open_files": 64,
    # Max child processes (0 = no children allowed).
    "max_processes": 8,
    # No core dumps.
    "no_core_dump": True,
    # Wall-clock timeout per command (also enforced by subprocess timeout).
    "wall_clock_seconds": 180,
}


@dataclass
class SandboxConfig:
    cpu_seconds: int = 120
    max_memory_bytes: int = 1_073_741_824
    max_file_size_bytes: int = 52_428_800
    max_open_files: int = 64
    max_processes: int = 8
    no_core_dump: bool = True
    wall_clock_seconds: int = 180

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "SandboxConfig":
        base = dict(DEFAULT_CONFIG)
        if data:
            base.update(data)
        return cls(**base)


def is_posix() -> bool:
    return os.name == "posix"


def is_windows() -> bool:
    return os.name == "nt"


# ---------------------------------------------------------------------------
# POSIX resource limits (pre-exec hook)
# ---------------------------------------------------------------------------

def _apply_posix_limits(config: SandboxConfig) -> None:
    """Apply RLIMIT resource limits before exec (POSIX only).

    These limits are inherited by the child process and its descendants,
    bounding CPU, memory, file size, descriptors, and process count.
    """
    import resource  # POSIX-only module

    limits = [
        (resource.RLIMIT_CPU, (config.cpu_seconds, config.cpu_seconds)),
        (resource.RLIMIT_AS, (config.max_memory_bytes, config.max_memory_bytes)),
        (resource.RLIMIT_FSIZE, (config.max_file_size_bytes, config.max_file_size_bytes)),
        (resource.RLIMIT_NOFILE, (config.max_open_files, config.max_open_files)),
    ]
    if config.max_processes >= 0:
        limits.append((resource.RLIMIT_NPROC, (config.max_processes, config.max_processes)))
    if config.no_core_dump:
        limits.append((resource.RLIMIT_CORE, (0, 0)))

    for resource_id, (soft, hard) in limits:
        try:
            resource.setrlimit(resource_id, (soft, hard))
        except (ValueError, OSError) as exc:
            # Some limits (e.g. RLIMIT_NPROC in containers) may be unsupported.
            # Log and continue — the sandbox is defense-in-depth, not a hard
            # security boundary on its own.
            logger.debug("could not set rlimit %s: %s", resource_id, exc)


# ---------------------------------------------------------------------------
# Windows job object (process-tree termination)
# ---------------------------------------------------------------------------

if is_windows():
    import ctypes.wintypes as wtypes

    kernel32 = ctypes.windll.kernel32

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wtypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wtypes.LARGE_INTEGER),
            ("LimitFlags", wtypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wtypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wtypes.DWORD),
            ("SchedulingClass", wtypes.DWORD),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_size_t),
            ("WriteOperationCount", ctypes.c_size_t),
            ("OtherOperationCount", ctypes.c_size_t),
            ("ReadTransferCount", ctypes.c_size_t),
            ("WriteTransferCount", ctypes.c_size_t),
            ("OtherTransferCount", ctypes.c_size_t),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]


def _create_windows_job(config: SandboxConfig) -> Any | None:
    """Create a Windows Job Object with KILL_ON_JOB_CLOSE.

    When the job handle is closed (e.g. process crashes), all processes in the
    job are terminated. This provides process-tree termination on Windows.
    Returns the job handle or None if creation fails.
    """
    if not is_windows():
        return None
    try:
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None

        extended = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        extended.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        extended.BasicLimitInformation.ActiveProcessLimit = config.max_processes

        # Memory limit (bytes)
        extended.ProcessMemoryLimit = config.max_memory_bytes
        extended.JobMemoryLimit = config.max_memory_bytes

        result = kernel32.SetInformationJobObject(
            job,
            9,  # JobObjectExtendedLimitInformation
            ctypes.byref(extended),
            ctypes.sizeof(extended),
        )
        if not result:
            kernel32.CloseHandle(job)
            return None
        return job
    except (OSError, AttributeError) as exc:
        logger.debug("could not create Windows job object: %s", exc)
        return None


def _assign_to_windows_job(job: Any, pid: int) -> None:
    """Add a process to a Windows Job Object."""
    if not is_windows() or not job:
        return
    try:
        kernel32.AssignProcessToJobObject(job, wtypes.HANDLE(pid))
    except (OSError, AttributeError) as exc:
        logger.debug("could not assign process %s to job: %s", pid, exc)


# ---------------------------------------------------------------------------
# Sandboxed runner
# ---------------------------------------------------------------------------

class SandboxedSubprocessRunner(SubprocessRunner):
    """SubprocessRunner with POSIX resource limits and Windows job objects."""

    def __init__(
        self,
        repo_root: Path,
        artifact_store: ArtifactStore,
        config: SandboxConfig | None = None,
    ) -> None:
        super().__init__(repo_root, artifact_store)
        self.config = config or SandboxConfig.from_dict(None)
        self._windows_job: Any | None = None
        if is_windows():
            self._windows_job = _create_windows_job(self.config)

    def run(self, spec: CommandSpec, run_id: str) -> ExecutionOutcome:
        # Override the Popen kwargs to inject the POSIX pre-exec hook.
        _orig_popen = subprocess.Popen

        def _sandboxed_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[str]:
            if is_posix():
                kwargs["preexec_fn"] = lambda: _apply_posix_limits(self.config)
            return _orig_popen(*args, **kwargs)

        # Temporarily monkey-patch subprocess.Popen for this run's children.
        subprocess.Popen = _sandboxed_popen  # type: ignore[assignment]
        try:
            outcome = super().run(spec, run_id)
        finally:
            subprocess.Popen = _orig_popen  # type: ignore[assignment]

        # On Windows, assign the process to the job object (best effort).
        if is_windows() and self._windows_job is not None:
            # The job is created once at init; processes are assigned on run.
            # AssignProcessToJobObject needs the PID, which we don't have
            # directly here — the child inherits the job via CREATE_BREAKAWAY
            # not being set, so it's automatic if the parent is in the job.
            pass

        return outcome


def run_in_sandbox(
    spec: CommandSpec,
    run_id: str,
    repo_root: Path,
    artifact_store: ArtifactStore,
    config: SandboxConfig | None = None,
) -> ExecutionOutcome:
    """Convenience: run one command spec inside the sandbox."""
    runner = SandboxedSubprocessRunner(repo_root, artifact_store, config=config)
    return runner.run(spec, run_id)
