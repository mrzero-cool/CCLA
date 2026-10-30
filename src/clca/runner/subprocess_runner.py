"""Subprocess execution of allow-listed checks with hard limits.

No shell is ever used. CWD must resolve inside the repository. Output is
redacted and truncated; each run records input/environment digests so a
``passed`` status carries real execution proof (architecture sections 3.6, 14).
"""
from __future__ import annotations

import os
import platform
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from ..digest import digest_obj, digest_tree
from ..redact import redact_excerpt
from .allowlist import CommandSpec
from .artifacts import ArtifactStore

_MAX_OUTPUT_CHARS = 20_000


@dataclass
class ExecutionOutcome:
    status: str  # passed | failed | error | timed_out
    exit_code: int | None
    duration_ms: int
    input_digest: str
    environment_digest: str
    artifact_refs: list[str]
    artifact_digests: dict[str, str]
    stdout_excerpt: str


class SubprocessRunner:
    def __init__(self, repo_root: Path, artifact_store: ArtifactStore):
        self.repo_root = repo_root.resolve()
        self.artifacts = artifact_store

    def run(self, spec: CommandSpec, run_id: str) -> ExecutionOutcome:
        cwd = (self.repo_root / spec.cwd).resolve()
        if not cwd.is_relative_to(self.repo_root):
            raise PermissionError(f"check '{spec.check_id}' cwd escapes the repository root")

        input_digest = digest_tree(self.repo_root)
        environment_digest = digest_obj({
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "argvs": [list(a) for a in spec.argvs],
            "cwd": spec.cwd,
        })
        env = {
            # Keep PATH for tools launched by tests, but execute the primary
            # Python/pytest entrypoint through the current interpreter below so
            # a PATH-shadowed `python` cannot replace the trusted runtime.
            "PATH": os.environ.get("PATH", ""),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            # Disable third-party pytest plugin auto-loading in checks. Plugins
            # can introduce hidden network access, nondeterminism, and child
            # processes that outlive a timed-out test command.
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "HOME": os.environ.get("HOME") or os.environ.get("USERPROFILE", ""),
        }
        if os.name == "nt":
            for var in ("SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC", "TEMP", "TMP", "PATHEXT"):
                if os.environ.get(var):
                    env[var] = os.environ[var]

        artifact_refs: list[str] = []
        artifact_digests: dict[str, str] = {}
        step_statuses: list[str] = []
        total_ms = 0
        excerpts: list[str] = []

        for index, argv in enumerate(spec.argvs):
            started = time.monotonic()
            # Pin Python-family launchers to this interpreter rather than PATH.
            # A command catalog is allowed to select a module/script, not a
            # different binary masquerading as `python` or `pytest`.
            effective_argv = list(argv)
            executable = effective_argv[0].lower()
            if executable in ("python", "python3", "python.exe", "python3.exe"):
                effective_argv[0] = sys.executable
            elif executable in ("pytest", "pytest.exe"):
                effective_argv = [sys.executable, "-m", "pytest", *effective_argv[1:]]
            popen_kwargs = {
                "cwd": str(cwd), "stdin": subprocess.DEVNULL,
                "stdout": subprocess.PIPE, "stderr": subprocess.PIPE,
                "text": True, "shell": False, "env": env, "close_fds": True,
            }
            if os.name == "nt":
                popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            else:
                popen_kwargs["start_new_session"] = True
            proc: subprocess.Popen[str] | None = None
            try:
                proc = subprocess.Popen(effective_argv, **popen_kwargs)
                stdout, stderr = proc.communicate(timeout=spec.timeout_seconds)
                exit_code: int | None = proc.returncode
                output = (stdout or "") + (("\n" + stderr) if stderr else "")
            except subprocess.TimeoutExpired as exc:
                # `subprocess.run(timeout=...)` kills only the direct child.
                # A spawned grandchild can keep stdout/stderr pipes open and
                # hang communicate() forever. Terminate the process group on
                # POSIX before draining pipes; Windows uses direct-child kill
                # as a best-effort fallback until Job Object isolation exists.
                if proc is not None:
                    # Kill the whole POSIX process group even when the direct
                    # child has already exited: a spawned descendant may still
                    # hold stdout/stderr open, which otherwise makes
                    # communicate() wait until timeout while leaving that child
                    # alive. Windows remains best-effort until Job Objects are
                    # introduced.
                    try:
                        if os.name == "nt":
                            if proc.poll() is None:
                                proc.kill()
                        else:
                            os.killpg(proc.pid, signal.SIGTERM)
                    except (ProcessLookupError, PermissionError, OSError):
                        if proc.poll() is None:
                            try:
                                proc.kill()
                            except OSError:
                                pass
                    try:
                        proc.communicate(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        try:
                            if os.name == "nt":
                                if proc.poll() is None:
                                    proc.kill()
                            else:
                                os.killpg(proc.pid, signal.SIGKILL)
                        except (ProcessLookupError, PermissionError, OSError):
                            if proc.poll() is None:
                                try:
                                    proc.kill()
                                except OSError:
                                    pass
                        proc.communicate()
                total_ms += int((time.monotonic() - started) * 1000)
                output = self._timeout_output(exc)
                ref, digest = self._write_artifact(run_id, spec, index, tuple(effective_argv), "timed_out", None, output, total_ms)
                artifact_refs.append(ref)
                artifact_digests[ref] = digest
                return ExecutionOutcome(
                    status="timed_out", exit_code=None, duration_ms=total_ms,
                    input_digest=input_digest, environment_digest=environment_digest,
                    artifact_refs=artifact_refs, artifact_digests=artifact_digests,
                    stdout_excerpt=redact_excerpt(output, 4000),
                )
            except (FileNotFoundError, PermissionError, OSError) as exc:
                exit_code = None
                output = f"{exc.__class__.__name__}: {exc}"
                step_statuses.append("error")
                total_ms += int((time.monotonic() - started) * 1000)
                ref, digest = self._write_artifact(run_id, spec, index, tuple(effective_argv), "error", None, output, total_ms)
                artifact_refs.append(ref)
                artifact_digests[ref] = digest
                excerpts.append(f"$ {' '.join(effective_argv)}\n{output}")
                continue

            duration_ms = int((time.monotonic() - started) * 1000)
            total_ms += duration_ms
            step_status = "passed" if exit_code == 0 else "failed"
            step_statuses.append(step_status)
            excerpts.append(f"$ {' '.join(effective_argv)}\n{output}")
            ref, digest = self._write_artifact(run_id, spec, index, tuple(effective_argv), step_status, exit_code, output, duration_ms)
            artifact_refs.append(ref)
            artifact_digests[ref] = digest

        if "error" in step_statuses:
            status = "error"
        elif "failed" in step_statuses:
            status = "failed"
        else:
            status = "passed"

        return ExecutionOutcome(
            status=status,
            exit_code=0 if status == "passed" else 1,
            duration_ms=total_ms,
            input_digest=input_digest,
            environment_digest=environment_digest,
            artifact_refs=artifact_refs,
            artifact_digests=artifact_digests,
            stdout_excerpt=redact_excerpt("\n".join(excerpts), 4000),
        )

    def _write_artifact(
        self, run_id: str, spec: CommandSpec, index: int,
        argv: tuple[str, ...], status: str, exit_code: int | None, output: str, duration_ms: int,
    ) -> tuple[str, str]:
        return self.artifacts.write(run_id, f"{spec.check_id}.{index}", {
            "check_id": spec.check_id,
            "command_ref": spec.command_ref,
            "argv": list(argv),
            "status": status,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "output": redact_excerpt(output, _MAX_OUTPUT_CHARS),
        })

    @staticmethod
    def _timeout_output(exc: subprocess.TimeoutExpired) -> str:
        parts = ["check exceeded its timeout"]
        for stream in ("stdout", "stderr"):
            value = getattr(exc, stream, None)
            if isinstance(value, bytes):
                parts.append(value.decode("utf-8", "replace"))
            elif isinstance(value, str):
                parts.append(value)
        return "\n".join(parts)
