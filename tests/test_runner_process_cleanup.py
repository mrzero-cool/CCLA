from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from clca.runner import ArtifactStore, CommandSpec, SubprocessRunner


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group cleanup is the behavior under test")
def test_timeout_kills_descendant_that_keeps_pipes_open(tmp_path):
    marker = tmp_path / "child-survived.txt"
    child_code = (
        "import time; from pathlib import Path; time.sleep(2); "
        f"Path({str(marker)!r}).write_text('survived')"
    )
    parent_code = (
        "import subprocess, sys; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        "print('parent exited; child inherited pipes')"
    )
    spec = CommandSpec(
        check_id="process-tree-timeout",
        command_ref="test-process-tree",
        argvs=(("python", "-c", parent_code),),
        cwd=".",
        timeout_seconds=1,
    )
    outcome = SubprocessRunner(tmp_path, ArtifactStore(tmp_path / "artifacts")).run(spec, "run-1")
    assert outcome.status == "timed_out"
    # Wait past the child's intended write time; its process group must have
    # been terminated rather than silently surviving the direct parent.
    time.sleep(2.2)
    assert not marker.exists()
