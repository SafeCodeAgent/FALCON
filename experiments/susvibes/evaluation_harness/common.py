"""Shared subprocess boundary for coding-agent harnesses."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .docker_workspace import DockerWorkspace


class HarnessCommandError(RuntimeError):
    def __init__(self, message: str, *, stdout: str = "", stderr: str = "",
                 returncode: int | None = None, timed_out: bool = False):
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.timed_out = timed_out


def command_from_template(template: list[str], *, model: str, prompt: str,
                          workspace: Path, session_id: str = "") -> list[str]:
    return [part.format(model=model, prompt=prompt, workspace=str(workspace),
                        session_id=session_id) for part in template]


def run_command(args: list[str], workspace: Path, timeout_s: int, *,
                runtime: DockerWorkspace | None = None,
                env: dict[str, str] | None = None) -> str:
    try:
        result = (runtime.execute(args, env=env, timeout_s=timeout_s) if runtime else
                  subprocess.run(args, cwd=workspace, capture_output=True, text=True,
                                 timeout=timeout_s))
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or ""
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or ""
        raise HarnessCommandError("coding harness timed out", stdout=stdout,
                                  stderr=stderr, timed_out=True) from exc
    if result.returncode:
        raise HarnessCommandError(f"coding harness exited {result.returncode}: {result.stderr[-1000:]}",
                                  stdout=result.stdout, stderr=result.stderr,
                                  returncode=result.returncode)
    return result.stdout
