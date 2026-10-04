"""Persistent no-test task container shared by Claude Code and OpenCode.

The repository is bind-mounted from a host scratch directory so the outer
repair loop can inspect each candidate patch. The CLI runs with the task
image's dependencies. Network egress is restricted after CLI setup.
"""
from __future__ import annotations

import re
import subprocess
import uuid
from pathlib import Path

from .network_isolation import RestrictedModelNetwork


ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _checked(args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Docker workspace setup failed: {result.stderr[-1000:]}")
    return result


class DockerWorkspace:
    def __init__(self, image: str, host_dir: Path, *, workdir: str = "/project",
                 label: str = "task"):
        self.image = image
        self.host_dir = host_dir.resolve()
        self.workdir = workdir
        self.label = re.sub(r"[^A-Za-z0-9-]", "-", label)[:24]
        self.container: str | None = None
        self.network: RestrictedModelNetwork | None = None

    def setup(self) -> Path:
        self.host_dir.mkdir(parents=True, exist_ok=True)
        temporary = _checked(["docker", "create", "--pull", "never", self.image]).stdout.strip()
        try:
            _checked(["docker", "cp", f"{temporary}:{self.workdir}/.", str(self.host_dir)])
        finally:
            subprocess.run(["docker", "rm", "-f", temporary], capture_output=True, text=True)
        name = f"av-{self.label}-{uuid.uuid4().hex[:10]}"
        _checked(["docker", "run", "-d", "--pull", "never", "--name", name,
                  "-v", f"{self.host_dir}:{self.workdir}", "-w", self.workdir,
                  "--entrypoint", "tail", self.image, "-f", "/dev/null"])
        self.container = name
        result = self.execute(["git", "config", "--global", "--add", "safe.directory", self.workdir],
                              timeout_s=30)
        if result.returncode:
            raise RuntimeError(f"Could not configure Git safe.directory: {result.stderr[-500:]}")
        return self.host_dir

    def execute(self, argv: list[str], *, env: dict[str, str] | None = None,
                timeout_s: int = 3600) -> subprocess.CompletedProcess[str]:
        if self.container is None:
            raise RuntimeError("Docker workspace has not started")
        args = ["docker", "exec", "-w", self.workdir]
        for key, value in (env or {}).items():
            if not ENV_NAME.fullmatch(key):
                raise ValueError(f"invalid environment variable name: {key}")
            args.extend(["-e", f"{key}={value}"])
        args.extend([self.container, *argv])
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout_s,
                              stdin=subprocess.DEVNULL)

    def copy_file(self, source: Path, destination: str) -> None:
        if self.container is None:
            raise RuntimeError("Docker workspace has not started")
        _checked(["docker", "cp", str(source), f"{self.container}:{destination}"])

    def isolate_model_api(self, base_url: str, *, paths: tuple[str, ...]) -> str:
        if self.container is None:
            raise RuntimeError("Docker workspace has not started")
        self.network = RestrictedModelNetwork(self.label)
        return self.network.activate(self.container, base_url, allowed_paths=paths)

    def close(self) -> None:
        if self.network is not None:
            self.network.close()
            self.network = None
        if self.container is not None:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True, text=True,
                           timeout=30)
            self.container = None

    def __enter__(self) -> "DockerWorkspace":
        self.setup()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
