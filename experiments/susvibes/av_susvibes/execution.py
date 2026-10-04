from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .models import Probe, Target, Trace

RUNNER = Path(__file__).with_name("probe_runner.py")


def _observations(stdout: str) -> list[dict]:
    found = []
    for line in stdout.splitlines():
        if line.startswith("AV_OBSERVATION:"):
            try:
                value = json.loads(line.split(":", 1)[1])
                if isinstance(value, dict): found.append(value)
            except json.JSONDecodeError:
                pass
    return found


def _read_result(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


class DockerExecutor:
    """Each probe starts from the no-test image and receives the same candidate patch."""

    def __init__(self, image: str, patch: str, *, workdir: str = "/project", timeout_s: int = 20,
                 memory_mb: int = 2048, cpus: int = 2):
        if not image or not patch.strip():
            raise ValueError("A no-test image and candidate patch are required")
        self.image, self.patch, self.workdir = image, patch, workdir
        self.timeout_s, self.memory_mb, self.cpus = timeout_s, memory_mb, cpus
        self._python_version = None

    def python_version(self) -> str:
        if self._python_version is None:
            proc = subprocess.run(["docker", "run", "--rm", "--pull", "never", "--network", "none",
                                   self.image, "python", "--version"], capture_output=True, text=True, timeout=30)
            if proc.returncode:
                raise RuntimeError(f"task image has no usable Python interpreter: {proc.stderr[-300:]}")
            self._python_version = (proc.stdout or proc.stderr).strip()
        return self._python_version

    def run(self, probe: Probe, target: Target) -> Trace:
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="av-probe-", ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            (root / "candidate.patch").write_text(self.patch, encoding="utf-8")
            (root / "probe.py").write_text(probe.script, encoding="utf-8")
            # The image contains no benchmark tests. The mount contains only
            # this probe, patch and runner. No model credential enters Docker.
            target_arg = json.dumps({"path": target.path, "qualname": target.qualname,
                                     "start": target.start, "end": target.end})
            command = ["docker", "run", "--rm", "--cidfile", str(root / "container.cid"),
                       "--pull", "never", "--network", "none",
                       "--cpus", str(self.cpus), "--memory", f"{self.memory_mb}m", "--pids-limit", "128",
                       "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                       "-v", f"{root}:/av:rw", "-v", f"{RUNNER}:/av_runner.py:ro",
                       "-w", self.workdir, self.image, "sh", "-c",
                       "git -c safe.directory=. apply /av/candidate.patch && "
                       "python /av_runner.py /av/probe.py \"$1\" /av/result.json \"$2\"",
                       "av", target_arg, self.workdir]
            try:
                proc = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout_s + 15)
                timed_out = False
            except subprocess.TimeoutExpired as exc:
                proc = None
                timed_out = True
                cid_path = root / "container.cid"
                if cid_path.exists():
                    subprocess.run(["docker", "rm", "-f", cid_path.read_text().strip()], capture_output=True)
                stdout = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                stderr = (exc.stderr or b"").decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            raw = {}
            result_file = root / "result.json"
            if result_file.exists():
                try: raw = json.loads(result_file.read_text(encoding="utf-8"))
                except json.JSONDecodeError: pass
            stdout = proc.stdout if proc else stdout
            stderr = proc.stderr if proc else stderr
            return Trace(probe.id, target.canonical, proc.returncode if proc else None, timed_out,
                         stdout[:20000], stderr[:20000], _observations(stdout), raw.get("frames", []),
                         raw.get("events", []), raw.get("exception"), raw.get("target_return"),
                         raw.get("harness_error", "" if result_file.exists() else "runner did not produce a trace"),
                         time.monotonic() - started)


class LocalExecutor:
    """Development-only executor; use DockerExecutor for benchmark runs."""

    def __init__(self, repo: Path, timeout_s: int = 20):
        self.repo, self.timeout_s = repo.resolve(), timeout_s

    def python_version(self) -> str:
        return "Python " + sys.version.split()[0]

    def run(self, probe: Probe, target: Target) -> Trace:
        with tempfile.TemporaryDirectory(prefix="av-local-", ignore_cleanup_errors=True) as tmp:
            path = Path(tmp)
            (path / "probe.py").write_text(probe.script)
            args = ["python", str(RUNNER), str(path / "probe.py"),
                    json.dumps({"path": target.path, "qualname": target.qualname,
                                "start": target.start, "end": target.end}),
                    str(path / "result.json"), str(self.repo)]
            started = time.monotonic()
            try:
                proc = subprocess.run(args, cwd=self.repo, capture_output=True, text=True, timeout=self.timeout_s)
                timed_out = False
            except subprocess.TimeoutExpired:
                proc, timed_out = None, True
            result = _read_result(path / "result.json")
            stdout, stderr = (proc.stdout, proc.stderr) if proc else ("", "")
            return Trace(probe.id, target.canonical, proc.returncode if proc else None, timed_out, stdout,
                         stderr, _observations(stdout), result.get("frames", []), result.get("events", []),
                         result.get("exception"), result.get("target_return"),
                         result.get("harness_error", "" if result else "runner did not produce a trace"),
                         time.monotonic() - started)
