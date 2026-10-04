from __future__ import annotations

import json
import os
import re
import shutil
import shlex
import subprocess
import tempfile
from pathlib import Path

from .models import Event, Probe, Target, Trace
from .targets import is_test_path

OBS_PREFIX = "AV_OBSERVATION:"
TRACE_PREFIX = "AV_TRACE:"
CANARY = re.compile(r"AV_CANARY_[A-Za-z0-9_]+")
FRAMES_FILE = ".av_frames.json"


def normalize_events(events: list[Event], observations: list[dict]) -> list[Event]:
    markers = sorted(set(CANARY.findall(json.dumps(observations, default=str))))
    normalized = []
    for event in events:
        detail = dict(event.detail)
        value = str(event.value)
        for marker in markers:
            if marker in value:
                detail["marker"] = marker
                break
        normalized.append(Event(event.kind, event.value, detail, event.frames, event.phase))
        if event.kind in {"return", "output"} and detail.get("marker") and re.search(
            r"<script\b|\bon\w+\s*=|javascript:", value, re.I
        ):
            normalized.append(Event("markup", event.value, detail, event.frames, event.phase))
    return normalized


class DockerExecutor:
    def __init__(self, image: str = "python:3.11-slim", timeout: int = 20,
                 memory_mb: int = 512, cpus: float = 1.0):
        self.image = image
        self.timeout = timeout
        self.memory_mb = memory_mb
        self.cpus = cpus

    def run(self, workspace: Path, target: Target, probe: Probe) -> Trace:
        if shutil.which("docker") is None:
            raise RuntimeError("Docker is required for untrusted probe execution")
        if target.language != "python":
            raise RuntimeError("Automatic trusted attribution currently requires Python targets")
        root = workspace.resolve()
        target_file = (root / target.path).resolve()
        if not target_file.is_relative_to(root) or not target_file.is_file():
            raise ValueError("Target path is outside the candidate workspace")
        with tempfile.TemporaryDirectory(prefix="av_probe_", ignore_cleanup_errors=True) as folder:
            staged = Path(folder) / "work"
            staged.mkdir()
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                rel = path.relative_to(root)
                if any(part.startswith(".") for part in rel.parts) or is_test_path(str(rel)):
                    continue
                if len(rel.parts) > 8 or path.stat().st_size > 2_000_000:
                    continue
                dst = staged / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dst)
                dst.chmod(0o644)
            scratch = Path(folder) / "scratch"
            scratch.mkdir()
            scratch.chmod(0o777)
            probe_file = scratch / "probe.py"
            probe_file.write_text(probe.script, encoding="utf-8")
            cidfile = Path(folder) / "container.cid"
            runner = Path(__file__).with_name("trace_runner.py")
            command = ["docker", "run", "--rm", "--cidfile", str(cidfile), "--network", "none",
                       "--pids-limit", "64",
                       "--memory", f"{self.memory_mb}m", "--cpus", str(self.cpus),
                       "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                       "--user", "65534:65534", "-v", f"{staged}:/work:ro",
                       "-v", f"{scratch}:/scratch:rw", "-v", f"{runner}:/opt/av/trace_runner.py:ro",
                       "-w", "/work", "-e", f"AV_TARGET_PATH=/work/{target.path}",
                       "-e", f"AV_TARGET_SYMBOL={target.symbol}",
                       "-e", "AV_PROBE_PATH=/scratch/probe.py",
                       "-e", f"AV_FRAMES_PATH=/scratch/{FRAMES_FILE}",
                       "-e", "PYTHONPATH=/work", self.image, "python", "/opt/av/trace_runner.py"]
            try:
                done = subprocess.run(command, capture_output=True, text=True,
                                      timeout=self.timeout + 5, check=False)
                timed_out = False
            except subprocess.TimeoutExpired as exc:
                # Killing the docker client does not stop the container; remove it explicitly.
                if cidfile.exists():
                    subprocess.run(["docker", "rm", "-f", cidfile.read_text().strip()],
                                   capture_output=True, check=False)
                done = subprocess.CompletedProcess(command, 124,
                    (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                    (exc.stderr or b"").decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""))
                timed_out = True
            entered_frames, target_active = _read_frames(scratch / FRAMES_FILE)
        startup_errors = ("Cannot connect to the Docker daemon", "Is the docker daemon running",
                          "error during connect", "Unable to find image", "pull access denied",
                          "Error response from daemon")
        if done.returncode in {125, 126, 127} or any(x in done.stderr for x in startup_errors):
            raise RuntimeError(f"Probe container failed to start: {done.stderr[-1000:]}")
        output = done.stdout[-100_000:]
        observations = []
        runner_traces = []
        for line in output.splitlines():
            if line.startswith(OBS_PREFIX):
                try:
                    value = json.loads(line[len(OBS_PREFIX):])
                    if isinstance(value, dict):
                        observations.append(value)
                except json.JSONDecodeError:
                    pass
            elif line.startswith(TRACE_PREFIX):
                try:
                    candidate = json.loads(line[len(TRACE_PREFIX):])
                    if isinstance(candidate, dict):
                        runner_traces.append(candidate)
                except json.JSONDecodeError:
                    pass
        runner_trace = runner_traces[0] if len(runner_traces) == 1 else None
        oom = done.returncode == 137
        killed = timed_out or oom or done.returncode in {134, 139}
        target_frames = (runner_trace or {}).get("target_frames", [])
        harness_error = "" if runner_trace else "Probe did not produce one trusted trace record"
        if runner_trace is None and not runner_traces and killed and entered_frames and target_active:
            # The process was killed while a target call was running, so the final record
            # was never printed. The frames written on entry attribute the termination.
            target_frames = entered_frames
            harness_error = ""
        if runner_trace and runner_trace.get("runner_errors") and not runner_trace.get("error_in_target"):
            harness_error = "Probe failed outside the target"
        if runner_trace and not observations and not runner_trace.get("error_in_target"):
            harness_error = "Probe emitted no observation"
        if observations and any("harness_error" in x for x in observations):
            harness_error = "Probe reported a setup error"
        events = normalize_events([Event.from_dict(x) for x in (runner_trace or {}).get("events", [])],
                                  observations)
        target_output = "\n".join(str(e.value) for e in events if e.kind == "output")
        return Trace(probe.id, target.key, target.language, target_output, done.stderr[-20_000:],
                     done.returncode, timed_out, oom, observations, events, target_frames,
                     harness_error)


def _read_frames(path: Path) -> tuple[list[str], bool]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [], False
    if not isinstance(value, dict) or not isinstance(value.get("frames"), list):
        return [], False
    return [str(x) for x in value["frames"]], value.get("active") is True


class AdapterExecutor:
    """Use a trusted language-specific sandbox adapter with the Trace JSON protocol."""

    def __init__(self, command: str, timeout: int = 30, memory_mb: int = 512):
        self.command = shlex.split(command)
        self.timeout = timeout
        self.memory_mb = memory_mb
        if not self.command:
            raise ValueError("adapter command is empty")

    def run(self, workspace: Path, target: Target, probe: Probe) -> Trace:
        request = {"workspace": str(workspace.resolve()), "target": target.__dict__,
                   "probe": probe.__dict__, "timeout": self.timeout,
                   "memory_mb": self.memory_mb}
        completed = subprocess.run(self.command, input=json.dumps(request), text=True,
                                   capture_output=True, timeout=self.timeout + 10, check=False)
        if completed.returncode:
            raise RuntimeError(f"Trace adapter failed: {completed.stderr[-1000:]}")
        result = Trace.from_dict(json.loads(completed.stdout))
        if result.target != target.key or result.probe_id != probe.id:
            raise ValueError("Trace adapter returned the wrong target or probe")
        return result
