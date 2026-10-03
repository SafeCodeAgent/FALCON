"""Sandboxed execution of a single probe.

``run_probe`` launches the :mod:`engine._harness` in its own process, with the
probe, the target descriptor, and a scratch directory wired in through the
environment. It supports two execution modes:

* ``host`` -- run in the current environment, under the permissions the coding
  session already has. Per-probe CPU and memory limits are applied where the
  platform supports them, and the probe is confined to a fresh scratch
  directory that is deleted afterwards.
* ``docker`` -- run inside a container, either freshly started from an image or
  exec'd into an already-running container, so execution is isolated from the
  host filesystem.

When the process dies abnormally (a signal such as a segfault, or the memory
limit), no trace file is written; the runner synthesises a crash trace so the
crash oracle can still act on it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_harness.py")
_FALLBACK_MARKER = "AV_TRACE_FALLBACK:"


def _preexec_limits(cpu_seconds: int, mem_bytes: int):
    """Return a preexec_fn that applies resource limits, or None if unavailable."""
    try:
        import resource
    except ImportError:
        return None

    def apply():  # pragma: no cover - runs in the child process
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
        except (ValueError, OSError):
            pass
        if mem_bytes:
            for limit_name in ("RLIMIT_AS", "RLIMIT_DATA"):
                limit = getattr(resource, limit_name, None)
                if limit is not None:
                    try:
                        resource.setrlimit(limit, (mem_bytes, mem_bytes))
                    except (ValueError, OSError):
                        pass
        try:
            os.setsid()
        except OSError:
            pass

    return apply


def _child_env(target_file: str, probe_path: str, trace_out: str, scratch: str) -> Dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "AV_TARGET_FILE": target_file,
            "AV_PROBE": probe_path,
            "AV_TRACE_OUT": trace_out,
            "AV_SCRATCH": scratch,
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return env


def _host_command(python: str) -> list:
    return [python, HARNESS]


def _docker_command(execution: Dict[str, Any], trace_out_in_container: str, env: Dict[str, str]) -> list:
    """Build a docker command that runs the harness inside a container."""
    python = execution.get("python", "python3")
    workdir = execution.get("workdir", "/work")
    env_flags = []
    for key in ("AV_TARGET_FILE", "AV_PROBE", "AV_TRACE_OUT", "AV_SCRATCH", "PYTHONHASHSEED"):
        env_flags += ["-e", "%s=%s" % (key, env[key])]

    harness_in_container = workdir + "/.attacker-verifier-harness.py"
    inner = [python, harness_in_container]

    if execution.get("container"):
        return ["docker", "exec"] + env_flags + [execution["container"]] + inner
    # Fresh container from an image, with the repo mounted read/write at workdir.
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        "%s:%s" % (env["AV_REPO_ROOT"], workdir),
        "-w",
        workdir,
    ] + env_flags + [execution["image"]] + inner


def run_probe(
    repo_root: str,
    probe_path: str,
    target_file: str,
    target_qualname: str,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Execute one probe and return its trace dict (always, even on crash)."""
    execution = config["execution"]
    cpu_seconds = max(1, int(config["probe_timeout_s"]))
    wall_timeout = cpu_seconds + 5
    mem_bytes = int(config["probe_mem_mb"]) * 1024 * 1024

    scratch = tempfile.mkdtemp(prefix="av-scratch-")
    trace_fd, trace_out = tempfile.mkstemp(prefix="av-trace-", suffix=".json")
    os.close(trace_fd)

    env = _child_env(
        os.path.abspath(target_file), os.path.abspath(probe_path), trace_out, scratch
    )
    env["AV_TARGET_QUALNAME"] = target_qualname

    if execution["mode"] == "docker":
        env["AV_REPO_ROOT"] = os.path.abspath(repo_root)
        # Stage the harness where the container can reach it.
        staged = os.path.join(repo_root, ".attacker-verifier-harness.py")
        shutil.copyfile(HARNESS, staged)
        command = _docker_command(execution, trace_out, env)
        preexec = None
    else:
        command = _host_command(execution.get("python", sys.executable or "python3"))
        preexec = _preexec_limits(cpu_seconds, mem_bytes)
        staged = None

    result: Dict[str, Any]
    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=wall_timeout,
            preexec_fn=preexec,  # type: ignore[arg-type]
        )
        result = _collect(trace_out, completed.returncode, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        result = _timeout_trace(target_file, target_qualname, exc)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        try:
            os.remove(trace_out)
        except OSError:
            pass
        if staged:
            try:
                os.remove(staged)
            except OSError:
                pass

    result.setdefault("target", {"file": target_file, "qualname": target_qualname})
    return result


def _collect(trace_out: str, returncode: int, stderr_bytes: bytes) -> Dict[str, Any]:
    trace = None
    try:
        if os.path.getsize(trace_out) > 0:
            with open(trace_out, "r", encoding="utf-8") as handle:
                trace = json.load(handle)
    except (OSError, ValueError):
        trace = None

    if trace is None:
        stderr_text = stderr_bytes.decode("utf-8", "replace") if stderr_bytes else ""
        marker = stderr_text.find(_FALLBACK_MARKER)
        if marker != -1:
            try:
                trace = json.loads(stderr_text[marker + len(_FALLBACK_MARKER):])
            except ValueError:
                trace = None

    if trace is None:
        # No trace at all: the process died before it could write one.
        trace = {
            "target_seen": False,
            "frames": [],
            "observations": [],
            "stdout": "",
            "stderr": stderr_bytes.decode("utf-8", "replace") if stderr_bytes else "",
            "top_level_exception": None,
            "completed": False,
        }

    trace["returncode"] = returncode
    # A negative return code is a kill-by-signal (e.g. SIGSEGV, SIGABRT, or the
    # CPU/memory limit). That is an abnormal termination of the running code.
    trace["killed_by_signal"] = returncode < 0
    trace["signal"] = -returncode if returncode < 0 else None
    return trace


def _timeout_trace(target_file: str, target_qualname: str, exc: subprocess.TimeoutExpired) -> Dict[str, Any]:
    stdout = exc.stdout.decode("utf-8", "replace") if exc.stdout else ""
    stderr = exc.stderr.decode("utf-8", "replace") if exc.stderr else ""
    return {
        "target": {"file": target_file, "qualname": target_qualname},
        "target_seen": False,
        "frames": [],
        "observations": [],
        "stdout": stdout,
        "stderr": stderr,
        "top_level_exception": None,
        "completed": False,
        "returncode": None,
        "killed_by_signal": False,
        "signal": None,
        "timed_out": True,
    }
