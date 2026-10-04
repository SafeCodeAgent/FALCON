"""Sandboxed execution of a single probe.

``run_probe`` launches the :mod:`engine._harness` in its own process, with the
probe, the target descriptor, and a scratch directory wired in through the
environment. It supports two execution modes:

* ``host`` -- run in the current environment, under the permissions the coding
  session already has. Per-probe CPU, memory, and wall-clock limits are applied
  where the platform supports them, and the probe gets a fresh scratch directory
  that is deleted afterwards.
* ``docker`` -- run inside a container, either freshly started from an image or
  exec'd into an already-running container, so execution is isolated from the
  host filesystem. The repository must be visible at ``execution.workdir``
  inside the container; run files are staged under the repository so the same
  paths work on both sides.

When the process is killed (a signal such as a segfault, a resource limit, or the
time limit), the harness may not get to write its full trace. The runner then
uses the provisional record the harness keeps up to date on every target call,
which says whether the target was running when the process died.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid
from typing import Any, Dict, List, Optional, Tuple

from ._harness import _parse_observations

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_harness.py")
_FALLBACK_MARKER = "AV_TRACE_FALLBACK:"
STATE_DIR = ".attacker-verifier"
# Wall-clock allowance on top of the CPU limit before the harness ends itself.
_WALL_SLACK_S = 5
# Extra time the runner waits for the harness before killing it from outside.
_KILL_SLACK_S = 10


def ensure_state_dir(repo_root: str) -> str:
    """Create ``.attacker-verifier/`` with a .gitignore for generated files."""
    state = os.path.join(repo_root, STATE_DIR)
    os.makedirs(state, exist_ok=True)
    ignore = os.path.join(state, ".gitignore")
    if not os.path.exists(ignore):
        with open(ignore, "w", encoding="utf-8") as handle:
            # Ignore generated files, but let a project's config.json be committed.
            handle.write("*\n!config.json\n")
    return state


def _limits_env(config: Dict[str, Any]) -> Dict[str, str]:
    cpu = max(1, int(config["probe_timeout_s"]))
    return {
        "AV_CPU_SECONDS": str(cpu),
        "AV_MEM_BYTES": str(int(config["probe_mem_mb"]) * 1024 * 1024),
        "AV_WALL_SECONDS": str(cpu + _WALL_SLACK_S),
    }


def _run(command: List[str], cwd: str, env: Optional[Dict[str, str]], timeout: int,
         on_timeout=None) -> Tuple[Optional[int], bytes, bytes, bool]:
    """Run a command in its own process group; kill the whole group on timeout."""
    process = subprocess.Popen(
        command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout, stderr, False
    except subprocess.TimeoutExpired:
        if on_timeout is not None:
            on_timeout()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, AttributeError):
            process.kill()
        stdout, stderr = process.communicate()
        return None, stdout, stderr, True


def run_probe(
    repo_root: str,
    probe_path: str,
    target_file: str,
    target_qualname: str,
    config: Dict[str, Any],
    target_kind: str = "function",
) -> Dict[str, Any]:
    """Execute one probe and return its trace dict (always, even on crash)."""
    execution = config["execution"]
    repo_root = os.path.abspath(repo_root)
    limits = _limits_env(config)
    wall = int(limits["AV_WALL_SECONDS"]) + _KILL_SLACK_S
    docker = execution["mode"] == "docker"

    if docker:
        run_dir = os.path.join(ensure_state_dir(repo_root), "run", uuid.uuid4().hex[:12])
    else:
        run_dir = tempfile.mkdtemp(prefix="av-run-")
    scratch = os.path.join(run_dir, "scratch")
    os.makedirs(scratch, exist_ok=True)
    trace_out = os.path.join(run_dir, "trace.json")

    if docker:
        workdir = execution.get("workdir", "/work").rstrip("/") or "/"
        harness = os.path.join(run_dir, "harness.py")
        shutil.copyfile(HARNESS, harness)

        def inside(path: str) -> str:
            rel = os.path.relpath(os.path.abspath(path), repo_root).replace(os.sep, "/")
            return workdir + "/" + rel

        paths = {"AV_TARGET_FILE": inside(target_file), "AV_PROBE": inside(probe_path),
                 "AV_TRACE_OUT": inside(trace_out), "AV_SCRATCH": inside(scratch)}
        harness_path = inside(harness)
    else:
        paths = {"AV_TARGET_FILE": os.path.abspath(target_file), "AV_PROBE": os.path.abspath(probe_path),
                 "AV_TRACE_OUT": trace_out, "AV_SCRATCH": scratch}
        harness_path = HARNESS

    harness_env = dict(paths, AV_TARGET_QUALNAME=target_qualname, AV_TARGET_KIND=target_kind or "",
                       PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1", **limits)

    cidfile = None
    try:
        if docker:
            python = execution.get("python", "python3")
            env_flags: List[str] = []
            for key, value in harness_env.items():
                env_flags += ["-e", "%s=%s" % (key, value)]
            if execution.get("container"):
                command = (["docker", "exec", "-w", workdir] + env_flags
                           + [execution["container"], python, harness_path])
            else:
                cidfile = os.path.join(tempfile.mkdtemp(prefix="av-cid-"), "container.cid")
                command = (["docker", "run", "--rm", "--cidfile", cidfile, "--network", "none",
                            "-v", "%s:%s" % (repo_root, workdir), "-w", workdir]
                           + env_flags + [execution["image"], python, harness_path])

            def remove_container() -> None:
                if cidfile and os.path.exists(cidfile):
                    with open(cidfile, "r", encoding="utf-8") as handle:
                        subprocess.run(["docker", "rm", "-f", handle.read().strip()],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            returncode, stdout, stderr, timed_out = _run(
                command, repo_root, None, wall, on_timeout=remove_container)
        else:
            env = dict(os.environ)
            env.update(harness_env)
            python = execution.get("python") or sys.executable or "python3"
            returncode, stdout, stderr, timed_out = _run([python, harness_path], repo_root, env, wall)
        trace = _collect(trace_out, returncode, stdout, stderr, timed_out, docker)
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)
        if cidfile:
            shutil.rmtree(os.path.dirname(cidfile), ignore_errors=True)

    trace.setdefault("target", {"file": target_file, "qualname": target_qualname})
    return trace


def _signal_of(returncode: Optional[int], docker: bool) -> Optional[int]:
    if returncode is None:
        return None
    if returncode < 0:
        return -returncode
    # Docker reports a process killed by signal N as exit status 128 + N.
    if docker and 128 < returncode < 160:
        return returncode - 128
    return None


def _collect(trace_out: str, returncode: Optional[int], stdout_bytes: bytes, stderr_bytes: bytes,
             timed_out: bool, docker: bool) -> Dict[str, Any]:
    stdout = stdout_bytes.decode("utf-8", "replace") if stdout_bytes else ""
    stderr = stderr_bytes.decode("utf-8", "replace") if stderr_bytes else ""
    trace = None
    try:
        if os.path.getsize(trace_out) > 0:
            with open(trace_out, "r", encoding="utf-8") as handle:
                trace = json.load(handle)
    except (OSError, ValueError):
        trace = None

    if trace is None:
        marker = stderr.find(_FALLBACK_MARKER)
        if marker != -1:
            try:
                trace = json.loads(stderr[marker + len(_FALLBACK_MARKER):])
            except ValueError:
                trace = None

    if trace is None:
        # No record at all: the process died before reaching the target.
        trace = {"target_seen": False, "target_active": False, "frames": [], "completed": False}

    if not trace.get("completed"):
        # Only the provisional record survived; take the output from the pipes.
        trace.setdefault("stdout", stdout[-20000:])
        trace.setdefault("stderr", stderr[-20000:])
        trace.setdefault("observations", _parse_observations(trace["stdout"], []))
        trace.setdefault("top_level_exception", None)

    sig = _signal_of(returncode, docker)
    if sig == getattr(signal, "SIGALRM", 14):
        # The harness's own wall-clock limit fired.
        timed_out, sig = True, None
    trace["returncode"] = returncode
    trace["timed_out"] = timed_out
    # A kill by signal (e.g. SIGSEGV, SIGABRT, or the CPU/memory limit) is an
    # abnormal termination of whatever code was running at the time.
    trace["killed_by_signal"] = sig is not None
    trace["signal"] = sig
    return trace
