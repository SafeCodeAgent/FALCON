"""In-process harness that runs one probe and records its execution trace.

This file is executed as ``__main__`` in the probe's own process (see
``runner.py``). It installs a trace function that watches for activations of the
attack target, runs the probe script, and writes a structured trace to the path
named by ``AV_TRACE_OUT``.

A small provisional record is written to the same path whenever a target call
starts or finishes, so a process killed by a signal or a resource limit still
leaves a record of whether the target was running at the time. The full trace
replaces it when the probe finishes normally.

It is deliberately standalone (stdlib only, no imports from the rest of the
engine) so it can run inside a minimal sandbox or container.

Environment inputs:
  AV_TARGET_FILE      absolute path to the file defining the target
  AV_TARGET_QUALNAME  qualified name of the target, e.g. "Class.method" or "func"
  AV_TARGET_KIND      "class" when the target is a class (its methods are tracked)
  AV_PROBE            path to the probe script to run
  AV_TRACE_OUT        path to write the trace JSON to
  AV_SCRATCH          a writable scratch directory the probe may use
  AV_CPU_SECONDS      optional CPU-time limit applied to this process
  AV_MEM_BYTES        optional address-space limit applied to this process
  AV_WALL_SECONDS     optional wall-clock limit; the process is ended by SIGALRM
"""

import json
import os
import runpy
import signal
import sys
import time
import traceback

MAX_REPR = 2000
MAX_STREAM = 20000
MAX_FRAMES = 500
OBSERVATION_PREFIX = "AV_OBSERVATION:"


def _safe_repr(value):
    try:
        text = repr(value)
    except Exception as exc:  # noqa: BLE001 - never let repr break the trace
        text = "<unreprable %s: %s>" % (type(value).__name__, exc)
    if len(text) > MAX_REPR:
        text = text[:MAX_REPR] + "...<truncated>"
    return text


def _apply_limits():
    """Apply the CPU, memory, and wall-clock limits passed in by the runner."""
    try:
        import resource
    except ImportError:
        resource = None
    cpu = int(os.environ.get("AV_CPU_SECONDS") or 0)
    mem = int(os.environ.get("AV_MEM_BYTES") or 0)
    if resource is not None and cpu:
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        except (ValueError, OSError):
            pass
    if resource is not None and mem:
        for name in ("RLIMIT_AS", "RLIMIT_DATA"):
            limit = getattr(resource, name, None)
            if limit is not None:
                try:
                    resource.setrlimit(limit, (mem, mem))
                except (ValueError, OSError):
                    pass
    wall = int(os.environ.get("AV_WALL_SECONDS") or 0)
    if wall and hasattr(signal, "alarm"):
        # Default SIGALRM action ends the process; the runner reports it as a timeout.
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(wall)


class _Recorder:
    """Collects activations of the target frame via sys.settrace."""

    def __init__(self, target_file, target_qualname, target_kind, on_change):
        try:
            self.target_file = os.path.realpath(target_file)
        except OSError:
            self.target_file = target_file
        self.target_qualname = target_qualname
        # A class body runs once at import; exercising a class means calling its methods.
        self.is_class = target_kind == "class"
        self.target_leaf = target_qualname.split(".")[-1]
        self.frames = []
        self.target_seen = False
        self.depth = 0
        self._on_change = on_change

    def _matches(self, code):
        try:
            same_file = os.path.realpath(code.co_filename) == self.target_file
        except OSError:
            same_file = code.co_filename == self.target_file
        if not same_file:
            return False
        qual = getattr(code, "co_qualname", None)
        if qual is None:  # Python < 3.11
            return not self.is_class and code.co_name == self.target_leaf
        if self.is_class:
            return qual.startswith(self.target_qualname + ".")
        return qual == self.target_qualname

    def trace(self, frame, event, arg):
        if event != "call":
            return None
        code = frame.f_code
        if not self._matches(code):
            return None
        first = not self.target_seen
        self.target_seen = True
        self.depth += 1
        record = None
        if len(self.frames) < MAX_FRAMES:
            argnames = code.co_varnames[: code.co_argcount + code.co_kwonlyargcount]
            record = {
                "func": getattr(code, "co_qualname", code.co_name),
                "file": code.co_filename,
                "line": frame.f_lineno,
                "args": {name: _safe_repr(frame.f_locals.get(name)) for name in argnames},
                "return": None,
                "exception": None,
            }
            self.frames.append(record)
        if first or self.depth == 1:
            self._on_change()
        return self._make_local(record)

    def _make_local(self, record):
        def local(frame, event, arg):
            if event == "return":
                if record is not None:
                    record["return"] = _safe_repr(arg)
                self.depth = max(0, self.depth - 1)
                if self.depth == 0:
                    self._on_change()
            elif event == "exception" and record is not None:
                exc_type, exc_value, _tb = arg
                record["exception"] = {
                    "type": getattr(exc_type, "__name__", str(exc_type)),
                    "message": _safe_repr(exc_value),
                }
            return local

        return local


class _Tee:
    """Captures a stream while still forwarding it to the real fd.

    For stdout it also notes, for every observation line, whether the target had
    already been entered when the line was printed.
    """

    def __init__(self, real, recorder=None):
        self.real = real
        self.buffer = []
        self._size = 0
        self._recorder = recorder
        self.observation_after_target = []

    def write(self, text):
        if self._recorder is not None and OBSERVATION_PREFIX in text:
            seen = self._recorder.target_seen
            self.observation_after_target.extend([seen] * text.count(OBSERVATION_PREFIX))
        if self._size < MAX_STREAM:
            self.buffer.append(text)
            self._size += len(text)
        try:
            self.real.write(text)
        except Exception:  # noqa: BLE001
            pass
        return len(text)

    def flush(self):
        try:
            self.real.flush()
        except Exception:  # noqa: BLE001
            pass

    def value(self):
        text = "".join(self.buffer)
        if len(text) > MAX_STREAM:
            text = text[:MAX_STREAM] + "...<truncated>"
        return text


def _parse_observations(stdout_text, after_target):
    observations = []
    for line in stdout_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith(OBSERVATION_PREFIX):
            continue
        payload = stripped[len(OBSERVATION_PREFIX):].strip()
        index = len(observations)
        # When a line was assembled from several writes its timing is unknown;
        # count it as after the target rather than discard it.
        after = after_target[index] if index < len(after_target) else True
        try:
            parsed = json.loads(payload)
        except ValueError:
            parsed = None
        observations.append({"raw": payload, "parsed": parsed, "after_target": after})
    return observations


def _write(path, trace):
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(trace, handle)
        return True
    except OSError:
        return False


def main():
    target_file = os.environ.get("AV_TARGET_FILE", "")
    target_qualname = os.environ.get("AV_TARGET_QUALNAME", "")
    probe_path = os.environ.get("AV_PROBE", "")
    trace_out = os.environ.get("AV_TRACE_OUT", "")
    _apply_limits()

    # The probe runs from the repository root and imports the candidate
    # implementation (e.g. ``from core.storage import ...``). runpy puts the
    # probe file's own directory on sys.path, not the repo root, so make the
    # working directory importable first.
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)

    state = {"out": None, "started": time.time()}

    def snapshot(completed, top_level_exception=None):
        out = state["out"]
        stdout_text = out.value() if out is not None else ""
        return {
            "target": {"file": target_file, "qualname": target_qualname},
            "target_seen": recorder.target_seen,
            "target_active": recorder.depth > 0,
            "frames": recorder.frames,
            "observations": _parse_observations(
                stdout_text, out.observation_after_target if out is not None else []),
            "stdout": stdout_text,
            "stderr": err.value(),
            "top_level_exception": top_level_exception,
            "duration_s": round(time.time() - state["started"], 4),
            "completed": completed,
        }

    def provisional():
        # Kept small: it is rewritten on every outermost target call and return.
        # The runner fills in stdout and stderr from the process pipes.
        _write(trace_out, {
            "target": {"file": target_file, "qualname": target_qualname},
            "target_seen": recorder.target_seen,
            "target_active": recorder.depth > 0,
            "frames": recorder.frames[:20],
            "completed": False,
        })

    recorder = _Recorder(target_file, target_qualname,
                         os.environ.get("AV_TARGET_KIND", ""), provisional)
    out = _Tee(sys.stdout, recorder)
    err = _Tee(sys.stderr)
    state["out"] = out
    sys.stdout = out
    sys.stderr = err

    top_level_exception = None
    sys.settrace(recorder.trace)
    try:
        runpy.run_path(probe_path, run_name="__main__")
    except SystemExit:
        pass
    except BaseException as exc:  # noqa: BLE001 - we report, never swallow silently
        tb = traceback.format_exc()
        # Did the failure pass through the target? That distinguishes a crash in
        # the code under test from a failure in the probe's own setup. An
        # exception event recorded on a target frame proves it directly; when a
        # memory or recursion error exhausts the stack the trace function cannot
        # run, so we also accept the target file appearing in the traceback.
        through_target = recorder.target_seen and (
            any(frame["exception"] is not None for frame in recorder.frames)
            or recorder.target_file in tb
            or target_file in tb
        )
        top_level_exception = {
            "type": type(exc).__name__,
            "message": _safe_repr(exc),
            "traceback": tb[-MAX_REPR:],
            "is_memory_error": isinstance(exc, (MemoryError, RecursionError)),
            "through_target": through_target,
        }
    finally:
        sys.settrace(None)
        if hasattr(signal, "alarm"):
            signal.alarm(0)
        sys.stdout = out.real
        sys.stderr = err.real

    trace = snapshot(True, top_level_exception)
    if not _write(trace_out, trace):
        # Last resort: emit on stderr so the runner can still recover something.
        sys.stderr.write("AV_TRACE_FALLBACK:" + json.dumps(trace))


if __name__ == "__main__":
    main()
