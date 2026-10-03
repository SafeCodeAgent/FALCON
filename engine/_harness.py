"""In-process harness that runs one probe and records its execution trace.

This file is executed as ``__main__`` in the probe's own process (see
``runner.py``). It installs a trace function that watches for activations of the
attack target, runs the probe script, and writes a structured trace to the path
named by ``AV_TRACE_OUT``.

It is deliberately standalone (stdlib only, no imports from the rest of the
engine) so it can run inside a minimal sandbox or container.

Environment inputs:
  AV_TARGET_FILE      absolute path to the file defining the target
  AV_TARGET_QUALNAME  qualified name of the target, e.g. "Class.method" or "func"
  AV_PROBE            path to the probe script to run
  AV_TRACE_OUT        path to write the trace JSON to
  AV_SCRATCH          a writable scratch directory the probe may use
"""

import json
import os
import runpy
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


class _Recorder:
    """Collects activations of the target frame via sys.settrace."""

    def __init__(self, target_file, target_qualname):
        try:
            self.target_file = os.path.realpath(target_file)
        except OSError:
            self.target_file = target_file
        self.target_qualname = target_qualname
        self.target_leaf = target_qualname.split(".")[-1]
        self.frames = []
        self.target_seen = False

    def _matches(self, code):
        try:
            same_file = os.path.realpath(code.co_filename) == self.target_file
        except OSError:
            same_file = code.co_filename == self.target_file
        if not same_file:
            return False
        qual = getattr(code, "co_qualname", None)
        if qual is not None:
            # Exact match, or method match ignoring an outer function wrapper.
            return qual == self.target_qualname or qual.endswith(
                "." + self.target_qualname
            ) or qual.split(".")[-1] == self.target_leaf and qual.endswith(
                self.target_leaf
            )
        return code.co_name == self.target_leaf

    def trace(self, frame, event, arg):
        if event != "call":
            return None
        code = frame.f_code
        if not self._matches(code):
            return None
        if len(self.frames) >= MAX_FRAMES:
            return None
        self.target_seen = True
        argnames = code.co_varnames[: code.co_argcount]
        record = {
            "func": getattr(code, "co_qualname", code.co_name),
            "file": code.co_filename,
            "line": frame.f_lineno,
            "args": {name: _safe_repr(frame.f_locals.get(name)) for name in argnames},
            "return": None,
            "exception": None,
        }
        self.frames.append(record)
        return self._make_local(record)

    def _make_local(self, record):
        def local(frame, event, arg):
            if event == "return":
                record["return"] = _safe_repr(arg)
            elif event == "exception":
                exc_type, exc_value, _tb = arg
                record["exception"] = {
                    "type": getattr(exc_type, "__name__", str(exc_type)),
                    "message": _safe_repr(exc_value),
                }
            return local

        return local


class _Tee:
    """Captures a stream while still forwarding it to the real fd."""

    def __init__(self, real):
        self.real = real
        self.buffer = []
        self._size = 0

    def write(self, text):
        if self._size < MAX_STREAM:
            self.buffer.append(text)
            self._size += len(text)
        try:
            self.real.write(text)
        except Exception:  # noqa: BLE001
            pass

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


def _parse_observations(stdout_text):
    observations = []
    for line in stdout_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith(OBSERVATION_PREFIX):
            continue
        payload = stripped[len(OBSERVATION_PREFIX):].strip()
        try:
            observations.append({"raw": payload, "parsed": json.loads(payload)})
        except ValueError:
            observations.append({"raw": payload, "parsed": None})
    return observations


def main():
    target_file = os.environ.get("AV_TARGET_FILE", "")
    target_qualname = os.environ.get("AV_TARGET_QUALNAME", "")
    probe_path = os.environ.get("AV_PROBE", "")
    trace_out = os.environ.get("AV_TRACE_OUT", "")

    # The probe runs from the repository root and imports the candidate
    # implementation (e.g. ``from core.storage import ...``). runpy puts the
    # probe file's own directory on sys.path, not the repo root, so make the
    # working directory importable first.
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)

    recorder = _Recorder(target_file, target_qualname)
    out = _Tee(sys.stdout)
    err = _Tee(sys.stderr)
    sys.stdout = out
    sys.stderr = err

    top_level_exception = None
    started = time.time()

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
        sys.stdout = out.real
        sys.stderr = err.real

    duration = time.time() - started
    stdout_text = out.value()

    trace = {
        "target": {"file": target_file, "qualname": target_qualname},
        "target_seen": recorder.target_seen,
        "frames": recorder.frames,
        "observations": _parse_observations(stdout_text),
        "stdout": stdout_text,
        "stderr": err.value(),
        "top_level_exception": top_level_exception,
        "duration_s": round(duration, 4),
        "completed": True,
    }

    try:
        with open(trace_out, "w", encoding="utf-8") as handle:
            json.dump(trace, handle)
    except OSError:
        # Last resort: emit on stderr so the runner can still recover something.
        sys.stderr.write("AV_TRACE_FALLBACK:" + json.dumps(trace))


if __name__ == "__main__":
    main()
