"""Executed inside the probe container, outside the submitted workspace."""

from __future__ import annotations

import json
import os
import runpy
import sys
import traceback
import io
import sqlite3
from pathlib import Path

target_path = Path(os.environ["AV_TARGET_PATH"]).resolve()
target_symbol = os.environ["AV_TARGET_SYMBOL"]
probe_path = os.environ["AV_PROBE_PATH"]
# Target frames, and whether a target call is still running, are also written here
# whenever a call starts or finishes. A probe killed by the time or memory limit then
# still leaves evidence of whether the target was executing when it was killed.
frames_path = os.environ.get("AV_FRAMES_PATH", "")
target_frames: list[str] = []
events: list[dict] = []
errors: list[str] = []
active = 0
original_stdout = sys.stdout
error_in_target = False
original_sqlite_connect = sqlite3.connect


class CapturedStdout(io.TextIOBase):
    def write(self, text):
        if active and text.strip():
            record("output", text.rstrip("\r\n"))
        return original_stdout.write(text)

    def flush(self):
        return original_stdout.flush()


def frame_name(frame):
    return f"{frame.f_code.co_filename}::{frame.f_code.co_qualname}"


def is_target(frame):
    try:
        same_file = Path(frame.f_code.co_filename).resolve() == target_path
    except (OSError, ValueError):
        return False
    name = frame.f_code.co_qualname
    return same_file and (name == target_symbol or name.endswith("." + target_symbol))


def stack():
    frame = sys._getframe(2)
    names = []
    while frame:
        names.append(frame_name(frame))
        frame = frame.f_back
    return names


def persist_frames():
    if not frames_path:
        return
    try:
        with open(frames_path, "w", encoding="utf-8") as handle:
            json.dump({"frames": sorted(set(target_frames)), "active": active > 0}, handle)
    except OSError:
        pass


def record(kind, value, detail=None):
    frames = stack()
    matches = [f for f in frames if f in target_frames]
    if matches:
        events.append({"kind": kind, "value": str(value)[:4000], "detail": detail or {},
                       "frames": matches, "phase": "target"})


def audit(kind, args):
    try:
        if kind in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
            record("process", args, {"shell": kind == "os.system"})
        elif kind in {"socket.connect", "socket.getaddrinfo"}:
            record("network", args)
        elif kind == "open":
            path = str(args[0]) if args else ""
            if frames_path and path == frames_path:
                return
            mode = str(args[1]) if len(args) > 1 else "r"
            record("file_write" if any(x in mode for x in "wax+") else "file_read", path,
                   {"resolved_path": str(Path(path).resolve()) if path else ""})
    except Exception:
        pass


def tracer(frame, action, arg):
    global active
    if action == "call" and is_target(frame):
        active += 1
        name = frame_name(frame)
        is_new = name not in target_frames
        target_frames.append(name)
        if is_new or active == 1:
            persist_frames()
        args = {k: repr(v)[:500] for k, v in frame.f_locals.items() if not k.startswith("__")}
        events.append({"kind": "call", "value": args, "detail": {},
                       "frames": [name], "phase": "target"})
    elif action == "return" and is_target(frame):
        name = frame_name(frame)
        events.append({"kind": "return", "value": repr(arg)[:4000], "detail": {},
                       "frames": [name], "phase": "target"})
        active = max(0, active - 1)
        if active == 0:
            persist_frames()
    elif action == "call" and active and frame.f_code.co_name == "_mock_call":
        name = str(frame.f_locals.get("self", ""))
        args = frame.f_locals.get("args", ())
        kwargs = frame.f_locals.get("kwargs", {})
        lowered = name.lower()
        kind = ("sql" if any(x in lowered for x in ("execute", "query", "cursor")) else
                "network" if any(x in lowered for x in ("request", "get", "post", "connect", "urlopen")) else
                "process")
        record(kind, {"args": repr(args)[:2000], "kwargs": repr(kwargs)[:2000]},
               {"shell": kwargs.get("shell") is True} if kind == "process" else {})
    elif action == "call" and active and frame.f_code.co_name == "_log" and \
            frame.f_code.co_filename.endswith("logging/__init__.py"):
        record("log", frame.f_locals.get("msg", ""))
    return tracer


class TrackingCursor(sqlite3.Cursor):
    def execute(self, sql, parameters=()):
        record("sql", sql, {"bound_parameters": bool(parameters)})
        return super().execute(sql, parameters)

    def executemany(self, sql, seq_of_parameters):
        record("sql", sql, {"bound_parameters": True})
        return super().executemany(sql, seq_of_parameters)


class TrackingConnection(sqlite3.Connection):
    def cursor(self, factory=None):
        return super().cursor(factory=factory or TrackingCursor)

    def execute(self, sql, parameters=()):
        record("sql", sql, {"bound_parameters": bool(parameters)})
        return super().execute(sql, parameters)


def tracked_connect(*args, **kwargs):
    kwargs.setdefault("factory", TrackingConnection)
    return original_sqlite_connect(*args, **kwargs)


sys.addaudithook(audit)
sys.settrace(tracer)
sys.stdout = CapturedStdout()
sqlite3.connect = tracked_connect
try:
    runpy.run_path(probe_path, run_name="__main__")
except BaseException as exc:
    error_in_target = any(Path(item.filename).resolve() == target_path and
                          (item.name == target_symbol or item.name == target_symbol.split(".")[-1])
                          for item in traceback.extract_tb(exc.__traceback__))
    errors.append("".join(traceback.format_exception(exc))[-4000:])
    if error_in_target and target_frames:
        events.append({"kind": "unhandled_exception", "value": str(exc), "detail": {},
                       "frames": [target_frames[-1]], "phase": "target"})
finally:
    sys.settrace(None)
    sys.stdout = original_stdout
    sqlite3.connect = original_sqlite_connect
    print("AV_TRACE:" + json.dumps({"target_frames": sorted(set(target_frames)),
          "events": events[:1000], "runner_errors": errors,
          "error_in_target": error_in_target}, default=str), flush=True)
