# -*- coding: utf-8 -*-
"""Standalone Python probe runner copied into the no-test task container.

Its result file is written by this process, separately from attacker stdout.
Only Python frames and audit events collected here count as runtime attribution.
"""
from __future__ import print_function

import json
import io
import os
import runpy
import sys
import threading
import traceback
try:
    import builtins
except ImportError:  # Python 2 task images
    import __builtin__ as builtins
import subprocess
import socket

probe_path, target_json, result_path, repo_root = sys.argv[1:5]
target = json.loads(target_json)
target_file = os.path.realpath(os.path.join(repo_root, target["path"]))
sys.path.insert(0, repo_root)
frames = []
events = []
target_return = None
target_exception = None
harness_error = ""
fatal = False
active = set()
MAX_EVENTS = 256
original_stdout, original_stderr = sys.stdout, sys.stderr
try:
    TEXT_TYPE = unicode
except NameError:
    TEXT_TYPE = str
PATH_TYPES = (str, bytes, TEXT_TYPE) + ((os.PathLike,) if hasattr(os, "PathLike") else ())


class SinkIntercepted(RuntimeError):
    pass


def snapshot():
    # Persist target entry immediately so a wall-time or OOM kill can still
    # be attributed to the exercised code rather than to probe setup.
    with io.open(result_path, "w", encoding="utf-8") as out:
        out.write(TEXT_TYPE(json.dumps({"frames": frames[:128], "events": events,
                                        "target_return": target_return,
                                        "exception": target_exception,
                                        "harness_error": harness_error}, default=str)))


def safe(value):
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return repr(value)[:2000]


def in_target(frame):
    while frame:
        if frame.f_code.co_filename and os.path.realpath(frame.f_code.co_filename) == target_file:
            qual = getattr(frame.f_code, "co_qualname", frame.f_code.co_name).replace("<locals>.", "")
            right_name = qual == target["qualname"] or (
                qual == target["qualname"].split(".")[-1]
                and target["start"] <= frame.f_code.co_firstlineno <= target["end"])
            if right_name:
                return {"path": target["path"], "qualname": target["qualname"], "line": frame.f_lineno}
        frame = frame.f_back
    return None


def trace(frame, action, arg):
    global target_return, target_exception
    match = in_target(frame)
    own = (os.path.realpath(frame.f_code.co_filename) == target_file and
           in_target(frame) is not None and
           (getattr(frame.f_code, "co_qualname", frame.f_code.co_name).replace("<locals>.", "") == target["qualname"]
            or (frame.f_code.co_name == target["qualname"].split(".")[-1]
                and target["start"] <= frame.f_code.co_firstlineno <= target["end"])))
    if own and action == "call":
        active.add(id(frame))
        frames.append(match)
        if len(frames) == 1:
            snapshot()
    elif own and action == "return" and id(frame) in active:
        active.discard(id(frame))
        target_return = safe(arg)
    elif own and action == "exception":
        exc_type, exc, _ = arg
        target_exception = {"type": exc_type.__name__, "message": str(exc)[:2000], "frame": match}
    return trace


def audit(name, args):
    if name == "open" and args and isinstance(args[0], PATH_TYPES) and str(args[0]) == result_path:
        return
    if name == "open" and args:
        path = args[0]
        try:
            real = os.path.realpath(path)
            rel = os.path.relpath(real, repo_root).replace(os.sep, "/").lower()
            parts = rel.split("/")
            if real.startswith(os.path.realpath(repo_root) + os.sep) and (
                any(p in {"test", "tests", "testing"} for p in parts[:-1])
                or parts[-1].startswith("test_") or parts[-1].endswith(("_test.py", "_tests.py"))
            ):
                raise PermissionError("probe access to repository tests is forbidden")
        except (TypeError, ValueError):
            pass
    if name not in {"open", "os.system", "subprocess.Popen", "socket.connect", "socket.getaddrinfo", "os.exec", "os.posix_spawn", "exec", "os.chmod", "os.mkdir"}:
        return
    match = in_target(sys._getframe(1))
    if match and len(events) < MAX_EVENTS:
        kind = "file" if name in {"open", "os.chmod", "os.mkdir"} else "process" if name in {"os.system", "subprocess.Popen", "os.exec", "os.posix_spawn"} else "code" if name == "exec" else "network"
        item = {"kind": kind, "api": name, "args": safe(args), "frames": [match], "attributed": True}
        if name == "open" and args and isinstance(args[0], PATH_TYPES):
            item["created"] = not os.path.exists(args[0])
        events.append(item)
        if name in {"os.system", "subprocess.Popen", "socket.connect", "os.exec", "os.posix_spawn"}:
            raise SinkIntercepted("intercepted target sink call: " + name)


def install_legacy_audit_fallback():
    # Python 3.7 lacks sys.addaudithook. Capture the common Python-level sinks
    # under a real target frame. The container still has network disabled.
    original_open = builtins.open
    original_popen = subprocess.Popen
    original_system = os.system
    original_connect = socket.create_connection
    original_socket = socket.socket
    def record(kind, api, args):
        match = in_target(sys._getframe(2))
        if match and len(events) < MAX_EVENTS:
            events.append({"kind": kind, "api": api, "args": safe(args),
                           "frames": [match], "attributed": True})
            return True
        return False
    def wrapped_open(*args, **kwargs):
        if args and args[0] != result_path:
            record("file", "open", args)
        return original_open(*args, **kwargs)
    def wrapped_popen(*args, **kwargs):
        if record("process", "subprocess.Popen", args): raise SinkIntercepted("process sink intercepted")
        return original_popen(*args, **kwargs)
    def wrapped_system(*args, **kwargs):
        if record("process", "os.system", args): raise SinkIntercepted("process sink intercepted")
        return original_system(*args, **kwargs)
    def wrapped_connect(*args, **kwargs):
        if record("network", "socket.connect", args): raise SinkIntercepted("network sink intercepted")
        return original_connect(*args, **kwargs)
    class TracedSocket(original_socket):
        def connect(self, address):
            if record("network", "socket.connect", (address,)):
                raise SinkIntercepted("network sink intercepted")
            return original_socket.connect(self, address)
        def connect_ex(self, address):
            if record("network", "socket.connect", (address,)):
                raise SinkIntercepted("network sink intercepted")
            return original_socket.connect_ex(self, address)
    builtins.open = wrapped_open
    subprocess.Popen = wrapped_popen
    os.system = wrapped_system
    socket.create_connection = wrapped_connect
    socket.socket = TracedSocket


def profile(frame, action, arg):
    # unittest.mock's call path remains visible even when the sensitive sink
    # itself is replaced. Capture its actual call arguments under a target frame.
    if action != "call":
        return
    match = in_target(frame.f_back)
    if not match or len(events) >= MAX_EVENTS:
        return
    module = str(frame.f_globals.get("__name__", ""))
    function = frame.f_code.co_name
    if module == "subprocess" and function in {"run", "call", "check_output", "check_call", "__init__"}:
        arguments = frame.f_locals.get("popenargs", frame.f_locals.get("args", ()))
        keywords = frame.f_locals.get("kwargs", {})
        if not isinstance(keywords, dict): keywords = {}
        if "shell" in frame.f_locals: keywords = dict(keywords, shell=frame.f_locals["shell"])
        events.append({"kind": "process", "api": "subprocess." + function,
                       "args": safe(arguments), "kwargs": safe(keywords),
                       "frames": [match], "attributed": True})
    elif module.startswith(("pickle", "yaml")) and function in {"load", "loads", "unsafe_load"}:
        events.append({"kind": "deserialize", "api": module + "." + function,
                       "args": safe({k: v for k, v in frame.f_locals.items() if k != "self"}),
                       "frames": [match], "attributed": True})
    elif module.startswith("logging") and function in {"log", "debug", "info", "warning", "error", "critical"}:
        events.append({"kind": "log", "api": module + "." + function,
                       "args": safe(frame.f_locals.get("msg", "")), "frames": [match], "attributed": True})
    if function not in {"_mock_call", "_execute_mock_call"}:
        return
    mock = frame.f_locals.get("self")
    if mock is not None:
        name = getattr(mock, "_mock_name", None) or "mock"
        events.append({"kind": "mock_sink", "api": name, "args": safe(frame.f_locals.get("args", ())),
                       "kwargs": safe(frame.f_locals.get("kwargs", {})), "frames": [match], "attributed": True})


class OutputRecorder:
    def __init__(self, stream, kind):
        self.stream, self.kind = stream, kind
    def write(self, value):
        match = in_target(sys._getframe(1))
        if match and value and len(events) < MAX_EVENTS:
            events.append({"kind": self.kind, "api": "write", "args": [value[:2000]],
                           "frames": [match], "attributed": True})
        return self.stream.write(value)
    def flush(self): return self.stream.flush()
    def __getattr__(self, key): return getattr(self.stream, key)


if hasattr(sys, "addaudithook"):
    sys.addaudithook(audit)
else:
    install_legacy_audit_fallback()
sys.settrace(trace)
threading.settrace(trace)
sys.setprofile(profile)
threading.setprofile(profile)
sys.stdout, sys.stderr = OutputRecorder(original_stdout, "stdout"), OutputRecorder(original_stderr, "stderr")
try:
    runpy.run_path(probe_path, run_name="__main__")
except BaseException as exc:
    fatal = True
    # A probe can fail after a target call. Such a failure is a harness error,
    # even when an earlier target exception was caught by the probe.
    tb = sys.exc_info()[2]
    attributable = False
    while tb is not None:
        if in_target(tb.tb_frame):
            attributable = True
            break
        tb = tb.tb_next
    if attributable:
        target_exception = {"type": type(exc).__name__, "message": str(exc)[:2000],
                            "unhandled": True}
    else:
        harness_error = "{}: {}".format(type(exc).__name__, exc)
    traceback.print_exc()
finally:
    sys.settrace(None)
    sys.setprofile(None)
    sys.stdout, sys.stderr = original_stdout, original_stderr
    for event in events:
        if event.get("kind") == "file" and event.get("api") == "open" and event.get("args"):
            try:
                event["mode_bits"] = os.stat(event["args"][0]).st_mode & 0o777
            except (OSError, TypeError, ValueError):
                pass
    snapshot()
if fatal:
    sys.exit(1)
