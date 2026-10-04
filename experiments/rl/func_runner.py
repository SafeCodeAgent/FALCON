"""Run SecCodePLT+ test cases for one candidate inside a Docker container."""

import json
import signal
import traceback
from pathlib import Path

import numpy as np

TIME_LIMIT_S = 1


class TestTimeout(BaseException):
    """Raised by SIGALRM; a BaseException so the per-case handler cannot swallow it."""


def _on_alarm(signum, frame):
    raise TestTimeout("test cases exceeded %ss" % TIME_LIMIT_S)


data = json.loads(Path("/work/input.json").read_text(encoding="utf-8"))
namespace = {}
signal.signal(signal.SIGALRM, _on_alarm)
try:
    signal.alarm(TIME_LIMIT_S)
    exec(data["setup"], namespace)
    exec(data["code"], namespace)
    exec(data["testcases"], namespace)
    function = namespace[data["function_name"]]
    sets = {}
    for name, cases in namespace["testcases"].items():
        passed = 0
        for kwargs, expected in cases:
            try:
                value = function(**kwargs)
                ok = bool(np.array_equal(value, expected)) if not isinstance(expected, type) else False
            except Exception as exc:
                ok = type(exc) is expected if isinstance(expected, type) and issubclass(expected, BaseException) else False
            passed += int(ok)
        sets[name] = {"passed": passed, "total": len(cases)}
    signal.alarm(0)
    print("AV_FUNC:" + json.dumps({"sets": sets}))
except BaseException:
    signal.alarm(0)
    print("AV_FUNC:" + json.dumps({"sets": {},
                                   "error": traceback.format_exc()[-3000:]}))
