"""End-to-end sandbox tests for the runner and crash oracle.

These run real probe subprocesses, so they are kept separate from the pure-logic
tests. Run from the repository root with:

    python3 -m unittest discover -s tests
"""

import os
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import config, faithfulness, runner, verifier


def _write(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(textwrap.dedent(text))


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config.load_config(".", None)
        self.cfg["probe_timeout_s"] = 10

    def _run(self, target_src, probe_src, qualname, kind="function"):
        root = tempfile.mkdtemp()
        target_file = os.path.join(root, "mod.py")
        probe_file = os.path.join(root, "probe.py")
        _write(target_file, target_src)
        _write(probe_file, probe_src)
        trace = runner.run_probe(root, probe_file, target_file, qualname, self.cfg, target_kind=kind)
        return trace

    def test_target_frame_is_recorded(self):
        trace = self._run(
            "def handle(x):\n    return x.upper()\n",
            "from mod import handle\n"
            "print('AV_OBSERVATION:' + __import__('json').dumps({'r': handle('ab')}))\n",
            "handle",
        )
        self.assertTrue(trace["target_seen"])
        self.assertEqual(len(trace["frames"]), 1)
        fatt = faithfulness.runtime_check(trace, "handle")
        self.assertTrue(fatt["admitted"])

    def test_probe_that_never_calls_target_is_inconclusive(self):
        trace = self._run(
            "def handle(x):\n    return x\n",
            "import mod\nprint('AV_OBSERVATION:{}')\n",
            "handle",
        )
        self.assertFalse(trace["target_seen"])
        fatt = faithfulness.runtime_check(trace, "handle")
        self.assertFalse(fatt["admitted"])

    def test_segfault_inside_the_target_is_a_crash(self):
        trace = self._run(
            "import os, signal\ndef parse(x):\n    os.kill(os.getpid(), signal.SIGSEGV)\n",
            "from mod import parse\nparse(b'x')\n",
            "parse",
        )
        self.assertTrue(trace["target_seen"])
        self.assertTrue(trace["target_active"])
        self.assertTrue(faithfulness.runtime_check(trace, "parse")["admitted"])
        self.assertIsNotNone(verifier.crash_oracle(trace))

    def test_hang_inside_the_target_times_out_without_a_crash(self):
        self.cfg["probe_timeout_s"] = 1
        trace = self._run(
            "import time\ndef wait(x):\n    time.sleep(60)\n",
            "from mod import wait\nwait(1)\n",
            "wait",
        )
        self.assertTrue(trace["timed_out"])
        self.assertTrue(trace["target_active"])
        self.assertTrue(faithfulness.runtime_check(trace, "wait")["admitted"])
        self.assertIsNone(verifier.crash_oracle(trace))

    def test_observation_order_is_recorded(self):
        trace = self._run(
            "def handle(x):\n    return x\n",
            "print('AV_OBSERVATION:{\"stage\": \"setup\"}')\n"
            "from mod import handle\nhandle(1)\nprint('AV_OBSERVATION:{\"r\": 1}')\n",
            "handle",
        )
        self.assertEqual([o["after_target"] for o in trace["observations"]], [False, True])

    def test_class_target_is_not_entered_by_import(self):
        trace = self._run(
            "class Store:\n    def get(self, k):\n        return k\n",
            "import mod\nprint('AV_OBSERVATION:{}')\n",
            "Store",
            kind="class",
        )
        self.assertFalse(trace["target_seen"])
        trace = self._run(
            "class Store:\n    def get(self, k):\n        return k\n",
            "from mod import Store\nStore().get(1)\nprint('AV_OBSERVATION:{}')\n",
            "Store",
            kind="class",
        )
        self.assertTrue(trace["target_seen"])

    def test_docker_mode_uses_container_paths(self):
        root = tempfile.mkdtemp()
        _write(os.path.join(root, "mod.py"), "def handle(x):\n    return x\n")
        probe = os.path.join(root, ".attacker-verifier", "probes", "p.py")
        os.makedirs(os.path.dirname(probe))
        _write(probe, "from mod import handle\nhandle(1)\n")
        cfg = dict(self.cfg, execution={"mode": "docker", "image": "python:3.12-slim",
                                        "container": None, "workdir": "/work", "python": "python3"})
        seen = {}

        def fake_run(command, cwd, env, timeout, on_timeout=None):
            seen["command"] = command
            flags = dict(item.split("=", 1) for item in command[command.index("-e") + 1::2]
                         if "=" in item and item.startswith("AV_"))
            seen["flags"] = flags
            # The staged harness and trace path must exist on the host side.
            rel = flags["AV_TRACE_OUT"][len("/work/"):]
            seen["staged"] = os.path.isfile(os.path.join(root, os.path.dirname(rel), "harness.py"))
            return 0, b"", b"", False

        with mock.patch.object(runner, "_run", fake_run):
            runner.run_probe(root, probe, os.path.join(root, "mod.py"), "handle", cfg)
        flags = seen["flags"]
        self.assertEqual(flags["AV_PROBE"], "/work/.attacker-verifier/probes/p.py")
        self.assertEqual(flags["AV_TARGET_FILE"], "/work/mod.py")
        self.assertTrue(flags["AV_TRACE_OUT"].startswith("/work/.attacker-verifier/run/"))
        self.assertTrue(seen["staged"])
        self.assertIn("%s:/work" % root, seen["command"])

    def test_unbounded_recursion_is_a_crash(self):
        trace = self._run(
            "def deep(n):\n    return deep(n) + 1\n",
            "import sys\nsys.setrecursionlimit(200)\n"
            "from mod import deep\ndeep(1)\n",
            "deep",
        )
        self.assertTrue(trace["target_seen"])
        self.assertIsNotNone(verifier.crash_oracle(trace))


if __name__ == "__main__":
    unittest.main()
