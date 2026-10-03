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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import config, faithfulness, runner, verifier


def _write(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(textwrap.dedent(text))


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config.load_config(".", None)
        self.cfg["probe_timeout_s"] = 10

    def _run(self, target_src, probe_src, qualname):
        root = tempfile.mkdtemp()
        target_file = os.path.join(root, "mod.py")
        probe_file = os.path.join(root, "probe.py")
        _write(target_file, target_src)
        _write(probe_file, probe_src)
        trace = runner.run_probe(root, probe_file, target_file, qualname, self.cfg)
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
