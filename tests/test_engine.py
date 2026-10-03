"""Unit tests for the deterministic engine.

Run from the repository root with:

    python3 -m unittest discover -s tests

These cover the pure-logic pieces (faithfulness screening, the crash oracle,
signal aggregation, target selection). The sandboxed execution path is exercised
separately in ``test_runner.py``.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import faithfulness, targets, verifier


class StaticFaithfulnessTests(unittest.TestCase):
    def test_admits_a_plain_probe(self):
        src = "from app.files import load_report\nload_report('../x')\n"
        result = faithfulness.static_check(src, "load_report", "files")
        self.assertTrue(result["admitted"])

    def test_rejects_redefinition(self):
        src = "def load_report(name):\n    return open(name).read()\nload_report('x')\n"
        result = faithfulness.static_check(src, "load_report", "files")
        self.assertFalse(result["admitted"])
        self.assertEqual(result["rule"], "target_redefined")

    def test_rejects_rebinding(self):
        src = "import app.files as m\nm.load_report = lambda n: 0\n"
        result = faithfulness.static_check(src, "load_report", "files")
        self.assertFalse(result["admitted"])
        self.assertEqual(result["rule"], "target_rebound")

    def test_rejects_mock_patch_of_target(self):
        src = "from unittest.mock import patch\nwith patch('files.load_report'):\n    pass\n"
        result = faithfulness.static_check(src, "load_report", "files")
        self.assertFalse(result["admitted"])
        self.assertEqual(result["rule"], "target_path_replaced")

    def test_rejects_syntax_error(self):
        result = faithfulness.static_check("def (:\n", "load_report", "files")
        self.assertFalse(result["admitted"])
        self.assertEqual(result["rule"], "parse_error")

    def test_rejects_empty(self):
        result = faithfulness.static_check("   ", "load_report", "files")
        self.assertFalse(result["admitted"])
        self.assertEqual(result["rule"], "no_probe_files")


class RuntimeFaithfulnessTests(unittest.TestCase):
    def test_rejects_when_target_never_ran(self):
        trace = {"target_seen": False, "frames": []}
        result = faithfulness.runtime_check(trace, "load_report")
        self.assertFalse(result["admitted"])
        self.assertEqual(result["rule"], "target_frame_missing")

    def test_admits_when_target_ran(self):
        trace = {"target_seen": True, "frames": [{"func": "load_report"}]}
        result = faithfulness.runtime_check(trace, "load_report")
        self.assertTrue(result["admitted"])


class CrashOracleTests(unittest.TestCase):
    def test_abort_signal_is_a_crash(self):
        trace = {"killed_by_signal": True, "signal": 11, "target_seen": True}
        self.assertIsNotNone(verifier.crash_oracle(trace))

    def test_uncaught_memory_error_through_target_is_a_crash(self):
        trace = {
            "killed_by_signal": False,
            "top_level_exception": {
                "type": "RecursionError",
                "is_memory_error": True,
                "through_target": True,
            },
        }
        self.assertIsNotNone(verifier.crash_oracle(trace))

    def test_caught_exception_is_not_a_crash(self):
        trace = {"killed_by_signal": False, "top_level_exception": None}
        self.assertIsNone(verifier.crash_oracle(trace))


class AggregateTests(unittest.TestCase):
    def test_insecure_when_any_admitted_is_insecure(self):
        results = [
            {"id": "a", "status": "admitted", "core": {"verdict": "insecure", "stage": 1, "reason": "crash"}, "target": {}},
            {"id": "b", "status": "admitted", "core": {"verdict": "uncertain"}, "target": {}},
        ]
        agg = verifier.aggregate(results, {"b": {"verdict": "secure"}})
        self.assertEqual(agg["signal"], "insecure")
        self.assertEqual(len(agg["counterexamples"]), 1)

    def test_secure_when_admitted_and_none_insecure(self):
        results = [{"id": "a", "status": "admitted", "core": {"verdict": "uncertain"}, "target": {}}]
        agg = verifier.aggregate(results, {"a": {"verdict": "secure", "reason": "ok"}})
        self.assertEqual(agg["signal"], "secure")

    def test_no_evidence_when_nothing_admitted(self):
        results = [{"id": "a", "status": "rejected_static", "faithfulness": {"rule": "target_redefined"}}]
        agg = verifier.aggregate(results, {})
        self.assertEqual(agg["signal"], "no-evidence")


class TargetSelectionTests(unittest.TestCase):
    def test_excludes_tests_and_ranks_by_relevance(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "pkg"))
            os.makedirs(os.path.join(root, "tests"))
            with open(os.path.join(root, "pkg", "a.py"), "w") as handle:
                handle.write(
                    "import subprocess\n"
                    "def run_cmd(x):\n    subprocess.run(x, shell=True)\n"
                    "def pure(y):\n    return y + 1\n"
                )
            with open(os.path.join(root, "tests", "test_a.py"), "w") as handle:
                handle.write("def test_x():\n    assert True\n")
            found = targets.select_targets(root, scope="whole", max_targets=10)
            names = [t["qualname"] for t in found]
            self.assertIn("run_cmd", names)
            self.assertIn("pure", names)
            self.assertNotIn("test_x", names)
            # The subprocess-touching function ranks above the pure one.
            self.assertLess(names.index("run_cmd"), names.index("pure"))


if __name__ == "__main__":
    unittest.main()
