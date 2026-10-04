import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evaluation_harness.claude_code.runner import agent_turn, command_args, result_event
from av_susvibes.benchmark import run_task
from av_susvibes.models import CheckReport


class ClaudeHarnessTests(unittest.TestCase):
    def test_command_uses_paper_cli_and_susvibes_tool_policy(self):
        command = command_args("model/example", "Public issue")
        self.assertEqual(command[:6], ["claude", "--verbose", "--output-format",
                                       "stream-json", "-p", "Public issue"])
        self.assertIn("--allowedTools", command)
        self.assertIn("--disallowedTools", command)
        self.assertIn("WebFetch", command)
        self.assertIn("WebSearch", command)

    def test_stream_result_is_read_and_cli_error_is_rejected(self):
        event = json.dumps({"type": "result", "subtype": "success", "is_error": False})
        self.assertEqual(result_event("notice\n" + event)["subtype"], "success")
        with tempfile.TemporaryDirectory() as tmp:
            with patch("evaluation_harness.claude_code.runner.run_command", return_value=event):
                stdout, session_id = agent_turn("model/example", "task", Path(tmp), 10)
            self.assertEqual((stdout, session_id), (event, ""))
            failure = json.dumps({"type": "result", "subtype": "error", "is_error": True})
            with patch("evaluation_harness.claude_code.runner.run_command", return_value=failure):
                with self.assertRaisesRegex(RuntimeError, "reported an error"):
                    agent_turn("model/example", "task", Path(tmp), 10)

    def test_fresh_repair_session_repeats_public_task(self):
        task = {"instance_id": "example-task", "problem_statement": "Fix public issue",
                "base_no_test_image_name": "example/no-test:1"}
        with tempfile.TemporaryDirectory() as tmp:
            with patch("av_susvibes.benchmark.extract_workspace"), \
                 patch("av_susvibes.benchmark.agent_turn",
                       side_effect=[("first", ""), ("second", "")]) as turns, \
                 patch("av_susvibes.benchmark.candidate_patch", return_value="diff --git a/a.py b/a.py\n"), \
                 patch("av_susvibes.benchmark.check_workspace",
                       side_effect=[CheckReport("insecure", []), CheckReport("secure", [])]), \
                 patch("av_susvibes.benchmark.feedback", return_value="Observed unsafe output"):
                run_task(task, harness="claude-code", model_name="model/example",
                         output=Path(tmp), model=object(), max_rounds=2,
                         containerized=False)
            prompts = [call.args[2] for call in turns.call_args_list]
            self.assertEqual(len(prompts), 2)
            self.assertIn("Fix public issue", prompts[0])
            self.assertIn("Fix public issue", prompts[1])
            self.assertIn("Observed unsafe output", prompts[1])
            self.assertEqual(turns.call_args_list[1].kwargs["session_id"], "")


class SweGateTests(unittest.TestCase):
    def test_failed_check_accepts_submission_instead_of_crashing(self):
        import sys
        import types

        class Handled:
            def __init__(self):
                self.done, self.submission = True, "diff --git a/a.py b/a.py\n"

        class DefaultAgent:
            def __init__(self):
                self._problem_statement = types.SimpleNamespace(id="example-task")

            def handle_submission(self, step, *, observation="", force_submission=False):
                return Handled()

        agents = types.ModuleType("sweagent.agent.agents")
        agents.DefaultAgent = DefaultAgent
        modules = {"sweagent": types.ModuleType("sweagent"),
                   "sweagent.agent": types.ModuleType("sweagent.agent"),
                   "sweagent.agent.agents": agents}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(sys.modules, modules):
            dataset = Path(tmp) / "tasks.jsonl"
            dataset.write_text(json.dumps({"instance_id": "example-task",
                                           "problem_statement": "Fix public issue",
                                           "base_no_test_image_name": "example/no-test:1"}) + "\n")
            from av_susvibes import swe_gate
            with patch.object(swe_gate, "_check_submission", side_effect=RuntimeError("docker unavailable")):
                swe_gate.install(dataset, "model/example", Path(tmp) / "out")
                handled = DefaultAgent().handle_submission(None)
            self.assertTrue(handled.done)
            self.assertEqual(handled.submission, "diff --git a/a.py b/a.py\n")
            state = json.loads(next((Path(tmp) / "out").rglob("state.json")).read_text())
            self.assertIn("docker unavailable", state["rounds"][0]["error"])


if __name__ == "__main__":
    unittest.main()
