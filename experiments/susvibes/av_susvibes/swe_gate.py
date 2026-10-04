"""SWE-agent 1.1.0 submission handler integration.

Import through the bootstrap sitecustomize in the SWE-agent worker. The hook
returns a counterexample as the submission observation, so the same agent
continues its trajectory until the fifth check or a non-insecure verdict.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from .benchmark import extract_workspace, load_tasks, swe_instance_dir
from .engine import check_workspace, feedback
from .execution import DockerExecutor
from .model_api import ModelClient


def _check_submission(record: dict, patch: str, model_name: str, run_dir: Path):
    with tempfile.TemporaryDirectory(prefix="av-swe-", ignore_cleanup_errors=True) as tmp:
        workspace = Path(tmp) / "repo"
        extract_workspace(record["base_no_test_image_name"], workspace)
        patch_file = Path(tmp) / "candidate.patch"
        patch_file.write_text(patch)
        applied = subprocess.run(["git", "-c", f"safe.directory={workspace}", "apply", str(patch_file)],
                                 cwd=workspace, capture_output=True, text=True)
        if applied.returncode:
            raise RuntimeError(f"submitted patch cannot be applied to no-test image: {applied.stderr}")
        return check_workspace(workspace, record["problem_statement"], patch,
                               ModelClient(model_name), DockerExecutor(record["base_no_test_image_name"], patch),
                               output=run_dir)


def install(dataset: Path, model_name: str, output: Path, *, max_rounds: int = 5) -> None:
    from sweagent.agent.agents import DefaultAgent

    if getattr(DefaultAgent, "_av_gate_installed", False): return
    records = {r["instance_id"]: r for r in load_tasks(dataset)}
    original = DefaultAgent.handle_submission

    def handle(self, step, *, observation="", force_submission=False):
        handled = original(self, step, observation=observation, force_submission=force_submission)
        if not getattr(handled, "done", False) or not getattr(handled, "submission", None):
            return handled
        instance_id = str(getattr(getattr(self, "_problem_statement", None), "id", "") or
                          Path(str(getattr(self, "traj_path", ""))).parent.name)
        record = records.get(instance_id)
        if record is None: return handled
        state = getattr(self, "_av_state", {"uses": 0, "last_patch": "", "rounds": []})
        if force_submission or state["uses"] >= max_rounds:
            if state["last_patch"]: handled.submission = state["last_patch"]
            return handled
        state["uses"] += 1
        patch = str(handled.submission)
        audit_dir = output / "checks" / swe_instance_dir(instance_id)
        run_dir = audit_dir / f"round_{state['uses']:02d}"
        run_dir.mkdir(parents=True, exist_ok=True)
        try:
            report = _check_submission(record, patch, model_name, run_dir)
        except Exception as exc:
            # A failed check must not end the trajectory; accept the submission as is.
            state["rounds"].append({"round": state["uses"], "error": f"{type(exc).__name__}: {exc}"})
            self._av_state = state
            (audit_dir / "state.json").write_text(json.dumps(state, indent=2) + "\n")
            return handled
        state["last_patch"] = patch
        state["rounds"].append({"round": state["uses"], "verdict": report.verdict,
                                 "counterexamples": len(report.counterexamples)})
        self._av_state = state
        (audit_dir / "state.json").write_text(json.dumps(state, indent=2) + "\n")
        if report.verdict == "insecure" and state["uses"] < max_rounds:
            handled.done = False
            handled.submission = None
            handled.exit_status = None
            handled.observation = feedback(report)
        return handled

    DefaultAgent.handle_submission = handle
    DefaultAgent._av_gate_installed = True
