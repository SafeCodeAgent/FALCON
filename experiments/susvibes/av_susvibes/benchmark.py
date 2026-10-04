"""SusVibes no-test inference and held-out evaluation bridge."""
from __future__ import annotations

import json
import hashlib
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from evaluation_harness.claude_code.prompts import repair_prompt as claude_repair_prompt
from evaluation_harness.claude_code.runner import agent_turn as claude_agent_turn
from evaluation_harness.claude_code.runner import prepare_runtime as prepare_claude_runtime
from evaluation_harness.claude_code.runner import result_event as claude_result_event
from evaluation_harness.common import HarnessCommandError
from evaluation_harness.docker_workspace import DockerWorkspace
from evaluation_harness.opencode.runner import agent_turn as opencode_agent_turn
from evaluation_harness.opencode.runner import prepare_runtime as prepare_opencode_runtime
from evaluation_harness.prompts import initial_prompt
from evaluation_harness.results_store import write_json

from .engine import check_workspace, feedback
from .execution import DockerExecutor
from .model_api import ModelClient


def load_tasks(path: Path) -> list[dict]:
    tasks = []
    with path.open(encoding="utf-8") as source:
        for line in source:
            if line.strip():
                item = json.loads(line)
                for key in ("instance_id", "problem_statement", "base_no_test_image_name"):
                    if not item.get(key): raise ValueError(f"dataset record missing {key}")
                tasks.append(item)
    return tasks


def _run_fingerprint(task: dict, command: list[str] | None) -> str:
    public = {key: task[key] for key in ("instance_id", "problem_statement", "base_no_test_image_name")}
    public["command"] = command or []
    return hashlib.sha256(json.dumps(public, sort_keys=True).encode()).hexdigest()


def swe_agent_instances(dataset: Path, destination: Path,
                        instance_ids: set[str] | None = None) -> Path:
    """Write SWE-agent expert instances from public, no-test task fields only."""
    instances = []
    seen = set()
    for task in load_tasks(dataset):
        instance_id = task["instance_id"]
        if instance_ids and instance_id not in instance_ids:
            continue
        if instance_id in seen:
            raise ValueError(f"duplicate instance_id: {instance_id}")
        seen.add(instance_id)
        instances.append({
            "env": {
                "deployment": {
                    "type": "docker",
                    "image": task["base_no_test_image_name"],
                    "python_standalone_dir": "/root",
                    "docker_args": ["--memory=16g", "--cpus=9"],
                },
                "repo": {"type": "preexisting", "base_commit": "HEAD", "repo_name": "project"},
            },
            "problem_statement": {
                "type": "text", "text": task["problem_statement"], "id": instance_id,
            },
        })
    if not instances:
        raise ValueError("no matching SusVibes tasks")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(instances, indent=2) + "\n", encoding="utf-8")
    return destination


def swe_instance_dir(instance_id: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", instance_id)[:80]
    return slug + "-" + hashlib.sha256(instance_id.encode()).hexdigest()[:10]


def collect_swe_predictions(dataset: Path, trajectories: Path, destination: Path,
                            model_name: str, instance_ids: set[str] | None = None,
                            process_returncode: int = 0) -> Path:
    """Convert SWE-agent's per-task .pred files to the SusVibes list schema."""
    predictions = []
    incomplete = 0
    for task in load_tasks(dataset):
        instance_id = task["instance_id"]
        if instance_ids and instance_id not in instance_ids:
            continue
        pred_file = trajectories / swe_instance_dir(instance_id) / instance_id / (instance_id + ".pred")
        if not pred_file.is_file():
            pred_file = trajectories / instance_id / (instance_id + ".pred")
        if pred_file.is_file():
            item = json.loads(pred_file.read_text(encoding="utf-8"))
            if item.get("instance_id") != instance_id:
                raise ValueError(f"SWE-agent prediction ID mismatch: {pred_file}")
            prediction = {"instance_id": instance_id, "model_name_or_path": model_name,
                          "model_patch": item.get("model_patch")}
        else:
            prediction = {"instance_id": instance_id, "model_name_or_path": model_name,
                          "model_patch": None, "error": "SWE-agent produced no prediction"}
        if not isinstance(prediction["model_patch"], str) or not prediction["model_patch"].strip():
            incomplete += 1
        predictions.append(prediction)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(predictions, indent=2) + "\n", encoding="utf-8")
    (destination.parent / "run_status.json").write_text(json.dumps({
        "status": "complete" if incomplete == 0 and process_returncode == 0 else "incomplete",
        "incomplete_count": incomplete, "process_returncode": process_returncode,
    }, indent=2) + "\n", encoding="utf-8")
    return destination


def _run(args: list[str], **kwargs):
    proc = subprocess.run(args, capture_output=True, text=True, **kwargs)
    if proc.returncode:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(args[:5])}: {proc.stderr[-1000:]}")
    return proc


def extract_workspace(image: str, destination: Path, *, workdir: str = "/project") -> None:
    destination.mkdir(parents=True, exist_ok=True)
    cid = _run(["docker", "create", "--pull", "never", image]).stdout.strip()
    try:
        _run(["docker", "cp", f"{cid}:{workdir}/.", str(destination)])
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
    _run(["git", "-c", f"safe.directory={destination}", "status", "--porcelain"], cwd=destination)


def candidate_patch(workspace: Path) -> str:
    # Include new files in the patch, but never include repository tests.
    _run(["git", "add", "-N", "."], cwd=workspace)
    return _run(["git", "diff", "--binary", "--", ".", ":(exclude)**/test/**",
                 ":(exclude)**/tests/**", ":(exclude)**/test_*.py", ":(exclude)**/*_test.py"], cwd=workspace).stdout


def agent_turn(harness: str, model: str, prompt: str, workspace: Path, *, session_id: str = "",
               timeout_s: int = 3600, command: list[str] | None = None,
               runtime: DockerWorkspace | None = None,
               agent_env: dict[str, str] | None = None) -> tuple[str, str]:
    if harness == "claude-code":
        return claude_agent_turn(model, prompt, workspace, timeout_s,
                                 command=command, runtime=runtime, agent_env=agent_env)
    if harness == "opencode":
        return opencode_agent_turn(model, prompt, workspace, timeout_s,
                                  session_id=session_id, command=command,
                                  runtime=runtime, agent_env=agent_env)
    raise ValueError("Use the SWE-agent submission hook for SWE-agent runs")


def run_task(task: dict, *, harness: str, model_name: str, output: Path, model: ModelClient,
             max_rounds: int = 5, command: list[str] | None = None, keep_workspace: bool = False,
             workdir: str = "/project", containerized: bool = True) -> dict:
    if max_rounds < 1: raise ValueError("max_rounds must be positive")
    output.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="av-task-"))
    workspace = scratch / "repo"
    checked_patch = ""
    rounds = []
    session_id = ""
    error = ""
    fingerprint = _run_fingerprint(task, command)
    total_timeout = {"claude-code": 3000, "opencode": 3600}.get(harness)
    deadline = time.monotonic() + total_timeout if total_timeout else None
    runtime: DockerWorkspace | None = None
    agent_env: dict[str, str] | None = None
    try:
        if containerized:
            runtime = DockerWorkspace(task["base_no_test_image_name"], workspace,
                                      workdir=workdir, label=task["instance_id"])
            runtime.setup()
            agent_env = (prepare_claude_runtime(runtime, model_name) if harness == "claude-code"
                         else prepare_opencode_runtime(runtime, model_name) if harness == "opencode"
                         else None)
        else:
            extract_workspace(task["base_no_test_image_name"], workspace, workdir=workdir)
        base_prompt = initial_prompt(task["problem_statement"], Path(workdir) if runtime else workspace)
        prompt = base_prompt
        for number in range(1, max_rounds + 1):
            remaining = int(deadline - time.monotonic()) if deadline else 1800
            if remaining < 1:
                error = "total task execution timeout reached"
                break
            round_dir = output / f"round_{number:02d}"
            round_dir.mkdir(parents=True, exist_ok=True)
            (round_dir / "agent_prompt.txt").write_text(prompt)
            agent_started = time.monotonic()
            try:
                raw, session_id = agent_turn(harness, model_name, prompt, workspace,
                                             session_id=session_id if harness == "opencode" else "",
                                             timeout_s=remaining,
                                             command=command, runtime=runtime,
                                             agent_env=agent_env)
            except Exception as exc:
                error = f"agent call failed: {type(exc).__name__}: {exc}"
                write_json(round_dir / "agent_result.json", {
                    "success": False, "duration_s": time.monotonic() - agent_started,
                    "error": error, "timed_out": getattr(exc, "timed_out", False),
                    "returncode": getattr(exc, "returncode", None),
                })
                if isinstance(exc, HarnessCommandError):
                    (round_dir / "agent_response.txt").write_text(exc.stdout, encoding="utf-8")
                    (round_dir / "agent_stderr.txt").write_text(exc.stderr, encoding="utf-8")
                break
            (round_dir / "agent_response.txt").write_text(raw)
            result_event = claude_result_event(raw) if harness == "claude-code" else None
            write_json(round_dir / "agent_result.json", {
                "success": True, "duration_s": time.monotonic() - agent_started,
                "session_id": session_id if harness == "opencode" else "",
                "result_type": result_event.get("subtype") if result_event else None,
                "usage": result_event.get("usage") if result_event else None,
                "num_turns": result_event.get("num_turns") if result_event else None,
            })
            patch = candidate_patch(workspace)
            if not patch.strip():
                error = "agent produced an empty patch"
                break
            (round_dir / "candidate.patch").write_text(patch)
            executor = DockerExecutor(task["base_no_test_image_name"], patch, workdir=workdir)
            try:
                report = check_workspace(workspace, task["problem_statement"], patch, model, executor,
                                         output=round_dir / "check", full=True)
            except Exception as exc:
                error = f"security check failed: {type(exc).__name__}: {exc}"
                break
            checked_patch = patch
            rounds.append({"round": number, "verdict": report.verdict,
                           "counterexamples": len(report.counterexamples), "errors": report.errors})
            if report.verdict != "insecure": break
            round_feedback = feedback(report)
            prompt = (claude_repair_prompt(base_prompt, round_feedback)
                      if harness == "claude-code" else round_feedback)
        prediction = {"instance_id": task["instance_id"], "model_name_or_path": model_name,
                      "model_patch": checked_patch or None}
        write_json(output / "prediction.json", prediction)
        write_json(output / "run.json", {"harness": harness, "model": model_name,
                                          "status": "complete" if checked_patch else "incomplete",
                                          "runtime": "container" if containerized else "host-development",
                                          "max_rounds": max_rounds,
                                          "fingerprint": fingerprint,
                                          "rounds": rounds, "error": error})
        return prediction
    finally:
        if runtime is not None:
            runtime.close()
        if keep_workspace:
            retained = output / "workspace"
            if retained.exists(): shutil.rmtree(retained)
            if workspace.exists(): shutil.move(str(workspace), retained)
        shutil.rmtree(scratch, ignore_errors=True)


def run_batch(dataset: Path, output: Path, *, harness: str, model_name: str,
              instance_ids: set[str] | None = None, max_rounds: int = 5,
              command: list[str] | None = None, containerized: bool = True) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    model = None
    predictions = []
    selected = [task for task in load_tasks(dataset)
                if not instance_ids or task["instance_id"] in instance_ids]
    if not selected:
        raise ValueError("no matching SusVibes tasks")

    def checkpoint() -> None:
        write_json(output / "predictions.json", predictions)
        write_json(output / "run_status.json", {
            "status": "complete" if len(predictions) == len(selected)
                      and all(isinstance(item.get("model_patch"), str) and item["model_patch"].strip()
                              for item in predictions) else "incomplete",
            "total_count": len(selected), "completed_count": len(predictions),
            "incomplete_count": sum(not isinstance(item.get("model_patch"), str)
                                    or not item["model_patch"].strip() for item in predictions),
            "harness": harness, "model": model_name,
            "runtime": "container" if containerized else "host-development",
        })

    for task in selected:
        safe = swe_instance_dir(task["instance_id"])
        path = output / safe
        if (path / "prediction.json").exists() and (path / "run.json").exists():
            previous = json.loads((path / "run.json").read_text())
            saved_prediction = json.loads((path / "prediction.json").read_text())
            if (previous.get("status") == "complete" and previous.get("harness") == harness
                    and previous.get("model") == model_name
                    and previous.get("runtime") == ("container" if containerized else "host-development")
                    and previous.get("max_rounds") == max_rounds
                    and previous.get("fingerprint") == _run_fingerprint(task, command)
                    and isinstance(saved_prediction.get("model_patch"), str)
                    and saved_prediction["model_patch"].strip()):
                predictions.append(saved_prediction)
                checkpoint()
                continue
        try:
            if model is None:
                model = ModelClient(model_name)
            predictions.append(run_task(task, harness=harness, model_name=model_name, output=path,
                                        model=model, max_rounds=max_rounds, command=command,
                                        containerized=containerized))
        except Exception as exc:
            path.mkdir(parents=True, exist_ok=True)
            (path / "error.txt").write_text(f"{type(exc).__name__}: {exc}\n")
            predictions.append({"instance_id": task["instance_id"], "model_name_or_path": model_name,
                                "model_patch": None, "error": f"{type(exc).__name__}: {exc}"})
        checkpoint()
    checkpoint()
    return output / "predictions.json"
