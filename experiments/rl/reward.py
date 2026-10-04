from __future__ import annotations

import ast
import functools
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from av_signal.executor import DockerExecutor
from av_signal.models import Probe
from av_signal.signal import SecuritySignal
from proxies import real_reward, seccodeprm_reward

REWARD_SETTINGS = ("av", "real", "seccodeprm", "av+real", "av+seccodeprm", "real+seccodeprm")
CODE_BLOCK = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.S | re.I)
# VeRL decodes prompt and response together. Score only the response, so a code
# block quoted in the prompt is never mistaken for the policy's answer.
ASSISTANT_MARKERS = ("<|im_start|>assistant",)


def response_text(sequence: str) -> str:
    for marker in ASSISTANT_MARKERS:
        if marker in sequence:
            return sequence.rsplit(marker, 1)[1]
    return sequence


def extract_code(text: str) -> str:
    blocks = CODE_BLOCK.findall(text)
    return (blocks[-1] if blocks else text).strip()


def capability_only_tests(source: str) -> str:
    tree = ast.parse(source)
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id == "testcases" for x in node.targets):
            if not isinstance(node.value, ast.Dict):
                raise ValueError("testcases must be a dictionary literal")
            kept = [(key, value) for key, value in zip(node.value.keys, node.value.values)
                    if isinstance(key, ast.Constant) and key.value == "capability"]
            node.value.keys = [key for key, _ in kept]
            node.value.values = [value for _, value in kept]
            found = True
    if not found:
        raise ValueError("capability testcases not found")
    return ast.unparse(tree)


def run_benchmark_tests(code: str, info: dict[str, Any], image: str,
                        capability_only: bool = False, timeout: int = 30) -> dict:
    unittest = info.get("unittest") or {}
    task = info.get("task_description") or {}
    if not unittest or not task.get("function_name"):
        raise ValueError("Missing functionality test fields")
    testcases = unittest["testcases"]
    if capability_only:
        testcases = capability_only_tests(testcases)
    with tempfile.TemporaryDirectory(prefix="av_func_", ignore_cleanup_errors=True) as temp:
        folder = Path(temp)
        (folder / "input.json").write_text(json.dumps({"setup": unittest.get("setup", ""),
            "testcases": testcases, "function_name": task["function_name"],
            "code": code}, default=str), encoding="utf-8")
        runner = Path(__file__).with_name("func_runner.py")
        cidfile = folder / "container.cid"
        command = ["docker", "run", "--rm", "--cidfile", str(cidfile), "--network", "none",
                   "--pids-limit", "64", "--memory", "512m", "--cpus", "1", "--read-only",
                   "--tmpfs", "/tmp:size=64m",
                   "-v", f"{folder}:/work:ro", "-v", f"{runner}:/opt/func_runner.py:ro",
                   "-w", "/work", image, "python", "/opt/func_runner.py"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            if cidfile.exists():
                subprocess.run(["docker", "rm", "-f", cidfile.read_text().strip()], capture_output=True)
            return {"sets": {}, "error": f"functionality sandbox timed out after {timeout}s"}
    for line in reversed(result.stdout.splitlines()):
        if line.startswith("AV_FUNC:"):
            return json.loads(line[len("AV_FUNC:"):])
    raise RuntimeError(f"Functionality sandbox produced no result: {result.stderr[-1000:]}")


def _functionality(code: str, info: dict[str, Any], image: str) -> float:
    record = run_benchmark_tests(code, info, image, capability_only=True)
    capability = record.get("sets", {}).get("capability", {})
    total = capability.get("total", 0)
    return capability.get("passed", 0) / total if total else 0.0


@functools.lru_cache(maxsize=4)
def _probe_index(path: str) -> dict[str, dict[str, list[Probe]]]:
    index = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            index[str(item.get("id"))] = {key: [Probe(**entry) for entry in probes]
                                          for key, probes in item.get("probes", {}).items()}
    return index


def _fixed_probes(task_id: str, path: Path) -> dict[str, list[Probe]]:
    index = _probe_index(str(path.resolve()))
    if task_id not in index:
        raise KeyError(f"No fixed probes for task {task_id} in {path}")
    return index[task_id]


def score_components(solution_str: str, extra_info: dict, probe_file: Path,
                     image: str = "av-python:latest") -> dict[str, float | str]:
    code = extract_code(solution_str)
    if not code:
        return {"functionality": 0.0, "av": 1.0, "signal_status": "no-evidence"}
    task_id = str(extra_info.get("id") or extra_info.get("task_id"))
    fixed = _fixed_probes(task_id, probe_file)
    with tempfile.TemporaryDirectory(prefix="av_rl_", ignore_cleanup_errors=True) as temp:
        workspace = Path(temp)
        (workspace / "solution.py").write_text(code, encoding="utf-8")
        task = json.dumps(extra_info.get("task_description", {}), ensure_ascii=False)
        result = SecuritySignal(None, DockerExecutor(image=image), mode="core").evaluate(
            task, workspace, ["solution.py"], fixed)
    failures = [record for record in result.probes if record.get("status") == "execution_error"]
    if failures:
        raise RuntimeError(f"Probe sandbox failed for task {task_id}: {failures[0]['reason']}")
    func = _functionality(code, extra_info, image)
    return {"functionality": func, "av": result.rl_security_reward,
            "signal_status": result.status}


def compute_score(data_source: str, solution_str: str, ground_truth=None,
                  extra_info=None, config=None, reward_setting=None,
                  eval_mode: bool = False):
    """Adapter for VeRL's run_ppo(compute_score=...) callback.

    Returns ``[total, functionality, 0.0, security]`` as the vendored reward
    manager expects. A response without a fenced code block gets -1.
    """
    response = response_text(solution_str)
    if not CODE_BLOCK.search(response):
        return [-1.0, 0.0, 0.0, 1.0]
    info = dict(extra_info or {})
    image = os.environ.get("AV_RL_IMAGE", "av-python:latest")
    setting = os.environ.get("AV_REWARD", "av")
    if setting not in REWARD_SETTINGS:
        raise ValueError(f"Unsupported reward setting: {setting}")
    terms = setting.split("+")
    code = extract_code(response)
    if "av" in terms:
        components = score_components(response, info, Path(os.environ["AV_PROBE_FILE"]), image)
        func = float(components["functionality"])
        av_security = float(components["av"])
    else:
        func = _functionality(code, info, image)
        av_security = 0.0
    parts = []
    for name in terms:
        if name == "av":
            parts.append(av_security)
        elif name == "real":
            parts.append(real_reward(code))
        else:
            parts.append(seccodeprm_reward(code))
    security = sum(parts) / len(parts)
    weight = float(os.environ.get("AV_SECURITY_WEIGHT", "0.5"))
    total = (1 - weight) * func + weight * security
    return [total, func, 0.0, security]
