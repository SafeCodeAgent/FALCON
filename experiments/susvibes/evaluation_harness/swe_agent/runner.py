"""Launch SWE-agent on public no-test SusVibes instances with per-task limits."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from evaluation_harness.network_isolation import PublishedPortNoEgressNetwork
from av_susvibes.benchmark import (
    collect_swe_predictions, swe_agent_instances, swe_instance_dir,
)
from av_susvibes.paths import vendor_path


def run_batch(dataset: Path, output: Path, model: str, *, max_rounds: int = 5,
              instance_ids: set[str] | None = None, num_workers: int = 1,
              command: list[str] | None = None) -> tuple[int, Path]:
    if num_workers < 1 or max_rounds < 1:
        raise ValueError("num_workers and max_rounds must be positive")
    output.mkdir(parents=True, exist_ok=True)
    instances = swe_agent_instances(dataset, output / "swe_instances.json", instance_ids)
    package = Path(__file__).resolve().parents[2] / "av_susvibes"
    root = package.parent
    vendor = vendor_path("swe-agent")
    env = os.environ.copy()
    env.update(AV_SWE_DATASET=str(dataset.resolve()), AV_SWE_MODEL=model,
               AV_SWE_OUTPUT=str(output.resolve()), AV_SWE_ROUNDS=str(max_rounds),
               SWE_AGENT_TRAJECTORY_DIR=str(output.resolve()),
               PYTHONPATH=os.pathsep.join([str(package / "bootstrap"), str(root), str(vendor),
                                           env.get("PYTHONPATH", "")]))
    if command:
        resolved = [part.replace("{instances}", str(instances.resolve())).replace(
            "{output}", str((output / "trajectories").resolve())) for part in command]
        result = subprocess.call(resolved, env=env)
    else:
        all_instances = json.loads(instances.read_text(encoding="utf-8"))

        def run_one(instance: dict) -> int:
            instance_id = instance["problem_statement"]["id"]
            name = swe_instance_dir(instance_id)
            instance_file = output / "task_instances" / (name + ".json")
            instance_file.parent.mkdir(parents=True, exist_ok=True)
            trajectory_dir = output / "trajectories" / name
            trajectory_dir.mkdir(parents=True, exist_ok=True)
            network = PublishedPortNoEgressNetwork(name)
            with (trajectory_dir / "harness.log").open("w", encoding="utf-8") as log:
                try:
                    network_name = network.create()
                    isolated = json.loads(json.dumps(instance))
                    isolated["env"]["deployment"]["docker_args"].insert(0, f"--network={network_name}")
                    instance_file.write_text(json.dumps([isolated], indent=2) + "\n", encoding="utf-8")
                    run_command = [sys.executable, "-m", "sweagent.run.run", "run-batch",
                                   "--config", str(vendor / "config" / "default.yaml"),
                                   "--agent.model.name", model,
                                   "--agent.model.per_instance_call_limit", "200",
                                   "--instances.type", "expert_file", "--instances.path", str(instance_file.resolve()),
                                   "--output_dir", str(trajectory_dir.resolve()), "--num_workers", "1"]
                    process = subprocess.Popen(run_command, env=env, stdout=log,
                                               stderr=subprocess.STDOUT, start_new_session=True)
                    try:
                        return process.wait(timeout=1800)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                        log.write("\nharness: 1800-second SWE-agent task timeout\n")
                        return 124
                except Exception as exc:
                    log.write(f"harness: SWE-agent launch failed: {exc}\n")
                    return 1
                finally:
                    network.close()

        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            codes = list(pool.map(run_one, all_instances))
        result = 0 if all(code == 0 for code in codes) else 1
    predictions = collect_swe_predictions(dataset, output / "trajectories",
                                          output / "predictions.json", model,
                                          instance_ids, process_returncode=result)
    return result, predictions
