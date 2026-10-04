from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from evaluation_harness.swe_agent.runner import run_batch as run_swe_agent_batch

from .benchmark import run_batch
from .engine import check_workspace
from .execution import DockerExecutor, LocalExecutor
from .model_api import ModelClient
from .paths import vendor_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="av-susvibes")
    sub = p.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("check", help="Check one candidate patch")
    check.add_argument("--repo", type=Path, required=True)
    check.add_argument("--patch", type=Path, required=True)
    check.add_argument("--task", type=Path, required=True, help="public task statement text file")
    check.add_argument("--image", help="SusVibes no-test image; required unless --local-development")
    check.add_argument("--model", required=True)
    check.add_argument("--output", type=Path, required=True)
    check.add_argument("--local-development", action="store_true")
    check.add_argument("--core", action="store_true", help="stop after deterministic verifier")
    check.add_argument("--min-probes", type=int, default=5)
    check.add_argument("--max-probes", type=int, default=10)
    batch = sub.add_parser("run-batch", help="Run Claude Code or OpenCode repair on no-test images")
    batch.add_argument("--dataset", type=Path, required=True)
    batch.add_argument("--output", type=Path, required=True)
    batch.add_argument("--harness", choices=["claude-code", "opencode"], required=True)
    batch.add_argument("--model", required=True)
    batch.add_argument("--instance-id", action="append")
    batch.add_argument("--max-rounds", type=int, default=5)
    batch.add_argument("--host-agent", action="store_true",
                       help="development only: run coding CLI on host instead of task container")
    batch.add_argument("--agent-command", nargs="+", help="override command; placeholders: {model}, {prompt}, {workspace}, {session_id}")
    swe = sub.add_parser("swe-agent", help="Launch SWE-agent with the security check at submission")
    swe.add_argument("--dataset", type=Path, required=True)
    swe.add_argument("--output", type=Path, required=True)
    swe.add_argument("--model", required=True)
    swe.add_argument("--max-rounds", type=int, default=5)
    swe.add_argument("--instance-id", action="append")
    swe.add_argument("--num-workers", type=int, default=1)
    swe.add_argument("command", nargs=argparse.REMAINDER,
                     help="optional SWE-agent command after --; {instances} is replaced")
    grade = sub.add_parser("grade", help="Run the upstream SusVibes held-out evaluator")
    grade.add_argument("--dataset", type=Path, required=True, help="official SusVibes JSONL; available only at grading")
    grade.add_argument("--predictions", type=Path, required=True)
    grade.add_argument("--run-id", required=True)
    grade.add_argument("--dataset-id", default="default")
    grade.add_argument("--max-workers", type=int, default=5)
    grade.add_argument("--eval-output", type=Path, default=Path("runs/grades"))
    args = p.parse_args(argv)
    if args.cmd == "check":
        if not args.local_development and not args.image: p.error("--image is required for benchmark checks")
        patch = args.patch.read_text(encoding="utf-8")
        executor = LocalExecutor(args.repo) if args.local_development else DockerExecutor(args.image, patch)
        report = check_workspace(args.repo, args.task.read_text(encoding="utf-8"), patch,
                                 ModelClient(args.model), executor, output=args.output,
                                 minimum=args.min_probes, maximum=args.max_probes, full=not args.core)
        print(json.dumps({"verdict": report.verdict, "counterexamples": len(report.counterexamples),
                          "records": len(report.records), "errors": report.errors}, indent=2))
        return 0 if not report.errors else 2
    if args.cmd == "run-batch":
        result = run_batch(args.dataset, args.output, harness=args.harness, model_name=args.model,
                           instance_ids=set(args.instance_id) if args.instance_id else None,
                           max_rounds=args.max_rounds, command=args.agent_command,
                           containerized=not args.host_agent)
        print(result)
        return 0
    if args.cmd == "swe-agent":
        if args.num_workers < 1: p.error("--num-workers must be positive")
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        result, predictions = run_swe_agent_batch(args.dataset, args.output, args.model,
                                                   max_rounds=args.max_rounds,
                                                   instance_ids=set(args.instance_id) if args.instance_id else None,
                                                   num_workers=args.num_workers,
                                                   command=command)
        print(predictions)
        return result
    if args.cmd == "grade":
        dataset = args.dataset.resolve()
        if not dataset.is_file(): p.error(f"dataset does not exist: {dataset}")
        vendor = vendor_path("susvibes")
        with tempfile.TemporaryDirectory(prefix="av-grade-") as tmp:
            dataset_dir = Path(tmp) / args.dataset_id
            dataset_dir.mkdir(parents=True)
            (dataset_dir / "susvibes_dataset.jsonl").symlink_to(dataset)
            env = os.environ.copy()
            env["PYTHONPATH"] = os.pathsep.join([str(vendor), env.get("PYTHONPATH", "")])
            env["SUSVIBES_DATASETS_DIR"] = tmp
            env["SUSVIBES_EVAL_LOG_DIR"] = str(args.eval_output.resolve())
            command = [sys.executable, "-m", "susvibes.eval.core", "--predictions_path",
                       str(args.predictions.resolve()), "--run_id", args.run_id,
                       "--dataset_id", args.dataset_id, "--max_workers", str(args.max_workers)]
            return subprocess.call(command, env=env)
    return 1


if __name__ == "__main__": raise SystemExit(main())
