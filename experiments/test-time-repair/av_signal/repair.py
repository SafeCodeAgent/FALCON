from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from .benchmarks import prepare_cweval, prepare_seccodebench, write_manifest
from .executor import AdapterExecutor, DockerExecutor
from .llm import ModelClient, parse_object
from .signal import SecuritySignal


def _files(workspace: Path, paths: list[str]) -> dict[str, str]:
    return {name: (workspace / name).read_text(encoding="utf-8", errors="replace")
            for name in paths}


def _edit_prompt(task: str, files: dict[str, str], feedback: str) -> str:
    return f"""Implement or repair the code for the public task. Preserve functionality and the required public interface. You may edit only the listed files. Return exactly one JSON object {{"files": {{"relative/path": "complete new file content"}}}}. Include every listed file, even if unchanged. No Markdown.

Public task:\n{task[:14000]}
Current files:\n{json.dumps(files, ensure_ascii=False)[:40000]}
Security counterexample from the last check, if any:\n{feedback[:16000]}
The benchmark task may specify a different response format. Use only the JSON files object requested above."""


def _apply_model_edit(model: ModelClient, task: str, workspace: Path,
                      paths: list[str], feedback: str) -> bool:
    prompt = _edit_prompt(task, _files(workspace, paths), feedback)
    allowed = set(paths)
    for attempt in range(2):
        try:
            result = parse_object(model.complete(prompt, max_tokens=8192))
            files = result["files"]
            if not isinstance(files, dict) or set(files) != allowed or not all(isinstance(v, str) for v in files.values()):
                raise ValueError("response must contain all and only editable files")
            for name, content in files.items():
                (workspace / name).write_text(content, encoding="utf-8")
            return True
        except (ValueError, KeyError, TypeError) as exc:
            prompt += f"\nInvalid response: {exc}. Return corrected JSON."
    return False


def run_case(entry: dict, model: ModelClient, output: Path, image: str,
             rounds: int = 5, adapter_command: str | None = None,
             n_min: int = 5, n_max: int = 10) -> dict:
    if entry.get("language") not in {None, "python"} and not adapter_command:
        raise RuntimeError(f"A trusted trace adapter is required for {entry['language']} targets")
    workspace = Path(entry["workspace"])
    paths = entry["changed_paths"]
    case_output = (output / "runs" / str(entry["benchmark"])
                   / str(entry.get("language", "mixed")) / str(entry["id"])
                   / str(entry.get("scenario", "default")))
    case_output.mkdir(parents=True, exist_ok=True)
    history = []
    if not _apply_model_edit(model, entry["task"], workspace, paths, ""):
        return {"id": entry["id"], "error": "initial generation failed", "rounds": []}
    executor = AdapterExecutor(adapter_command) if adapter_command else DockerExecutor(image=image)
    signal = SecuritySignal(model, executor, mode="full", n_min=n_min, n_max=n_max)
    for round_index in range(1, rounds + 1):
        result = signal.evaluate(entry["task"], workspace, paths)
        if any(p["status"] == "execution_error" for p in result.probes):
            raise RuntimeError(f"Probe execution failed for {entry['id']}; inspect the sandbox or adapter")
        snapshot = case_output / f"round_{round_index}"
        for name in paths:
            destination = snapshot / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(workspace / name, destination)
        record = {"round": round_index, "signal": result.to_dict(), "files": str(snapshot)}
        history.append(record)
        (case_output / "history.json").write_text(json.dumps(history, indent=2, default=str), encoding="utf-8")
        if result.status != "insecure" or round_index == rounds:
            break
        example = result.counterexamples[0]
        feedback = json.dumps({"probe": example["probe"], "trace": example["trace"],
                               "reason": example["reason"]}, default=str)
        if not _apply_model_edit(model, entry["task"], workspace, paths, feedback):
            break
    return {"id": entry["id"], "rounds": history, "final_status": history[-1]["signal"]["status"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--benchmark", choices=("cweval", "seccodebench-v2"), required=True)
    prepare.add_argument("--benchmark-root", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--scenario", default="gen")
    prepare.add_argument("--language")
    prepare.add_argument("--limit", type=int)
    prepare.add_argument("--prompt-map", type=Path)
    run = sub.add_parser("run")
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--model", required=True)
    run.add_argument("--image", default="av-python:latest")
    run.add_argument("--limit", type=int)
    run.add_argument("--adapter-command")
    run.add_argument("--rounds", type=int, default=5, help="maximum number of security checks")
    run.add_argument("--min-probes", type=int, default=5)
    run.add_argument("--max-probes", type=int, default=10)
    args = parser.parse_args()
    if args.command == "prepare":
        args.output.mkdir(parents=True, exist_ok=True)
        entries = (prepare_cweval(args.benchmark_root, args.output, args.limit, args.language)
                   if args.benchmark == "cweval" else
                   prepare_seccodebench(args.benchmark_root, args.output, args.scenario,
                                        args.limit, args.prompt_map, args.language))
        print(write_manifest(entries, args.output))
        return
    model = ModelClient(args.model)
    entries = [json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    for entry in entries[:args.limit]:
        result = run_case(entry, model, args.output, args.image, rounds=args.rounds,
                          adapter_command=args.adapter_command,
                          n_min=args.min_probes, n_max=args.max_probes)
        print(json.dumps({"id": result["id"], "status": result.get("final_status", result.get("error"))}))


if __name__ == "__main__":
    main()
