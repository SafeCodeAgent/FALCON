from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .executor import AdapterExecutor, DockerExecutor
from .faithfulness import runtime_check, static_check
from .llm import ModelClient, parse_object
from .models import Probe, SignalResult, Target, Verdict
from .prompts import attacker_prompt, judge_prompt
from .targets import select_targets
from .verifier import verify_core


class SecuritySignal:
    def __init__(self, model: ModelClient | None = None, executor: DockerExecutor | None = None,
                 mode: str = "full", n_min: int = 5, n_max: int = 10):
        if mode not in {"core", "full"}:
            raise ValueError("mode must be core or full")
        if not 1 <= n_min <= n_max:
            raise ValueError("probe budget must satisfy 1 <= n_min <= n_max")
        self.model = model
        self.executor = executor or DockerExecutor()
        self.mode = mode
        self.n_min = n_min
        self.n_max = n_max

    def generate(self, task: str, patch: str, target: Target) -> list[Probe]:
        if self.model is None:
            raise ValueError("A model is needed to generate probes")
        prompt = attacker_prompt(task, patch, target, self.n_min, self.n_max,
                                 timeout=self.executor.timeout, memory_mb=self.executor.memory_mb)
        probes: list[Probe] = []
        for attempt in range(2):
            try:
                value = parse_object(self.model.complete(prompt))
                probes, errors = self._parse_probes(value, target)
            except ValueError as exc:
                probes, errors = [], [str(exc)]
            if not errors and len(probes) >= self.n_min:
                return probes
            if len(probes) < self.n_min:
                errors.append(f"returned {len(probes)} valid probes, at least {self.n_min} requested")
            prompt += f"\nValidation errors: {'; '.join(errors)}. Return a corrected complete JSON object."
        # After the one follow-up, keep whatever probes are valid and discard the rest.
        return probes

    def _parse_probes(self, value: dict, target: Target) -> tuple[list[Probe], list[str]]:
        entries = value.get("probes")
        if not isinstance(entries, list):
            return [], ["probes must be a list"]
        probes: list[Probe] = []
        errors: list[str] = []
        seen: set[str] = set()
        for index, item in enumerate(entries[:self.n_max]):
            if not isinstance(item, dict) or not all(isinstance(item.get(k), str) and item[k].strip()
                                                     for k in ("id", "target", "script")):
                errors.append(f"probe {index}: id, target and script must be non-empty strings")
                continue
            if item["id"] in seen:
                errors.append(f"probe {index}: duplicate id {item['id']!r}")
                continue
            seen.add(item["id"])
            probes.append(Probe(item["id"], item["target"], str(item.get("cwe", "")),
                                str(item.get("rationale", "")), item["script"], target.language))
        return probes, errors

    def stage_3_trace_judge(self, task: str, trace) -> Verdict:
        if self.model is None:
            return Verdict("uncertain", "stage_3_llm", "No Stage 3 model configured")
        try:
            result = parse_object(self.model.complete(judge_prompt(task, trace), max_tokens=800))
            if result.get("verdict") not in {"secure", "insecure"}:
                raise ValueError("invalid verdict")
            return Verdict(result["verdict"], "stage_3_llm", str(result.get("reason", "")),
                           str(result.get("evidence", "")))
        except (ValueError, KeyError, TypeError):
            return Verdict("uncertain", "stage_3_llm", "Stage 3 response could not be parsed")

    def evaluate(self, task: str, workspace: Path, changed_paths: list[str],
                 fixed_probes: dict[str, list[Probe]] | None = None) -> SignalResult:
        targets = select_targets(workspace, changed_paths)
        admitted = 0
        counterexamples = []
        records = []
        patch = "\n".join(f"{t.key}\n{t.source}" for t in targets)[:40000]
        for target in targets:
            probes = fixed_probes.get(target.key, []) if fixed_probes is not None else self.generate(task, patch, target)
            for probe in probes:
                record = {"probe_id": probe.id, "target": target.key, "cwe": probe.cwe}
                valid, reason = static_check(probe, target)
                if not valid:
                    record.update(status="rejected_static", reason=reason)
                    records.append(record)
                    continue
                try:
                    trace = self.executor.run(workspace, target, probe)
                except (RuntimeError, OSError, ValueError) as exc:
                    record.update(status="execution_error", reason=str(exc))
                    records.append(record)
                    continue
                valid, reason = runtime_check(trace, target)
                if not valid:
                    record.update(status="rejected_runtime", reason=reason, trace=trace.to_dict())
                    records.append(record)
                    continue
                verdict = verify_core(trace)
                if verdict.status == "uncertain" and self.mode == "full":
                    verdict = self.stage_3_trace_judge(task, trace)
                record.update(status="admitted", verdict=asdict(verdict), trace=trace.to_dict())
                records.append(record)
                admitted += 1
                if verdict.status == "insecure":
                    counterexamples.append({"probe": asdict(probe), "trace": trace.to_dict(),
                                            "reason": verdict.reason, "stage": verdict.stage,
                                            "detector": verdict.detector})
        status = "insecure" if counterexamples else "secure" if admitted else "no-evidence"
        return SignalResult(status, admitted, counterexamples, records)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-file", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--changed", nargs="+", required=True)
    parser.add_argument("--model")
    parser.add_argument("--image", default="av-python:latest")
    parser.add_argument("--mode", choices=("core", "full"), default="full")
    parser.add_argument("--min-probes", type=int, default=5)
    parser.add_argument("--max-probes", type=int, default=10)
    parser.add_argument("--probes", type=Path)
    parser.add_argument("--adapter-command", help="trusted sandbox adapter for non-Python targets")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.mode == "full" and not args.model:
        parser.error("--model is required for full verification")
    model = ModelClient(args.model) if args.model else None
    fixed = None
    if args.probes:
        data = json.loads(args.probes.read_text(encoding="utf-8"))
        fixed = {key: [Probe(**item) for item in items] for key, items in data.items()}
    executor = AdapterExecutor(args.adapter_command) if args.adapter_command else DockerExecutor(image=args.image)
    signal = SecuritySignal(model, executor=executor, mode=args.mode,
                            n_min=args.min_probes, n_max=args.max_probes)
    result = signal.evaluate(args.task_file.read_text(), args.workspace, args.changed, fixed)
    output = json.dumps(result.to_dict(), indent=2, default=str)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
