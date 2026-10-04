"""Algorithm 1 for one candidate workspace and patch."""
from __future__ import annotations

import ast
import json
from dataclasses import asdict
from pathlib import Path
from typing import Protocol

from .faithfulness import runtime_reasons, static_reasons
from .models import CheckReport, Probe, ProbeRecord, Target
from .prompts import attacker_prompt, judge_prompt
from .targets import public_patch, select_targets
from .verifier import verify_stage_1, verify_stage_2, verify_stage_3


class Model(Protocol):
    def complete(self, prompt: str) -> tuple[dict, str, dict]: ...


class Executor(Protocol):
    def run(self, probe: Probe, target: Target): ...


def parse_probes(value: dict, target: Target, maximum: int) -> tuple[list[Probe], list[str]]:
    errors = []
    probes = []
    seen = set()
    if not isinstance(value.get("coverage"), list): errors.append("missing coverage list")
    entries = value.get("probes")
    if not isinstance(entries, list): return [], errors + ["missing probes list"]
    for index, item in enumerate(entries[:maximum]):
        if not isinstance(item, dict): errors.append(f"probe {index}: not an object"); continue
        if any(not isinstance(item.get(k), str) or not item[k].strip() for k in ("id", "target", "script", "rationale", "cwe")):
            errors.append(f"probe {index}: missing required string"); continue
        if item["target"] != target.canonical:
            errors.append(f"probe {index}: target is not {target.canonical}"); continue
        if item["id"] in seen:
            errors.append(f"probe {index}: duplicate id"); continue
        try: tree = ast.parse(item["script"])
        except SyntaxError as exc: errors.append(f"probe {index}: syntax error at line {exc.lineno}"); continue
        if any(isinstance(n, ast.Assert) for n in ast.walk(tree)):
            errors.append(f"probe {index}: asserts an expected outcome"); continue
        if any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and isinstance(n.func.value, ast.Name) and (
                   n.func.value.id in {"random", "secrets", "uuid"} or
                   n.func.value.id == "time" and n.func.attr in {"time", "monotonic", "perf_counter"} or
                   n.func.value.id == "datetime" and n.func.attr in {"now", "utcnow"})
               for n in ast.walk(tree)):
            errors.append(f"probe {index}: uses a nondeterministic source"); continue
        seen.add(item["id"])
        probes.append(Probe(item["id"], item["target"], item["cwe"], item["rationale"], item["script"]))
    if len(entries) > maximum: errors.append(f"truncated probes to maximum {maximum}")
    return probes, errors


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")


def check_workspace(repo: Path, task: str, patch: str, model: Model, executor: Executor,
                    *, output: Path | None = None, minimum: int = 5, maximum: int = 10,
                    full: bool = True, timeout_s: int = 20, memory_mb: int = 2048) -> CheckReport:
    if minimum < 1 or maximum < minimum: raise ValueError("invalid probe budget")
    targets = select_targets(repo, patch)
    records: list[ProbeRecord] = []
    errors: list[str] = []
    try:
        python_version = executor.python_version() if hasattr(executor, "python_version") else "Python"
    except Exception as exc:
        python_version = "Python (version unavailable)"
        errors.append(f"could not inspect task interpreter: {type(exc).__name__}: {exc}")
    if output:
        output.mkdir(parents=True, exist_ok=True)
        (output / "candidate.patch").write_text(patch, encoding="utf-8")
        _write_json(output / "targets.json", [asdict(t) for t in targets])
    for target_index, target in enumerate(targets):
        target_dir = output / f"target_{target_index:03d}" if output else None
        prompt = attacker_prompt(task, public_patch(patch), target, minimum=minimum, maximum=maximum,
                                 timeout_s=timeout_s, memory_mb=memory_mb,
                                 python_version=python_version)
        if target_dir: (target_dir / "attacker_prompt.txt").parent.mkdir(parents=True, exist_ok=True); (target_dir / "attacker_prompt.txt").write_text(prompt)
        probes: list[Probe] = []
        for attempt in range(2):
            try:
                response, raw, usage = model.complete(prompt)
                candidate, validation_errors = parse_probes(response, target, maximum)
                if target_dir:
                    (target_dir / f"attacker_response_{attempt}.txt").write_text(raw)
                    _write_json(target_dir / f"attacker_usage_{attempt}.json", usage)
                probes = candidate
                if not validation_errors and len(probes) >= minimum: break
                issue = "; ".join(validation_errors + ([f"generated {len(probes)}, requested at least {minimum}"] if len(probes) < minimum else []))
                errors.append(f"{target.canonical}: {issue}")
                prompt += "\n\nValidation feedback: " + issue + ". Return a corrected JSON object once."
            except Exception as exc:
                errors.append(f"{target.canonical}: attacker call failed: {type(exc).__name__}: {exc}")
                break
        def process_probe(probe: Probe, probe_index: int) -> ProbeRecord:
            record = ProbeRecord(probe)
            records.append(record)
            probe_dir = target_dir / f"probe_{probe_index:03d}" if target_dir else None
            if probe_dir:
                probe_dir.mkdir(parents=True, exist_ok=True)
                (probe_dir / "probe.py").write_text(probe.script)
            record.static_reasons = static_reasons(probe, target, path=f"probes/{probe.id}.py")
            if record.static_reasons:
                if probe_dir: _write_json(probe_dir / "record.json", asdict(record))
                return record
            try: record.trace = executor.run(probe, target)
            except Exception as exc:
                errors.append(f"{probe.id}: execution failed: {type(exc).__name__}: {exc}")
                return record
            record.runtime_reasons = runtime_reasons(record.trace, target)
            if record.runtime_reasons:
                if probe_dir: _write_json(probe_dir / "record.json", asdict(record))
                return record
            # Stage 1 runs first; only traces without a crash reach Stage 2.
            record.decision = verify_stage_1(record.trace) or verify_stage_2(record.trace, task)
            if full and record.decision.verdict == "uncertain":
                # Stage 3 runs only when the deterministic stages are inconclusive.
                jprompt = judge_prompt(task, record.trace)
                if probe_dir: (probe_dir / "judge_prompt.txt").write_text(jprompt)
                try:
                    record.decision, raw, usage = verify_stage_3(record.trace, task, model, prompt=jprompt)
                    if probe_dir:
                        (probe_dir / "judge_response.txt").write_text(raw)
                        _write_json(probe_dir / "judge_usage.json", usage)
                except Exception as exc:
                    errors.append(f"{probe.id}: judge call failed: {type(exc).__name__}: {exc}")
            if probe_dir: _write_json(probe_dir / "record.json", asdict(record))
            return record

        initial_records = [process_probe(probe, index) for index, probe in enumerate(probes)]
        failed = [r for r in initial_records if r.trace and
                  ("target_frame_missing" in r.runtime_reasons or r.trace.harness_error)]
        if failed:
            runtime_feedback = json.dumps([{"id": r.probe.id,
                                            "runtime_reasons": r.runtime_reasons,
                                            "harness_error": r.trace.harness_error if r.trace else "",
                                            "stderr": r.trace.stderr[-1500:] if r.trace else ""}
                                           for r in failed], ensure_ascii=False)
            retry_prompt = attacker_prompt(task, public_patch(patch), target,
                                           minimum=1, maximum=min(maximum, len(failed)),
                                           timeout_s=timeout_s, memory_mb=memory_mb,
                                           python_version=python_version,
                                           runtime_feedback=runtime_feedback)
            if target_dir: (target_dir / "attacker_runtime_prompt.txt").write_text(retry_prompt)
            try:
                answer, raw, usage = model.complete(retry_prompt)
                replacements, validation_errors = parse_probes(answer, target, len(failed))
                if target_dir:
                    (target_dir / "attacker_runtime_response.txt").write_text(raw)
                    _write_json(target_dir / "attacker_runtime_usage.json", usage)
                if validation_errors:
                    errors.append(f"{target.canonical}: runtime retry validation: {'; '.join(validation_errors)}")
                for offset, probe in enumerate(replacements):
                    process_probe(probe, len(probes) + offset)
            except Exception as exc:
                errors.append(f"{target.canonical}: runtime retry failed: {type(exc).__name__}: {exc}")
    if any(r.admitted and r.decision and r.decision.verdict == "insecure" for r in records):
        verdict = "insecure"
    elif any(r.admitted and r.decision and r.decision.verdict == "secure" for r in records):
        verdict = "secure"
    else:
        verdict = "no-evidence"
    report = CheckReport(verdict, records, errors)
    if output: _write_json(output / "report.json", report.to_dict())
    return report


def feedback(report: CheckReport, *, limit: int = 3) -> str:
    examples = report.counterexamples[:limit]
    if not examples: return ""
    text = ["The security check observed the following violations in the current patch. Repair them and preserve the task's functionality."]
    for item in examples:
        text.append(json.dumps({"probe_id": item.probe.id, "target": item.probe.target,
                                "reason": item.decision.reason if item.decision else "",
                                "input_script": item.probe.script,
                                "trace": item.trace.for_judge() if item.trace else {}}, ensure_ascii=False, default=str)[:18000])
    return "\n\n".join(text)
