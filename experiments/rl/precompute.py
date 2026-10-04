from __future__ import annotations

import argparse
import json
import re
import tempfile
from dataclasses import asdict
from pathlib import Path

import pandas as pd

from av_signal.llm import ModelClient
from av_signal.models import Target
from av_signal.signal import SecuritySignal
from av_signal.targets import select_targets


def extract_code(text: str) -> str:
    matches = re.findall(r"```(?:python)?\s*\n(.*?)```", text, re.S | re.I)
    return (matches[-1] if matches else text).strip()


def public_task(row: dict) -> str:
    prompt = row.get("prompt")
    if isinstance(prompt, (list, tuple)) or hasattr(prompt, "tolist"):
        prompt = prompt.tolist() if hasattr(prompt, "tolist") else prompt
        return "\n".join(str(x.get("content", "")) for x in prompt if isinstance(x, dict))
    return json.dumps(row.get("task_description", {}), ensure_ascii=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train-parquet", type=Path, required=True)
    parser.add_argument("--base-solutions", type=Path)
    parser.add_argument("--base-model")
    parser.add_argument("--attacker-model", default="Qwen/Qwen3-8B")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    base = {}
    if args.base_solutions:
        for line in args.base_solutions.read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            base[str(item["id"])] = extract_code(item["code"])
    elif not args.base_model:
        parser.error("Provide --base-solutions or --base-model")
    base_client = ModelClient(args.base_model) if args.base_model else None
    attacker = SecuritySignal(ModelClient(args.attacker_model), mode="core")
    frame = pd.read_parquet(args.train_parquet)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    pending = args.output.with_suffix(args.output.suffix + ".partial")
    with pending.open("w", encoding="utf-8") as output:
        for _, row in (frame if args.limit is None else frame.head(args.limit)).iterrows():
            data = row.to_dict()
            task_id = str(data["id"])
            task = public_task(data)
            code = base.get(task_id)
            if code is None and base_client:
                code = extract_code(base_client.complete(task, max_tokens=2048))
            if not code:
                raise ValueError(f"No base solution for task {task_id}")
            with tempfile.TemporaryDirectory(prefix="av_base_") as tmp:
                workspace = Path(tmp)
                (workspace / "solution.py").write_text(code, encoding="utf-8")
                targets = select_targets(workspace, ["solution.py"])
                name = str(data.get("task_description", {}).get("function_name", ""))
                targets = [t for t in targets if t.symbol == name] or targets[:1]
                if not targets:
                    raise ValueError(f"No callable target in base solution for task {task_id}")
                probes = {}
                for target in targets:
                    generated = attacker.generate(task, code, target)
                    if len(generated) < attacker.n_min:
                        raise ValueError(f"Too few fixed probes for task {task_id}, target {target.key}")
                    probes[target.key] = [asdict(p) for p in generated]
            output.write(json.dumps({"id": task_id, "probes": probes}, ensure_ascii=False) + "\n")
    pending.replace(args.output)


if __name__ == "__main__":
    main()
