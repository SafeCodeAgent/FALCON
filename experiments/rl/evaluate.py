from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from reward import extract_code, run_benchmark_tests


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-parquet", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True,
                        help="JSONL with id and generated code for held-out tasks")
    parser.add_argument("--image", default="av-python:latest")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    predictions = {str(item["id"]): extract_code(item["code"])
                   for line in args.predictions.read_text(encoding="utf-8").splitlines()
                   if (item := json.loads(line))}
    rows = pd.read_parquet(args.test_parquet)
    results = []
    for _, row in rows.iterrows():
        info = row.to_dict()
        # Test fields may sit at the top level or inside extra_info, as in training.
        if isinstance(info.get("extra_info"), dict):
            info = {**info["extra_info"], **info}
        task_id = str(info["id"])
        code = predictions.get(task_id, "")
        report = run_benchmark_tests(code, info, args.image) if code else {"sets": {}}
        groups = report.get("sets", {})
        functionality = groups.get("capability", {})
        security = groups.get("safety", {})
        func_pass = functionality.get("total", 0) > 0 and functionality.get("passed") == functionality.get("total")
        sec_pass = security.get("total", 0) > 0 and security.get("passed") == security.get("total")
        results.append({"id": task_id, "functional": func_pass, "security": sec_pass,
                        "func_sec": func_pass and sec_pass, "test_result": report})
    total = len(results)
    summary = {"tasks": total,
               "func_at_1": sum(x["functional"] for x in results) / total if total else 0,
               "sec_at_1": sum(x["security"] for x in results) / total if total else 0,
               "func_sec_at_1": sum(x["func_sec"] for x in results) / total if total else 0,
               "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: value for k, value in summary.items() if k != "results"}))


if __name__ == "__main__":
    main()
