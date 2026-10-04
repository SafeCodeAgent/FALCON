from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx

SERVICE_PORTS = {"c-verifier": 24683, "python-verifier": 24684,
                 "go-verifier": 24685, "nodejs-verifier": 24686,
                 "java-verifier": 24687}


def _cweval(entry: dict, root: Path, image: str) -> dict:
    source = root / "benchmark" / entry["source_task"]
    test_name = source.stem.removesuffix("_task") + "_test.py"
    test_source = source.with_name(test_name)
    if not test_source.is_file():
        raise FileNotFoundError(test_source)
    candidate = (Path(entry["workspace"]) / entry["changed_paths"][0]).read_text(encoding="utf-8")
    if source.suffix in {".c", ".cpp", ".go"} and "main(" not in candidate and "BEGIN ENTRYPOINT" in source.read_text():
        candidate += "\n" + source.read_text().split("BEGIN ENTRYPOINT", 1)[1]
    with tempfile.TemporaryDirectory(prefix="av_heldout_", ignore_cleanup_errors=True) as temp:
        staged = Path(temp) / "case" / Path(entry["source_task"]).parent
        staged.mkdir(parents=True)
        for item in source.parent.rglob("*"):
            if not item.is_file() or "compiled" in item.parts:
                continue
            if "_task." in item.name or "_test." in item.name:
                continue
            destination = staged / item.relative_to(source.parent)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, destination)
        shutil.copy2(test_source, staged / test_name)
        (staged / source.name).write_text(candidate, encoding="utf-8")
        runner = Path(__file__).with_name("heldout_runner.py")
        cidfile = Path(temp) / "container.cid"
        command = ["docker", "run", "--rm", "--cidfile", str(cidfile), "--network", "none", "--memory", "2g",
                   "--pids-limit", "128", "-v", f"{Path(temp) / 'case'}:/case:rw",
                   "-v", f"{root.resolve()}:/benchmark_source:ro",
                   "-v", f"{runner}:/opt/av/heldout_runner.py:ro",
                   "-e", "PYTHONPATH=/benchmark_source:/case",
                   "-e", f"AV_CASE_DIR=/case/{Path(entry['source_task']).parent}",
                   "-e", f"AV_TEST_FILE={test_name}", "-e", f"AV_TASK_FILE={source.name}",
                   image, "python", "/opt/av/heldout_runner.py"]
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
        except subprocess.TimeoutExpired:
            if cidfile.exists():
                subprocess.run(["docker", "rm", "-f", cidfile.read_text().strip()], capture_output=True)
            raise
    for line in reversed(done.stdout.splitlines()):
        if line.startswith("AV_HELDOUT:"):
            return json.loads(line.removeprefix("AV_HELDOUT:"))
    return {"functional": False, "security": False,
            "error": (done.stderr or done.stdout)[-2000:]}


def _seccodebench(entry: dict, root: Path) -> dict:
    catalog = root / "datasets" / entry["catalog"]
    case = json.loads(catalog.read_text(encoding="utf-8"))[entry["id"]]
    url = case["verify_urls"][entry["scenario"]]
    parsed = urlparse(url)
    if parsed.hostname in SERVICE_PORTS:
        url = urlunparse((parsed.scheme, f"127.0.0.1:{SERVICE_PORTS[parsed.hostname]}",
                          parsed.path, parsed.params, parsed.query, parsed.fragment))
    changed = entry["changed_paths"]
    if len(changed) != 1:
        raise ValueError("Remote verifier expects one target file")
    code = (Path(entry["workspace"]) / changed[0]).read_text(encoding="utf-8")
    payload = {"token": "local-eval-token", "code": code,
               "prompt_path": case.get("remote_prompt_paths", {}).get(entry["scenario"])}
    response = httpx.post(url, json=payload, timeout=300)
    response.raise_for_status()
    report = response.json().get("test_result", {})
    result = {}
    for name, group in (("functional", "functional_result"), ("security", "security_result")):
        tests = report.get(group, {})
        result[name] = (tests.get("total_tests", 0) > 0 and tests.get("total_failures", 0) == 0
                        and tests.get("total_errors", 0) == 0 and tests.get("total_skipped", 0) == 0)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--benchmark-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cweval-image", default="cweval-runtime:latest")
    args = parser.parse_args()
    entries = [json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line]
    results = []
    for entry in entries:
        try:
            grade = (_cweval(entry, args.benchmark_root, args.cweval_image)
                     if entry["benchmark"] == "cweval" else _seccodebench(entry, args.benchmark_root))
        except Exception as exc:
            grade = {"functional": False, "security": False, "error": str(exc)}
        results.append({"id": entry["id"], "benchmark": entry["benchmark"],
                        "language": entry.get("language"), "scenario": entry.get("scenario"),
                        **grade, "func_sec": grade["functional"] and grade["security"]})
    total = len(results)
    summary = {"tasks": total, "func_at_1": sum(x["functional"] for x in results) / total if total else 0,
               "sec_at_1": sum(x["security"] for x in results) / total if total else 0,
               "func_sec_at_1": sum(x["func_sec"] for x in results) / total if total else 0,
               "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}))


if __name__ == "__main__":
    main()
