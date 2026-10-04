from __future__ import annotations

import json
import shutil
from pathlib import Path

from .targets import is_test_path


def _copy_public_tree(source: Path, destination: Path) -> None:
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(source)
        if (is_test_path(str(rel)) or "test" in {part.lower() for part in rel.parts}
                or any(part.startswith(".") for part in rel.parts)):
            continue
        if path.name == "signature.json" or ("resources" in rel.parts and path.suffix == ".md"):
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def prepare_cweval(benchmark_root: Path, output: Path, limit: int | None = None,
                   language: str | None = None) -> list[dict]:
    benchmark = benchmark_root / "benchmark"
    if not benchmark.is_dir():
        raise ValueError("CWEval benchmark directory not found")
    entries = []
    for path in sorted(benchmark.rglob("*_task.*")):
        task_language = {".py": "python", ".js": "javascript", ".go": "go",
                         ".c": "c", ".cpp": "cpp"}.get(path.suffix)
        if language and task_language != language:
            continue
        if limit is not None and len(entries) >= limit:
            break
        source = path.read_text(encoding="utf-8", errors="replace")
        if "BEGIN SOLUTION" not in source:
            continue
        public = source.split("BEGIN SOLUTION", 1)[0]
        entrypoint = source.split("BEGIN ENTRYPOINT", 1)[1] if "BEGIN ENTRYPOINT" in source else ""
        case_id = path.stem.removesuffix("_task")
        workspace = output / "workspaces" / case_id
        workspace.mkdir(parents=True, exist_ok=True)
        name = f"solution{path.suffix}"
        (workspace / name).write_text(public, encoding="utf-8")
        entries.append({"id": case_id, "benchmark": "cweval", "workspace": str(workspace),
                        "language": task_language,
                        "changed_paths": [name],
                        "task": public + ("\nRequired public entrypoint scaffold:\n" + entrypoint if entrypoint else ""),
                        "source_task": str(path.relative_to(benchmark))})
    return entries


def prepare_seccodebench(benchmark_root: Path, output: Path, scenario: str = "gen",
                         limit: int | None = None, prompt_map: Path | None = None,
                         language: str | None = None) -> list[dict]:
    if scenario not in {"gen", "gen-hints", "fix", "fix-hints"}:
        raise ValueError("invalid SecCodeBench scenario")
    dataset = benchmark_root / "datasets"
    external_prompts = json.loads(prompt_map.read_text(encoding="utf-8")) if prompt_map else {}
    entries = []
    for catalog in sorted((dataset / "benchmark").glob("*/*.json")):
        if catalog.name.endswith("-test.json"):
            continue
        if catalog.parent.name == "java" and catalog.name != "java.json":
            continue
        cases = json.loads(catalog.read_text(encoding="utf-8"))
        for case_id, info in sorted(cases.items()):
            if language and info.get("language") != language:
                continue
            if limit is not None and len(entries) >= limit:
                return entries
            if scenario not in info.get("scenarios", []):
                continue
            template = dataset / "templates" / catalog.parent.name / info["template"]
            prompt_name = {"gen": "generate.md", "gen-hints": "generate_hints.md",
                           "fix": "fix.md", "fix-hints": "fix_hints.md"}[scenario]
            prompt_path = template / "resources" / "questionnaire_prompts" / prompt_name
            if not prompt_path.is_file():
                alternate = {"gen": "generate.md", "gen-hints": "generate_sec.md",
                             "fix": "fix.md", "fix-hints": "fix_sec.md"}[scenario]
                prompt_path = template / "resources" / alternate
            key = f"{catalog.parent.name}/{case_id}/{scenario}"
            prompt_text = (prompt_path.read_text(encoding="utf-8") if prompt_path.is_file()
                           else external_prompts.get(key))
            if not template.is_dir() or not prompt_text:
                continue
            workspace = output / "workspaces" / catalog.parent.name / case_id / scenario
            workspace.mkdir(parents=True, exist_ok=True)
            _copy_public_tree(template, workspace)
            changed = list(info.get("params", {}).values())
            if not changed:
                continue
            for name in changed:
                path = workspace / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_text("", encoding="utf-8")
            entries.append({"id": case_id, "benchmark": "seccodebench-v2",
                            "scenario": scenario, "language": info.get("language"),
                            "workspace": str(workspace), "changed_paths": changed,
                            "task": prompt_text,
                            "catalog": str(catalog.relative_to(dataset))})
    return entries


def write_manifest(entries: list[dict], output: Path) -> Path:
    path = output / "manifest.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return path
