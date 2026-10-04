from __future__ import annotations

import ast
import re
from pathlib import Path

from .models import Target

EXTENSIONS = {".py": "python", ".js": "javascript", ".mjs": "javascript",
              ".ts": "javascript", ".c": "c", ".cc": "cpp", ".cpp": "cpp",
              ".go": "go", ".java": "java"}
TEST_PARTS = {"test", "tests", "__tests__", "spec", "fixtures"}


def is_test_path(path: str) -> bool:
    p = Path(path)
    name = p.name.lower()
    return bool(TEST_PARTS.intersection(x.lower() for x in p.parts) or
                name.startswith("test_") or name.endswith(("_test.py", ".test.js", ".spec.js")))


def select_targets(workspace: Path, changed_paths: list[str]) -> list[Target]:
    targets: list[Target] = []
    root = workspace.resolve()
    for relative in sorted(set(changed_paths)):
        file = (root / relative).resolve()
        if not file.is_relative_to(root) or not file.is_file() or is_test_path(relative):
            continue
        language = EXTENSIONS.get(file.suffix.lower())
        if not language:
            continue
        source = file.read_text(encoding="utf-8", errors="replace")
        if language == "python":
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    body = ast.get_source_segment(source, node) or ""
                    targets.append(Target(relative, node.name, language, body))
                    if isinstance(node, ast.ClassDef):
                        for child in node.body:
                            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                targets.append(Target(relative, f"{node.name}.{child.name}", language,
                                                      ast.get_source_segment(source, child) or ""))
        else:
            patterns = {
                "javascript": r"(?:function\s+|(?:const|let|var)\s+|class\s+)([A-Za-z_$][\w$]*)",
                "go": r"func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)",
                "java": r"(?:class\s+|(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\]]+\s+)([A-Za-z_]\w*)\s*(?:\(|\{)",
                "c": r"(?:^|\n)\s*[\w*]+\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{",
                "cpp": r"(?:^|\n)\s*[\w:*&<>]+\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{",
            }
            for name in dict.fromkeys(re.findall(patterns[language], source)):
                targets.append(Target(relative, name, language, source[:8000]))
    return targets
