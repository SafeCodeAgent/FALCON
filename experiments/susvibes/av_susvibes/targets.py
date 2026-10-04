from __future__ import annotations

import ast
import re
from pathlib import Path, PurePosixPath

from .models import Target

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def test_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    name = parts[-1].lower() if parts else ""
    return any(p.lower() in {"test", "tests", "testing"} for p in parts[:-1]) or name.startswith("test_") or name.endswith(("_test.py", "_tests.py"))


def patch_files(patch: str) -> dict[str, set[int]]:
    """Map changed destination lines, including the anchor of deletion-only hunks."""
    changed: dict[str, set[int]] = {}
    path = None
    line_no = None
    anchor = None
    added = False
    def finish() -> None:
        if path and anchor is not None and not added:
            changed[path].add(max(1, anchor))
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            finish(); path = None; line_no = None; anchor = None; added = False
        elif line.startswith("+++ "):
            raw = line[4:].split("\t", 1)[0].strip('"')
            path = raw[2:] if raw.startswith("b/") else raw
            if path == "/dev/null" or not path.endswith(".py") or test_path(path) or ".." in PurePosixPath(path).parts:
                path = None
            elif path:
                changed.setdefault(path, set())
        elif (m := HUNK.match(line)):
            finish(); line_no = int(m.group(1)); anchor = line_no; added = False
        elif path and line_no is not None:
            if line.startswith("+") and not line.startswith("+++"):
                changed[path].add(max(1, line_no)); line_no += 1; added = True
            elif line.startswith(" "):
                line_no += 1
    finish()
    return changed


def public_patch(patch: str) -> str:
    return "".join("diff --git " + block for block in patch.split("diff --git ")[1:]
                   if (path := block.splitlines()[0].split()[-1].removeprefix("b/"))
                   and path.endswith(".py") and not test_path(path))


def select_targets(repo: Path, patch: str) -> list[Target]:
    selected: list[Target] = []
    for path, changed in patch_files(patch).items():
        file = (repo / path).resolve()
        if not file.is_relative_to(repo.resolve()) or not file.is_file():
            continue
        source = file.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            selected.extend(_lexical_targets(path, source, changed))
            continue
        lines = source.splitlines()
        imports = "\n".join(ast.get_source_segment(source, n) or "" for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom)))[:6000]
        for node in tree.body:
            nodes = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nodes.append((node, node.name, "function"))
            elif isinstance(node, ast.ClassDef):
                methods = [(n, node.name + "." + n.name, "method") for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                nodes.extend((n, q, k) for n, q, k in methods if changed.intersection(range(n.lineno, n.end_lineno + 1)))
                if changed.intersection(range(node.lineno, node.end_lineno + 1)) and not nodes:
                    nodes.append((node, node.name, "class"))
            for n, qualname, kind in nodes:
                if changed.intersection(range(n.lineno, n.end_lineno + 1)):
                    selected.append(Target(path, qualname, kind, n.lineno, n.end_lineno,
                                           "\n".join(lines[n.lineno - 1:n.end_lineno])[:80000], imports))
    return selected


DEF_LINE = re.compile(r"^([ \t]*)(?:async\s+)?(def|class)\s+([A-Za-z_]\w*)\b")


def _lexical_targets(path: str, source: str, changed: set[int]) -> list[Target]:
    """Fallback for Python 2 syntax that Python 3's AST cannot parse."""
    lines = source.splitlines()
    imports = "\n".join(line for line in lines if re.match(r"^(?:from|import)\s", line))[:6000]
    nodes: list[tuple[int, int, int, str, str]] = []
    stack: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        while stack and indent <= stack[-1][0]:
            stack.pop()
        match = DEF_LINE.match(line)
        if not match: continue
        kind, name = match.group(2), match.group(3)
        parent_class = next((entry[1] for entry in reversed(stack) if entry[2] == "class"), "")
        if not stack or parent_class and stack[-1][2] == "class":
            qualname = parent_class + "." + name if parent_class else name
            node_kind = "method" if parent_class and kind == "def" else "class" if kind == "class" else "function"
            nodes.append((index, indent, len(lines), qualname, node_kind))
        stack.append((indent, name, kind))
    bounded = []
    for start, indent, _, qualname, kind in nodes:
        end = len(lines)
        for index in range(start + 1, len(lines) + 1):
            line = lines[index - 1]
            if line.strip() and not line.lstrip().startswith("#") and len(line) - len(line.lstrip(" \t")) <= indent:
                end = index - 1
                break
        bounded.append((start, end, qualname, kind))
    selected = []
    for start, end, qualname, kind in bounded:
        if not changed.intersection(range(start, end + 1)):
            continue
        if kind == "class" and any(k == "method" and q.startswith(qualname + ".") and
                                   changed.intersection(range(s, e + 1))
                                   for s, e, q, k in bounded):
            continue
        selected.append(Target(path, qualname, kind, start, end,
                               "\n".join(lines[start - 1:end])[:80000], imports))
    return selected
