"""Attack-target selection.

A target is a function, method, or class that could be exercised by a probe.
:func:`select_targets` finds them in non-test Python files and ranks them by how
much security-relevant surface they touch, so a bounded run spends its probe
budget where a vulnerability is most likely to live.

Scopes:
* ``whole``   -- every non-test Python file under the repo root.
* ``path``    -- a single file or directory given by the caller.
* ``changed`` -- only uncommitted work: files changed against ``HEAD``, with
  targets narrowed to functions whose body overlaps the changed lines, plus new
  untracked files in full.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

STATE_DIR = ".attacker-verifier"
_TEST_PATH_RE = re.compile(r"(^|/)(tests?|testing)(/|$)", re.IGNORECASE)
_TEST_FILE_RE = re.compile(r"(^test_|_test\.py$|^conftest\.py$)", re.IGNORECASE)
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env",
    "node_modules", ".tox", ".mypy_cache", ".pytest_cache", "build", "dist",
    ".attacker-verifier",
}

# Import/attribute markers that suggest a function touches a security-sensitive
# operation. Each matched marker adds to a function's relevance score.
_RELEVANCE_MARKERS = {
    "subprocess": 3, "os.system": 3, "os.popen": 3, "os.exec": 3, "pty": 2,
    "eval": 3, "exec": 3, "compile": 1,
    "pickle": 3, "marshal": 2, "yaml.load": 3, "shelve": 1, "dill": 3,
    "sqlite3": 2, "psycopg2": 2, "pymysql": 2, "sqlalchemy": 1, "execute": 2,
    "open": 1, "shutil": 1, "pathlib": 1, "os.path": 1, "os.remove": 2,
    "os.symlink": 2, "os.link": 2, "tempfile": 1, "zipfile": 2, "tarfile": 2,
    "requests": 2, "urllib": 2, "httpx": 2, "socket": 2, "http.client": 2,
    "hashlib": 1, "hmac": 1, "ssl": 2, "cryptography": 1, "Crypto": 2,
    "jinja2": 2, "Template": 1, "render_template_string": 3,
    "flask": 1, "django": 1, "fastapi": 1, "redirect": 2,
    "jwt": 2, "secrets": 1, "base64": 1, "md5": 2, "sha1": 1, "DES": 2,
}


def select_targets(
    repo_root: str,
    scope: str = "whole",
    path: Optional[str] = None,
    max_targets: int = 20,
) -> List[Dict[str, Any]]:
    """Return a ranked list of target descriptors, longest/riskiest first."""
    repo_root = os.path.abspath(repo_root)
    if scope == "changed":
        files, changed_lines = _changed_files(repo_root)
    elif scope == "path":
        files, changed_lines = _files_under(repo_root, path or repo_root), None
    else:
        files, changed_lines = _files_under(repo_root, repo_root), None

    targets: List[Dict[str, Any]] = []
    for abspath in files:
        rel = os.path.relpath(abspath, repo_root)
        if _is_test(rel):
            continue
        targets.extend(_targets_in_file(repo_root, abspath, rel, changed_lines))

    targets.sort(key=lambda t: (t["score"], t["_size"]), reverse=True)
    return targets[:max_targets]


def _files_under(repo_root: str, start: str) -> List[str]:
    start = os.path.abspath(start)
    if os.path.isfile(start):
        return [start] if start.endswith(".py") else []
    collected: List[str] = []
    for dirpath, dirnames, filenames in os.walk(start):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if name.endswith(".py"):
                collected.append(os.path.join(dirpath, name))
    return collected


def _git(repo_root: str, *args: str) -> Optional[str]:
    try:
        done = subprocess.run(
            ["git", *args], cwd=repo_root, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.decode("utf-8", "replace") if done.returncode == 0 else None


def _changed_files(repo_root: str) -> Tuple[List[str], Dict[str, Set[int]]]:
    """Return changed .py files and, per file, the set of changed line numbers.

    Tracked files contribute the lines changed against ``HEAD``. New, untracked
    files (and every file in a repository with no commits yet) count as changed
    in full.
    """
    files: List[str] = []
    changed: Dict[str, Set[int]] = {}

    def whole(rel: str) -> None:
        abspath = os.path.join(repo_root, rel)
        if rel.endswith(".py") and os.path.isfile(abspath) and abspath not in changed:
            files.append(abspath)
            changed[abspath] = set(range(1, _line_count(abspath) + 1))

    has_head = _git(repo_root, "rev-parse", "--verify", "--quiet", "HEAD") is not None
    if has_head:
        diff = _git(repo_root, "diff", "--unified=0", "HEAD", "--", "*.py") or ""
        current: Optional[str] = None
        for line in diff.splitlines():
            if line.startswith("+++ "):
                # "+++ /dev/null" marks a deleted file; its hunks belong to nothing.
                current = line[6:].strip() if line.startswith("+++ b/") else None
                if current and current.endswith(".py"):
                    abspath = os.path.join(repo_root, current)
                    if abspath not in changed:
                        files.append(abspath)
                        changed[abspath] = set()
            elif line.startswith("@@") and current:
                match = re.search(r"\+(\d+)(?:,(\d+))?", line)
                if match:
                    start = int(match.group(1))
                    count = int(match.group(2) or "1")
                    abspath = os.path.join(repo_root, current)
                    changed.setdefault(abspath, set()).update(range(start, start + max(count, 1)))
        listed = _git(repo_root, "ls-files", "--others", "--exclude-standard") or ""
    else:
        listed = _git(repo_root, "ls-files", "--cached", "--others", "--exclude-standard") or ""
    for rel in listed.splitlines():
        if not rel.startswith(STATE_DIR + "/"):
            whole(rel.strip())
    return files, changed


def _line_count(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def _targets_in_file(
    repo_root: str,
    abspath: str,
    rel: str,
    changed_lines: Optional[Dict[str, Set[int]]],
) -> List[Dict[str, Any]]:
    try:
        with open(abspath, "r", encoding="utf-8") as handle:
            source = handle.read()
    except OSError:
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    out: List[Dict[str, Any]] = []
    changed_set = (changed_lines or {}).get(abspath)

    for node, qualname in _iter_definitions(tree):
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", start)
        if start is None:
            continue
        if changed_set is not None:
            body_lines = set(range(start, (end or start) + 1))
            if body_lines.isdisjoint(changed_set):
                continue
        segment = ast.get_source_segment(source, node) or ""
        out.append(
            {
                "file": rel,
                "qualname": qualname,
                "kind": _kind(node),
                "lineno": start,
                "end_lineno": end,
                "score": _relevance(segment),
                "_size": (end or start) - start,
                "source": segment,
            }
        )
    return out


def _iter_definitions(tree: ast.AST):
    """Yield (node, qualname) for top-level and nested defs/classes."""
    def walk(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qual = prefix + child.name
                yield child, qual
                if isinstance(child, ast.ClassDef):
                    yield from walk(child, qual + ".")
    yield from walk(tree, "")


def _kind(node: ast.AST) -> str:
    if isinstance(node, ast.ClassDef):
        return "class"
    if isinstance(node, ast.AsyncFunctionDef):
        return "async function"
    return "function"


def _relevance(segment: str) -> int:
    score = 0
    for marker, weight in _RELEVANCE_MARKERS.items():
        if marker in segment:
            score += weight
    return score


def _is_test(rel: str) -> bool:
    base = os.path.basename(rel)
    return bool(_TEST_PATH_RE.search(rel) or _TEST_FILE_RE.search(base))
