from __future__ import annotations

import ast
import re
from pathlib import Path

from .models import Probe, Target, Trace

SENSITIVE_READS = {"read", "read_text", "read_bytes"}
REPLACE_CALLS = {"patch", "patch.object", "setattr", "delattr", "sys.modules"}
RUNNER_MARKERS = ("AV_TRACE:", "AV_FRAMES_PATH", ".av_frames.json")


def _path(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_path(node.value)}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return f"{_path(node.value)}[]"
    return ""


def _assigned(node: ast.AST) -> list[str]:
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in _assigned(item)]
    return [_path(node)]


def static_check(probe: Probe, target: Target) -> tuple[bool, str]:
    if not probe.script.strip():
        return False, "no_probe_files"
    if probe.target != target.key:
        return False, "target_not_inferred"
    if target.language == "python":
        try:
            tree = ast.parse(probe.script)
        except SyntaxError:
            return False, "parse_error"
        if any(marker in probe.script for marker in RUNNER_MARKERS):
            # Writing the runner's own trace channels would replace the measured target path.
            return False, "target_path_replaced"
        symbol = target.symbol.split(".")[-1]
        module = Path(target.path).stem
        aliases = {symbol, module}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    if alias.name == module or alias.name == symbol:
                        aliases.add(alias.asname or alias.name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == symbol:
                return False, "target_redefined"
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                written = []
                if isinstance(node, ast.Assign):
                    written = [name for item in node.targets for name in _assigned(item)]
                elif isinstance(node, ast.NamedExpr):
                    written = _assigned(node.target)
                else:
                    written = _assigned(node.target)
                for name in written:
                    if name == symbol or name.endswith("." + symbol):
                        return False, "target_rebound"
                    if name == module or name == "sys.modules[]":
                        return False, "module_path_rebound"
            if isinstance(node, ast.Call):
                call = _path(node.func)
                args = [ast.literal_eval(x) if isinstance(x, ast.Constant) else None for x in node.args]
                if call in {"sys.settrace", "sys.setprofile", "sys.addaudithook"}:
                    return False, "target_path_replaced"
                if call in {"setattr", "delattr", "patch.object"} and len(args) > 1 and args[1] == symbol:
                    return False, "target_rebound"
                if call.endswith("patch") and args and isinstance(args[0], str) and (
                    args[0] == module or args[0].endswith("." + symbol)
                ):
                    return False, "target_path_replaced"
                if call == "open" and args and isinstance(args[0], str):
                    path = args[0]
                    mode = args[1] if len(args) > 1 and isinstance(args[1], str) else "r"
                    if any(c in mode for c in "wax+") and not path.startswith(("/tmp/", "/scratch/")):
                        return False, "non_test_code_path"
                if call in {"write_text", "write_bytes", "unlink"} or call.endswith((".write_text", ".write_bytes", ".unlink")):
                    receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
                    if isinstance(receiver, ast.Call) and _path(receiver.func) == "Path":
                        if receiver.args and isinstance(receiver.args[0], ast.Constant):
                            path = str(receiver.args[0].value)
                            if not path.startswith(("/tmp/", "/scratch/")):
                                return False, "non_test_code_path"
        def reads_sensitive(node: ast.AST) -> bool:
            return any(isinstance(child, ast.Call) and
                       _path(child.func).split(".")[-1] in SENSITIVE_READS
                       for child in ast.walk(node))

        tainted = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and reads_sensitive(node.value):
                tainted.update(name for item in node.targets for name in _assigned(item))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _path(node.func) in {"print", "sys.stdout.write"}:
                if any(reads_sensitive(arg) or any(isinstance(child, ast.Name) and child.id in tainted
                                                   for child in ast.walk(arg)) for arg in node.args):
                    return False, "probe_reports_own_sensitive_read"
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _path(node.func) == "print":
                if any(isinstance(x, ast.Constant) and isinstance(x.value, str) and
                       "AV_CANARY_" in x.value and "AV_OBSERVATION:" not in x.value
                       for x in node.args):
                    return False, "probe_prints_fabricated_canary"
        return True, ""

    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", probe.script, flags=re.S)
    if not text.strip():
        return False, "no_probe_files"
    symbol = re.escape(target.symbol.split(".")[-1])
    module = re.escape(Path(target.path).stem)
    if re.search(rf"\b(?:function|class|func|def)\s+{symbol}\b", text):
        return False, "target_redefined"
    if re.search(rf"\b{symbol}\s*(?:=|\+=|:=)", text):
        return False, "target_rebound"
    if re.search(rf"\b{module}\s*(?:=|:=)", text):
        return False, "module_path_rebound"
    if re.search(rf"(?:mock|patch|replace)\s*\([^)]*(?:{module}|{symbol})", text, re.I):
        return False, "target_path_replaced"
    if re.search(r"(?:writeFile|write_text|fwrite)\s*\([^)]*(?:\.\./|/work/(?!\.av_scratch))", text):
        return False, "non_test_code_path"
    if re.search(r"(?:readFile|read_text|fread)\s*\([^)]*\).{0,80}(?:print|console\.log)", text, re.S):
        return False, "probe_reports_own_sensitive_read"
    if re.search(r"(?:print|console\.log)\s*\(\s*['\"]AV_CANARY_", text):
        return False, "probe_prints_fabricated_canary"
    return True, ""


def runtime_check(trace: Trace, target: Target) -> tuple[bool, str]:
    if trace.target != target.key:
        return False, "target_not_inferred"
    if trace.harness_error:
        return False, "harness_error"
    if not trace.target_frames:
        return False, "target_frame_missing"
    for event in trace.events:
        if event.phase != "target":
            continue
        if not any(frame in trace.target_frames for frame in event.frames):
            return False, "unattributed_evidence_event"
    return True, ""
