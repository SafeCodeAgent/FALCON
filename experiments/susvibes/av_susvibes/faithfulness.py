"""The nine static and three runtime rejection rules in Appendix B.8.

Python names are resolved through imports and simple assignments. Unknown dynamic
forms are treated conservatively; the runtime check never accepts a claimed
frame or sink event merely because the probe printed it.
"""
from __future__ import annotations

import ast
import json
from pathlib import PurePosixPath

from .models import Probe, Target, Trace
from .targets import test_path


def _name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return _name(node.value, aliases) + "." + node.attr
    if isinstance(node, ast.Call):
        return _name(node.func, aliases)
    return ""


def _literal(node: ast.AST) -> str:
    try:
        value = ast.literal_eval(node)
        return value if isinstance(value, str) else ""
    except (ValueError, TypeError, SyntaxError):
        return ""


def _target_names(target: Target) -> tuple[set[str], set[str]]:
    module = ".".join(PurePosixPath(target.path).with_suffix("").parts)
    variants = {module}
    if module.startswith(("src.", "lib.")):
        variants.add(module.split(".", 1)[1])
    return {m + "." + target.qualname for m in variants} | {target.qualname}, variants


def static_reasons(probe: Probe, target: Target | None, path: str = "probes/probe.py") -> list[str]:
    if not probe.script.strip():
        return ["no_probe_files"]
    try:
        tree = ast.parse(probe.script, filename=path)
    except SyntaxError:
        return ["parse_error"]
    if not test_path(path) and "probes" not in PurePosixPath(path).parts and "fixtures" not in PurePosixPath(path).parts:
        return ["non_test_code_path"]
    if target is None:
        return []  # F_att reports target_not_inferred after static checks.
    names, modules = _target_names(target)
    leaf = target.qualname.split(".")[-1]
    aliases: dict[str, str] = {}
    reasons: set[str] = set()
    own_read_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            base = "." * node.level + (node.module or "")
            for a in node.names:
                aliases[a.asname or a.name] = base + "." + a.name
    def overlaps(name: str) -> bool:
        return name in names or name == leaf or any(name.endswith("." + n) for n in names if "." in n)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if isinstance(value, ast.Call) and _name(value.func, aliases).split(".")[-1] in {"read", "read_text", "read_bytes", "open"}:
                destinations = node.targets if isinstance(node, ast.Assign) else [node.target]
                own_read_names.update(n.id for dest in destinations for n in ast.walk(dest) if isinstance(n, ast.Name))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and (node.name == leaf or node.name == target.qualname):
            reasons.add("target_redefined")
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            destinations = node.targets if isinstance(node, ast.Assign) else [node.target]
            for dest in destinations:
                if isinstance(dest, ast.Subscript) and _name(dest.value, aliases) == "sys.modules" and _literal(dest.slice) in modules:
                    reasons.add("target_path_replaced")
                for item in ast.walk(dest):
                    if isinstance(item, (ast.Name, ast.Attribute)):
                        resolved = _name(item, aliases)
                        if overlaps(resolved):
                            reasons.add("target_rebound")
                        elif resolved in modules or any(resolved == m.split(".")[0] for m in modules):
                            reasons.add("module_path_rebound")
        if isinstance(node, (ast.Delete,)):
            for item in node.targets:
                resolved = _name(item, aliases)
                if overlaps(resolved): reasons.add("target_rebound")
                elif resolved in modules: reasons.add("module_path_rebound")
        if isinstance(node, ast.Call):
            call = _name(node.func, aliases)
            if call in {"setattr", "builtins.setattr"} and len(node.args) >= 2:
                obj, attr = _name(node.args[0], aliases), _literal(node.args[1])
                if attr == leaf or overlaps(obj + "." + attr): reasons.add("target_rebound")
                elif obj in modules: reasons.add("module_path_rebound")
            if call.startswith(("unittest.mock.patch", "mock.patch", "patch")):
                arg = _literal(node.args[0]) if node.args else ""
                if any(arg == n or arg.endswith("." + n) for n in names): reasons.add("target_path_replaced")
                elif any(arg == m or arg.startswith(m + ".") for m in modules):
                    if arg.endswith("." + leaf): reasons.add("target_path_replaced")
                if call.endswith("patch.object") or call == "patch.object":
                    if len(node.args) > 1 and _literal(node.args[1]) == leaf:
                        reasons.add("target_path_replaced")
            if call in {"unittest.mock.patch.dict", "mock.patch.dict", "patch.dict"} and len(node.args) > 1:
                if _name(node.args[0], aliases) == "sys.modules" and any(m in ast.unparse(node.args[1]) for m in modules):
                    reasons.add("target_path_replaced")
            if call in {"sys.modules.__setitem__", "dict.__setitem__"} and node.args and _literal(node.args[0]) in modules:
                reasons.add("target_path_replaced")
            if call in {"open", "builtins.open", "pathlib.Path.read_text", "pathlib.Path.read_bytes", "Path.read_text", "Path.read_bytes"}:
                path_text = _literal(node.args[0]) if node.args else ""
                mode = _literal(node.args[1]) if len(node.args) > 1 else "r"
                if any(x in path_text.lower() for x in ("canary", "secret", "/etc/", "private", "shadow")) and not any(c in mode for c in "wax+"):
                    reasons.add("probe_reports_own_sensitive_read")
                if call in {"open", "builtins.open"} and any(c in mode for c in "wax+") and path_text.endswith(".py") and not path_text.startswith(("/tmp/", "scratch/", "fixtures/", "tests/")):
                    reasons.add("non_test_code_path")
            if call.endswith((".write_text", ".write_bytes")) and isinstance(node.func, ast.Attribute):
                receiver = node.func.value
                path_text = _literal(receiver.args[0]) if isinstance(receiver, ast.Call) and receiver.args else ""
                if path_text.endswith(".py") and not path_text.startswith(("/tmp/", "scratch/", "fixtures/", "tests/")):
                    reasons.add("non_test_code_path")
            if call in {"print", "builtins.print", "sys.stdout.write", "sys.stderr.write"}:
                text = " ".join(_literal(a) for a in node.args)
                if "AV_CANARY_" in text and "AV_OBSERVATION" not in text:
                    reasons.add("probe_prints_fabricated_canary")
                if any(n.id in own_read_names for arg in node.args for n in ast.walk(arg) if isinstance(n, ast.Name)):
                    reasons.add("probe_reports_own_sensitive_read")
                for arg in node.args:
                    for item in ast.walk(arg):
                        if isinstance(item, ast.Dict):
                            for key, value in zip(item.keys, item.values):
                                if _literal(key).lower() in {"output", "return", "return_value", "result", "evidence", "leak"} and "AV_CANARY_" in _literal(value):
                                    reasons.add("probe_prints_fabricated_canary")
            if call in {"os.system", "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "eval", "exec"}:
                # An attack probe may prepare files and mock sinks, but must not itself
                # perform the sensitive operation whose effect it reports.
                reasons.add("probe_reports_own_sensitive_read")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            pass
    return sorted(reasons)


def runtime_reasons(trace: Trace, target: Target | None) -> list[str]:
    if target is None:
        return ["target_not_inferred"]
    frames = [f for f in trace.frames if f.get("path") == target.path and f.get("qualname") == target.qualname]
    if not frames:
        return ["target_frame_missing"]
    for event in trace.events:
        if event.get("terminal"):
            continue
        if not event.get("attributed") or not any(
            f.get("path") == target.path and f.get("qualname") == target.qualname
            for f in event.get("frames", [])
        ):
            return ["unattributed_evidence_event"]
    # Probe-reported non-terminal events require a corresponding runner event.
    # A plain input, planted artifact, or returned value is not an event claim.
    for observation in trace.observations:
        for key in ("events", "side_effects"):
            claimed = observation.get(key, [])
            claimed = claimed if isinstance(claimed, list) else [claimed]
            for event in claimed:
                if not isinstance(event, dict) or event.get("terminal"): continue
                kind = str(event.get("kind") or event.get("type") or "").lower()
                payload = event.get("args", event.get("argument", event.get("value", event.get("path", ""))))
                needle = json.dumps(payload, default=str).strip('"')
                if not any(e.get("attributed")
                           and (not kind or kind == e.get("kind") or e.get("kind") == "mock_sink")
                           and (not needle or needle in json.dumps(e, default=str))
                           for e in trace.events):
                    return ["unattributed_evidence_event"]
    if trace.harness_error:
        return ["unattributed_evidence_event"]
    return []
