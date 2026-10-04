"""Faithfulness checks for probes.

A probe is only useful as evidence if the behaviour it reports was actually
produced by the target under test. Two predicates enforce that:

* :func:`static_check` (F_stat) runs before execution. It parses the probe and
  rejects it if the probe redefines or rebinds the target, rebinds or replaces
  the module that reaches it, writes code into the repository, or produces the
  evidence itself (prints a canary it made, or reports a value it read).
* :func:`runtime_check` (F_att) runs on the resulting trace. It confirms the
  probe actually reached the target, and that the observations it offers were
  printed after the target ran.

A probe rejected by ``static_check`` never runs. A probe rejected by
``runtime_check`` has run but yields no admissible evidence; it is recorded as
inconclusive. Admitted probes pass both.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, Iterable, List, Optional, Set

CANARY = "AV_CANARY_"
OBSERVATION = "AV_OBSERVATION"
# Calls that replace an attribute or a module for the rest of the probe.
_PATCH_TAILS = {"patch", "setattr", "delattr"}
# Calls that would replace the tracer that attributes behaviour to the target.
_TRACER_CALLS = {"sys.settrace", "sys.setprofile", "threading.settrace", "threading.setprofile"}
# Reading a file or the environment and printing the value is evidence the probe
# made, not the target.
_READ_METHODS = {"read", "read_text", "read_bytes", "readline", "readlines"}
_FILE_OPENERS = {"open", "io.open", "builtins.open", "Path", "pathlib.Path"}
# Sensitive operations a probe must not perform in its own body.
_OWN_SINKS = {"os.system", "os.popen", "subprocess.run", "subprocess.Popen", "subprocess.call",
              "subprocess.check_call", "subprocess.check_output", "eval", "exec"}
_PRINTS = {"print", "sys.stdout.write", "sys.stderr.write"}
_EVIDENCE_KEYS = {"output", "return", "return_value", "result", "evidence", "leak", "leaked"}


def module_variants(module_path: Optional[str]) -> Set[str]:
    """Dotted module names a probe may use to import the target's file."""
    if not module_path:
        return set()
    variants = {module_path}
    for prefix in ("src.", "lib."):
        if module_path.startswith(prefix):
            variants.add(module_path[len(prefix):])
    return variants


def _chain(node: ast.AST) -> Optional[str]:
    """Render a dotted attribute/name chain like ``a.b.c``, or None."""
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _string(node: Optional[ast.AST]) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _names_in(node: ast.AST) -> Iterable[str]:
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            yield child.id


def static_check(
    probe_source: str,
    target_qualname: str,
    module_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Run F_stat on one probe's source.

    ``module_path`` is the dotted module of the target's file (``app.files``).
    Returns ``{"admitted": bool, "rule": str | None, "detail": str}``. ``rule``
    names the first rule that rejected the probe.
    """
    if not probe_source or not probe_source.strip():
        return _reject("no_probe_files", "probe is empty")
    try:
        tree = ast.parse(probe_source)
    except SyntaxError as exc:
        return _reject("parse_error", "probe does not parse: %s" % exc)

    parts = target_qualname.split(".")
    leaf = parts[-1]
    owner = parts[-2] if len(parts) >= 2 else None
    modules = module_variants(module_path)
    module_names = _module_aliases(tree, modules)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == leaf:
            return _reject("target_redefined", "probe defines its own '%s', shadowing the target" % leaf)

        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets = (node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target])
            for tgt in targets:
                for item in (tgt.elts if isinstance(tgt, (ast.Tuple, ast.List)) else [tgt]):
                    rejected = _check_binding(item, leaf, module_names, modules)
                    if rejected:
                        return rejected

        if isinstance(node, ast.Call):
            rejected = _check_call(node, leaf, owner, modules, module_names)
            if rejected:
                return rejected

    rejected = _check_own_evidence(tree)
    if rejected:
        return rejected
    return {"admitted": True, "rule": None, "detail": ""}


def _module_aliases(tree: ast.AST, modules: Set[str]) -> Set[str]:
    """Names in the probe that are bound to the target's module (or its package)."""
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in modules:
                    names.add(alias.asname or alias.name.split(".")[0])
                elif any(m.startswith(alias.name + ".") for m in modules) and not alias.asname:
                    names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if "%s.%s" % (node.module, alias.name) in modules:
                    names.add(alias.asname or alias.name)
    return names


def _check_binding(node: ast.AST, leaf: str, module_names: Set[str],
                   modules: Set[str]) -> Optional[Dict[str, Any]]:
    if isinstance(node, ast.Subscript):
        if _chain(node.value) == "sys.modules" and _string(node.slice) in modules:
            return _reject("target_path_replaced", "probe replaces the target's module in sys.modules")
        return None
    chain = _chain(node)
    if chain is None:
        return None
    if chain.split(".")[-1] == leaf:
        return _reject("target_rebound", "probe assigns over the target '%s'" % chain)
    if chain in module_names:
        return _reject("module_path_rebound", "probe rebinds '%s', the module path reaching the target" % chain)
    return None


def _check_call(node: ast.Call, leaf: str, owner: Optional[str], modules: Set[str],
                module_names: Set[str]) -> Optional[Dict[str, Any]]:
    name = _chain(node.func) or ""
    tail = name.split(".")[-1]
    first = _string(node.args[0]) if node.args else ""
    second = _string(node.args[1]) if len(node.args) > 1 else ""

    if name in _TRACER_CALLS:
        return _reject("target_path_replaced", "probe replaces the tracer with %s" % name)
    if tail in _PATCH_TAILS or name.endswith("patch.object"):
        if name.endswith(".object") or tail in {"setattr", "delattr"}:
            # patch.object(obj, "leaf") / setattr(obj, "leaf", value) on the target's
            # module or owning class.
            holder = _chain(node.args[0]) if node.args else None
            if second == leaf and holder and (holder in module_names or holder.split(".")[-1] == owner
                                              or not modules):
                return _reject("target_path_replaced", "probe replaces the target via %s" % name)
            if first and _replaces_target(first, leaf, owner, modules):
                return _reject("target_path_replaced", "probe patches %r, replacing the target" % first)
        elif first and _replaces_target(first, leaf, owner, modules):
            return _reject("target_path_replaced", "probe patches %r, replacing the target" % first)
    if name.endswith("patch.dict") and node.args and _chain(node.args[0]) == "sys.modules":
        text = ast.dump(node)
        if any(m in text for m in modules):
            return _reject("target_path_replaced", "probe swaps the target's module in sys.modules")
    if name in {"open", "builtins.open", "io.open"} and first.endswith(".py"):
        mode = second or _string(_keyword(node, "mode")) or "r"
        if any(c in mode for c in "wax+") and not first.startswith("/tmp/"):
            return _reject("non_test_code_path", "probe writes Python code to %r" % first)
    if tail in {"write_text", "write_bytes"} and isinstance(node.func, ast.Attribute):
        receiver = node.func.value
        path = _string(receiver.args[0]) if isinstance(receiver, ast.Call) and receiver.args else ""
        if path.endswith(".py") and not path.startswith("/tmp/"):
            return _reject("non_test_code_path", "probe writes Python code to %r" % path)
    if name in _OWN_SINKS:
        return _reject("probe_reports_own_sensitive_read",
                       "probe performs the sensitive operation %s itself" % name)
    return None


def _replaces_target(dotted: str, leaf: str, owner: Optional[str], modules: Set[str]) -> bool:
    """True if a patch path names the target, its owning class, or its module."""
    if not modules:
        return dotted.split(".")[-1] == leaf
    for module in modules:
        if dotted == module:
            return True
        if dotted.startswith(module + "."):
            inside = dotted[len(module) + 1:].split(".")
            if inside[-1] == leaf or (owner and inside == [owner]):
                return True
    return False


def _keyword(node: ast.Call, name: str) -> Optional[ast.AST]:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _check_own_evidence(tree: ast.AST) -> Optional[Dict[str, Any]]:
    """Reject probes that print a canary they made or a value they read themselves."""
    handles = _file_handles(tree)
    tainted: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None and _reads(node.value, handles):
            for tgt in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                tainted.update(_names_in(tgt))
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and (_chain(node.func) or "") in _PRINTS):
            continue
        for arg in node.args:
            literal = _string(arg)
            if CANARY in literal and OBSERVATION not in literal:
                return _reject("probe_prints_fabricated_canary",
                               "probe prints a canary it produced: %r" % literal[:80])
            for item in ast.walk(arg):
                if isinstance(item, ast.Dict):
                    for key, value in zip(item.keys, item.values):
                        if _string(key).lower() in _EVIDENCE_KEYS and CANARY in _string(value):
                            return _reject("probe_prints_fabricated_canary",
                                           "probe reports a literal canary as %r" % _string(key))
            if _reads(arg, handles) or tainted.intersection(_names_in(arg)):
                return _reject("probe_reports_own_sensitive_read",
                               "probe prints a value it read itself rather than one the target returned")
    return None


def _file_handles(tree: ast.AST) -> Set[str]:
    """Names the probe binds to files it opened itself."""
    handles: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _is_opener(node.value):
            for tgt in node.targets:
                handles.update(_names_in(tgt))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if _is_opener(item.context_expr) and item.optional_vars is not None:
                    handles.update(_names_in(item.optional_vars))
    return handles


def _is_opener(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Call) and (_chain(node.func) or "") in _FILE_OPENERS


def _reads(node: ast.AST, handles: Set[str]) -> bool:
    """True if the expression reads a file the probe opened, or the environment."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _chain(child.func) or ""
            if name in {"os.getenv", "os.environ.get"}:
                return True
            if isinstance(child.func, ast.Attribute) and child.func.attr in _READ_METHODS:
                receiver = child.func.value
                if _is_opener(receiver) or (isinstance(receiver, ast.Name) and receiver.id in handles):
                    return True
        if isinstance(child, ast.Subscript) and _chain(child.value) == "os.environ":
            return True
    return False


def runtime_check(trace: Dict[str, Any], target_qualname: str) -> Dict[str, Any]:
    """Run F_att on a trace.

    A probe whose process never reached the target yields no admissible
    evidence. Nor does a probe that ran normally but printed all of its
    observations before the target was entered: those observations describe the
    probe's own actions, not the target's.
    """
    if not trace.get("target_seen") or not trace.get("frames"):
        return _reject(
            "target_frame_missing",
            "no frame for the target was recorded; the probe did not reach '%s'" % target_qualname,
        )
    observations = trace.get("observations") or []
    ended_normally = trace.get("completed") and not trace.get("killed_by_signal") and not trace.get("timed_out")
    if ended_normally and observations and not any(o.get("after_target", True) for o in observations):
        return _reject(
            "unattributed_evidence_event",
            "every observation was printed before the target ran",
        )
    return {"admitted": True, "rule": None, "detail": ""}


def _reject(rule: str, detail: str) -> Dict[str, Any]:
    return {"admitted": False, "rule": rule, "detail": detail}
