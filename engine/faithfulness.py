"""Faithfulness checks for probes.

A probe is only useful as evidence if the behaviour it reports was actually
produced by the target under test. Two predicates enforce that:

* :func:`static_check` (F_stat) runs before execution. It parses the probe and
  rejects it if the probe redefines or rebinds the target, rebinds the module
  path that reaches it, replaces the target with a mock, or otherwise arranges
  to observe its own behaviour instead of the target's.
* :func:`runtime_check` (F_att) runs on the resulting trace. It confirms the
  probe actually reached the target and that there is a target frame to which
  the observed behaviour can be attributed.

A probe rejected by ``static_check`` never runs. A probe rejected by
``runtime_check`` has run but yields no admissible evidence; it is recorded as
inconclusive. Admitted probes pass both.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional, Tuple

# Names whose use to swap out a symbol makes a probe unfaithful.
_PATCH_CALLS = {"patch", "patch.object", "setattr", "monkeypatch.setattr"}
_MODULE_INJECTORS = {"sys.modules"}


def _target_names(target_qualname: str) -> Tuple[str, Optional[str]]:
    """Return (leaf_name, owner_name) for a target qualified name.

    For ``Report.load`` this is ("load", "Report"); for ``load_report`` it is
    ("load_report", None).
    """
    parts = target_qualname.split(".")
    leaf = parts[-1]
    owner = parts[-2] if len(parts) >= 2 else None
    return leaf, owner


def _attr_chain(node: ast.AST) -> Optional[str]:
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


def static_check(
    probe_source: str,
    target_qualname: str,
    module_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Run F_stat on one probe's source.

    Returns ``{"admitted": bool, "rule": str | None, "detail": str}``. ``rule``
    names the first rule that rejected the probe.
    """
    if not probe_source or not probe_source.strip():
        return _reject("no_probe_files", "probe is empty")

    try:
        tree = ast.parse(probe_source)
    except SyntaxError as exc:
        return _reject("parse_error", "probe does not parse: %s" % exc)

    leaf, owner = _target_names(target_qualname)
    module_leaf = module_name.split(".")[-1] if module_name else None

    for node in ast.walk(tree):
        # target_redefined: the probe defines the target itself.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == leaf:
                return _reject(
                    "target_redefined",
                    "probe defines its own '%s', shadowing the target" % leaf,
                )

        # target_rebound / module_path_rebound: assignment over the target or
        # the module path that reaches it.
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for tgt in targets:
                chain = _attr_chain(tgt) or (tgt.id if isinstance(tgt, ast.Name) else None)
                if chain is None:
                    continue
                tail = chain.split(".")[-1]
                if tail == leaf:
                    return _reject(
                        "target_rebound", "probe assigns over the target '%s'" % chain
                    )
                if module_leaf and tail == module_leaf:
                    return _reject(
                        "module_path_rebound",
                        "probe rebinds the module path '%s' reaching the target" % chain,
                    )

        # target_path_replaced: mock/patch/monkeypatch aimed at the target.
        if isinstance(node, ast.Call):
            call_name = _attr_chain(node.func)
            if call_name:
                tail = call_name.split(".")[-1]
                if tail in {"patch", "object", "setattr"} or call_name in _PATCH_CALLS:
                    arg_text = _first_string_arg(node)
                    if arg_text and (leaf in arg_text or (module_name and module_name in arg_text)):
                        return _reject(
                            "target_path_replaced",
                            "probe patches/mocks the target via %s(%r)" % (call_name, arg_text),
                        )

        # module_path_rebound via sys.modules[...] = ...
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Subscript):
                    base = _attr_chain(tgt.value)
                    if base in _MODULE_INJECTORS:
                        return _reject(
                            "module_path_rebound",
                            "probe injects into sys.modules, replacing a real module",
                        )

    return {"admitted": True, "rule": None, "detail": ""}


def _first_string_arg(call: ast.Call) -> Optional[str]:
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    return None


def runtime_check(trace: Dict[str, Any], target_qualname: str) -> Dict[str, Any]:
    """Run F_att on a trace.

    A probe whose process never reached the target, or that reports an evidence
    event with no target frame behind it, yields no admissible evidence.
    """
    # A process killed by a signal still counts as having exercised the target
    # if a target frame was recorded before the crash; the crash oracle will
    # read it. Only treat "no frame at all" as unattributable.
    if not trace.get("target_seen"):
        # If the process was killed before the harness could record a frame but
        # clearly started the target, we cannot attribute anything.
        return _reject(
            "target_frame_missing",
            "no frame for the target was recorded; the probe did not reach '%s'"
            % target_qualname,
        )

    if not trace.get("frames"):
        return _reject(
            "target_frame_missing", "target reported seen but no frame captured"
        )

    # unattributed_evidence_event: an observation that claims an effect but the
    # trace holds no target frame to back it is not admissible. Here target_seen
    # is true, so observations are attributable; this is the hook where a
    # stricter per-event policy would live.
    return {"admitted": True, "rule": None, "detail": ""}


def _reject(rule: str, detail: str) -> Dict[str, Any]:
    return {"admitted": False, "rule": rule, "detail": detail}
