"""The verifier's deterministic core and signal aggregation.

The verifier reads an execution trace and returns a verdict. Its deterministic
core decides only on positive evidence:

* :func:`crash_oracle` fires when the target terminates abnormally through a
  memory error or an abort/segfault-style signal. An exception the probe caught
  and recorded is not a crash; it is left for the trace judge.

Anything the core cannot decide is returned as ``uncertain`` and handed to the
Stage 3 trace judge, which the coding agent runs from the judge prompt. The
judge's verdicts are merged back in by :func:`aggregate`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

INSECURE = "insecure"
SECURE = "secure"
UNCERTAIN = "uncertain"
NO_EVIDENCE = "no-evidence"

# Signals that mean the process aborted abnormally rather than raising a normal,
# catchable exception.
_ABORT_SIGNALS = {4, 6, 8, 11}  # SIGILL, SIGABRT, SIGFPE, SIGSEGV


def crash_oracle(trace: Dict[str, Any]) -> Optional[str]:
    """Return a one-line reason if the trace shows a crash, else None."""
    if trace.get("killed_by_signal") and trace.get("signal") in _ABORT_SIGNALS:
        return (
            "target process aborted on signal %s during the exercised call"
            % trace.get("signal")
        )
    if trace.get("killed_by_signal"):
        # A non-abort signal kill (e.g. the CPU/memory rlimit) that happened
        # while the target was running is still an abnormal termination.
        if trace.get("target_seen"):
            return (
                "target process was killed (signal %s) while the exercised call "
                "was running" % trace.get("signal")
            )
    top = trace.get("top_level_exception")
    if top and top.get("is_memory_error") and top.get("through_target"):
        return "uncaught %s propagated out of the target" % top.get("type")
    return None


def core_verdict(trace: Dict[str, Any]) -> Dict[str, Any]:
    """Stage 1 verdict for a single admitted trace.

    Returns ``{"verdict": ..., "stage": 1|None, "reason": str}``. ``uncertain``
    means the deterministic core abstained and Stage 3 must decide.
    """
    reason = crash_oracle(trace)
    if reason is not None:
        return {"verdict": INSECURE, "stage": 1, "reason": reason}
    return {"verdict": UNCERTAIN, "stage": None, "reason": ""}


def aggregate(
    probe_results: List[Dict[str, Any]],
    stage3_verdicts: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Aggregate per-probe results into a target-level signal.

    ``probe_results`` is a list of the per-probe records produced by the check
    command (each with ``status`` and, for admitted probes, ``core``).
    ``stage3_verdicts`` maps a probe id to ``{"verdict": "secure"|"insecure",
    "reason": str, "evidence": str}`` for probes the core left uncertain.

    The signal is insecure if any admitted trace is insecure, secure if the
    admitted set is non-empty and none is insecure, and no-evidence otherwise.
    """
    stage3_verdicts = stage3_verdicts or {}
    admitted = 0
    counterexamples: List[Dict[str, Any]] = []
    resolved: List[Dict[str, Any]] = []

    for result in probe_results:
        if result.get("status") != "admitted":
            continue
        admitted += 1
        probe_id = result.get("id", "")
        core = result.get("core", {})
        verdict = core.get("verdict")
        reason = core.get("reason", "")
        stage = core.get("stage")

        if verdict == UNCERTAIN:
            judged = stage3_verdicts.get(probe_id)
            if judged is None:
                # Still undecided (judge not run yet): treat conservatively as
                # not-insecure for the signal, but flag it as pending.
                resolved.append({"id": probe_id, "verdict": UNCERTAIN, "stage": 3})
                continue
            verdict = judged.get("verdict", SECURE)
            reason = judged.get("reason", reason)
            stage = 3

        entry = {"id": probe_id, "verdict": verdict, "stage": stage, "reason": reason}
        resolved.append(entry)
        if verdict == INSECURE:
            counterexamples.append(
                {
                    "id": probe_id,
                    "stage": stage,
                    "reason": reason,
                    "evidence": (stage3_verdicts.get(probe_id, {}) or {}).get("evidence", ""),
                    "target": result.get("target", {}),
                    "probe_path": result.get("probe_path", ""),
                }
            )

    if counterexamples:
        signal = INSECURE
    elif admitted > 0:
        signal = SECURE
    else:
        signal = NO_EVIDENCE

    return {
        "signal": signal,
        "admitted": admitted,
        "counterexamples": counterexamples,
        "resolved": resolved,
    }
