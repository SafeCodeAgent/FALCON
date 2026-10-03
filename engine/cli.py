#!/usr/bin/env python3
"""Command-line entry point for the attacker-verifier engine.

Subcommands, in the order a run uses them:

    select-targets   Rank attack targets in a scope and write targets.json.
    check            Screen probes for faithfulness, run the admitted ones in a
                     sandbox, apply the crash oracle, and write run.json plus a
                     traces file for any trace the deterministic stage leaves
                     undecided.
    finalize         Merge the trace-judge verdicts into run.json, aggregate the
                     signal, and write the Markdown report.
    session          Read or write the per-session execution-mode marker.
    config           Print the effective configuration.
    version          Print the engine version.

The coding agent runs these around its own two jobs -- proposing probes and
judging the undecided traces -- as described in the skill instructions.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import __version__, config as config_mod  # noqa: E402
from engine import faithfulness, models as models_mod, report, runner, targets as targets_mod, verifier  # noqa: E402

STDOUT_EXCERPT = 1500


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _progress(message: str) -> None:
    sys.stderr.write("[attacker-verifier] %s\n" % message)
    sys.stderr.flush()


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def _timestamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def _repo_name(repo_root: str) -> str:
    return os.path.basename(os.path.abspath(repo_root)) or "repo"


def _trace_excerpt(trace: Dict[str, Any]) -> Dict[str, Any]:
    stdout = trace.get("stdout", "") or ""
    return {
        "target": trace.get("target", {}),
        "target_seen": trace.get("target_seen", False),
        "frames": trace.get("frames", []),
        "observations": [o.get("parsed", o.get("raw")) for o in trace.get("observations", [])],
        "stdout": stdout[:STDOUT_EXCERPT],
        "stderr": (trace.get("stderr", "") or "")[:600],
        "top_level_exception": trace.get("top_level_exception"),
        "returncode": trace.get("returncode"),
        "signal": trace.get("signal"),
        "timed_out": trace.get("timed_out", False),
        "duration_s": trace.get("duration_s"),
    }


# --------------------------------------------------------------------------- #
# select-targets
# --------------------------------------------------------------------------- #
def cmd_select_targets(args: argparse.Namespace) -> int:
    cfg = config_mod.load_config(args.repo, args.config_json)
    found = targets_mod.select_targets(
        args.repo, scope=args.scope, path=args.path, max_targets=cfg["max_targets"]
    )
    for target in found:
        target.pop("source", None)  # keep targets.json small; skill re-reads files
    payload = {
        "schema": "attacker-verifier/targets@1",
        "repo_root": os.path.abspath(args.repo),
        "scope": args.scope,
        "path": args.path,
        "max_targets": cfg["max_targets"],
        "probes_min": cfg["probes_min"],
        "probes_max": cfg["probes_max"],
        "targets": found,
    }
    _write_json(args.out, payload)
    _progress("selected %d target(s) in scope '%s' -> %s" % (len(found), args.scope, args.out))
    return 0


# --------------------------------------------------------------------------- #
# check
# --------------------------------------------------------------------------- #
def _resolve_target(repo_root: str, target_str: str, lookup: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    target_str = target_str.strip()
    if target_str in lookup:
        return lookup[target_str]
    if "::" in target_str:
        file_part, qual = target_str.split("::", 1)
    elif ":" in target_str and target_str.count(":") == 1:
        file_part, qual = target_str.split(":", 1)
    else:
        # Match by qualname alone if unambiguous.
        matches = [t for t in lookup.values() if t["qualname"] == target_str]
        return matches[0] if len(matches) == 1 else None
    file_part = file_part.strip()
    qual = qual.strip()
    key = "%s::%s" % (file_part, qual)
    if key in lookup:
        return lookup[key]
    abspath = os.path.join(repo_root, file_part)
    if os.path.isfile(abspath):
        return {"file": file_part, "qualname": qual, "kind": "function", "lineno": None, "score": 0}
    return None


def _module_name(rel_file: str) -> str:
    return os.path.splitext(os.path.basename(rel_file))[0]


def cmd_check(args: argparse.Namespace) -> int:
    cfg = config_mod.load_config(args.repo, args.config_json)
    repo_root = os.path.abspath(args.repo)
    targets_doc = _load_json(args.targets)
    probes_doc = _load_json(args.probes)

    lookup: Dict[str, Dict[str, Any]] = {}
    for target in targets_doc.get("targets", []):
        lookup["%s::%s" % (target["file"], target["qualname"])] = target

    probe_list = probes_doc.get("probes", [])
    _progress("checking %d probe(s) across %d target(s)" % (len(probe_list), len(lookup) or len(targets_doc.get("targets", []))))

    traces_dir = args.traces_dir or os.path.join(os.path.dirname(os.path.abspath(args.out)), "traces")
    os.makedirs(traces_dir, exist_ok=True)

    results: List[Dict[str, Any]] = []
    uncertain: List[Dict[str, Any]] = []

    for order, probe in enumerate(probe_list):
        probe_id = str(probe.get("id") or "probe_%d" % order)
        target_str = str(probe.get("target", ""))
        target = _resolve_target(repo_root, target_str, lookup)
        record: Dict[str, Any] = {
            "id": probe_id,
            "target": {"file": (target or {}).get("file"), "qualname": (target or {}).get("qualname"),
                       "lineno": (target or {}).get("lineno")},
            "cwe": probe.get("cwe"),
            "rationale": probe.get("rationale"),
        }

        if target is None:
            record.update(status="inconclusive",
                          faithfulness={"stage": "runtime", "rule": "target_not_inferred",
                                        "detail": "probe names no resolvable target: %r" % target_str})
            results.append(record)
            continue

        script = probe.get("script", "")
        # Stage the probe inside the repo so its imports resolve from the root.
        probe_path = os.path.join(repo_root, ".attacker-verifier", "probes", "%s.py" % _safe_name(probe_id))
        os.makedirs(os.path.dirname(probe_path), exist_ok=True)
        with open(probe_path, "w", encoding="utf-8") as handle:
            handle.write(script)
        record["probe_path"] = os.path.relpath(probe_path, repo_root)

        fstat = faithfulness.static_check(script, target["qualname"], _module_name(target["file"]))
        if not fstat["admitted"]:
            record.update(status="rejected_static",
                          faithfulness={"stage": "static", "rule": fstat["rule"], "detail": fstat["detail"]})
            results.append(record)
            _progress("  %s: rejected before running (%s)" % (probe_id, fstat["rule"]))
            continue

        target_file_abs = os.path.join(repo_root, target["file"])
        trace = runner.run_probe(repo_root, probe_path, target_file_abs, target["qualname"], cfg)

        fatt = faithfulness.runtime_check(trace, target["qualname"])
        if not fatt["admitted"]:
            record.update(status="inconclusive",
                          faithfulness={"stage": "runtime", "rule": fatt["rule"], "detail": fatt["detail"]})
            results.append(record)
            _progress("  %s: inconclusive (%s)" % (probe_id, fatt["rule"]))
            continue

        core = verifier.core_verdict(trace)
        excerpt = _trace_excerpt(trace)
        record.update(status="admitted", faithfulness={"stage": None, "rule": None, "detail": ""},
                      core=core, trace_excerpt=excerpt)
        results.append(record)

        if core["verdict"] == verifier.INSECURE:
            _progress("  %s: INSECURE (stage 1 crash oracle)" % probe_id)
        else:
            trace_path = os.path.join(traces_dir, "%s.json" % _safe_name(probe_id))
            _write_json(trace_path, excerpt)
            uncertain.append({"id": probe_id, "target": record["target"],
                              "cwe": probe.get("cwe"), "rationale": probe.get("rationale"),
                              "trace": excerpt})
            _progress("  %s: admitted, needs trace judge" % probe_id)

    run = {
        "schema": "attacker-verifier/run@1",
        "tool_version": __version__,
        "repo_name": _repo_name(repo_root),
        "repo_root": repo_root,
        "scope": targets_doc.get("scope"),
        "path": targets_doc.get("path"),
        "execution": {k: cfg["execution"].get(k) for k in ("mode", "image", "container")},
        "config": _safe_config(cfg),
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "targets": targets_doc.get("targets", []),
        "results": results,
    }
    _write_json(args.out, run)

    judge_doc = {
        "schema": "attacker-verifier/traces@1",
        "instructions": "Judge each trace with the stage-3 trace-judge prompt. "
                        "Write verdicts to a JSON object mapping probe id -> "
                        "{verdict: secure|insecure, reason, evidence, confidence}.",
        "traces": uncertain,
    }
    _write_json(args.traces_out, judge_doc)

    admitted = sum(1 for r in results if r["status"] == "admitted")
    stage1 = sum(1 for r in results if r.get("core", {}).get("verdict") == verifier.INSECURE)
    _progress("done: %d admitted, %d insecure by crash oracle, %d awaiting trace judge -> %s"
              % (admitted, stage1, len(uncertain), args.traces_out))
    return 0


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80] or "probe"


def _safe_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(cfg)
    return out


# --------------------------------------------------------------------------- #
# finalize
# --------------------------------------------------------------------------- #
def cmd_finalize(args: argparse.Namespace) -> int:
    run = _load_json(args.run)
    verdicts = _load_json(args.verdicts) if args.verdicts and os.path.isfile(args.verdicts) else {}

    results = run.get("results", [])
    by_target: Dict[str, List[Dict[str, Any]]] = {}
    for record in results:
        key = "%s::%s" % (record["target"].get("file"), record["target"].get("qualname"))
        by_target.setdefault(key, []).append(record)

    per_target: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    rule_counts: Dict[str, int] = {}
    total_admitted = total_rejected = total_inconclusive = 0

    overall = verifier.NO_EVIDENCE
    for key, records in by_target.items():
        agg = verifier.aggregate(records, verdicts)
        admitted = sum(1 for r in records if r["status"] == "admitted")
        rejected = sum(1 for r in records if r["status"] == "rejected_static")
        inconclusive = sum(1 for r in records if r["status"] == "inconclusive")
        total_admitted += admitted
        total_rejected += rejected
        total_inconclusive += inconclusive
        for record in records:
            rule = record.get("faithfulness", {}).get("rule")
            if rule:
                rule_counts[rule] = rule_counts.get(rule, 0) + 1

        file_part, _, qual = key.partition("::")
        per_target.append({
            "file": file_part, "qualname": qual, "signal": agg["signal"],
            "admitted": admitted, "rejected_static": rejected, "inconclusive": inconclusive,
        })

        if agg["signal"] == verifier.INSECURE:
            overall = verifier.INSECURE
        elif overall != verifier.INSECURE and agg["signal"] == verifier.SECURE:
            overall = verifier.SECURE

        for counter in agg["counterexamples"]:
            record = next((r for r in records if r["id"] == counter["id"]), {})
            findings.append({
                "id": counter["id"],
                "stage": counter["stage"],
                "reason": counter["reason"],
                "evidence": counter.get("evidence", ""),
                "cwe": record.get("cwe"),
                "target": record.get("target", {}),
                "trace_excerpt": json.dumps(record.get("trace_excerpt", {}), indent=2)
                if record.get("trace_excerpt") else "",
            })

    per_target.sort(key=lambda r: (r["signal"] != "insecure", r["file"], r["qualname"]))
    findings.sort(key=lambda f: (f.get("stage") or 9, f["target"].get("file", "")))

    stats = {
        "targets": len(by_target),
        "probes_total": len(results),
        "admitted": total_admitted,
        "rejected_static": total_rejected,
        "inconclusive": total_inconclusive,
        "findings": len(findings),
        "targets_insecure": sum(1 for r in per_target if r["signal"] == "insecure"),
        "rule_counts": rule_counts,
    }

    execution = run.get("execution", {})
    execution_label = execution.get("mode", "host")
    if execution.get("mode") == "docker":
        execution_label = "docker (%s)" % (execution.get("image") or execution.get("container") or "?")

    scope_label = run.get("scope", "whole")
    if run.get("path"):
        scope_label = "%s · %s" % (scope_label, run["path"])

    final = {
        "signal": overall,
        "meta": {
            "repo_name": run.get("repo_name", "repo"),
            "generated_at": run.get("generated_at", datetime.datetime.now().isoformat(timespec="seconds")),
            "scope_label": scope_label,
            "execution_label": execution_label,
            "tool_version": run.get("tool_version", __version__),
            "skipped_languages": args.skipped.split(",") if args.skipped else [],
        },
        "stats": stats,
        "findings": findings,
        "per_target": per_target,
        "config_json": json.dumps(run.get("config", {}), indent=2),
    }

    text = report.render_markdown(final)
    repo_name = _repo_name(run.get("repo_root", "."))
    out_path = args.out or os.path.join(
        run.get("repo_root", "."), "%s_%s.md" % (_safe_name(repo_name), _timestamp())
    )
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    if args.final_out:
        _write_json(args.final_out, final)

    _progress("verdict: %s · %d finding(s) · report -> %s" % (overall.upper(), len(findings), out_path))
    print(out_path)
    return 0


# --------------------------------------------------------------------------- #
# session / config / version
# --------------------------------------------------------------------------- #
def cmd_session(args: argparse.Namespace) -> int:
    marker = os.path.join(args.data_dir, "sessions", "%s.json" % _safe_name(args.session_id))
    if args.set_json is not None:
        _write_json(marker, json.loads(args.set_json))
        _progress("recorded execution mode for session %s" % args.session_id)
        return 0
    if os.path.isfile(marker):
        print(json.dumps(_load_json(marker)))
        return 0
    print("")  # empty => not configured yet
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    cfg = config_mod.load_config(args.repo, args.config_json)
    print(json.dumps(cfg, indent=2))
    return 0


def cmd_list_models(args: argparse.Namespace) -> int:
    found = models_mod.list_models()
    if args.names_only:
        for model in found:
            print(model["name"])
        return 0
    print(json.dumps({
        "source": "claude-code model catalog (fable excluded)",
        "available": bool(found),
        "models": found,
    }, indent=2))
    return 0


def cmd_resolve_model(args: argparse.Namespace) -> int:
    resolved = models_mod.resolve(args.model)
    if resolved is None:
        sys.stderr.write("attacker-verifier: unknown or unsupported model: %r\n" % args.model)
        return 1
    print(resolved)
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    print(__version__)
    return 0


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="attacker-verifier", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    common_repo = {"default": ".", "help": "repository root (default: current dir)"}
    common_cfg = {"default": None, "help": "inline JSON config override"}

    p = sub.add_parser("select-targets", help="rank attack targets in a scope")
    p.add_argument("--repo", **common_repo)
    p.add_argument("--scope", choices=["whole", "changed", "path"], default="whole")
    p.add_argument("--path", default=None, help="file or directory for --scope path")
    p.add_argument("--out", required=True, help="where to write targets.json")
    p.add_argument("--config-json", **common_cfg)
    p.set_defaults(func=cmd_select_targets)

    p = sub.add_parser("check", help="screen, run, and crash-check probes")
    p.add_argument("--repo", **common_repo)
    p.add_argument("--targets", required=True, help="targets.json from select-targets")
    p.add_argument("--probes", required=True, help="probes.json from the attacker")
    p.add_argument("--out", required=True, help="where to write run.json")
    p.add_argument("--traces-out", required=True, help="where to write the trace-judge input")
    p.add_argument("--traces-dir", default=None, help="directory for individual trace files")
    p.add_argument("--config-json", **common_cfg)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("finalize", help="merge judge verdicts and write the report")
    p.add_argument("--repo", **common_repo)
    p.add_argument("--run", required=True, help="run.json from check")
    p.add_argument("--verdicts", default=None, help="trace-judge verdicts JSON (optional)")
    p.add_argument("--out", default=None, help="report path (default: <repo>_<ts>.md)")
    p.add_argument("--final-out", default=None, help="also write the finalised run JSON here")
    p.add_argument("--skipped", default=None, help="comma-separated 'not attacked' notes")
    p.set_defaults(func=cmd_finalize)

    p = sub.add_parser("session", help="read or write the per-session execution marker")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--set-json", default=None, help="record this execution config")
    p.set_defaults(func=cmd_session)

    p = sub.add_parser("config", help="print the effective configuration")
    p.add_argument("--repo", **common_repo)
    p.add_argument("--config-json", **common_cfg)
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("list-models", help="list Claude Code's live models (fable excluded)")
    p.add_argument("--names-only", action="store_true", help="print one model name per line")
    p.set_defaults(func=cmd_list_models)

    p = sub.add_parser("resolve-model", help="resolve a model name/alias to an Agent-tool model id")
    p.add_argument("model", help="e.g. 'Opus 5.5', 'opus', 'main coding agent'")
    p.set_defaults(func=cmd_resolve_model)

    p = sub.add_parser("version", help="print the engine version")
    p.set_defaults(func=cmd_version)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except config_mod.ConfigError as exc:
        sys.stderr.write("attacker-verifier: configuration error: %s\n" % exc)
        return 2
    except FileNotFoundError as exc:
        sys.stderr.write("attacker-verifier: %s\n" % exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
