"""Deterministic Markdown report for a security check.

The report always follows the same structure so results are comparable across
runs and easy to diff:

1. Title and run metadata
2. Verdict summary with counts
3. Insecure findings -- the parts of the repository judged unsafe
4. Per-target results table
5. Faithfulness summary (rejected and inconclusive probes)
6. Not attacked (files or languages skipped this run)
7. Run configuration

:func:`render_markdown` takes the finalised run structure produced by the CLI
and returns the report text; it performs no analysis of its own.
"""

from __future__ import annotations

from typing import Any, Dict, List

_VERDICT_BADGE = {
    "insecure": "INSECURE",
    "secure": "SECURE",
    "no-evidence": "NO EVIDENCE",
}


def render_markdown(final: Dict[str, Any]) -> str:
    meta = final["meta"]
    stats = final["stats"]
    findings = final["findings"]
    per_target = final["per_target"]

    lines: List[str] = []
    out = lines.append

    out("# Security check — %s" % meta["repo_name"])
    out("")
    out("> Overall verdict: **%s**" % _VERDICT_BADGE.get(final["signal"], final["signal"].upper()))
    out("")
    out("| | |")
    out("|---|---|")
    out("| Repository | `%s` |" % meta["repo_name"])
    out("| Generated | %s |" % meta["generated_at"])
    out("| Scope | %s |" % meta["scope_label"])
    out("| Execution | %s |" % meta["execution_label"])
    out("| Tool | attacker-verifier %s |" % meta["tool_version"])
    out("")

    out("## Summary")
    out("")
    out("| Metric | Count |")
    out("|---|---:|")
    out("| Targets attacked | %d |" % stats["targets"])
    out("| Probes generated | %d |" % stats["probes_total"])
    out("| Probes admitted | %d |" % stats["admitted"])
    out("| Rejected before running (unfaithful) | %d |" % stats["rejected_static"])
    out("| Inconclusive (did not reach target) | %d |" % stats["inconclusive"])
    out("| Insecure findings | %d |" % stats["findings"])
    out("| Targets flagged insecure | %d |" % stats["targets_insecure"])
    out("")

    out("## Insecure findings")
    out("")
    if not findings:
        out("No admitted probe produced a security violation in this run. This "
            "means no attack in the current budget exposed unsafe behaviour; it "
            "is not a proof that the code is free of vulnerabilities.")
        out("")
    else:
        out("Each finding below is backed by a probe that ran against the target "
            "and an observed event in its execution trace.")
        out("")
        for index, finding in enumerate(findings, start=1):
            target = finding["target"]
            out("### %d. %s" % (index, _target_label(target)))
            out("")
            out("- **Location:** `%s`%s" % (
                target.get("file", "?"),
                (" (line %s)" % target["lineno"]) if target.get("lineno") else "",
            ))
            out("- **Weakness:** %s" % (finding.get("cwe") or "see reason"))
            out("- **Decided by:** stage %s (%s)" % (
                finding.get("stage", "?"),
                "crash oracle" if finding.get("stage") == 1 else "trace judge",
            ))
            out("- **Probe:** `%s`" % finding.get("id", "?"))
            out("")
            out("**Why it is unsafe**")
            out("")
            out("> " + _blockquote(finding.get("reason", "(no reason recorded)")))
            out("")
            evidence = finding.get("evidence")
            if evidence:
                out("**Evidence**")
                out("")
                out("> " + _blockquote(evidence))
                out("")
            excerpt = finding.get("trace_excerpt")
            if excerpt:
                out("**Trace excerpt**")
                out("")
                out("```json")
                out(excerpt)
                out("```")
                out("")

    out("## Per-target results")
    out("")
    out("| Target | File | Verdict | Admitted | Rejected | Inconclusive |")
    out("|---|---|---|---:|---:|---:|")
    for row in per_target:
        out("| `%s` | `%s` | %s | %d | %d | %d |" % (
            row["qualname"], row["file"],
            _VERDICT_BADGE.get(row["signal"], row["signal"]),
            row["admitted"], row["rejected_static"], row["inconclusive"],
        ))
    out("")

    out("## Faithfulness summary")
    out("")
    out("Probes that would have reported their own behaviour instead of the "
        "target's are removed before they can count as evidence.")
    out("")
    if stats["rule_counts"]:
        out("| Rule | Probes rejected |")
        out("|---|---:|")
        for rule, count in sorted(stats["rule_counts"].items(), key=lambda kv: -kv[1]):
            out("| `%s` | %d |" % (rule, count))
    else:
        out("No probes were rejected by the faithfulness checks.")
    out("")

    out("## Not attacked")
    out("")
    skipped = meta.get("skipped_languages") or []
    if skipped:
        out("The following were present but not attacked in this run "
            "(the current version attacks Python):")
        out("")
        for item in skipped:
            out("- %s" % item)
    else:
        out("Nothing in scope was skipped for language reasons.")
    out("")

    out("## Run configuration")
    out("")
    out("```json")
    out(final["config_json"])
    out("```")
    out("")
    out("---")
    out("")
    out("*A secure verdict means no admitted probe exposed a violation under the "
        "configured budget. Increase the probe budget or widen the scope for a "
        "more thorough check.*")
    return "\n".join(lines) + "\n"


def _target_label(target: Dict[str, Any]) -> str:
    return "%s::%s" % (target.get("file", "?"), target.get("qualname", "?"))


def _blockquote(text: str) -> str:
    return str(text).replace("\n", "\n> ")
