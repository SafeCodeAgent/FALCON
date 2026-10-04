# Security check — demo-app

> Overall verdict: **INSECURE**

| | |
|---|---|
| Repository | `demo-app` |
| Generated | 2026-10-04T17:08:06 |
| Scope | whole |
| Execution | host |
| Tool | attacker-verifier 0.2.0 |

## Summary

| Metric | Count |
|---|---:|
| Targets attacked | 2 |
| Probes generated | 5 |
| Probes admitted | 4 |
| Rejected before running (unfaithful) | 1 |
| Inconclusive (no evidence attributable to the target) | 0 |
| Insecure findings | 1 |
| Targets flagged insecure | 1 |

## Insecure findings

Each finding below is backed by a probe that ran against the target and an observed event in its execution trace.

### 1. app/files.py::load_report

- **Location:** `app/files.py` (line 6)
- **Weakness:** CWE-22 Path Traversal
- **Decided by:** stage 3 (trace judge)
- **Probe:** `pt1`

**Why it is unsafe**

> Path traversal (CWE-22): the name '../AV_CANARY_pt1.txt' was resolved outside the reports directory and load_report returned the planted file's contents. Resolve the path and reject names that leave REPORTS_DIR.

**Evidence**

> pt1 frames[0].return == 'AV_CANARY_pt1_secret' for args.name == '../AV_CANARY_pt1.txt'

**Trace excerpt**

```json
{
  "target": {
    "file": "/path/to/demo-app/app/files.py",
    "qualname": "load_report"
  },
  "target_seen": true,
  "target_active_at_exit": false,
  "frames": [
    {
      "func": "load_report",
      "file": "/path/to/demo-app/app/files.py",
      "line": 6,
      "args": {
        "name": "'../AV_CANARY_pt1.txt'"
      },
      "return": "'AV_CANARY_pt1_secret'",
      "exception": null
    }
  ],
  "observations": [
    {
      "input": "../AV_CANARY_pt1.txt",
      "return": "AV_CANARY_pt1_secret"
    }
  ],
  "stdout": "AV_OBSERVATION:{\"input\": \"../AV_CANARY_pt1.txt\", \"return\": \"AV_CANARY_pt1_secret\"}\n",
  "stderr": "",
  "top_level_exception": null,
  "returncode": 0,
  "killed_by_signal": false,
  "signal": null,
  "timed_out": false,
  "duration_s": 0.0586
}
```

## Per-target results

| Target | File | Verdict | Admitted | Rejected | Inconclusive |
|---|---|---|---:|---:|---:|
| `load_report` | `app/files.py` | INSECURE | 2 | 1 | 0 |
| `report_path` | `app/files.py` | SECURE | 2 | 0 | 0 |

## Faithfulness summary

Probes that would have reported their own behaviour instead of the target's are removed before they can count as evidence.

| Rule | Probes rejected |
|---|---:|
| `target_redefined` | 1 |

## Not attacked

Nothing in scope was skipped for language reasons.

## Run configuration

```json
{
  "attacker": "main coding agent",
  "verifier": "main coding agent",
  "probes_min": 5,
  "probes_max": 10,
  "num_turns": 2,
  "attacker_max_turns": 20,
  "max_targets": 20,
  "probe_timeout_s": 30,
  "probe_mem_mb": 1024,
  "model_timeout_s": 600,
  "execution": {
    "mode": "host",
    "image": null,
    "container": null,
    "workdir": "/work",
    "python": "python3"
  }
}
```

---

*A secure verdict means no admitted probe exposed a violation under the configured budget. Increase the probe budget or widen the scope for a more thorough check.*
