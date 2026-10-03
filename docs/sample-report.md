# Security check — demo-app

> Overall verdict: **INSECURE**

| | |
|---|---|
| Repository | `demo-app` |
| Generated | 2026-10-03T23:24:12 |
| Scope | whole |
| Execution | host |
| Tool | attacker-verifier 0.1.0 |

## Summary

| Metric | Count |
|---|---:|
| Targets attacked | 1 |
| Probes generated | 1 |
| Probes admitted | 1 |
| Rejected before running (unfaithful) | 0 |
| Inconclusive (did not reach target) | 0 |
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

> Path traversal: a canary planted above the reports directory was read back through load_report, so the function follows ../ outside its intended root (CWE-22). Normalise the path and confirm it stays within REPORTS_DIR.

**Evidence**

> pt1 observation: return == 'AV_CANARY_pt_topsecret' for input '../AV_CANARY_pt.txt'

**Trace excerpt**

```json
{
  "target": {
    "file": "/path/to/demo-app/app/files.py",
    "qualname": "load_report"
  },
  "target_seen": true,
  "frames": [
    {
      "func": "load_report",
      "file": "/path/to/demo-app/app/files.py",
      "line": 6,
      "args": {
        "name": "'../AV_CANARY_pt.txt'"
      },
      "return": "'AV_CANARY_pt_topsecret'",
      "exception": null
    }
  ],
  "observations": [
    {
      "input": "../AV_CANARY_pt.txt",
      "return": "AV_CANARY_pt_topsecret"
    }
  ],
  "stdout": "AV_OBSERVATION:{\"input\": \"../AV_CANARY_pt.txt\", \"return\": \"AV_CANARY_pt_topsecret\"}\n",
  "stderr": "",
  "top_level_exception": null,
  "returncode": 0,
  "signal": null,
  "timed_out": false,
  "duration_s": 0.0595
}
```

## Per-target results

| Target | File | Verdict | Admitted | Rejected | Inconclusive |
|---|---|---|---:|---:|---:|
| `load_report` | `app/files.py` | INSECURE | 1 | 0 | 0 |

## Faithfulness summary

Probes that would have reported their own behaviour instead of the target's are removed before they can count as evidence.

No probes were rejected by the faithfulness checks.

## Not attacked

The following were present but not attacked in this run (the current version attacks Python):

- No non-Python files in scope

## Run configuration

```json
{
  "attacker": "main",
  "verifier": "main",
  "probes_min": 5,
  "probes_max": 10,
  "num_turns": 2,
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
