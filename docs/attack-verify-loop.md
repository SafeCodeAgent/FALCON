# The attack → verify loop

This is the shared procedure both skills use to attack code and judge the
results. It runs one **pass** over a scope. `/check-code-security` runs a single
pass and reports; `/secure-code-generation` runs a pass, repairs, and loops.

Throughout, show progress on its own line so the user can follow which agent is
working and where in the run you are:

```
[attacker-verifier] turn <t>/<N> · <agent> · <what> (<counts>)
```

where `<agent>` is one of `attacker`, `verifier`, or `main coding agent`.

## Configuration for the run

Resolve settings in this order, each overriding the previous: engine defaults →
`.attacker-verifier/config.json` at the repo root (if present) → the arguments
the user passed to the skill. Build a single JSON string, `CONFIG_JSON`, holding
the non-default settings plus the `execution` block from the session marker.
Recognised settings:

| Setting | Meaning | Default |
|---|---|---|
| `probes_min`, `probes_max` | probe budget per target (`--probes 5-10`) | 5, 10 |
| `attacker` | `main coding agent` (inline) or a model name (`--attacker opus`) | `main coding agent` |
| `verifier` | `main coding agent` (inline) or a model name (`--verifier sonnet`) | `main coding agent` |
| `num_turns` | repair cycles, generation only (`--turns 2`) | 2 |
| `max_targets` | cap on targets attacked (`--max-targets 20`) | 20 |
| `execution` | sandbox block from the session marker | `{"mode":"host"}` |

Keep a per-run scratch directory for intermediate files:
`RUN_DIR="${CLAUDE_PLUGIN_DATA}/runs/${CLAUDE_SESSION_ID}-<timestamp>"`.

## Steps

### 1. Select targets — deterministic

```
python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" select-targets \
  --repo "<repo>" --scope <whole|changed|path> [--path <P>] \
  --out "$RUN_DIR/targets.json" --config-json "$CONFIG_JSON"
```

Read `targets.json`. It lists the functions, methods, and classes to attack,
ranked by security relevance, with the probe budget (`probes_min`,
`probes_max`). If it is empty, tell the user nothing was in scope and stop.

Progress: `turn t/N · main coding agent · selected K target(s)`.

### 2. Attack — the attacker agent

The attacker proposes probes. It is an **agent**, not a single reply: it may
read the code and the repository and iterate, up to 20 turns, before writing its
probes. Read the attacker prompt at
`${CLAUDE_PLUGIN_ROOT}/engine/prompts/attacker.md` and follow it exactly.

- If `attacker` is `main coding agent` (default): **you** play the attacker,
  inline. For each target, work through the attacker prompt and produce between
  `probes_min` and `probes_max` deterministic probes. Explore the target as
  needed before committing probes — treat your budget as up to 20 steps of
  attacker work.
- If `attacker` is a model name (e.g. `opus`): delegate to the
  `attacker-verifier:attacker` subagent via the Agent tool with `model` set to
  that value (it runs up to 20 turns), passing the target, the task, and the
  path to write to.

Collect all probes into one file `"$RUN_DIR/probes.json"`:

```json
{ "probes": [
  { "id": "unique_id", "target": "path.py::Qualified.symbol",
    "cwe": "weakness name or id", "rationale": "what it exercises, no verdict",
    "script": "complete deterministic Python script" }
] }
```

Never put an expected output or a verdict in a probe. Never read repository
tests. Write only inside `AV_SCRATCH`. Print at least one
`AV_OBSERVATION:<json>` line per probe and mark payloads with `AV_CANARY_<id>`.

Progress: `turn t/N · attacker · wrote P probe(s) for K target(s)`.

### 3. Screen, run, and crash-check — deterministic (sandbox)

```
python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" check \
  --repo "<repo>" --targets "$RUN_DIR/targets.json" \
  --probes "$RUN_DIR/probes.json" --out "$RUN_DIR/run.json" \
  --traces-out "$RUN_DIR/traces.json" --config-json "$CONFIG_JSON"
```

This removes probes that would report their own behaviour (faithfulness check),
runs the admitted probes in the sandbox, applies the crash oracle, and writes
any trace it could not decide to `traces.json`.

Progress: `turn t/N · verifier · sandbox ran A probe(s), S undecided`.

### 4. Judge undecided traces — the verifier (stage 3)

Read `"$RUN_DIR/traces.json"`. If its `traces` array is empty, skip to step 5.
Otherwise judge each trace with the stage-3 prompt at
`${CLAUDE_PLUGIN_ROOT}/engine/prompts/verifier_stage3.md`, reading **only** the
trace — not the source, the patch, or any test.

- If `verifier` is `main coding agent` (default): you judge each trace inline.
- If `verifier` is a model name: delegate to the `attacker-verifier:verifier`
  subagent via the Agent tool with `model` set to that value.

Write the verdicts to `"$RUN_DIR/verdicts.json"`:

```json
{ "<probe_id>": { "verdict": "secure" | "insecure",
  "reason": "name the weakness and the behaviour that shows it",
  "evidence": "probe id and the trace field the verdict rests on",
  "confidence": "high" | "low" } }
```

Progress: `turn t/N · verifier · judged S trace(s), I insecure`.

### 5. Aggregate

```
python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" finalize \
  --run "$RUN_DIR/run.json" --verdicts "$RUN_DIR/verdicts.json" \
  --final-out "$RUN_DIR/final.json" --out "<report-or-omit>" \
  [--skipped "<notes on non-Python files not attacked>"]
```

`final.json` carries the per-target signal and the counterexamples (the unsafe
findings). The signal for a target is **insecure** if any admitted probe is
insecure, **secure** if the admitted set is non-empty and none is insecure, and
**no-evidence** if no probe was admitted.

For `/check-code-security`, pass `--out "<repo>_<timestamp>.md"` to write the
report. For `/secure-code-generation`, omit `--out` during the loop and use
`final.json` to drive repair; write a report only if the user asks.
