# Test-time repair on CWEval and SecCodeBench-V2

The `av_signal` package computes the security signal for a candidate program
and runs the repair loop of Sections 4.2.1 and 4.2.2 of the paper: a coding
model writes a solution, the solution is attacked and the traces verified, and
any observed violation is returned to the model for another attempt, up to five
checks. The RL experiments in `../rl/` use the same package.

Benchmark scripts are in [CWEval/](CWEval/README.md) and
[sec-code-bench/](sec-code-bench/README.md). Each prepares public task
workspaces, runs the repair loop, and grades the saved candidates with the
benchmark's own tests.

## Setup

```bash
pip install -e '.[test]'
docker build -f Dockerfile.python -t av-python:latest .
export OPENAI_API_KEY=...            # and OPENAI_BASE_URL for a compatible endpoint
```

The coding model, the attacker, and the Stage 3 judge use the same model name,
as in the paper.

## Commands

Prepare tasks:

```bash
av-repair prepare --benchmark cweval --benchmark-root /path/to/CWEval --output outputs/cweval
av-repair prepare --benchmark seccodebench-v2 --benchmark-root /path/to/sec-code-bench \
  --scenario gen --output outputs/seccodebench
```

The SecCodeBench checkout has prompts for Python, Go, C/C++, and JavaScript.
Java prompts are fetched from a remote service, so supply them with
`--prompt-map public_prompts.json`, a JSON object of public prompt strings
keyed by `java/<case id>/<scenario>`. It must not contain tests or labels.

Repair:

```bash
av-repair run --manifest outputs/cweval/manifest.jsonl --output outputs/cweval \
  --model MODEL_NAME --image av-python:latest
```

`--limit 1` runs one task. `--rounds` (default 5) caps the number of checks, and
`--min-probes`/`--max-probes` (default 5 and 10) set the probe budget per target
(the attacker-budget sweep in Appendix C.2 uses 1, 2–5, 5–10, and 10–20). The
loop stops when a check finds no violation. Each task's checked candidates and
`history.json` are saved under `outputs/<benchmark>/runs/...`. An insecure
check sends the coding model the probe, its trace, and the reason.

Signal for an existing candidate:

```bash
av-signal --task-file task.txt --workspace candidate/ --changed solution.py \
  --model MODEL_NAME --mode full --output signal.json
```

`--mode core` runs only the deterministic stages (no model calls when probes
are supplied). `--probes probes.json` supplies fixed probes as a JSON object
keyed by `path::symbol`.

Held-out grading, after repair:

```bash
docker build -t cweval-runtime:latest /path/to/CWEval
av-heldout --manifest outputs/cweval/manifest.jsonl --benchmark-root /path/to/CWEval \
  --cweval-image cweval-runtime:latest --output outputs/cweval/heldout.json
av-heldout --manifest outputs/seccodebench/manifest.jsonl \
  --benchmark-root /path/to/sec-code-bench --output outputs/seccodebench/heldout.json
```

The CWEval image must provide the `cweval` package, compilers, dependencies,
and pytest. The SecCodeBench grader calls the benchmark's verifier services on
local ports 24683 to 24687. The signal and the repair loop never import either
grader.

## How the signal works

`SecuritySignal.evaluate` in `av_signal/signal.py`:

1. selects the functions, methods, and classes in the changed non-test files
   (`targets.py`);
2. asks the attacker for 5 to 10 deterministic probes per target, with one
   follow-up listing validation errors; invalid probes are dropped
   (`prompts.py`);
3. applies the static faithfulness rules (`faithfulness.py`);
4. runs each probe in its own container: no network, read-only workspace with
   tests removed, 512 MB, one CPU, and a 20-second limit (`executor.py`);
5. applies the runtime faithfulness rules;
6. runs the verifier (`verifier.py`);
7. reports `insecure` if any admitted trace is insecure, `secure` if at least
   one probe was admitted, and `no-evidence` otherwise.

The verifier stages:

- Stage 1, `stage_1_crash_oracle`: a memory error or sanitizer abort on the
  target path, or an exception that escapes the target and the probe.
- Stage 2, `stage_2_cwe_oracle`: the 21 ordered `DETECTORS`, covering 33 CWE
  identifiers. Each needs a runtime event; detectors that need policy fields
  (`intended_root`, `allowed_hosts`, `forbidden_algorithms`, …) fire only when
  a trusted adapter supplies them. If none fires, a benign rule clears traces
  with no suspicious event and no probe payload in the target's output.
- Stage 3, `SecuritySignal.stage_3_trace_judge`: the model judge sees the public
  task and the trace, nothing else (`judge_prompt` in `prompts.py`).

`verify_core` runs Stages 1 and 2. In `mode="full"` uncertain traces go to
Stage 3. In `mode="core"`, used for RL, the security reward is 0 only for an
insecure verdict and 1 otherwise (`SignalResult.rl_security_reward`).

`trace_runner.py` runs inside the probe container. It records target frames,
calls and returns, output, process, network, and file events, and SQLite
queries made under a target frame, and prints them as one `AV_TRACE:` record.
It also writes the target frames to a scratch file whenever a target call
starts or ends, so a probe killed by the time or memory limit while the target
is running is still attributed to the target (the resource-exhaustion
detector).

## Other languages

The Docker executor attributes frames for Python only. For C, C++, Go, Java,
and JavaScript tasks, pass `--adapter-command` with a trusted sandbox adapter.
It reads one JSON request on stdin (workspace, target, probe, timeout, memory
limit) and prints a `Trace` object (see `av_signal/models.py`). The adapter must
record target frames and attributed events with its own instrumentation;
repeating frames the probe printed is not enough. `av-repair run` refuses
non-Python tasks without an adapter.

## Tests

```bash
python -m pytest -q tests
```

The tests cover every detector, the stage entry points, faithfulness rules,
event normalization, probe generation retries, and the trace runner's
behaviour when a probe is killed. They need neither Docker nor model access.
