# SusVibes: repair inside coding agents

This package runs the repository-level experiment (Section 4.2.3 and Appendix
C.5 of the paper). A coding agent edits a real repository to solve a SusVibes
task. Before its patch is accepted, the changed code is attacked and the traces
are verified; an observed violation goes back to the agent as feedback for
another round, up to five checks per task. SWE-agent, Claude Code, and OpenCode
are supported.

## What one check does

1. Targets are the changed functions, methods, and classes in non-test Python
   files of the candidate patch (`av_susvibes/targets.py`).
2. For each target the attacker model gets the public task, the non-test part of
   the diff, and the target, and returns 5 to 10 deterministic probes without
   expected outputs (`prompts.py`, `engine.py`).
3. The static faithfulness rules run before execution (`faithfulness.py`).
4. Each remaining probe runs in a fresh container from the task's
   `base_no_test_image_name` with the candidate patch applied and no network
   (`execution.py`). `probe_runner.py` records target frames, return values,
   exceptions, and file, process, network, output, logging, and mock-sink
   events attributed to the target.
5. The runtime faithfulness rules reject traces that never reach the target or
   offer events with no target frame behind them.
6. The verifier (`verifier.py`) applies the crash oracle (Stage 1), the 21
   ordered CWE detectors and the safe-evidence rule (Stage 2), and sends only
   the traces still undecided to the model judge (Stage 3).

| Stage | Entry point | Purpose |
| --- | --- | --- |
| 1 | `verify_stage_1` | crash on the exercised target path |
| 2 | `verify_stage_2` | 21 CWE detectors, then the safe-evidence rule |
| 3 | `verify_stage_3` | model judgment for traces left uncertain |

`check_workspace` in `engine.py` runs the whole check. A probe that never
reached its target is sent back to the attacker once with the runtime error.

The result is `insecure` if any admitted trace is insecure, `secure` if at
least one admitted trace was decided safe and none is insecure, and
`no-evidence` otherwise. Neither `secure` nor `no-evidence` means the
repository is free of vulnerabilities. SecPass, FuncPass, and Func-Sec@1 come
only from the held-out SusVibes tests.

## Requirements

- Python 3.11 or newer, a Docker daemon, and a Linux host (the model relay binds
  to a Docker network gateway).
- The SusVibes JSONL dataset and its task images. Inference uses only the
  no-test image; the evaluation image and test patches are used by the grader
  after predictions are saved.
- The coding agent for the run: SWE-agent 1.1.0 with SWE-ReX 1.4.0, Claude Code
  1.0.128 (installed into each task container), or OpenCode 1.18.16 (a
  standalone binary copied into each task container).
- An OpenAI-compatible endpoint for the attacker, the Stage 3 judge, and
  OpenCode: set `AV_API_BASE_URL` and `AV_API_KEY`, and `AV_API_MODE=responses`
  for a Responses endpoint. Claude Code also needs an Anthropic-compatible
  endpoint (`ANTHROPIC_BASE_URL`, and `ANTHROPIC_AUTH_TOKEN` or
  `ANTHROPIC_API_KEY`). Point both at the same underlying model.

Install from this directory:

```bash
python -m pip install -e .              # the package and the av-susvibes command
python -m pip install -e '.[grade]'     # dependencies of the SusVibes grader
python -m pip install -e vendor/swe-agent 'swe-rex==1.4.0'   # only for SWE-agent runs
```

## Check one candidate

```bash
export AV_API_BASE_URL=https://your-endpoint/v1
export AV_API_KEY=...
av-susvibes check \
  --repo /path/to/worktree-with-patch \
  --patch /path/to/candidate.patch \
  --task /path/to/public-task.txt \
  --image NO_TEST_IMAGE \
  --model MODEL_ID \
  --output runs/check-001
```

`--core` stops after Stages 1 and 2, the setting used for the RL reward.
`--local-development` runs probes in a local subprocess instead of Docker; it
has no isolation and is meant for development only.

## Repair runs

Claude Code and OpenCode:

```bash
av-susvibes run-batch --dataset /path/to/susvibes_dataset.jsonl \
  --harness claude-code --model MODEL_ID --output runs/claude

av-susvibes run-batch --dataset /path/to/susvibes_dataset.jsonl \
  --harness opencode --model MODEL_ID --output runs/opencode
```

`--instance-id ID` selects tasks and `--max-rounds` sets the check cap (default
5). The agent runs inside a long-lived container built from the task's no-test
image, with the repository bind-mounted from a host scratch directory. After
the agent CLI is installed, the container is moved to an internal network where
it can reach only a relay to the model API. Probes run in separate containers.
Claude Code starts a new session for each repair; OpenCode resumes its session.
If a repair call fails, the last checked patch is kept. Results are
checkpointed per task, and rerunning the command resumes incomplete tasks.
`--host-agent` runs the agent CLI on the host (development only), and
`--agent-command` replaces the CLI invocation with an argv template using
`{model}`, `{prompt}`, `{workspace}`, and `{session_id}`.

SWE-agent:

```bash
av-susvibes swe-agent --dataset /path/to/susvibes_dataset.jsonl \
  --model MODEL_ID --output runs/swe-agent
```

The launcher writes `swe_instances.json` from the public fields only and runs
the vendored SWE-agent with a 1,800-second deadline and 200 model calls per
task. `--num-workers N` runs tasks in parallel. A `sitecustomize` hook wraps
SWE-agent's submission handler: an insecure patch cancels the submission and
the counterexample becomes the next observation, up to five checks. Predictions
are merged into `runs/swe-agent/predictions.json`, and each task's
`harness.log` keeps the runner output. To change the SWE-agent call, append
`--` and the full command with `{instances}` where the instance file goes.

Settings from the paper: 5 to 10 probes per target, at most five checks,
600-second model calls, the same model for the agent, attacker, and judge;
SWE-agent 200 calls and 1,800 s per task, Claude Code 3,000 s, OpenCode 3,600 s.

## Held-out grading

`run-batch` and `swe-agent` write `predictions.json` in the format the SusVibes
evaluator reads. Grade after inference:

```bash
av-susvibes grade --dataset /path/to/susvibes_dataset.jsonl \
  --predictions runs/claude/predictions.json \
  --run-id claude-run --eval-output runs/grades
```

Grading is a separate step that calls the vendored `susvibes.eval.core`. The
inference code never reads `test_patch`, `security_patch`, `golden_patch`, or
any pass/fail labels.

## Probe and trace format

The attacker returns one JSON object with `coverage` and `probes`. Each probe
has `id`, `target` (`path.py::Qualified.symbol`), `cwe`, `rationale`, and a
Python `script`. A script prints one or more `AV_OBSERVATION:<json>` lines with
the input, the return value or exception, and optional `artifacts` describing
files or state it planted. It never asserts an outcome.

The runner's `frames`, `events`, `target_return`, and `exception` fields are
measured separately from what the probe prints. Stage 2 detectors need a
measured event to confirm a claimed artifact or sink call, and the runtime
faithfulness check rejects a printed `events` or `side_effects` claim that has
no matching attributed event. The judge sees the public task and the trace,
never the source or the patch.

## Outputs

Each `round_XX/check/` directory holds the targets, every probe with a
`record.json` (static and runtime rejection rules, trace, verifier stage,
evidence), and the raw attacker and judge prompts and responses.
`report.json` has the verdict and the counts of generated probes, static
rejections, runtime rejections, admitted probes, and execution errors. API keys
are never written out.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests cover target selection, real execution of a target, shadowed and
missing targets, fabricated sink claims, bound SQL parameters, the 21-detector
registry, the Claude Code harness, and the SWE-agent gate. They do not need
Docker, task images, or model access, and they do not reproduce the paper's
numbers.
