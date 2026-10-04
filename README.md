<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="img/logo-dark.svg">
    <img src="img/logo.svg" alt="Attacker-Verifier" width="560">
  </picture>
</p>

<h3 align="center">Security feedback for coding agents, grounded in real attacks and their execution traces.</h3>

<p align="center">
  <a href="#quick-start"><img src="https://img.shields.io/badge/Claude%20Code-plugin-d97757?style=flat" alt="Claude Code plugin"></a>
  <img src="https://img.shields.io/badge/version-0.2.0-1f6feb?style=flat" alt="version 0.2.0">
  <img src="https://img.shields.io/badge/python-3.8%2B-3776ab?style=flat" alt="python 3.8+">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea44f?style=flat" alt="license MIT"></a>
  <a href="experiments/README.md"><img src="https://img.shields.io/badge/benchmarks-CWEval%20%7C%20SecCodeBench--V2%20%7C%20SusVibes%20%7C%20SecCodePLT%2B-6e40c9?style=flat" alt="benchmarks"></a>
</p>

<p align="center">
  <a href="#quick-start"><b>Quick start</b></a> ·
  <a href="#how-it-works"><b>How it works</b></a> ·
  <a href="#results"><b>Results</b></a> ·
  <a href="experiments/README.md"><b>Experiments</b></a> ·
  <a href="docs/configuration.md"><b>Configuration</b></a>
</p>

<p align="center">
  <img src="img/overview.png" alt="Overview: the coding agent's patch is attacked with PoC probes, unfaithful probes are rejected, the admitted probes run in a sandbox, and the verifier turns their traces into a verdict and feedback." width="100%">
</p>

---

Attacker-Verifier checks code by attacking it. An attacker writes small
proof-of-concept probes that call the code with adversarial inputs and never say
what the output should be. Probes that fake their evidence are thrown out; the
rest run in a sandbox, and a verifier decides from each execution trace whether
the code did something unsafe. A reported violation always comes with the probe
and the trace that show it, so a coding agent can fix the cause instead of
guessing.

This repository has the Claude Code plugin and the code for the experiments in
*Secure Agentic Coding through Counterexample-Grounded Feedback*, where the
method is called FALCON. The figures below come from the paper.

## Quick start

In Claude Code:

```
/plugin marketplace add SafeCodeAgent/attacker-verifier
/plugin install attacker-verifier@attacker-verifier
```

Audit existing code, or write new code and harden it:

```
/check-code-security src/storage.py
/secure-code-generation add an endpoint that serves report files by name
```

`/check-code-security` writes a report named `<repo>_<timestamp>.md`
([example](docs/sample-report.md)). `/secure-code-generation` implements the
request, then attacks and repairs it for two rounds by default. The first run in
a session asks whether probes should run in Docker or on the host. The probes
need Python 3.8 or newer; the engine uses only the standard library.

## How it works

<p align="center">
  <img src="img/motivation.png" alt="Prior approaches ask a model to reason about code or to define expected outcomes; Attacker-Verifier separates exploration from verification through execution evidence." width="62%">
</p>

A judge that reads source code has to infer how the program behaves, and a model
that writes security tests also has to decide the correct output. Mistakes in
either let a candidate pass while keeping the vulnerability. Attacker-Verifier
splits the job in two and connects the halves through execution:

1. **Targets.** The changed functions, methods, and classes in non-test files
   are selected (the plugin can also rank a whole repository by
   security-relevant code).
2. **Attack.** An attacker writes deterministic probes that call each target
   with adversarial inputs or a prepared environment. A probe records what
   happened and never states the expected result.
3. **Faithfulness.** Before running, a probe is rejected if it redefines,
   rebinds, or patches the target, writes code into the repository, runs the
   sensitive operation itself, or prints evidence it made up. After running, a
   probe that never reached the target, or whose output cannot be tied to it,
   is discarded.
4. **Execution.** Each probe runs alone in a sandbox, under a tracer that records
   the target's calls, arguments, return values, exceptions, and side effects.
5. **Verification.** Deterministic checks decide traces with clear runtime
   evidence, such as a crash on the target path. A judge model reads the
   remaining traces, never the source, and decides whether the observed
   behaviour is a violation.
6. **Feedback.** A target is insecure if any admitted probe is insecure, secure
   if at least one probe was admitted and none is insecure, and has no evidence
   otherwise. Each violation goes back to the coding agent with its probe and
   trace.

## Results

All numbers are from the paper. Func-Sec@1 counts a task only when both the
benchmark's functional tests and its security tests pass; those tests are never
shown to the attacker, the verifier, or the coding model.

### Reported progress versus held-out security

<p align="center"><img src="img/signal-comparison.png" alt="Repair on CWEval with four security signals: held-out Func-Sec@1 per round, the improvement each signal reports, and reported versus held-out improvement." width="100%"></p>

GPT-5.4-mini repaired its CWEval solutions for five rounds against four
different signals. Every signal reported progress on its own verdicts, but only
part of it reached the held-out tests: Attacker-Verifier raised Func-Sec@1 by
25.2 points (61.3 to 86.6), CodeQL by 6.7, the LLM judge by 0.0, and
attacker-written tests lowered it by 1.7.

### Test-time repair

<p align="center">
  <img src="img/repair-seccodebench.png" alt="Func-Sec@1 on SecCodeBench-V2 before and after repair, with frontier models as single-pass references." width="49%">
  <img src="img/repair-cweval.png" alt="Func-Sec@1 on CWEval before and after repair, with frontier models as single-pass references." width="49%">
</p>

Up to five rounds of repair, with the attacker and the judge on the same model
as the coder (starred). Func-Sec@1 rises by 22.5 to 24.0 points on
SecCodeBench-V2 and 24.4 to 25.2 points on CWEval. GPT-5.4-nano goes from 40.6%
to 64.3% and from 52.9% to 77.3%, close to or above Claude Opus 4.8 without
repair.

<details>
<summary>Functionality, security, and Func-Sec per repair round</summary>
<p align="center"><img src="img/repair-rounds.png" alt="Func, Sec, and Func-Sec over five repair rounds on SecCodeBench-V2 and CWEval." width="100%"></p>
</details>

### Coding agents on SusVibes

SWE-agent, Claude Code, and OpenCode edit real Python repositories (186 tasks,
77 CWEs). Before a patch is accepted, the changed code is attacked and any
violation goes back to the agent, for at most five checks. Averages over the
three agents:

| Model | FuncPass | SecPass | Func-TestRate | Sec-TestRate |
|---|---:|---:|---:|---:|
| GPT-5.4-mini | 44.09 | 12.36 | 74.01 | 69.76 |
| + Attacker-Verifier | **46.59** (+2.50) | **17.20** (+4.84) | **76.24** (+2.23) | **72.55** (+2.79) |
| GPT-5.4 | 68.82 | 20.25 | 81.65 | 77.55 |
| + Attacker-Verifier | **70.97** (+2.15) | **25.27** (+5.02) | **83.12** (+1.47) | **79.35** (+1.80) |
| GPT-5.6-luna | 62.54 | 19.00 | 80.99 | 77.78 |
| + Attacker-Verifier | **63.62** (+1.08) | **22.22** (+3.22) | **81.47** (+0.48) | **79.36** (+1.58) |
| DeepSeek-V4-Pro-08-13 | 81.90 | 20.79 | 83.87 | 79.92 |
| + Attacker-Verifier | **82.61** (+0.71) | **24.91** (+4.12) | **84.68** (+0.81) | **81.59** (+1.67) |

### Reinforcement learning

<p align="center"><img src="img/rl-training-curves.png" alt="GRPO training reward, held-out Func-Sec@1, and KL for six security rewards on Qwen2.5-Coder-3B and 7B." width="100%"></p>

GRPO on SecCodePLT+ with six security rewards and the same functionality
reward. Every policy raises its own training reward, but the static-analysis
(REAL) and learned (SecCodePRM) rewards transfer much less to held-out
Func-Sec@1, and at 3B it falls while their reward keeps rising. Adding the
Attacker-Verifier reward to either one gives the best held-out results:

| Security reward | 3B Func-Sec@1 | 7B Func-Sec@1 |
|---|---:|---:|
| REAL | 38.75 | 57.13 |
| SecCodePRM | 29.46 | 54.50 |
| REAL + SecCodePRM | 38.01 | 56.89 |
| Attacker-Verifier | 49.27 | 68.70 |
| Attacker-Verifier + REAL | **57.25** | 70.87 |
| Attacker-Verifier + SecCodePRM | 51.95 | **77.26** |

### Verifier accuracy and cost

Agreement with CWEval's labeled security tests, averaged over code from three
models. Judging one observed execution is easier than judging all the
executions a piece of code allows, and it is cheaper.

| Verifier (judge: GPT-5.2) | Accuracy | False positives | False negatives | Cost per example |
|---|---:|---:|---:|---:|
| Deterministic checks only | 97.54% | 2.33% | 2.62% | $0 |
| Deterministic checks + trace judge | **98.58%** | 2.73% | 0.20% | $0.085 |
| Trace judge on every trace | 87.99% | 23.92% | 0.18% | $0.634 |
| Judge reading the source code | 61.16% | 50.43% | 28.05% | $1.227 |
| CodeQL | 56.68% | 17.95% | 66.42% | $0 |

## Using the plugin

### Commands

```
/check-code-security                       # asks: whole repository or a part you name
/check-code-security src/ --probes 8-12
/check-code-security --scope changed       # uncommitted work, including new files
/secure-code-generation implement the CSV import --turns 3
```

The report lists each unsafe function with the weakness, the reason, the
evidence, and a trace excerpt, followed by per-target results and the probes
the faithfulness check removed.

### Sandbox

The first time either command runs in a session, it asks how to run probes:
in a Docker image (a fresh container per probe) or a running container, with
the repository mounted inside it, or on the host with the permissions the Claude
Code session already has. The answer is kept for the session. See
[docs/sandbox.md](docs/sandbox.md).

### Configuration

Every setting has a default. Change them in `/config` (or `/plugin`, then
attacker-verifier, then Configure), or for one run with arguments:

| Setting | Default | Argument |
|---|---|---|
| Attacker model | `main coding agent` | `--attacker NAME` |
| Verifier model (trace judge) | `main coding agent` | `--verifier NAME` |
| Attacker / verifier reasoning effort | `inherit` | `--attacker-effort`, `--verifier-effort` |
| Attacker max turns per target | 20 | `--attacker-max-turns N` |
| Probes per target | 5 to 10 | `--probes MIN-MAX` |
| Repair rounds (`/secure-code-generation`) | 2 | `--turns N` |
| Max targets per run | 20 | `--max-targets N` |

`main coding agent` runs the role in your current session; a model name runs it
as a subagent on that model. A repository can pin engine settings in
`.attacker-verifier/config.json`. [docs/configuration.md](docs/configuration.md)
lists everything.

### Limits

- Only Python is attacked. Files in other languages are listed in the report as
  not attacked.
- A secure result means the probes that ran found nothing, not that the code is
  proven safe. A larger probe budget or a wider scope checks more.
- Running code takes longer than reading it.

## Reproducing the experiments

| Experiment | Paper | Code |
|---|---|---|
| Test-time repair on CWEval and SecCodeBench-V2 | §4.2.1–4.2.2 | [experiments/test-time-repair](experiments/test-time-repair/README.md) |
| Coding agents on SusVibes | §4.2.3 | [experiments/susvibes](experiments/susvibes/README.md) |
| GRPO on SecCodePLT+ | §4.2.4 | [experiments/rl](experiments/rl/README.md) |

Benchmarks, task images, and model weights are not included, and the held-out
tests run only in the separate grading commands. See
[experiments/README.md](experiments/README.md).

## Repository layout

```
.claude-plugin/   plugin and marketplace manifests
skills/           /check-code-security and /secure-code-generation
agents/           attacker and verifier subagents
engine/           target selection, faithfulness checks, sandbox, crash oracle, report
docs/             procedures, configuration reference, sample report
tests/            engine tests (python3 -m pytest tests)
experiments/      code for the paper's experiments
img/              logo and figures
```

## License

MIT, see [LICENSE](LICENSE). The experiment code includes third-party components
under their own licenses; see [experiments/README.md](experiments/README.md#third-party-code).
