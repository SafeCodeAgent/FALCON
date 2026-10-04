# Experiments

Code for the experiments in *Secure Agentic Coding through Counterexample-Grounded
Feedback*. Each directory is a separate Python project with its own README.

| Directory | Paper | What it runs |
| --- | --- | --- |
| [test-time-repair/](test-time-repair/README.md) | Sections 4.2.1–4.2.2; Appendix C.2–C.4 | the security signal, and the five-round repair loop on [CWEval](https://arxiv.org/abs/2501.08200) and [SecCodeBench-V2](https://arxiv.org/abs/2602.15485) |
| [susvibes/](susvibes/README.md) | Section 4.2.3; Appendix C.1, C.5 | repair inside [SWE-agent](https://github.com/SWE-agent/SWE-agent), [Claude Code](https://claude.com/product/claude-code), and [OpenCode](https://github.com/anomalyco/opencode) on [SusVibes](https://arxiv.org/abs/2512.03262) |
| [rl/](rl/README.md) | Section 4.2.4; Appendix B.2 | [GRPO](https://arxiv.org/abs/2402.03300) on [SecCodePLT+](https://arxiv.org/abs/2505.22704) with six security reward settings |

`rl/` imports the signal package from `test-time-repair/`. `susvibes/` has its
own implementation of the same method for repository patches, including Python
2 task images. The baseline signals compared in Section 4.2.1 (attacker-only
tests, LLM-as-a-judge, CodeQL) and the verifier-accuracy study of Section 4.3
are not part of this code.

## The method in this code

For a candidate program, the changed functions, methods, and classes are
selected as targets. An attacker model writes 5 to 10 deterministic probes per
target; a probe calls the target with an adversarial input and prints what it
observed, without an expected result. Static faithfulness rules reject probes
that shadow or patch the target, or produce their own evidence. The remaining
probes run in containers without network access, under a tracer that records
the target's frames and the events attributed to them. Runtime faithfulness
rules discard traces that never reach the target or report events with no
target frame behind them.

The verifier has three stages: a crash oracle, 21 CWE detectors that fire only
on positive runtime evidence, and a model judge that reads the trace (never the
source) for whatever the first two leave undecided. Repair uses all three. RL
uses only the first two, and gives a security reward of 0 only for an insecure
verdict.

A candidate is `insecure` if any admitted trace is insecure, `secure` if at
least one probe was admitted and none is insecure, and `no-evidence` if no probe
was admitted. Each insecure verdict carries the probe, its trace, and the
reason, which is what the coding model or agent receives as feedback.

## Shared settings

| Setting | Value |
| --- | --- |
| Probes per target | 5 to 10 |
| Maximum checks per task | 5 |
| Model API timeout | 600 s |
| Attacker and judge model | the same model name as the coding model (RL: Qwen3-8B attacker) |

## What the code does not use

The attacker and judge see the public task, the candidate code, and the traces.
No benchmark test, reference solution, or label is passed to any model or used
by the signal. Held-out tests run only in the separate grading commands, after
candidates or predictions are saved. In RL, the functionality reward uses the
training tasks' capability tests, as in the original training setup; the safety
tests are used only by `rl/evaluate.py`.

The repository does not include benchmark datasets, task images, model weights,
or results. Running the experiments needs Docker, the benchmark checkouts or
datasets, model endpoints, and for RL, eight GPUs.

## Third-party code

- `susvibes/vendor/swe-agent/`: SWE-agent 1.1.0, MIT.
- `susvibes/vendor/susvibes/`: the SusVibes package and evaluator, MIT.
- `rl/verl/`: [VeRL](https://github.com/volcengine/verl) as used in the [REAL](https://arxiv.org/abs/2505.22704) codebase, Apache-2.0 (`rl/LICENSE`).
- `rl/real_detector.py`: the REAL static detectors, Apache-2.0
  (`rl/REAL_DETECTOR_LICENSE`).

See [susvibes/vendor/README.md](susvibes/vendor/README.md) for the exact
upstream commits.
