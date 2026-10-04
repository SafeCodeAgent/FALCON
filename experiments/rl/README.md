# RL training on SecCodePLT+

[GRPO](https://arxiv.org/abs/2402.03300) training on [SecCodePLT+](https://arxiv.org/abs/2505.22704) with the security reward from the paper (Section 4.2.4 and
Appendix B.2). The code extends the [REAL](https://arxiv.org/abs/2505.22704) training setup, which uses [VeRL](https://github.com/volcengine/verl). Only
the security term of the reward changes between settings; the functionality
term (the pass rate of the task's capability tests) is the same for all.

| Setting | Security term |
| --- | --- |
| `av` | the attacker-verifier signal with the deterministic verifier |
| `real` | the REAL static analyzer |
| `seccodeprm` | [SecCodePRM](https://arxiv.org/abs/2602.10418), a learned process reward model |
| `av+real`, `av+seccodeprm`, `real+seccodeprm` | the average of the two terms |

The reward for a program is `(1 - w) * functionality + w * security` with
`w = AV_SECURITY_WEIGHT` (default 0.5). A response without a fenced code block
gets -1.

For `av`, the security term uses Stages 1 and 2 only. It is 0 when an admitted
probe produces an insecure verdict and 1 otherwise, including uncertain and
no-evidence results, so every negative reward is backed by a deterministic
check of a runtime event. Probes are generated once, before training: the
attacker (Qwen3-8B by default) reads each task's public prompt and a solution
from the base model and writes a fixed probe set, which is rerun, with both
faithfulness checks, against every rollout.

## Setup

```bash
pip install -e '../test-time-repair[rl]'
pip install -r requirements.txt
docker build -f ../test-time-repair/Dockerfile.python -t av-python:latest ../test-time-repair
```

Put the SecCodePLT+ parquet files in `data/seccodeplt/` (`train.parquet` with
655 tasks, `test.parquet` with 164). Each row needs `id`, `prompt`,
`task_description`, and the `extra_info` fields used by the capability tests.

## Commands

The scripts in [run/seccodeplt/](run/seccodeplt/README.md) wrap the steps below
for both model sizes and all six settings.

Precompute the fixed probes:

```bash
python precompute.py --train-parquet data/seccodeplt/train.parquet \
  --base-solutions base_solutions.jsonl --attacker-model Qwen/Qwen3-8B \
  --output outputs/fixed_probes.jsonl
```

`base_solutions.jsonl` holds one record per task with `id` and `code`;
`--base-model` generates them instead through the OpenAI-compatible endpoint in
`OPENAI_BASE_URL`. The attacker sees only the public prompt and that code, never
the benchmark's safety tests or reference patch.

Train:

```bash
python train.py --train-parquet data/seccodeplt/train.parquet \
  --val-parquet data/seccodeplt/test.parquet --model MODEL_CHECKPOINT \
  --probes outputs/fixed_probes.jsonl --reward av --output outputs/checkpoints
```

`--dry-run` prints the resolved VeRL configuration without starting Ray or
loading a model. Extra arguments are passed to VeRL as Hydra overrides. Set
`SECCODEPRM_ENDPOINT` for settings that use SecCodePRM, and `AV_RL_IMAGE` for
the image that runs probes and tests.

`train.py` sets the hyperparameters of Table 3: learning rate 1e-6, train batch
64, PPO mini-batch 32, micro-batch 2 per GPU, 8 rollouts per prompt, response
length 2,048, tensor parallel size 2, KL coefficient 0.001 applied through the
reward with the KL loss off, and 50 epochs, on 8 GPUs by default.

Evaluate held-out predictions (one JSONL record per test task with `id` and
`code`):

```bash
python evaluate.py --test-parquet data/seccodeplt/test.parquet \
  --predictions heldout_predictions.jsonl --image av-python:latest \
  --output outputs/heldout.json
```

During training, `func_runner.py` runs only the capability tests; the safety
tests are removed before execution. `evaluate.py` is the only place the safety
tests run.

## Files

- `reward.py`: the reward callback passed to VeRL.
- `precompute.py`: fixed probe generation.
- `func_runner.py`: runs a task's tests inside a container.
- `proxies.py`, `real_detector.py`: the REAL and SecCodePRM security terms.
- `train.py`: builds the VeRL configuration and starts GRPO.
- `evaluate.py`: held-out Func@1, Sec@1, and Func-Sec@1.
- `verl/`: the VeRL tree from the REAL codebase; its SecCodePLT reward entry
  calls `reward.py`.

`verl/` is Apache-2.0 licensed (`LICENSE`), and so is `real_detector.py`
(`REAL_DETECTOR_LICENSE`).
