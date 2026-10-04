# SecCodePLT+ run scripts

The scripts can be run from any directory; they find `experiments/rl/`
themselves. They read the parquet files from `experiments/rl/data/seccodeplt/`
unless `TRAIN_DATA` and `VAL_DATA` point elsewhere.

One script per model size and security term. All use the same VeRL settings
from `train.py`.

| Security term | 3B | 7B |
| --- | --- | --- |
| attacker-verifier | `grpo-3b-av.sh` | `grpo-7b-av.sh` |
| REAL | `grpo-3b-real.sh` | `grpo-7b-real.sh` |
| SecCodePRM | `grpo-3b-seccodeprm.sh` | `grpo-7b-seccodeprm.sh` |
| attacker-verifier + REAL | `grpo-3b-av-real.sh` | `grpo-7b-av-real.sh` |
| attacker-verifier + SecCodePRM | `grpo-3b-av-seccodeprm.sh` | `grpo-7b-av-seccodeprm.sh` |
| REAL + SecCodePRM | `grpo-3b-real-seccodeprm.sh` | `grpo-7b-real-seccodeprm.sh` |

Fixed probes are needed once per starting model before any setting that
includes the attacker-verifier term:

```bash
BASE_SOLUTIONS=/path/to/base_3b.jsonl ./prepare-probes-3b.sh
BASE_SOLUTIONS=/path/to/base_7b.jsonl ./prepare-probes-7b.sh
```

Without `BASE_SOLUTIONS`, the base solutions are requested from `MODEL_3B` or
`MODEL_7B` through the OpenAI-compatible endpoint in `OPENAI_BASE_URL` (with
`OPENAI_API_KEY`), which also serves the attacker; set `ATTACKER_MODEL` if its
name differs from `Qwen/Qwen3-8B`. The probes are written to
`outputs/fixed_probes_3b.jsonl` or `fixed_probes_7b.jsonl`; an existing file is
kept unless `OVERWRITE=1`.

Training:

```bash
MODEL_3B=/path/to/checkpoint ./grpo-3b-av.sh
SECCODEPRM_ENDPOINT=http://localhost:8007/score ./grpo-7b-av-seccodeprm.sh
DRY_RUN=1 MODEL_3B=/path/to/checkpoint ./grpo-3b-av.sh    # print the config only
```

`MODEL_3B` and `MODEL_7B` default to `Qwen/Qwen2.5-Coder-3B` and
`Qwen/Qwen2.5-Coder-7B-Instruct`; set them to the starting checkpoints you
use. `CUDA_VISIBLE_DEVICES` defaults to eight GPUs and `N_GPUS` overrides the
count. `PROBE_FILE`, `AV_RL_IMAGE`, and `REWARD_WORKERS` set the probe file,
the sandbox image, and reward parallelism. Logs and checkpoints go to
`outputs/`; `RUN_NAME`, `CHECKPOINT_DIR`, and `LOG_DIR` change the names and
locations. Extra arguments are passed to VeRL as Hydra overrides.

Held-out grading after generating predictions:

```bash
./evaluate-heldout.sh 3b av /path/to/heldout_predictions.jsonl
```
