#!/usr/bin/env bash
set -euo pipefail

if (( $# < 2 )); then
  echo "Usage: $0 <3b|7b> <av|real|seccodeprm|av+real|av+seccodeprm|real+seccodeprm> [VeRL overrides...]" >&2
  exit 2
fi

size=$1
reward=$2
shift 2
case "$size" in
  3b) default_model=Qwen/Qwen2.5-Coder-3B; model_var=MODEL_3B ;;
  7b) default_model=Qwen/Qwen2.5-Coder-7B-Instruct; model_var=MODEL_7B ;;
  *) echo "Unsupported model size: $size" >&2; exit 2 ;;
esac
case "$reward" in
  av|real|seccodeprm|av+real|av+seccodeprm|real+seccodeprm) ;;
  *) echo "Unsupported reward setting: $reward" >&2; exit 2 ;;
esac

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
rl_dir=$(cd -- "$script_dir/../.." && pwd)
cd "$rl_dir"

model=${BASE_MODEL:-${!model_var:-$default_model}}
train_data=${TRAIN_DATA:-$rl_dir/data/seccodeplt/train.parquet}
val_data=${VAL_DATA:-$rl_dir/data/seccodeplt/test.parquet}
probe_file=${PROBE_FILE:-$rl_dir/outputs/fixed_probes_${size}.jsonl}
reward_label=${reward//+/_}
run_name=${RUN_NAME:-grpo_${size}_${reward_label}_$(date +%Y%m%d_%H%M%S)}
checkpoint_dir=${CHECKPOINT_DIR:-$rl_dir/outputs/checkpoints/$run_name}
log_dir=${LOG_DIR:-$rl_dir/outputs/logs}
export RAY_TMPDIR=${RAY_TMPDIR:-$rl_dir/outputs/ray}
export VLLM_ATTENTION_BACKEND=${VLLM_ATTENTION_BACKEND:-XFORMERS}
export AV_RL_IMAGE=${AV_RL_IMAGE:-av-python:latest}
export AV_SECURITY_WEIGHT=${AV_SECURITY_WEIGHT:-0.5}
export CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-0,1,2,3,4,5,6,7}
n_gpus=${N_GPUS:-$(awk -F, '{print NF}' <<< "$CUDA_VISIBLE_DEVICES")}
reward_workers=${REWARD_WORKERS:-8}
python_bin=${PYTHON_BIN:-python3}

if [[ "+$reward+" == *+av+* && ${DRY_RUN:-0} != 1 && ! -f "$probe_file" ]]; then
  echo "Missing fixed probes: $probe_file. Run prepare-probes-${size}.sh first." >&2
  exit 2
fi
if [[ "$reward" == *seccodeprm* && ${DRY_RUN:-0} != 1 && -z ${SECCODEPRM_ENDPOINT:-} ]]; then
  echo "SECCODEPRM_ENDPOINT is required for this reward setting." >&2
  exit 2
fi
if [[ ${DRY_RUN:-0} != 1 ]]; then
  for path in "$train_data" "$val_data"; do
    if [[ ! -f "$path" ]]; then
      echo "Missing SecCodePLT+ parquet file: $path" >&2
      exit 2
    fi
  done
fi

mkdir -p "$checkpoint_dir" "$log_dir" "$RAY_TMPDIR"
command=("$python_bin" "$rl_dir/train.py" --train-parquet "$train_data"
         --val-parquet "$val_data" --model "$model" --output "$checkpoint_dir"
         --gpus "$n_gpus" --reward-workers "$reward_workers" --reward "$reward")
if [[ "+$reward+" == *+av+* ]]; then
  command+=(--probes "$probe_file")
fi
if [[ ${DRY_RUN:-0} == 1 ]]; then
  command+=(--dry-run)
fi
command+=("actor_rollout_ref.model.attn_implementation=${MODEL_ATTN_IMPLEMENTATION:-sdpa}"
         "trainer.experiment_name=$run_name" "$@")

"${command[@]}" 2>&1 | tee "$log_dir/$run_name.log"
