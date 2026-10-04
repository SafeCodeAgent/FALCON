#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "Usage: $0 <3b|7b>" >&2
  exit 2
fi
size=$1
case "$size" in
  3b) default_model=Qwen/Qwen2.5-Coder-3B; model_var=MODEL_3B ;;
  7b) default_model=Qwen/Qwen2.5-Coder-7B-Instruct; model_var=MODEL_7B ;;
  *) echo "Unsupported model size: $size" >&2; exit 2 ;;
esac

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
rl_dir=$(cd -- "$script_dir/../.." && pwd)
cd "$rl_dir"
model=${BASE_MODEL:-${!model_var:-$default_model}}
train_data=${TRAIN_DATA:-$rl_dir/data/seccodeplt/train.parquet}
probe_file=${PROBE_FILE:-$rl_dir/outputs/fixed_probes_${size}.jsonl}
python_bin=${PYTHON_BIN:-python3}

if [[ ! -f "$train_data" ]]; then
  echo "Missing SecCodePLT+ training data: $train_data" >&2
  exit 2
fi
if [[ -e "$probe_file" && ${OVERWRITE:-0} != 1 ]]; then
  echo "Fixed probe file already exists: $probe_file. Set OVERWRITE=1 to regenerate." >&2
  exit 2
fi

args=(--train-parquet "$train_data" --attacker-model "${ATTACKER_MODEL:-Qwen/Qwen3-8B}"
      --output "$probe_file")
if [[ -n ${BASE_SOLUTIONS:-} ]]; then
  if [[ ! -f "$BASE_SOLUTIONS" ]]; then
    echo "Missing base solutions: $BASE_SOLUTIONS" >&2
    exit 2
  fi
  args+=(--base-solutions "$BASE_SOLUTIONS")
else
  args+=(--base-model "$model")
fi
if [[ -n ${LIMIT:-} ]]; then
  args+=(--limit "$LIMIT")
fi
"$python_bin" "$rl_dir/precompute.py" "${args[@]}"
