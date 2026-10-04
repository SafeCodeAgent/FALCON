#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo "Usage: $0 <3b|7b> <reward-setting> <predictions.jsonl>" >&2
  exit 2
fi
size=$1
reward=$2
predictions=$3
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
rl_dir=$(cd -- "$script_dir/../.." && pwd)
test_data=${VAL_DATA:-$rl_dir/data/seccodeplt/test.parquet}
output=${EVAL_OUTPUT:-$rl_dir/outputs/evaluation/${size}_${reward//+/_}.json}
python_bin=${PYTHON_BIN:-python3}

for path in "$test_data" "$predictions"; do
  if [[ ! -f "$path" ]]; then
    echo "Missing evaluation input: $path" >&2
    exit 2
  fi
done
mkdir -p "$(dirname -- "$output")"
exec "$python_bin" "$rl_dir/evaluate.py" --test-parquet "$test_data" \
  --predictions "$predictions" --image "${AV_RL_IMAGE:-av-python:latest}" \
  --output "$output"
