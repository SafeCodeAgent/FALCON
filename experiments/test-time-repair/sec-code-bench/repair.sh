#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repair_dir=$(cd -- "$script_dir/.." && pwd)
scenario=${SCENARIO:-gen}
output=${OUTPUT_ROOT:-$repair_dir/outputs/seccodebench/$scenario}
if [[ -z ${MODEL:-} ]]; then
  echo "Set MODEL to the coding, attacker, and judge model name." >&2
  exit 2
fi
if [[ ! -f "$output/manifest.jsonl" ]]; then
  echo "Missing manifest. Run prepare.sh first." >&2
  exit 2
fi
export PYTHONPATH="$repair_dir${PYTHONPATH:+:$PYTHONPATH}"
args=(--manifest "$output/manifest.jsonl" --output "$output" --model "$MODEL"
      --image "${PYTHON_IMAGE:-av-python:latest}")
if [[ -n ${ADAPTER_COMMAND:-} ]]; then args+=(--adapter-command "$ADAPTER_COMMAND"); fi
if [[ -n ${LIMIT:-} ]]; then args+=(--limit "$LIMIT"); fi
exec "${PYTHON_BIN:-python3}" -m av_signal.repair run "${args[@]}"
