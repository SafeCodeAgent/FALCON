#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repair_dir=$(cd -- "$script_dir/.." && pwd)
benchmark_root=${SECCODEBENCH_ROOT:-}
if [[ -z "$benchmark_root" ]]; then
  echo "Set SECCODEBENCH_ROOT to the SecCodeBench checkout." >&2
  exit 2
fi
scenario=${SCENARIO:-gen}
output=${OUTPUT_ROOT:-$repair_dir/outputs/seccodebench/$scenario}
if [[ ! -f "$output/manifest.jsonl" ]]; then
  echo "Missing manifest. Run prepare.sh first." >&2
  exit 2
fi
export PYTHONPATH="$repair_dir${PYTHONPATH:+:$PYTHONPATH}"
exec "${PYTHON_BIN:-python3}" -m av_signal.heldout \
  --manifest "$output/manifest.jsonl" --benchmark-root "$benchmark_root" \
  --output "${GRADE_OUTPUT:-$output/heldout.json}"
