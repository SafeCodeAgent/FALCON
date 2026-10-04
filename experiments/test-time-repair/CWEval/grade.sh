#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repair_dir=$(cd -- "$script_dir/.." && pwd)
benchmark_root=${CWEVAL_ROOT:-}
if [[ -z "$benchmark_root" ]]; then
  echo "Set CWEVAL_ROOT to the CWEval checkout." >&2
  exit 2
fi
output=${OUTPUT_ROOT:-$repair_dir/outputs/cweval}
if [[ ! -f "$output/manifest.jsonl" ]]; then
  echo "Missing manifest. Run prepare.sh first." >&2
  exit 2
fi
export PYTHONPATH="$repair_dir${PYTHONPATH:+:$PYTHONPATH}"
exec "${PYTHON_BIN:-python3}" -m av_signal.heldout \
  --manifest "$output/manifest.jsonl" --benchmark-root "$benchmark_root" \
  --cweval-image "${CWEVAL_IMAGE:-cweval-runtime:latest}" \
  --output "${GRADE_OUTPUT:-$output/heldout.json}"
