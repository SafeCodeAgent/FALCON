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
export PYTHONPATH="$repair_dir${PYTHONPATH:+:$PYTHONPATH}"
args=(--benchmark cweval --benchmark-root "$benchmark_root" --output "$output")
if [[ -n ${BENCH_LANGUAGE:-} ]]; then args+=(--language "$BENCH_LANGUAGE"); fi
if [[ -n ${LIMIT:-} ]]; then args+=(--limit "$LIMIT"); fi
exec "${PYTHON_BIN:-python3}" -m av_signal.repair prepare "${args[@]}"
