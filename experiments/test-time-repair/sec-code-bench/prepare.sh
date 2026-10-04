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
export PYTHONPATH="$repair_dir${PYTHONPATH:+:$PYTHONPATH}"
args=(--benchmark seccodebench-v2 --benchmark-root "$benchmark_root"
      --scenario "$scenario" --output "$output")
if [[ -n ${BENCH_LANGUAGE:-} ]]; then args+=(--language "$BENCH_LANGUAGE"); fi
if [[ -n ${PROMPT_MAP:-} ]]; then args+=(--prompt-map "$PROMPT_MAP"); fi
if [[ -n ${LIMIT:-} ]]; then args+=(--limit "$LIMIT"); fi
exec "${PYTHON_BIN:-python3}" -m av_signal.repair prepare "${args[@]}"
