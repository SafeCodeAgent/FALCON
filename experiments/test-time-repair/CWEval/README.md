# CWEval

Set `CWEVAL_ROOT` to a CWEval checkout and `MODEL` to the model used for
coding, probe generation, and Stage 3 judgment.

```bash
export CWEVAL_ROOT=/path/to/CWEval
export MODEL=MODEL_NAME
./prepare.sh
./repair.sh
./grade.sh
```

`prepare.sh` writes the 119 public task workspaces and a manifest, without
reference solutions or tests. `repair.sh` runs up to five checks per task and
saves each checked candidate with its traces and counterexamples. `grade.sh`
runs CWEval's own tests on the final candidates; build its image first with
`docker build -t cweval-runtime:latest "$CWEVAL_ROOT"`.

The built-in probe runner instruments Python. For the C, C++, Go, and
JavaScript tasks, set `ADAPTER_COMMAND` to a trusted trace adapter (see the
[parent README](../README.md#other-languages)); without one, `repair.sh` stops
at the first such task. `BENCH_LANGUAGE=python LIMIT=1` gives a quick Python
run. `OUTPUT_ROOT`, `PYTHON_IMAGE`, `CWEVAL_IMAGE`, and `GRADE_OUTPUT` override
the default locations and images.
