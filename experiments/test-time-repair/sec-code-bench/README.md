# SecCodeBench-V2

Set `SECCODEBENCH_ROOT` to a SecCodeBench checkout, `MODEL` to the model used
for coding, probe generation, and Stage 3 judgment, and `SCENARIO` to `gen`,
`gen-hints`, `fix`, or `fix-hints`.

```bash
export SECCODEBENCH_ROOT=/path/to/sec-code-bench
export MODEL=MODEL_NAME
export SCENARIO=gen
./prepare.sh
./repair.sh
./grade.sh
```

`prepare.sh` copies only the public project scaffold and task prompt; tests,
signatures, and unused hint files are left out. The checkout has no Java prompt
text, so set `PROMPT_MAP` to a JSON object of public prompts keyed by
`java/<case id>/<scenario>` to include Java tasks. `LIMIT=1` runs one task.

The built-in probe runner instruments Python. Set `ADAPTER_COMMAND` to a
trusted trace adapter for C/C++, Go, JavaScript, or Java; without one,
`repair.sh` stops at the first such task. `BENCH_LANGUAGE=python LIMIT=1` gives
a quick Python run. `grade.sh` calls the benchmark's verifier services, which
you start with its `docker-compose-verifiers.yml`. The held-out tests run only
in this grading step.
