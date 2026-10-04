# Vendored code

Source snapshots of MIT-licensed projects used by the SusVibes experiments.
Each keeps its upstream license file.

- `swe-agent/`: SWE-agent 1.1.0 (`sweagent`, `tools`, and `config`) from commit
  `0f3acafacabc0def8cc76b4e48acb4b6cf302cb9`. `av-susvibes swe-agent` puts this
  tree on `PYTHONPATH` and installs the submission hook before SWE-agent starts.
  The browser frontend and the trajectory inspector are left out. SWE-agent's
  Python dependencies and SWE-ReX 1.4.0 still have to be installed.
- `susvibes/`: the `susvibes` Python package from commit
  `4e2f7462063e3a57563b0f7025bdd9aa1565939e`, including `core`, `curate`,
  `env_specs`, and the held-out evaluator in `eval`. Local paths, the image
  registry, and the model gateway are read from environment variables.
  `av-susvibes grade` runs `susvibes.eval.core` after predictions are saved.

OpenCode is not vendored. The harness uses the standalone OpenCode 1.18.16
release binary (see `evaluation_harness/opencode/`).

No dataset records, test patches, model outputs, images, or credentials are
included.
