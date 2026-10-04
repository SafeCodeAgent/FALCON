# Coding-agent harnesses

Adapters for the three coding agents used in the SusVibes experiments. All of
them work from the public task statement and the task's no-test image. Probe
execution and the verifier live in `av_susvibes/`.

| Harness | Code | Repair |
| --- | --- | --- |
| Claude Code | `claude_code/runner.py` | a new `claude -p` session per repair |
| OpenCode | `opencode/runner.py` | resumes the same session with `--session` |
| SWE-agent | `swe_agent/runner.py` | the submission hook feeds violations back into the same trajectory |

`docker_workspace.py` copies the task repository out of the no-test image and
bind-mounts it into a long-running container from the same image, so the agent
runs with the task's dependencies. `network_isolation.py` provides the fixed
model relay and the no-egress Docker networks. `results_store.py` writes
checkpoints atomically. The repair loop itself (patch extraction, checks, the
five-check cap, predictions) is in `av_susvibes/benchmark.py`.
