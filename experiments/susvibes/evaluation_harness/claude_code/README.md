# Claude Code harness

`runner.py` builds the Claude Code 1.0.128 command (`claude -p` with verbose
`stream-json` output). The allowed and disallowed tools follow the SusVibes
Claude Code settings. `setup_cli.sh` installs Node.js 22 and the pinned CLI in
the no-test task container, before the container's network is restricted. After
that, the container can reach only the Anthropic Messages routes through a
fixed model relay.

Each repair starts a new Claude Code session. `prompts.py` builds the repair
prompt from the original public task plus the latest security feedback. The
3,000-second task deadline and the rule that the last checked patch is kept if
a later call fails are enforced in `av_susvibes/benchmark.py`.

```bash
av-susvibes run-batch --harness claude-code \
  --dataset /path/to/susvibes_dataset.jsonl \
  --model MODEL_ID --output runs/claude
```

Set `ANTHROPIC_BASE_URL` to an Anthropic-compatible endpoint and
`ANTHROPIC_AUTH_TOKEN` or `ANTHROPIC_API_KEY`. Only that key is passed into the
task container.
