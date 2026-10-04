# OpenCode harness

`installer.py` finds a standalone OpenCode 1.18.16 binary: the path in
`AV_OPENCODE_BINARY`, an `opencode` on `PATH` with that version, or the
matching GitHub release, downloaded once into `~/.cache/attacker-verifier/`.
`runner.py` copies the binary into the no-test task container, writes a
provider configuration for an OpenAI-compatible endpoint, and restricts the
container's network to that endpoint's model route.

OpenCode runs with JSON event output. The runner reads the session ID from the
events, and each repair resumes the same session with `--session`. The outer
loop enforces a 3,600-second task deadline.

Set `AV_API_BASE_URL` and `AV_API_KEY`, and `AV_API_MODE=responses` for a
Responses endpoint (the default is Chat Completions). `AV_OPENCODE_MODEL` and
`AV_OPENCODE_CONFIG_CONTENT` override the generated model name and provider
configuration.

For development with `--host-agent`, `AV_OPENCODE_SOURCE=/path/to/opencode`
runs an OpenCode v1.18.16 source checkout with Bun instead of the binary.
