# Sandbox setup (run once per session)

Probes execute real code with adversarial inputs, so they must run in a sandbox.
The first time either `attacker-verifier` skill runs in a session, settle how
probes will execute and record the choice for the rest of the session.

## Procedure

1. **Check for an existing decision.** Read the session marker:

   ```
   python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" session \
     --data-dir "${CLAUDE_PLUGIN_DATA}" --session-id "${CLAUDE_SESSION_ID}"
   ```

   If it prints a JSON object, reuse it as the execution config for this run and
   skip the rest of this procedure. If it prints an empty line, continue.

2. **Ask the user, clearly, once.** Ask whether the project already has a
   sandbox or container they want probes to run in. Use `AskUserQuestion` with
   two options:

   - **Use an existing sandbox / Docker** — the user names a Docker image
     (fresh container per probe) or a running container (exec into it). Probes
     execute isolated from the host.
   - **Run here with current session permissions** — no container; probes run on
     the host under the permissions and sandboxing this Claude Code session
     already has. This is the default if the user has no sandbox.

   If the user picks Docker, ask for the image (e.g. `python:3.12-slim`) or the
   container name. For a running container, confirm the repository is mounted
   at a working directory inside it (default `/work`).

3. **Record the decision** so later runs in this session don't ask again:

   - Host mode:
     ```
     python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" session \
       --data-dir "${CLAUDE_PLUGIN_DATA}" --session-id "${CLAUDE_SESSION_ID}" \
       --set-json '{"mode":"host"}'
     ```
   - Docker image mode:
     ```
     ... session ... --set-json '{"mode":"docker","image":"python:3.12-slim","workdir":"/work"}'
     ```
   - Running container mode:
     ```
     ... session ... --set-json '{"mode":"docker","container":"my-dev","workdir":"/work"}'
     ```

4. **Carry the execution block into every engine call this run** by passing it
   inside `--config-json` as the `execution` object, merged with any other
   settings the user requested. For example:

   ```
   --config-json '{"execution":{"mode":"docker","image":"python:3.12-slim","workdir":"/work"},"probes_min":5,"probes_max":10}'
   ```

How each mode runs a probe:

- Host: the probe runs as a child process with CPU, memory, and wall-clock
  limits and its own scratch directory. It can reach whatever the Claude Code
  session can reach, so use this mode for code you are willing to run locally.
- Docker image: each probe gets `docker run --rm --network none` with the
  repository mounted at `workdir`.
- Running container: each probe runs through `docker exec`. The repository must
  already be mounted at `workdir` inside that container.

In both Docker modes the probe, its trace file, and a copy of the harness are
staged under `.attacker-verifier/run/` in the repository, so the same paths
resolve on the host and in the container. The engine writes a `.gitignore` in
`.attacker-verifier/` that ignores everything except `config.json`.

Only the execution mode is remembered per session. Probe budgets, attacker and
verifier choices, scope, and turns are read fresh from each invocation's
arguments, so the user can change them between runs.
