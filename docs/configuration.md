# Configuration reference

Every setting, where to set it, what it accepts, and how it is applied. All
settings have working defaults, so the plugin runs with no configuration at all.

## Two places to configure

- **Models** (which model the attacker and verifier run on) are chosen with the
  **`/attacker-verifier:configure`** command, which reads Claude Code's **live**
  model list. Saved to `.attacker-verifier/config.json` in your repo.
- **Everything else** (reasoning effort, probe counts, repair turns, max
  targets) is set in **`/config`** (or `/plugin` → attacker-verifier →
  Configure). Saved to `pluginConfigs` in your `settings.json`.

Per-run arguments typed after a command override both for that single run.

## Models (live list)

The attacker and verifier can run on any model Claude Code currently offers. The
list is **not hardcoded in this plugin** — it is read at run time from Claude
Code's own model catalog, so when Claude Code adds or changes models the choices
update automatically. The **Fable family is excluded**.

Set the models with:

```
/attacker-verifier:configure
```

It shows the live models as a picker and saves your choice to
`.attacker-verifier/config.json`:

```json
{ "attacker": "main", "verifier": "claude-sonnet-5-5" }
```

- `main` means **run the role inline on your current session model** (no
  delegation). This is the default when nothing is set.
- A model id (e.g. `claude-opus-5-5`) runs the role on the dedicated subagent at
  that model.

The engine exposes the same live data directly:

```
python3 engine/cli.py list-models          # current models, fable excluded
python3 engine/cli.py resolve-model opus    # -> the latest Opus's model id
```

### The always-current path

If you want a role to simply follow the newest model you use, leave it on `main`
and pick your model with Claude Code's own **`/model`** picker (that list is
live). Set a specific model here only when you want the attacker or verifier on a
model *different* from your session model.

## Effort, probes, and limits (`/config`)

| Key | Control | Accepts | Default | Applies to |
|---|---|---|---|---|
| `attacker_effort` | dropdown | `inherit`, `low`, `medium`, `high`, `xhigh`, `max` | `inherit` | a delegated attacker |
| `verifier_effort` | dropdown | `inherit`, `low`, `medium`, `high`, `xhigh`, `max` | `inherit` | a delegated verifier |
| `attacker_max_turns` | number | 1–100 | 20 | the attacker, per target |
| `probes_min` | number | 1–100 | 5 | both commands |
| `probes_max` | number | 1–100 | 10 | both commands |
| `num_turns` | number | 1–10 | 2 | `/secure-code-generation` only |
| `max_targets` | number | 1–200 | 20 | both commands |

`inherit` effort uses your current session effort. A chosen level applies when
the role runs on a model (not `main`).

## Per-run arguments

Typed after the command, overriding the saved settings for one run:

`--attacker <name>`, `--verifier <name>` (any name from `list-models`, or
`opus`/`sonnet`/`haiku`, or `main coding agent`), `--attacker-effort`,
`--verifier-effort`, `--attacker-max-turns N`, `--probes MIN-MAX`, `--turns N`,
`--max-targets N`, `--scope whole|changed|path`.

## Attacker turn budget

`attacker_max_turns` (default 20) is how long the attacker works on one target:
it reads the code and crafts probes for up to this many turns, then returns its
probes — even if fewer than `probes_min`. If it reaches the limit without
returning, it is asked once more to output what it has; if it still produces no
probes, that target is skipped and reported with no evidence. This is distinct
from `max_targets` (how many targets a run attacks) and `num_turns` (how many
repair cycles `/secure-code-generation` runs).

## The sandbox (`execution`)

How probes execute is decided once per session (the plugin asks on first use)
and recorded separately. You can also pin it in `.attacker-verifier/config.json`:

```json
{ "execution": { "mode": "host" } }
```

or, for a container:

```json
{ "execution": { "mode": "docker", "image": "python:3.12-slim", "workdir": "/work" } }
```

`mode` is `host` (run under the current session's permissions) or `docker`
(fresh container per probe from `image`, or exec into a running `container`).
