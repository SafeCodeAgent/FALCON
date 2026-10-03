# Configuration reference

Every setting, where to set it, what it accepts, and how it is applied. All
settings have working defaults, so the plugin runs with no configuration at all.

## Where to set it

- **Settings UI** — `/config`, or `/plugin` → attacker-verifier → **Configure**.
  Every setting below is an editable row there (dropdown or number). Saved to
  `pluginConfigs` in your `settings.json`.
- **Per-run arguments** typed after the command override the settings for one
  run.
- An optional **project file** `.attacker-verifier/config.json` at the repo root
  can also carry engine-level values (probe limits, `max_targets`, and the
  `execution` sandbox block).

## The settings

| Key | Control | Accepts | Default | Applies to |
|---|---|---|---|---|
| `attacker` | dropdown | `main coding agent` + model names (`Opus 5.5`, `Opus 5`, …) | `main coding agent` | both commands |
| `attacker_effort` | dropdown | `inherit`, `low`, `medium`, `high`, `xhigh`, `max` | `inherit` | a delegated attacker |
| `verifier` | dropdown | `main coding agent` + model names (`Opus 5.5`, `Opus 5`, …) | `main coding agent` | both commands |
| `verifier_effort` | dropdown | `inherit`, `low`, `medium`, `high`, `xhigh`, `max` | `inherit` | a delegated verifier |
| `attacker_max_turns` | number | 1–100 | 20 | the attacker, per target |
| `probes_min` | number | 1–100 | 5 | both commands |
| `probes_max` | number | 1–100 | 10 | both commands |
| `num_turns` | number | 1–10 | 2 | `/secure-code-generation` only |
| `max_targets` | number | 1–200 | 20 | both commands |

Per-run argument equivalents: `--attacker`, `--attacker-effort`, `--verifier`,
`--verifier-effort`, `--attacker-max-turns N`, `--probes MIN-MAX`, `--turns N`,
`--max-targets N`, `--scope whole|changed|path`.

## How the model setting works

`main coding agent` (the default) runs the role **inline** on your current
session model — no delegation. To follow whatever model you are using, leave it
on `main coding agent` and set your session model with Claude Code's own
`/model` picker.

Any other choice is a **model name** (`Opus 5.5`, `Opus 5`, `Sonnet 5.5`, …) and
runs the role on the dedicated subagent at that model. At run time the plugin
maps the chosen name to the exact current model id by looking it up in Claude
Code's live model catalog (`engine/cli.py resolve-model "<name>"`), so the id is
always correct. The Fable family is not offered.

**The dropdown list is fixed, not live.** A settings dropdown is part of the
plugin manifest and cannot be populated from Claude Code's live model list, so
the *names shown in the dropdown* are a fixed list that is updated in a plugin
release. When Claude Code ships a brand-new model, it appears once the list is
updated. (You can always leave the role on `main coding agent` and pick the new
model with `/model`, which needs no plugin change.) Run `engine/cli.py
list-models` to see the models Claude Code currently offers.

## How reasoning effort works

- `inherit` uses your current session effort.
- Any other level (`low` … `max`) sets the effort for that role **when it runs on
  a chosen family** (not `main coding agent`).
- When a role is `main coding agent`, it always uses the session effort.

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
